"""Single-event detection rules: JSON, Sigma-flavoured, validated on load.

    {
      "id": "lolbin-certutil-download",
      "title": "certutil used to download or decode a file",
      "level": "high",                       # info | low | medium | high | critical
      "mitre": ["T1105", "T1140"],
      "channels": ["Security", "Microsoft-Windows-Sysmon/Operational"],
      "event_ids": [4688, 1],
      "where": [                             # every condition must hold (AND)
        ["CommandLine|contains", ["certutil"]],
        ["CommandLine|contains", ["urlcache", "verifyctl", "-decode"]]   # list = any of (OR)
      ],
      "where_not": [["ParentImage|endswith", ["\\\\msiexec.exe"]]],      # any match excludes
      "show": ["CommandLine", "SubjectUserName"]
    }

Field names are EventData/UserData keys. `*` means "any data value"; `provider`, `computer`, `channel`
and `user_sid` address the System section. Operators: equals (default), contains, startswith,
endswith, re; append `|all` to require every listed value instead of any. Matching ignores case.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .evtx import Event

LEVELS = ("info", "low", "medium", "high", "critical")
OPERATORS = ("equals", "contains", "startswith", "endswith", "re")
META_FIELDS = {"provider", "computer", "channel", "user_sid"}
_ENCODED = re.compile(r"(?i)(?:^|\s)[-/](?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+"
                      r"['\"]?([A-Za-z0-9+/]{16,}={0,2})")


def decode_powershell(text: str) -> str | None:
    """The command hidden in `powershell -EncodedCommand <base64>` (UTF-16LE), or None."""
    m = _ENCODED.search(text)
    if not m:
        return None
    blob = m.group(1)
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
    return " ".join(decoded.split()) if decoded and printable / len(decoded) > 0.9 else None


@dataclass(frozen=True)
class Show:
    field: str
    label: str
    extract: re.Pattern | None = None


class RuleError(ValueError):
    pass


def rank(level: str) -> int:
    return LEVELS.index(level)


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    values: tuple
    require_all: bool = False

    def _candidates(self, event: Event) -> list[str]:
        if self.field == "*":
            return list(event.data.values())
        if self.field in META_FIELDS:
            return [getattr(event, self.field) or ""]
        value = event.data.get(self.field)
        return [] if value is None else [value]

    def _one(self, text: str, needle) -> bool:
        if self.op == "re":
            return needle.search(text) is not None
        if self.op == "contains":
            return needle in text
        if self.op == "startswith":
            return text.startswith(needle)
        if self.op == "endswith":
            return text.endswith(needle)
        return text == needle

    def matches(self, event: Event) -> bool:
        texts = [t.lower() for t in self._candidates(event)]
        if not texts:
            return False
        check = all if self.require_all else any
        return any(check(self._one(t, n) for n in self.values) for t in texts)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    mitre: tuple
    description: str
    channels: frozenset
    event_ids: frozenset
    where: tuple
    where_not: tuple
    show: tuple

    def matches(self, event: Event) -> bool:
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        if self.channels and event.channel.lower() not in self.channels:
            return False
        if not all(c.matches(event) for c in self.where):
            return False
        return not any(c.matches(event) for c in self.where_not)

    def summary(self, event: Event) -> str:
        parts, decoded = [], None
        for spec in self.show:
            value = getattr(event, spec.field) if spec.field in META_FIELDS else event.data.get(spec.field)
            if not value:
                continue
            if spec.extract is not None:
                m = spec.extract.search(value)
                if not m:
                    continue
                value = m.group(1)
            decoded = decoded or decode_powershell(value)
            value = " ".join(str(value).split())
            parts.append(f"{spec.label}={_clip(value)}")
        if decoded:
            parts.append(f"decoded={_clip(decoded)}")
        return " · ".join(parts)


def _clip(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _show(raw, where: str) -> Show:
    if isinstance(raw, str):
        return Show(raw, raw)
    if isinstance(raw, dict) and raw.get("field"):
        pattern = None
        if raw.get("extract"):
            try:
                pattern = re.compile(raw["extract"], re.IGNORECASE)
            except re.error as e:
                raise RuleError(f"{where}: bad show.extract regex: {e}") from None
            if pattern.groups < 1:
                raise RuleError(f"{where}: show.extract needs one capture group")
        return Show(raw["field"], raw.get("label", raw["field"]), pattern)
    raise RuleError(f"{where}: show entries are field names or {{field, extract, label}} objects")


def _condition(expr, values, where: str) -> Condition:
    if not isinstance(expr, str) or not expr:
        raise RuleError(f"{where}: condition field must be a non-empty string")
    field, *mods = expr.split("|")
    require_all = "all" in mods
    ops = [m for m in mods if m != "all"]
    op = ops[0] if ops else "equals"
    if op not in OPERATORS or len(ops) > 1:
        raise RuleError(f"{where}: unknown operator in {expr!r}")
    if isinstance(values, (str, int)):
        values = [values]
    if not isinstance(values, list) or not values:
        raise RuleError(f"{where}: {expr!r} needs a non-empty value list")
    if op == "re":
        try:
            compiled = tuple(re.compile(str(v), re.IGNORECASE) for v in values)
        except re.error as e:
            raise RuleError(f"{where}: bad regex in {expr!r}: {e}") from None
        return Condition(field, op, compiled, require_all)
    return Condition(field, op, tuple(str(v).lower() for v in values), require_all)


def _conditions(raw, where: str) -> tuple:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise RuleError(f"{where}: must be a list of [field, values] pairs")
    out = []
    for item in raw:
        if not (isinstance(item, list) and len(item) == 2):
            raise RuleError(f"{where}: each condition is [field, values]")
        out.append(_condition(item[0], item[1], where))
    return tuple(out)


def compile_rule(raw: dict, source: str) -> Rule:
    if not isinstance(raw, dict) or not raw.get("id"):
        raise RuleError(f"{source}: every rule needs an 'id'")
    rid = raw["id"]
    where = f"{source}:{rid}"
    level = raw.get("level", "medium")
    if level not in LEVELS:
        raise RuleError(f"{where}: unknown level {level!r}")
    try:
        event_ids = frozenset(int(i) for i in raw.get("event_ids", []))
    except (TypeError, ValueError):
        raise RuleError(f"{where}: event_ids must be integers") from None
    conditions = _conditions(raw.get("where"), where)
    if not event_ids and not conditions:
        raise RuleError(f"{where}: a rule needs event_ids or conditions, or it matches everything")
    return Rule(
        id=rid,
        title=raw.get("title", rid),
        level=level,
        mitre=tuple(raw.get("mitre", ())),
        description=raw.get("description", ""),
        channels=frozenset(c.lower() for c in raw.get("channels", [])),
        event_ids=event_ids,
        where=conditions,
        where_not=_conditions(raw.get("where_not"), where),
        show=tuple(_show(s, where) for s in raw.get("show", ())),
    )


def parse_rules(doc, source: str) -> list[Rule]:
    items = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise RuleError(f"{source}: expected a list of rules")
    rules = [compile_rule(r, source) for r in items]
    ids = [r.id for r in rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise RuleError(f"{source}: duplicate rule ids: {', '.join(dupes)}")
    return rules


def load_builtin() -> list[Rule]:
    text = resources.files("evtxhunter").joinpath("rules/builtin.json").read_text(encoding="utf-8")
    return parse_rules(json.loads(text), "builtin")


def load_path(path: Path) -> list[Rule]:
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    rules: list[Rule] = []
    for f in files:
        try:
            rules += parse_rules(json.loads(f.read_text(encoding="utf-8")), str(f))
        except json.JSONDecodeError as e:
            raise RuleError(f"{f}: {e}") from None
    return rules
