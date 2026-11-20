"""Sigma rules (https://github.com/SigmaHQ/sigma) run straight on .evtx, with the standard library only.

    evtx-hunter logs/ --sigma sigma/rules/windows

What is supported: the YAML subset Sigma rules are written in; the whole condition grammar (and / or /
not, parentheses, `1 of sel_*`, `all of them`); the modifiers contains, startswith, endswith, all, re
(with i / m / s), cased, windash, base64, base64offset, utf16le / utf16be / wide, exists, cidr, lt / lte /
gt / gte, fieldref; `null` values and keyword lists; and Windows logsources mapped to the channels and
event ids that hold them. `process_creation` runs on Sysmon event 1 *and* on Security 4688, with the
field names translated (Image -> NewProcessName, ParentImage -> ParentProcessName...), so the rules work
on machines without Sysmon.

What is not: aggregations (`| count() by ...`), `near`, correlation rules, and logsources this mapping does
not know. Those rules are skipped and counted, never half-run.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .evtx import Event
from .rules import LEVELS, decode_powershell

SYSMON = "microsoft-windows-sysmon/operational"
PS_OP = "microsoft-windows-powershell/operational"

SERVICES = {
    "security": ["security"], "system": ["system"], "application": ["application"], "sysmon": [SYSMON],
    "powershell": [PS_OP], "powershell-classic": ["windows powershell"],
    "windefend": ["microsoft-windows-windows defender/operational"],
    "taskscheduler": ["microsoft-windows-taskscheduler/operational"],
    "wmi": ["microsoft-windows-wmi-activity/operational"],
    "bits-client": ["microsoft-windows-bits-client/operational"],
    "codeintegrity-operational": ["microsoft-windows-codeintegrity/operational"],
    "firewall-as": ["microsoft-windows-windows firewall with advanced security/firewall"],
    "terminalservices-localsessionmanager": ["microsoft-windows-terminalservices-localsessionmanager/operational"],
    "ntlm": ["microsoft-windows-ntlm/operational"], "smbclient-security": ["microsoft-windows-smbclient/security"],
    "dns-server": ["dns server"], "openssh": ["openssh/operational"],
    "driver-framework": ["microsoft-windows-driverframeworks-usermode/operational"],
    "printservice-operational": ["microsoft-windows-printservice/operational"],
    "appxdeployment-server": ["microsoft-windows-appxdeploymentserver/operational"],
    "applocker": ["microsoft-windows-applocker/exe and dll", "microsoft-windows-applocker/msi and script",
                  "microsoft-windows-applocker/packaged app-deployment", "microsoft-windows-applocker/packaged app-execution"],
    "diagnosis-scripted": ["microsoft-windows-diagnosis-scripted/operational"],
    "shell-core": ["microsoft-windows-shell-core/operational"],
    "lsa-server": ["microsoft-windows-lsa/operational"],
}

# Security 4688 carries the same facts as Sysmon 1 under other names
MAP_4688 = {"Image": "NewProcessName", "ParentImage": "ParentProcessName", "User": "SubjectUserName",
            "LogonId": "SubjectLogonId", "IntegrityLevel": "MandatoryLabel"}

SYSMON_CATEGORIES = {
    "process_termination": [5], "network_connection": [3], "dns_query": [22], "image_load": [7],
    "file_event": [11], "file_change": [2], "file_delete": [23, 26], "file_delete_detected": [26],
    "file_executable_detected": [29], "create_stream_hash": [15], "registry_add": [12], "registry_delete": [12],
    "registry_set": [13], "registry_rename": [14], "registry_event": [12, 13, 14], "process_access": [10],
    "create_remote_thread": [8], "raw_access_thread": [9], "driver_load": [6], "pipe_created": [17, 18],
    "wmi_event": [19, 20, 21], "sysmon_status": [4, 16], "sysmon_error": [255], "process_tampering": [25],
    "clipboard_capture": [24],
}


@dataclass
class Target:
    channels: frozenset
    event_ids: frozenset                   # empty: any event of those channels
    fieldmap: dict = field(default_factory=dict)


class SigmaError(ValueError):
    """The rule cannot be run faithfully; the reason is shown in the skip summary."""


# ── YAML: the subset Sigma rules use ────────────────────────────────────────

def _strip_comment(s: str) -> str:
    quote, i = None, 0
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == "'" == quote and s[i + 1:i + 2] == "'":
                i += 1                                           # '' is a quote inside a single-quoted string
            elif ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"" and (i == 0 or s[i - 1] in " \t:-[,"):
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
        i += 1
    return s.rstrip()


def _split_flow(s: str) -> list[str]:
    out, cur, quote = [], "", None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote, cur = ch, cur + ch
        elif ch == ",":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def scalar(s: str):
    s = s.strip()
    if not s:
        return None
    if s[0] == "'" and s.endswith("'") and len(s) > 1:
        return s[1:-1].replace("''", "'")
    if s[0] == '"' and s.endswith('"') and len(s) > 1:
        try:
            return json.loads(s)
        except ValueError:
            return s[1:-1]
    if s[0] == "[" and s.endswith("]"):
        return [scalar(x) for x in _split_flow(s[1:-1])]
    if s in ("null", "~", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def _key_value(text: str):
    """'key: value' -> (key, value text); None when the line is not a mapping entry."""
    if text[:1] in "'\"":
        q = text[0]
        end = text.find(q, 1)
        while end != -1 and q == "'" and text[end + 1:end + 2] == "'":
            end = text.find("'", end + 2)
        if end != -1 and text[end + 1:end + 2] == ":":
            return scalar(text[:end + 1]), text[end + 2:].strip()
        return None
    m = re.match(r"([^:\[{]+?):(?:\s+(.*)|\s*)$", text)
    return (m.group(1).strip(), (m.group(2) or "").strip()) if m else None


def _is_item(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("- ") or t == "-"


def load_yaml(text: str):
    """The first document of a YAML file, for the block-style subset Sigma rules are written in."""
    raw, lines, i = text.replace("\t", "    ").splitlines(), [], 0
    while i < len(raw):
        line = raw[i]
        if line.strip() in ("---", "..."):
            if lines:
                break
            i += 1
            continue
        body = _strip_comment(line)
        i += 1
        if not body.strip():
            continue
        ind = len(body) - len(body.lstrip())
        m = re.search(r":\s+([|>])[-+]?\d*$", body)
        if m:                                                    # a block scalar: gather it into one string
            block = []
            while i < len(raw) and (not raw[i].strip() or len(raw[i]) - len(raw[i].lstrip()) > ind):
                block.append(raw[i].strip())
                i += 1
            joined = ("\n" if m.group(1) == "|" else " ").join(block).strip()
            body = body[:m.start()] + ": " + json.dumps(joined, ensure_ascii=False)
        lines.append((ind, body))
    if not lines:
        return None
    return _block(lines, 0, lines[0][0])[0]


def _block(lines, i, ind):
    return _list(lines, i, ind) if _is_item(lines[i][1]) else _map(lines, i, ind)


def _value(lines, i, ind, text):
    """The value whose inline text is `text` (after 'key:' or '- '), at line i of indent ind."""
    j = i + 1
    if text:
        while j < len(lines) and lines[j][0] > ind and text[:1] not in "'\"[":
            text += " " + lines[j][1].strip()                    # a plain scalar folded over several lines
            j += 1
        return scalar(text), j
    if j < len(lines) and (lines[j][0] > ind or (lines[j][0] == ind and _is_item(lines[j][1]))):
        return _block(lines, j, lines[j][0])
    return None, j


def _map(lines, i, ind):
    out = {}
    while i < len(lines) and lines[i][0] == ind and not _is_item(lines[i][1]):
        kv = _key_value(lines[i][1].strip())
        if kv is None:
            raise SigmaError("YAML line not understood")
        out[kv[0]], i = _value(lines, i, ind, kv[1])
    return out, i


def _list(lines, i, ind):
    out = []
    while i < len(lines) and lines[i][0] == ind and _is_item(lines[i][1]):
        text = lines[i][1].strip()[1:].strip()
        kv = _key_value(text) if text else None
        if kv is not None:
            # "- key: value": a mapping whose other keys are indented to where "key" starts
            inner = ind + (len(lines[i][1].strip()) - len(text))
            sub, j = [(inner, text)], i + 1
            while j < len(lines) and lines[j][0] > ind:
                sub.append(lines[j])
                j += 1
            out.append(_map(sub, 0, inner)[0])
            i = j
        else:
            value, i = _value(lines, i, ind, text)
            out.append(value)
    return out, i


# ── values and modifiers ────────────────────────────────────────────────────

def _glob(value: str) -> str:
    """Sigma wildcards (* ?, backslash-escaped when literal) to a regex body."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)


def _b64_offsets(data: bytes) -> list[str]:
    starts, ends = (0, 2, 3), (None, -3, -2)
    return [base64.b64encode(b" " * i + data)[starts[i]:ends[(len(data) + i) % 3]].decode() for i in range(3)]


UNSUPPORTED = {"expand", "near", "count"}


def _compile_values(mods: list[str], values: list) -> Callable[[str | None, Callable], bool]:
    mods = [m.lower() for m in mods]
    for m in mods:
        if m in UNSUPPORTED or m not in {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased",
                                         "windash", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide",
                                         "exists", "cidr", "lt", "lte", "gt", "gte", "fieldref"}:
            raise SigmaError(f"modifier '{m}' not supported")
    need_all = "all" in mods
    if "exists" in mods:
        want = bool(values[0]) if values else True
        return lambda v, get: (v is not None) == want
    if "fieldref" in mods:
        names = [str(v) for v in values]
        check = all if need_all else any
        return lambda v, get: v is not None and check((get(n) or "").lower() == v.lower() for n in names)
    if any(m in mods for m in ("lt", "lte", "gt", "gte")):
        op = next(m for m in mods if m in ("lt", "lte", "gt", "gte"))
        cmp = {"lt": int.__lt__, "lte": int.__le__, "gt": int.__gt__, "gte": int.__ge__}[op]
        nums = [int(v) for v in values]

        def num(v, get):
            try:
                n = int(v, 0) if isinstance(v, str) else None
            except ValueError:
                return False
            return n is not None and any(cmp(n, x) for x in nums)
        return num
    if "cidr" in mods:
        nets = [ipaddress.ip_network(str(v), strict=False) for v in values]

        def in_net(v, get):
            try:
                ip = ipaddress.ip_address((v or "").strip().removeprefix("::ffff:"))
            except ValueError:
                return False
            return any(ip in n for n in nets)
        return in_net
    pats, nulls = [], False
    for v in values:
        if v is None:
            nulls = True
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        text = str(v)
        if "re" in mods:
            flags = (0 if "cased" in mods else 0) | (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
            try:
                pats.append(re.compile(text, flags))
            except re.error as e:
                raise SigmaError(f"bad regex: {e}") from None
            continue
        variants = [text]
        if any(m in mods for m in ("base64", "base64offset")):
            enc = "utf-16-le" if any(m in mods for m in ("utf16le", "utf16", "wide")) else "utf-16-be" if "utf16be" in mods else "utf-8"
            data = text.encode(enc)
            variants = _b64_offsets(data) if "base64offset" in mods else [base64.b64encode(data).decode()]
            body = "|".join(re.escape(x) for x in variants)
            literal = True
        else:
            body = _glob(text)
            if "windash" in mods:
                body = body.replace(r"\-", "-").replace("-", "[-/–—―]")   # every dash: - / – — ―
            literal = False
        if "contains" in mods or "base64offset" in mods:
            rx = f"(?:{body})"
        elif "startswith" in mods:
            rx = f"^(?:{body})"
        elif "endswith" in mods:
            rx = f"(?:{body})$"
        else:
            rx = f"^(?:{body})$"
        flags = re.S | (0 if "cased" in mods or literal else re.I)
        pats.append(re.compile(rx, flags))

    def match(v, get):
        if v is None or v == "":
            return nulls or (not pats and v == "")
        if not pats:
            return False
        hits = (p.search(v) is not None for p in pats)
        return all(hits) if need_all else any(hits)
    return match


# ── detection and condition ─────────────────────────────────────────────────

def _search(spec, where: str) -> Callable[[Callable, Event], bool]:
    """A search identifier: a map (AND of fields), a list of maps (OR), or keywords."""
    if isinstance(spec, dict):
        checks = []
        for key, values in spec.items():
            fieldname, *mods = str(key).split("|")
            values = values if isinstance(values, list) else [values]
            if not fieldname:                                   # "|contains": keywords with modifiers
                kw = _compile_values(mods or ["contains"], values)
                checks.append(lambda get, e, kw=kw: any(kw(v, get) for v in e.data.values()))
                continue
            fn = _compile_values(mods, values)
            checks.append(lambda get, e, f=fieldname, fn=fn: fn(get(f), get))
        return lambda get, e: all(c(get, e) for c in checks)
    if isinstance(spec, list) and spec and all(isinstance(x, dict) for x in spec):
        subs = [_search(x, where) for x in spec]
        return lambda get, e: any(s(get, e) for s in subs)
    if isinstance(spec, (list, str, int)):
        values = spec if isinstance(spec, list) else [spec]
        kw = _compile_values(["contains"], values)
        return lambda get, e: any(kw(v, get) for v in e.data.values())
    raise SigmaError(f"search '{where}' has an unreadable shape")


TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|\d+\s+of\b|all\s+of\b|any\s+of\b|[\w*\-.]+)", re.I)


def _condition(text: str, searches: dict) -> Callable[[Callable, Event], bool]:
    if "|" in text:
        raise SigmaError("aggregation in condition not supported")
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or not m.group(1):
            raise SigmaError(f"condition not understood near {text[pos:pos + 20]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    i = 0

    def names(pattern: str) -> list:
        if pattern == "them":
            return [k for k in searches if not k.startswith("_")]
        found = [k for k in searches if fnmatch.fnmatchcase(k, pattern)]
        if not found:
            raise SigmaError(f"condition names '{pattern}', which the rule does not define")
        return found

    def primary():
        nonlocal i
        if i >= len(tokens):
            raise SigmaError("condition ends too early")
        tok = tokens[i]
        low = tok.lower()
        if low == "(":
            i += 1
            inner = expr()
            if i >= len(tokens) or tokens[i] != ")":
                raise SigmaError("unbalanced parentheses in condition")
            i += 1
            return inner
        if low == "not":
            i += 1
            inner = primary()
            return lambda get, e: not inner(get, e)
        if re.fullmatch(r"(\d+|all|any)\s+of", low):
            i += 1
            if i >= len(tokens):
                raise SigmaError("'of' needs a name")
            subs = [searches[n] for n in names(tokens[i])]
            i += 1
            q = low.split()[0]
            if q == "all":
                return lambda get, e: all(s(get, e) for s in subs)
            n = 1 if q == "any" else int(q)
            return lambda get, e: sum(1 for s in subs if s(get, e)) >= n
        if tok not in searches:
            raise SigmaError(f"condition names '{tok}', which the rule does not define")
        i += 1
        return searches[tok]

    def conj():
        nonlocal i
        left = primary()
        while i < len(tokens) and tokens[i].lower() == "and":
            i += 1
            right = primary()
            left = (lambda a, b: lambda get, e: a(get, e) and b(get, e))(left, right)
        return left

    def expr():
        nonlocal i
        left = conj()
        while i < len(tokens) and tokens[i].lower() == "or":
            i += 1
            right = conj()
            left = (lambda a, b: lambda get, e: a(get, e) or b(get, e))(left, right)
        return left

    result = expr()
    if i != len(tokens):
        raise SigmaError(f"unexpected '{tokens[i]}' in condition")
    return result


def _targets(logsource: dict) -> list[Target]:
    if str(logsource.get("product", "")).lower() != "windows":
        raise SigmaError("not a Windows rule")
    category = str(logsource.get("category", "") or "").lower()
    service = str(logsource.get("service", "") or "").lower()
    if category == "process_creation":
        return [Target(frozenset([SYSMON]), frozenset([1])), Target(frozenset(["security"]), frozenset([4688]), MAP_4688)]
    if category in SYSMON_CATEGORIES:
        return [Target(frozenset([SYSMON]), frozenset(SYSMON_CATEGORIES[category]))]
    if category == "ps_script":
        return [Target(frozenset([PS_OP]), frozenset([4104]))]
    if category == "ps_module":
        return [Target(frozenset([PS_OP]), frozenset([4103]))]
    if category:
        raise SigmaError(f"logsource category '{category}' not mapped")
    if service in SERVICES:
        return [Target(frozenset(SERVICES[service]), frozenset())]
    raise SigmaError(f"logsource service '{service or '?'}' not mapped")


META = {"eventid": lambda e: str(e.event_id) if e.event_id is not None else None,
        "provider_name": lambda e: e.provider, "channel": lambda e: e.channel, "computer": lambda e: e.computer}


class SigmaRule:
    def __init__(self, doc: dict, source: str):
        if not isinstance(doc, dict) or "detection" not in doc:
            raise SigmaError("not a Sigma rule (no detection)")
        if doc.get("correlation") or doc.get("action"):
            raise SigmaError("correlation or collection rule not supported")
        self.title = str(doc.get("title") or Path(source).stem)
        rid = str(doc.get("id") or Path(source).stem)
        self.id = f"sigma:{rid}"
        level = str(doc.get("level", "medium")).lower()
        self.level = {"informational": "info"}.get(level, level)
        if self.level not in LEVELS:
            self.level = "medium"
        tags = [str(t).lower() for t in (doc.get("tags") or [])]
        self.mitre = tuple(t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t))
        self.description = str(doc.get("description") or "")
        self.targets = _targets(doc.get("logsource") or {})
        det = dict(doc["detection"])
        cond = det.pop("condition", None)
        det.pop("timeframe", None)
        if cond is None:
            raise SigmaError("no condition")
        searches = {k: _search(v, k) for k, v in det.items()}
        conds = cond if isinstance(cond, list) else [cond]
        compiled = [_condition(str(c), searches) for c in conds]
        self._match = lambda get, e: any(c(get, e) for c in compiled)
        self.fields = []
        for spec in det.values():
            for m in (spec if isinstance(spec, list) else [spec]):
                if isinstance(m, dict):
                    self.fields += [str(k).split("|")[0] for k in m if str(k).split("|")[0] not in self.fields]
        self.fields = [f for f in dict.fromkeys(self.fields) if f and f.lower() not in ("eventid", "provider_name", "channel")]

    def _getter(self, event: Event, target: Target):
        lower = None

        def get(name: str):
            nonlocal lower
            meta = META.get(name.lower())
            if meta:
                return meta(event)
            key = target.fieldmap.get(name, name)
            if key in event.data:
                return event.data[key]
            if lower is None:                       # Defender writes "New Value", Sigma says NewValue
                lower = {k.lower().replace(" ", ""): v for k, v in event.data.items()}
            return lower.get(key.lower().replace(" ", ""))
        return get

    def _target(self, event: Event) -> Target | None:
        ch = event.channel.lower()
        for t in self.targets:
            if ch in t.channels and (not t.event_ids or event.event_id in t.event_ids):
                return t
        return None

    def matches(self, event: Event) -> bool:
        t = self._target(event)
        return t is not None and self._match(self._getter(event, t), event)

    def summary(self, event: Event) -> str:
        t = self._target(event) or self.targets[0]
        get = self._getter(event, t)
        parts, decoded = [], None
        for f in self.fields[:4] + [x for x in ("CommandLine", "ScriptBlockText", "User") if x not in self.fields[:4]]:
            v = get(f)
            if v:
                decoded = decoded or decode_powershell(v)
                v = " ".join(str(v).split())
                parts.append(f"{f}={v if len(v) <= 160 else v[:157] + '...'}")
            if len(parts) >= 4:
                break
        if decoded:
            parts.append(f"decoded={decoded[:160]}")
        return " · ".join(parts)


@dataclass
class Loaded:
    rules: list
    skipped: dict                          # reason -> count
    files: int


def load(path: Path) -> Loaded:
    if os.name == "nt" and not str(path).startswith("\\\\?\\"):
        path = Path("\\\\?\\" + os.path.abspath(path))        # SigmaHQ's folders nest past MAX_PATH (260)
    files =sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml")) if path.is_dir() else [path]
    rules, skipped = [], {}
    for f in files:
        try:
            doc = load_yaml(f.read_text(encoding="utf-8-sig"))
            rules.append(SigmaRule(doc, str(f)))
        except (SigmaError, ValueError, TypeError, AttributeError, KeyError) as e:
            reason = re.sub(r"\s*'[^']*'", "", str(e)) if isinstance(e, SigmaError) else f"unreadable ({type(e).__name__})"   # group by kind, not by name
            reason = re.sub(r"\s+", " ", reason).rstrip(" :")
            skipped[reason] = skipped.get(reason, 0) + 1
        except OSError as e:
            skipped[f"cannot read file ({e.strerror})"] = skipped.get(f"cannot read file ({e.strerror})", 0) + 1
    return Loaded(rules, skipped, len(files))
