"""Command-line entry point. Exit codes: 0 nothing at/above --fail-on · 1 findings at/above it · 2 error."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .correlate import Settings
from .hunter import LogStats, hunt
from .rules import LEVELS, RuleError, load_builtin, load_path, rank

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
UNICODE = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "info": "·", "sep": "·", "fix": "└",
           "arrow": "→", "ok": "✔"}
ASCII = {"critical": "X", "high": "x", "medium": "!", "low": "-", "info": ".", "sep": "|", "fix": "`-",
         "arrow": "->", "ok": "+"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="evtx-hunter",
        description="Hunt for attacker activity in Windows .evtx logs: a from-scratch parser, ATT&CK-mapped "
                    "rules, multi-event correlation and log-tampering checks. Zero dependencies.")
    ap.add_argument("paths", nargs="+", type=Path, help=".evtx files or directories")
    ap.add_argument("-r", "--recursive", action="store_true", help="search directories recursively")
    ap.add_argument("--rules", action="append", type=Path, default=[], metavar="PATH",
                    help="extra rule file or directory of *.json rules (repeatable)")
    ap.add_argument("--no-builtin", action="store_true", help="skip the built-in rules")
    ap.add_argument("--min-level", choices=LEVELS, default="low", help="hide findings below this (default: low)")
    ap.add_argument("--fail-on", choices=LEVELS, default="high",
                    help="lowest level that makes the exit code 1 (default: high)")
    ap.add_argument("--since", metavar="DATE", help="only events at/after this UTC date or datetime")
    ap.add_argument("--until", metavar="DATE", help="only events at/before this UTC date or datetime")
    ap.add_argument("--brute-threshold", type=int, default=10, metavar="N",
                    help="failed logons in 10 minutes that count as brute force (default: 10)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--csv", type=Path, metavar="FILE", help="also write the timeline to a CSV file")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def parse_date(text: str | None, end_of_day: bool = False) -> datetime | None:
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d" and end_of_day:
            dt += timedelta(days=1) - timedelta(microseconds=1)
        return dt
    raise ValueError(f"unrecognised date {text!r} (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")


def collect(paths: list[Path], recursive: bool) -> list[Path]:
    files = []
    for p in paths:
        # resolve "..\.." away: on Windows an unresolved relative path can blow past MAX_PATH (260)
        p = p.resolve()
        if p.is_dir():
            files += sorted(p.rglob("*.evtx") if recursive else p.glob("*.evtx"))
        elif p.is_file():
            files.append(p)
        else:
            print(f"evtx-hunter: no such file or directory: {p}", file=sys.stderr)
    return files


def _glyphs(stream) -> dict:
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _when(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-" * 19


def render(findings, stats: list[LogStats], elapsed: float, color: bool, g: dict) -> str:
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    sep = f"  {g['sep']}  "
    total = sum(s.events for s in stats)
    firsts = [s.first for s in stats if s.first]
    lasts = [s.last for s in stats if s.last]
    span = f"{min(firsts):%Y-%m-%d} {g['arrow']} {max(lasts):%Y-%m-%d}" if firsts else "no events"
    lines = [paint(f" evtx-hunter v{__version__}", "1;36") +
             paint(f"{sep}{len(stats)} log(s){sep}{total:,} events{sep}{span}{sep}{elapsed:.1f}s", "2"), "",
             paint(" LOGS", "1")]
    width = max((len(Path(s.path).name) for s in stats), default=10)
    for s in stats:
        if s.error:
            state = paint(f"unreadable: {s.error}", "31")
        elif s.intact:
            state = paint(f"{g['ok']} intact", "32")
        else:
            problems = []
            if s.recovered:
                problems.append(_plural(len(s.recovered), "hidden record") + " recovered")
            if s.missing:
                problems.append(_plural(sum(b - a + 1 for a, b in s.missing), "record") + " missing")
            if s.bad_checksums:
                problems.append("checksum mismatch")
            if s.errors:
                problems.append(_plural(s.errors, "unreadable record"))
            state = paint(f"{g['high']} {', '.join(problems)}", "31")
        dirty = paint("  (dirty: copied while in use)", "2") if s.dirty else ""
        lines.append(f"   {Path(s.path).name:<{width}}  {s.events:>8,} events  {state}{dirty}")
    lines.append("")

    if not findings:
        lines.append(paint(" nothing found at or above the selected level", "32"))
        return "\n".join(lines)

    lines.append(paint(" FINDINGS  (UTC timeline)", "1"))
    title_w = min(58, max(len(f.title) for f in findings))
    for f in findings:
        color_code = COLORS[f.level]
        badge = paint(f"{g[f.level]} {f.level.upper():<8}", color_code)
        repeat = paint(f" ×{f.count}", "1") if f.count > 1 else ""
        mitre = paint(" ".join(f.mitre), "35")
        where = paint(f.computer or f.source, "2")
        recovered = paint("  [recovered: hidden from Windows]", "1;35") if f.source.endswith("(recovered)") else ""
        lines.append(f"  {_when(f.time)}  {badge} {f.title:<{title_w}}{repeat}  {mitre}  {where}{recovered}")
        detail = f.summary
        if f.count > 1 and f.last_time and f.time and f.last_time != f.time:
            detail += f"  (until {_when(f.last_time)})"
        if detail:
            lines.append(f"  {' ' * 19}  {' ' * 10} " + paint(f"{g['fix']} {detail}", "2"))
    lines.append("")
    counts = [paint(f"{sum(f.level == lv for f in findings)} {lv}", COLORS[lv]) for lv in reversed(LEVELS)
              if any(f.level == lv for f in findings)]
    techniques = sorted({t for f in findings for t in f.mitre})
    lines.append(" " + paint(sep, "2").join(counts) + (paint(f"{sep}ATT&CK: ", "2") + paint(" ".join(techniques), "35")
                                                       if techniques else ""))
    return "\n".join(lines)


def _finding_dict(f) -> dict:
    return {"time": f.time.isoformat() if f.time else None, "level": f.level, "title": f.title,
            "rule_id": f.rule_id, "mitre": list(f.mitre), "computer": f.computer, "summary": f.summary,
            "source": f.source, "record_id": f.record_id, "event_id": f.event_id, "count": f.count,
            "last_time": f.last_time.isoformat() if f.last_time else None}


def _stats_dict(s: LogStats) -> dict:
    return {"path": s.path, "events": s.events, "unreadable_records": s.errors, "chunks": s.chunks,
            "dirty": s.dirty, "first": s.first.isoformat() if s.first else None,
            "last": s.last.isoformat() if s.last else None, "bad_checksums": s.bad_checksums,
            "missing_record_ranges": s.missing, "recovered_record_ids": s.recovered, "intact": s.intact,
            "error": s.error}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        since, until = parse_date(args.since), parse_date(args.until, end_of_day=True)
        rules = [] if args.no_builtin else load_builtin()
        for p in args.rules:
            rules += load_path(p)
    except (RuleError, ValueError, OSError) as e:
        print(f"evtx-hunter: {e}", file=sys.stderr)
        return 2
    files = collect(args.paths, args.recursive)
    if not files:
        print("evtx-hunter: no .evtx files to scan", file=sys.stderr)
        return 2

    started = time.perf_counter()
    findings, stats = hunt(files, rules, Settings(brute_threshold=args.brute_threshold), since, until,
                           args.min_level)
    elapsed = time.perf_counter() - started

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(_finding_dict(findings[0]) if findings else
                                                        ["time", "level", "title"]))
            writer.writeheader()
            for f in findings:
                row = _finding_dict(f)
                row["mitre"] = " ".join(row["mitre"])
                writer.writerow(row)
    if args.json:
        print(json.dumps({"version": __version__, "logs": [_stats_dict(s) for s in stats],
                          "findings": [_finding_dict(f) for f in findings]}, indent=2))
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        print(render(findings, stats, elapsed, color, _glyphs(sys.stdout)))

    if all(s.error for s in stats):
        return 2
    return 1 if any(rank(f.level) >= rank(args.fail_on) for f in findings) else 0
