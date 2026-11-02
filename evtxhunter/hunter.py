"""Run every rule and correlation over a set of logs, plus integrity checks on the logs themselves."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .correlate import Correlator, Settings
from .evtx import FileInfo, ParseError, read_events
from .findings import Finding
from .rules import Rule, rank


@dataclass
class LogStats:
    path: str
    events: int = 0
    errors: int = 0
    chunks: int = 0
    dirty: bool = False
    first: datetime | None = None
    last: datetime | None = None
    bad_checksums: list[str] = field(default_factory=list)
    missing: list[tuple[int, int]] = field(default_factory=list)   # (first missing id, last missing id)
    recovered: list[int] = field(default_factory=list)             # hidden records we brought back
    error: str | None = None

    @property
    def intact(self) -> bool:
        return not (self.bad_checksums or self.missing or self.recovered or self.errors or self.error)


def missing_ranges(ids: list[int]) -> list[tuple[int, int]]:
    """Gaps inside a log's record-id sequence. Windows numbers records contiguously and a wrapped
    log drops its *oldest* records, so a hole in the middle means records were removed."""
    ids = sorted(set(ids))
    return [(a + 1, b - 1) for a, b in zip(ids, ids[1:]) if b - a > 1]


def aggregate(findings: list[Finding]) -> list[Finding]:
    """Fold repeats of the same finding into one with a count and a time span."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        k = f.key()
        if k not in merged:
            merged[k] = f
            continue
        m = merged[k]
        m.count += f.count
        times = [t for t in (m.time, m.last_time, f.time, f.last_time) if t]
        if times:
            m.time, m.last_time = min(times), max(times)
    return list(merged.values())


def hunt(paths: list[Path], rules: list[Rule], settings: Settings | None = None,
         since: datetime | None = None, until: datetime | None = None,
         min_level: str = "info") -> tuple[list[Finding], list[LogStats]]:
    correlator = Correlator(settings)
    findings: list[Finding] = []
    stats: list[LogStats] = []
    for path in paths:
        st = LogStats(str(path))
        stats.append(st)
        info = FileInfo(str(path))
        ids: list[int] = []
        times: dict[int, datetime] = {}
        source = path.name
        try:
            for event in read_events(str(path), info):
                ids.append(event.record_id)               # hidden ones too: they explain their own gap
                source = f"{path.name} (recovered)" if event.recovered else path.name
                if event.time:
                    times[event.record_id] = event.time
                    st.first = min(st.first, event.time) if st.first else event.time
                    st.last = max(st.last, event.time) if st.last else event.time
                if event.time and ((since and event.time < since) or (until and event.time > until)):
                    continue
                for rule in rules:
                    if rule.matches(event):
                        findings.append(Finding(event.time, rule.level, rule.title, rule.id, rule.mitre,
                                                event.computer, rule.summary(event), source, event.record_id,
                                                event.event_id))
                correlator.feed(event, source)
        except (ParseError, OSError) as e:
            st.error = str(e)
        st.events, st.errors, st.chunks = info.records, info.errors, info.chunks
        st.dirty, st.bad_checksums, st.recovered = info.dirty, info.bad_checksums, sorted(info.recovered)
        st.missing = missing_ranges(ids)
        findings += _integrity_findings(st, path.name, times)

    findings += correlator.run()
    findings = [f for f in aggregate(findings) if rank(f.level) >= rank(min_level)]
    findings.sort(key=_sort_key)
    return findings, stats


def _sort_key(f: Finding):
    return (f.time.timestamp() if f.time else float("-inf"), -rank(f.level))


def _ranges(ids: list[int]) -> str:
    spans, start = [], None
    for i, rid in enumerate(ids):
        if start is None:
            start = rid
        if i + 1 == len(ids) or ids[i + 1] != rid + 1:
            spans.append(str(start) if start == rid else f"{start}-{rid}")
            start = None
    return ", ".join(spans[:5]) + (" ..." if len(spans) > 5 else "")


def _integrity_findings(st: LogStats, source: str, times: dict[int, datetime]) -> list[Finding]:
    out = []
    if st.recovered:
        n = len(st.recovered)
        out.append(Finding(times.get(st.recovered[0]), "critical",
                           "Records hidden inside other records (log tampering), recovered", "hidden-records",
                           ("T1070",), "",
                           f"{n} record{'s' if n != 1 else ''} invisible to Windows recovered from slack space: "
                           f"ids {_ranges(st.recovered)}; their findings are marked '(recovered)'", source))
    if st.missing:
        total = sum(b - a + 1 for a, b in st.missing)
        shown = ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in st.missing[:5])
        when = times.get(st.missing[0][0] - 1)
        out.append(Finding(when, "high", "Event records missing from the middle of the log", "record-gap",
                           ("T1070",), "", f"{total} record{'s' if total != 1 else ''} removed: ids {shown}"
                           + (" ..." if len(st.missing) > 5 else ""), source))
    if st.bad_checksums:
        out.append(Finding(None, "medium", "Log integrity checksum mismatch", "checksum-mismatch", ("T1070",), "",
                           f"{', '.join(st.bad_checksums[:5])} (edited or corrupted after it was written)",
                           source))
    return out
