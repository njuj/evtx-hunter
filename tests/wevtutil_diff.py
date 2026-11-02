"""Differential check: evtx-hunter's parser vs. Windows' own decoder (`wevtutil qe /f:xml`).

Every event is compared field by field. Usable as a module (from the test suite) or a script:

    python tests/wevtutil_diff.py some.evtx [more.evtx ...]
"""

from __future__ import annotations

import collections
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evtxhunter.evtx import FileInfo, read_events  # noqa: E402

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def wevtutil_available() -> bool:
    return shutil.which("wevtutil") is not None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _ref_time(s: str | None):
    if not s:
        return None
    head, _, frac = s.rstrip("Z").partition(".")
    dt = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S")
    return dt.replace(microsecond=int((frac + "000000")[:6]) if frac else 0, tzinfo=timezone.utc)


def reference_events(path: str) -> dict[int, dict]:
    """Events as Windows decodes them, keyed by record id."""
    # /uni:true makes wevtutil emit UTF-16, so non-ASCII text survives (the console codepage turns it into '?')
    out = subprocess.run(["wevtutil", "qe", path, "/lf:true", "/f:xml", "/uni:true"], capture_output=True,
                         check=True)
    raw = out.stdout
    text = raw.decode("utf-16-le" if raw[1:2] == b"\x00" or raw[:2] == b"\xff\xfe" else "utf-8", "replace")
    text = text.lstrip("﻿")
    root = ET.fromstring(f"<Events>{text}</Events>")
    events = {}
    for ev in root:
        system = ev.find(f"{NS}System")
        get = lambda name: system.find(f"{NS}{name}")  # noqa: E731
        rec = {
            "event_id": int(get("EventID").text),
            "provider": get("Provider").get("Name", ""),
            "channel": (get("Channel").text or "") if get("Channel") is not None else "",
            "computer": (get("Computer").text or "") if get("Computer") is not None else "",
            "time": _ref_time(get("TimeCreated").get("SystemTime")) if get("TimeCreated") is not None else None,
            "level": int(get("Level").text) if get("Level") is not None and get("Level").text else None,
            "user_sid": get("Security").get("UserID") if get("Security") is not None else None,
            "pid": int(get("Execution").get("ProcessID")) if get("Execution") is not None
            and get("Execution").get("ProcessID") else None,
            "data": {},
        }
        for section in ("EventData", "UserData"):
            node = ev.find(f"{NS}{section}")
            if node is None:
                continue
            leaves = [n for n in node.iter() if n is not node and len(n) == 0]
            for leaf in leaves:
                key = leaf.get("Name") or _local(leaf.tag)
                if key in rec["data"]:
                    i = 2
                    while f"{key}_{i}" in rec["data"]:
                        i += 1
                    key = f"{key}_{i}"
                rec["data"][key] = leaf.text or ""
        events[int(get("EventRecordID").text)] = rec
    return events


def compare(path: str) -> dict:
    ref = reference_events(path)
    info = FileInfo(path)
    mine = {e.record_id: e for e in read_events(path, info)}
    fields = ("event_id", "provider", "channel", "computer", "time", "level", "user_sid", "pid")
    mismatches = collections.Counter()
    examples = {}
    compared = values_compared = 0
    for rid, r in ref.items():
        e = mine.get(rid)
        if e is None:
            mismatches["missing record"] += 1
            continue
        compared += 1
        for f in fields:
            if getattr(e, f) != r[f]:
                mismatches[f] += 1
                examples.setdefault(f, (rid, getattr(e, f), r[f]))
        for key in set(r["data"]) | set(e.data):
            values_compared += 1
            # an XML parser turns \r\n (and lone \r) into \n, so normalise ours the same way before comparing
            a = e.data.get(key, "").replace("\r\n", "\n").replace("\r", "\n")
            b = r["data"].get(key, "")
            if a != b:
                tag = f"data:{e.provider}:{key}"
                mismatches[tag] += 1
                examples.setdefault(tag, (rid, a[:80], b[:80]))
    return {"path": path, "reference": len(ref), "parsed": len(mine), "compared": compared,
            "values_compared": values_compared, "parse_errors": info.errors,
            "mismatches": mismatches, "examples": examples}


if __name__ == "__main__":
    for p in sys.argv[1:]:
        res = compare(p)
        total = sum(res["mismatches"].values())
        print(f"{Path(p).name}: windows={res['reference']} parsed={res['parsed']} events compared={res['compared']} "
              f"fields+values compared={res['compared'] * 8 + res['values_compared']} mismatches={total}")
        for k, n in res["mismatches"].most_common(15):
            print(f"   {n:6}  {k}   e.g. {res['examples'].get(k)}")
