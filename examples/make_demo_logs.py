"""Regenerate examples/demo/*.evtx: a fictional intrusion written as real event logs.

    python examples/make_demo_logs.py
    evtx-hunter examples/demo
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from demo_story import build_story  # noqa: E402

if __name__ == "__main__":
    for path in build_story(Path(__file__).resolve().parent / "demo"):
        print("wrote", path)
