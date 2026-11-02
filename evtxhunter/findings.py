from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Finding:
    time: datetime | None
    level: str
    title: str
    rule_id: str
    mitre: tuple
    computer: str
    summary: str
    source: str
    record_id: int | None = None
    event_id: int | None = None
    count: int = 1
    last_time: datetime | None = None

    def key(self) -> tuple:
        return (self.rule_id, self.computer, self.summary)
