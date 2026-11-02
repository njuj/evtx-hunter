"""Detections that need more than one event: brute force, password spraying, Kerberoasting and
"new account straight into an admin group". Single-event rules can't see any of these."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .evtx import Event
from .findings import Finding

PRIVILEGED_GROUP_SUFFIXES = ("-544", "-548", "-549", "-551", "-512", "-518", "-519")
NOT_AN_ADDRESS = {"", "-", "::1", "127.0.0.1"}
WANTED = {4624, 4625, 4720, 4728, 4732, 4756, 4769}


@dataclass
class Settings:
    brute_threshold: int = 10
    brute_window: timedelta = timedelta(minutes=10)
    spray_accounts: int = 5
    spray_window: timedelta = timedelta(minutes=30)
    kerberoast_services: int = 3
    kerberoast_window: timedelta = timedelta(minutes=30)
    admin_window: timedelta = timedelta(hours=24)


def _duration(delta: timedelta) -> str:
    s = int(delta.total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def bursts(times: list, window: timedelta, threshold: int) -> list[tuple[int, int]]:
    """Maximal index ranges [i, j] in which at least `threshold` sorted timestamps fit inside `window`."""
    out: list[tuple[int, int]] = []
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        if right - left + 1 >= threshold:
            if out and left <= out[-1][1]:
                out[-1] = (out[-1][0], right)
            else:
                out.append((left, right))
    return out


class Correlator:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.events: dict[int, list[tuple[Event, str]]] = defaultdict(list)

    def feed(self, event: Event, source: str) -> None:
        if event.event_id in WANTED and event.time and event.channel.lower() == "security":
            self.events[event.event_id].append((event, source))

    def run(self) -> list[Finding]:
        for items in self.events.values():
            items.sort(key=lambda pair: pair[0].time)
        return self._brute_force() + self._spraying() + self._kerberoasting() + self._new_admin()

    # ── brute force (+ did it work?) ──
    def _brute_force(self) -> list[Finding]:
        s = self.settings
        groups: dict[tuple, list] = defaultdict(list)
        for e, src in self.events[4625]:
            groups[(e.get("TargetUserName").lower(), e.get("IpAddress"), e.computer)].append((e, src))
        findings = []
        for (user, ip, computer), items in groups.items():
            times = [e.time for e, _ in items]
            for i, j in bursts(times, s.brute_window, s.brute_threshold):
                first, last = items[i][0], items[j][0]
                origin = f"from {ip}" if ip not in NOT_AN_ADDRESS else "from the local machine"
                types = ",".join(sorted({e.get("LogonType") for e, _ in items[i:j + 1] if e.get("LogonType")}))
                summary = (f"{j - i + 1} failed logons for '{user}' {origin} in "
                           f"{_duration(last.time - first.time)} (logon type {types or '?'})")
                findings.append(Finding(first.time, "high", "Brute-force logon attempts", "brute-force",
                                        ("T1110.001",), computer, summary, items[i][1], first.record_id, 4625,
                                        count=j - i + 1, last_time=last.time))
                success = self._success_after(user, ip, computer, first.time, last.time + s.brute_window)
                if success:
                    e, src = success
                    findings.append(Finding(
                        e.time, "critical", "Brute force succeeded", "brute-force-success", ("T1110",), computer,
                        f"{summary}, then a successful logon for '{user}' "
                        f"(type {e.get('LogonType') or '?'}) at {e.time:%H:%M:%S}", src, e.record_id, 4624))
        return findings

    def _success_after(self, user, ip, computer, start, end):
        for e, src in self.events[4624]:
            if e.time < start or e.time > end or e.computer != computer:
                continue
            if e.get("TargetUserName").lower() != user:
                continue
            if ip in NOT_AN_ADDRESS or e.get("IpAddress") == ip:
                return e, src
        return None

    # ── one address, many accounts ──
    def _spraying(self) -> list[Finding]:
        s = self.settings
        by_ip: dict[tuple, list] = defaultdict(list)
        for e, src in self.events[4625]:
            ip = e.get("IpAddress")
            if ip not in NOT_AN_ADDRESS:
                by_ip[(ip, e.computer)].append((e, src))
        findings = []
        for (ip, computer), items in by_ip.items():
            left, users, best = 0, Counter(), None
            for right, (e, _) in enumerate(items):
                users[e.get("TargetUserName").lower()] += 1
                while e.time - items[left][0].time > s.spray_window:
                    old = items[left][0].get("TargetUserName").lower()
                    users[old] -= 1
                    if not users[old]:
                        del users[old]
                    left += 1
                if len(users) >= s.spray_accounts and (best is None or len(users) > best[2]):
                    best = (left, right, len(users))
            if best:
                i, j, n = best
                first, last = items[i][0], items[j][0]
                findings.append(Finding(
                    first.time, "high", "Password spraying", "password-spray", ("T1110.003",), computer,
                    f"{ip} tried {n} different accounts ({j - i + 1} failures) in "
                    f"{_duration(last.time - first.time)}", items[i][1], first.record_id, 4625,
                    count=j - i + 1, last_time=last.time))
        return findings

    # ── many RC4 service tickets for one requester ──
    def _kerberoasting(self) -> list[Finding]:
        s = self.settings
        by_requester: dict[tuple, list] = defaultdict(list)
        for e, src in self.events[4769]:
            service = e.get("ServiceName").lower()
            if e.get("TicketEncryptionType").lower() not in ("0x17", "0x18"):
                continue
            if service.endswith("$") or service.startswith("krbtgt") or e.get("Status", "0x0").lower() != "0x0":
                continue
            by_requester[(e.get("TargetUserName").lower(), e.computer)].append((e, src))
        findings = []
        for (requester, computer), items in by_requester.items():
            left, services, best = 0, Counter(), None
            for right, (e, _) in enumerate(items):
                services[e.get("ServiceName").lower()] += 1
                while e.time - items[left][0].time > s.kerberoast_window:
                    old = items[left][0].get("ServiceName").lower()
                    services[old] -= 1
                    if not services[old]:
                        del services[old]
                    left += 1
                if len(services) >= s.kerberoast_services and (best is None or len(services) > best[2]):
                    best = (left, right, len(services), sorted(services))
            if best:
                i, j, n, names = best
                first = items[i][0]
                findings.append(Finding(
                    first.time, "high", "Kerberoasting: RC4 service tickets for many accounts", "kerberoasting",
                    ("T1558.003",), computer,
                    f"'{requester}' requested RC4 tickets for {n} services: {', '.join(names[:6])}"
                    + (" ..." if n > 6 else ""), items[i][1], first.record_id, 4769,
                    count=j - i + 1, last_time=items[j][0].time))
        return findings

    # ── created, then promoted ──
    def _new_admin(self) -> list[Finding]:
        s = self.settings
        additions = self.events[4728] + self.events[4732] + self.events[4756]
        findings = []
        for created, src in self.events[4720]:
            sid = created.get("TargetSid")
            if not sid:
                continue
            for added, added_src in additions:
                group_sid = added.get("TargetSid")
                if added.get("MemberSid") != sid or not group_sid.endswith(PRIVILEGED_GROUP_SUFFIXES):
                    continue
                if not (created.time <= added.time <= created.time + s.admin_window):
                    continue
                findings.append(Finding(
                    added.time, "critical", "New account added straight to a privileged group", "new-admin",
                    ("T1136.001", "T1098"), added.computer,
                    f"'{created.get('TargetUserName')}' created by '{created.get('SubjectUserName')}', then added to "
                    f"'{added.get('TargetUserName')}' {_duration(added.time - created.time)} later",
                    added_src, added.record_id, added.event_id))
        return findings
