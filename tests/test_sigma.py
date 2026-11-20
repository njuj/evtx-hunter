"""Sigma rules on events: the YAML subset, the condition grammar, every supported modifier, the Windows
logsource mapping (Security 4688 as well as Sysmon 1) and what is skipped instead of half-run.
The rules here are written for the tests in Sigma's own format."""

import base64
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from evtxhunter import sigma
from evtxhunter.evtx import Event

T0 = datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc)
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def ev(event_id, data, channel=SYSMON, provider="Microsoft-Windows-Sysmon"):
    return Event(1, event_id, provider, channel, "WS01", T0, data=data)


def rule(text):
    return sigma.SigmaRule(sigma.load_yaml(text), "test.yml")


CERTUTIL = r"""
title: Certutil Download # trailing comment
id: 11111111-2222-3333-4444-555555555555
status: test
description: |
    Detects certutil used to fetch a file:
    a classic living-off-the-land download.
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains|windash:
            - '-urlcache '
            - '-verifyctl '
    filter_main_msi:
        ParentImage|endswith: '\msiexec.exe'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
"""


class Yaml(unittest.TestCase):
    def test_sigma_shapes(self):
        doc = sigma.load_yaml(CERTUTIL)
        self.assertEqual(doc["title"], "Certutil Download")
        self.assertEqual(doc["description"], "Detects certutil used to fetch a file:\na classic living-off-the-land download.")
        self.assertEqual(doc["tags"], ["attack.command-and-control", "attack.t1105"])
        self.assertEqual(doc["detection"]["selection_img"], [{"Image|endswith": "\\certutil.exe"},
                                                             {"OriginalFileName": "CertUtil.exe"}])
        self.assertEqual(doc["detection"]["selection_cli"]["CommandLine|contains|windash"], ["-urlcache ", "-verifyctl "])

    def test_scalars_flow_lists_and_quotes(self):
        doc = sigma.load_yaml("a: 'it''s # not a comment'\nb: \"x\\ty\"\nc: [1, 'two', three]\nd: null\ne: true\n"
                              "f: 4688\ng:\n- top-level item\n- \"#hash\"\n")
        self.assertEqual(doc, {"a": "it's # not a comment", "b": "x\ty", "c": [1, "two", "three"], "d": None,
                               "e": True, "f": 4688, "g": ["top-level item", "#hash"]})

    def test_folded_plain_scalar_and_second_document(self):
        doc = sigma.load_yaml("title: a long\n    title folded\nlevel: low\n---\ntitle: second\n")
        self.assertEqual(doc, {"title": "a long title folded", "level": "low"})


class Matching(unittest.TestCase):
    def test_process_creation_on_sysmon_and_on_security_4688(self):
        r = rule(CERTUTIL)
        self.assertEqual((r.level, r.mitre, r.id), ("high", ("T1105",), "sigma:11111111-2222-3333-4444-555555555555"))
        sysmon = ev(1, {"Image": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil -urlcache -f http://x/a a",
                        "ParentImage": r"C:\Windows\explorer.exe"})
        security = ev(4688, {"NewProcessName": r"C:\Windows\System32\CERTUTIL.EXE",
                             "CommandLine": "certutil /urlcache -f http://x/a a",     # windash: / for -
                             "ParentProcessName": r"C:\Windows\explorer.exe"},
                      channel="Security", provider="Microsoft-Windows-Security-Auditing")
        self.assertTrue(r.matches(sysmon))
        self.assertTrue(r.matches(security))
        self.assertIn("Image=C:\\Windows\\System32\\CERTUTIL.EXE", r.summary(security))
        excluded = ev(1, {**sysmon.data, "ParentImage": r"C:\Windows\System32\msiexec.exe"})
        self.assertFalse(r.matches(excluded))
        self.assertFalse(r.matches(ev(1, {**sysmon.data, "CommandLine": "certutil -hashfile a"})))
        self.assertFalse(r.matches(ev(3, sysmon.data)))                  # a network event is another category

    def test_condition_grammar(self):
        r = rule("""
title: grammar
logsource: {product: windows, service: security}
""".replace("logsource: {product: windows, service: security}", "logsource:\n    product: windows\n    service: security") + """
detection:
    a:
        EventID: 4625
    b:
        TargetUserName: 'admin'
    c:
        TargetUserName: 'root'
    k_one:
        IpAddress|startswith: '10.'
    k_two:
        IpAddress|startswith: '192.168.'
    condition: a and (b or c) and not 1 of k_*
""")
        sec = lambda **d: ev(d.pop("eid", 4625), d, channel="Security", provider="x")
        self.assertTrue(r.matches(sec(TargetUserName="ROOT", IpAddress="203.0.113.5")))
        self.assertFalse(r.matches(sec(TargetUserName="root", IpAddress="10.0.0.5")))
        self.assertFalse(r.matches(sec(TargetUserName="bob", IpAddress="203.0.113.5")))
        self.assertFalse(r.matches(sec(eid=4624, TargetUserName="root", IpAddress="203.0.113.5")))

    def modifier_rule(self, detection):
        return rule("title: m\nlogsource:\n    product: windows\n    service: sysmon\ndetection:\n" + detection +
                    "\n    condition: sel\n")

    def test_modifiers(self):
        cases = [
            ("    sel:\n        CommandLine|contains|all:\n            - 'a b'\n            - 'zz'", "x a b y zz", "a b only"),
            ("    sel:\n        CommandLine|re: '^cmd\\.exe /c (whoami|hostname)$'", "cmd.exe /c whoami", "CMD.EXE /c whoami"),
            ("    sel:\n        CommandLine|re|i: '^cmd\\.exe'", "CMD.EXE /c x", "powershell"),
            ("    sel:\n        CommandLine|cased: 'Exact'", "Exact", "exact"),
            ("    sel:\n        Image: 'C:\\Windows\\Sys*\\cmd.ex?'", "c:\\windows\\system32\\cmd.exe", "c:\\windows\\cmd.exe"),
            ("    sel:\n        DestinationIp|cidr: '10.0.0.0/8'", "10.20.30.40", "11.0.0.1"),
            ("    sel:\n        DestinationPort|gte: 1024", "4444", "443"),
            ("    sel:\n        CommandLine|contains|base64offset: 'Invoke-Mimi'",
             "powershell -e " + base64.b64encode(b"xxInvoke-Mimix").decode(), "powershell -e AAAA"),
            ("    sel:\n        CommandLine|base64offset|contains|utf16le: 'IEX'",
             "powershell -enc " + base64.b64encode("x;IEX(x)".encode("utf-16-le")).decode(), "powershell -enc AAAA"),
        ]
        for detection, yes, no in cases:
            r = self.modifier_rule(detection)
            field = detection.split("\n")[1].strip().split("|")[0].split(":")[0]
            self.assertTrue(r.matches(ev(1, {field: yes})), detection)
            self.assertFalse(r.matches(ev(1, {field: no})), detection)

    def test_null_exists_fieldref_and_keywords(self):
        r = self.modifier_rule("    sel:\n        Image|endswith: '.exe'\n        OriginalFileName: null")
        self.assertTrue(r.matches(ev(1, {"Image": "a.exe"})))
        self.assertFalse(r.matches(ev(1, {"Image": "a.exe", "OriginalFileName": "b.exe"})))
        r = self.modifier_rule("    sel:\n        ParentImage|exists: false")
        self.assertTrue(r.matches(ev(1, {"Image": "a"})))
        self.assertFalse(r.matches(ev(1, {"ParentImage": "a"})))
        r = self.modifier_rule("    sel:\n        Image|fieldref: ParentImage")
        self.assertTrue(r.matches(ev(1, {"Image": "C:\\x.exe", "ParentImage": "c:\\X.EXE"})))
        self.assertFalse(r.matches(ev(1, {"Image": "C:\\x.exe", "ParentImage": "C:\\y.exe"})))
        r = self.modifier_rule("    sel:\n        - 'mimikatz'\n        - 'sekurlsa'")
        self.assertTrue(r.matches(ev(1, {"CommandLine": "run MIMIKATZ now"})))
        self.assertFalse(r.matches(ev(1, {"CommandLine": "notepad"})))

    def test_field_names_with_spaces(self):
        # Defender writes "New Value"; Sigma rules say NewValue
        r = rule("title: d\nlogsource:\n    product: windows\n    service: windefend\ndetection:\n    sel:\n"
                 "        EventID: 5007\n        NewValue|contains: '\\Exclusions'\n    condition: sel\n")
        self.assertTrue(r.matches(ev(5007, {"New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\x"},
                                     channel="Microsoft-Windows-Windows Defender/Operational", provider="d")))


class Skipped(unittest.TestCase):
    def assert_skip(self, text, why):
        with self.assertRaises(sigma.SigmaError) as cm:
            rule(text)
        self.assertIn(why, str(cm.exception))

    def test_what_is_never_half_run(self):
        base = "title: s\nlogsource:\n    product: windows\n    service: security\ndetection:\n    sel:\n        EventID: 4625\n"
        self.assert_skip(base + "    condition: sel | count() by IpAddress > 10\n", "aggregation")
        self.assert_skip(base + "    condition: sel and other\n", "does not define")
        self.assert_skip(base.replace("service: security", "service: nonexistent") + "    condition: sel\n", "not mapped")
        self.assert_skip(base.replace("product: windows", "product: linux") + "    condition: sel\n", "not a Windows rule")
        self.assert_skip(base.replace("EventID: 4625", "EventID|expand: '%x%'") + "    condition: sel\n", "not supported")

    def test_folder_load_counts_skips(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "good.yml").write_text(CERTUTIL, encoding="utf-8")
            Path(d, "sub").mkdir()
            Path(d, "sub", "agg.yml").write_text(CERTUTIL.replace("condition: all of selection_* and not 1 of filter_main_*",
                                                                  "condition: selection_img | count() > 3"), encoding="utf-8")
            Path(d, "broken.yml").write_text("title: [unclosed\n  - : :\n", encoding="utf-8")
            loaded = sigma.load(Path(d))
        self.assertEqual((loaded.files, len(loaded.rules)), (3, 1))
        self.assertEqual(sum(loaded.skipped.values()), 2)


if __name__ == "__main__":
    unittest.main()
