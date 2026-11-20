import csv
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from demo_story import build_story

from evtxhunter import cli


class CLITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        build_story(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def report(self, *extra):
        code, out, _ = self.run_cli(self.dir, "--json", *extra)
        return code, json.loads(out)

    def test_the_whole_intrusion_is_reconstructed(self):
        code, doc = self.report()
        self.assertEqual(code, 1)
        found = {f["rule_id"]: f for f in doc["findings"]}
        expected = {"brute-force", "brute-force-success", "rdp-logon", "lolbin-certutil-download",
                    "user-account-created", "added-to-privileged-group", "new-admin",
                    "service-suspicious-imagepath", "powershell-encoded-command", "ps-download-and-execute",
                    "inhibit-recovery", "system-log-cleared", "record-gap", "hidden-records"}
        self.assertEqual(set(found), expected)
        self.assertIn("37 failed logons for 'administrator' from 203.0.113.50", found["brute-force"]["summary"])
        self.assertIn("1 record removed: ids 143", found["record-gap"]["summary"])
        self.assertIn("2 records invisible to Windows recovered", found["hidden-records"]["summary"])
        self.assertIn("ids 144, 148", found["hidden-records"]["summary"])
        # the hidden records still trip their rules, and say where they came from
        self.assertEqual(found["lolbin-certutil-download"]["source"], "Security.evtx (recovered)")
        self.assertEqual(found["inhibit-recovery"]["source"], "Security.evtx (recovered)")
        self.assertIn("decoded=IEX (New-Object Net.WebClient).DownloadString", found["powershell-encoded-command"]
                      ["summary"])
        times = [f["time"] for f in doc["findings"] if f["time"]]
        self.assertEqual(times, sorted(times))                       # a timeline

    def test_benign_activity_is_not_flagged(self):
        _, doc = self.report()
        text = json.dumps(doc["findings"])
        for benign in ("notepad.exe", "whoami /all", "igdkmd64", "Get-ChildItem", "alice"):
            self.assertNotIn(benign, text)
        # at --min-level info the ordinary driver install appears, but only as context
        _, doc = self.report("--min-level", "info")
        driver = [f for f in doc["findings"] if "igdkmd64" in f["summary"]]
        self.assertEqual([f["level"] for f in driver], ["info"])

    def test_log_stats(self):
        _, doc = self.report()
        logs = {Path(s["path"]).name: s for s in doc["logs"]}
        self.assertEqual(logs["Security.evtx"]["events"], 45)          # what Windows itself can see
        self.assertEqual(logs["Security.evtx"]["recovered_record_ids"], [144, 148])
        self.assertEqual(logs["Security.evtx"]["missing_record_ranges"], [[143, 143]])
        self.assertTrue(logs["System.evtx"]["intact"])

    @unittest.skipUnless(shutil.which("wevtutil"), "needs Windows")
    def test_windows_cannot_see_the_hidden_records_but_we_can(self):
        import re
        import subprocess
        out = subprocess.run(["wevtutil", "qe", str(self.dir / "Security.evtx"), "/lf:true", "/f:xml"],
                             capture_output=True, text=True, check=True).stdout
        shown = {int(i) for i in re.findall(r"<EventRecordID>(\d+)</EventRecordID>", out)}
        self.assertEqual(len(shown), 45)
        self.assertFalse({144, 148} & shown)

    def test_levels_and_time_window(self):
        _, doc = self.report("--min-level", "critical")
        self.assertEqual({f["level"] for f in doc["findings"]}, {"critical"})
        _, doc = self.report("--since", "2026-10-30T21:10:00", "--until", "2026-10-30T21:14:00")
        self.assertEqual({f["rule_id"] for f in doc["findings"]} - {"record-gap", "hidden-records"},
                         {"service-suspicious-imagepath", "powershell-encoded-command", "ps-download-and-execute"})

    def test_text_and_csv(self):
        csv_path = self.dir / "timeline.csv"
        code, out, _ = self.run_cli(self.dir, "--no-color", "--csv", csv_path)
        self.assertIn("Brute force succeeded", out)
        self.assertIn("FINDINGS", out)
        rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
        self.assertTrue(any(r["rule_id"] == "inhibit-recovery" and r["mitre"] == "T1490" for r in rows))

    def test_sigma_rules_run_on_security_4688(self):
        rule = Path(self.dir.parent, "sigma-cli-test")
        rule.mkdir(exist_ok=True)
        (rule / "certutil.yml").write_text("""title: Certutil Download From A URL
id: 9b1c2a3d-0000-4000-8000-00000000c3c7
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|windash: '-urlcache'
    condition: selection
level: high
""", encoding="utf-8")
        (rule / "count.yml").write_text("title: c\nlogsource:\n    product: windows\n    service: security\n"
                                        "detection:\n    s:\n        EventID: 4625\n    condition: s | count() > 5\n",
                                        encoding="utf-8")
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main([str(self.dir), "--json", "--no-builtin", "--sigma", str(rule)])
        finally:
            shutil.rmtree(rule, ignore_errors=True)
        self.assertEqual(code, 1)
        self.assertIn("1 rules loaded from 2 files (1 skipped: aggregation", err.getvalue())
        hits = [f for f in json.loads(out.getvalue())["findings"] if f["rule_id"].startswith("sigma:")]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["mitre"], ["T1105"])
        self.assertIn("certutil.exe -urlcache", json.dumps(hits[0]))
        code, _, err = self.run_cli(self.dir, "--sigma", self.dir / "no-such-rules")
        self.assertEqual(code, 2)
        self.assertIn("no such Sigma rule", err)

    def test_fail_on_and_errors(self):
        self.assertEqual(self.run_cli(self.dir, "--json", "--fail-on", "critical")[0], 1)
        self.assertEqual(self.run_cli(self.dir / "nope")[0], 2)
        self.assertEqual(self.run_cli(self.dir, "--since", "yesterday-ish")[0], 2)
        bad = self.dir / "bad.json"
        bad.write_text('[{"id": "x", "level": "spicy", "event_ids": [1]}]')
        self.assertEqual(self.run_cli(self.dir, "--rules", bad)[0], 2)


if __name__ == "__main__":
    unittest.main()
