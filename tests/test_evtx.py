import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evtxwriter import Ev, name_hash, write_evtx

from evtxhunter.evtx import FileInfo, ParseError, _filetime_str, read_events
from evtxhunter.hunter import missing_ranges

T0 = datetime(2026, 10, 30, 21, 10, 5, 123456, tzinfo=timezone.utc)


class TempDir(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, events, name="t.evtx"):
        path = self.dir / name
        write_evtx(path, events)
        return path


class ReaderTest(TempDir):
    def test_round_trip_of_system_and_event_data(self):
        path = self.write([Ev(41, T0, 4625, user_sid="S-1-5-21-1004336348-1177238915-682003330-512",
                              data={"TargetUserName": "admin", "IpAddress": "203.0.113.50", "LogonType": "10"})])
        info = FileInfo(str(path))
        [e] = list(read_events(str(path), info))
        self.assertEqual((e.record_id, e.event_id, e.channel, e.computer), (41, 4625, "Security", "WS01.corp.example"))
        self.assertEqual(e.provider, "Microsoft-Windows-Security-Auditing")
        self.assertEqual(e.time, T0)
        self.assertEqual(e.user_sid, "S-1-5-21-1004336348-1177238915-682003330-512")
        self.assertEqual(e.data, {"TargetUserName": "admin", "IpAddress": "203.0.113.50", "LogonType": "10"})
        self.assertEqual((info.records, info.errors, info.bad_checksums), (1, 0, []))

    def test_templates_are_reused_across_records_and_chunks(self):
        events = [Ev(i, T0 + timedelta(seconds=i), 4625, data={"TargetUserName": f"user{i}", "LogonType": "3"})
                  for i in range(1, 2001)]
        path = self.write(events)
        info = FileInfo(str(path))
        got = list(read_events(str(path), info))
        self.assertEqual(len(got), 2000)
        self.assertGreater(info.chunks, 1)                       # forced across several 64 KiB chunks
        self.assertEqual(got[1999].data["TargetUserName"], "user2000")
        self.assertEqual(info.errors, 0)

    def test_value_types(self):
        path = self.write([Ev(1, T0, 7045, provider="Service Control Manager", channel="System",
                              data={"Unicode": "خدمة ✓ ünïcode", "Count": 42, "List": ["a", "", "c"]})])
        [e] = list(read_events(str(path)))
        self.assertEqual(e.data["Unicode"], "خدمة ✓ ünïcode")
        self.assertEqual(e.data["Count"], "42")
        # arrays become repeated keys, empty items kept, as Windows renders <Data> per item
        self.assertEqual((e.data["List"], e.data["List_2"], e.data["List_3"]), ("a", "", "c"))
        self.assertIsNone(e.user_sid)                            # optional substitution left null

    def test_corruption_is_detected_not_fatal(self):
        path = self.write([Ev(i, T0, 4624, data={"TargetUserName": "u"}) for i in range(1, 50)])
        raw = bytearray(path.read_bytes())
        raw[0x1000 + 0x400] ^= 0xFF                              # flip a byte inside chunk 0's records
        path.write_bytes(bytes(raw))
        info = FileInfo(str(path))
        list(read_events(str(path), info))
        self.assertIn("chunk 0 records", info.bad_checksums)

    def test_truncated_file(self):
        path = self.write([Ev(i, T0, 4624, data={"TargetUserName": "u" * 40}) for i in range(1, 400)])
        raw = path.read_bytes()
        path.write_bytes(raw[:0x1000 + 0x10000 + 3000])           # second chunk cut short
        info = FileInfo(str(path))
        events = list(read_events(str(path), info))
        self.assertTrue(events)

    def test_not_an_evtx_file(self):
        path = self.dir / "x.evtx"
        path.write_bytes(b"MZ" + bytes(5000))
        with self.assertRaises(ParseError):
            list(read_events(str(path)))

    def test_filetime_rendering_matches_windows(self):
        self.assertEqual(_filetime_str(0), "1601-01-01T00:00:00.0000000Z")
        # 1 Jan 2020 = 116444736000000000 (Unix epoch) + 1577836800 s * 10^7
        self.assertEqual(_filetime_str(132_223_104_001_234_567), "2020-01-01T00:00:00.1234567Z")

    def test_name_hash_matches_a_real_log(self):
        self.assertEqual(name_hash("Event"), 0x0CBA)              # stored hash read from a real System.evtx

    def test_missing_ranges(self):
        self.assertEqual(missing_ranges([5, 1, 2, 3, 9, 10]), [(4, 4), (6, 8)])
        self.assertEqual(missing_ranges([7, 8, 9]), [])


@unittest.skipUnless(shutil.which("wevtutil") and os.name == "nt", "needs Windows' own decoder")
class AgainstWindowsTest(TempDir):
    """Our writer's files must open in Windows, and our reader must agree with Windows on every field."""

    def test_windows_decodes_our_files_exactly_like_we_do(self):
        from wevtutil_diff import compare
        events = [Ev(i, T0 + timedelta(seconds=i), 4625 if i % 3 else 4624,
                     user_sid="S-1-5-18" if i % 2 else None,
                     data={"TargetUserName": f"user{i % 7}", "IpAddress": "203.0.113.50", "LogonType": "10",
                           "Status": "0xc000006d", "Note": "مرحبا" if i % 5 == 0 else "plain"})
                  for i in range(1, 1201)]
        path = self.write(events)
        result = compare(str(path))
        self.assertEqual(result["reference"], 1200)
        self.assertEqual(sum(result["mismatches"].values()), 0, result["examples"])

    @unittest.skipUnless(os.environ.get("CI") or os.environ.get("EVTXHUNTER_DIFF"), "slow: set EVTXHUNTER_DIFF=1")
    def test_real_system_log_matches_windows(self):
        import subprocess
        from wevtutil_diff import compare
        path = self.dir / "System.evtx"
        subprocess.run(["wevtutil", "epl", "System", str(path)], check=True)
        result = compare(str(path))
        self.assertGreater(result["compared"], 0)
        self.assertEqual(sum(result["mismatches"].values()), 0, result["examples"])


if __name__ == "__main__":
    unittest.main()
