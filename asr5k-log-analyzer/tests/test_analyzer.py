import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, read_jsonl


def event(line, evt, t, session="A", tb="LA", source="LA", fields=None):
    return {"_line": line, "session_id": session, "ts_us": t, "timebase": tb,
            "source": source, "event": evt, "fields": fields or {}}


def check_report(report, rule, status):
    return [x for x in report["findings"] if x["rule"] == rule and x["status"] == status]


class TestAnalyzer(unittest.TestCase):
    def test_40ms_pass(self):
        records = [event(1, "out_on_high", 100_000), event(2, "dds_wave_start", 140_000)]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_DELAY", "PASS"))

    def test_42ms_fail(self):
        records = [event(1, "out_on_high", 100_000), event(2, "dds_wave_start", 142_000)]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_DELAY", "FAIL"))

    def test_boundary_41ms_pass(self):
        records = [event(1, "out_on_high", 100_000), event(2, "dds_wave_start", 141_000)]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_DELAY", "PASS"))

    def test_different_timebases_no_measurement(self):
        records = [event(1, "out_on_high", 100_000, tb="M0"),
                   event(2, "dds_wave_start", 140_000, tb="CPU2")]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE"))

    def test_different_sources_no_measurement(self):
        records = [event(1, "out_on_high", 100_000, source="M0"),
                   event(2, "dds_wave_start", 140_000, source="CPU2")]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE"))

    def test_no_cross_session_pairing(self):
        records = [event(1, "out_on_high", 100_000, session="A"),
                   event(2, "dds_wave_start", 140_000, session="B")]
        reports = check_report(analyze(records), "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE")
        self.assertEqual(len(reports), 2)

    def test_sequence_is_warning_not_hard_fault(self):
        records = [event(1, "snapshot", 0, source="CPU1", tb="CPU1",
                         fields={"command_seq": 8, "applied_seq": 4})]
        self.assertTrue(check_report(analyze(records), "COMMAND_APPLIED_DIFFER", "WARN"))
        self.assertFalse(check_report(analyze(records), "COMMAND_APPLIED_DIFFER", "FAIL"))

    def test_explicit_nack_exhausted(self):
        records = [event(1, "on_edge_terminal", 0, source="CPU1", tb="CPU1",
                         fields={"terminal_reason": "NACK_EXHAUSTED", "retry_count": 1})]
        self.assertTrue(check_report(analyze(records), "ON_EDGE_NACK_EXHAUSTED", "WARN"))

    def test_unknown_numeric_reason_not_decoded(self):
        records = [event(1, "on_edge_terminal", 0, fields={"terminal_reason": 3})]
        self.assertFalse(check_report(analyze(records), "ON_EDGE_NACK_EXHAUSTED", "WARN"))

    def test_nonmonotonic_time_warning(self):
        records = [event(1, "snapshot", 100), event(2, "snapshot", 50)]
        self.assertTrue(check_report(analyze(records), "NON_MONOTONIC_TIMESTAMP", "WARN"))

    def test_invalid_jsonl_raises_precise_line(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.jsonl"
            p.write_text('{"event": "x"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"line 1: missing"):
                read_jsonl(p)

    def test_nonfinite_time_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.jsonl"
            p.write_text('{"session_id":"A","ts_us":NaN,"timebase":"LA","source":"LA","event":"x"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ts_us"):
                read_jsonl(p)


if __name__ == "__main__":
    unittest.main()
