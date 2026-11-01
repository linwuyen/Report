"""V1.0 unit/integration regressions, including safety-negative cases."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asr5k.ai import preview_payload, redact
from asr5k.analysis import analyze, verified_rules
from asr5k.cli import main
from asr5k.ingest import InputError, export_jsonl, import_events, read_jsonl
from asr5k.outputs import render_analysis, save_json
from asr5k.regression import compare

ROOT = Path(__file__).resolve().parents[1]


def simple(event, ts, line=1, source="LA", timebase="LA_CLOCK", capture="CAP_1", session="S1", **extra):
    result = {"_line": line, "session_id": session, "ts_us": ts,
              "timebase": timebase, "source": source, "capture_id": capture,
              "event": event, "fields": {}, "_input_file": "fixture.jsonl", "_input_sha256": "a" * 64}
    result.update(extra)
    return result


def has(report, rule, status):
    return [f for f in report["findings"] if f["rule"] == rule and f["status"] == status]


class InputContractTests(unittest.TestCase):
    def test_la_unverified_mapping_is_not_hardware_pass(self):
        records, info = import_events(ROOT / "samples/la_demo.csv", "la-csv", ROOT / "profiles/la_example_unverified.json")
        report = analyze(records, info["sha256"], source_info=info)
        self.assertEqual(len(records), 4)
        self.assertEqual(report["overall"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(len(has(report, "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE")), 2)
        self.assertFalse(report["hardware_acceptance_verified"])
        self.assertEqual(info["quality"]["unknown_signal_levels"], 0)

    def test_la_verified_mapping_can_compute_two_cycles(self):
        profile = json.loads((ROOT / "profiles/la_example_unverified.json").read_text())
        profile["signal_mapping_verified"] = True
        with tempfile.TemporaryDirectory() as folder:
            mapped = Path(folder) / "profile.json"
            mapped.write_text(json.dumps(profile))
            records, _ = import_events(ROOT / "samples/la_demo.csv", "la-csv", mapped)
        report = analyze(records)
        self.assertEqual(len(has(report, "ON_EDGE_DELAY", "FAIL")), 1)
        self.assertEqual(len(has(report, "ON_EDGE_DELAY", "PASS")), 1)
        self.assertEqual(report["timing_statistics"]["ON_EDGE_DELAY"]["max_us"], 42_500)
        self.assertFalse(report["hardware_acceptance_verified"])

    def test_la_first_high_not_false_rising_edge(self):
        content = "Time [s],OUT_ON,DDS_WAVE\n0,1,0\n0.010,1,0\n0.012,0,0\n0.02,1,0\n0.06,1,1\n"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "d.csv"
            path.write_text(content)
            records, _ = import_events(path, "la-csv", ROOT / "profiles/la_example_unverified.json")
        self.assertEqual([r["event"] for r in records], ["out_on_high", "dds_wave_start"])
        self.assertEqual(records[0]["ts_us"], 20_000)

    def test_la_nonmonotonic_rejected(self):
        content = "Time [s],OUT_ON,DDS_WAVE\n0.1,0,0\n0.09,1,0\n"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "d.csv"
            path.write_text(content)
            with self.assertRaisesRegex(InputError, "time decreased"):
                import_events(path, "la-csv", ROOT / "profiles/la_example_unverified.json")

    def test_la_missing_channel_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "d.csv"
            path.write_text("Time [s],OUT_ON\n0,0\n")
            with self.assertRaisesRegex(InputError, "missing columns"):
                import_events(path, "la-csv", ROOT / "profiles/la_example_unverified.json")

    def test_watch_snapshot_has_no_fake_clock_and_no_enum_guess(self):
        rows, info = import_events(ROOT / "samples/watch_demo.csv", "watch-csv", ROOT / "profiles/watch_example_unverified.json")
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["ts_us"])
        self.assertEqual(rows[0]["timebase"], "UNSPECIFIED")
        self.assertEqual(rows[0]["fields"]["system_state_raw"], 4)
        self.assertNotIn("system_state", rows[0]["fields"])
        self.assertEqual(info["quality"]["ignored_variables"], 1)
        report = analyze(rows)
        self.assertTrue(has(report, "COMMAND_APPLIED_DIFFER", "WARN"))
        self.assertFalse(has(report, "ENTERED_FAULT", "WARN"))

    def test_watch_declared_verified_enum_map(self):
        profile = json.loads((ROOT / "profiles/watch_example_unverified.json").read_text())
        profile["verified_enum_map"] = {"system_state": {"4": "FAULT"}}
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "watch.json"
            p.write_text(json.dumps(profile))
            rows, _ = import_events(ROOT / "samples/watch_demo.csv", "watch-csv", p)
        self.assertEqual(rows[0]["fields"]["system_state"], "FAULT")
        self.assertTrue(has(analyze(rows), "ENTERED_FAULT", "WARN"))

    def test_watch_duplicate_field_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "dup.csv"
            p.write_text("Expression,Value\nu16OutputCommandSequence,5\nu16OutputCommandSequence,8\n")
            with self.assertRaisesRegex(InputError, "duplicate canonical Watch field"):
                import_events(p, "watch-csv", ROOT / "profiles/watch_example_unverified.json")

    def test_uart_fixture(self):
        rows, info = import_events(ROOT / "samples/uart_demo.log", "uart-kv", ROOT / "profiles/uart_example_unverified.json")
        self.assertEqual(len(rows), 4)
        report = analyze(rows)
        self.assertTrue(has(report, "ENTERED_FAULT", "WARN"))
        self.assertTrue(has(report, "ON_EDGE_NACK_EXHAUSTED", "WARN"))
        self.assertEqual(info["quality"]["events"], 4)

    def test_uart_does_not_silently_skip_bad_line(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "bad.log"
            p.write_text("[100] CPU1 snapshot command_seq=4\ninvalid UART line\n")
            with self.assertRaisesRegex(InputError, "line 2: unrecognized"):
                import_events(p, "uart-kv", ROOT / "profiles/uart_example_unverified.json")

    def test_uart_missing_source_clock_mapping_is_error(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "bad.log"
            p.write_text("[100] M0 snapshot command_seq=4\n")
            profile = json.loads((ROOT / "profiles/uart_example_unverified.json").read_text())
            profile["timebase_by_source"].pop("M0")
            m = Path(folder) / "profile.json"
            m.write_text(json.dumps(profile))
            with self.assertRaisesRegex(InputError, "no explicit clock domain"):
                import_events(p, "uart-kv", m)

    def test_conversion_preserves_origin_line_and_sha(self):
        rows, info = import_events(ROOT / "samples/la_demo.csv", "la-csv", ROOT / "profiles/la_example_unverified.json")
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "normalized.jsonl"
            export_jsonl(rows, p)
            converted, digest = read_jsonl(p)
            self.assertEqual(len(converted), len(rows))
            self.assertEqual(converted[0]["_lines"], rows[0]["_lines"])
            self.assertEqual(converted[0]["_input_sha256"], info["sha256"])
            self.assertEqual(converted[0]["_input_file"], "la_demo.csv")
            self.assertTrue(converted[0]["_origin_is_reported"])
            self.assertNotEqual(digest, info["sha256"])

    def test_unsupported_raw_format_without_profile(self):
        with self.assertRaisesRegex(InputError, "requires --profile"):
            import_events(ROOT / "samples/la_demo.csv", "la-csv")

    def test_hash_source_matches_file(self):
        _, info = import_events(ROOT / "samples/demo.jsonl", "jsonl")
        import hashlib
        self.assertEqual(info["sha256"], hashlib.sha256((ROOT / "samples/demo.jsonl").read_bytes()).hexdigest())


class EngineContractTests(unittest.TestCase):
    def test_no_cross_capture_pairing(self):
        events = [simple("out_on_high", 1000, capture="A"),
                  simple("dds_wave_start", 41000, capture="B")]
        report = analyze(events)
        self.assertFalse(has(report, "ON_EDGE_DELAY", "PASS"))
        self.assertTrue(has(report, "ON_EDGE_CROSS_TIMEBASE", "INSUFFICIENT_EVIDENCE"))

    def test_ambiguous_multiple_on_edges_rejected(self):
        events = [simple("out_on_high", 1000, line=1), simple("out_on_high", 3000, line=2),
                  simple("dds_wave_start", 41000, line=3), simple("dds_wave_start", 43000, line=4)]
        report = analyze(events)
        self.assertTrue(has(report, "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE"))
        self.assertEqual(report["measurements"], [])

    def test_missing_start_event_is_unknown(self):
        report = analyze([simple("dds_wave_start", 41000)])
        self.assertTrue(has(report, "ON_EDGE_DELAY", "INSUFFICIENT_EVIDENCE"))

    def test_custom_interval_observation_only(self):
        config = verified_rules({"intervals": [{"name": "SPIB", "start_event": "spib_service_start", "end_event": "spib_service_end"}]})
        report = analyze([simple("spib_service_start", 100), simple("spib_service_end", 800)], rules=config)
        self.assertTrue(has(report, "INTERVAL_SPIB", "INFO"))
        self.assertEqual(report["timing_statistics"]["INTERVAL_SPIB"]["max_us"], 700)

    def test_custom_interval_explicit_limit(self):
        config = {"intervals": [{"name": "I2C", "start_event": "i2c_start", "end_event": "i2c_done", "max_us": 100}]}
        report = analyze([simple("i2c_start", 100), simple("i2c_done", 201)], rules=config)
        self.assertTrue(has(report, "INTERVAL_I2C", "FAIL"))

    def test_invalid_state_transition_with_supplied_contract_only(self):
        items = [simple("system_state", 100, source="CPU1", timebase="CPU1_LOCAL", fields={"state": "IDLE"}),
                 simple("system_state", 200, source="CPU1", timebase="CPU1_LOCAL", fields={"state": "RUN"})]
        with_contract = analyze(items, rules={"allowed_transitions": {"CPU1": {"IDLE": ["READY", "FAULT"]}}})
        self.assertTrue(has(with_contract, "INVALID_STATE_TRANSITION", "FAIL"))
        without_contract = analyze(items)
        self.assertFalse(has(without_contract, "INVALID_STATE_TRANSITION", "FAIL"))

    def test_incorrect_rule_limits_are_rejected(self):
        for config in ({"on_edge": {"tolerance_us": -1}},
                       {"on_edge": {"target_us": "40000"}},
                       {"incorrect": 1},
                       {"intervals": [{"name": "X", "start_event": "A", "end_event": "A"}]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                verified_rules(config)

    def test_event_source_line_in_finding(self):
        report = analyze([simple("out_on_high", 1000, 10), simple("dds_wave_start", 43000, 11)])
        f = has(report, "ON_EDGE_DELAY", "FAIL")[0]
        self.assertEqual(f["evidence_lines"], [10, 11])
        self.assertEqual(f["evidence"][0]["file_sha256"], "a" * 64)

    def test_no_numeric_fault_reason_guess(self):
        report = analyze([simple("on_edge_terminal", 100, fields={"terminal_reason": 3})])
        self.assertFalse(has(report, "ON_EDGE_NACK_EXHAUSTED", "WARN"))


class RegressionContractTests(unittest.TestCase):
    def setUp(self):
        self.context = {"test_id": "T1", "hardware_id": "DUT_1", "capture_setup_id": "LA_S1"}
        self.baseline = analyze([simple("out_on_high", 1000), simple("dds_wave_start", 41000)], test_context=self.context)
        self.candidate = analyze([simple("out_on_high", 1000), simple("dds_wave_start", 43500)], test_context=self.context)

    def test_regression_new_fail_detected(self):
        diff = compare(self.baseline, self.candidate)
        self.assertTrue(diff["comparable"])
        self.assertEqual(diff["verdict"], "REGRESSION")
        self.assertEqual(diff["timing_deltas"][0]["delta_max_us"], 2500)

    def test_missing_metadata_fails_closed(self):
        self.baseline["test_context"] = {}
        self.assertEqual(compare(self.baseline, self.candidate)["verdict"], "NOT_COMPARABLE")

    def test_simulated_and_non_demo_reports_not_comparable(self):
        self.baseline["demo_data_not_hardware_evidence"] = True
        self.assertEqual(compare(self.baseline, self.candidate)["verdict"], "NOT_COMPARABLE")

    def test_different_la_profile_hash_fails_closed(self):
        self.baseline["input"] = {"profile_sha256": "X"}
        self.candidate["input"] = {"profile_sha256": "Y"}
        self.assertEqual(compare(self.baseline, self.candidate)["verdict"], "NOT_COMPARABLE")

    def test_rule_mismatch_fails_closed(self):
        self.candidate["rules_sha256"] = "different"
        self.assertEqual(compare(self.baseline, self.candidate)["verdict"], "NOT_COMPARABLE")

    def test_different_hardware_id_fails_closed(self):
        self.candidate["test_context"]["hardware_id"] = "OTHER_DUT"
        self.assertEqual(compare(self.baseline, self.candidate)["verdict"], "NOT_COMPARABLE")

    def test_same_run_is_no_new_fail(self):
        self.assertEqual(compare(self.baseline, self.baseline)["verdict"], "NO_NEW_FAIL")

    def test_different_event_count_yields_incomplete_comparison(self):
        new = analyze([simple("out_on_high", 1), simple("dds_wave_start", 40001),
                       simple("out_on_high", 100000), simple("dds_wave_start", 140000)], test_context=self.context)
        self.assertEqual(compare(self.baseline, new)["verdict"], "INCOMPLETE_COMPARISON")


class OutputAndSecurityTests(unittest.TestCase):
    def test_html_escapes_untrusted_fields(self):
        attack = '<script>alert("owned")</script>'
        report = analyze([simple("system_state", 200, source="CPU1", fields={"state": "FAULT"},
                                 session=attack)])
        rendered = render_analysis(report)
        self.assertNotIn(attack, rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_api_preview_no_raw_log_or_provenance_hash(self):
        report = analyze([simple("snapshot", 100, fields={"command_seq": 8, "applied_seq": 4})])
        payload = preview_payload(report)
        text = json.dumps(payload)
        self.assertNotIn("fixture.jsonl", text)
        self.assertNotIn("a" * 64, text)
        self.assertNotIn("OPENAI_API_KEY", text)

    def test_redact_api_credentials(self):
        self.assertNotIn("sk-proj-verylongsecret01234567890", redact("key sk-proj-verylongsecret01234567890"))
        self.assertNotIn("abc123", redact("token=abc123"))

    def test_byte_identical_deterministic_report(self):
        report = analyze([simple("out_on_high", 1000), simple("dds_wave_start", 41000)])
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.json", Path(folder) / "b.json"
            save_json(a, report)
            save_json(b, report)
            self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_cli_legacy_and_html_end_to_end(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            self.assertEqual(main(["--input", str(ROOT / "samples/demo.jsonl"), "--output", str(output), "--demo"]), 0)
            self.assertTrue(output.exists())
            self.assertTrue(output.with_suffix(".html").exists())
            self.assertEqual(json.loads(output.read_text())["overall"], "FAIL")

    def test_cli_explicit_fail_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            result = main(["analyze", "--input", str(ROOT / "samples/demo.jsonl"),
                           "--output", str(output), "--demo", "--fail-on-fail"])
            self.assertEqual(result, 3)

    def test_cli_reject_unknown_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            code = main(["analyze", "--input", str(ROOT / "samples/la_demo.csv"),
                         "--format", "la-csv", "--profile", str(ROOT / "profiles/la_example_unverified.json"),
                         "--output", str(output), "--demo", "--reject-unknown"])
            self.assertEqual(code, 4)

    def test_cli_no_key_required_for_preview(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            self.assertEqual(main(["analyze", "--input", str(ROOT / "samples/demo.jsonl"),
                                   "--output", str(output), "--ai-preview", "--demo"]), 0)
            self.assertTrue((Path(folder) / "result_ai_preview.json").exists())


if __name__ == "__main__":
    unittest.main()
