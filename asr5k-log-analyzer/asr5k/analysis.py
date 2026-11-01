"""Deterministic, evidence-based firmware diagnostics. No network dependency."""
from __future__ import annotations

import hashlib
import json
import statistics
from collections import defaultdict
from typing import Any

from . import __version__
from .ingest import check_event

DEFAULT_RULES: dict[str, Any] = {
    "on_edge": {"target_us": 40_000, "tolerance_us": 1_000},
    "sequence_mismatch_warn_samples": 1,
    "intervals": [],
    "allowed_transitions": {},
}
STATUS_RANK = {"PASS": 0, "INFO": 1, "INSUFFICIENT_EVIDENCE": 2, "WARN": 3, "FAIL": 4}


def rules_digest(rules: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(rules, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def verified_rules(user_rules: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate explicit contracts; never guess timing limits or state transitions."""
    rules = json.loads(json.dumps(DEFAULT_RULES))
    if user_rules:
        unknown = set(user_rules) - set(rules)
        if unknown:
            raise ValueError(f"unsupported rules keys: {sorted(unknown)}")
        for name, value in user_rules.items():
            if name == "on_edge":
                if not isinstance(value, dict) or set(value) - {"target_us", "tolerance_us"}:
                    raise ValueError("on_edge must only contain target_us and tolerance_us")
                rules[name].update(value)
            else:
                rules[name] = value
    target = rules["on_edge"]["target_us"]
    tolerance = rules["on_edge"]["tolerance_us"]
    for name, number in (("target_us", target), ("tolerance_us", tolerance)):
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ValueError(f"on_edge.{name} must be a nonnegative integer microsecond value")
    if target == 0:
        raise ValueError("on_edge.target_us cannot be zero")
    mismatch = rules["sequence_mismatch_warn_samples"]
    if isinstance(mismatch, bool) or not isinstance(mismatch, int) or mismatch < 1:
        raise ValueError("sequence_mismatch_warn_samples must be positive integer")
    if not isinstance(rules["allowed_transitions"], dict):
        raise ValueError("allowed_transitions must be an object indexed by source")
    for source, edges in rules["allowed_transitions"].items():
        if not isinstance(source, str) or not isinstance(edges, dict):
            raise ValueError("allowed_transitions entries must be objects")
        for state, targets in edges.items():
            if not isinstance(state, str) or not isinstance(targets, list) or not all(isinstance(x, str) for x in targets):
                raise ValueError("transition targets must be an array of state names")
    if not isinstance(rules["intervals"], list):
        raise ValueError("intervals must be an array")
    for spec in rules["intervals"]:
        if not isinstance(spec, dict) or not {"name", "start_event", "end_event"}.issubset(spec):
            raise ValueError("interval rule must define name/start_event/end_event")
        if spec["start_event"] == spec["end_event"]:
            raise ValueError("start_event and end_event cannot be identical")
        if not all(isinstance(spec[k], str) and spec[k] for k in ("name", "start_event", "end_event")):
            raise ValueError("interval names must be nonempty strings")
        if "max_us" in spec and (isinstance(spec["max_us"], bool) or not isinstance(spec["max_us"], int) or spec["max_us"] < 0):
            raise ValueError("max_us must be nonnegative integer")
    return rules


def evidence_for(event: dict[str, Any]) -> dict[str, Any]:
    # Stable, auditable trace. A file name alone is not sufficient evidence identity.
    return {
        "file": event.get("_input_file", "UNKNOWN"),
        "file_sha256": event.get("_input_sha256", "UNKNOWN"),
        "lines": event.get("_lines", [event.get("_line")]),
        "session_id": event.get("session_id"),
        "capture_id": event.get("capture_id", "LEGACY"),
        "source": event.get("source"),
        "timebase": event.get("timebase"),
        "ts_us": event.get("ts_us"),
        "event": event.get("event"),
        "origin_is_reported": bool(event.get("_origin_is_reported", False)),
    }


def finding(rule: str, status: str, detail: str, items: list[dict[str, Any]], next_test: str) -> dict[str, Any]:
    source_refs = []
    seen = set()
    lines = set()
    for item in items:
        ref = evidence_for(item)
        key = (ref["file_sha256"], tuple(ref["lines"] or ()), ref["event"], ref["ts_us"])
        if key not in seen:
            source_refs.append(ref)
            seen.add(key)
        lines.update(line for line in (ref["lines"] or []) if isinstance(line, int))
    return {"rule": rule, "status": status, "detail": detail,
            "evidence_lines": sorted(lines), "evidence": source_refs, "next_test": next_test}


def _track(event: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (event["session_id"], event.get("capture_id", "LEGACY"),
            event["source"], event["timebase"], event.get("_input_sha256", "LEGACY"))


def _intervals(
    events: list[dict[str, Any]], start_event: str, end_event: str, rule_name: str,
    max_us: int | None, results: list[dict[str, Any]], measurements: list[dict[str, Any]],
    *, target_us: int | None = None, tolerance_us: int | None = None,
) -> None:
    """Only pair an unambiguous, alternating edge sequence within one capture track."""
    by_track: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event"] in (start_event, end_event):
            by_track[_track(event)].append(event)
    for track, items in sorted(by_track.items()):
        session, capture, source, timebase, digest = track
        selected = sorted(items, key=lambda row: (float("inf") if row["ts_us"] is None else row["ts_us"], row.get("_line", 0)))
        if any(item["ts_us"] is None for item in selected):
            results.append(finding(rule_name, "INSUFFICIENT_EVIDENCE", f"{session}/{capture}: missing timestamp.", selected,
                                   "Acquire both edges from the same measurable capture clock."))
            continue
        if any(b["ts_us"] < a["ts_us"] for a, b in zip(items, items[1:])):
            results.append(finding(rule_name, "INSUFFICIENT_EVIDENCE", f"{session}/{capture}: capture timestamps decrease.", items,
                                   "Confirm sorting, rollover and capture/session boundary."))
            continue
        if len(selected) % 2 or any(selected[i]["event"] != start_event or selected[i+1]["event"] != end_event for i in range(0, len(selected) - 1, 2)):
            results.append(finding(
                rule_name, "INSUFFICIENT_EVIDENCE", f"{session}/{capture}: ambiguous/missing event pairs; no FIFO guess made.",
                selected[:12], "Provide complete alternating edges or split by verified cycle/capture boundary.",
            ))
            continue
        for cycle, i in enumerate(range(0, len(selected), 2), 1):
            start, end = selected[i], selected[i + 1]
            delay = end["ts_us"] - start["ts_us"]
            if delay < 0:
                results.append(finding(rule_name, "INSUFFICIENT_EVIDENCE", f"{session}/{capture}: negative delay.", [start, end],
                                       "Verify clock domain, capture integrity and event definitions."))
                continue
            # The normalized demo has no mapping flag for backwards compatibility.
            # Raw LA adapters explicitly mark mapping as unverified until checked.
            physical_mapping_verified = all(x.get("signal_mapping_verified", True) for x in (start, end))
            if not physical_mapping_verified:
                status = "INSUFFICIENT_EVIDENCE"
            elif target_us is not None and tolerance_us is not None:
                status = "PASS" if (target_us - tolerance_us <= delay <= target_us + tolerance_us) else "FAIL"
            elif max_us is not None:
                status = "PASS" if delay <= max_us else "FAIL"
            else:
                status = "INFO"
            description = f"{session}/{capture}/{source}/{timebase} cycle {cycle}: {delay / 1000:g} ms"
            if target_us is not None and tolerance_us is not None:
                description += f" (target {target_us/1000:g} ±{tolerance_us/1000:g} ms)"
            elif max_us is not None:
                description += f" (maximum {max_us/1000:g} ms)"
            else:
                description += " (no approved numeric limit; observation only)"
            if not physical_mapping_verified:
                description += "; signal mapping not independently verified"
            results.append(finding(
                rule_name, status, description, [start, end],
                "Verify physical channel-to-pin assignment, transition polarity, capture clock, flashed .out and trigger point.",
            ))
            measurements.append({
                "rule": rule_name, "session_id": session, "capture_id": capture, "cycle": cycle,
                "value_us": delay, "status": status, "evidence": [evidence_for(start), evidence_for(end)],
            })


def analyze(
    records: list[dict[str, Any]], input_sha256: str = "", rules: dict[str, Any] | None = None,
    *, source_info: dict[str, Any] | None = None, test_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = verified_rules(rules)
    if not records:
        raise ValueError("analysis requires at least one event")
    for idx, event in enumerate(records, 1):
        check_event(event, f"event {idx}")
    findings: list[dict[str, Any]] = []
    measurements: list[dict[str, Any]] = []
    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_track: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in records:
        by_session[event["session_id"]].append(event)
        by_track[_track(event)].append(event)

    for (session, capture, source, timebase, _digest), items in sorted(by_track.items()):
        prior_timestamp = None
        prior_item = None
        previous_state = None
        state_item = None
        mismatch_run = []
        for row in items:
            timestamp = row["ts_us"]
            if prior_timestamp is not None and timestamp is not None and timestamp < prior_timestamp:
                findings.append(finding("NON_MONOTONIC_TIMESTAMP", "WARN",
                                        f"{session}/{source}/{capture}: timestamp decreased inside a single source track.",
                                        [prior_item, row], "Split reset sessions; inspect counter rollover and acquisition order."))
            if timestamp is not None:
                prior_timestamp, prior_item = timestamp, row
            fields = row.get("fields", {})
            state = None
            if row["event"] == "snapshot":
                command, applied = fields.get("command_seq"), fields.get("applied_seq")
                if (isinstance(command, int) and not isinstance(command, bool) and
                        isinstance(applied, int) and not isinstance(applied, bool) and command != applied):
                    mismatch_run.append(row)
                    # A mismatch is not a hard fault; these are sampled states.
                    if len(mismatch_run) == config["sequence_mismatch_warn_samples"]:
                        findings.append(finding(
                            "COMMAND_APPLIED_DIFFER", "WARN",
                            f"{session}: command_seq={command}, applied_seq={applied} in snapshot; transient until apply contract and latency are verified.",
                            mismatch_run, "Capture multiple snapshots with same-clock timestamps and known apply deadline.",
                        ))
                else:
                    mismatch_run.clear()
                state = fields.get("system_state")
            elif row["event"] == "system_state":
                state = fields.get("state")
            if isinstance(state, str):
                if state == "FAULT" and previous_state != "FAULT":
                    findings.append(finding(
                        "ENTERED_FAULT", "WARN",
                        f"{session}/{source}: FAULT observed (previous observed state: {previous_state or 'UNKNOWN'}).",
                        [x for x in (state_item, row) if x],
                        "Correlate fault state, protection bits and terminal reason within verified clock domains.",
                    ))
                allowed = config["allowed_transitions"].get(source, {})
                if (previous_state is not None and state != previous_state and previous_state in allowed
                        and state not in allowed[previous_state]):
                    findings.append(finding(
                        "INVALID_STATE_TRANSITION", "FAIL", f"{session}/{source}: {previous_state} -> {state} violates supplied state contract.",
                        [x for x in (state_item, row) if x],
                        "Confirm the supplied transition contract and reconstruct missing intermediate states.",
                    ))
                previous_state, state_item = state, row
            if row["event"] == "on_edge_terminal" and fields.get("terminal_reason") == "NACK_EXHAUSTED":
                findings.append(finding(
                    "ON_EDGE_NACK_EXHAUSTED", "WARN",
                    f"{session}/{source}: explicitly logged terminal_reason=NACK_EXHAUSTED; retry_count={fields.get('retry_count','UNKNOWN')}",
                    [row], "Capture master I2C NACK status, M0 slave readiness, and the ON-edge read transaction.",
                ))

    # Require same capture/source/timebase/file. Cross-track observations are UNKNOWN.
    _intervals(records, "out_on_high", "dds_wave_start", "ON_EDGE_DELAY", None, findings, measurements,
               target_us=config["on_edge"]["target_us"], tolerance_us=config["on_edge"]["tolerance_us"])
    for spec in config["intervals"]:
        _intervals(records, spec["start_event"], spec["end_event"], f"INTERVAL_{spec['name']}",
                   spec.get("max_us"), findings, measurements)

    # For sessions where both edges exist but on separate sources or timebases,
    # a lack of a matched track must explicitly mention the incomparable clocks.
    for session, items in sorted(by_session.items()):
        if any(e["event"] == "out_on_high" for e in items) and any(e["event"] == "dds_wave_start" for e in items):
            keys_on = {_track(e) for e in items if e["event"] == "out_on_high"}
            keys_start = {_track(e) for e in items if e["event"] == "dds_wave_start"}
            if not keys_on.intersection(keys_start):
                edges = [e for e in items if e["event"] in ("out_on_high", "dds_wave_start")]
                findings.append(finding(
                    "ON_EDGE_CROSS_TIMEBASE", "INSUFFICIENT_EVIDENCE",
                    f"{session}: OUT-ON and WAVE events are in different source/timebase/capture/file tracks; latency cannot be calculated.",
                    edges[:8], "Capture both physical edges with one LA clock and verified channel mappings.",
                ))

    provenance: dict[str, Any] = {}
    for session, items in sorted(by_session.items()):
        sources = {str(e["firmware_sha"]) for e in items if isinstance(e.get("firmware_sha"), str)
                   and e["firmware_sha"].strip().upper() != "UNKNOWN"}
        binaries = {str(e["binary_sha256"]) for e in items if isinstance(e.get("binary_sha256"), str)
                    and e["binary_sha256"].strip().upper() != "UNKNOWN"}
        provenance[session] = {"reported_source_shas": sorted(sources),
                               "reported_binary_sha256s": sorted(binaries),
                               "flashed_binary_correspondence_verified": False}
        if len(sources) > 1 or len(binaries) > 1:
            findings.append(finding("PROVENANCE_CONFLICT", "WARN",
                                    f"{session}: conflicting reported source/binary hashes in one session.", items[:8],
                                    "Split captures by tested firmware build; obtain trusted build and flash records."))
        if not sources or not binaries:
            findings.append(finding("PROVENANCE_UNVERIFIED", "INFO",
                                    f"{session}: source SHA or flashed .out SHA256 is missing; cannot prove binary-to-source mapping.",
                                    items[:1], "Record source commit, .out SHA256 and an independently checked flash manifest."))

    timing_stats: dict[str, dict[str, Any]] = {}
    for name in sorted(set(m["rule"] for m in measurements)):
        ms = [m["value_us"] for m in measurements if m["rule"] == name and m["status"] in ("PASS", "FAIL", "INFO")]
        if ms:
            timing_stats[name] = {"count": len(ms), "min_us": min(ms), "max_us": max(ms),
                                  "median_us": statistics.median(ms)}
    overall = max((f["status"] for f in findings), key=lambda status: STATUS_RANK[status], default="INFO")
    statuses: dict[str, int] = {status: 0 for status in STATUS_RANK}
    for f in findings:
        statuses[f["status"]] += 1
    safe_context = json.loads(json.dumps(test_context or {}))
    return {
        "schema_version": __version__, "input_sha256": input_sha256, "input": json.loads(json.dumps(source_info or {})),
        "rules": config, "rules_sha256": rules_digest(config),
        "test_context": safe_context, "demo_data_not_hardware_evidence": False,
        "hardware_acceptance_verified": False,  # Never asserted from a single imported file.
        "records": len(records), "sessions": len(by_session), "overall": overall,
        "status_counts": statuses, "timing_statistics": timing_stats,
        "provenance": provenance, "measurements": measurements,
        "findings": sorted(findings, key=lambda f: (-STATUS_RANK[f["status"]], min(f["evidence_lines"] or [0]), f["rule"])),
        "events": [{"session_id": e["session_id"], "capture_id": e.get("capture_id", "LEGACY"),
                    "source": e["source"], "timebase": e["timebase"], "ts_us": e["ts_us"],
                    "event": e["event"], "evidence": evidence_for(e)} for e in records],
    }
