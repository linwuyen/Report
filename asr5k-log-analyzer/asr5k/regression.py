"""Contract-gated comparison; never compare incompatible hardware tests."""
from __future__ import annotations

from collections import Counter
from typing import Any

REQUIRED_CONTEXT = ("test_id", "hardware_id", "capture_setup_id")


def summarize_findings(report: dict[str, Any]) -> dict[str, dict[str, int]]:
    counts: dict[str, Counter[str]] = {}
    for f in report.get("findings", []):
        counts.setdefault(f["rule"], Counter())[f["status"]] += 1
    return {rule: dict(counts[rule]) for rule in sorted(counts)}


def compare(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    if not str(baseline.get("schema_version", "")).startswith("1.") or not str(candidate.get("schema_version", "")).startswith("1."):
        failures.append("Both reports must use schema V1.x")
    if not baseline.get("rules_sha256") or baseline.get("rules_sha256") != candidate.get("rules_sha256"):
        failures.append("Rule contracts or numerical limits differ")
    bctx = baseline.get("test_context") or {}
    cctx = candidate.get("test_context") or {}
    if bool(baseline.get("demo_data_not_hardware_evidence")) != bool(candidate.get("demo_data_not_hardware_evidence")):
        failures.append("Cannot compare simulated fixtures and non-demo measurements")
    bprofile = (baseline.get("input") or {}).get("profile_sha256")
    cprofile = (candidate.get("input") or {}).get("profile_sha256")
    if bprofile != cprofile:
        failures.append("Raw import mapping profile hashes differ or one is missing")
    for name in REQUIRED_CONTEXT:
        if not bctx.get(name) or not cctx.get(name):
            failures.append(f"{name} is missing from one or both reports")
        elif bctx[name] != cctx[name]:
            failures.append(f"{name} does not match ({bctx[name]!r} vs {cctx[name]!r})")
    bstats = baseline.get("timing_statistics") or {}
    cstats = candidate.get("timing_statistics") or {}
    metrics = []
    for name in sorted(set(bstats) | set(cstats)):
        old, new = bstats.get(name), cstats.get(name)
        if not old or not new or old["count"] != new["count"]:
            metrics.append({"rule": name, "comparable": False, "reason": "Missing metric or different sample count"})
            continue
        metrics.append({"rule": name, "comparable": True,
                        "baseline_max_us": old["max_us"], "candidate_max_us": new["max_us"],
                        "delta_max_us": new["max_us"] - old["max_us"],
                        "baseline_median_us": old["median_us"], "candidate_median_us": new["median_us"],
                        "delta_median_us": new["median_us"] - old["median_us"]})
    bfind = summarize_findings(baseline)
    cfind = summarize_findings(candidate)
    issue_diffs = []
    for name in sorted(set(bfind) | set(cfind)):
        old = bfind.get(name, {})
        new = cfind.get(name, {})
        issue_diffs.append({"rule": name, "baseline": old, "candidate": new,
                            "new_failures": new.get("FAIL", 0) - old.get("FAIL", 0),
                            "new_warnings": new.get("WARN", 0) - old.get("WARN", 0)})
    comparable = not failures
    if not comparable:
        verdict = "NOT_COMPARABLE"
    elif any(diff["new_failures"] > 0 for diff in issue_diffs):
        verdict = "REGRESSION"
    elif any(not metric["comparable"] for metric in metrics):
        verdict = "INCOMPLETE_COMPARISON"
    else:
        verdict = "NO_NEW_FAIL"
    return {
        "schema_version": "1.0.0", "type": "regression_comparison",
        "verdict": verdict, "comparable": comparable, "comparability_blockers": failures,
        "demo_data_not_hardware_evidence": bool(baseline.get("demo_data_not_hardware_evidence") or candidate.get("demo_data_not_hardware_evidence")),
        "baseline_input_sha256": baseline.get("input_sha256"),
        "candidate_input_sha256": candidate.get("input_sha256"),
        "rules_sha256": baseline.get("rules_sha256") if comparable else None,
        "test_context": bctx if comparable else {},
        "timing_deltas": metrics if comparable else [],
        "finding_deltas": issue_diffs if comparable else [],
        "warnings": ["Only FAIL count increases cause REGRESSION; WARN changes need engineering review.",
                     "Matching test metadata is declared by the operator; hardware provenance is not independently verified."],
    }
