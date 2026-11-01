"""Portable Windows/Linux command line; old V0.1 flags remain supported."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .ai import interpret, preview_payload
from .analysis import analyze, verified_rules
from .ingest import InputError, export_jsonl, import_events
from .outputs import render_analysis, render_comparison, save_html, save_json
from .regression import compare

FORMATS = ("jsonl", "la-csv", "watch-csv", "uart-kv")


def _model_path(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, UnicodeError, OSError) as exc:
        raise InputError(f"invalid JSON: {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path.name}: expected JSON object")
    return data


def _emit(report: dict[str, Any], output: Path, html: Path | None, *, comparison: bool = False) -> None:
    save_json(output, report)
    html_path = html or output.with_suffix(".html")
    save_html(html_path, render_comparison(report) if comparison else render_analysis(report))
    print(f"JSON report: {output}")
    print(f"Offline HTML: {html_path}")


def _cmd_analyze(args: argparse.Namespace) -> int:
    records, info = import_events(args.input, args.format, args.profile)
    rules = verified_rules(_model_path(args.rules) if args.rules else None)
    context = {name: value for name, value in (
        ("test_id", args.test_id), ("hardware_id", args.hardware_id),
        ("capture_setup_id", args.capture_setup_id)) if value}
    report = analyze(records, info["sha256"], rules, source_info=info, test_context=context)
    report["demo_data_not_hardware_evidence"] = bool(args.demo)
    _emit(report, args.output, args.html)
    print(f"Overall: {report['overall']} | {report['records']} events | {report['sessions']} session(s)")
    for f in report["findings"]:
        print(f"[{f['status']}] {f['rule']} lines={f['evidence_lines']}: {f['detail']}")
    if args.ai_preview:
        preview_path = args.output.with_name(args.output.stem + "_ai_preview.json")
        save_json(preview_path, preview_payload(report))
        print(f"Review exactly what may be sent to API: {preview_path} (no upload)")
    if args.ai:
        try:
            interpretation = interpret(report, approved=args.allow_external_upload, model=args.model)
        except Exception as exc:
            print(f"AI analysis unavailable: {exc}", file=sys.stderr)
            return 2
        ai_path = args.output.with_name(args.output.stem + "_ai.md")
        ai_path.write_text(interpretation + "\n", encoding="utf-8")
        print(f"Optional AI interpretation: {ai_path}")
    if args.fail_on_fail and report["overall"] == "FAIL":
        return 3
    if args.reject_unknown and report["status_counts"].get("INSUFFICIENT_EVIDENCE", 0):
        return 4
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    if args.format == "jsonl":
        raise InputError("use analyze directly for existing normalized JSONL")
    records, info = import_events(args.input, args.format, args.profile)
    export_jsonl(records, args.output)
    print(f"Converted {len(records)} events from {info['filename']} ({info['format']}) -> {args.output}")
    print(f"Source SHA256: {info['sha256']}; profile SHA256: {info['profile_sha256']}")
    print("No hardware semantics were guessed. Converted events retain original file/line evidence.")
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    baseline = _model_path(args.baseline)
    candidate = _model_path(args.candidate)
    result = compare(baseline, candidate)
    _emit(result, args.output, args.html, comparison=True)
    print(f"Regression verdict: {result['verdict']}")
    for item in result["comparability_blockers"]:
        print(f"[BLOCKER] {item}")
    if args.fail_on_regression and result["verdict"] == "REGRESSION":
        return 3
    if args.require_comparable and not result["comparable"]:
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0].startswith("-") and arguments[0] not in ("--help", "-h", "--version"):
        arguments.insert(0, "analyze")  # legacy: py analyzer.py --input ...
    p = argparse.ArgumentParser(prog="analyzer.py", description="ASR5K Offline Diagnostic Center V1.0 — never touches firmware")
    p.add_argument("--version", action="version", version=f"ASR5K Analyzer {__version__}")
    commands = p.add_subparsers(dest="command", required=True)
    a = commands.add_parser("analyze", help="analyze normalized/explicitly mapped offline data")
    a.add_argument("--input", type=Path, required=True)
    a.add_argument("--format", choices=FORMATS, default="jsonl")
    a.add_argument("--profile", type=Path, help="required for raw formats; map physical channels and columns explicitly")
    a.add_argument("--rules", type=Path, help="optional strict rule contract JSON")
    a.add_argument("--output", type=Path, default=Path("reports/report.json"))
    a.add_argument("--html", type=Path)
    a.add_argument("--test-id", help="required for meaningful regression comparison")
    a.add_argument("--hardware-id", help="explicit DUT/board identifier")
    a.add_argument("--capture-setup-id", help="explicit verified measurement setup identifier")
    a.add_argument("--demo", action="store_true", help="mark fixture as simulated (never hardware evidence)")
    a.add_argument("--fail-on-fail", action="store_true", help="exit 3 if deterministic overall FAIL")
    a.add_argument("--reject-unknown", action="store_true", help="exit 4 if any rule has insufficient evidence")
    a.add_argument("--ai", action="store_true", help="optional API analysis; disabled by default")
    a.add_argument("--ai-preview", action="store_true", help="write local JSON payload preview, no upload")
    a.add_argument("--allow-external-upload", action="store_true", help="operator confirms data may leave the machine")
    a.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-6.1-terra"))
    a.set_defaults(func=_cmd_analyze)

    conv = commands.add_parser("convert", help="convert explicitly mapped raw logs to normalized JSONL")
    conv.add_argument("--input", type=Path, required=True)
    conv.add_argument("--format", choices=("la-csv", "watch-csv", "uart-kv"), required=True)
    conv.add_argument("--profile", type=Path, required=True)
    conv.add_argument("--output", type=Path, required=True)
    conv.set_defaults(func=_cmd_convert)

    cmp = commands.add_parser("compare", help="compare two deterministic JSON reports")
    cmp.add_argument("--baseline", type=Path, required=True)
    cmp.add_argument("--candidate", type=Path, required=True)
    cmp.add_argument("--output", type=Path, default=Path("reports/regression.json"))
    cmp.add_argument("--html", type=Path)
    cmp.add_argument("--fail-on-regression", action="store_true", help="exit 3 if new FAIL rules detected")
    cmp.add_argument("--require-comparable", action="store_true", help="exit 4 if required metadata missing/mismatch")
    cmp.set_defaults(func=_cmd_compare)

    selftest = commands.add_parser("selftest", help="run offline Python unit tests without API/network")
    selftest.set_defaults(func=lambda _: subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=Path(__file__).resolve().parents[1], check=False).returncode)
    try:
        ns = p.parse_args(arguments)
        return ns.func(ns)
    except (InputError, ValueError, OSError) as exc:
        print(f"INPUT/CONFIG ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
