"""Self-contained offline reports; all imported strings escaped as HTML text."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

BASE_STYLE = """
:root{font-family:system-ui,'Segoe UI',Arial,sans-serif;color-scheme:light;--fg:#14283a;--bg:#f3f6f9;--card:#fff;--line:#d7e0e8}
*{box-sizing:border-box}body{max-width:1200px;margin:0 auto;padding:28px 18px 90px;background:var(--bg);color:var(--fg)}
h1{margin:0;font-size:28px}h2{margin-top:26px;font-size:20px}small,.muted{color:#5e7180}.muted{font-size:13px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:17px;margin:15px 0;box-shadow:0 1px 3px #0000000a}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.stat{font-weight:700;font-size:24px}
.badge{border-radius:5px;padding:2px 7px;font-size:12px;font-weight:700;display:inline-block;background:#e6ebef;color:#334}
.FAIL,.REGRESSION{background:#fbe0e0;color:#921919}.WARN{background:#fff0c4;color:#725200}
.PASS,.NO_NEW_FAIL{background:#d4f3e6;color:#086a4a}.INFO,.INSUFFICIENT_EVIDENCE,.NOT_COMPARABLE,.INCOMPLETE_COMPARISON{background:#e0eaf6;color:#174d82}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:9px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{position:sticky;top:0;background:#edf2f6}.scroll{max-height:400px;overflow:auto}details{padding:12px 0;border-bottom:1px solid var(--line)}summary{cursor:pointer;font-weight:600}
code,pre{font-family:ui-monospace,Consolas,monospace}code{word-break:break-word}pre{white-space:pre-wrap;overflow-wrap:anywhere}
.search{max-width:450px;border:1px solid var(--line);border-radius:7px;padding:8px;font-size:14px;width:100%}
.footer{margin-top:26px;font-size:12px;color:#677}
@media print{body{padding:0;background:white}.panel{box-shadow:none}button,input{display:none}}
"""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def badge(value: str) -> str:
    safe = esc(value)
    return f'<span class="badge {safe}">{safe}</span>'


def head(title: str) -> str:
    return '<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' + f'<title>{esc(title)}</title><style>{BASE_STYLE}</style></head><body>'


def evidence_list(items: list[dict[str, Any]]) -> str:
    pieces = []
    for e in items:
        digest = str(e.get("file_sha256", "UNKNOWN"))
        lines = ",".join(str(x) for x in e.get("lines", []) if x is not None)
        pieces.append(f'<li><code>{esc(e.get("file", "UNKNOWN"))} : L{esc(lines)} / sha256={esc(digest)}</code> '
                      f'({esc(e.get("source"))}/{esc(e.get("timebase"))}, ts={esc(e.get("ts_us"))})</li>')
    return '<ul>' + ''.join(pieces) + '</ul>' if pieces else '<p class="muted">No source references</p>'


def render_analysis(report: dict[str, Any]) -> str:
    out = [head("ASR5K Diagnostic Report V1.0")]
    out.append('<h1>ASR5K Diagnostic Center <small>V1.0</small></h1>')
    out.append('<p class="muted">離線分析／確定性判定。此報告本身不證明實際燒錄版本或硬體量測鏈已驗收。</p>')
    out.append('<div class="grid">')
    for label, value in (("Overall", badge(report["overall"])), ("Records", esc(report["records"])),
                         ("Sessions", esc(report["sessions"])),
                         ("Hardware Acceptance", badge("UNVERIFIED"))):
        out.append(f'<section class="panel"><div class="muted">{label}</div><div class="stat">{value}</div></section>')
    out.append('</div>')
    if report.get("demo_data_not_hardware_evidence"):
        out.append('<p class="panel"><b>SIMULATED DATA:</b> This report is a test fixture, not a hardware acceptance record.</p>')
    input_info = report.get("input", {})
    ctx = report.get("test_context", {})
    out.append('<section class="panel"><h2>Traceability</h2><table>')
    for label, value in (("Input", input_info.get("filename", "UNKNOWN")),
                         ("File SHA256", input_info.get("sha256", report.get("input_sha256"))),
                         ("Mapping SHA256", input_info.get("profile_sha256", "None")),
                         ("Rules SHA256", report.get("rules_sha256")),
                         ("Test ID", ctx.get("test_id", "NOT RECORDED")),
                         ("Hardware ID", ctx.get("hardware_id", "NOT RECORDED")),
                         ("Setup ID", ctx.get("capture_setup_id", "NOT RECORDED"))):
        out.append(f'<tr><th>{esc(label)}</th><td><code>{esc(value)}</code></td></tr>')
    out.append('</table><p class="muted">Hash metadata is reported evidence; flashed binary correspondence needs independent validation.</p></section>')
    out.append('<section class="panel"><h2>Findings (' + str(len(report["findings"])) + ')</h2>')
    out.append('<input aria-label="Filter findings" class="search" id="search" placeholder="搜尋 rule / detail / status" oninput="filterFindings()">')
    for f in report["findings"]:
        detail = esc(f["detail"])
        out.append(f'<details class="finding" data-search="{esc(f["rule"] + " " + f["detail"] + " " + f["status"])}"><summary>{badge(f["status"])} '
                   f'{esc(f["rule"])} — {detail}</summary><div><p><b>下一個最小測試：</b>{esc(f["next_test"])}</p>'
                   '<b>Evidence</b>' + evidence_list(f.get("evidence", [])) + '</div></details>')
    out.append('</section>')
    out.append('<section class="panel"><h2>Timing Metrics</h2><table><thead><tr><th>Rule</th><th>N</th><th>Min (ms)</th><th>Median (ms)</th><th>Max (ms)</th></tr></thead><tbody>')
    for name, metric in report.get("timing_statistics", {}).items():
        out.append(f'<tr><td>{esc(name)}</td><td>{metric["count"]}</td><td>{metric["min_us"]/1000:g}</td>'
                   f'<td>{metric["median_us"]/1000:g}</td><td>{metric["max_us"]/1000:g}</td></tr>')
    out.append('</tbody></table></section>')
    events = report.get("events", [])
    out.append('<section class="panel"><h2>Event Timeline</h2><p class="muted">前 1000 筆事件；保留原始檔案與行號可重新檢驗。</p>'
               '<div class="scroll"><table><thead><tr><th>Session</th><th>Capture</th><th>Timestamp (µs)</th>'
               '<th>Source</th><th>Event</th><th>Evidence</th></tr></thead><tbody>')
    for event in events[:1000]:
        evidence = event.get("evidence", {})
        out.append(f'<tr><td>{esc(event["session_id"])}</td><td>{esc(event["capture_id"])}</td><td>{esc(event["ts_us"])}</td>'
                   f'<td>{esc(event["source"])}</td><td>{esc(event["event"])}</td>'
                   f'<td>{esc(evidence.get("file"))}:{esc(evidence.get("lines"))}</td></tr>')
    out.append('</tbody></table></div></section>')
    out.append('<div class="footer">Deterministic offline output; OpenAI never modifies pass/fail status.</div>')
    out.append('<script>function filterFindings(){const q=document.getElementById("search").value.toLowerCase();'
               'document.querySelectorAll(".finding").forEach(e=>{e.style.display=e.dataset.search.toLowerCase().includes(q)?"":"none"})}</script></body></html>')
    return ''.join(out)


def render_comparison(report: dict[str, Any]) -> str:
    out = [head("ASR5K Regression Comparison V1.0"), '<h1>ASR5K Regression Comparison V1.0</h1>']
    out.append(f'<div class="panel"><h2>Verdict: {badge(report["verdict"])}</h2>')
    if report.get("demo_data_not_hardware_evidence"):
        out.append('<p><b>SIMULATED DATA:</b> Comparison is a software fixture check, not hardware regression acceptance.</p>')
    if report["comparability_blockers"]:
        out.append('<p><b>Comparison blocked:</b></p><ul>' + ''.join(f'<li>{esc(x)}</li>' for x in report["comparability_blockers"]) + '</ul>')
    out.append('</div>')
    out.append('<section class="panel"><h2>Timing changes</h2><table><thead><tr><th>Rule</th><th>Comparable</th><th>Max Δ (µs)</th><th>Median Δ (µs)</th></tr></thead><tbody>')
    for item in report.get("timing_deltas", []):
        out.append(f'<tr><td>{esc(item["rule"])}</td><td>{esc(item["comparable"])}</td>'
                   f'<td>{esc(item.get("delta_max_us", item.get("reason", "--")))}</td>'
                   f'<td>{esc(item.get("delta_median_us", "--"))}</td></tr>')
    out.append('</tbody></table></section>')
    out.append('<section class="panel"><h2>Finding changes</h2><table><thead><tr><th>Rule</th><th>New FAIL</th><th>New WARN</th></tr></thead><tbody>')
    for item in report.get("finding_deltas", []):
        out.append(f'<tr><td>{esc(item["rule"])}</td><td>{esc(item["new_failures"])}</td><td>{esc(item["new_warnings"])}</td></tr>')
    out.append('</tbody></table></section>')
    out.append('<p class="footer">Metadata matches are declared by user, not independent proof of identical hardware or flashed binary.</p></body></html>')
    return ''.join(out)


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys + no clock timestamps makes report reproducible byte-for-byte.
    path.write_text(json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + '\n', encoding="utf-8")


def save_html(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
