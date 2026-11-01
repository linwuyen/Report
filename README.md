# ASR5K Log Analyzer

**V1.0.0 offline diagnostic tool** — [Source, Windows setup and documentation](asr5k-log-analyzer/README.md).

Features: normalized JSONL, mapped Logic Analyzer CSV, CCS Watch CSV, UART KV logs, deterministic 40 ±1 ms timing rules, evidence traceability, fault/state analysis, offline HTML reports, regression comparison and optional OpenAI API.

Quick start on Windows PowerShell:

```powershell
git clone https://github.com/linwuyen/ASR5K-Log-Analyzer.git
cd ASR5K-Log-Analyzer\asr5k-log-analyzer
py analyzer.py selftest
py analyzer.py --input samples/demo.jsonl --output reports/demo.json --demo
start .\reports\demo.html
```

**The included samples are simulated.** Real ASR5K bench verification and Windows runtime acceptance are pending; never interpret synthetic PASS/FAIL as actual hardware results.

The pre-existing `index.html` and `buck.html` files have been left unchanged.
