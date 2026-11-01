# ASR5K Firmware Log Analyzer V1.0.0

**An evidence-first, offline firmware diagnostic tool.** It does not build, flash, modify or control ASR5K firmware, PWM, relay, DDS, MCU registers or hardware. The default (deterministic) path uses only Python's standard library and does **not** contact OpenAI.

> Release scope: the parser/rules/reports have been exercised against synthetic fixtures. **Real ASR5K CCS Watch exports, Logic Analyzer captures, UART logs, Windows platform execution and actual flashed binary provenance still require hardware acceptance.** `V1.0` describes the deployable offline software interface, not confirmed production hardware validity.

## Windows quick start (fresh PC)

1. Install Python 3.10+ and Git for Windows.
2. In Windows PowerShell:

```powershell
git clone https://github.com/linwuyen/ASR5K-Log-Analyzer.git
cd ASR5K-Log-Analyzer\asr5k-log-analyzer
py --version
py analyzer.py selftest
py analyzer.py --input samples/demo.jsonl --output reports/demo.json --demo
start .\reports\demo.html
```

The demo is **deliberately FAIL**: 42.5 ms exceeds the **40 ±1 ms** rule. It is simulated data, not an ASR5K hardware fault. The report includes JSON and a self-contained HTML dashboard. Run the full offline smoke suite:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\smoke.ps1
```

Optional isolated environment (does not install API SDK by default):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

## Commands

### Analyze normalized JSONL (backwards compatible with V0.1)

```powershell
py analyzer.py --input samples/demo.jsonl --output reports/demo.json --demo
py analyzer.py analyze --input samples/demo.jsonl --output reports/demo.json --demo --ai-preview
```

`--ai-preview` **does not call the API**; it writes exactly the summary that could be transmitted to `reports/demo_ai_preview.json`. `--fail-on-fail` returns process exit code 3 on a deterministic FAIL; `--reject-unknown` returns exit code 4 when insufficient evidence remains. Without this option, software successfully writing a FAIL report returns 0.

### Analyze Logic Analyzer CSV

```powershell
py analyzer.py analyze --input samples/la_demo.csv --format la-csv --profile profiles/la_example_unverified.json --output reports/la.json --demo
start .\reports\la.html
```

The example mapping is **unverified**, so it produces `INSUFFICIENT_EVIDENCE` despite computing 42.5 ms and 40.0 ms candidates. To use a real capture, **copy** the profile, update exact column names, capture ID, physical pin/channel mapping, signal polarity, unit and clock source. Change `signal_mapping_verified` to `true` **only after independent bench validation**. This flag is a user assertion, not cryptographic verification. Even then `hardware_acceptance_verified=false` until a full manual evidence chain is completed.

The LA adapter supports wide CSV with a time column and stable digital logic levels. It identifies rising/falling transitions only after seeing a known previous state; the first HIGH sample is **not** assumed to be a rising edge. Missing/unknown levels reset edge detection. All timing pairs must be alternating and captured in the same session, source, timebase, file and capture ID.

### Analyze CCS Watch CSV (static snapshot)

```powershell
py analyzer.py analyze --input samples/watch_demo.csv --format watch-csv --profile profiles/watch_example_unverified.json --output reports/watch.json --demo
```

Watch CSV is treated as **one static snapshot without a real timestamp**. No time is invented. Numeric state values are kept as `system_state_raw` until `verified_enum_map` is explicitly provided from an approved firmware contract. Unknown variables are counted, not automatically decoded. Real CCS exports may have different headers—edit the profile first.

### Analyze UART key=value log

```powershell
py analyzer.py analyze --input samples/uart_demo.log --format uart-kv --profile profiles/uart_example_unverified.json --output reports/uart.json --demo
```

The UART adapter requires a line-anchored regular expression, explicit time unit, source-to-clock mappings and per-session isolation. Unmatched nonempty lines fail ingestion rather than disappearing silently. UART-local clocks are **not** assumed synchronized across CPU1/CPU2/M0.

### Convert raw input to normalized JSONL

```powershell
py analyzer.py convert --input samples/la_demo.csv --format la-csv --profile profiles/la_example_unverified.json --output reports/la_normalized.jsonl
py analyzer.py analyze --input reports/la_normalized.jsonl --output reports/la_converted.json --demo
```

Normalized events retain **declared** raw file hash and original line references. When re-importing a converted JSONL file, the tool has not re-read the original raw file; re-hash the raw data independently before making acceptance claims.

### Compare two test reports

```powershell
py analyzer.py analyze --input samples/demo_pass.jsonl --output reports/baseline.json --demo --test-id SIM_ON_EDGE --hardware-id SIM_DUT --capture-setup-id SIM_LA
py analyzer.py analyze --input samples/demo.jsonl --output reports/candidate.json --demo --test-id SIM_ON_EDGE --hardware-id SIM_DUT --capture-setup-id SIM_LA
py analyzer.py compare --baseline reports/baseline.json --candidate reports/candidate.json --output reports/diff.json --require-comparable --fail-on-regression
start .\reports\diff.html
```

The comparison above is a synthetic **REGRESSION**. Exit code 3 is expected with `--fail-on-regression`. `--require-comparable` returns code 4 if test ID, hardware ID, capture setup, rules hash, import profile hash or simulated/live classification do not match. `NO_NEW_FAIL` means **no newly detected deterministic FAIL**; it is not proof of hardware quality. WARN differences still require review.

### Add explicit timing/state rules

The `profiles/rules_example.json` file provides an opt-in SPIB service interval **without inventing a timing limit** and shows how to configure state transitions once an approved state contract is available.

```powershell
py analyzer.py analyze --input samples/demo.jsonl --rules profiles/rules_example.json --output reports/rules_demo.json --demo
```

For intervals without `max_us`, timing is **observational (INFO)**, not PASS. Unknown enum values, missing clock sync, missing physical mapping and ambiguous event pairs fail closed.

## Optional OpenAI API

Only if sending the *summarized findings* externally is authorized:

```powershell
py -m pip install -r requirements.txt
$secureKey = Read-Host 'Enter OpenAI API Secret Key' -AsSecureString
$env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password.Trim()
py analyzer.py analyze --input samples/demo.jsonl --output reports/demo.json --demo --ai-preview
# Inspect reports/demo_ai_preview.json before approving any external transmission
py analyzer.py analyze --input samples/demo.jsonl --output reports/demo.json --demo --ai --allow-external-upload
```

The SDK calls OpenAI's Responses API with `store=False`. **This is not a promise of zero provider-side retention.** By default no request is sent. The transmitted payload excludes raw logs, signal traces, source files, hash values and local paths but may still contain project-sensitive diagnostic descriptions; never upload company data without permission. AI can hypothesize and recommend tests but **cannot overwrite** deterministic findings. No API key is stored in the repository.

## Report schema and trust limits

Each event has `session_id`, `ts_us` (microseconds; null for static snapshots only), `timebase`, `source`, `event`, `fields`; `capture_id`, `firmware_sha` and `binary_sha256` are optional. Numeric fault/enum semantics are not guessed. Report findings contain source filename, SHA256, original line(s), session/capture/timebase, rule, severity and minimal next test.

- **FAIL**: deterministic configured limit violated, or verified state transition contract violated.
- **WARN**: real observation requiring attention, not proof of root cause.
- **INSUFFICIENT_EVIDENCE**: no trustworthy time pairing / mapping / adequate capture.
- **INFO**: provenance gap or observation without a configured specification.
- **PASS**: deterministic check succeeded on the given interpreted evidence; not hardware acceptance.

The report always sets `hardware_acceptance_verified=false`; real approval requires independent confirmation of the exact flashed `.out`, linked source commit, LA channel mapping, acquisition clock and test conditions. For `Get-FileHash` of the **local** `.out`, see `docs/ACCEPTANCE.md`—this does not on its own prove what was flashed.

## Development & rollback

Run tests on every change:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q asr5k analyzer.py
```

Offline core Python 3.10+; standard-library only. Optional API requires `openai` package and a valid API key. Reports, real logs, secrets, binary files and raw captures are gitignored. Work on a branch, keep a tagged known-good version, and revert only the `asr5k-log-analyzer/` changes if necessary; nothing here touches ASR5K product firmware.

See `docs/ACCEPTANCE.md` for PASS/FAIL acceptance conditions and a concise manual bench checklist.
