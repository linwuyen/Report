# ASR5K Analyzer V1.0 Acceptance and Evidence Contract

## Definitions

- **Software release candidate** means source code, schemas, CLI and deterministic rules pass local automated tests.
- **Hardware acceptance** means traceable real ASR5K captures validate a specific controller, firmware build, waveform and measurement chain.
- `PASS` applies to *one evaluated deterministic rule*. It cannot, by itself, certify a DUT, product firmware, or flashed binary.
- `UNKNOWN` is represented as `INSUFFICIENT_EVIDENCE`, not fabricated numerical PASS/FAIL.

## Evidence needed for real ON-edge 40 ±1 ms

1. Obtain approval for collecting/exporting the test data. Keep original raw capture **outside the public GitHub repository**.
2. Record actual board ID, source git SHA, exact `.out` path and `Get-FileHash -Algorithm SHA256 <path-to-out>`. Independently check the flashing/programming process and link it to that binary; hashing a file alone does **not** prove it was flashed.
3. Independently verify the Logic Analyzer channel connected to **M0's physical OUT-ON pin**, edge polarity, capture resolution/timebase and the channel or observable physical signal representing **DDS WAVE activation**. A CPU1 command timestamp is **not** a substitute for OUT-ON HIGH.
4. Capture several ON/OFF cycles with both physical edges **on the same LA clock**. Label captures/sessions so RESET sequences are not mixed. Initial HIGH without a preceding LOW must not count as an edge.
5. Copy `profiles/la_example_unverified.json`, update it for real column names, source/capture/session labels and pin definitions. Only set `signal_mapping_verified=true` after independent bench evidence exists.
6. Run `analyze --format la-csv ...`. Verify every computed interval by comparing the raw CSV line numbers against the actual instrument timeline. PASS only when **39,000 <= delay_us <= 41,000**, inclusive, under the approved mapping.
7. Re-run with a deliberately mis-mapped channel, missing edge, reversed timestamp and cross-clock sample: the result must be `INSUFFICIENT_EVIDENCE` or an explicit input error, never a fake PASS.

## Engine guarantees and limitations

| Rule | Pass / observable | Fail / unknown | Regression risk |
|---|---|---|---|
| JSONL parse | Strict record schema + source SHA | Bad line or nonfinite timestamp aborts | Accepting partial corrupt data |
| LA CSV | Explicit column mapping, edge polarity, monotonic time | Unknown initial level ignored, missing mapping -> UNKNOWN | False rising edges / wrong pin |
| CCS Watch | Mapped variable values in one snapshot | No timestamp or numeric enum guesses | Fake temporal sequence |
| UART KV | All nonempty lines match anchored format | Bad line, unmapped source clock -> input error | Silent log loss |
| 40 ms timing | Same file/capture/source/timebase, clear start/end pairs | Ambiguous or cross-timebase -> UNKNOWN | False timing PASS |
| State / fault | Fault explicitly logged; transitions only checked against supplied contract | No invented enum/root cause | Misclassified FAULT |
| Regression | Same test ID, DUT ID, setup ID, rule hash, mapping hash, demo flag | NOT_COMPARABLE if any differ; unknown sample counts | Apples-to-oranges comparisons |
| AI | Explicit authorization and SDK; summarizes deterministic evidence | API outage leaves offline report intact | Hypotheses misread as facts |
| HTML | Standalone and all user-controlled text HTML escaped | Not a live dashboard, no external telemetry | Script injection |

## Explicit stop conditions

- Cross-core timestamps lack a verified shared clock.
- Actual `.out` / source relationship is not independently established.
- CCS exports show undocumented enum value or unknown state semantics.
- Two pulses or paired edges cannot be unambiguously associated.
- Real company logs are not authorized for external API processing.

For these conditions, stop the relevant acceptance claim and collect the missing evidence. Do not solve it by weakening constraints.

## Windows test procedure

```powershell
py analyzer.py selftest
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\smoke.ps1
start .\reports\demo.html
```

**Expected:** 51 offline unit tests PASS at initial local implementation. Synthetic `demo.jsonl` must report `Overall: FAIL` because of deliberate 42.5 ms; unverified LA example must report `INSUFFICIENT_EVIDENCE`. Actual Windows environment/SDK behavior must be measured independently.

**Rollback:** restore the previous commit of `asr5k-log-analyzer/`; preserve existing raw files and reports. Never revert or modify ASR5K product firmware as part of analyzer rollback.
