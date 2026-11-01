$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
if (Test-Path '.\.venv\Scripts\python.exe') { $py = '.\.venv\Scripts\python.exe' } else { $py = 'py' }
& $py analyzer.py selftest
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }
& $py analyzer.py --input samples/demo.jsonl --output reports/demo.json --demo
if ($LASTEXITCODE -ne 0) { throw 'Legacy smoke failed' }
& $py analyzer.py analyze --input samples/la_demo.csv --format la-csv --profile profiles/la_example_unverified.json --output reports/la_demo.json --demo
if ($LASTEXITCODE -ne 0) { throw 'LA CSV smoke failed' }
& $py analyzer.py analyze --input samples/watch_demo.csv --format watch-csv --profile profiles/watch_example_unverified.json --output reports/watch_demo.json --demo
if ($LASTEXITCODE -ne 0) { throw 'CCS Watch smoke failed' }
& $py analyzer.py analyze --input samples/uart_demo.log --format uart-kv --profile profiles/uart_example_unverified.json --output reports/uart_demo.json --demo
if ($LASTEXITCODE -ne 0) { throw 'UART smoke failed' }
Write-Host 'Smoke PASS. HTML reports are in .\reports'
