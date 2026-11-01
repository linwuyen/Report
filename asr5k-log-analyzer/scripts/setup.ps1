$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
py -3 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python 3 venv creation failed' }
Write-Host 'Offline core is ready (no packages required).'
Write-Host 'Optional AI SDK: .\.venv\Scripts\python.exe -m pip install -r requirements.txt'
.\.venv\Scripts\python.exe analyzer.py selftest
if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Do not proceed with hardware data.' }
