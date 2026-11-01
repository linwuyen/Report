#!/usr/bin/env python3
"""Backwards-compatible entry point for ASR5K Analyzer V1.0.

V0.1 users may continue: py analyzer.py --input ... --output ... --demo
"""
from asr5k.ingest import read_jsonl
from asr5k.analysis import analyze, finding
from asr5k.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
