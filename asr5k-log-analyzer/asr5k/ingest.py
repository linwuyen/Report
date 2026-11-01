"""Explicit, fail-closed ingestion with source-line and SHA-256 evidence.

Adapters intentionally do not try to guess arbitrary vendor column/enum meanings.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

REQUIRED = ("session_id", "ts_us", "timebase", "source", "event")
UNIT_SCALE = {"s": Decimal(1_000_000), "ms": Decimal(1_000), "us": Decimal(1)}
EVENTS_WITHOUT_TIMESTAMP = {"snapshot", "system_state", "on_edge_terminal", "fault", "protection"}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 250_000


class InputError(ValueError):
    pass


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise InputError(f"input file not found: {path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InputError(f"input exceeds {MAX_FILE_BYTES} bytes: {path.name}")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_ts(value: Any, unit: str, context: str) -> int:
    if unit not in UNIT_SCALE:
        raise InputError(f"{context}: unsupported time unit {unit!r}; choose s/ms/us explicitly")
    if isinstance(value, bool) or value is None:
        raise InputError(f"{context}: timestamp must be numeric")
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise InputError(f"{context}: timestamp is not numeric: {value!r}") from exc
    if not number.is_finite() or number < 0:
        raise InputError(f"{context}: timestamp must be nonnegative and finite")
    timestamp = number * UNIT_SCALE[unit]
    # A decimal timestamp with >microsecond resolution is retained as a float.
    if timestamp == timestamp.to_integral_value():
        return int(timestamp)
    return float(timestamp)  # type: ignore[return-value]


def check_event(record: dict[str, Any], origin: str) -> dict[str, Any]:
    missing = [k for k in REQUIRED if k not in record]
    if missing:
        raise InputError(f"{origin}: missing {', '.join(missing)}")
    for key in ("session_id", "timebase", "source", "event"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise InputError(f"{origin}: {key} must be nonempty text")
    timestamp = record["ts_us"]
    if timestamp is None:
        if record["event"] not in EVENTS_WITHOUT_TIMESTAMP:
            raise InputError(f"{origin}: timed event {record['event']!r} cannot have null ts_us")
    elif isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp) or timestamp < 0:
        raise InputError(f"{origin}: ts_us must be a nonnegative finite number")
    if not isinstance(record.get("fields", {}), dict):
        raise InputError(f"{origin}: fields must be an object")
    record["fields"] = record.get("fields", {})
    if not isinstance(record.get("capture_id", "LEGACY"), str):
        raise InputError(f"{origin}: capture_id must be text")
    return record


def annotate(record: dict[str, Any], path: Path, digest: str, lines: list[int], format_name: str) -> dict[str, Any]:
    # A normalized conversion may carry source references from the original raw
    # file. Preserve the declaration rather than replacing it with the JSONL line.
    # Only direct raw imports are independently hash-checked by this importer.
    declared_origin = record.get("origin") if format_name == "jsonl" else None
    if isinstance(declared_origin, dict) and isinstance(declared_origin.get("lines"), list) and declared_origin.get("lines"):
        record["_line"] = declared_origin["lines"][0]
        record["_lines"] = declared_origin["lines"]
        record["_input_file"] = str(declared_origin.get("file", path.name))
        record["_input_sha256"] = str(declared_origin.get("file_sha256", digest))
        record["_origin_is_reported"] = True
    else:
        record["_line"] = lines[0]
        record["_lines"] = lines
        record["_input_file"] = path.name  # no absolute machine-specific or private paths
        record["_input_sha256"] = digest
        record["_origin_is_reported"] = False
    record["_format"] = format_name
    record.setdefault("capture_id", f"file:{digest[:16]}")
    return check_event(record, f"{path.name}:line {lines[0]}")


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], str]:
    digest = sha256_file(path)
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}:line {line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"{path.name}:line {line_no}: expected JSON object")
            events.append(annotate(record, path, digest, [line_no], "jsonl"))
            if len(events) > MAX_EVENTS:
                raise InputError("event count limit exceeded")
    if not events:
        raise InputError(f"{path.name}: no records found")
    return events, digest


def read_profile(path: Path) -> tuple[dict[str, Any], str]:
    digest = sha256_file(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InputError(f"invalid profile {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError("profile must contain a JSON object")
    return data, digest


def require(profile: dict[str, Any], keys: tuple[str, ...], kind: str) -> None:
    missing = [x for x in keys if x not in profile]
    if missing:
        raise InputError(f"{kind} profile missing required keys: {', '.join(missing)}")


def parse_level(value: str) -> bool | None:
    value = str(value).strip().lower()
    if value in ("1", "true", "high", "h"):
        return True
    if value in ("0", "false", "low", "l"):
        return False
    return None


def read_la_csv(path: Path, profile: dict[str, Any]) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """Convert explicit mapping of a single common-clock digital capture.

    First sampled HIGH is not interpreted as a rising edge; a prior LOW is required.
    """
    require(profile, ("time_column", "time_unit", "signals", "session_id", "capture_id", "timebase"), "la-csv")
    if not isinstance(profile["signals"], dict) or not profile["signals"]:
        raise InputError("la-csv signals must map named events to channel definitions")
    digest = sha256_file(path)
    out: list[dict[str, Any]] = []
    prev: dict[str, bool | None] = {event: None for event in profile["signals"]}
    prior_ts: float | int | None = None
    missing_levels = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = set(reader.fieldnames or [])
        required_columns = {profile["time_column"]}
        for event, spec in profile["signals"].items():
            if event not in ("out_on_high", "dds_wave_start"):
                raise InputError(f"unsupported event {event!r}; explicit mapping required")
            if not isinstance(spec, dict) or "column" not in spec:
                raise InputError(f"signal {event} must define 'column'")
            required_columns.add(spec["column"])
            if spec.get("edge", "rising") not in ("rising", "falling"):
                raise InputError(f"signal {event}: edge must be rising/falling")
        if required_columns - headers:
            raise InputError(f"LA CSV missing columns: {sorted(required_columns - headers)}")
        for row in reader:
            line = reader.line_num
            ts = parse_ts(row[profile["time_column"]], profile["time_unit"], f"line {line}")
            if prior_ts is not None and ts < prior_ts:
                raise InputError(f"line {line}: LA time decreased; verify sorting/timebase before analysis")
            prior_ts = ts
            for event, spec in profile["signals"].items():
                state = parse_level(row[spec["column"]])
                if state is None:
                    missing_levels += 1
                    prev[event] = None
                    continue
                direction = spec.get("edge", "rising")
                trigger = (prev[event] is False and state is True) if direction == "rising" else (prev[event] is True and state is False)
                if trigger:
                    out.append(annotate({
                        "session_id": profile["session_id"], "capture_id": profile["capture_id"],
                        "timebase": profile["timebase"], "source": profile.get("source", "LA"),
                        "ts_us": ts, "event": event,
                        "signal_mapping_verified": bool(profile.get("signal_mapping_verified", False)),
                        "fields": {"channel": spec["column"], "transition": direction},
                    }, path, digest, [line], "la-csv"))
                prev[event] = state
                if len(out) > MAX_EVENTS:
                    raise InputError("event count limit exceeded")
    if not out:
        raise InputError("LA CSV contains no configured transitions; check initial state, column mapping and edges")
    return out, digest, {"type": "la-csv", "events": len(out), "unknown_signal_levels": missing_levels,
                         "mapping_verified": bool(profile.get("signal_mapping_verified", False)),
                         "note": "Initial signal state is not assumed. Physical pin semantics require independent verification."}


def parse_watch_value(raw: str) -> Any:
    text = str(raw).strip()
    if re.fullmatch(r"[+-]?0x[0-9a-fA-F]+", text):
        return int(text, 16)
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?", text):
        value = float(text)
        return value if math.isfinite(value) else text
    return text


def read_watch_csv(path: Path, profile: dict[str, Any]) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """CCS Watch export for ONE static snapshot; no fake timestamp is generated."""
    require(profile, ("variable_column", "value_column", "field_map", "session_id", "source"), "watch-csv")
    if not isinstance(profile["field_map"], dict) or not profile["field_map"]:
        raise InputError("watch-csv field_map must be a nonempty mapping")
    digest = sha256_file(path)
    fields: dict[str, Any] = {}
    lines: list[int] = []
    ignored = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = set(reader.fieldnames or [])
        required_columns = {profile["variable_column"], profile["value_column"]}
        if required_columns - headers:
            raise InputError(f"Watch CSV missing columns: {sorted(required_columns - headers)}")
        for row in reader:
            key = str(row[profile["variable_column"]]).strip()
            if key not in profile["field_map"]:
                ignored += 1
                continue
            field = profile["field_map"][key]
            if field in fields:
                raise InputError(f"line {reader.line_num}: duplicate canonical Watch field {field!r}")
            value = parse_watch_value(row[profile["value_column"]])
            # Map an enum ONLY when a user-provided verified map explicitly supplies it.
            enum = profile.get("verified_enum_map", {}).get(field, {})
            if isinstance(enum, dict):
                value = enum.get(str(value), value)
            fields[field] = value
            lines.append(reader.line_num)
    if not fields:
        raise InputError("Watch CSV has no mapped fields; check exact column and variable names")
    if "system_state" in fields and not isinstance(fields["system_state"], str):
        # Numeric state codes have no defined meaning without an enum contract.
        fields["system_state_raw"] = fields.pop("system_state")
    record = annotate({
        "session_id": profile["session_id"], "ts_us": None,
        "capture_id": profile.get("capture_id", f"watch:{digest[:16]}"),
        "timebase": "UNSPECIFIED", "source": profile["source"],
        "event": "snapshot", "fields": fields,
    }, path, digest, lines, "watch-csv")
    return [record], digest, {"type": "watch-csv", "mapped_fields": len(fields), "ignored_variables": ignored,
                               "note": "One static snapshot, timestamp unknown; cannot infer event ordering or latency."}


def parse_key_values(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # Strict space-separated key=value tokens. Quoted values are intentionally unsupported.
    for item in text.strip().split():
        if "=" not in item:
            raise InputError(f"malformed UART token {item!r}; expected key=value")
        key, value = item.split("=", 1)
        if not key or key in out:
            raise InputError(f"duplicate/empty UART field name {key!r}")
        out[key] = parse_watch_value(value)
    return out


def read_uart_kv(path: Path, profile: dict[str, Any]) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """Strict opt-in text adapter. No guesswork for unrecognized lines."""
    require(profile, ("pattern", "time_unit", "timebase_by_source", "session_id"), "uart-kv")
    digest = sha256_file(path)
    try:
        pattern = re.compile(profile["pattern"])
    except re.error as exc:
        raise InputError(f"invalid UART pattern: {exc}") from exc
    if not {"timestamp", "source", "event", "kv"}.issubset(pattern.groupindex):
        raise InputError("UART regex must define timestamp, source, event, kv named groups")
    events = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            found = pattern.fullmatch(raw.rstrip("\r\n"))
            if not found:
                raise InputError(f"line {line_no}: unrecognized UART format; no data silently discarded")
            source = found.group("source")
            if source not in profile["timebase_by_source"]:
                raise InputError(f"line {line_no}: no explicit clock domain for {source}")
            fields = parse_key_values(found.group("kv"))
            fields = {profile.get("field_map", {}).get(key, key): value for key, value in fields.items()}
            events.append(annotate({
                "session_id": profile["session_id"], "capture_id": profile.get("capture_id", f"uart:{digest[:16]}"),
                "ts_us": parse_ts(found.group("timestamp"), profile["time_unit"], f"line {line_no}"),
                "source": source, "timebase": profile["timebase_by_source"][source],
                "event": profile.get("event_map", {}).get(found.group("event"), found.group("event")),
                "fields": fields,
            }, path, digest, [line_no], "uart-kv"))
            if len(events) > MAX_EVENTS:
                raise InputError("event count limit exceeded")
    if not events:
        raise InputError("UART file contains no events")
    return events, digest, {"type": "uart-kv", "events": len(events)}


def import_events(path: Path, kind: str, profile_path: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if kind == "jsonl":
        if profile_path is not None:
            raise InputError("jsonl does not need a mapping profile")
        records, digest = read_jsonl(path)
        return records, {"filename": path.name, "sha256": digest, "format": kind, "profile_sha256": None,
                         "quality": {"type": "jsonl", "records": len(records)}}
    if profile_path is None:
        raise InputError(f"{kind} requires --profile with explicitly verified column definitions")
    profile, profile_sha = read_profile(profile_path)
    if kind == "la-csv":
        records, digest, quality = read_la_csv(path, profile)
    elif kind == "watch-csv":
        records, digest, quality = read_watch_csv(path, profile)
    elif kind == "uart-kv":
        records, digest, quality = read_uart_kv(path, profile)
    else:
        raise InputError(f"unknown input format: {kind}")
    return records, {"filename": path.name, "sha256": digest, "format": kind,
                     "profile_name": profile_path.name, "profile_sha256": profile_sha,
                     "quality": quality}


def export_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for event in records:
            public = {key: val for key, val in event.items() if not key.startswith("_")}
            # Preserve original provenance even after conversion to normalized JSONL.
            public["origin"] = {"file": event.get("_input_file"), "file_sha256": event.get("_input_sha256"),
                                "lines": event.get("_lines", [event["_line"]])}
            fh.write(json.dumps(public, ensure_ascii=False, allow_nan=False, sort_keys=True) + "\n")
