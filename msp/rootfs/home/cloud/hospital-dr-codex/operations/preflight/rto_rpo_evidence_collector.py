#!/usr/bin/env python3
"""Collect a presentation-safe RTO/RPO evidence bundle from runtime evidence.

This collector is deliberately read-only with respect to operational sources.
It reads the existing RTO timeline, ChatOps state/audit, optional timing JSONL,
and an operator-supplied read-only RPO document.  It never connects to AWS or
MySQL, changes replication, sends Slack messages, or starts a DR workflow.

Both ``run_id`` and ``incident_id`` are required.  A missing or ambiguous
source remains unmeasured; the collector never invents a timestamp or merges a
different run merely because it is the newest record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from rpo_evidence import collect as collect_rpo_evidence
except ImportError:  # pragma: no cover - supports importing from repository root
    from operations.preflight.rpo_evidence import collect as collect_rpo_evidence


RTO_TARGET_SECONDS = 3600
RPO_TARGET_SECONDS = 15 * 60
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# The order is used only to reject impossible evidence.  Missing events are
# allowed because real runs may not expose every source.
EVENT_ORDER = (
    "incident_detected_at",
    "zabbix_problem_at",
    "dr_escalation_at",
    "slack_request_at",
    "first_approval_at",
    "second_approval_at",
    "execution_started_at",
    "terraform_started_at",
    "terraform_completed_at",
    "ansible_started_at",
    "ansible_completed_at",
    "aws_service_healthy_at",
    "traffic_recovered_at",
    "failover_completed_at",
)

TIMELINE_STAGE_MAP = {
    "incident_at": "incident_detected_at",
    "zabbix_detected_at": "zabbix_problem_at",
    "failover_approval_created_at": "slack_request_at",
    "first_approval_at": "first_approval_at",
    "second_approval_at": "second_approval_at",
    "failover_approved_at": "second_approval_at",
    "failover_started_at": "execution_started_at",
    "terraform_started_at": "terraform_started_at",
    "terraform_completed_at": "terraform_completed_at",
    "ansible_started_at": "ansible_started_at",
    "ansible_completed_at": "ansible_completed_at",
    "service_recovered_at": "aws_service_healthy_at",
    "dns_traffic_recovered_at": "traffic_recovered_at",
    "failover_completed_at": "failover_completed_at",
}

TIMING_EVENT_MAP = {
    ("terraform", "started_at"): "terraform_started_at",
    ("terraform", "finished_at"): "terraform_completed_at",
    ("ansible", "started_at"): "ansible_started_at",
    ("ansible", "finished_at"): "ansible_completed_at",
    ("aws_service", "started_at"): "aws_service_healthy_at",
    ("aws_service", "finished_at"): "aws_service_healthy_at",
    ("traffic", "finished_at"): "traffic_recovered_at",
}

RPO_OPTIONAL_FIELDS = (
    "source_log_file",
    "source_log_pos",
    "replica_log_file",
    "replica_log_pos",
    "relay_source_log_file",
    "relay_source_log_pos",
    "exec_source_log_file",
    "exec_source_log_pos",
    "seconds_behind_source",
    "last_test_transaction_id",
    "last_replicated_transaction_id",
    "incident_at",
    "last_replicated_at",
    "last_dump_at",
    "dump_timestamp",
    "checksum",
    "checksum_algorithm",
    "replica_io_running",
    "replica_sql_running",
    "master_status",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_timestamp(value: Any) -> tuple[float, str]:
    """Parse only an actual source timestamp; never substitute current time."""

    if value is None or isinstance(value, bool) or str(value).strip() == "":
        raise ValueError("timestamp is missing")
    if isinstance(value, (int, float)):
        epoch = float(value)
        if not math.isfinite(epoch):
            raise ValueError("timestamp is not finite")
        parsed = datetime.fromtimestamp(epoch, timezone.utc)
        return epoch, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")

    raw = str(value).strip()
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", raw):
            return _canonical_timestamp(float(raw))
        parsed_raw = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        parsed = datetime.fromisoformat(parsed_raw)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timestamp is not ISO-8601 or epoch") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp timezone is missing")
    parsed = parsed.astimezone(timezone.utc)
    epoch = parsed.timestamp()
    return epoch, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_id(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not value or not ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a non-empty safe identifier")
    return value


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_source_path(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _event_set(
    events: dict[str, dict[str, Any]],
    event: str,
    value: Any,
    source: str,
    errors: list[str],
    duplicates: list[str],
) -> None:
    if value is None or str(value).strip() == "":
        return
    try:
        epoch, canonical = _canonical_timestamp(value)
    except ValueError as exc:
        errors.append(f"INVALID_TIMESTAMP:{event}:{source}:{exc}")
        return
    candidate = {"at": canonical, "epoch": epoch, "source": source}
    existing = events.get(event)
    if existing is None:
        events[event] = candidate
        return
    if abs(float(existing["epoch"]) - epoch) < 0.000001:
        duplicates.append(f"{event}:{source}")
        return
    # Conflicting timestamps must never be silently selected.  Keep the first
    # authoritative value for inspectability but make the RTO unmeasured.
    errors.append(f"CONFLICTING_TIMESTAMP:{event}:{existing['source']}:{source}")


def _timeline_stages(run: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    stages = run.get("stages")
    if not isinstance(stages, dict):
        return {}, set()
    event_ids: set[str] = set()
    for value in stages.values():
        if isinstance(value, dict) and value.get("event_id"):
            event_ids.add(str(value["event_id"]))
    return stages, event_ids


def _collect_timeline(
    path: Path | None,
    run_id: str,
    incident_id: str,
    events: dict[str, dict[str, Any]],
    errors: list[str],
    duplicates: list[str],
) -> dict[str, Any]:
    result = {"path": _safe_source_path(path), "status": "MISSING", "incident_linked": False}
    if path is None or not path.is_file():
        return result
    try:
        document = _read_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError):
        result["status"] = "INVALID"
        return result
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        result["status"] = "INVALID"
        return result
    matches = [run for run in runs if isinstance(run, dict) and run.get("run_id") == run_id]
    if len(matches) == 0:
        result["status"] = "NOT_MATCHED"
        return result
    if len(matches) != 1:
        errors.append("DUPLICATE_RUN_ID")
        result["status"] = "AMBIGUOUS"
        return result
    run = matches[0]
    stages, event_ids = _timeline_stages(run)
    result["status"] = "PASS"
    result["incident_linked"] = incident_id in event_ids
    for stage, value in stages.items():
        event = TIMELINE_STAGE_MAP.get(stage)
        if event is None:
            continue
        timestamp = value.get("at") if isinstance(value, dict) else value
        _event_set(events, event, timestamp, f"rto_timeline:{stage}", errors, duplicates)
    return result


def _read_state_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    uri = f"file:{path}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "approval_requests" not in tables:
            return []
        return [dict(row) for row in connection.execute("SELECT * FROM approval_requests").fetchall()]


def _collect_state(
    path: Path | None,
    run_id: str,
    incident_id: str,
    events: dict[str, dict[str, Any]],
    errors: list[str],
    duplicates: list[str],
) -> tuple[dict[str, Any], set[str]]:
    result = {
        "path": _safe_source_path(path), "status": "MISSING", "matched_requests": 0,
        "request_status": None,
    }
    request_ids: set[str] = set()
    if path is None or not path.is_file():
        return result, request_ids
    try:
        rows = _read_state_rows(path)
    except (OSError, sqlite3.Error, UnicodeError):
        result["status"] = "INVALID"
        return result, request_ids

    matches: list[dict[str, Any]] = []
    for row in rows:
        try:
            incidents = json.loads(row.get("incidents") or "[]")
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(incidents, list):
            continue
        if any(
            isinstance(item, dict)
            and (
                str(item.get("incident_id") or "") == incident_id
                or str(item.get("rto_run_id") or "") == run_id
            )
            for item in incidents
        ):
            matches.append(row)
    result["matched_requests"] = len(matches)
    if len(matches) > 1:
        errors.append("DUPLICATE_STATE_REQUEST_MATCH")
        result["status"] = "AMBIGUOUS"
    elif matches:
        result["status"] = "PASS"
    else:
        result["status"] = "NOT_MATCHED"

    for row in matches[:1]:
        result["request_status"] = str(row.get("status") or "").upper() or None
        request_id = str(row.get("request_id") or "")
        if request_id:
            request_ids.add(request_id)
        try:
            incidents = json.loads(row.get("incidents") or "[]")
        except (TypeError, json.JSONDecodeError):
            incidents = []
        matching_incidents = [
            item
            for item in incidents
            if isinstance(item, dict)
            and (
                str(item.get("incident_id") or "") == incident_id
                or str(item.get("rto_run_id") or "") == run_id
            )
        ]
        for incident in matching_incidents:
            _event_set(
                events,
                "incident_detected_at",
                incident.get("incident_at"),
                "chatops_state:incident_at",
                errors,
                duplicates,
            )
            if str(incident.get("source") or "").lower() == "zabbix":
                _event_set(
                    events,
                    "zabbix_problem_at",
                    incident.get("observed_at"),
                    "chatops_state:observed_at",
                    errors,
                    duplicates,
                )
        _event_set(events, "slack_request_at", row.get("created_at"), "chatops_state:created_at", errors, duplicates)
        _event_set(events, "first_approval_at", row.get("first_approved_at"), "chatops_state:first_approved_at", errors, duplicates)
        _event_set(events, "execution_started_at", row.get("execution_started_at"), "chatops_state:execution_started_at", errors, duplicates)
        if str(row.get("status") or "").upper() == "SUCCEEDED" and "failover_completed_at" not in events:
            _event_set(events, "failover_completed_at", row.get("finished_at"), "chatops_state:finished_at", errors, duplicates)
    return result, request_ids


def _collect_audit(
    path: Path | None,
    run_id: str,
    incident_id: str,
    request_ids: set[str],
    events: dict[str, dict[str, Any]],
    errors: list[str],
    duplicates: list[str],
) -> dict[str, Any]:
    result = {"path": _safe_source_path(path), "status": "MISSING", "matched_records": 0}
    if path is None or not path.is_file():
        return result
    matched = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        result["status"] = "INVALID"
        return result
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        incident_ids = record.get("incident_ids")
        if not isinstance(incident_ids, list):
            incident_ids = []
        linked = (
            str(record.get("incident_id") or "") == incident_id
            or incident_id in {str(value) for value in incident_ids}
            or str(record.get("rto_run_id") or "") == run_id
            or str(record.get("request_id") or "") in request_ids
        )
        if not linked:
            continue
        matched += 1
        event_name = str(record.get("event") or "").upper()
        if event_name in {"CHATOPS_APPROVAL_REQUEST", "FAILOVER_APPROVAL_CREATED"}:
            _event_set(events, "slack_request_at", record.get("timestamp"), "chatops_audit:timestamp", errors, duplicates)
        elif event_name in {"DR_ESCALATE", "FAILOVER_ESCALATED", "SECURITY_DR_ESCALATION"}:
            _event_set(events, "dr_escalation_at", record.get("timestamp"), "chatops_audit:timestamp", errors, duplicates)
        if record.get("kind") == "request" or record.get("action") in {"failover", "failback"}:
            _event_set(events, "slack_request_at", record.get("created_at"), "chatops_audit:created_at", errors, duplicates)
            _event_set(events, "first_approval_at", record.get("first_approved_at"), "chatops_audit:first_approved_at", errors, duplicates)
            _event_set(events, "execution_started_at", record.get("execution_started_at"), "chatops_audit:execution_started_at", errors, duplicates)
            if str(record.get("status") or "").upper() == "SUCCEEDED" and "failover_completed_at" not in events:
                _event_set(events, "failover_completed_at", record.get("completed_at"), "chatops_audit:completed_at", errors, duplicates)
    result["matched_records"] = matched
    result["status"] = "PASS" if matched else "NOT_MATCHED"
    return result


def _collect_timing(
    path: Path | None,
    run_id: str,
    incident_id: str,
    events: dict[str, dict[str, Any]],
    errors: list[str],
    duplicates: list[str],
) -> dict[str, Any]:
    result = {"path": _safe_source_path(path), "status": "MISSING", "matched_records": 0, "unscoped_records": 0}
    if path is None or not path.is_file():
        return result
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        result["status"] = "INVALID"
        return result
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        record_run = str(record.get("run_id") or record.get("rto_run_id") or "")
        if not record_run:
            result["unscoped_records"] += 1
            continue
        if record_run != run_id:
            continue
        record_incident = str(record.get("incident_id") or record.get("event_id") or "")
        if record_incident and record_incident != incident_id:
            continue
        event = TIMING_EVENT_MAP.get((str(record.get("phase") or ""), str(record.get("event") or "")))
        if event is None:
            continue
        result["matched_records"] += 1
        _event_set(events, event, record.get("value"), f"timing:{record.get('phase')}:{record.get('event')}", errors, duplicates)
    if result["matched_records"]:
        result["status"] = "PASS"
    elif result["unscoped_records"]:
        result["status"] = "UNSCOPED_NOT_USED"
    else:
        result["status"] = "NOT_MATCHED"
    return result


def _validate_order(events: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    present = [(event, events[event]) for event in EVENT_ORDER if event in events]
    for previous, current in zip(present, present[1:]):
        if current[1]["epoch"] < previous[1]["epoch"]:
            errors.append(f"INVALID_CLOCK_ORDER:{previous[0]}>{current[0]}")
    return errors


def _build_rto(events: dict[str, dict[str, Any]], errors: list[str], duplicates: list[str]) -> dict[str, Any]:
    order_errors = _validate_order(events)
    all_errors = list(dict.fromkeys([*errors, *order_errors]))
    completion_verified = "failover_completed_at" in events
    recovery_event = next(
        (name for name in ("traffic_recovered_at", "aws_service_healthy_at") if name in events),
        None,
    )
    end_event = recovery_event if completion_verified else None
    required_missing = [
        name
        for name, present in (
            ("incident_detected_at", "incident_detected_at" in events),
            ("verified_service_recovery_at", recovery_event is not None),
            ("failover_completed_at", completion_verified),
        )
        if not present
    ]
    seconds = None
    status = "NOT_MEASURED"
    if not all_errors and "incident_detected_at" in events and end_event:
        seconds = round(events[end_event]["epoch"] - events["incident_detected_at"]["epoch"], 3)
        if seconds < 0:
            all_errors.append("INVALID_CLOCK_ORDER:incident_detected_at>final_event")
            seconds = None
        else:
            status = "PASS" if seconds <= RTO_TARGET_SECONDS else "FAIL"
    return {
        "schema_version": 1,
        "measurement_basis": "DETECTION_BASED" if "incident_detected_at" in events else "UNKNOWN",
        "target_seconds": RTO_TARGET_SECONDS,
        "rto_seconds": seconds,
        "rto_status": status,
        "end_event": end_event,
        "missing_required_events": required_missing,
        "validation_errors": all_errors,
        "duplicate_events": duplicates,
        "events": {
            event: ({"at": events[event]["at"], "source": events[event]["source"]} if event in events else None)
            for event in EVENT_ORDER
        },
    }


def _copy_optional_rpo_fields(raw: dict[str, Any], result: dict[str, Any]) -> None:
    for field in RPO_OPTIONAL_FIELDS:
        value = raw.get(field)
        if value in (None, ""):
            continue
        if field == "master_status":
            if isinstance(value, dict):
                safe = {}
                for key in ("file", "File", "position", "Position"):
                    if value.get(key) not in (None, ""):
                        safe[key] = str(value[key])[:200]
                if safe:
                    result[field] = safe
            continue
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            result[field] = str(value)[:500] if isinstance(value, str) else value


def _replication_health(raw: dict[str, Any], rpo: dict[str, Any]) -> str:
    if rpo.get("rpo_status") != "MEASURED":
        return "UNKNOWN"
    io = str(raw.get("replica_io_running") or "").strip().lower()
    sql = str(raw.get("replica_sql_running") or "").strip().lower()
    healthy = {"yes", "true", "on", "1"}
    if io in healthy and sql in healthy:
        return "PASS"
    return "UNKNOWN"


def _build_rpo(input_path: Path | None, db_nr_enabled: str) -> dict[str, Any]:
    enabled = str(db_nr_enabled).strip().lower() == "true"
    base: dict[str, Any] = {
        "schema_version": 1,
        "db_nr_enabled": enabled,
        "rpo_target": "RPO_15_MINUTES",
        "rpo_target_seconds": RPO_TARGET_SECONDS,
        "rpo_status": "NOT_MEASURABLE" if not enabled else "NOT_MEASURED",
        "rpo_seconds": None,
        "rpo_value_status": "NOT_MEASURED",
        "rpo_value_reason": "RECOVERED_DATA_CUTOFF_NOT_VERIFIED",
        "measured": False,
        "reason": "DB_NR_ENABLED_FALSE" if not enabled else "EVIDENCE_NOT_AVAILABLE",
    }
    if not enabled:
        base["replication_health"] = "NOT_ENABLED"
        return base
    if input_path is None or not input_path.is_file():
        base["reason"] = "EVIDENCE_FILE_MISSING"
        base["replication_health"] = "UNKNOWN"
        return base
    try:
        raw = _read_json(input_path)
    except (OSError, UnicodeError, json.JSONDecodeError):
        base["reason"] = "EVIDENCE_FILE_INVALID"
        base["replication_health"] = "UNKNOWN"
        return base
    if not isinstance(raw, dict):
        base["reason"] = "EVIDENCE_OBJECT_INVALID"
        base["replication_health"] = "UNKNOWN"
        return base
    validated = collect_rpo_evidence(input_path, nr_enabled="true")
    if validated.get("rpo_status") != "MEASURED":
        base["reason"] = validated.get("reason", "EVIDENCE_INVALID")
        base["missing_fields"] = validated.get("missing_fields", [])
        base["invalid_fields"] = validated.get("invalid_fields", [])
        base["replication_health"] = "UNKNOWN"
        return base
    base.update(
        {
            "rpo_status": "MEASURED",
            "measured": True,
            "reason": "COMPLETE_READ_ONLY_EVIDENCE",
            "replication_health": _replication_health(raw, base),
        }
    )
    _copy_optional_rpo_fields(raw, base)
    base["replication_health"] = _replication_health(raw, base)
    return base


def collect_evidence(
    *,
    run_id: str,
    incident_id: str,
    timeline_path: Path | None = None,
    state_db_path: Path | None = None,
    audit_path: Path | None = None,
    timing_path: Path | None = None,
    rpo_input_path: Path | None = None,
    db_nr_enabled: str = "false",
) -> dict[str, Any]:
    run_id = _validate_id(run_id, "run_id")
    incident_id = _validate_id(incident_id, "incident_id")
    events: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    duplicates: list[str] = []
    sources: dict[str, Any] = {}
    timeline_result = _collect_timeline(timeline_path, run_id, incident_id, events, errors, duplicates)
    sources["rto_timeline"] = timeline_result
    state_result, request_ids = _collect_state(state_db_path, run_id, incident_id, events, errors, duplicates)
    sources["chatops_state"] = state_result
    sources["chatops_audit"] = _collect_audit(audit_path, run_id, incident_id, request_ids, events, errors, duplicates)
    if (
        state_result.get("status") == "PASS"
        and state_result.get("request_status") != "SUCCEEDED"
    ):
        # A non-successful ChatOps result overrides any stale completion stage.
        events.pop("failover_completed_at", None)
    sources["timing_log"] = _collect_timing(timing_path, run_id, incident_id, events, errors, duplicates)
    if not timeline_result.get("incident_linked") and not state_result.get("matched_requests"):
        if sources["chatops_audit"].get("matched_records", 0) == 0:
            errors.append("INCIDENT_ID_NOT_LINKED_TO_SOURCES")
    rto = _build_rto(events, errors, duplicates)
    rpo = _build_rpo(rpo_input_path, db_nr_enabled)
    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "incident_id": incident_id,
        "rto_seconds": rto["rto_seconds"],
        "rto_measurement_basis": rto["measurement_basis"],
        "rto_target_seconds": RTO_TARGET_SECONDS,
        "rpo_target_seconds": RPO_TARGET_SECONDS,
        "rpo_seconds": rpo["rpo_seconds"],
        "rpo_value_status": rpo["rpo_value_status"],
        "rpo_value_reason": rpo["rpo_value_reason"],
        "rto_status": rto["rto_status"],
        "rpo_status": rpo["rpo_status"],
        "replication_health": rpo["replication_health"],
        "db_nr_enabled": rpo["db_nr_enabled"],
        "validation_errors": rto["validation_errors"],
        "sources": sources,
    }
    return {"summary": summary, "rto": rto, "rpo": rpo}


def _write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_bundle(result: dict[str, Any], output_root: Path) -> Path:
    run_id = result["summary"]["run_id"]
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output_root, 0o700)
    output_dir = output_root / run_id
    if output_dir.exists():
        raise FileExistsError(f"evidence directory already exists: {output_dir}")
    temporary_dir = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=output_root))
    os.chmod(temporary_dir, 0o700)
    try:
        result["summary"]["generated_at"] = _utc_now()
        result["summary"]["evidence_dir"] = str(output_dir)
        _write_json(temporary_dir / "summary.json", result["summary"])
        _write_json(temporary_dir / "rto_timeline.json", result["rto"])
        _write_json(temporary_dir / "rpo_evidence.json", result["rpo"])
        manifest_lines = [
            "HOSPITAL_DR_EVIDENCE_MANIFEST_V1",
            f"RUN_ID={run_id}",
            f"INCIDENT_ID={result['summary']['incident_id']}",
            f"GENERATED_AT={result['summary']['generated_at']}",
        ]
        for name in ("summary.json", "rto_timeline.json", "rpo_evidence.json"):
            file_path = temporary_dir / name
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            manifest_lines.append(f"FILE={name} SHA256={digest} BYTES={file_path.stat().st_size}")
        (temporary_dir / "evidence_manifest.txt").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
        os.chmod(temporary_dir / "evidence_manifest.txt", 0o600)
        os.replace(temporary_dir, output_dir)
    except Exception:
        shutil.rmtree(temporary_dir, ignore_errors=True)
        raise
    return output_dir


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--timeline", type=Path, default=Path(os.environ.get("DR_RTO_TIMELINE_FILE", "/var/lib/hospital-dr/rto_timeline.json")))
    parser.add_argument("--state-db", type=Path, default=Path(os.environ.get("CHATOPS_STATE_DB", "/var/lib/hospital-dr/chatops_state.sqlite3")))
    parser.add_argument("--audit", type=Path, default=Path(os.environ.get("CHATOPS_AUDIT_FILE", "/var/lib/hospital-dr/audit/chatops_audit.jsonl")))
    parser.add_argument("--timing-log", type=Path, default=None)
    parser.add_argument("--rpo-input", type=Path, default=None)
    parser.add_argument("--db-nr-enabled", default=os.environ.get("DB_NR_ENABLED", "false"))
    parser.add_argument("--output-root", type=Path, default=Path(os.environ.get("DR_EVIDENCE_ROOT", "/var/lib/hospital-dr/evidence")))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = collect_evidence(
            run_id=args.run_id,
            incident_id=args.incident_id,
            timeline_path=args.timeline,
            state_db_path=args.state_db,
            audit_path=args.audit,
            timing_path=args.timing_log,
            rpo_input_path=args.rpo_input,
            db_nr_enabled=args.db_nr_enabled,
        )
        evidence_dir = write_bundle(result, args.output_root)
    except (OSError, ValueError, RuntimeError, sqlite3.Error, FileExistsError) as exc:
        print(f"EVIDENCE_COLLECTOR_ERROR={type(exc).__name__}: {exc}")
        return 2

    summary = result["summary"]
    print(f"RUN_ID={summary['run_id']}")
    print(f"INCIDENT_ID={summary['incident_id']}")
    print(f"RTO_SECONDS={summary['rto_seconds'] if summary['rto_seconds'] is not None else 'UNKNOWN'}")
    print(f"RTO_TARGET_SECONDS={summary['rto_target_seconds']}")
    print(f"RTO_STATUS={summary['rto_status']}")
    print(f"RPO_STATUS={summary['rpo_status']}")
    print(f"RPO_TARGET_SECONDS={summary['rpo_target_seconds']}")
    print(f"RPO_SECONDS={summary['rpo_seconds'] if summary['rpo_seconds'] is not None else 'UNKNOWN'}")
    print(f"RPO_VALUE_STATUS={summary['rpo_value_status']}")
    print(f"RPO_VALUE_REASON={summary['rpo_value_reason']}")
    print(f"REPLICATION_HEALTH={summary['replication_health']}")
    print(f"EVIDENCE_DIR={evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
