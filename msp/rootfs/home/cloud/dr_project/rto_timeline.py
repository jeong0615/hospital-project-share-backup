#!/usr/bin/env python3
"""Persist and calculate a correlation-aware DR RTO timeline.

The timeline is controller/runtime state, not repository data.  It is stored
as one atomically replaced JSON document so a partially written workflow
cannot produce a plausible-looking RTO.  Missing stages remain ``null`` and
the target result is ``NOT_MEASURED`` until a complete run exists.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


TARGET_SECONDS = 60 * 60
STAGES = (
    "incident_at",
    "zabbix_detected_at",
    "failover_approval_created_at",
    "failover_approved_at",
    "failover_started_at",
    "service_recovered_at",
)

# Additional evidence stages are optional.  Keeping the original six stages
# in STAGES preserves the existing RTO metric contract; live operators may
# record these extra stages without inventing values when a phase is absent.
EVIDENCE_STAGES = STAGES + (
    "slack_alert_at",
    "first_approval_at",
    "second_approval_at",
    "automation_started_at",
    "failover_completed_at",
    "terraform_started_at",
    "terraform_completed_at",
    "ansible_started_at",
    "ansible_completed_at",
    "dns_traffic_recovered_at",
)


def default_path() -> Path:
    return Path(
        os.environ.get(
            "DR_RTO_TIMELINE_FILE",
            os.path.join(os.environ.get("DR_STATE_DIR", "/var/lib/hospital-dr"), "rto_timeline.json"),
        )
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> tuple[float, str]:
    """Return an epoch and canonical ISO-8601 timestamp without exposing data."""

    if value is None or str(value).strip() == "":
        current = utc_now()
        return current.timestamp(), isoformat(current)
    if isinstance(value, (int, float)):
        current = datetime.fromtimestamp(float(value), timezone.utc)
        return float(value), isoformat(current)

    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y.%m.%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise ValueError("timestamp must be ISO-8601 or a Zabbix date/time value")
    if parsed.tzinfo is None:
        # Zabbix's EVENT.DATE/EVENT.TIME pair has no timezone.  Interpret it
        # in the controller's local timezone, then persist UTC explicitly.
        parsed = parsed.astimezone()
    parsed = parsed.astimezone(timezone.utc)
    return parsed.timestamp(), isoformat(parsed)


def _empty_document() -> dict[str, Any]:
    return {"version": 1, "target_seconds": TARGET_SECONDS, "updated_at": isoformat(utc_now()), "runs": []}


def _read_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_document()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read RTO timeline: {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise RuntimeError(f"invalid RTO timeline document: {path}")
    document.setdefault("version", 1)
    document.setdefault("target_seconds", TARGET_SECONDS)
    return document


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


def _find_run(document: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    return next((run for run in document["runs"] if run.get("run_id") == run_id), None)


def record_stage(
    run_id: str,
    stage: str,
    *,
    timestamp: Any = None,
    event_id: str | None = None,
    approval_id: str | None = None,
    path: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Record one stage idempotently and return the calculated run summary."""

    if not run_id or any(character.isspace() for character in str(run_id)):
        raise ValueError("run_id must be a non-empty correlation identifier")
    if stage not in EVIDENCE_STAGES:
        raise ValueError(f"unsupported RTO stage: {stage}")
    if stage == "incident_at" and timestamp is None:
        raise ValueError("incident_at requires a source timestamp; it is never inferred")
    timeline_path = Path(path) if path is not None else default_path()
    timeline_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    lock_path = _lock_path(timeline_path)
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        document = _read_document(timeline_path)
        # Apply the current objective to new/in-progress runs while completed
        # historical runs keep the target stored with each run.
        document["target_seconds"] = TARGET_SECONDS
        run = _find_run(document, str(run_id))
        if run is None:
            run = {
                "run_id": str(run_id),
                "created_at": isoformat(utc_now()),
                "target_seconds": TARGET_SECONDS,
                "stages": {},
            }
            document["runs"].append(run)
        elif not any(
            (run.get("stages") or {}).get(stage_name, {}).get("at")
            for stage_name in ("service_recovered_at", "dns_traffic_recovered_at", "failover_completed_at")
        ):
            run["target_seconds"] = TARGET_SECONDS
        stages = run.setdefault("stages", {})
        if force or stage not in stages:
            _, canonical = parse_timestamp(timestamp)
            value: dict[str, Any] = {"at": canonical}
            if event_id:
                value["event_id"] = str(event_id)
            if approval_id:
                value["approval_id"] = str(approval_id)
            stages[stage] = value
        document["updated_at"] = isoformat(utc_now())
        _atomic_write(timeline_path, document)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return calculate_run(run)


def _epoch(stage: dict[str, Any] | None) -> float | None:
    if not stage or not stage.get("at"):
        return None
    try:
        return parse_timestamp(stage["at"])[0]
    except ValueError:
        return None


def _duration(stages: dict[str, Any], start: str, end: str) -> float | None:
    first = _epoch(stages.get(start))
    last = _epoch(stages.get(end))
    if first is None or last is None or last < first:
        return None
    return round(last - first, 3)


def calculate_run(run: dict[str, Any]) -> dict[str, Any]:
    stages = run.get("stages") or {}
    detection = _duration(stages, "incident_at", "zabbix_detected_at")
    alert = _duration(stages, "zabbix_detected_at", "slack_alert_at")
    approval_creation = _duration(
        stages, "zabbix_detected_at", "failover_approval_created_at"
    )
    approval = _duration(stages, "failover_approval_created_at", "failover_approved_at")
    first_approval = _duration(stages, "failover_approval_created_at", "first_approval_at")
    second_approval = _duration(stages, "first_approval_at", "second_approval_at")
    approval_to_start = _duration(stages, "failover_approved_at", "failover_started_at")
    execution = _duration(stages, "failover_started_at", "service_recovered_at")
    traffic_recovery = _duration(stages, "service_recovered_at", "dns_traffic_recovered_at")
    completion_verified = _epoch(stages.get("failover_completed_at")) is not None
    rto_end = next(
        (
            stage
            for stage in ("dns_traffic_recovered_at", "service_recovered_at")
            if _epoch(stages.get(stage)) is not None
        ),
        None,
    )
    total = _duration(stages, "incident_at", rto_end) if completion_verified and rto_end else None
    target = int(run.get("target_seconds", TARGET_SECONDS))
    result = "NOT_MEASURED" if total is None else ("PASS" if total <= target else "FAIL")
    return {
        "run_id": run.get("run_id"),
        "measurement_basis": "DETECTION_BASED" if _epoch(stages.get("incident_at")) is not None else "UNKNOWN",
        "target_seconds": target,
        "stages": {stage: (stages.get(stage) or {}).get("at") for stage in EVIDENCE_STAGES},
        "stage_metadata": {stage: stages.get(stage) for stage in EVIDENCE_STAGES if stage in stages},
        "detection_time_seconds": detection,
        "alert_time_seconds": alert,
        "approval_creation_time_seconds": approval_creation,
        "approval_time_seconds": approval,
        "first_approval_time_seconds": first_approval,
        "second_approval_time_seconds": second_approval,
        "approval_to_start_seconds": approval_to_start,
        "execution_time_seconds": execution,
        "traffic_recovery_time_seconds": traffic_recovery,
        "total_rto_seconds": total,
        "rto_target_result": result,
    }


def metric_values(run: dict[str, Any]) -> dict[str, int | float]:
    """Return only measured values suitable for the existing Zabbix trapper host.

    Missing stages are intentionally omitted.  In particular, an incomplete
    run never publishes a zero-valued RTO that could be mistaken for success.
    """

    result = run if "rto_target_result" in run and "total_rto_seconds" in run else calculate_run(run)
    values: dict[str, int | float] = {
        "dr.rto.target_seconds": result["target_seconds"],
        "dr.rto.result": {"PASS": 1, "FAIL": 0, "NOT_MEASURED": -1}[result["rto_target_result"]],
    }
    for stage in EVIDENCE_STAGES:
        timestamp = result["stages"].get(stage)
        if timestamp:
            epoch = _epoch({"at": timestamp})
            if epoch is not None:
                values[f"dr.{stage}"] = int(epoch)

    duration_keys = {
        "detection_time_seconds": "dr.rto.detection_seconds",
        "alert_time_seconds": "dr.rto.alert_seconds",
        "approval_creation_time_seconds": "dr.rto.approval_creation_seconds",
        "approval_time_seconds": "dr.rto.approval_seconds",
        "first_approval_time_seconds": "dr.rto.first_approval_seconds",
        "second_approval_time_seconds": "dr.rto.second_approval_seconds",
        "approval_to_start_seconds": "dr.rto.approval_to_start_seconds",
        "execution_time_seconds": "dr.rto.execution_seconds",
        "traffic_recovery_time_seconds": "dr.rto.traffic_recovery_seconds",
        "total_rto_seconds": "dr.rto.seconds",
    }
    for result_key, metric_key in duration_keys.items():
        value = result[result_key]
        if value is not None:
            values[metric_key] = value
    return values


def get_run(run_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    document = _read_document(Path(path) if path is not None else default_path())
    run = _find_run(document, run_id)
    return calculate_run(run) if run else None


def synthetic_run(path: str | Path | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Create a deterministic, complete dry-run timeline under the supplied path."""

    run_id = run_id or f"dry-run-{uuid.uuid4().hex[:12]}"
    base = utc_now()
    offsets = {
        "incident_at": 0,
        "zabbix_detected_at": 30,
        "failover_approval_created_at": 60,
        "failover_approved_at": 120,
        "failover_started_at": 180,
        "service_recovered_at": 600,
        "failover_completed_at": 601,
    }
    for stage, offset in offsets.items():
        record_stage(
            run_id,
            stage,
            timestamp=isoformat(base.replace(microsecond=0) + timedelta(seconds=offset)),
            event_id="dry-run-event" if stage in {"incident_at", "zabbix_detected_at"} else None,
            approval_id="dry-run-approval" if "approval" in stage else None,
            path=path,
        )
    result = get_run(run_id, path)
    assert result is not None
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=None, help="runtime JSON timeline path")
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record")
    record.add_argument("--path", dest="command_path", default=None, help="runtime JSON timeline path")
    record.add_argument("--run-id", required=True)
    record.add_argument("--stage", choices=EVIDENCE_STAGES, required=True)
    record.add_argument("--at")
    record.add_argument("--event-id")
    record.add_argument("--approval-id")
    record.add_argument("--force", action="store_true")
    calculate = subparsers.add_parser("calculate")
    calculate.add_argument("--path", dest="command_path", default=None, help="runtime JSON timeline path")
    calculate.add_argument("--run-id", required=True)
    synthetic = subparsers.add_parser("synthetic")
    synthetic.add_argument("--path", dest="command_path", default=None, help="runtime JSON timeline path")
    synthetic.add_argument("--run-id")
    metrics = subparsers.add_parser("metrics")
    metrics.add_argument("--path", dest="command_path", default=None, help="runtime JSON timeline path")
    metrics.add_argument("--run-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        path = args.command_path or args.path or str(default_path())
        if args.command == "record":
            result = record_stage(
                args.run_id,
                args.stage,
                timestamp=args.at,
                event_id=args.event_id,
                approval_id=args.approval_id,
                path=path,
                force=args.force,
            )
        elif args.command == "calculate":
            result = get_run(args.run_id, path)
            if result is None:
                print("RTO_RUN_NOT_FOUND", flush=True)
                return 1
        elif args.command == "metrics":
            run = get_run(args.run_id, path)
            if run is None:
                print("RTO_RUN_NOT_FOUND", flush=True)
                return 1
            for key, value in metric_values(run).items():
                print(f"{key}={value}")
            return 0
        else:
            result = synthetic_run(path, args.run_id)
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"RTO_TIMELINE_ERROR={type(exc).__name__}: {exc}", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
