#!/usr/bin/env python3
"""Read-only validation of an existing MySQL Position replica for failover."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path


class NRStatusError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


DUMP_TARGET = {
    "instance_id": "AWS_RESOURCE_ID_REDACTED",
    "private_ip": "IP_REDACTED",
    "port": 3306,
    "database": "hospital_db",
}
DUMP_REQUIRED_STAGES = {
    "TARGET_IDENTITY", "DB_ONLY_INSTANCE_START", "SSM_TRANSPORT", "APPLICATION_FENCE",
    "PRESNAPSHOT_PREFLIGHT", "PRESNAPSHOT", "SELECTED_DUMP_REVALIDATION",
    "SELECTED_DUMP_STAGE", "FINAL_FENCE_AND_AUTHORIZATION_CHECK", "RESTORE_ATTEMPTED",
    "POST_RESTORE_DB_VERIFICATION",
}
DUMP_CORE_TABLES = {"users", "patients", "doctors", "medicalrecords", "accesslogs", "reservationposts"}
FAILOVER_RPO_FAILURE_POLICY = "BLOCK_IF_UNMEASURED_OR_OVER_900_SECONDS"


def validate_dump_restore_receipt(
    path: str | Path, *, request_id: str, backup_id: str, expected_sha256: str,
    expected_sidecar_sha256: str = "",
) -> dict:
    """Validate an existing same-request, approved DB restore before promotion."""
    if (
        not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", request_id or "")
        or not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id or "")
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "")
    ):
        raise NRStatusError("dump_receipt_identity_invalid")
    receipt_path = Path(path)
    descriptor = None
    try:
        if not receipt_path.is_absolute():
            raise NRStatusError("dump_receipt_untrusted")
        current_path = Path("/")
        for component in receipt_path.parts[1:-1]:
            current_path = current_path / component
            ancestor = current_path.lstat()
            if stat.S_ISLNK(ancestor.st_mode) or not stat.S_ISDIR(ancestor.st_mode):
                raise NRStatusError("dump_receipt_untrusted")
        request_dir = receipt_path.parent
        state_dir = request_dir.parent
        if request_dir.is_symlink() or state_dir.is_symlink():
            raise NRStatusError("dump_receipt_untrusted")
        request_info = request_dir.lstat()
        state_info = state_dir.lstat()
        if (
            not stat.S_ISDIR(request_info.st_mode)
            or request_info.st_uid != os.geteuid()
            or stat.S_IMODE(request_info.st_mode) != 0o700
            or not stat.S_ISDIR(state_info.st_mode)
            or state_info.st_uid != os.geteuid()
            or stat.S_IMODE(state_info.st_mode) & 0o022
            or request_dir.name != request_id
            or receipt_path.name != "result.json"
        ):
            raise NRStatusError("dump_receipt_untrusted")
        descriptor = os.open(
            receipt_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or not 2 <= info.st_size <= 1024 * 1024
        ):
            raise NRStatusError("dump_receipt_untrusted")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            payload = json.load(stream)
    except NRStatusError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise NRStatusError("dump_receipt_unavailable_or_invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if not isinstance(payload, dict):
        raise NRStatusError("dump_receipt_invalid")
    if payload.get("request_id") != request_id:
        raise NRStatusError("dump_receipt_request_mismatch")
    if payload.get("backup_id") != backup_id:
        raise NRStatusError("dump_receipt_backup_mismatch")
    if str(payload.get("expected_sha256") or "").lower() != expected_sha256.lower():
        raise NRStatusError("dump_receipt_sha256_mismatch")
    fallback = payload.get("recovery_mode") == "DUMP_FALLBACK"
    if fallback and not re.fullmatch(r"[0-9a-f]{64}", expected_sidecar_sha256 or ""):
        raise NRStatusError("dump_fallback_sidecar_identity_unconfigured")
    pipeline = payload.get("failover_pipeline")
    restore_only_passed = (
        payload.get("status") == "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        and payload.get("phase") == "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        and payload.get("failure_code") is None
        and payload.get("operator_intervention_required") is False
        and payload.get("dns_changed") is False
        and (
            pipeline is None
            or (isinstance(pipeline, dict) and pipeline.get("status") in {None, "NOT_STARTED"})
        )
    )
    prior_followup_failed = (
        payload.get("status") == "PARTIAL_FAILURE"
        and payload.get("phase") == "FULL_FAILOVER"
        and payload.get("failure_code") == "FULL_FAILOVER_FAILED_AFTER_DUMP_RESTORE"
        and payload.get("dump_restore_status", "PASS") == "PASS"
        and payload.get("dump_failover_status") in {None, "PARTIAL_FAILURE"}
        and payload.get("dump_failover_resume_attempted") is not True
        and payload.get("operator_intervention_required") is True
        and payload.get("dns_changed") == "UNKNOWN"
        and isinstance(pipeline, dict)
        and pipeline.get("status") == "PARTIAL_FAILURE"
        and pipeline.get("request_id") == request_id
        and pipeline.get("recovery_mode") == "APPROVED_DUMP"
        and pipeline.get("backup_id") == backup_id
        and str(pipeline.get("sha256") or "").lower() == expected_sha256.lower()
        and pipeline.get("final_dr_state") == "IDLE"
        and pipeline.get("completion_marker_verified") is False
        and isinstance(pipeline.get("return_code"), int)
        and not isinstance(pipeline.get("return_code"), bool)
        and pipeline.get("return_code") != 0
    )
    if (
        (fallback and payload.get("request_type") not in {"NORMAL_FAILOVER", "EMERGENCY_FAILOVER"})
        or (not fallback and payload.get("request_type") not in {"DUMP_RESTORE_FAILOVER", "DUMP_RESTORE"})
        or not (restore_only_passed or prior_followup_failed)
        or payload.get("restore_attempted") is not True
        or payload.get("overwrite_approval_request_id") != request_id
        or payload.get("apps_fenced") is not True
        or payload.get("apps_fence_state") not in {"WEB_AND_EMR_EC2_STOPPED", "VERIFIED"}
        or payload.get("automatic_db_rollback") is not False
        or payload.get("dr_active_recorded") is not False
        or payload.get("target") != DUMP_TARGET
    ):
        raise NRStatusError("dump_restore_completion_or_target_unverified")
    authorization = payload.get("overwrite_authorization")
    origin = payload.get("request_origin")
    if fallback:
        request_type = payload.get("request_type")
        source = payload.get("request_source")
        client = payload.get("slack_client_key")
        if request_type == "NORMAL_FAILOVER":
            provenance_valid = (
                client == "failover"
                and (
                    (origin == "GENERAL" and source in {"manual", "zabbix"})
                    or (origin == "CLOUD_SLACK_DR_TRIGGER" and source == "zabbix"
                        and payload.get("production_action_verified") is True)
                )
            )
        else:
            provenance_valid = (
                origin == "EMERGENCY" and source == "emergency_console" and client == "emergency"
            )
        plan = payload.get("recovery_plan")
        candidate = plan.get("dump") if isinstance(plan, dict) else None
        provenance = provenance_valid
    else:
        provenance = {
            "GENERAL": ("dump_restore_console", "failover"),
            "EMERGENCY": ("emergency_dump_restore_console", "emergency"),
        }.get(origin)
        candidate = None
        plan = None
    if (
        not isinstance(authorization, dict)
        or (fallback and provenance is not True)
        or (not fallback and payload.get("request_source") != (provenance[0] if provenance else None))
        or (not fallback and payload.get("slack_client_key") != (provenance[1] if provenance else None))
        or authorization.get("scope") != "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB"
        or authorization.get("target") != DUMP_TARGET
        or authorization.get("backup_id") != backup_id
        or str(authorization.get("sha256") or "").lower() != expected_sha256.lower()
        or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(authorization.get("authorization_id") or ""))
    ):
        raise NRStatusError("dump_overwrite_authorization_unverified")
    approval = payload.get("approval_evidence")
    approvers = approval.get("approver_ids") if isinstance(approval, dict) else None
    execution_id = approval.get("execution_id") if isinstance(approval, dict) else None
    if (
        not isinstance(approval, dict)
        or approval.get("approval_required") != 2
        or approval.get("approval_count") != 2
        or not isinstance(approvers, list)
        or len(approvers) != 2
        or any(not isinstance(item, str) or not item for item in approvers)
        or len(set(approvers)) != 2
        or authorization.get("execution_id") != execution_id
        or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(execution_id or ""))
    ):
        raise NRStatusError("dump_two_admin_approval_unverified")
    if fallback:
        master_status = candidate.get("master_status") if isinstance(candidate, dict) else None
        expected_rpo = candidate.get("expected_rpo") if isinstance(candidate, dict) else None
        replica_fence = payload.get("replication_fence")
        seconds = expected_rpo.get("seconds") if isinstance(expected_rpo, dict) else None
        if (
            not isinstance(expected_rpo, dict)
            or expected_rpo.get("status") != "PASS"
            or expected_rpo.get("target_seconds") != 900
            or isinstance(seconds, bool)
            or not isinstance(seconds, int)
            or not 0 <= seconds <= 900
        ):
            raise NRStatusError("conditional_dump_fallback_rpo_unverified")
        if (
            not isinstance(plan, dict)
            or plan.get("version") != 1
            or plan.get("policy") != "NR_FIRST_DUMP_FALLBACK"
            or plan.get("rpo_failure_policy") != FAILOVER_RPO_FAILURE_POLICY
            or plan.get("target") != DUMP_TARGET
            or plan.get("overwrite_scope") != "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB"
            or not isinstance(candidate, dict)
            or candidate.get("status") != "READY"
            or candidate.get("backup_id") != backup_id
            or str(candidate.get("sha256") or "").lower() != expected_sha256.lower()
            or not re.fullmatch(r"[0-9a-f]{64}", str(candidate.get("sidecar_sha256") or ""))
            or candidate.get("sidecar_sha256") != expected_sidecar_sha256
            or payload.get("sidecar_sha256") != candidate.get("sidecar_sha256")
            or payload.get("master_status") != master_status
            or payload.get("apps_fence_state") != "VERIFIED"
            or authorization.get("grant_kind") != "CONDITIONAL_DUMP_FALLBACK"
            or authorization.get("request_id") != request_id
            or authorization.get("request_type") != payload.get("request_type")
            or authorization.get("request_origin") != origin
            or authorization.get("request_source") != payload.get("request_source")
            or authorization.get("slack_client_key") != payload.get("slack_client_key")
            or authorization.get("status") != "APPROVED_BY_TWO_DISTINCT_ADMINS"
            or authorization.get("sidecar_sha256") != candidate.get("sidecar_sha256")
            or authorization.get("master_status") != master_status
            or authorization.get("data_timestamp") != candidate.get("data_timestamp")
            or authorization.get("expected_rpo") != expected_rpo
            or authorization.get("rpo_failure_policy") != plan.get("rpo_failure_policy")
            or authorization.get("recovery_plan_version") != plan.get("version")
            or authorization.get("approval_required") != 2
            or authorization.get("approval_count") != 2
            or authorization.get("approver_ids") != approvers
            or not isinstance(replica_fence, dict)
            or replica_fence.get("channel_state") not in {"NONE", "STOPPED"}
            or replica_fence.get("restart_protection") != (
                "NONE" if replica_fence.get("channel_state") == "NONE"
                else "PERSISTED_SKIP_REPLICA_START"
            )
            or not isinstance(replica_fence.get("verified_at_utc"), str)
        ):
            raise NRStatusError("conditional_dump_fallback_proof_unverified")
    stages = payload.get("stages")
    if not isinstance(stages, dict) or any(
        not isinstance(stages.get(name), dict) or stages[name].get("status") != "COMPLETE"
        for name in DUMP_REQUIRED_STAGES
    ):
        raise NRStatusError("dump_restore_stages_incomplete")
    verification = payload.get("database_verification")
    identity = verification.get("database_identity") if isinstance(verification, dict) else None
    read_only_standby = verification.get("read_only_standby") if isinstance(verification, dict) else None
    read_only_standby_valid = (
        isinstance(read_only_standby, dict)
        and read_only_standby.get("read_only") is True
        and read_only_standby.get("super_read_only") is True
        and (
            (
                read_only_standby.get("persisted_read_only") == "ON"
                and read_only_standby.get("persisted_super_read_only") == "ON"
            )
            or (
                read_only_standby.get("persisted_read_only") == "MISSING"
                and read_only_standby.get("persisted_super_read_only") == "MISSING"
                and read_only_standby.get("startup_read_only") == "ON"
                and read_only_standby.get("startup_super_read_only") == "ON"
                and read_only_standby.get("startup_source_verified") is True
                and read_only_standby.get("persistence_source") == "MYSQL_STARTUP_CONFIGURATION"
            )
        )
    )
    if (
        not isinstance(verification, dict)
        or verification.get("mysql_responded") is not True
        or not isinstance(identity, dict)
        or identity.get("port") != 3306
        or identity.get("server_id") != 20
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            str(identity.get("server_uuid") or ""),
        )
        or not read_only_standby_valid
        or not isinstance(verification.get("row_counts"), dict)
        or {str(name).lower() for name in verification.get("core_tables", [])} != DUMP_CORE_TABLES
        or {str(name).lower() for name in verification.get("row_counts", {})} != DUMP_CORE_TABLES
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in verification.get("row_counts", {}).values()
        )
    ):
        raise NRStatusError("dump_restore_database_verification_missing")
    return {
        "mode": "DUMP",
        "request_id": request_id,
        "backup_id": backup_id,
        "sha256": expected_sha256.lower(),
        "target": dict(DUMP_TARGET),
        "authorization_id": authorization["authorization_id"],
        "execution_id": execution_id,
        "recovery_mode": "DUMP_FALLBACK" if fallback else "DUMP_RESTORE",
        "sidecar_sha256": payload.get("sidecar_sha256"),
        "data_timestamp": candidate.get("data_timestamp") if fallback else None,
        "expected_rpo": candidate.get("expected_rpo") if fallback else None,
    }


def _status_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_]+):\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        if key in fields:
            raise NRStatusError("replica_status_ambiguous")
        fields[key] = value
    if not fields:
        raise NRStatusError("replica_channel_missing")
    return fields


def _one(fields: dict[str, str], *names: str) -> str:
    found = [fields[name] for name in names if name in fields]
    if len(found) != 1:
        raise NRStatusError("replica_status_field_missing_or_ambiguous")
    return found[0]


def _coordinate(filename: str, position: str) -> tuple[str, int, int]:
    match = re.fullmatch(r"([A-Za-z0-9._-]*?)([0-9]{6,})", filename or "")
    if not match or not position or not re.fullmatch(r"[0-9]{1,20}", position):
        raise NRStatusError("replication_coordinate_invalid")
    prefix, sequence = match.groups()
    value = int(position)
    if value <= 0:
        raise NRStatusError("replication_coordinate_invalid")
    return prefix, int(sequence), value


def _at_or_after(actual_file: str, actual_pos: str, target_file: str, target_pos: str) -> bool:
    actual_prefix, actual_sequence, actual_position = _coordinate(actual_file, actual_pos)
    target_prefix, target_sequence, target_position = _coordinate(target_file, target_pos)
    if actual_prefix != target_prefix:
        raise NRStatusError("replication_binlog_prefix_mismatch")
    return (actual_sequence, actual_position) >= (target_sequence, target_position)


def validate_replica_status(
    replica_status: str,
    *,
    expected_source_uuid: str,
    expected_source_host: str,
    expected_source_port: int = 3306,
    source_log_file: str,
    source_log_position: int,
) -> dict:
    """Accept NR only when the executed SQL position reaches the fenced source."""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", expected_source_uuid or ""):
        raise NRStatusError("expected_source_uuid_unconfigured")
    if not expected_source_host or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", expected_source_host):
        raise NRStatusError("expected_source_host_unconfigured")
    fields = _status_fields(replica_status)
    io_running = _one(fields, "Replica_IO_Running", "Slave_IO_Running")
    sql_running = _one(fields, "Replica_SQL_Running", "Slave_SQL_Running")
    if io_running != "Yes":
        raise NRStatusError("replica_io_not_running")
    if sql_running != "Yes":
        raise NRStatusError("replica_sql_not_running")
    source_uuid = _one(fields, "Source_UUID", "Master_UUID")
    if source_uuid.lower() != expected_source_uuid.lower():
        raise NRStatusError("replica_source_uuid_mismatch")
    source_host = _one(fields, "Source_Host", "Master_Host")
    if source_host.lower() != expected_source_host.lower():
        raise NRStatusError("replica_source_host_mismatch")
    source_port = _one(fields, "Source_Port", "Master_Port")
    if not source_port.isdecimal() or int(source_port) != int(expected_source_port):
        raise NRStatusError("replica_source_port_mismatch")
    lag = _one(fields, "Seconds_Behind_Source", "Seconds_Behind_Master")
    if lag != "0":
        raise NRStatusError("replica_lag_not_zero")
    for names in (("Last_IO_Error",), ("Last_SQL_Error",)):
        error = _one(fields, *names)
        if error:
            raise NRStatusError("replica_last_error_present")

    expected_pos = str(source_log_position)
    received_file = _one(fields, "Source_Log_File", "Master_Log_File")
    received_pos = _one(fields, "Read_Source_Log_Pos", "Read_Master_Log_Pos")
    executed_file = _one(fields, "Relay_Source_Log_File", "Relay_Master_Log_File")
    executed_pos = _one(fields, "Exec_Source_Log_Pos", "Exec_Master_Log_Pos")
    target_file, target_pos = source_log_file, expected_pos
    if not _at_or_after(received_file, received_pos, target_file, target_pos):
        raise NRStatusError("replica_io_position_behind_source")
    if not _at_or_after(executed_file, executed_pos, target_file, target_pos):
        raise NRStatusError("replica_sql_position_behind_source")
    return {
        "mode": "NR",
        "source_uuid": source_uuid.lower(),
        "source_host": source_host,
        "source_port": int(source_port),
        "source_log_file": target_file,
        "source_log_position": int(target_pos),
        "replica_log_file": executed_file,
        "replica_log_position": int(executed_pos),
        "seconds_behind_source": int(lag),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-uuid", default="")
    parser.add_argument("--source-host", default="")
    parser.add_argument("--source-port", type=int, default=3306)
    parser.add_argument("--source-log-file", default="")
    parser.add_argument("--source-log-position", default=None, type=int)
    parser.add_argument("--dump-receipt", default="")
    parser.add_argument("--request-id", default="")
    parser.add_argument("--backup-id", default="")
    parser.add_argument("--sha256", default="")
    parser.add_argument("--sidecar-sha256", default="")
    args = parser.parse_args(argv)
    try:
        if args.dump_receipt:
            if not args.request_id or not args.backup_id or not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
                raise NRStatusError("dump_receipt_identity_unconfigured")
            result = validate_dump_restore_receipt(
                args.dump_receipt, request_id=args.request_id,
                backup_id=args.backup_id, expected_sha256=args.sha256,
                expected_sidecar_sha256=args.sidecar_sha256,
            )
            print(
                "RECOVERY_STRATEGY=VERIFIED mode=DUMP "
                f"request_id={result['request_id']} backup_id={result['backup_id']} "
                f"sha256={result['sha256']} authorization_id={result['authorization_id']}"
                f" recovery_mode={result['recovery_mode']}"
            )
            return 0
        if not args.source_log_file or args.source_log_position is None:
            raise NRStatusError("source_coordinate_unconfigured")
        result = validate_replica_status(
            sys.stdin.read(), expected_source_uuid=args.source_uuid,
            expected_source_host=args.source_host, expected_source_port=args.source_port,
            source_log_file=args.source_log_file, source_log_position=args.source_log_position,
        )
    except NRStatusError as exc:
        print(f"NR_READINESS=BLOCKED reason={exc.code}")
        return 1
    print(
        "NR_READINESS=VERIFIED "
        f"source_uuid={result['source_uuid']} source={result['source_host']}:{result['source_port']} "
        f"coordinate={result['source_log_file']}:{result['source_log_position']} "
        f"applied={result['replica_log_file']}:{result['replica_log_position']} "
        f"lag={result['seconds_behind_source']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
