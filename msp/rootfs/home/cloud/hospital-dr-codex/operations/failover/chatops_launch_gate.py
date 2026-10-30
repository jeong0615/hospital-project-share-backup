#!/usr/bin/env python3
"""Read-only approval and recovery-policy gate for the canonical Failover entrypoint."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import stat
import sys
import time
from pathlib import Path
from urllib.parse import quote


class LaunchGateError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


PRODUCTION_CHATOPS_STATE_DB = Path("/var/lib/hospital-dr/chatops_state.sqlite3")
SYNTHETIC_DEMO_REQUEST_TYPE = "SYNTHETIC_MYSQL_DEMO_FAILOVER"
SYNTHETIC_DEMO_REQUEST_ORIGIN = "CHATOPS_SYNTHETIC_MYSQL_DEMO"
SYNTHETIC_DEMO_REQUEST_SOURCE = "chatops_synthetic_mysql_demo"


def _chatops_module():
    chatops_dir = Path(__file__).resolve().parents[1] / "chatops"
    if str(chatops_dir) not in sys.path:
        sys.path.insert(0, str(chatops_dir))
    try:
        import chatops_core
    except Exception as exc:  # fail closed if the deployed ChatOps contract cannot load
        raise LaunchGateError("chatops_contract_unavailable") from exc
    required = (
        "FAILOVER_RECOVERY_REQUEST_TYPES", "_failover_request_contract",
        "_failover_rpo_gate_error", "_failover_rpo_policy_error",
        "_failover_recovery_authorization_error", "_dump_overwrite_authorization_error",
        "_demo_dump_restore_recovery_data_valid", "_demo_dump_approval_evidence_matches",
        "_demo_dump_overwrite_authorization_matches",
        "REQUEST_TYPE_DUMP_RESTORE",
        "is_test_mode_failover", "latest_incident", "request_type_from_state",
    )
    if any(not hasattr(chatops_core, name) for name in required):
        raise LaunchGateError("chatops_contract_unavailable")
    return chatops_core


def _state_database(path: str, request_id: str) -> dict:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise LaunchGateError("chatops_state_path_untrusted")
    try:
        if candidate.resolve(strict=True) != candidate:
            raise LaunchGateError("chatops_state_path_untrusted")
        metadata = candidate.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        parent = candidate.parent.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or mode != 0o600
            or metadata.st_nlink != 1
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_mode & stat.S_IFLNK
        ):
            raise LaunchGateError("chatops_state_permissions_invalid")
        parent_mode = stat.S_IMODE(parent.st_mode)
        if parent_mode & 0o022:
            raise LaunchGateError("chatops_state_directory_permissions_invalid")
    except OSError as exc:
        raise LaunchGateError("chatops_state_unavailable") from exc

    uri = f"file:{quote(str(candidate), safe='/')}?mode=ro"
    connection = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(approval_requests)")
        }
        required = {
            "request_id", "action", "slack_client_key", "status", "incidents", "approvers",
            "created_at", "first_approved_at", "expires_at", "finished_at", "cancelled_by",
            "execution_started_at", "execution_heartbeat_at", "execution_lease_until",
            "execution_id", "approval_required",
        }
        if not required.issubset(columns):
            raise LaunchGateError("chatops_state_schema_invalid")
        row = connection.execute(
            "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
    except LaunchGateError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise LaunchGateError("chatops_state_read_failed") from exc
    finally:
        if connection is not None:
            connection.close()
    if row is None:
        raise LaunchGateError("approved_failover_request_missing")
    try:
        state = dict(row)
        state["incidents"] = json.loads(state["incidents"])
        state["approvers"] = json.loads(state["approvers"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise LaunchGateError("chatops_state_record_invalid") from exc
    return state


def _read_dump_followup_receipt(path: str, request_id: str) -> dict:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise LaunchGateError("dump_followup_receipt_path_untrusted")
    descriptor = None
    try:
        request_dir = candidate.parent
        state_dir = request_dir.parent
        request_info = request_dir.lstat()
        state_info = state_dir.lstat()
        if (
            not stat.S_ISDIR(request_info.st_mode) or request_info.st_uid != os.geteuid()
            or stat.S_IMODE(request_info.st_mode) != 0o700
            or not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != os.geteuid()
            or stat.S_IMODE(state_info.st_mode) & 0o022
            or request_dir.name != request_id or candidate.name != "result.json"
        ):
            raise LaunchGateError("dump_followup_receipt_untrusted")
        descriptor = os.open(
            candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 2 <= info.st_size <= 1024 * 1024
        ):
            raise LaunchGateError("dump_followup_receipt_untrusted")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            payload = json.load(stream)
    except LaunchGateError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LaunchGateError("dump_followup_receipt_unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise LaunchGateError("dump_followup_receipt_invalid")
    return payload


def _other_active_request_exists(database: str, request_id: str) -> bool:
    connection = None
    try:
        uri = f"file:{quote(str(Path(database)), safe='/')}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT COUNT(*) FROM approval_requests WHERE request_id != ? "
            "AND status IN ('PENDING','PARTIALLY_APPROVED','EXECUTING') "
            "AND cancelled_by IS NULL",
            (request_id,),
        ).fetchone()
        return not row or int(row[0]) != 0
    except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
        raise LaunchGateError("chatops_active_request_check_failed") from exc
    finally:
        if connection is not None:
            connection.close()


def validate_launch_context(
    database: str,
    request_id: str,
    *,
    now: float | None = None,
    dump_followup: tuple[str, str, str] | None = None,
    dump_followup_resume: bool = False,
) -> dict:
    """Require active two-admin approval and its request-bound RPO policy."""
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        request_id or "",
    ):
        raise LaunchGateError("request_id_invalid")
    current = float(time.time() if now is None else now)
    if not math.isfinite(current) or current <= 0:
        raise LaunchGateError("verification_clock_invalid")
    state = _state_database(database, request_id)
    chatops = _chatops_module()
    try:
        resume_terminal = dump_followup is not None and dump_followup_resume
        expected_status = "PARTIAL_FAILURE" if resume_terminal else "EXECUTING"
        if (
            state.get("request_id") != request_id
            or state.get("action") != "failover"
            or state.get("status") != expected_status
            or (state.get("finished_at") is None if resume_terminal else state.get("finished_at") is not None)
            or state.get("cancelled_by") is not None
            or state.get("approval_required") != 2
        ):
            raise LaunchGateError("failover_request_not_approved_or_active")
        approvers = state.get("approvers")
        if (
            not isinstance(approvers, list)
            or len(approvers) != 2
            or any(not isinstance(item, str) or not item.strip() for item in approvers)
            or len(set(approvers)) != 2
        ):
            raise LaunchGateError("two_distinct_admin_approvals_unverified")
        for field, reason in (
            ("created_at", "request_created_at_invalid"),
            ("first_approved_at", "request_approval_time_invalid"),
            ("expires_at", "request_expiry_invalid"),
            ("execution_started_at", "execution_start_invalid"),
        ):
            value = state.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise LaunchGateError(reason)
        if (
            state["created_at"] <= 0
            or state["first_approved_at"] < state["created_at"]
            or state["first_approved_at"] > current
            or state["expires_at"] <= current
            or state["execution_started_at"] < state["first_approved_at"]
            or state["execution_started_at"] > current
        ):
            raise LaunchGateError("failover_request_expired_or_execution_lease_invalid")
        if resume_terminal:
            if (
                not isinstance(state.get("finished_at"), (int, float))
                or isinstance(state.get("finished_at"), bool)
                or not math.isfinite(float(state["finished_at"]))
                or not state["execution_started_at"] <= state["finished_at"] <= current
                or state.get("result") != "dump_restore_succeeded_but_common_failover_incomplete"
            ):
                raise LaunchGateError("dump_followup_resume_state_invalid")
            if _other_active_request_exists(database, request_id):
                raise LaunchGateError("another_chatops_request_is_active")
        else:
            for field, reason in (
                ("execution_heartbeat_at", "execution_heartbeat_invalid"),
                ("execution_lease_until", "execution_lease_invalid"),
            ):
                value = state.get(field)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise LaunchGateError(reason)
            if state["execution_heartbeat_at"] > current + 5 or state["execution_lease_until"] <= current:
                raise LaunchGateError("failover_request_expired_or_execution_lease_invalid")
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            str(state.get("execution_id") or ""),
        ):
            raise LaunchGateError("execution_id_invalid")

        incidents = state.get("incidents")
        if not isinstance(incidents, list) or not incidents or any(not isinstance(item, dict) for item in incidents):
            raise LaunchGateError("failover_incident_record_invalid")
        if chatops.is_test_mode_failover(state):
            raise LaunchGateError("test_mode_request_cannot_launch_failover")
        incident = chatops.latest_incident(state)
        request_type = chatops.request_type_from_state(state)
        if dump_followup is not None:
            expected_backup_id, expected_sha256, receipt_text = dump_followup
            if request_type != chatops.REQUEST_TYPE_DUMP_RESTORE:
                raise LaunchGateError("dump_followup_request_type_mismatch")
            if (
                not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", expected_backup_id or "")
                or not re.fullmatch(r"[0-9a-f]{64}", (expected_sha256 or "").lower())
                or str(incident.get("backup_id") or "") != expected_backup_id
                or str(incident.get("backup_checksum") or "").lower() != expected_sha256.lower()
            ):
                raise LaunchGateError("dump_followup_identity_mismatch")
            source_contracts = {
                "GENERAL": ("failover", "dump_restore_console"),
                "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
            }
            origin = str(incident.get("request_origin") or "").strip().upper()
            client_key, source = source_contracts.get(origin, (None, None))
            if (
                client_key is None
                or state.get("slack_client_key") != client_key
                or incident.get("source") != source
            ):
                raise LaunchGateError("dump_followup_request_provenance_invalid")
            authorization_state = dict(state)
            if resume_terminal:
                authorization_state["status"] = "EXECUTING"
                authorization_state["finished_at"] = None
            authorization_error = chatops._dump_overwrite_authorization_error(
                authorization_state, request_id=request_id, approved=True, now=current,
            )
            if authorization_error:
                raise LaunchGateError(authorization_error)
            restore_mode = str(incident.get("dump_restore_mode") or "")
            expected_rpo = incident.get("expected_rpo")
            if restore_mode == "LEGACY_MANUAL":
                if (
                    not isinstance(expected_rpo, dict)
                    or expected_rpo.get("status") != "NOT_MEASURED"
                    or expected_rpo.get("seconds") is not None
                ):
                    raise LaunchGateError("dump_followup_legacy_rpo_invalid")
                rpo_status = "NOT_MEASURED"
            elif restore_mode == "MANIFEST_VERIFIED":
                if not isinstance(expected_rpo, dict):
                    raise LaunchGateError("dump_followup_rpo_invalid")
                seconds = expected_rpo.get("seconds")
                if expected_rpo.get("status") == "NOT_MEASURED" and seconds is None:
                    rpo_status = "NOT_MEASURED"
                elif (
                    isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
                    and math.isfinite(float(seconds)) and float(seconds) >= 0
                ):
                    rpo_status = "WITHIN_900_SECONDS" if float(seconds) <= 900 else "EXCEEDED_900_SECONDS"
                else:
                    raise LaunchGateError("dump_followup_rpo_invalid")
            else:
                raise LaunchGateError("dump_followup_restore_mode_invalid")
            receipt_path = Path(receipt_text)
            if not receipt_path.is_absolute() or receipt_path.is_symlink():
                raise LaunchGateError("dump_followup_receipt_path_untrusted")
            try:
                if resume_terminal:
                    receipt = _read_dump_followup_receipt(receipt_text, request_id)
                    expected_failure_codes = {"FULL_FAILOVER_FAILED_AFTER_DUMP_RESTORE"}
                    pipeline = receipt.get("failover_pipeline")
                    if (
                        state.get("result") != "dump_restore_succeeded_but_common_failover_incomplete"
                        or receipt.get("request_id") != request_id
                        or receipt.get("request_type") != chatops.REQUEST_TYPE_DUMP_RESTORE
                        or receipt.get("request_origin") != origin
                        or receipt.get("request_source") != source
                        or receipt.get("slack_client_key") != client_key
                        or receipt.get("backup_id") != expected_backup_id
                        or str(receipt.get("expected_sha256") or "").lower() != expected_sha256.lower()
                        or receipt.get("target") != {
                            "instance_id": "AWS_RESOURCE_ID_REDACTED",
                            "private_ip": "IP_REDACTED", "port": 3306, "database": "hospital_db",
                        }
                        or receipt.get("status") != "PARTIAL_FAILURE"
                        or receipt.get("phase") != "FULL_FAILOVER"
                        or receipt.get("failure_code") not in expected_failure_codes
                        or receipt.get("restore_attempted") is not True
                        or receipt.get("dns_changed") != "UNKNOWN"
                        or receipt.get("dr_active_recorded") is not False
                        or receipt.get("automatic_db_rollback") is not False
                        or not isinstance(pipeline, dict)
                        or pipeline.get("status") != "PARTIAL_FAILURE"
                        or pipeline.get("request_id") != request_id
                        or pipeline.get("recovery_mode") != "APPROVED_DUMP"
                        or pipeline.get("final_dr_state") != "IDLE"
                        or pipeline.get("completion_marker_verified") is not False
                        or receipt.get("dump_failover_resume_attempted") is True
                        or not chatops._demo_dump_restore_recovery_data_valid(state, receipt)
                        or not chatops._demo_dump_approval_evidence_matches(state, receipt)
                        or not chatops._demo_dump_overwrite_authorization_matches(state, receipt)
                    ):
                        raise LaunchGateError("dump_followup_resume_receipt_invalid")
                else:
                    repo_root = Path(__file__).resolve().parents[2]
                    if str(repo_root) not in sys.path:
                        sys.path.insert(0, str(repo_root))
                    from operations.failover.nr_readiness import validate_dump_restore_receipt

                    validate_dump_restore_receipt(
                        receipt_path, request_id=request_id, backup_id=expected_backup_id,
                        expected_sha256=expected_sha256.lower(),
                    )
            except LaunchGateError:
                raise
            except Exception as exc:
                raise LaunchGateError("dump_followup_restore_receipt_invalid") from exc
        else:
            if (
                request_type not in chatops.FAILOVER_RECOVERY_REQUEST_TYPES
                or chatops._failover_request_contract(state) is None
            ):
                raise LaunchGateError("failover_request_provenance_invalid")
            rpo_policy_error = chatops._failover_rpo_policy_error(incident)
            if rpo_policy_error:
                raise LaunchGateError(rpo_policy_error)
            rpo_error = chatops._failover_rpo_gate_error(incident)
            if rpo_error == "failover_rpo_target_exceeded":
                rpo_status = "EXCEEDED_900_SECONDS"
            elif rpo_error == "failover_rpo_not_measured":
                rpo_status = "NOT_MEASURED"
            elif rpo_error:
                raise LaunchGateError(rpo_error)
            else:
                rpo_status = "WITHIN_900_SECONDS"
            recovery_error = chatops._failover_recovery_authorization_error(state, approved=True, now=current)
            if recovery_error:
                raise LaunchGateError(recovery_error)
    except LaunchGateError:
        raise
    except Exception as exc:
        raise LaunchGateError("chatops_contract_validation_failed") from exc
    return {
        "request_id": request_id,
        "execution_id": state["execution_id"],
        "request_type": chatops.request_type_from_state(state),
        "approval_count": len(approvers),
        "rpo": rpo_status,
    }


def validate_synthetic_demo_launch(database: str, request_id: str, *, now: float | None = None) -> dict:
    """Validate the one-admin grant for the isolated synthetic MySQL runner only.

    This is deliberately separate from ``validate_launch_context``. It does not
    authorize the production Failover shell path and does not consume RPO/Fence
    evidence as production proof.
    """
    if Path(database) != PRODUCTION_CHATOPS_STATE_DB:
        raise LaunchGateError("synthetic_demo_state_path_mismatch")
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        request_id or "",
    ):
        raise LaunchGateError("request_id_invalid")
    current = float(time.time() if now is None else now)
    if not math.isfinite(current) or current <= 0:
        raise LaunchGateError("verification_clock_invalid")
    state = _state_database(database, request_id)
    chatops = _chatops_module()
    if (
        state.get("request_id") != request_id
        or state.get("action") != "failover"
        or state.get("status") != "EXECUTING"
        or state.get("finished_at") is not None
        or state.get("cancelled_by") is not None
        or state.get("approval_required") != 1
    ):
        raise LaunchGateError("synthetic_demo_request_not_approved_or_active")

    approvers = state.get("approvers")
    if (
        not isinstance(approvers, list)
        or len(approvers) != 1
        or not isinstance(approvers[0], str)
        or not approvers[0].strip()
    ):
        raise LaunchGateError("synthetic_demo_single_admin_approval_unverified")

    incidents = state.get("incidents")
    if not isinstance(incidents, list) or len(incidents) != 1 or not isinstance(incidents[0], dict):
        raise LaunchGateError("synthetic_demo_request_contract_invalid")
    incident = incidents[0]
    if (
        incident.get("request_type") != SYNTHETIC_DEMO_REQUEST_TYPE
        or incident.get("request_origin") != SYNTHETIC_DEMO_REQUEST_ORIGIN
        or incident.get("source") != SYNTHETIC_DEMO_REQUEST_SOURCE
        or incident.get("test_mode") is True
        or chatops.request_type_from_state(state) != SYNTHETIC_DEMO_REQUEST_TYPE
    ):
        raise LaunchGateError("synthetic_demo_request_provenance_invalid")

    try:
        repo_root = Path(__file__).resolve().parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from operations.demo.synthetic_mysql_demo_contract import (
            AUTHORIZATION_FIELD,
            AUTHORIZATION_KIND,
            AUTHORIZATION_VERSION,
            expected_static_binding,
        )

        expected = expected_static_binding(repo_root)
    except Exception as exc:
        raise LaunchGateError("synthetic_demo_executor_contract_unavailable") from exc

    authorization = incident.get(AUTHORIZATION_FIELD)
    if not isinstance(authorization, dict):
        raise LaunchGateError("synthetic_demo_authorization_missing")
    expected_keys = set(expected) | {
        "request_id", "status", "approval_required", "issued_at",
        "approval_mode_expires_at", "approved_at", "approval_count",
        "approver_ids", "execution_id",
    }
    if set(authorization) != expected_keys or any(
        authorization.get(key) != value for key, value in expected.items()
    ):
        raise LaunchGateError("synthetic_demo_authorization_scope_mismatch")

    for field, reason in (
        ("created_at", "request_created_at_invalid"),
        ("first_approved_at", "request_approval_time_invalid"),
        ("expires_at", "request_expiry_invalid"),
        ("execution_started_at", "execution_start_invalid"),
        ("execution_heartbeat_at", "execution_heartbeat_invalid"),
        ("execution_lease_until", "execution_lease_invalid"),
    ):
        value = state.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise LaunchGateError(reason)
    try:
        mode_expiry = float(state.get("approval_mode_expires_at"))
        issued_at = float(authorization.get("issued_at"))
        grant_expiry = float(authorization.get("approval_mode_expires_at"))
        approved_at = float(authorization.get("approved_at"))
    except (TypeError, ValueError):
        raise LaunchGateError("synthetic_demo_approval_window_invalid")

    if (
        authorization.get("request_id") != request_id
        or authorization.get("kind") != AUTHORIZATION_KIND
        or authorization.get("version") != AUTHORIZATION_VERSION
        or authorization.get("status") != "APPROVED_FOR_SYNTHETIC_EXECUTION"
        or authorization.get("approval_required") != 1
        or authorization.get("approval_count") != 1
        or authorization.get("approver_ids") != approvers
        or authorization.get("execution_id") != state.get("execution_id")
        or not math.isfinite(mode_expiry)
        or mode_expiry <= current
        or abs(mode_expiry - grant_expiry) > 0.001
        or state.get("expires_at") > mode_expiry
        or not math.isfinite(issued_at)
        or issued_at <= 0
        or issued_at > state.get("first_approved_at")
        or not math.isfinite(approved_at)
        or approved_at != state.get("first_approved_at")
        or state.get("first_approved_at") > current
        or state.get("created_at") > current
        or state.get("expires_at") <= current
        or state.get("execution_started_at") < state.get("first_approved_at")
        or state.get("execution_started_at") > current
        or state.get("execution_heartbeat_at") > current + 5
        or state.get("execution_lease_until") <= current
        or not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            str(state.get("execution_id") or ""),
        )
    ):
        raise LaunchGateError("synthetic_demo_approval_or_lease_invalid")

    return {
        "request_id": request_id,
        "execution_id": state["execution_id"],
        "request_type": SYNTHETIC_DEMO_REQUEST_TYPE,
        "approval_count": 1,
        "target_instance_id": expected["target"]["instance_id"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--synthetic-mysql-demo", action="store_true")
    parser.add_argument("--dump-restore-followup", action="store_true")
    parser.add_argument("--dump-followup-resume", action="store_true")
    parser.add_argument("--backup-id", default="")
    parser.add_argument("--sha256", default="")
    parser.add_argument("--dump-receipt", default="")
    args = parser.parse_args(argv)
    try:
        if Path(args.database) != PRODUCTION_CHATOPS_STATE_DB:
            raise LaunchGateError("chatops_state_path_mismatch")
        if args.synthetic_mysql_demo:
            result = validate_synthetic_demo_launch(args.database, args.request_id)
            print(
                "SYNTHETIC_DEMO_LAUNCH=VERIFIED "
                f"request_id={result['request_id']} approvals=1 target={result['target_instance_id']}"
            )
            return 0
        if args.dump_restore_followup:
            if not args.backup_id or not args.sha256 or not args.dump_receipt:
                raise LaunchGateError("dump_followup_identity_missing")
            result = validate_launch_context(
                args.database, args.request_id,
                dump_followup=(args.backup_id, args.sha256.lower(), args.dump_receipt),
                dump_followup_resume=args.dump_followup_resume,
            )
        else:
            result = validate_launch_context(args.database, args.request_id)
    except LaunchGateError as exc:
        print(f"FAILOVER_LAUNCH=BLOCKED reason={exc.reason}")
        return 1
    print(
        "FAILOVER_LAUNCH=VERIFIED "
        f"request_id={result['request_id']} execution_id={result['execution_id']} "
        f"request_type={result['request_type']} approvals={result['approval_count']} "
        f"rpo={result['rpo']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
