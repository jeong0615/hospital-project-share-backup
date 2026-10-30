#!/usr/bin/env python3
"""ChatOps-only orchestrator for the isolated Dump Failover workflow.

This controller never calls the normal full_failover.sh path.  Every child
stage receives the same request/backup identity and inherited canonical DR
locks; each existing stage remains responsible for validating its own current
receipts and live infrastructure state.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from zoneinfo import ZoneInfo

from operations.db import dump_db_dns_transaction as dns_transaction
from operations.db import dump_db_service_open as service_open
from operations.db.dump_execution_contract import (
    LockContractError,
    acquire_shared_dr_locks,
    validate_inherited_dr_locks,
)
from operations.db.isolated_dump_restore import validate_backup_pair


REPO_ROOT = Path(__file__).resolve().parents[2]
EXECUTOR_WRAPPER = Path(__file__).with_suffix(".sh")
DEFAULT_RECEIPT_ROOT = Path("/var/lib/hospital-dr/dump-failover-executions")
BACKUP_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
APPROVAL_TYPE = "DUMP_RESTORE_FAILOVER"
FAILOVER_RPO_FAILURE_POLICY = "BLOCK_IF_UNVERIFIED_OR_OVER_900_SECONDS"
FAILOVER_RPO_TARGET_SECONDS = 900
EXISTING_DR_OVERWRITE_AUTH_FIELD = "existing_dr_overwrite_authorization"
EXISTING_DR_OVERWRITE_AUTH_VERSION = 1
EXISTING_DR_OVERWRITE_SCOPE = "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB"
EXISTING_DR_OVERWRITE_TARGET = {
    "instance_id": "AWS_RESOURCE_ID_REDACTED",
    "private_ip": "IP_REDACTED",
    "port": 3306,
    "database": "hospital_db",
}
MUTATING_STAGES = {
    "restore", "prepare-service", "service-cutover", "service-promote",
    "readonly-health", "public-readiness", "dns-transaction", "service-open",
    "final-service-verify",
}
STAGE_OPTINS = (
    "DUMP_DB_SERVICE_CUTOVER_ENABLED",
    "DUMP_DB_SERVICE_PROMOTION_ENABLED",
    "DUMP_DB_DNS_PREFLIGHT_ENABLED",
    "DUMP_DB_READONLY_HEALTH_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_ENABLED",
    "DUMP_DB_DNS_TRANSACTION_ENABLED",
    "DUMP_DB_SERVICE_OPEN_ENABLED",
)
SECRET_ENV_NAMES = {
    "DB_BACKUP_ENCRYPTION_KEY", "DUMP_RESTORE_SERVICE_DB_PASSWORD",
    "MYSQL_ROOT_PASS", "ONPREM_DB_ROOT_PASS", "ONPREM_DOC_DB_PASSWORD",
    "DOC_DB_PASSWORD", "CLOUDFLARE_API_TOKEN", "SLACK_FAILOVER_BOT_TOKEN",
    "SLACK_FAILBACK_BOT_TOKEN", "SLACK_EMERGENCY_BOT_TOKEN",
    "SLACK_FAILOVER_SIGNING_SECRET", "SLACK_FAILBACK_SIGNING_SECRET",
    "SLACK_EMERGENCY_SIGNING_SECRET",
}
CHILD_ENV_ALLOWLIST = {
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
    "SSH_AUTH_SOCK", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE",
    "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_EC2_METADATA_DISABLED",
    "DR_REPO_ROOT", "DR_TERRAFORM_DIR", "DR_ANSIBLE_DIR", "DR_SECRET_FILE",
    "DR_STATE_DIR", "DR_STATE_FILE", "DR_DNS_ORIGIN_SNAPSHOT_DIR",
    "DR_CLOUDFLARE_AUTH_SCRIPT",
    "DR_WORKFLOW_LOCK_FILE", "DR_FAILOVER_LOCK_FILE", "DR_SSH_CONFIG_FILE",
    "DR_SSH_KNOWN_HOSTS_FILE", "DR_SSH_PRIVATE_KEY", "DR_SSH_KEY", "SSH_KEY",
    "TF_VAR_ssh_public_key_path", "INVENTORY", "CHATOPS_STATE_DB", "DUMP_BACKUP_DIR",
    "CHATOPS_EXECUTION_TIMEOUT_SECONDS", "SLACK_ADMIN_USER_IDS", "DUMP_RESTORE_EXEC_ENABLED",
    "DUMP_RESTORE_EXECUTOR", "DUMP_FAILOVER_MAX_RUNTIME_SECONDS",
    "DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS", "DR_DOMAIN", "EMR_DOMAIN",
    "DR_WEB_EIP_EXPECTED", "ONPREM_TUNNEL_HOST", "ONPREM_EMR_DNS_IP_EXPECTED",
    "CF_ZONE_ID", "CF_RECORD_ID_EXPECTED", "CF_EMR_RECORD_ID_EXPECTED",
    "TF_VAR_cloudflare_ipv4_cidrs", "TF_VAR_management_ipv4_cidrs",
    "TF_VAR_zabbix_agent_source_ipv4_cidrs", "TF_VAR_aws_dr_wg_peer_ingress_ipv4_cidrs",
    "TF_VAR_aws_dr_wg_enabled", "DUMP_DB_PUBLIC_READINESS_TTL_SECONDS",
    "DUMP_DB_DNS_HEALTH_ATTEMPTS", "DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS",
    "DUMP_DB_PUBLIC_READINESS_STATE_DIR", "DUMP_DB_DNS_TRANSACTION_STATE_DIR",
    "DUMP_DB_SERVICE_OPEN_STATE_DIR", "DUMP_DB_SERVICE_OPEN_LOCK_FILE",
    "DUMP_DB_SERVICE_CUTOVER_ENABLED", "DUMP_DB_SERVICE_PROMOTION_ENABLED",
    "DUMP_DB_DNS_PREFLIGHT_ENABLED", "DUMP_DB_READONLY_HEALTH_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_ENABLED", "DUMP_DB_DNS_TRANSACTION_ENABLED",
    "DUMP_DB_SERVICE_OPEN_ENABLED", "DR_DUMP_EXECUTOR_CHILD", "DR_RTO_RUN_ID",
    "DR_RTO_EVENT_ID", "DR_RTO_APPROVAL_ID", "ANSIBLE_CONFIG",
    "ANSIBLE_HOST_KEY_CHECKING", "ANSIBLE_DEPRECATION_WARNINGS", "ANSIBLE_LOCAL_TEMP",
    "ANSIBLE_REMOTE_TEMP", "ANSIBLE_SSH_CONTROL_PATH_DIR", "PYTHONWARNINGS",
}


class DumpExecutorError(RuntimeError):
    """Safe, stable refusal reason; never contains subprocess output."""


class ExecutionInterrupted(DumpExecutorError):
    pass


def _canonical_uuid(value: str, code: str = "REQUEST_ID_INVALID") -> str:
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DumpExecutorError(code) from exc
    if not UUID_RE.fullmatch(parsed) or parsed != str(value).lower():
        raise DumpExecutorError(code)
    return parsed


def validate_cli_identity(args: argparse.Namespace) -> tuple[str, str, str]:
    request_id = _canonical_uuid(args.request_id)
    backup_id = str(args.backup_id or "")
    if not BACKUP_RE.fullmatch(backup_id) or Path(backup_id).name != backup_id:
        raise DumpExecutorError("BACKUP_ID_INVALID")
    checksum = str(args.expected_sha256 or "").lower()
    if not SHA_RE.fullmatch(checksum):
        raise DumpExecutorError("BACKUP_CHECKSUM_INVALID")
    return request_id, backup_id, checksum


def _bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_executor_configuration(env: Mapping[str, str], *, executor_path: Path = EXECUTOR_WRAPPER) -> tuple[int, int, int]:
    if not _bool(env.get("DUMP_RESTORE_EXEC_ENABLED")):
        raise DumpExecutorError("DUMP_RESTORE_EXECUTOR_DISABLED")
    configured = str(env.get("DUMP_RESTORE_EXECUTOR", "")).strip()
    if not configured or not Path(configured).is_absolute() or Path(configured).is_symlink():
        raise DumpExecutorError("DUMP_RESTORE_EXECUTOR_PATH_INVALID")
    try:
        if Path(configured).resolve(strict=True) != executor_path.resolve(strict=True):
            raise DumpExecutorError("DUMP_RESTORE_EXECUTOR_PATH_MISMATCH")
    except OSError as exc:
        raise DumpExecutorError("DUMP_RESTORE_EXECUTOR_PATH_INVALID") from exc
    for name in STAGE_OPTINS:
        if not _bool(env.get(name)):
            raise DumpExecutorError(f"{name}_NOT_EXPLICITLY_ENABLED")
    try:
        max_runtime = int(env.get("DUMP_FAILOVER_MAX_RUNTIME_SECONDS", ""))
        shutdown_margin = int(env.get("DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS", ""))
        chatops_timeout = int(env.get("CHATOPS_EXECUTION_TIMEOUT_SECONDS", ""))
    except (TypeError, ValueError) as exc:
        raise DumpExecutorError("DUMP_FAILOVER_RUNTIME_BUDGET_CONFIGURATION_REQUIRED") from exc
    if min(max_runtime, shutdown_margin, chatops_timeout) <= 0:
        raise DumpExecutorError("DUMP_FAILOVER_RUNTIME_BUDGET_INVALID")
    if max_runtime + shutdown_margin > chatops_timeout:
        raise DumpExecutorError("CHATOPS_TIMEOUT_SHORTER_THAN_DUMP_RUNTIME_BUDGET")
    if not str(env.get("CHATOPS_STATE_DB", "")).strip():
        raise DumpExecutorError("CHATOPS_STATE_DB_UNAVAILABLE")
    if not str(env.get("DUMP_BACKUP_DIR", "")).strip():
        raise DumpExecutorError("DUMP_BACKUP_DIR_UNAVAILABLE")
    return max_runtime, shutdown_margin, chatops_timeout


def verify_finops_runway(
    *, now: datetime, max_runtime_seconds: int, shutdown_margin_seconds: int,
    elapsed_seconds: float = 0, timezone_name: str = "Asia/Seoul",
) -> None:
    if now.tzinfo is None:
        raise DumpExecutorError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    zone = ZoneInfo(timezone_name)
    local_now = now.astimezone(zone)
    cutoff = datetime.combine(local_now.date(), datetime_time(19, 0), tzinfo=zone)
    if local_now >= cutoff:
        cutoff += timedelta(days=1)
    remaining_runtime = max(0.0, float(max_runtime_seconds) - max(0.0, float(elapsed_seconds)))
    available = (cutoff - local_now).total_seconds()
    if available <= remaining_runtime + shutdown_margin_seconds:
        raise DumpExecutorError("INSUFFICIENT_RUNWAY_BEFORE_19_KST_FINOPS_WINDOW")


def _safe_child_environment(env: Mapping[str, str]) -> dict[str, str]:
    child = {
        key: str(value)
        for key, value in env.items()
        if key in CHILD_ENV_ALLOWLIST or key.startswith("AWS_")
    }
    for key in SECRET_ENV_NAMES:
        child.pop(key, None)
    child["DR_DUMP_EXECUTOR_CHILD"] = "1"
    child["DR_WORKFLOW_LOCK_HELD"] = "1"
    child["DR_FAILOVER_LOCK_HELD"] = "1"
    child["DUMP_RESTORE_EXEC_ENABLED"] = "false"
    child.pop("DUMP_RESTORE_EXECUTOR", None)
    child["ISOLATED_DUMP_RESTORE_WRAPPER"] = "1"
    return child


def _validate_approval(
    *, request_id: str, backup_path: Path, expected_sha256: str,
    environment: Mapping[str, str], now: datetime,
    approval_validator: Callable = dns_transaction.validate_approved_chatops_request,
    allowed_request_origins: tuple[str, ...] = ("GENERAL",),
    require_existing_dr_overwrite_authorization: bool = False,
    allow_conditional_failover_fallback: bool = False,
) -> dict:
    database = Path(environment.get("CHATOPS_STATE_DB", ""))
    identity_args = argparse.Namespace(
        request_id=request_id, backup=backup_path, expected_sha256=expected_sha256,
        allow_conditional_failover_fallback=allow_conditional_failover_fallback,
    )
    try:
        approval = approval_validator(database, identity_args, now=now, owner_uid=os.geteuid())
    except Exception as exc:
        if isinstance(exc, dns_transaction.DNSTransactionError):
            raise DumpExecutorError(str(exc)) from exc
        raise DumpExecutorError("CHATOPS_APPROVAL_NOT_CURRENT") from exc
    if (
        approval.get("request_id") != request_id
        or approval.get("approval_required") != 2
        or approval.get("approval_count") != 2
        or not isinstance(approval.get("approver_ids"), list)
        or len(set(approval["approver_ids"])) != 2
    ):
        raise DumpExecutorError("CURRENT_TWO_ADMIN_APPROVAL_REQUIRED")
    allowlist = {
        item.strip() for item in environment.get("SLACK_ADMIN_USER_IDS", "").split(",")
        if item.strip()
    }
    if not allowlist or not set(approval["approver_ids"]).issubset(allowlist):
        raise DumpExecutorError("CHATOPS_APPROVER_ALLOWLIST_MISMATCH")

    uri = database.absolute().as_uri() + "?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT action, slack_client_key, incidents, status, expires_at, execution_id, "
                "approval_required, approvers FROM approval_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        raise DumpExecutorError("CHATOPS_APPROVAL_STATE_UNAVAILABLE") from exc
    if row is None:
        raise DumpExecutorError("CHATOPS_APPROVED_REQUEST_NOT_FOUND")
    try:
        incidents = json.loads(row["incidents"])
        latest = incidents[-1]
    except (TypeError, ValueError, json.JSONDecodeError, IndexError) as exc:
        raise DumpExecutorError("CHATOPS_APPROVAL_STATE_INVALID") from exc
    source_contracts = {
        "GENERAL": ("failover", "dump_restore_console"),
        "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
    }
    allowed_origins = {str(value).strip().upper() for value in allowed_request_origins}
    origin = str(latest.get("request_origin") or "").strip().upper() if isinstance(latest, dict) else ""
    contract = source_contracts.get(origin)
    conditional_fallback = bool(allow_conditional_failover_fallback)
    request_type = latest.get("request_type") if isinstance(latest, dict) else None
    fallback_candidate = None
    recovery_plan = None
    if conditional_fallback:
        recovery_plan = latest.get("failover_recovery_plan") if isinstance(latest, dict) else None
        fallback_candidate = recovery_plan.get("dump") if isinstance(recovery_plan, dict) else None
        if request_type == "NORMAL_FAILOVER":
            valid_origin = (
                (origin in {"", "GENERAL"} and row["slack_client_key"] == "failover"
                 and latest.get("source") in {"", "manual", "zabbix"})
                or (origin == "CLOUD_SLACK_DR_TRIGGER" and row["slack_client_key"] == "failover"
                    and latest.get("source") == "zabbix"
                    and latest.get("production_action_verified") is True)
            )
            contract = (row["slack_client_key"], latest.get("source")) if valid_origin else None
        elif request_type == "EMERGENCY_FAILOVER":
            valid_origin = (
                origin == "EMERGENCY" and row["slack_client_key"] == "emergency"
                and latest.get("source") == "emergency_console"
            )
            contract = ("emergency", "emergency_console") if valid_origin else None
        else:
            contract = None
    expected_backup_id = (
        fallback_candidate.get("backup_id")
        if conditional_fallback and isinstance(fallback_candidate, dict)
        else latest.get("backup_id") if isinstance(latest, dict) else None
    )
    expected_checksum = (
        str(fallback_candidate.get("sha256") or "").lower()
        if conditional_fallback and isinstance(fallback_candidate, dict)
        else str(latest.get("backup_checksum", "")).lower() if isinstance(latest, dict) else ""
    )
    if (
        row["action"] != "failover"
        or row["status"] != "EXECUTING"
        or not isinstance(latest, dict)
        or (
            latest.get("request_type") not in {"NORMAL_FAILOVER", "EMERGENCY_FAILOVER"}
            if conditional_fallback
            else latest.get("request_type") != APPROVAL_TYPE
        )
        or origin not in allowed_origins
        or contract is None
        or (not conditional_fallback and (
            row["slack_client_key"] != contract[0]
            or latest.get("slack_client_key") != contract[0]
            or latest.get("source") != contract[1]
        ))
        or expected_backup_id != backup_path.name
        or expected_checksum != expected_sha256.lower()
    ):
        raise DumpExecutorError("GENERAL_DUMP_FAILOVER_APPROVAL_REQUIRED")
    approval = dict(approval)
    approval.update({
        "request_origin": origin,
        "request_type": latest["request_type"],
        "request_source": latest.get("source") if conditional_fallback else contract[1],
        "slack_client_key": row["slack_client_key"],
        "production_action_verified": latest.get("production_action_verified") is True,
    })
    if conditional_fallback:
        target = {
            "instance_id": "AWS_RESOURCE_ID_REDACTED",
            "private_ip": "IP_REDACTED",
            "port": 3306,
            "database": "hospital_db",
        }
        rpo_error = _conditional_fallback_rpo_error(latest, fallback_candidate)
        if rpo_error:
            raise DumpExecutorError(rpo_error)
        if (
            not isinstance(recovery_plan, dict)
            or recovery_plan.get("version") != 1
            or recovery_plan.get("policy") != "NR_FIRST_DUMP_FALLBACK"
            or recovery_plan.get("rpo_failure_policy") != FAILOVER_RPO_FAILURE_POLICY
            or recovery_plan.get("target") != target
            or recovery_plan.get("overwrite_scope") != EXISTING_DR_OVERWRITE_SCOPE
            or not isinstance(fallback_candidate, dict)
            or fallback_candidate.get("status") != "READY"
            or fallback_candidate.get("backup_id") != backup_path.name
            or fallback_candidate.get("sha256") != expected_sha256.lower()
            or not SHA_RE.fullmatch(str(fallback_candidate.get("sidecar_sha256") or ""))
        ):
            raise DumpExecutorError("CONDITIONAL_DUMP_RECOVERY_PLAN_INVALID")
        approval["recovery_plan"] = recovery_plan
    if require_existing_dr_overwrite_authorization:
        if not conditional_fallback:
            restore_mode = str(latest.get("dump_restore_mode") or "")
            expected_rpo = latest.get("expected_rpo")
            sidecar_checksum = str(latest.get("backup_sidecar_checksum") or "").lower()
            if restore_mode == "LEGACY_MANUAL":
                if (
                    not isinstance(expected_rpo, dict)
                    or expected_rpo.get("status") != "NOT_MEASURED"
                    or expected_rpo.get("seconds") is not None
                    or not SHA_RE.fullmatch(sidecar_checksum)
                ):
                    raise DumpExecutorError("LEGACY_DUMP_REQUEST_VALIDATION_INVALID")
            elif restore_mode != "MANIFEST_VERIFIED":
                raise DumpExecutorError("DUMP_RESTORE_MODE_INVALID")
            approval.update({
                "dump_restore_mode": restore_mode,
                "expected_rpo": expected_rpo,
                "backup_sidecar_checksum": sidecar_checksum,
            })
        try:
            grant = latest.get(EXISTING_DR_OVERWRITE_AUTH_FIELD)
            expiry = float(row["expires_at"])
            approved_at = float(grant.get("approved_at")) if isinstance(grant, dict) else 0
            grant_expiry = float(grant.get("expires_at")) if isinstance(grant, dict) else 0
            grant_approvers = grant.get("approver_ids") if isinstance(grant, dict) else None
            approval_required = int(row["approval_required"])
            row_approvers = json.loads(row["approvers"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DumpExecutorError("EXISTING_DR_OVERWRITE_AUTHORIZATION_INVALID") from exc
        now_epoch = now.astimezone(timezone.utc).timestamp()
        expected_type = latest["request_type"]
        expected_source = latest.get("source") if conditional_fallback else contract[1]
        expected_client = row["slack_client_key"] if conditional_fallback else contract[0]
        if (
            not isinstance(grant, dict)
            or grant.get("version") != EXISTING_DR_OVERWRITE_AUTH_VERSION
            or not UUID_RE.fullmatch(str(grant.get("authorization_id") or ""))
            or grant.get("request_id") != request_id
            or grant.get("status") != "APPROVED_BY_TWO_DISTINCT_ADMINS"
            or grant.get("scope") != EXISTING_DR_OVERWRITE_SCOPE
            or grant.get("target") != EXISTING_DR_OVERWRITE_TARGET
            or grant.get("request_type") != expected_type
            or grant.get("request_origin") != origin
            or grant.get("request_source") != expected_source
            or grant.get("slack_client_key") != expected_client
            or (
                not conditional_fallback
                and (
                    grant.get("requested_by") != latest.get("requested_by")
                    or not isinstance(latest.get("requested_by"), str)
                    or not latest.get("requested_by", "").strip()
                )
            )
            or grant.get("backup_id") != backup_path.name
            or grant.get("sha256") != expected_sha256
            or (
                conditional_fallback
                and (
                    grant.get("grant_kind") != "CONDITIONAL_DUMP_FALLBACK"
                    or grant.get("sidecar_sha256") != fallback_candidate.get("sidecar_sha256")
                    or grant.get("master_status") != fallback_candidate.get("master_status")
                    or grant.get("data_timestamp") != fallback_candidate.get("data_timestamp")
                    or grant.get("expected_rpo") != fallback_candidate.get("expected_rpo")
                    or grant.get("rpo_failure_policy") != recovery_plan.get("rpo_failure_policy")
                )
            )
            or not math.isfinite(expiry)
            or expiry <= now_epoch
            or not math.isfinite(grant_expiry)
            or abs(expiry - grant_expiry) > 0.001
            or not math.isfinite(approved_at)
            or not 0 < approved_at <= now_epoch
            or approval_required != 2
            or grant.get("approval_required") != 2
            or grant.get("approval_count") != 2
            or not isinstance(row_approvers, list)
            or len(row_approvers) != 2
            or len(set(row_approvers)) != 2
            or grant_approvers != row_approvers
            or grant_approvers != approval.get("approver_ids")
            or grant.get("execution_id") != approval.get("execution_id")
            or grant.get("execution_id") != row["execution_id"]
        ):
            raise DumpExecutorError("EXISTING_DR_OVERWRITE_AUTHORIZATION_INVALID")
        approval["overwrite_authorization"] = {
            key: grant[key] for key in (
                "authorization_id", "request_id", "status", "scope", "target",
                "backup_id", "sha256", "request_type", "request_origin",
                "request_source", "slack_client_key", "requested_by", "requested_at",
                "expires_at", "approved_at", "approval_required", "approval_count",
                "rpo_failure_policy",
                "approver_ids", "execution_id",
            ) if key in grant
        }
        if conditional_fallback:
            approval["overwrite_authorization"].update({
                key: grant.get(key) for key in (
                    "grant_kind", "sidecar_sha256", "master_status", "data_timestamp",
                    "expected_rpo", "recovery_plan_version", "rpo_failure_policy",
                )
            })
    return approval


def _conditional_fallback_rpo_error(incident: dict, candidate: dict | None) -> str | None:
    """Defense-in-depth: do not authorize an unmeasured or synthetic RPO in the executor."""
    expected = candidate.get("expected_rpo") if isinstance(candidate, dict) else None
    evidence = candidate.get("data_reference_evidence") if isinstance(candidate, dict) else None
    if not isinstance(expected, dict) or not isinstance(evidence, dict):
        return "failover_rpo_not_measured"
    source = expected.get("evidence_source")
    source_key = re.sub(r"[^A-Z0-9]+", "_", source.upper()).strip("_") if isinstance(source, str) else ""
    rejected_markers = (
        "BACKUP", "COMPLETED", "CREATED", "UPLOAD", "SIDECAR", "ARTIFACT",
        "MYSQL", "OBSERVATION", "CLOCK", "MANIFEST",
    )
    test_only_source_tokens = {"TEST", "SYNTHETIC", "MOCK", "FIXTURE", "DEMO"}
    if (
        candidate.get("data_reference_time_status") != "VERIFIED"
        or candidate.get("data_reference_at") != expected.get("data_reference_at")
        or evidence.get("status") != "VERIFIED"
        or evidence.get("authenticated") is not True
        or not isinstance(source, str)
        or not source.strip()
        or any(marker in source_key for marker in rejected_markers)
        or bool(test_only_source_tokens.intersection(source_key.split("_")))
        or evidence.get("source") != source
        or expected.get("evidence_status") != "VERIFIED"
        or expected.get("evidence_authenticated") is not True
        or expected.get("reason") != "MEASURED_FROM_VERIFIED_DATA_CUTOFF"
        or expected.get("incident_at") != incident.get("incident_at")
        or expected.get("target_seconds") != FAILOVER_RPO_TARGET_SECONDS
        or expected.get("status") not in {"PASS", "RPO_NOT_GUARANTEED"}
    ):
        return "failover_rpo_not_measured"
    try:
        cutoff = datetime.fromisoformat(str(expected.get("data_reference_at")).replace("Z", "+00:00"))
        incident_at = datetime.fromisoformat(str(expected.get("incident_at")).replace("Z", "+00:00"))
    except ValueError:
        return "failover_rpo_not_measured"
    seconds = expected.get("seconds")
    if (
        cutoff.tzinfo is None or incident_at.tzinfo is None or cutoff > incident_at
        or isinstance(seconds, bool) or not isinstance(seconds, int)
        or int((incident_at - cutoff).total_seconds()) != seconds
    ):
        return "failover_rpo_not_measured"
    if seconds > FAILOVER_RPO_TARGET_SECONDS:
        return "failover_rpo_target_exceeded"
    if expected.get("status") != "PASS":
        return "failover_rpo_not_measured"
    return None


def _same_approval(current: dict, initial: dict) -> bool:
    same = (
        current.get("execution_id") == initial.get("execution_id")
        and current.get("approver_ids") == initial.get("approver_ids")
        and current.get("approval_required") == 2
        and current.get("approval_count") == 2
    )
    if "overwrite_authorization" in initial or "overwrite_authorization" in current:
        same = same and current.get("overwrite_authorization") == initial.get("overwrite_authorization")
    return same


def _read_terraform_outputs(
    terraform_dir: Path, *, runner: Callable = subprocess.run,
) -> dict:
    if not terraform_dir.is_dir() or terraform_dir.is_symlink():
        raise DumpExecutorError("TERRAFORM_RUNTIME_UNAVAILABLE")
    try:
        result = runner(
            ["terraform", f"-chdir={terraform_dir}", "output", "-json"],
            capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        raise DumpExecutorError("TERRAFORM_READ_ONLY_OUTPUT_UNAVAILABLE") from exc
    if result.returncode != 0:
        raise DumpExecutorError("TERRAFORM_READ_ONLY_OUTPUT_UNAVAILABLE")
    try:
        raw = json.loads(result.stdout)
        outputs = {key: raw[key]["value"] for key in (
            "dump_restore_isolated_instance_id",
            "dump_restore_isolated_private_ip",
            "dump_restore_isolated_data_volume_id",
            "dump_restore_isolated_stage_volume_id",
            "dump_restore_isolated_service_security_group_id",
        )}
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise DumpExecutorError("ISOLATED_TERRAFORM_OUTPUTS_INVALID") from exc
    if (
        not INSTANCE_RE.fullmatch(str(outputs["dump_restore_isolated_instance_id"] or ""))
        or not VOLUME_RE.fullmatch(str(outputs["dump_restore_isolated_data_volume_id"] or ""))
        or not VOLUME_RE.fullmatch(str(outputs["dump_restore_isolated_stage_volume_id"] or ""))
        or outputs["dump_restore_isolated_data_volume_id"] == outputs["dump_restore_isolated_stage_volume_id"]
        or not SG_RE.fullmatch(str(outputs["dump_restore_isolated_service_security_group_id"] or ""))
        or not str(outputs["dump_restore_isolated_private_ip"] or "")
    ):
        raise DumpExecutorError("ISOLATED_TERRAFORM_OUTPUTS_NOT_OPTED_IN_OR_INVALID")
    return {
        "instance_id": str(outputs["dump_restore_isolated_instance_id"]),
        "private_ip": str(outputs["dump_restore_isolated_private_ip"]),
        "data_volume_id": str(outputs["dump_restore_isolated_data_volume_id"]),
        "stage_volume_id": str(outputs["dump_restore_isolated_stage_volume_id"]),
        "service_security_group_id": str(outputs["dump_restore_isolated_service_security_group_id"]),
    }


def _secure_operation_dir(root: Path, request_id: str, *, owner_uid: int) -> Path:
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise DumpExecutorError("EXECUTOR_STATE_DIRECTORY_INVALID")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_meta = root.stat()
    if root_meta.st_uid != owner_uid or stat.S_IMODE(root_meta.st_mode) != 0o700:
        raise DumpExecutorError("EXECUTOR_STATE_DIRECTORY_PERMISSIONS_INVALID")
    operation_dir = root / request_id
    try:
        operation_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise DumpExecutorError("DUMP_FAILOVER_REQUEST_ALREADY_RECORDED") from exc
    metadata = operation_dir.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise DumpExecutorError("EXECUTOR_STATE_DIRECTORY_PERMISSIONS_INVALID")
    return operation_dir


def _write_json_private(path: Path, record: dict, *, owner_uid: int) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.stat().st_uid != owner_uid:
            raise DumpExecutorError("EXECUTOR_RECEIPT_OWNER_INVALID")
        os.replace(temporary, path)
        path.chmod(0o600)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _append_safe_log(path: Path, message: str, *, owner_uid: int) -> None:
    if not re.fullmatch(r"[A-Z0-9_.:-]{1,96}", message):
        raise DumpExecutorError("EXECUTOR_LOG_MARKER_INVALID")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise DumpExecutorError("EXECUTOR_LOG_PERMISSIONS_INVALID")
        os.write(fd, f"{datetime.now(timezone.utc).isoformat()} {message}\n".encode("ascii"))
    finally:
        os.close(fd)


def _read_private_json(path: Path, *, owner_uid: int) -> dict:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 2 or metadata.st_size > 1024 * 1024
        ):
            raise DumpExecutorError("STAGE_RECEIPT_INVALID")
        value = json.loads(path.read_text(encoding="utf-8"))
    except DumpExecutorError:
        raise
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DumpExecutorError("STAGE_RECEIPT_UNAVAILABLE") from exc
    if not isinstance(value, dict):
        raise DumpExecutorError("STAGE_RECEIPT_INVALID")
    return value


def _terraform_stage_arguments(target: dict, backup: Path, checksum: str) -> list[str]:
    values = [
        "--region", "ap-northeast-2",
        "--instance-id", target["instance_id"],
        "--private-ip", target["private_ip"],
        "--data-volume-id", target["data_volume_id"],
        "--stage-volume-id", target["stage_volume_id"],
        "--backup", str(backup),
        "--expected-sha256", checksum,
    ]
    return values


def _build_stages(*, request_id: str, backup: Path, checksum: str, target: dict, env: Mapping[str, str]) -> list[tuple[str, list[str]]]:
    isolated = REPO_ROOT / "operations/db/isolated_dump_restore.sh"
    dns_preflight = REPO_ROOT / "operations/db/dump_db_dns_preflight.sh"
    readonly = REPO_ROOT / "operations/db/dump_db_readonly_health.sh"
    public_readiness = REPO_ROOT / "operations/db/dump_db_public_readiness.sh"
    dns_switch = REPO_ROOT / "operations/db/dump_db_dns_transaction.sh"
    service_open = REPO_ROOT / "operations/db/dump_db_service_open.sh"
    base = _terraform_stage_arguments(target, backup, checksum)
    target_sg = ["--service-security-group-id", target["service_security_group_id"]]
    promotion_args = ["--promotion-id", request_id, "--cutover-id", request_id]
    request_arg = ["--request-id", request_id]
    ssh_args = ["--ssh-key", env.get("SSH_KEY", "")]
    preflight = ["bash", str(isolated), "preflight", *base, "--request-id", request_id]
    restore = [
        "bash", str(isolated), "restore", *base, "--request-id", request_id,
        "--confirm-isolated-restore",
    ]
    prepare_service = [
        "bash", str(isolated), "prepare-service", *base, *target_sg,
        "--request-id", request_id, "--confirm-isolated-service-prepare",
    ]
    service_preflight = [
        "bash", str(isolated), "service-preflight", *base, *target_sg,
        "--request-id", request_id,
    ]
    cutover = [
        "bash", str(isolated), "service-cutover", *base, *target_sg,
        "--cutover-id", request_id, "--confirm-db-service-switch",
    ]
    promote = [
        "bash", str(isolated), "service-promote", *base, *target_sg,
        *promotion_args, "--confirm-write-promotion",
    ]
    gate_args = [*base, *target_sg, *promotion_args, *ssh_args]
    dns_gate = ["bash", str(dns_preflight), *gate_args]
    readonly_gate = [
        "bash", str(readonly), *gate_args, "--confirm-readonly-health",
    ]
    prepare_public = [
        "bash", str(public_readiness), *gate_args, "--confirm-public-readiness",
    ]
    dns_transaction = [
        "bash", str(dns_switch), *gate_args, *request_arg,
        "--confirm-dns-transaction",
    ]
    open_service = [
        "bash", str(service_open), *gate_args, *request_arg,
        "--confirm-service-open",
    ]
    return [
        ("target-preflight", preflight),
        ("restore", restore),
        ("prepare-service", prepare_service),
        ("service-preflight", service_preflight),
        ("service-cutover", cutover),
        ("service-promote", promote),
        ("dns-preflight", dns_gate),
        ("readonly-health", readonly_gate),
        ("public-readiness", prepare_public),
        ("dns-transaction", dns_transaction),
        ("service-open", open_service),
    ]


def _terminate_process_group(process: subprocess.Popen, *, grace_seconds: float = 5.0) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        process.wait(timeout=grace_seconds)


def _run_stage_process(
    command: list[str], *, environment: Mapping[str, str], checkpoint: Callable,
    poll_seconds: float = 1.0, popen_factory: Callable = subprocess.Popen,
) -> int:
    try:
        process = popen_factory(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            start_new_session=True,
            close_fds=True,
            pass_fds=(7, 8),
        )
    except OSError as exc:
        raise DumpExecutorError("DUMP_STAGE_PROCESS_START_FAILED") from exc
    try:
        while process.poll() is None:
            try:
                checkpoint()
            except Exception:
                _terminate_process_group(process)
                raise
            time.sleep(poll_seconds)
        return int(process.returncode or 0)
    except BaseException:
        if process.poll() is None:
            _terminate_process_group(process)
        raise


@contextmanager
def _held_shared_locks(env: Mapping[str, str]):
    descriptors = acquire_shared_dr_locks(env)
    try:
        yield descriptors
    finally:
        for descriptor in descriptors:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            except OSError:
                pass


def _read_dr_state(state_helper: Path, environment: Mapping[str, str], *, runner: Callable) -> str:
    result = runner(
        ["bash", "-c", 'source "$1"; dr_state_read', "dump-state-read", str(state_helper)],
        env=dict(environment), capture_output=True, text=True, check=False,
    )
    state = str(result.stdout or "").strip()
    if result.returncode != 0 or state not in {"IDLE", "FAILED", "DR_ACTIVE", "PARTIAL_FAILURE"}:
        raise DumpExecutorError("DR_STATE_READ_ONLY_CHECK_FAILED")
    return state


def _write_dr_state(state: str, state_helper: Path, environment: Mapping[str, str], *, runner: Callable) -> None:
    if state not in {"DR_ACTIVE", "PARTIAL_FAILURE"}:
        raise DumpExecutorError("DR_STATE_TRANSITION_NOT_ALLOWED")
    result = runner(
        ["bash", "-c", 'source "$1"; dr_state_write "$2"', "dump-state-write", str(state_helper), state],
        env=dict(environment), capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise DumpExecutorError("DR_STATE_WRITE_FAILED")


def _receipt_stage_path(env: Mapping[str, str], request_id: str, name: str) -> Path:
    state_dir = Path(env.get("DUMP_DB_DNS_TRANSACTION_STATE_DIR", "/var/lib/hospital-dr/dump-dns-transactions"))
    return state_dir / request_id / name


def _classify_dns_failure(env: Mapping[str, str], request_id: str, *, owner_uid: int) -> str:
    try:
        receipt = _read_private_json(_receipt_stage_path(env, request_id, "transaction.json"), owner_uid=owner_uid)
    except DumpExecutorError:
        return "PARTIAL_FAILURE"
    if (
        receipt.get("request_id") == request_id
        and receipt.get("cutover_id") == request_id
        and receipt.get("status") == dns_transaction.ROLLED_BACK_STATUS
        and receipt.get("rollback") == "SUCCESS_AND_READBACK_VERIFIED"
        and receipt.get("automatic_dns_rollback_allowed") is True
    ):
        return "FAILED"
    return "PARTIAL_FAILURE"


def _classify_service_open_failure(env: Mapping[str, str], request_id: str, *, owner_uid: int) -> str:
    state_dir = Path(env.get("DUMP_DB_SERVICE_OPEN_STATE_DIR", "/var/lib/hospital-dr/dump-service-open"))
    path = state_dir / request_id / "service-open.json"
    try:
        receipt = _read_private_json(path, owner_uid=owner_uid)
    except DumpExecutorError:
        return "PARTIAL_FAILURE"
    if receipt.get("request_id") != request_id or receipt.get("cutover_id") != request_id:
        return "PARTIAL_FAILURE"
    if (
        receipt.get("status") == service_open.PRE_DML_ROLLBACK_STATUS
        and receipt.get("dml_grant_attempted") is False
        and receipt.get("dns_rollback") == "SUCCESS_AND_READBACK_VERIFIED"
        and receipt.get("application_writes_allowed") is False
    ):
        return "FAILED"
    if receipt.get("status") == service_open.PARTIAL_STATUS or receipt.get("dml_grant_attempted") is not False:
        return "PARTIAL_FAILURE"
    return "PARTIAL_FAILURE"


def _classify_stage_failure(stage: str, receipt: Mapping[str, object]) -> str:
    if stage in {"dns-transaction", "service-open"}:
        return "PARTIAL_FAILURE"  # These callers use receipt-aware classifiers.
    if stage in MUTATING_STAGES or receipt.get("completed_stages"):
        return "PARTIAL_FAILURE"
    return "FAILED"


def _verify_success_receipt(path: Path, *, request_id: str, backup_id: str, checksum: str,
                            target: dict, owner_uid: int, expected_execution_id: str) -> dict:
    receipt = _read_private_json(path, owner_uid=owner_uid)
    expected = {
        "status": service_open.SUCCESS_STATUS,
        "request_id": request_id,
        "promotion_id": request_id,
        "cutover_id": request_id,
        "backup_id": backup_id,
        "sha256": checksum,
        "isolated_instance_id": target["instance_id"],
        "isolated_private_ip": target["private_ip"],
        "data_volume_id": target["data_volume_id"],
        "stage_volume_id": target["stage_volume_id"],
        "service_security_group_id": target["service_security_group_id"],
        "application_writes_allowed": True,
        "user_service_writes_open": True,
        "service_account_dml_enabled": True,
        "maintenance_mode": False,
        "dr_active_recorded": False,
        "dr_state_changed": False,
        "automatic_dns_rollback_allowed": False,
        "rollback_to_prior_database_allowed": False,
        "durable_service_fence": "CLOUDFLARE_WEB_TO_EMR_ONLY_VERIFIED",
        "preparation_timer": "CANCELLED_AFTER_DURABLE_FENCE_HANDOFF",
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise DumpExecutorError("SERVICE_OPEN_SUCCESS_RECEIPT_MISMATCH")
    approval = receipt.get("approval")
    if (
        not isinstance(approval, dict)
        or approval.get("execution_id") != expected_execution_id
        or approval.get("approval_required") != 2
        or approval.get("approval_count") != 2
    ):
        raise DumpExecutorError("SERVICE_OPEN_APPROVAL_RECEIPT_INVALID")
    health = receipt.get("public_service_health")
    if not isinstance(health, dict):
        raise DumpExecutorError("SERVICE_OPEN_PUBLIC_HEALTH_RECEIPT_INVALID")
    for alias in ("web", "emr"):
        outcome = health.get(alias)
        if not isinstance(outcome, dict) or outcome.get("status") != 200 or outcome.get("cloudflare_edge") is not True or outcome.get("tls_verified") is not True:
            raise DumpExecutorError("SERVICE_OPEN_PUBLIC_HEALTH_RECEIPT_INVALID")
    if receipt.get("cloudflare_health_204") != {"web": True, "emr": True}:
        raise DumpExecutorError("SERVICE_OPEN_PRIVATE_HEALTH_RECEIPT_INVALID")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", str(receipt.get("db_server_uuid", ""))):
        raise DumpExecutorError("SERVICE_OPEN_DB_IDENTITY_RECEIPT_INVALID")
    return receipt


def _safe_failure_state(
    *, status: str, phase: str, reason: str, request_id: str,
    operation_dir: Path, receipt_path: Path, receipt: dict,
    state_helper: Path, state_environment: Mapping[str, str], runner: Callable,
    state_reader: Callable | None = None, state_writer: Callable | None = None,
    state_observed: str, owner_uid: int,
) -> dict:
    receipt.update({
        "status": status,
        "phase": phase,
        "failure_code": reason if re.fullmatch(r"[A-Z0-9_]{1,96}", reason) else "EXECUTION_FAILED",
        "operator_intervention_required": status == "PARTIAL_FAILURE",
        "automatic_dns_rollback_allowed": False,
        "rollback_to_prior_database_allowed": False,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    if status == "PARTIAL_FAILURE":
        try:
            current = (
                state_reader() if state_reader is not None
                else _read_dr_state(state_helper, state_environment, runner=runner)
            )
            if current in {state_observed, "PARTIAL_FAILURE"} and current != "DR_ACTIVE":
                if state_writer is not None:
                    state_writer("PARTIAL_FAILURE")
                else:
                    _write_dr_state("PARTIAL_FAILURE", state_helper, state_environment, runner=runner)
                receipt["dr_state_marked_partial_failure"] = True
            else:
                receipt["dr_state_marked_partial_failure"] = False
                if current == "DR_ACTIVE":
                    receipt["dr_active_recorded"] = "UNKNOWN_OR_SET"
                    receipt["dr_state_observed_after_failure"] = "DR_ACTIVE"
        except Exception:
            receipt["dr_state_marked_partial_failure"] = False
            receipt["dr_state_observed_after_failure"] = "UNKNOWN"
    _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
    safe_phase = re.sub(r"[^A-Z0-9_.:-]", "_", str(phase).upper()).replace("-", "_")[:96] or "UNKNOWN"
    try:
        log_path = operation_dir / f"{request_id}.log"
        _append_safe_log(
            log_path,
            f"{safe_phase}:FAIL:{receipt['failure_code']}", owner_uid=owner_uid,
        )
        _append_safe_log(log_path, f"EXECUTOR_STATUS:{status}", owner_uid=owner_uid)
        _append_safe_log(
            log_path,
            "OPERATOR_INTERVENTION_REQUIRED:"
            f"{'TRUE' if receipt['operator_intervention_required'] else 'FALSE'}",
            owner_uid=owner_uid,
        )
    except (OSError, DumpExecutorError):
        # The receipt is authoritative; logging trouble must not mask its result.
        pass
    print(
        f"DUMP_FAILOVER_EXECUTOR request_id={request_id} phase={phase} "
        f"result={status} reason={receipt['failure_code']}",
        flush=True,
    )
    return receipt


def execute_dump_failover(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.monotonic,
    approval_validator: Callable = dns_transaction.validate_approved_chatops_request,
    backup_validator: Callable = validate_backup_pair,
    outputs_provider: Callable | None = None,
    stage_runner: Callable | None = None,
    lock_acquirer: Callable = _held_shared_locks,
    lock_validator: Callable = validate_inherited_dr_locks,
    state_reader: Callable | None = None,
    state_writer: Callable | None = None,
    owner_uid: int | None = None,
    receipt_root: Path | None = None,
) -> dict:
    env = dict(environment if environment is not None else os.environ)
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    request_id, backup_id, checksum = validate_cli_identity(args)
    max_runtime, shutdown_margin, chatops_timeout = validate_executor_configuration(env)
    started_monotonic = monotonic()
    backup_dir = Path(env["DUMP_BACKUP_DIR"])
    backup = backup_dir / backup_id
    if backup.is_symlink() or not backup.is_file():
        raise DumpExecutorError("BACKUP_ARTIFACT_UNAVAILABLE")
    try:
        verified_backup = backup_validator(backup, checksum)
    except Exception as exc:
        raise DumpExecutorError("BACKUP_CHECKSUM_OR_PAIR_INVALID") from exc
    if not isinstance(verified_backup, dict) or str(verified_backup.get("sha256", "")).lower() != checksum:
        raise DumpExecutorError("BACKUP_CHECKSUM_MISMATCH")
    backup = Path(verified_backup.get("backup_path", backup))
    if backup.name != backup_id or backup.is_symlink():
        raise DumpExecutorError("BACKUP_ARTIFACT_IDENTITY_INVALID")

    now = clock()
    verify_finops_runway(
        now=now, max_runtime_seconds=max_runtime,
        shutdown_margin_seconds=shutdown_margin,
    )
    approval = _validate_approval(
        request_id=request_id, backup_path=backup, expected_sha256=checksum,
        environment=env, now=now, approval_validator=approval_validator,
    )
    terraform_dir = Path(env.get("DR_TERRAFORM_DIR", str(REPO_ROOT / "infra/terraform")))
    if outputs_provider is None:
        outputs_provider = lambda: _read_terraform_outputs(terraform_dir)
    try:
        target = outputs_provider()
    except DumpExecutorError:
        raise
    except Exception as exc:
        raise DumpExecutorError("ISOLATED_TERRAFORM_OUTPUTS_INVALID") from exc
    for key, pattern in (("instance_id", INSTANCE_RE), ("data_volume_id", VOLUME_RE),
                         ("stage_volume_id", VOLUME_RE), ("service_security_group_id", SG_RE)):
        if not pattern.fullmatch(str(target.get(key, ""))):
            raise DumpExecutorError("ISOLATED_TARGET_IDENTITY_INVALID")
    if target["data_volume_id"] == target["stage_volume_id"]:
        raise DumpExecutorError("ISOLATED_TARGET_VOLUME_COLLISION")
    if target["instance_id"] == "AWS_RESOURCE_ID_REDACTED" or target["private_ip"] in {
        "IP_REDACTED", "IP_REDACTED", "IP_REDACTED", "IP_REDACTED",
    }:
        raise DumpExecutorError("PROTECTED_DATABASE_TARGET_FORBIDDEN")

    state_helper = Path(env.get("DR_STATE_HELPER", str(REPO_ROOT / "operations/runtime/dr_state.sh")))
    if state_reader is None:
        state_reader = lambda: _read_dr_state(state_helper, env, runner=subprocess.run)
    if state_writer is None:
        state_writer = lambda value: _write_dr_state(value, state_helper, env, runner=subprocess.run)
    try:
        state_observed = state_reader()
    except Exception as exc:
        raise DumpExecutorError("DR_STATE_READ_ONLY_CHECK_FAILED") from exc
    if state_observed not in {"IDLE", "FAILED"}:
        raise DumpExecutorError("DR_STATE_NOT_SAFE_FOR_DUMP_FAILOVER")

    operation_root = receipt_root or Path(env.get("DUMP_FAILOVER_EXECUTOR_STATE_DIR", str(DEFAULT_RECEIPT_ROOT)))
    operation_dir = _secure_operation_dir(operation_root, request_id, owner_uid=owner_uid)
    receipt_path = operation_dir / "executor.json"
    log_path = operation_dir / f"{request_id}.log"
    receipt = {
        "status": "RUNNING",
        "phase": "INITIALIZED",
        "request_id": request_id,
        "backup_id": backup_id,
        "sha256": checksum,
        "isolated_instance_id": target["instance_id"],
        "isolated_private_ip": target["private_ip"],
        "data_volume_id": target["data_volume_id"],
        "stage_volume_id": target["stage_volume_id"],
        "service_security_group_id": target["service_security_group_id"],
        "approval": {"execution_id": approval["execution_id"], "required": 2, "count": 2},
        "dr_state_observed": state_observed,
        "dr_active_recorded": False,
        "dns_mutation_started": False,
        "dml_grant_attempted": False,
        "automatic_dns_rollback_allowed": False,
        "rollback_to_prior_database_allowed": False,
        "completed_stages": [],
        "execution_log_path": str(log_path),
        "started_at_utc": now.astimezone(timezone.utc).isoformat(),
    }
    _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
    _append_safe_log(log_path, "EXECUTOR_STARTED", owner_uid=owner_uid)
    print(f"DUMP_FAILOVER_EXECUTOR request_id={request_id} phase=INITIALIZED result=STARTED", flush=True)
    child_env = _safe_child_environment(env)
    child_env["DR_WORKFLOW_LOCK_FILE"] = env.get("DR_WORKFLOW_LOCK_FILE", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "workflow.lock"))
    child_env["DR_FAILOVER_LOCK_FILE"] = env.get("DR_FAILOVER_LOCK_FILE", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "failover.lock"))
    child_env["DR_STATE_HELPER"] = str(state_helper)
    child_env["DUMP_FAILOVER_EXECUTOR_STATE_DIR"] = str(operation_root)
    child_env["DUMP_DB_PUBLIC_READINESS_STATE_DIR"] = env.get("DUMP_DB_PUBLIC_READINESS_STATE_DIR", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "dump-public-readiness"))
    child_env["DUMP_DB_DNS_TRANSACTION_STATE_DIR"] = env.get("DUMP_DB_DNS_TRANSACTION_STATE_DIR", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "dump-dns-transactions"))
    child_env["DUMP_DB_SERVICE_OPEN_STATE_DIR"] = env.get("DUMP_DB_SERVICE_OPEN_STATE_DIR", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "dump-service-open"))
    stages = _build_stages(request_id=request_id, backup=backup, checksum=checksum, target=target, env=child_env)
    if stage_runner is None:
        stage_runner = lambda command, stage, checkpoint: _run_stage_process(
            command, environment=child_env, checkpoint=checkpoint,
        )

    def checkpoint() -> None:
        try:
            lock_validator(child_env)
        except Exception as exc:
            raise ExecutionInterrupted("SHARED_DR_EXECUTION_LOCK_LOST") from exc
        current_approval = _validate_approval(
            request_id=request_id, backup_path=backup, expected_sha256=checksum,
            environment=env, now=clock(), approval_validator=approval_validator,
        )
        if not _same_approval(current_approval, approval):
            raise ExecutionInterrupted("CHATOPS_APPROVAL_CHANGED_DURING_DUMP_EXECUTION")
        elapsed = monotonic() - started_monotonic
        if elapsed >= max_runtime or elapsed >= chatops_timeout:
            raise ExecutionInterrupted("DUMP_FAILOVER_EXECUTION_BUDGET_EXHAUSTED")
        verify_finops_runway(
            now=clock(), max_runtime_seconds=max_runtime,
            shutdown_margin_seconds=shutdown_margin, elapsed_seconds=elapsed,
        )

    previous_handlers = {}
    if threading.current_thread() is threading.main_thread():
        def interrupt(signum, _frame):
            raise ExecutionInterrupted("EXECUTOR_SIGNAL_TERMINATED")

        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, interrupt)

    try:
        with lock_acquirer(env):
            # The shared lock acquisition is the first exclusive operation.
            checkpoint()
            for stage, command in stages:
                checkpoint()
                receipt["phase"] = stage.upper().replace("-", "_")
                receipt["phase_started_at_utc"] = clock().astimezone(timezone.utc).isoformat()
                if stage == "dns-transaction":
                    receipt["dns_mutation_started"] = True
                if stage == "service-open":
                    # Service-open writes its durable irreversible boundary
                    # before DML, so interruption from here is conservative.
                    receipt["dml_grant_attempted"] = "UNKNOWN_OR_ATTEMPTED"
                _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
                _append_safe_log(log_path, f"{stage.upper().replace('-', '_')}:STARTED", owner_uid=owner_uid)
                print(f"DUMP_FAILOVER_EXECUTOR request_id={request_id} phase={stage} result=STARTED", flush=True)
                try:
                    exit_code = int(stage_runner(command, stage, checkpoint))
                except BaseException as exc:
                    reason = str(exc) if isinstance(exc, DumpExecutorError) and re.fullmatch(r"[A-Z0-9_]{1,96}", str(exc)) else "DUMP_STAGE_INTERRUPTED_OR_RESULT_UNKNOWN"
                    if stage == "dns-transaction":
                        failure_status = _classify_dns_failure(env, request_id, owner_uid=owner_uid)
                    elif stage == "service-open":
                        failure_status = _classify_service_open_failure(env, request_id, owner_uid=owner_uid)
                    else:
                        failure_status = _classify_stage_failure(stage, receipt)
                    return _safe_failure_state(
                        status=failure_status, phase=stage, reason=reason,
                        request_id=request_id, operation_dir=operation_dir,
                        receipt_path=receipt_path, receipt=receipt,
                        state_helper=state_helper, state_environment=env,
                        runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                        state_observed=state_observed, owner_uid=owner_uid,
                    )
                if exit_code != 0:
                    if stage == "dns-transaction":
                        failure_status = _classify_dns_failure(env, request_id, owner_uid=owner_uid)
                    elif stage == "service-open":
                        failure_status = _classify_service_open_failure(env, request_id, owner_uid=owner_uid)
                    else:
                        failure_status = _classify_stage_failure(stage, receipt)
                    return _safe_failure_state(
                        status=failure_status, phase=stage,
                        reason=f"STAGE_{stage.upper().replace('-', '_')}_EXIT_{exit_code}",
                        request_id=request_id, operation_dir=operation_dir,
                        receipt_path=receipt_path, receipt=receipt,
                        state_helper=state_helper, state_environment=env,
                        runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                        state_observed=state_observed, owner_uid=owner_uid,
                    )
                checkpoint()

                if stage == "dns-transaction":
                    dns_receipt = _read_private_json(
                        _receipt_stage_path(child_env, request_id, "transaction.json"),
                        owner_uid=owner_uid,
                    )
                    if (
                        dns_receipt.get("status") != dns_transaction.SUCCESS_STATUS
                        or dns_receipt.get("request_id") != request_id
                        or dns_receipt.get("cutover_id") != request_id
                        or dns_receipt.get("backup_id") != backup_id
                        or str(dns_receipt.get("sha256", "")).lower() != checksum
                        or dns_receipt.get("dns_records_switched") is not True
                        or dns_receipt.get("maintenance_mode") is not True
                        or dns_receipt.get("application_dml_allowed") is not False
                        or dns_receipt.get("dr_active_recorded") is not False
                    ):
                        return _safe_failure_state(
                            status="PARTIAL_FAILURE", phase=stage,
                            reason="DNS_TRANSACTION_SUCCESS_RECEIPT_MISMATCH",
                            request_id=request_id, operation_dir=operation_dir,
                            receipt_path=receipt_path, receipt=receipt,
                            state_helper=state_helper, state_environment=env,
                            runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                            state_observed=state_observed, owner_uid=owner_uid,
                        )

                if stage == "service-open":
                    service_receipt = _read_private_json(
                        Path(child_env["DUMP_DB_SERVICE_OPEN_STATE_DIR"]) / request_id / "service-open.json",
                        owner_uid=owner_uid,
                    )
                    if service_receipt.get("status") == service_open.PRE_DML_ROLLBACK_STATUS:
                        return _safe_failure_state(
                            status="FAILED", phase=stage,
                            reason="SERVICE_OPEN_PRE_DML_ROLLBACK_VERIFIED",
                            request_id=request_id, operation_dir=operation_dir,
                            receipt_path=receipt_path, receipt=receipt,
                            state_helper=state_helper, state_environment=env,
                            runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                            state_observed=state_observed, owner_uid=owner_uid,
                        )
                    if service_receipt.get("status") != service_open.SUCCESS_STATUS:
                        return _safe_failure_state(
                            status="PARTIAL_FAILURE", phase=stage,
                            reason="SERVICE_OPEN_DML_OR_RESULT_UNKNOWN",
                            request_id=request_id, operation_dir=operation_dir,
                            receipt_path=receipt_path, receipt=receipt,
                            state_helper=state_helper, state_environment=env,
                            runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                            state_observed=state_observed, owner_uid=owner_uid,
                        )
                    _verify_success_receipt(
                        Path(child_env["DUMP_DB_SERVICE_OPEN_STATE_DIR"]) / request_id / "service-open.json",
                        request_id=request_id, backup_id=backup_id, checksum=checksum,
                        target=target, owner_uid=owner_uid,
                        expected_execution_id=approval["execution_id"],
                    )
                    receipt["dml_grant_attempted"] = True

                receipt["completed_stages"].append(stage)
                receipt["phase_completed_at_utc"] = clock().astimezone(timezone.utc).isoformat()
                _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
                _append_safe_log(log_path, f"{stage.upper().replace('-', '_')}:COMPLETE", owner_uid=owner_uid)
                print(
                    f"DUMP_FAILOVER_EXECUTOR request_id={request_id} "
                    f"phase={stage} result=COMPLETE",
                    flush=True,
                )

            # The controller does a fresh read-only check after service-open's
            # success receipt; it does not alter DNS, DB, apps, or DR state.
            checkpoint()
            final_command = [
                "bash", str(REPO_ROOT / "operations/db/dump_db_service_open.sh"),
                *_terraform_stage_arguments(target, backup, checksum),
                "--request-id", request_id, "--promotion-id", request_id,
                "--cutover-id", request_id, "--service-security-group-id",
                target["service_security_group_id"], "--confirm-service-open",
                "--verify-final-service-open",
            ]
            receipt["phase"] = "FINAL_SERVICE_VERIFY"
            _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
            _append_safe_log(log_path, "FINAL_SERVICE_VERIFY:STARTED", owner_uid=owner_uid)
            final_code = int(stage_runner(final_command, "final-service-verify", checkpoint))
            if final_code != 0:
                return _safe_failure_state(
                    status="PARTIAL_FAILURE", phase="final-service-verify",
                    reason="FINAL_SERVICE_HEALTH_OR_IDENTITY_RECHECK_FAILED",
                    request_id=request_id, operation_dir=operation_dir,
                    receipt_path=receipt_path, receipt=receipt,
                    state_helper=state_helper, state_environment=env,
                    runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                    state_observed=state_observed, owner_uid=owner_uid,
                )
            final_verification_path = (
                Path(child_env["DUMP_DB_SERVICE_OPEN_STATE_DIR"])
                / request_id / "final-service-verification.json"
            )
            final_verification = _read_private_json(final_verification_path, owner_uid=owner_uid)
            opened_receipt = _verify_success_receipt(
                Path(child_env["DUMP_DB_SERVICE_OPEN_STATE_DIR"]) / request_id / "service-open.json",
                request_id=request_id, backup_id=backup_id, checksum=checksum,
                target=target, owner_uid=owner_uid,
                expected_execution_id=approval["execution_id"],
            )
            approval_receipt = final_verification.get("approval")
            if (
                final_verification.get("status") != "DUMP_FINAL_SERVICE_VERIFIED_NOT_DR_ACTIVE"
                or final_verification.get("request_id") != request_id
                or final_verification.get("backup_id") != backup_id
                or str(final_verification.get("sha256", "")).lower() != checksum
                or final_verification.get("isolated_instance_id") != target["instance_id"]
                or final_verification.get("private_ip") != target["private_ip"]
                or final_verification.get("data_volume_id") != target["data_volume_id"]
                or final_verification.get("stage_volume_id") != target["stage_volume_id"]
                or final_verification.get("service_security_group_id") != target["service_security_group_id"]
                or final_verification.get("db_server_uuid") != opened_receipt.get("db_server_uuid")
                or not isinstance(approval_receipt, dict)
                or approval_receipt.get("execution_id") != approval.get("execution_id")
                or approval_receipt.get("approver_ids") != approval.get("approver_ids")
                or final_verification.get("web_public_health") != 200
                or final_verification.get("emr_public_health") != 200
                or final_verification.get("cloudflare_health_204") != {"web": True, "emr": True}
                or final_verification.get("application_writes_allowed") is not True
                or final_verification.get("maintenance_mode") is not False
                or final_verification.get("dr_state_changed") is not False
                or final_verification.get("dr_active_recorded") is not False
            ):
                return _safe_failure_state(
                    status="PARTIAL_FAILURE", phase="final-service-verify",
                    reason="FINAL_SERVICE_VERIFICATION_RECEIPT_MISMATCH",
                    request_id=request_id, operation_dir=operation_dir,
                    receipt_path=receipt_path, receipt=receipt,
                    state_helper=state_helper, state_environment=env,
                    runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                    state_observed=state_observed, owner_uid=owner_uid,
                )
            receipt["completed_stages"].append("final-service-verify")
            receipt["final_service_verification_receipt"] = str(final_verification_path)
            _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
            _append_safe_log(log_path, "FINAL_SERVICE_VERIFY:COMPLETE", owner_uid=owner_uid)
            checkpoint()
            state_now = state_reader()
            if state_now != state_observed or state_now not in {"IDLE", "FAILED"}:
                return _safe_failure_state(
                    status="PARTIAL_FAILURE", phase="dr-active-commit",
                    reason="DR_STATE_CHANGED_BEFORE_FINAL_COMMIT",
                    request_id=request_id, operation_dir=operation_dir,
                    receipt_path=receipt_path, receipt=receipt,
                    state_helper=state_helper, state_environment=env,
                    runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
                    state_observed=state_observed, owner_uid=owner_uid,
                )
            state_writer("DR_ACTIVE")
            if state_reader() != "DR_ACTIVE":
                raise DumpExecutorError("DR_ACTIVE_READBACK_FAILED")
            receipt.update({
                "status": "SUCCESS",
                "phase": "DR_ACTIVE_VERIFIED",
                "dr_active_recorded": True,
                "dr_state_changed": True,
                "automatic_dns_rollback_allowed": False,
                "rollback_to_prior_database_allowed": False,
                "operator_intervention_required": False,
                "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_json_private(receipt_path, receipt, owner_uid=owner_uid)
            try:
                _append_safe_log(log_path, "DR_ACTIVE:VERIFIED", owner_uid=owner_uid)
                _append_safe_log(log_path, "EXECUTOR_STATUS:SUCCESS", owner_uid=owner_uid)
                _append_safe_log(log_path, "OPERATOR_INTERVENTION_REQUIRED:FALSE", owner_uid=owner_uid)
            except (OSError, DumpExecutorError):
                # ChatOps verifies the private receipt and exit code independently.
                pass
            print(f"DUMP_FAILOVER_EXECUTOR request_id={request_id} phase=DR_ACTIVE result=SUCCESS", flush=True)
            return receipt
    except Exception as exc:
        reason = str(exc) if isinstance(exc, DumpExecutorError) and re.fullmatch(r"[A-Z0-9_]{1,96}", str(exc)) else "DUMP_FAILOVER_EXECUTION_FAILED"
        if receipt.get("status") != "RUNNING":
            raise
        status = "PARTIAL_FAILURE" if receipt.get("completed_stages") or receipt.get("dns_mutation_started") or receipt.get("dml_grant_attempted") else "FAILED"
        return _safe_failure_state(
            status=status, phase=str(receipt.get("phase", "UNKNOWN")), reason=reason,
            request_id=request_id, operation_dir=operation_dir,
            receipt_path=receipt_path, receipt=receipt,
            state_helper=state_helper, state_environment=env,
            runner=subprocess.run, state_reader=state_reader, state_writer=state_writer,
            state_observed=state_observed, owner_uid=owner_uid,
        )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_dump_failover(args)
    except DumpExecutorError as exc:
        reason = str(exc) if re.fullmatch(r"[A-Z0-9_]{1,96}", str(exc)) else "DUMP_EXECUTOR_BLOCKED"
        print(f"DUMP_FAILOVER_EXECUTOR=BLOCKED request_id={args.request_id} reason={reason}", file=sys.stderr, flush=True)
        return 1
    status = result.get("status")
    print(f"DUMP_FAILOVER_EXECUTOR request_id={args.request_id} result={status}", flush=True)
    return 0 if status == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
