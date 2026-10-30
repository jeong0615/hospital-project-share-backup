import fcntl
import hashlib
import hmac
import json
import logging
import math
import os
import queue
import re
import sqlite3
import signal
import subprocess
import stat
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import requests
from flask import Flask, jsonify, request

from chatops_audit import ChatOpsAudit, request_audit_payload
from rto_timeline import (
    calculate_run as calculate_rto_run,
    default_path as default_rto_timeline_path,
    record_stage as record_rto_stage,
)
from emergency_dr import (
    EMERGENCY_TTL_SECONDS,
    REQUEST_TYPE_DUMP_RESTORE,
    REQUEST_TYPE_EMERGENCY_FAILBACK,
    REQUEST_TYPE_EMERGENCY_FAILOVER,
    REQUEST_TYPE_SECURITY,
    EmergencyConsoleStore,
    dump_confirm_view,
    dump_request_result_view,
    dump_select_view,
    dump_verification_view,
    emergency_console_blocks,
    emergency_reason_view,
    list_dump_backups,
    reason_options,
    resolve_dump_backup,
    validate_reason,
)


ACTIVE_STATUSES = ("PENDING", "PARTIALLY_APPROVED", "EXECUTING")
APPROVAL_STATUSES = ("PENDING", "PARTIALLY_APPROVED")
TERMINAL_STATUSES = (
    "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE", "FAILED",
    "PARTIAL_FAILURE", "CANCELLED", "EXPIRED",
)
REQUIRED_APPROVALS = 2
CHATOPS_TEST_FAILOVER_REQUEST_TYPE = "CHATOPS_TEST_FAILOVER"
ZABBIX_TEST_FAILOVER_REQUEST_TYPE = "ZABBIX_TEST_FAILOVER"
SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE = "SYNTHETIC_MYSQL_DEMO_FAILOVER"
SYNTHETIC_MYSQL_DEMO_REQUEST_ORIGIN = "CHATOPS_SYNTHETIC_MYSQL_DEMO"
SYNTHETIC_MYSQL_DEMO_REQUEST_SOURCE = "chatops_synthetic_mysql_demo"
SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD = "synthetic_mysql_demo_authorization"
DEMO_DUMP_OVERWRITE_AUTH_FIELD = "existing_dr_overwrite_authorization"
DEMO_DUMP_OVERWRITE_AUTH_VERSION = 1
DEMO_DUMP_OVERWRITE_SCOPE = "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB"
FAILOVER_RECOVERY_PLAN_FIELD = "failover_recovery_plan"
FAILOVER_RECOVERY_PLAN_VERSION = 1
# Conditional Dump overwrite keeps its measured-RPO requirement. The general
# Failover policy below treats missing evidence as advisory, then requires an
# independently verified existing DR dataset before DB promotion.
FAILOVER_RPO_FAILURE_POLICY = "BLOCK_IF_UNMEASURED_OR_OVER_900_SECONDS"
FAILOVER_RPO_EXECUTION_POLICY = "WARN_AND_REQUIRE_TWO_ADMIN_RISK_ACCEPTANCE"
FAILOVER_RECOVERY_REQUEST_TYPES = {"NORMAL_FAILOVER", REQUEST_TYPE_EMERGENCY_FAILOVER}
DEMO_DUMP_OVERWRITE_TARGET = {
    "instance_id": "AWS_RESOURCE_ID_REDACTED",
    "private_ip": "IP_REDACTED",
    "port": 3306,
    "database": "hospital_db",
}
MAX_SINGLE_APPROVAL_TEST_WINDOW_SECONDS = 4 * 60 * 60
INITIAL_APPROVAL_TTL_SECONDS = 20 * 60
FIRST_APPROVAL_TTL_SECONDS = 60 * 60
DEFAULT_EXECUTION_TIMEOUT_SECONDS = 60 * 60
DEFAULT_EXECUTION_HEARTBEAT_SECONDS = 15
DEFAULT_EXECUTION_LEASE_SECONDS = 60
DEFAULT_EXECUTION_LOG_TAIL_LINES = 80
DEFAULT_EXECUTION_LOG_MAX_CHARS = 6000
WORKFLOW_SSH_ENV_KEYS = (
    "SSH_KEY",
    "DR_SSH_PRIVATE_KEY",
    "DR_SSH_KEY",
    "TF_VAR_ssh_public_key_path",
)
DUMP_WORKFLOW_CONFIG_KEYS = (
    "DR_TERRAFORM_DIR",
    "DR_ANSIBLE_DIR",
    "DR_REPO_ROOT",
    "DR_STATE_DIR",
    "DR_STATE_FILE",
    "DR_WORKFLOW_LOCK_FILE",
    "DR_FAILOVER_LOCK_FILE",
    "DR_SSH_CONFIG_FILE",
    "DR_SSH_KNOWN_HOSTS_FILE",
    "DR_DNS_ORIGIN_SNAPSHOT_DIR",
    "DUMP_FAILOVER_EXECUTOR_STATE_DIR",
    "DR_CLOUDFLARE_AUTH_SCRIPT",
    "INVENTORY",
    "AWS_REGION",
    "DUMP_FAILOVER_MAX_RUNTIME_SECONDS",
    "DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS",
    "DUMP_DB_SERVICE_CUTOVER_ENABLED",
    "DUMP_DB_SERVICE_PROMOTION_ENABLED",
    "DUMP_DB_DNS_PREFLIGHT_ENABLED",
    "DUMP_DB_READONLY_HEALTH_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_ENABLED",
    "DUMP_DB_DNS_TRANSACTION_ENABLED",
    "DUMP_DB_SERVICE_OPEN_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_TTL_SECONDS",
    "DUMP_DB_PUBLIC_READINESS_STATE_DIR",
    "DUMP_DB_DNS_TRANSACTION_STATE_DIR",
    "DUMP_DB_SERVICE_OPEN_STATE_DIR",
    "DUMP_DB_SERVICE_OPEN_LOCK_FILE",
    "DUMP_DB_DNS_HEALTH_ATTEMPTS",
    "DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS",
    "DEMO_DUMP_RESTORE_STATE_DIR",
    "DR_DOMAIN",
    "EMR_DOMAIN",
    "DR_WEB_EIP_EXPECTED",
    "ONPREM_TUNNEL_HOST",
    "ONPREM_EMR_DNS_IP_EXPECTED",
    "CF_ZONE_ID",
    "CF_RECORD_ID_EXPECTED",
    "CF_EMR_RECORD_ID_EXPECTED",
    "TF_VAR_cloudflare_ipv4_cidrs",
    "TF_VAR_management_ipv4_cidrs",
    "TF_VAR_zabbix_agent_source_ipv4_cidrs",
    "TF_VAR_aws_dr_wg_peer_ingress_ipv4_cidrs",
    "TF_VAR_aws_dr_wg_enabled",
)
DUMP_FAILOVER_EXECUTOR_RECEIPT_ROOT = "/var/lib/hospital-dr/dump-failover-executions"
DUMP_FAILOVER_SUCCESS_STAGES = (
    "target-preflight",
    "restore",
    "prepare-service",
    "service-preflight",
    "service-cutover",
    "service-promote",
    "dns-preflight",
    "readonly-health",
    "public-readiness",
    "dns-transaction",
    "service-open",
    "final-service-verify",
)
DUMP_STAGE_OPTIN_KEYS = {
    "DUMP_DB_SERVICE_CUTOVER_ENABLED",
    "DUMP_DB_SERVICE_PROMOTION_ENABLED",
    "DUMP_DB_DNS_PREFLIGHT_ENABLED",
    "DUMP_DB_READONLY_HEALTH_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_ENABLED",
    "DUMP_DB_DNS_TRANSACTION_ENABLED",
    "DUMP_DB_SERVICE_OPEN_ENABLED",
}
DUMP_CHILD_BASE_ENV_KEYS = {
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
    "SSH_AUTH_SOCK", "SSH_KEY", "DR_SSH_PRIVATE_KEY", "DR_SSH_KEY",
    "TF_VAR_ssh_public_key_path", "ANSIBLE_CONFIG", "ANSIBLE_HOST_KEY_CHECKING",
    "ANSIBLE_DEPRECATION_WARNINGS", "ANSIBLE_LOCAL_TEMP", "ANSIBLE_REMOTE_TEMP",
    "ANSIBLE_SSH_CONTROL_PATH_DIR", "PYTHONWARNINGS", "DR_FAILOVER_REQUEST_ID",
}
SLACK_SIGNATURE_MAX_AGE_SECONDS = 300
SLACK_REPLAY_CACHE_SIZE = 4096
DEFAULT_TEST_MODE_MAX_EVENT_AGE_SECONDS = 3600
DEFAULT_DR_MAX_EVENT_AGE_SECONDS = 86400
DEFAULT_ZABBIX_ACTION_SIGNATURE_MAX_AGE_SECONDS = 60
ZABBIX_PRODUCTION_ACTION_NAME = "Cloud_Slack_DR_Trigger"
ZABBIX_TEST_ACTION_NAME = "Cloud_Slack_DR_Broad_Test_Mode"
ZABBIX_PRODUCTION_EVENT_TAGS = {
    "DR_Escalate": "1",
    "DR_Policy": "production",
    "DR_Scope": "Hospital-Core",
    "DR_Type": "Failover",
}


def utc_timestamp():
    return time.time()


def format_timestamp(value):
    if value is None:
        return "-"
    return datetime.fromtimestamp(value, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def format_kst_timestamp(value):
    if value is None:
        return "-"
    try:
        return datetime.fromtimestamp(float(value), ZoneInfo("Asia/Seoul")).strftime(
            "%Y-%m-%d %H:%M:%S KST"
        )
    except (OverflowError, OSError, TypeError, ValueError):
        return "-"


def as_bool(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_single_approval_expiry(value):
    """Parse a timezone-qualified ISO-8601 test-mode deadline."""
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def approval_policy_from_config(config, action, request_type=None, now=None):
    """Return the immutable quorum; single approval is demo-only."""
    now = utc_timestamp() if now is None else float(now)
    if action not in {"failover", "failback"}:
        return REQUIRED_APPROVALS, None
    if action != "failover" or request_type != SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
        return REQUIRED_APPROVALS, None
    required = config.get("APPROVAL_REQUIRED", REQUIRED_APPROVALS)
    deadline = config.get("APPROVAL_TEST_EXPIRES_AT_EPOCH")
    if required == 1 and deadline is not None and now < float(deadline):
        return 1, float(deadline)
    return REQUIRED_APPROVALS, None


def request_type_for_action(action):
    return "NORMAL_FAILOVER" if action == "failover" else "NORMAL_FAILBACK"


def parse_event_age(value):
    """Parse Zabbix's numeric or human-readable EVENT.AGE value."""
    raw = str(value or "").strip()
    if not raw or raw.startswith("{"):
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    matches = re.findall(r"(\d+(?:\.\d+)?)\s*([smhdw])", raw.lower())
    if not matches or "".join(f"{number}{unit}" for number, unit in matches) != re.sub(r"\s+", "", raw.lower()):
        return None
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return sum(float(number) * multipliers[unit] for number, unit in matches)


def _zabbix_production_event_contract(payload):
    """Validate the signed Action 3 event fields and its actual event tags."""
    if not isinstance(payload, dict):
        return False
    if (
        payload.get("source") != "zabbix_production_action"
        or payload.get("action_name") != ZABBIX_PRODUCTION_ACTION_NAME
        or payload.get("action") != "failover"
        or payload.get("test_mode") is not False
        or str(payload.get("event_source") or "") != "0"
        or str(payload.get("status") or "").strip().upper() != "PROBLEM"
        or str(payload.get("host") or "").strip().casefold() != "zabbix server"
        or not re.fullmatch(r"[1-9][0-9]*", str(payload.get("event_id") or ""))
        or not re.fullmatch(r"[1-9][0-9]*", str(payload.get("trigger_id") or ""))
    ):
        return False
    try:
        tags = json.loads(payload.get("event_tags_json") or "")
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(tags, list):
        return False
    observed = {}
    for tag in tags:
        if not isinstance(tag, dict) or "tag" not in tag or "value" not in tag:
            return False
        name, value = str(tag["tag"]), str(tag["value"])
        if name in ZABBIX_PRODUCTION_EVENT_TAGS:
            if name in observed and observed[name] != value:
                return False
            observed[name] = value
    return all(observed.get(name) == value for name, value in ZABBIX_PRODUCTION_EVENT_TAGS.items())


def _zabbix_test_action_event_contract(payload):
    """Validate the separate signed Zabbix test action; it can never authorize a runner."""
    if not isinstance(payload, dict):
        return False
    event_id = str(payload.get("event_id") or "")
    if not (
        payload.get("source") == "zabbix_test_action"
        and payload.get("action_name") == ZABBIX_TEST_ACTION_NAME
        and payload.get("action") == "failover"
        and payload.get("test_mode") is True
        and str(payload.get("event_source") or "") == "0"
        and str(payload.get("status") or "").strip().upper() == "PROBLEM"
        and str(payload.get("incident_id") or "") == event_id
        and re.fullmatch(r"[1-9][0-9]*", event_id)
        and re.fullmatch(r"[1-9][0-9]*", str(payload.get("trigger_id") or ""))
        and str(payload.get("host") or "").strip()
        and str(payload.get("event_tags_json") or "")
    ):
        return False
    try:
        tags = json.loads(payload["event_tags_json"])
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(tags, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("tag"), str)
        and isinstance(item.get("value"), str)
        for item in tags
    )


def _verify_zabbix_production_action_signature(app, body, timestamp, signature):
    """Authenticate only the dedicated local Zabbix production Action sender."""
    secret = str(app.config.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY") or "")
    if len(secret.encode("utf-8")) < 32:
        return False
    raw_timestamp = str(timestamp or "")
    if not re.fullmatch(r"[0-9]{1,12}", raw_timestamp):
        return False
    try:
        skew = abs(time.time() - int(raw_timestamp))
        max_age = int(app.config.get(
            "ZABBIX_PRODUCTION_ACTION_SIGNATURE_MAX_AGE_SECONDS",
            DEFAULT_ZABBIX_ACTION_SIGNATURE_MAX_AGE_SECONDS,
        ))
    except (TypeError, ValueError, OverflowError):
        return False
    if max_age < 1 or skew > max_age:
        return False
    supplied = str(signature or "")
    if not re.fullmatch(r"v1=[0-9a-f]{64}", supplied):
        return False
    signed = raw_timestamp.encode("ascii") + b"." + body
    expected = "v1=" + hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def read_persistent_dr_state(path):
    """Read the fail-closed DR lifecycle state without mutating it."""
    try:
        with open(path, "r", encoding="utf-8") as stream:
            state = stream.readline().strip()
    except (OSError, UnicodeError):
        return ""
    valid_states = {
        "IDLE",
        "FAILOVER_EXECUTING",
        "DR_ACTIVE",
        "FAILBACK_EXECUTING",
        "FAILED",
        "PARTIAL_FAILURE",
    }
    return state if state in valid_states else ""


class FailoverRequestBlocked(RuntimeError):
    """Raised when the persistent lifecycle says DR is already active."""

    code = "DR_ALREADY_ACTIVE"

    def __init__(self):
        super().__init__("Failover request suppressed because DR is already active.")


def _rto_run_id(incident):
    """Return the stable correlation ID used by the RTO timeline."""
    explicit = str(incident.get("rto_run_id") or "").strip()
    if explicit:
        return explicit
    incident_id = str(incident.get("incident_id") or "").strip()
    if incident_id and incident.get("source") == "zabbix":
        return f"zabbix-{incident_id}"
    if incident_id and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", incident_id):
        return f"chatops-{incident_id}"
    return ""


def _bind_rto_child_env(child_env, incident, request_id):
    """Remove inherited correlation and bind a failover child to this request."""
    for key in ("DR_RTO_RUN_ID", "DR_RTO_EVENT_ID", "DR_RTO_APPROVAL_ID"):
        child_env.pop(key, None)
    run_id = _rto_run_id(incident)
    incident_id = str(incident.get("incident_id") or "").strip()
    safe_id = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
    if not (
        re.fullmatch(safe_id, run_id)
        and re.fullmatch(safe_id, incident_id)
        and re.fullmatch(safe_id, str(request_id or ""))
    ):
        return False
    child_env["DR_RTO_RUN_ID"] = run_id
    child_env["DR_RTO_EVENT_ID"] = incident_id
    child_env["DR_RTO_APPROVAL_ID"] = str(request_id)
    return True


def _bind_failover_request_id(child_env, request_id):
    """Bind the approved request independently of optional RTO metadata."""
    child_env.pop("DR_FAILOVER_REQUEST_ID", None)
    value = str(request_id or "")
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    ):
        return False
    child_env["DR_FAILOVER_REQUEST_ID"] = value
    return True


def _record_rto(incident, stage, *, approval_id=None):
    """Best-effort RTO bookkeeping; never blocks an alert or approval."""
    run_id = _rto_run_id(incident)
    if not run_id:
        return
    if stage == "incident_at" and not incident.get("incident_at"):
        # A missing Zabbix event timestamp is not the incident start time.
        # Leave the stage absent so the run remains NOT_MEASURED.
        print(
            "[RTO] timeline record skipped stage=incident_at "
            "error=source_timestamp_unavailable",
            flush=True,
        )
        return
    try:
        record_rto_stage(
            run_id,
            stage,
            timestamp=incident.get("incident_at") if stage == "incident_at" else None,
            event_id=incident.get("incident_id"),
            approval_id=approval_id,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[RTO] timeline record skipped stage={stage} error={type(exc).__name__}", flush=True)


def load_env_file(path):
    values = {}
    if not path or not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key:
                values[key] = value
    return values


def build_workflow_child_env(base_env, secret_file, action):
    """Build a child environment from the canonical secret file selectively.

    The workflow receives the secret-file path and SSH key *paths*, not the
    complete secret file contents. The Failback runner reads the DR DB
    credential and On-Prem SSH configuration from that file; On-Prem DB
    administration uses the restricted local-socket wrapper.
    """
    child_env = dict(base_env)
    child_env["DR_SECRET_FILE"] = str(secret_file)
    if action == "failback":
        # A persistent environment value must never act as a DB overwrite grant.
        child_env.pop("DB_FAILBACK_CONFIRM", None)
        child_env.pop("DB_FAILBACK_CONFIRM_REQUEST_ID", None)
        child_env.pop("DR_FAILBACK_REQUEST_ID", None)
    if not secret_file or not os.path.isfile(secret_file) or not os.access(secret_file, os.R_OK):
        return child_env, "DR_SECRET_FILE is missing or unreadable"

    try:
        file_values = load_env_file(secret_file)
    except (OSError, UnicodeError):
        return child_env, "DR_SECRET_FILE could not be read"

    # Do not let stale systemd/process values silently override the configured
    # secret-file source of truth for SSH identity and Terraform's public key.
    for key in WORKFLOW_SSH_ENV_KEYS:
        child_env.pop(key, None)
    ssh_key = next(
        (file_values.get(key, "").strip() for key in WORKFLOW_SSH_ENV_KEYS[:3]
         if file_values.get(key, "").strip()),
        "",
    )
    if not ssh_key:
        return child_env, "SSH_KEY is missing from DR_SECRET_FILE"
    public_key = file_values.get("TF_VAR_ssh_public_key_path", "").strip() or f"{ssh_key}.pub"
    if not os.path.isfile(ssh_key) or not os.access(ssh_key, os.R_OK):
        return child_env, "SSH private key is missing or unreadable"
    if not os.path.isfile(public_key) or not os.access(public_key, os.R_OK):
        return child_env, "SSH public key is missing or unreadable"

    child_env.update(
        {
            "SSH_KEY": ssh_key,
            "DR_SSH_PRIVATE_KEY": ssh_key,
            "DR_SSH_KEY": ssh_key,
            "TF_VAR_ssh_public_key_path": public_key,
        }
    )
    if file_values.get("AWS_REGION", "").strip():
        child_env["AWS_REGION"] = file_values["AWS_REGION"].strip()

    if action == "failback":
        required = (
            "MYSQL_ROOT_PASS",
            "ONPREM_DB_HOST",
        )
        missing = [name for name in required if not file_values.get(name, "").strip()]
        if missing:
            return child_env, "Failback configuration is missing: " + ", ".join(missing)

    return child_env, None


def configure_dump_workflow_child_env(app, child_env):
    """Pass only non-secret Dump executor configuration to its dedicated runner.

    The DR secret file remains the source for the stage opt-ins and runtime
    paths. Credentials are deliberately not copied; each reviewed stage wrapper
    loads only the credential it needs for that invocation.
    """
    secret_file = app.config.get("DR_SECRET_FILE", "")
    if not secret_file or not os.path.isfile(secret_file) or not os.access(secret_file, os.R_OK):
        return "DR_SECRET_FILE is missing or unreadable"
    try:
        file_values = load_env_file(secret_file)
    except (OSError, UnicodeError):
        return "DR_SECRET_FILE could not be read"

    # Give the Dump runner a narrow environment. AWS credentials remain
    # available for the existing read-only AWS checks; service and Slack
    # credentials are reloaded only by their scoped stage wrappers.
    safe_env = {
        key: value for key, value in child_env.items()
        if key in DUMP_CHILD_BASE_ENV_KEYS or key.startswith("AWS_")
    }
    for key in DUMP_WORKFLOW_CONFIG_KEYS:
        configured = str(file_values.get(key, "")).strip()
        inherited = str(child_env.get(key, "")).strip()
        if key in DUMP_STAGE_OPTIN_KEYS:
            # Stage opt-ins are sourced only from the canonical secret file;
            # stale systemd values must never enable an omitted stage.
            safe_env.pop(key, None)
            if configured:
                safe_env[key] = configured
        elif configured:
            safe_env[key] = configured
        elif inherited:
            # Runtime-specific paths may be supplied by the managed unit
            # when the secret file intentionally contains no path override.
            safe_env[key] = inherited
    child_env.clear()
    child_env.update(safe_env)

    child_env.update({
        "DR_SECRET_FILE": str(secret_file),
        "DUMP_RESTORE_EXEC_ENABLED": (
            "true" if app.config.get("DUMP_RESTORE_EXEC_ENABLED") else "false"
        ),
        "CHATOPS_STATE_DB": str(app.config.get("CHATOPS_STATE_DB") or ""),
        "DUMP_BACKUP_DIR": str(app.config.get("DUMP_BACKUP_DIR") or ""),
        "CHATOPS_EXECUTION_TIMEOUT_SECONDS": str(
            app.config.get("CHATOPS_EXECUTION_TIMEOUT_SECONDS", DEFAULT_EXECUTION_TIMEOUT_SECONDS)
        ),
        "SLACK_ADMIN_USER_IDS": ",".join(
            sorted(str(value) for value in app.extensions.get("admin_user_ids", set()))
        ),
    })
    configured_executor = str(app.config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
    if configured_executor:
        child_env["DUMP_RESTORE_EXECUTOR"] = configured_executor
    else:
        child_env.pop("DUMP_RESTORE_EXECUTOR", None)
    return None


def _demo_dump_executor_expected_path(config):
    repo_root = str(config.get("DR_REPO_ROOT") or "").strip()
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    return root / "operations" / "db" / "demo_dump_restore_existing_dr.sh"


def is_demo_dump_executor_configured(config):
    """True only when configured runner is the existing-DR DB-only demo runner."""
    configured = str(config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
    expected = _demo_dump_executor_expected_path(config)
    if not configured or not os.path.isabs(configured):
        return False
    configured_path = Path(configured)
    if configured_path.is_symlink() or expected.is_symlink():
        return False
    try:
        return configured_path.resolve(strict=True) == expected.resolve(strict=True)
    except OSError:
        return False


def _dump_overwrite_authorization_error(state, *, request_id=None, approved=False, now=None):
    """Validate the request-bound overwrite grant stored with the SQLite row."""
    now = utc_timestamp() if now is None else float(now)
    request_id = str(request_id or state.get("request_id") or "")
    incident = latest_incident(state)
    grant = incident.get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
    origin = str(incident.get("request_origin") or "").strip().upper()
    source_contracts = {
        "GENERAL": ("failover", "dump_restore_console"),
        "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
    }
    contract = source_contracts.get(origin)
    backup_id = str(incident.get("backup_id") or "")
    checksum = str(incident.get("backup_checksum") or "").strip().lower()
    expires_at = state.get("expires_at")
    try:
        expires_at = float(expires_at)
    except (TypeError, ValueError):
        return "existing_dr_overwrite_authorization_expiry_invalid"
    try:
        approval_required = int(state.get("approval_required") or 0)
    except (TypeError, ValueError):
        return "existing_dr_overwrite_authorization_invalid"
    expected_status = "APPROVED_BY_TWO_DISTINCT_ADMINS" if approved else "PENDING_TWO_ADMIN_APPROVAL"
    if (
        state.get("action") != "failover"
        or request_type_from_state(state) != REQUEST_TYPE_DUMP_RESTORE
        or not isinstance(grant, dict)
        or grant.get("version") != DEMO_DUMP_OVERWRITE_AUTH_VERSION
        or grant.get("authorization_id") is None
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            str(grant.get("authorization_id") or ""),
        )
        or grant.get("request_id") != request_id
        or grant.get("status") != expected_status
        or grant.get("scope") != DEMO_DUMP_OVERWRITE_SCOPE
        or grant.get("target") != DEMO_DUMP_OVERWRITE_TARGET
        or grant.get("request_type") != REQUEST_TYPE_DUMP_RESTORE
        or grant.get("approval_required") != REQUIRED_APPROVALS
        or grant.get("request_origin") != origin
        or not contract
        or state.get("slack_client_key") != contract[0]
        or grant.get("slack_client_key") != contract[0]
        or grant.get("request_source") != contract[1]
        or incident.get("source") != contract[1]
        or grant.get("requested_by") != incident.get("requested_by")
        or not isinstance(grant.get("requested_by"), str)
        or not grant.get("requested_by", "").strip()
        or not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id)
        or grant.get("backup_id") != backup_id
        or not re.fullmatch(r"[0-9a-f]{64}", checksum)
        or not hmac.compare_digest(str(grant.get("sha256") or "").lower(), checksum)
        or approval_required != REQUIRED_APPROVALS
        or any(bool(item.get("test_mode")) for item in state.get("incidents") or [])
        or not math.isfinite(expires_at)
        or not expires_at > now
        or grant.get("expires_at") is None
    ):
        return "existing_dr_overwrite_authorization_invalid"
    try:
        grant_expires_at = float(grant.get("expires_at"))
        requested_at = float(grant.get("requested_at"))
    except (TypeError, ValueError):
        return "existing_dr_overwrite_authorization_invalid"
    if (
        not math.isfinite(grant_expires_at)
        or not math.isfinite(requested_at)
        or abs(grant_expires_at - expires_at) > 0.001
        or not 0 < requested_at <= now
    ):
        return "existing_dr_overwrite_authorization_invalid"
    if approved:
        approvers = state.get("approvers")
        try:
            approval_required = int(state.get("approval_required") or 0)
            approval_count = int(grant.get("approval_count") or 0)
            grant_approvers = grant.get("approver_ids")
            approved_at = float(grant.get("approved_at"))
        except (TypeError, ValueError):
            return "existing_dr_overwrite_authorization_approval_invalid"
        if (
            state.get("status") != "EXECUTING"
            or approval_required != REQUIRED_APPROVALS
            or not isinstance(approvers, list)
            or len(approvers) != REQUIRED_APPROVALS
            or len(set(approvers)) != REQUIRED_APPROVALS
            or grant_approvers != approvers
            or approval_count != REQUIRED_APPROVALS
            or grant.get("approval_required") != REQUIRED_APPROVALS
            or grant.get("execution_id") != state.get("execution_id")
            or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                str(grant.get("execution_id") or ""),
            )
            or not math.isfinite(approved_at)
            or not 0 < approved_at <= now
        ):
            return "existing_dr_overwrite_authorization_approval_invalid"
    return None


def _new_dump_overwrite_authorization(
    action, incident, request_id, now, expires_at, client_key, approval_required,
):
    """Create a server-authored grant request; never trust a Slack-supplied scope."""
    origin = str(incident.get("request_origin") or "").strip().upper()
    contracts = {
        "GENERAL": ("failover", "dump_restore_console"),
        "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
    }
    contract = contracts.get(origin)
    backup_id = str(incident.get("backup_id") or "")
    checksum = str(incident.get("backup_checksum") or "").strip().lower()
    requested_by = incident.get("requested_by")
    valid = (
        action == "failover"
        and incident.get("request_type") == REQUEST_TYPE_DUMP_RESTORE
        and incident.get("source") == (contract[1] if contract else None)
        and client_key == (contract[0] if contract else None)
        and isinstance(requested_by, str) and bool(requested_by.strip())
        and int(approval_required) == REQUIRED_APPROVALS
        and not bool(incident.get("test_mode"))
        and re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id)
        and re.fullmatch(r"[0-9a-f]{64}", checksum)
    )
    return {
        "version": DEMO_DUMP_OVERWRITE_AUTH_VERSION,
        "authorization_id": str(uuid.uuid4()),
        "request_id": request_id,
        "status": "PENDING_TWO_ADMIN_APPROVAL" if valid else "BLOCKED_REQUEST_METADATA_INVALID",
        "scope": DEMO_DUMP_OVERWRITE_SCOPE,
        "target": dict(DEMO_DUMP_OVERWRITE_TARGET),
        "backup_id": backup_id,
        "sha256": checksum,
        "request_type": REQUEST_TYPE_DUMP_RESTORE,
        "approval_required": int(approval_required),
        "request_origin": origin,
        "request_source": contract[1] if contract else "",
        "slack_client_key": client_key,
        "requested_by": requested_by,
        "requested_at": now,
        "expires_at": expires_at,
    }


FAILOVER_RPO_TARGET_SECONDS = 900


def _failover_rpo_gate_error(incident):
    """Classify request-bound production RPO evidence without treating absence as PASS.

    Backup/job timestamps and unverified Manifest observations are deliberately
    not accepted as measured RPO. Synthetic/test evidence is never operational
    proof. Missing evidence remains NOT_MEASURED; callers may continue only
    through the existing-DR data verification path. A measured RPO over target
    remains blocking.
    """
    plan = incident.get(FAILOVER_RECOVERY_PLAN_FIELD) if isinstance(incident, dict) else None
    candidate = plan.get("dump") if isinstance(plan, dict) else None
    expected = candidate.get("expected_rpo") if isinstance(candidate, dict) else None
    if not isinstance(candidate, dict) or not isinstance(expected, dict):
        return "failover_rpo_not_measured"

    evidence = candidate.get("data_reference_evidence")
    source = expected.get("evidence_source")
    cutoff_raw = expected.get("data_reference_at")
    incident_raw = expected.get("incident_at")
    source_key = re.sub(r"[^A-Z0-9]+", "_", source.upper()).strip("_") if isinstance(source, str) else ""
    non_cutoff_source_markers = (
        "BACKUP", "COMPLETED", "CREATED", "UPLOAD", "SIDECAR", "ARTIFACT",
        "MYSQL", "OBSERVATION", "CLOCK", "MANIFEST",
    )
    test_only_source_tokens = {"TEST", "SYNTHETIC", "MOCK", "FIXTURE", "DEMO"}
    if (
        candidate.get("data_reference_time_status") != "VERIFIED"
        or candidate.get("data_reference_at") != cutoff_raw
        or not isinstance(evidence, dict)
        or evidence.get("status") != "VERIFIED"
        or evidence.get("authenticated") is not True
        or not isinstance(source, str)
        or not source.strip()
        or any(marker in source_key for marker in non_cutoff_source_markers)
        or bool(test_only_source_tokens.intersection(source_key.split("_")))
        or evidence.get("source") != source
        or expected.get("evidence_status") != "VERIFIED"
        or expected.get("evidence_authenticated") is not True
        or expected.get("reason") != "MEASURED_FROM_VERIFIED_DATA_CUTOFF"
        or not isinstance(incident_raw, str)
        or incident.get("incident_at") != incident_raw
    ):
        return "failover_rpo_not_measured"

    def parse_trusted_timestamp(raw):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    cutoff = parse_trusted_timestamp(cutoff_raw)
    incident_time = parse_trusted_timestamp(incident_raw)
    seconds = expected.get("seconds")
    if (
        cutoff is None or incident_time is None or cutoff > incident_time
        or isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 0
        or expected.get("target_seconds") != FAILOVER_RPO_TARGET_SECONDS
    ):
        return "failover_rpo_not_measured"
    measured_seconds = int((incident_time - cutoff).total_seconds())
    if measured_seconds != seconds:
        return "failover_rpo_not_measured"
    if seconds > FAILOVER_RPO_TARGET_SECONDS:
        return "failover_rpo_target_exceeded"
    if expected.get("status") != "PASS":
        return "failover_rpo_not_measured"
    return None


def _failover_rpo_policy_error(incident):
    """Require the RPO and existing-data policy bound into the admin request."""
    plan = incident.get(FAILOVER_RECOVERY_PLAN_FIELD) if isinstance(incident, dict) else None
    if (
        not isinstance(plan, dict)
        or plan.get("rpo_failure_policy") != FAILOVER_RPO_FAILURE_POLICY
        or plan.get("failover_rpo_policy") != FAILOVER_RPO_EXECUTION_POLICY
    ):
        return "failover_rpo_policy_not_approved"
    return None


def _server_failover_recovery_plan(incident, config):
    """Pin the best current Dump pair server-side; never accept it from Slack."""
    request_type = str(incident.get("request_type") or "").strip()
    plan = {
        "version": FAILOVER_RECOVERY_PLAN_VERSION,
        "policy": "NR_FIRST_DUMP_FALLBACK",
        "rpo_failure_policy": FAILOVER_RPO_FAILURE_POLICY,
        "failover_rpo_policy": FAILOVER_RPO_EXECUTION_POLICY,
        "target": dict(DEMO_DUMP_OVERWRITE_TARGET),
        "nr_policy": "PREFER_ONLY_IF_FRESH_AND_POSITION_VERIFIED",
        "dump": {"status": "UNAVAILABLE", "reason": "no_verified_backup_pair"},
        "overwrite_scope": DEMO_DUMP_OVERWRITE_SCOPE,
    }
    if request_type not in FAILOVER_RECOVERY_REQUEST_TYPES or bool(incident.get("test_mode")):
        plan["dump"] = {"status": "DISABLED", "reason": "test_or_non_failover_request"}
        return plan
    if not (
        as_bool(config.get("DUMP_RESTORE_EXEC_ENABLED"))
        and is_demo_dump_executor_configured(config)
    ):
        plan["dump"] = {"status": "UNAVAILABLE", "reason": "dump_executor_not_enabled_or_configured"}
        return plan
    try:
        backups = list_dump_backups(
            config.get("DUMP_BACKUP_DIR", ""), limit=1, compute_checksum=True
        )
        candidate = backups[0] if backups else None
        if candidate is None:
            return plan
        backup_path = Path(candidate["path"])
        sidecar_path = backup_path.with_name(candidate["status_filename"])
        if backup_path.is_symlink() or sidecar_path.is_symlink() or not sidecar_path.is_file():
            return plan
        sidecar_digest = hashlib.sha256(sidecar_path.read_bytes()).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", sidecar_digest):
            return plan
        # Backup completion, sidecar job markers, and standalone MySQL clock
        # observations are not recovered-data cutoffs. The inventory currently
        # exposes no authenticated cutoff, so RPO remains unmeasured.
        rpo = {"status": "NOT_MEASURED", "seconds": None}
        plan["dump"] = {
            "status": "READY",
            "backup_id": candidate["backup_id"],
            "sha256": candidate["checksum"].lower(),
            "sidecar_filename": candidate["status_filename"],
            "sidecar_sha256": sidecar_digest,
            "master_status": {
                "file": candidate["master_status_file"],
                "position": int(candidate["master_status_position"]),
            },
            "backup_started_at": candidate.get("backup_started_at"),
            "data_timestamp": None,
            "data_timestamp_source": "UNVERIFIED",
            "data_reference_at": candidate.get("data_reference_at"),
            "data_reference_evidence": candidate.get(
                "data_reference_evidence", {"status": "UNVERIFIED", "source": None}
            ),
            "data_reference_time_status": candidate.get("data_reference_time_status", "UNVERIFIED"),
            "expected_rpo": rpo,
        }
    except (OSError, KeyError, TypeError, ValueError):
        plan["dump"] = {"status": "UNAVAILABLE", "reason": "backup_pair_read_or_hash_failed"}
    return plan


def _failover_request_contract(state):
    incident = latest_incident(state)
    request_type = request_type_from_state(state)
    origin = str(incident.get("request_origin") or "GENERAL").strip().upper()
    client_key = str(state.get("slack_client_key") or incident.get("slack_client_key") or "").strip()
    source = str(incident.get("source") or "").strip()
    if state.get("action") != "failover":
        return None
    if request_type == REQUEST_TYPE_EMERGENCY_FAILOVER:
        if origin == "EMERGENCY" and client_key == "emergency" and source == "emergency_console":
            return request_type, origin, source, client_key
        return None
    if request_type == "NORMAL_FAILOVER" and client_key == "failover":
        if origin == ZABBIX_PRODUCTION_ACTION_NAME.upper():
            if source == "zabbix" and incident.get("production_action_verified") is True:
                return request_type, origin, source, client_key
            return None
        if origin in {"", "GENERAL"} and source in {"", "manual", "zabbix"}:
            return request_type, origin, source, client_key
    return None


def _new_failover_recovery_authorization(
    action, incident, request_id, now, expires_at, client_key, approval_required,
):
    plan = incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
    contract = _failover_request_contract({
        "action": action, "slack_client_key": client_key, "incidents": [incident],
    })
    candidate = plan.get("dump") if isinstance(plan, dict) else None
    valid = (
        contract is not None
        and isinstance(plan, dict)
        and plan.get("version") == FAILOVER_RECOVERY_PLAN_VERSION
        and plan.get("policy") == "NR_FIRST_DUMP_FALLBACK"
        and plan.get("rpo_failure_policy") == FAILOVER_RPO_FAILURE_POLICY
        and plan.get("target") == DEMO_DUMP_OVERWRITE_TARGET
        and plan.get("overwrite_scope") == DEMO_DUMP_OVERWRITE_SCOPE
        and isinstance(candidate, dict)
        and candidate.get("status") == "READY"
        and bool(re.fullmatch(
            r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc",
            str(candidate.get("backup_id") or ""),
        ))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(candidate.get("sha256") or "")))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(candidate.get("sidecar_sha256") or "")))
        and int(approval_required) == REQUIRED_APPROVALS
        and not bool(incident.get("test_mode"))
    )
    request_type, origin, source, actual_client = contract or ("", "", "", client_key)
    return {
        "version": DEMO_DUMP_OVERWRITE_AUTH_VERSION,
        "authorization_id": str(uuid.uuid4()),
        "request_id": request_id,
        "grant_kind": "CONDITIONAL_DUMP_FALLBACK",
        "status": "PENDING_TWO_ADMIN_APPROVAL" if valid else "NR_ONLY_DUMP_FALLBACK_UNAVAILABLE",
        "scope": DEMO_DUMP_OVERWRITE_SCOPE,
        "target": dict(DEMO_DUMP_OVERWRITE_TARGET),
        "backup_id": candidate.get("backup_id") if isinstance(candidate, dict) else None,
        "sha256": candidate.get("sha256") if isinstance(candidate, dict) else None,
        "sidecar_sha256": candidate.get("sidecar_sha256") if isinstance(candidate, dict) else None,
        "master_status": candidate.get("master_status") if isinstance(candidate, dict) else None,
        "data_timestamp": candidate.get("data_timestamp") if isinstance(candidate, dict) else None,
        "expected_rpo": candidate.get("expected_rpo") if isinstance(candidate, dict) else None,
        "rpo_failure_policy": plan.get("rpo_failure_policy") if isinstance(plan, dict) else None,
        "recovery_plan_version": FAILOVER_RECOVERY_PLAN_VERSION,
        "request_type": request_type,
        "approval_required": int(approval_required),
        "request_origin": origin,
        "request_source": source,
        "slack_client_key": actual_client,
        "requested_by": incident.get("requested_by"),
        "requested_at": now,
        "expires_at": expires_at,
    }


def _failover_recovery_authorization_error(state, *, approved=False, now=None):
    now = utc_timestamp() if now is None else float(now)
    contract = _failover_request_contract(state)
    incident = latest_incident(state)
    plan = incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
    grant = incident.get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
    candidate = plan.get("dump") if isinstance(plan, dict) else None
    if not isinstance(plan, dict) or plan.get("version") != FAILOVER_RECOVERY_PLAN_VERSION:
        return "failover_recovery_plan_invalid"
    if plan.get("rpo_failure_policy") != FAILOVER_RPO_FAILURE_POLICY:
        return "failover_rpo_policy_not_approved"
    if not isinstance(candidate, dict) or candidate.get("status") != "READY":
        return None
    if contract is None or not isinstance(grant, dict):
        return "failover_recovery_authorization_invalid"
    request_type, origin, source, client_key = contract
    expected_status = "APPROVED_BY_TWO_DISTINCT_ADMINS" if approved else "PENDING_TWO_ADMIN_APPROVAL"
    try:
        expires_at = float(state.get("expires_at"))
        grant_expiry = float(grant.get("expires_at"))
        requested_at = float(grant.get("requested_at"))
    except (TypeError, ValueError):
        return "failover_recovery_authorization_invalid"
    if (
        grant.get("version") != DEMO_DUMP_OVERWRITE_AUTH_VERSION
        or grant.get("grant_kind") != "CONDITIONAL_DUMP_FALLBACK"
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            str(grant.get("authorization_id") or ""),
        )
        or grant.get("request_id") != state.get("request_id")
        or grant.get("status") != expected_status
        or grant.get("scope") != DEMO_DUMP_OVERWRITE_SCOPE
        or grant.get("target") != DEMO_DUMP_OVERWRITE_TARGET
        or grant.get("request_type") != request_type
        or grant.get("request_origin") != origin
        or grant.get("request_source") != source
        or grant.get("slack_client_key") != client_key
        or grant.get("backup_id") != candidate.get("backup_id")
        or str(grant.get("sha256") or "").lower() != str(candidate.get("sha256") or "").lower()
        or str(grant.get("sidecar_sha256") or "").lower() != str(candidate.get("sidecar_sha256") or "").lower()
        or grant.get("master_status") != candidate.get("master_status")
        or grant.get("data_timestamp") != candidate.get("data_timestamp")
        or grant.get("expected_rpo") != candidate.get("expected_rpo")
        or grant.get("rpo_failure_policy") != plan.get("rpo_failure_policy")
        or grant.get("recovery_plan_version") != FAILOVER_RECOVERY_PLAN_VERSION
        or int(grant.get("approval_required") or 0) != REQUIRED_APPROVALS
        or not math.isfinite(expires_at) or expires_at <= now
        or not math.isfinite(grant_expiry) or abs(grant_expiry - expires_at) > 0.001
        or not math.isfinite(requested_at) or requested_at <= 0 or requested_at > now
    ):
        return "failover_recovery_authorization_invalid"
    if approved:
        approvers = state.get("approvers")
        try:
            approved_at = float(grant.get("approved_at"))
        except (TypeError, ValueError):
            return "failover_recovery_approval_invalid"
        if (
            state.get("status") != "EXECUTING"
            or int(state.get("approval_required") or 0) != REQUIRED_APPROVALS
            or not isinstance(approvers, list) or len(approvers) != REQUIRED_APPROVALS
            or len(set(approvers)) != REQUIRED_APPROVALS
            or grant.get("approver_ids") != approvers
            or grant.get("approval_count") != REQUIRED_APPROVALS
            or grant.get("execution_id") != state.get("execution_id")
            or not math.isfinite(approved_at) or not 0 < approved_at <= now
        ):
            return "failover_recovery_approval_invalid"
    return None


def _mark_dump_overwrite_authorization(incidents, status, *, at=None):
    """Keep the request-local authorization lifecycle aligned with SQLite status."""
    result = [dict(item) if isinstance(item, dict) else item for item in (incidents or [])]
    if not result or not isinstance(result[-1], dict):
        return result
    latest = dict(result[-1])
    grant = latest.get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
    if not isinstance(grant, dict):
        return result
    updated = dict(grant)
    updated["status"] = status
    if at is not None:
        updated["closed_at"] = float(at)
    latest[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = updated
    result[-1] = latest
    return result


class ApprovalStore:
    def __init__(
        self,
        path,
        initial_ttl=INITIAL_APPROVAL_TTL_SECONDS,
        approved_ttl=FIRST_APPROVAL_TTL_SECONDS,
        execution_timeout=DEFAULT_EXECUTION_TIMEOUT_SECONDS,
        execution_lease_seconds=DEFAULT_EXECUTION_LEASE_SECONDS,
    ):
        self.path = path
        self.initial_ttl = initial_ttl
        self.approved_ttl = approved_ttl
        self.execution_timeout = max(1.0, float(execution_timeout))
        self.execution_lease_seconds = max(1.0, float(execution_lease_seconds))
        self.lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    slack_client_key TEXT,
                    status TEXT NOT NULL,
                    incidents TEXT NOT NULL,
                    approvers TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    first_approved_at REAL,
                    expires_at REAL NOT NULL,
                    slack_channel_id TEXT,
                    slack_message_ts TEXT,
                    finished_at REAL,
                    cancelled_by TEXT,
                    result TEXT,
                    execution_started_at REAL,
                    execution_heartbeat_at REAL,
                    execution_lease_until REAL,
                    execution_id TEXT,
                    approval_required INTEGER NOT NULL DEFAULT 2,
                    approval_mode_expires_at REAL
                )
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(approval_requests)")
            }
            for name, definition in (
                ("slack_client_key", "TEXT"),
                ("finished_at", "REAL"),
                ("cancelled_by", "TEXT"),
                ("result", "TEXT"),
                ("execution_started_at", "REAL"),
                ("execution_heartbeat_at", "REAL"),
                ("execution_lease_until", "REAL"),
                ("execution_id", "TEXT"),
                ("approval_required", "INTEGER NOT NULL DEFAULT 2"),
                ("approval_mode_expires_at", "REAL"),
            ):
                if name not in columns:
                    connection.execute(f"ALTER TABLE approval_requests ADD COLUMN {name} {definition}")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_active ON approval_requests(action, status, created_at)"
            )
        os.chmod(self.path, 0o600)

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        result = dict(row)
        result["incidents"] = json.loads(result["incidents"])
        result["approvers"] = json.loads(result["approvers"])
        return result

    @staticmethod
    def _read(connection, request_id):
        return connection.execute(
            "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
        ).fetchone()

    def get(self, request_id):
        with self.lock, self._connect() as connection:
            return self._decode(self._read(connection, request_id))

    def finish_test_approval(self, request_id):
        """Close an approved test request without recording a runner start."""
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._read(connection, request_id)
            state = self._decode(row)
            incidents = (state or {}).get("incidents") or []
            approvers = (state or {}).get("approvers") or []
            is_test_failover = (
                state is not None
                and state.get("action") == "failover"
                and any(bool(item.get("test_mode")) for item in incidents if isinstance(item, dict))
            )
            if not (
                is_test_failover
                and state.get("status") == "EXECUTING"
                and int(state.get("approval_required") or 0) == REQUIRED_APPROVALS
                and len(approvers) == REQUIRED_APPROVALS
                and len(set(approvers)) == REQUIRED_APPROVALS
            ):
                connection.commit()
                return None
            connection.execute(
                "UPDATE approval_requests SET status = 'FAILED', finished_at = ?, "
                "result = 'test_mode_executor_suppressed', execution_started_at = NULL, "
                "execution_heartbeat_at = NULL, execution_lease_until = NULL, execution_id = NULL "
                "WHERE request_id = ? AND status = 'EXECUTING'",
                (now, request_id),
            )
            connection.commit()
        return self.get(request_id)

    def list_with_messages(self):
        with self.lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM approval_requests WHERE slack_channel_id IS NOT NULL "
                "AND slack_message_ts IS NOT NULL ORDER BY created_at ASC"
            ).fetchall()
            return [self._decode(row) for row in rows]

    def _recover_stale_executions_locked(self, connection, now):
        rows = connection.execute(
            """
            SELECT request_id, action, incidents, created_at, execution_started_at,
                   execution_heartbeat_at, execution_lease_until
            FROM approval_requests
            WHERE status = 'EXECUTING'
            """
        ).fetchall()
        stale_requests = []
        for row in rows:
            lease_until = row["execution_lease_until"]
            started_at = row["execution_started_at"] or row["execution_heartbeat_at"] or row["created_at"]
            stale = lease_until is not None and lease_until <= now
            if lease_until is None:
                stale = started_at + self.execution_timeout <= now
            if stale:
                try:
                    incidents = json.loads(row["incidents"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    incidents = []
                latest = incidents[-1] if incidents and isinstance(incidents[-1], dict) else {}
                # A stale Dump process may already have changed DNS or data.
                # Treat every Dump origin as outcome-unknown; never infer a
                # safe failure from a missing or emergency origin marker.
                dump_partial = (
                    row["action"] == "failover"
                    and latest.get("request_type") == REQUEST_TYPE_DUMP_RESTORE
                )
                stale_requests.append((row["request_id"], dump_partial))
        if stale_requests:
            connection.executemany(
                """
                UPDATE approval_requests
                SET status = ?, finished_at = ?, result = ?,
                    execution_lease_until = NULL
                WHERE request_id = ? AND status = 'EXECUTING'
                """,
                [
                    (
                        "PARTIAL_FAILURE" if dump_partial else "FAILED",
                        now,
                        "dump_executor_outcome_unknown_operator_review"
                        if dump_partial else "stale_execution_recovered",
                        request_id,
                    )
                    for request_id, dump_partial in stale_requests
                ],
            )
        return [request_id for request_id, _dump_partial in stale_requests]

    def recover_stale_executions(self, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stale_ids = self._recover_stale_executions_locked(connection, now)
            states = [self._decode(self._read(connection, request_id)) for request_id in stale_ids]
            connection.commit()
            return states

    def find_active(self, action):
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            row = connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?)
                ORDER BY created_at DESC LIMIT 1
                """,
                (action, *ACTIVE_STATUSES),
            ).fetchone()
            connection.commit()
            return self._decode(row)

    def find_executing(self):
        """Return the current execution, if any, for the global DR lock view."""
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            row = connection.execute(
                "SELECT * FROM approval_requests WHERE status = 'EXECUTING' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            connection.commit()
            return self._decode(row)

    def peek_executing(self):
        """Read the current execution without stale recovery or state mutation."""
        with self.lock, self._connect() as connection:
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                "SELECT * FROM approval_requests WHERE status = 'EXECUTING' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return self._decode(row)

    def peek_latest_terminal_result(self, action):
        """Read the latest completed execution result without changing request state."""
        if action not in {"failover", "failback"}:
            raise ValueError("unsupported action")
        with self.lock, self._connect() as connection:
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                """
                SELECT status, finished_at FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?, ?) AND finished_at IS NOT NULL
                ORDER BY finished_at DESC, created_at DESC LIMIT 1
                """,
                (
                    action,
                    "SUCCEEDED",
                    "DB_RESTORED_NOT_FAILOVER_COMPLETE",
                    "FAILED",
                    "PARTIAL_FAILURE",
                ),
            ).fetchone()
            return dict(row) if row is not None else None

    def peek_terminal_results(self, action):
        """Read terminal request evidence for workflow-specific status rendering."""
        if action not in {"failover", "failback"}:
            raise ValueError("unsupported action")
        with self.lock, self._connect() as connection:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute(
                """
                SELECT request_id, action, slack_client_key, status, incidents,
                       approvers, approval_required, finished_at, result,
                       execution_started_at, execution_id
                FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?, ?) AND finished_at IS NOT NULL
                ORDER BY finished_at DESC, created_at DESC
                """,
                (
                    action,
                    "SUCCEEDED",
                    "DB_RESTORED_NOT_FAILOVER_COMPLETE",
                    "FAILED",
                    "PARTIAL_FAILURE",
                ),
            ).fetchall()
            return [dict(row) for row in rows]

    def _expire_due_locked(self, connection, now):
        rows = connection.execute(
            """
            SELECT request_id, incidents FROM approval_requests
            WHERE status IN (?, ?) AND expires_at <= ?
            """,
            (*APPROVAL_STATUSES, now),
        ).fetchall()
        expired_ids = [row["request_id"] for row in rows]
        if rows:
            for row in rows:
                try:
                    incidents = json.loads(row["incidents"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    incidents = []
                incidents = _mark_dump_overwrite_authorization(
                    incidents, "EXPIRED", at=now,
                )
                connection.execute(
                "UPDATE approval_requests SET status = 'EXPIRED', finished_at = ?, result = 'expired' "
                    ", incidents = ? WHERE request_id = ?",
                    (now, json.dumps(incidents, ensure_ascii=True), row["request_id"]),
                )
        return expired_ids

    def expire_due(self, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            expired_ids = self._expire_due_locked(connection, now)
            states = [self._decode(self._read(connection, request_id)) for request_id in expired_ids]
            connection.commit()
            return states

    def expire_single_approval_requests(self, active_mode_expires_at=None, now=None):
        """Expire incomplete test-quorum requests after mode change or deadline."""
        now = utc_timestamp() if now is None else float(now)
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT request_id, action, incidents, approval_mode_expires_at FROM approval_requests "
                "WHERE approval_required = 1 AND status IN (?, ?)",
                APPROVAL_STATUSES,
            ).fetchall()
            expired_ids = []
            for row in rows:
                recorded_deadline = row["approval_mode_expires_at"]
                try:
                    incidents = json.loads(row["incidents"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    incidents = []
                latest = incidents[-1] if incidents and isinstance(incidents[-1], dict) else {}
                authorization = latest.get(SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD)
                demo_request = (
                    row["action"] == "failover"
                    and latest.get("request_type") == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE
                    and latest.get("request_origin") == SYNTHETIC_MYSQL_DEMO_REQUEST_ORIGIN
                    and latest.get("source") == SYNTHETIC_MYSQL_DEMO_REQUEST_SOURCE
                    and latest.get("test_mode") is not True
                    and isinstance(authorization, dict)
                )
                same_active_window = (
                    demo_request
                    and
                    active_mode_expires_at is not None
                    and recorded_deadline is not None
                    and abs(float(recorded_deadline) - float(active_mode_expires_at)) < 1
                )
                if not same_active_window or float(recorded_deadline) <= now:
                    expired_ids.append(row["request_id"])
            if expired_ids:
                connection.executemany(
                    "UPDATE approval_requests SET status = 'EXPIRED', finished_at = ?, "
                    "result = 'single_approval_test_mode_ended', approvers = '[]' "
                    "WHERE request_id = ? AND status IN (?, ?)",
                    [(now, request_id, *APPROVAL_STATUSES) for request_id in expired_ids],
                )
            states = [self._decode(self._read(connection, request_id)) for request_id in expired_ids]
            connection.commit()
            return states

    def create_or_merge(
        self,
        action,
        incident,
        now=None,
        ttl_seconds=None,
        approval_required=REQUIRED_APPROVALS,
        approval_mode_expires_at=None,
        recovery_plan=None,
    ):
        now = utc_timestamp() if now is None else now
        approval_required = int(approval_required)
        if approval_required not in (1, REQUIRED_APPROVALS):
            raise ValueError("approval_required must be 1 or 2")
        if approval_required == 1 and (
            approval_mode_expires_at is None or float(approval_mode_expires_at) <= now
        ):
            raise ValueError("single-approval requests require a future test-mode expiry")
        requested_type = str(incident.get("request_type") or request_type_for_action(action)).strip()
        requested_client = str(incident.get("slack_client_key") or action).strip()
        is_dump_request = requested_type == REQUEST_TYPE_DUMP_RESTORE
        is_auto_failover = action == "failover" and requested_type in FAILOVER_RECOVERY_REQUEST_TYPES
        is_synthetic_demo = (
            action == "failover" and requested_type == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE
        )
        if is_synthetic_demo:
            binding = incident.get(SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD)
            if (
                approval_required != 1
                or requested_client != "failover"
                or incident.get("request_origin") != SYNTHETIC_MYSQL_DEMO_REQUEST_ORIGIN
                or incident.get("source") != SYNTHETIC_MYSQL_DEMO_REQUEST_SOURCE
                or incident.get("test_mode") is True
                or not isinstance(binding, dict)
                or binding.get("status") != "PENDING"
                or binding.get("approval_required") != 1
                or binding.get("approval_mode_expires_at") != approval_mode_expires_at
            ):
                raise ValueError("synthetic demo request contract is invalid")
        request_has_dump_identity = bool(
            re.fullmatch(
                r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc",
                str(incident.get("backup_id") or ""),
            )
            and re.fullmatch(r"[0-9a-f]{64}", str(incident.get("backup_checksum") or "").lower())
        )
        requested_ttl = self.initial_ttl if ttl_seconds is None else max(1.0, float(ttl_seconds))
        request_expires_at = now + requested_ttl
        if approval_required == 1:
            request_expires_at = min(request_expires_at, float(approval_mode_expires_at))
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            rows = connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?)
                ORDER BY created_at DESC
                """,
                (action, *ACTIVE_STATUSES),
            ).fetchall()
            if is_synthetic_demo:
                active_any = connection.execute(
                    "SELECT request_id FROM approval_requests WHERE status IN (?, ?, ?) LIMIT 1",
                    ACTIVE_STATUSES,
                ).fetchone()
                if active_any is not None:
                    connection.commit()
                    raise ValueError("synthetic demo requires no active ChatOps request")
            requested_test_mode = bool(incident.get("test_mode"))
            if (
                action == "failover"
                and requested_type == ZABBIX_TEST_FAILOVER_REQUEST_TYPE
                and requested_test_mode
            ):
                event_id = str(incident.get("zabbix_event_id") or incident.get("incident_id") or "")
                historical = connection.execute(
                    "SELECT * FROM approval_requests WHERE action = ? "
                    "AND incidents LIKE ? ORDER BY created_at DESC",
                    (action, '%"request_type": "ZABBIX_TEST_FAILOVER"%'),
                ).fetchall()
                for historical_row in historical:
                    historical_state = self._decode(historical_row)
                    for historical_incident in historical_state.get("incidents") or []:
                        if (
                            isinstance(historical_incident, dict)
                            and historical_incident.get("test_mode") is True
                            and historical_incident.get("request_type") == ZABBIX_TEST_FAILOVER_REQUEST_TYPE
                            and historical_incident.get("request_origin") == ZABBIX_TEST_ACTION_NAME
                            and str(historical_incident.get("zabbix_event_id") or "") == event_id
                        ):
                            connection.commit()
                            return historical_state, True
                # Separate Zabbix test events receive separate, test-only rows;
                # they are never merged into a production approval request.
                rows = []
            row = None
            for candidate in rows:
                candidate_state = self._decode(candidate)
                candidate_test_mode = any(
                    bool(item.get("test_mode")) for item in candidate_state.get("incidents") or []
                )
                latest = (candidate_state.get("incidents") or [{}])[-1]
                candidate_type = str(
                    latest.get("request_type") or request_type_for_action(action)
                ).strip()
                candidate_has_dump_identity = bool(
                    re.fullmatch(
                        r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc",
                        str(latest.get("backup_id") or ""),
                    )
                    and re.fullmatch(
                        r"[0-9a-f]{64}", str(latest.get("backup_checksum") or "").lower()
                    )
                )
                # A complete Dump approval is a single-use destructive grant.
                # Never merge a new selection into an existing request row.
                if (is_dump_request and request_has_dump_identity) or (
                    candidate_type == REQUEST_TYPE_DUMP_RESTORE and candidate_has_dump_identity
                ):
                    continue
                candidate_client = str(
                    candidate_state.get("slack_client_key")
                    or latest.get("slack_client_key")
                    or action
                ).strip()
                candidate_required = int(candidate_state.get("approval_required") or REQUIRED_APPROVALS)
                candidate_mode_expires_at = candidate_state.get("approval_mode_expires_at")
                same_mode_expiry = (
                    candidate_mode_expires_at is None and approval_mode_expires_at is None
                ) or (
                    candidate_mode_expires_at is not None
                    and approval_mode_expires_at is not None
                    and abs(float(candidate_mode_expires_at) - float(approval_mode_expires_at)) < 1
                )
                candidate_origin = str(latest.get("request_origin") or "GENERAL").upper()
                requested_origin = str(incident.get("request_origin") or "GENERAL").upper()
                same_emergency_target = True
                if candidate_origin == "EMERGENCY" or requested_origin == "EMERGENCY":
                    candidate_target = next(
                        (str(latest.get(key)).strip().casefold() for key in
                         ("dr_target_id", "failover_target_id", "target_id") if latest.get(key)),
                        "__emergency_default_target__",
                    )
                    requested_target = next(
                        (str(incident.get(key)).strip().casefold() for key in
                         ("dr_target_id", "failover_target_id", "target_id") if incident.get(key)),
                        "__emergency_default_target__",
                    )
                    same_emergency_target = (
                        candidate_origin == requested_origin == "EMERGENCY"
                        and candidate_client == requested_client == "emergency"
                        and candidate_target == requested_target
                    )
                same_dump_selection = True
                if requested_type == REQUEST_TYPE_DUMP_RESTORE:
                    candidate_target = next(
                        (str(latest.get(key)).strip().casefold() for key in
                         ("dr_target_id", "failover_target_id", "target_id") if latest.get(key)),
                        None,
                    )
                    requested_target = next(
                        (str(incident.get(key)).strip().casefold() for key in
                         ("dr_target_id", "failover_target_id", "target_id") if incident.get(key)),
                        None,
                    )
                    same_dump_selection = (
                        str(latest.get("backup_id") or "") == str(incident.get("backup_id") or "")
                        and str(latest.get("backup_checksum") or "").lower()
                        == str(incident.get("backup_checksum") or "").lower()
                        and candidate_origin == requested_origin
                        and candidate_target == requested_target
                    )
                    if requested_origin == "EMERGENCY":
                        same_dump_selection = same_dump_selection and (
                            latest.get("reason_code") == incident.get("reason_code")
                            and latest.get("reason_text") == incident.get("reason_text")
                            and latest.get("requested_by") == incident.get("requested_by")
                        )
                same_recovery_plan = True
                if is_auto_failover:
                    same_recovery_plan = (
                        recovery_plan is None
                        or (
                            isinstance(recovery_plan, dict)
                            and latest.get(FAILOVER_RECOVERY_PLAN_FIELD) == recovery_plan
                        )
                    )
                if (
                    candidate_test_mode == requested_test_mode
                    and candidate_type == requested_type
                    and candidate_client == requested_client
                    and candidate_required == approval_required
                    and same_mode_expiry
                    and same_emergency_target
                    and same_dump_selection
                    and same_recovery_plan
                ):
                    row = candidate
                    break
            if row is not None:
                state = self._decode(row)
                incident_ids = {item.get("incident_id") for item in state["incidents"]}
                if incident.get("incident_id") not in incident_ids:
                    stored_incident = dict(incident)
                    if is_auto_failover and isinstance(recovery_plan, dict):
                        stored_incident.pop(DEMO_DUMP_OVERWRITE_AUTH_FIELD, None)
                        stored_incident[FAILOVER_RECOVERY_PLAN_FIELD] = dict(recovery_plan or {})
                        prior_grant = latest_incident(state).get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
                        if isinstance(prior_grant, dict):
                            stored_incident[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = dict(prior_grant)
                        else:
                            stored_incident[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = _new_failover_recovery_authorization(
                                action, stored_incident, state["request_id"], now,
                                state["expires_at"], requested_client, approval_required,
                            )
                    state["incidents"].append(stored_incident)
                    connection.execute(
                        "UPDATE approval_requests SET incidents = ? WHERE request_id = ?",
                        (json.dumps(state["incidents"], ensure_ascii=True), state["request_id"]),
                    )
                connection.commit()
                return self.get(state["request_id"]), True

            request_id = str(uuid.uuid4())
            stored_incident = dict(incident)
            if is_synthetic_demo:
                authorization = dict(stored_incident[SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD])
                authorization.update({
                    "request_id": request_id,
                    "status": "PENDING",
                    "approval_required": 1,
                    "approval_mode_expires_at": float(approval_mode_expires_at),
                })
                stored_incident[SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD] = authorization
            if is_auto_failover and isinstance(recovery_plan, dict):
                # Only the server-computed plan is persisted. Slack request
                # fields cannot choose an AWS target or overwrite artifact.
                stored_incident.pop(FAILOVER_RECOVERY_PLAN_FIELD, None)
                stored_incident.pop(DEMO_DUMP_OVERWRITE_AUTH_FIELD, None)
                if isinstance(recovery_plan, dict):
                    stored_incident[FAILOVER_RECOVERY_PLAN_FIELD] = dict(recovery_plan)
                stored_incident[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = _new_failover_recovery_authorization(
                    action, stored_incident, request_id, now, request_expires_at,
                    requested_client, approval_required,
                )
            if is_dump_request:
                # The Slack payload cannot choose or widen this scope. The
                # request row ID, selected backup and exact target are written
                # together by this SQLite transaction.
                stored_incident.pop(DEMO_DUMP_OVERWRITE_AUTH_FIELD, None)
                stored_incident[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = _new_dump_overwrite_authorization(
                    action,
                    stored_incident,
                    request_id,
                    now,
                    request_expires_at,
                    requested_client,
                    approval_required,
                )
            connection.execute(
                """
                INSERT INTO approval_requests (
                    request_id, action, slack_client_key, status, incidents, approvers,
                    created_at, first_approved_at, expires_at,
                    slack_channel_id, slack_message_ts,
                    execution_started_at, execution_heartbeat_at,
                    execution_lease_until, execution_id,
                    approval_required, approval_mode_expires_at
                ) VALUES (?, ?, ?, 'PENDING', ?, '[]', ?, NULL, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    request_id,
                    action,
                    requested_client,
                    json.dumps([stored_incident], ensure_ascii=True),
                    now,
                    request_expires_at,
                    approval_required,
                    approval_mode_expires_at,
                ),
            )
            connection.commit()
            return self.get(request_id), False

    def cancel_failover_requests_for_dump(self, replacement_request_id, now=None):
        """Cancel unstarted competing Failover approvals after a Dump request exists."""
        now = utc_timestamp() if now is None else float(now)
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replacement_row = self._read(connection, replacement_request_id)
            if replacement_row is None:
                connection.commit()
                return []
            replacement = self._decode(replacement_row)
            replacement_incident = latest_incident(replacement)
            replacement_type = request_type_from_state(replacement)
            emergency_replacement = (
                replacement["action"] == "failover"
                and replacement_type in {
                    REQUEST_TYPE_EMERGENCY_FAILOVER,
                    REQUEST_TYPE_DUMP_RESTORE,
                }
                and str(replacement_incident.get("request_origin") or "").upper() == "EMERGENCY"
                and request_client_key_from_state(replacement) == "emergency"
            )

            if emergency_replacement:
                if (
                    replacement["status"] not in APPROVAL_STATUSES
                    or not replacement.get("slack_channel_id")
                    or not replacement.get("slack_message_ts")
                ):
                    connection.commit()
                    return []

                def emergency_target(state):
                    incident = latest_incident(state)
                    for key in ("dr_target_id", "failover_target_id", "target_id"):
                        value = str(incident.get(key) or "").strip()
                        if value:
                            return value.casefold()
                    # The current Emergency Console owns one configured DR
                    # destination. Explicitly different targets never match.
                    return "__emergency_default_target__"

                def is_emergency_failover(state):
                    incident = latest_incident(state)
                    return (
                        state.get("action") == "failover"
                        and request_type_from_state(state)
                        in {REQUEST_TYPE_EMERGENCY_FAILOVER, REQUEST_TYPE_DUMP_RESTORE}
                        and str(incident.get("request_origin") or "").upper() == "EMERGENCY"
                        and request_client_key_from_state(state) == "emergency"
                        and emergency_target(state) == emergency_target(replacement)
                    )

                rows = connection.execute(
                    "SELECT * FROM approval_requests WHERE action = ? AND status IN (?, ?) "
                    "ORDER BY created_at DESC, request_id DESC",
                    ("failover", *APPROVAL_STATUSES),
                ).fetchall()
                candidates = [
                    self._decode(row) for row in rows
                    if is_emergency_failover(self._decode(row))
                ]
                replacement_order = (float(replacement["created_at"]), replacement["request_id"])
                if any(
                    state["request_id"] != replacement_request_id
                    and request_type_from_state(state) in {
                        REQUEST_TYPE_EMERGENCY_FAILOVER,
                        REQUEST_TYPE_DUMP_RESTORE,
                    }
                    and (float(state["created_at"]), state["request_id"]) > replacement_order
                    for state in candidates
                ):
                    # A newer competing request owns the transition. Its
                    # successful delivery will supersede this one in turn.
                    connection.commit()
                    return []

                cancelled_ids = []
                supersede_result = (
                    "superseded_by_dump_request"
                    if replacement_type == REQUEST_TYPE_DUMP_RESTORE
                    else "superseded_by_emergency_failover_request"
                )
                superseded_by = (
                    f"system:dump_request:{replacement_request_id}"
                    if replacement_type == REQUEST_TYPE_DUMP_RESTORE
                    else f"system:emergency_failover_request:{replacement_request_id}"
                )
                for state in candidates:
                    if state["request_id"] == replacement_request_id:
                        continue
                    cancelled_incidents = _mark_dump_overwrite_authorization(
                        state.get("incidents"), "CANCELLED", at=now,
                    )
                    cursor = connection.execute(
                        "UPDATE approval_requests SET status = 'CANCELLED', finished_at = ?, "
                        "cancelled_by = ?, result = ?, incidents = ?, "
                        "execution_lease_until = NULL "
                        "WHERE request_id = ? AND status IN (?, ?)",
                        (
                            now,
                            superseded_by,
                            supersede_result,
                            json.dumps(cancelled_incidents, ensure_ascii=True),
                            state["request_id"],
                            *APPROVAL_STATUSES,
                        ),
                    )
                    if cursor.rowcount == 1:
                        cancelled_ids.append(state["request_id"])
                cancelled = [
                    self._decode(self._read(connection, request_id))
                    for request_id in cancelled_ids
                ]
                connection.commit()
                return cancelled

        replaceable_types = {
            request_type_for_action("failover"),
            REQUEST_TYPE_EMERGENCY_FAILOVER,
            REQUEST_TYPE_DUMP_RESTORE,
        }
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM approval_requests WHERE action = ? AND status IN (?, ?) "
                "ORDER BY created_at DESC",
                ("failover", *APPROVAL_STATUSES),
            ).fetchall()
            cancelled_ids = []
            for row in rows:
                state = self._decode(row)
                if state["request_id"] == replacement_request_id:
                    continue
                request_type = request_type_from_state(state)
                if request_type not in replaceable_types:
                    continue
                cancelled_incidents = _mark_dump_overwrite_authorization(
                    state.get("incidents"), "CANCELLED", at=now,
                )
                connection.execute(
                    "UPDATE approval_requests SET status = 'CANCELLED', approvers = '[]', "
                    "expires_at = ?, finished_at = ?, cancelled_by = ?, "
                    "result = 'superseded_by_dump_request', execution_lease_until = NULL, incidents = ? "
                    "WHERE request_id = ? AND status IN (?, ?)",
                    (
                        now,
                        now,
                        f"system:dump_request:{replacement_request_id}",
                        json.dumps(cancelled_incidents, ensure_ascii=True),
                        state["request_id"],
                        *APPROVAL_STATUSES,
                    ),
                )
                cancelled_ids.append(state["request_id"])
            cancelled = [self._decode(self._read(connection, request_id)) for request_id in cancelled_ids]
            connection.commit()
            return cancelled

    def fail_request_creation(self, request_id, result="slack_delivery_failed", now=None):
        """Close a newly-created request that never obtained a Slack message."""
        now = utc_timestamp() if now is None else float(now)
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._read(connection, request_id)
            try:
                incidents = json.loads(row["incidents"] or "[]") if row is not None else []
            except (TypeError, json.JSONDecodeError):
                incidents = []
            incidents = _mark_dump_overwrite_authorization(
                incidents, "REQUEST_DELIVERY_FAILED", at=now,
            )
            connection.execute(
                "UPDATE approval_requests SET status = 'FAILED', finished_at = ?, result = ?, incidents = ? "
                "WHERE request_id = ? AND status IN (?, ?) "
                "AND slack_message_ts IS NULL AND approvers = '[]'",
                (now, result, json.dumps(incidents, ensure_ascii=True), request_id, *APPROVAL_STATUSES),
            )
            connection.commit()
        return self.get(request_id)

    def reset_approvals(self, request_id, ttl_seconds=None, result="precheck_failed"):
        """Discard approvals after a safety gate changed, keeping the request visible."""
        now = utc_timestamp()
        ttl = self.initial_ttl if ttl_seconds is None else max(1.0, float(ttl_seconds))
        with self.lock, self._connect() as connection:
            row = self._read(connection, request_id)
            if row is None:
                return None
            state = self._decode(row)
            expires_at = now + ttl
            if int(state.get("approval_required") or REQUIRED_APPROVALS) == 1:
                expires_at = min(expires_at, float(state.get("approval_mode_expires_at") or now))
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'PENDING', approvers = '[]', first_approved_at = NULL,
                    expires_at = ?, result = ?, execution_started_at = NULL,
                    execution_heartbeat_at = NULL, execution_lease_until = NULL,
                    execution_id = NULL
                WHERE request_id = ? AND status IN ('PENDING', 'PARTIALLY_APPROVED')
                """,
                (expires_at, result, request_id),
            )
            connection.commit()
        return self.get(request_id)

    def attach_slack_message(self, request_id, channel_id, message_ts):
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE approval_requests
                SET slack_channel_id = ?, slack_message_ts = ?
                WHERE request_id = ?
                """,
                (channel_id, message_ts, request_id),
            )
            connection.commit()
        return self.get(request_id)

    def clear_slack_message(self, request_id):
        with self.lock, self._connect() as connection:
            connection.execute(
                "UPDATE approval_requests SET slack_message_ts = NULL WHERE request_id = ?",
                (request_id,),
            )
            connection.commit()
        return self.get(request_id)

    def refresh_failback_security(self, request_id, security):
        """Persist the latest gate result and discard stale partial approvals when blocked."""
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return None
            state = self._decode(row)
            if state["action"] != "failback" or not state["incidents"]:
                connection.commit()
                return state
            incidents = state["incidents"]
            latest = dict(incidents[-1])
            latest.update(
                {
                    "security_status": security.get("status", "UNKNOWN"),
                    "security_reason": security.get("reason", "Security readiness was not evaluated."),
                    "security_agents": security.get("agents", "-"),
                    "security_critical_incident": security.get("critical_incident", "-"),
                    "wazuh_risk_level": security.get("risk_level", "UNKNOWN"),
                    "wazuh_risk_observed_at": security.get("risk_observed_at", "-"),
                    "wazuh_risk_checked_at": security.get("risk_checked_at", "-"),
                    "wazuh_risk_reason": security.get("risk_reason", "Wazuh risk was not evaluated."),
                }
            )
            incidents[-1] = latest
            values = [json.dumps(incidents, ensure_ascii=True)]
            update = "UPDATE approval_requests SET incidents = ?"
            if security.get("status") == "BLOCKED" and state["status"] in APPROVAL_STATUSES:
                update += ", status = 'PENDING', approvers = '[]', first_approved_at = NULL, expires_at = ?"
                expires_at = now + self.initial_ttl
                if int(state.get("approval_required") or REQUIRED_APPROVALS) == 1:
                    expires_at = min(expires_at, float(state.get("approval_mode_expires_at") or now))
                values.append(expires_at)
            update += " WHERE request_id = ?"
            values.append(request_id)
            connection.execute(update, values)
            connection.commit()
        return self.get(request_id)

    def refresh_failback_network(self, request_id, network):
        """Persist Zabbix/SNMP status as context; live DB/Health/DNS checks gate execution."""
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return None
            state = self._decode(row)
            if state["action"] != "failback" or not state["incidents"]:
                connection.commit()
                return state
            incidents = state["incidents"]
            latest = dict(incidents[-1])
            latest.update(
                {
                    "network_status": network.get("status", "UNKNOWN"),
                    "network_reason": network.get("reason", "Network readiness was not evaluated."),
                    "network_source": network.get("source", "-"),
                    "network_devices": network.get("devices", {}),
                    "network_checked_at": network.get("checked_at", "-"),
                }
            )
            incidents[-1] = latest
            values = [json.dumps(incidents, ensure_ascii=True)]
            update = "UPDATE approval_requests SET incidents = ?"
            update += " WHERE request_id = ?"
            values.append(request_id)
            connection.execute(update, values)
            connection.commit()
        return self.get(request_id)

    def approve(self, request_id, action, user_id, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return "missing", None
            state = self._decode(row)
            if state["action"] != action:
                connection.commit()
                return "action_mismatch", state
            executing_row = connection.execute(
                "SELECT * FROM approval_requests WHERE status = 'EXECUTING' "
                "AND request_id != ? ORDER BY created_at DESC LIMIT 1",
                (request_id,),
            ).fetchone()
            if executing_row is not None:
                connection.commit()
                return "global_lock", self._decode(executing_row)
            if state["status"] == "EXECUTING":
                connection.commit()
                return "executing", state
            if state["status"] in TERMINAL_STATUSES:
                connection.commit()
                return "closed", state
            if user_id in state["approvers"]:
                connection.commit()
                return "duplicate", state

            is_dump_request = request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE
            is_auto_failover = (
                state["action"] == "failover"
                and request_type_from_state(state) in FAILOVER_RECOVERY_REQUEST_TYPES
            )
            is_synthetic_demo = is_synthetic_mysql_demo_request(state)
            if is_synthetic_demo:
                authorization = latest_incident(state).get(
                    SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD
                )
                if not (
                    isinstance(authorization, dict)
                    and authorization.get("request_id") == request_id
                    and authorization.get("status") == "PENDING"
                    and authorization.get("approval_required") == 1
                    and int(state.get("approval_required") or 0) == 1
                    and authorization.get("approval_mode_expires_at")
                    == state.get("approval_mode_expires_at")
                    and authorization.get("kind") == "SYNTHETIC_AWS_MYSQL_A_B_ROUNDTRIP"
                ):
                    connection.commit()
                    return "synthetic_demo_authorization_invalid", state
            if is_dump_request:
                authorization_error = _dump_overwrite_authorization_error(
                    state, request_id=request_id, approved=False, now=now,
                )
                if authorization_error:
                    connection.commit()
                    return "overwrite_authorization_invalid", state
            elif is_auto_failover and isinstance(
                latest_incident(state).get(FAILOVER_RECOVERY_PLAN_FIELD), dict
            ):
                authorization_error = _failover_recovery_authorization_error(
                    state, approved=False, now=now,
                )
                if authorization_error:
                    connection.commit()
                    return "recovery_authorization_invalid", state

            approval_required = int(state.get("approval_required") or REQUIRED_APPROVALS)
            approvers = state["approvers"] + [user_id]
            first_approved_at = state["first_approved_at"]
            expires_at = state["expires_at"]
            if first_approved_at is None:
                first_approved_at = now
                if request_type_from_state(state) in {
                    REQUEST_TYPE_EMERGENCY_FAILOVER,
                    REQUEST_TYPE_EMERGENCY_FAILBACK,
                }:
                    expires_at = min(expires_at, now + EMERGENCY_TTL_SECONDS)
                else:
                    expires_at = now + self.approved_ttl
                if approval_required == 1 and state.get("approval_mode_expires_at") is not None:
                    expires_at = min(expires_at, float(state["approval_mode_expires_at"]))
            status = "EXECUTING" if len(approvers) >= approval_required else "PARTIALLY_APPROVED"
            execution_started_at = state.get("execution_started_at")
            execution_heartbeat_at = state.get("execution_heartbeat_at")
            execution_lease_until = state.get("execution_lease_until")
            execution_id = state.get("execution_id")
            if status == "EXECUTING":
                execution_started_at = now
                execution_heartbeat_at = now
                execution_lease_until = now + self.execution_lease_seconds
                execution_id = str(uuid.uuid4())
            incidents = state.get("incidents") or []
            if is_synthetic_demo and status == "EXECUTING":
                latest = dict(incidents[-1])
                authorization = dict(latest[SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD])
                authorization.update({
                    "status": "APPROVED_FOR_SYNTHETIC_EXECUTION",
                    "approved_at": now,
                    "approval_count": 1,
                    "approver_ids": list(approvers),
                    "execution_id": execution_id,
                })
                latest[SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD] = authorization
                incidents[-1] = latest
            if (is_dump_request or is_auto_failover) and incidents:
                latest = dict(incidents[-1])
                authorization = latest.get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
                if isinstance(authorization, dict):
                    authorization = dict(authorization)
                    authorization["expires_at"] = expires_at
                else:
                    authorization = None
                candidate = (
                    latest.get(FAILOVER_RECOVERY_PLAN_FIELD, {}).get("dump")
                    if is_auto_failover else None
                )
                grant_ready = (
                    authorization is not None
                    and (not is_auto_failover or (
                        isinstance(candidate, dict) and candidate.get("status") == "READY"
                    ))
                )
                if status == "EXECUTING" and grant_ready:
                    authorization.update({
                        "status": "APPROVED_BY_TWO_DISTINCT_ADMINS",
                        "approved_at": now,
                        "approval_required": REQUIRED_APPROVALS,
                        "approval_count": REQUIRED_APPROVALS,
                        "approver_ids": list(approvers),
                        "execution_id": execution_id,
                    })
                if authorization is not None:
                    latest[DEMO_DUMP_OVERWRITE_AUTH_FIELD] = authorization
                    incidents[-1] = latest
            connection.execute(
                """
                UPDATE approval_requests
                SET status = ?, approvers = ?, first_approved_at = ?, expires_at = ?,
                    execution_started_at = ?, execution_heartbeat_at = ?,
                    execution_lease_until = ?, execution_id = ?, incidents = ?
                WHERE request_id = ?
                """,
                (
                    status,
                    json.dumps(approvers, ensure_ascii=True),
                    first_approved_at,
                    expires_at,
                    execution_started_at,
                    execution_heartbeat_at,
                    execution_lease_until,
                    execution_id,
                    json.dumps(incidents, ensure_ascii=True),
                    request_id,
                ),
            )
            connection.commit()
            return ("approved" if status == "EXECUTING" else "pending"), self.get(request_id)

    def cancel(self, request_id, action, now=None, cancelled_by=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return "missing", None
            state = self._decode(row)
            if state["action"] != action:
                connection.commit()
                return "action_mismatch", state
            if state["status"] == "EXECUTING":
                connection.commit()
                return "executing", state
            if state["status"] in TERMINAL_STATUSES:
                connection.commit()
                return "closed", state
            incidents = _mark_dump_overwrite_authorization(
                state.get("incidents"), "CANCELLED", at=now,
            )
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'CANCELLED', approvers = '[]', expires_at = ?,
                    finished_at = ?, cancelled_by = ?, result = 'cancelled',
                    execution_lease_until = NULL, incidents = ?
                WHERE request_id = ?
                """,
                (now, now, cancelled_by, json.dumps(incidents, ensure_ascii=True), request_id),
            )
            connection.commit()
            return "cancelled", self.get(request_id)

    def heartbeat(self, request_id, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE approval_requests
                SET execution_heartbeat_at = ?, execution_lease_until = ?
                WHERE request_id = ? AND status = 'EXECUTING'
                """,
                (now, now + self.execution_lease_seconds, request_id),
            )
            connection.commit()
            return cursor.rowcount == 1

    def finish(self, request_id, succeeded, result=None, terminal_status=None):
        default_status = "SUCCEEDED" if succeeded else "FAILED"
        status = terminal_status or default_status
        if status not in {
            "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE", "FAILED", "PARTIAL_FAILURE"
        }:
            raise ValueError("unsupported execution terminal status")
        if succeeded != (status == "SUCCEEDED"):
            raise ValueError("execution success flag and terminal status disagree")
        finished_at = utc_timestamp()
        result = result or ("success" if succeeded else "failed")
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = ?, finished_at = ?, result = ?, execution_lease_until = NULL
                WHERE request_id = ? AND status IN ('PENDING', 'PARTIALLY_APPROVED', 'EXECUTING')
                """,
                (status, finished_at, result, request_id),
            )
            connection.commit()
        return self.get(request_id)


class SlackApiError(RuntimeError):
    def __init__(self, method, error):
        self.method = method
        self.error = error
        super().__init__(f"Slack API {method} failed: {error}")


class SlackClient:
    def __init__(self, token, channel_id):
        self.token = token
        self.channel_id = channel_id

    @property
    def available(self):
        return bool(self.token and self.channel_id)

    def _call(self, method, payload, timeout=10):
        response = requests.post(
            f"https://slack.com/api/{method}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            raise SlackApiError(method, data.get("error", "unknown_error"))
        return data

    def post_message(self, text, blocks):
        return self._call(
            "chat.postMessage",
            {"channel": self.channel_id, "text": text, "blocks": blocks},
        )

    def update_message(self, channel_id, message_ts, text, blocks):
        return self._call(
            "chat.update",
            {"channel": channel_id, "ts": message_ts, "text": text, "blocks": blocks},
        )

    def message_exists(self, channel_id, message_ts):
        """Check a message without mutating Slack or the message itself."""
        self._call(
            "chat.getPermalink",
            {"channel": channel_id, "message_ts": message_ts},
        )
        return True

    def delete_message(self, channel_id, message_ts):
        return self._call(
            "chat.delete",
            {"channel": channel_id, "ts": message_ts},
        )

    def open_view(self, trigger_id, view):
        started = time.monotonic()
        try:
            # Slack invalidates interaction trigger_ids quickly and expects an
            # acknowledgement within 3 seconds. Bound this API call so a slow
            # network cannot leave the user with Slack's generic retry screen.
            result = self._call(
                "views.open",
                {"trigger_id": trigger_id, "view": view},
                timeout=(0.75, 1.25),
            )
        except SlackApiError as exc:
            error_code = re.sub(r"[^A-Za-z0-9_-]", "", str(exc.error))[:80] or "unknown"
            elapsed_ms = int((time.monotonic() - started) * 1000)
            print(
                f"[SLACK MODAL] views.open failed error={error_code} duration_ms={elapsed_ms}",
                flush=True,
            )
            raise
        except requests.RequestException as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            print(
                f"[SLACK MODAL] views.open transport_error={type(exc).__name__} "
                f"duration_ms={elapsed_ms}",
                flush=True,
            )
            raise
        elapsed_ms = int((time.monotonic() - started) * 1000)
        print(f"[SLACK MODAL] views.open success duration_ms={elapsed_ms}", flush=True)
        return result

    def update_view(self, view_id, view):
        return self._call("views.update", {"view_id": view_id, "view": view})

    def pin_message(self, channel_id, message_ts):
        return self._call("pins.add", {"channel": channel_id, "timestamp": message_ts})


def action_label(action):
    return "DR FAILOVER" if action == "failover" else "WEB+DOC+DB FAILBACK"


def status_label(status):
    return {
        "PENDING": "PENDING / 승인 대기",
        "PARTIALLY_APPROVED": "PENDING / 추가 승인 대기",
        "EXECUTING": "EXECUTING / 실행 중",
        "SUCCEEDED": "SUCCEEDED / 완료",
        "DB_RESTORED_NOT_FAILOVER_COMPLETE": "DB 복원 완료 / 전체 Failover 미완료",
        "FAILED": "FAILED / 실패",
        "CANCELLED": "CANCELLED / 취소",
        "EXPIRED": "EXPIRED / 만료",
    }.get(status, status)


def safe_mrkdwn(value, limit=300):
    text = str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text[:limit]


def button_value(request_id, action, operation, **extra):
    value = {"request_id": request_id, "action": action, "operation": operation}
    value.update({key: item for key, item in extra.items() if item is not None})
    return json.dumps(value, separators=(",", ":"))


def valid_slack_signature(signing_secret, raw_body, timestamp, signature, now=None):
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        request_time = int(timestamp)
    except (TypeError, ValueError):
        return False
    current_time = int(utc_timestamp() if now is None else now)
    if abs(current_time - request_time) > SLACK_SIGNATURE_MAX_AGE_SECONDS:
        return False
    base = b"v0:" + str(request_time).encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def remember_slack_request(replay_cache, replay_lock, timestamp, signature, now=None):
    """Accept a valid Slack request signature only once within its replay window."""
    now = int(time.time()) if now is None else int(now)
    cutoff = now - SLACK_SIGNATURE_MAX_AGE_SECONDS
    cache_key = (str(timestamp), str(signature))
    with replay_lock:
        expired = [key for key, seen_at in replay_cache.items() if seen_at < cutoff]
        for key in expired:
            replay_cache.pop(key, None)
        if cache_key in replay_cache:
            return False
        if len(replay_cache) >= SLACK_REPLAY_CACHE_SIZE:
            oldest_key = min(replay_cache, key=replay_cache.get)
            replay_cache.pop(oldest_key, None)
        replay_cache[cache_key] = now
        return True


def failback_security_from_state(state):
    if state.get("action") != "failback":
        return "READY", "", "-", "-"
    for incident in reversed(state.get("incidents") or []):
        if "security_status" in incident:
            return (
                incident.get("security_status") or "UNKNOWN",
                incident.get("security_reason") or "Security readiness was not evaluated.",
                incident.get("security_agents") or "-",
                incident.get("security_critical_incident") or "-",
            )
    return "UNKNOWN", "Security readiness was not evaluated.", "-", "-"


def failback_risk_from_state(state):
    if state.get("action") != "failback":
        return "NORMAL", "-", "-", ""
    for incident in reversed(state.get("incidents") or []):
        if "wazuh_risk_level" in incident:
            return (
                incident.get("wazuh_risk_level") or "UNKNOWN",
                incident.get("wazuh_risk_observed_at") or "-",
                incident.get("wazuh_risk_checked_at") or "-",
                incident.get("wazuh_risk_reason") or "Wazuh risk was not evaluated.",
            )
    return "UNKNOWN", "-", "-", "Wazuh risk data is unavailable."


def failback_risk_confirmation(risk_level):
    """Return Slack's native button confirmation only for high risk states."""
    level = str(risk_level or "UNKNOWN").strip().upper()
    if level not in {"HIGH", "CRITICAL"}:
        return None
    return {
        "title": {"type": "plain_text", "text": f"Wazuh 위험도 {level} 확인"},
        "text": {
            "type": "mrkdwn",
            "text": (
                f"최근 Wazuh 위험도가 *{level}*입니다. 위험을 확인하고 승인 동작을 계속할까요? "
                "이 확인은 관리자 2인 승인이나 별도 실행 안전 검사를 대신하지 않습니다."
            ),
        },
        "confirm": {"type": "plain_text", "text": "위험 확인 후 승인"},
        "deny": {"type": "plain_text", "text": "취소"},
    }


def failback_db_overwrite_confirmation(request_id, risk_level):
    """Require an explicit request-scoped Slack confirmation for DB overwrite."""
    text = (
        "이 Failback은 AWS DR의 최신 데이터를 On-Prem `hospital_db`에 복원해 "
        "기존 데이터를 덮어씁니다. 요청별 기존 DB 사전 백업이 완료된 뒤 진행합니다. "
        f"요청 ID `{request_id}`의 DB 덮어쓰기를 확인하고 승인을 계속할까요?"
    )
    level = str(risk_level or "UNKNOWN").strip().upper()
    if level in {"HIGH", "CRITICAL"}:
        text += (
            f"\n최근 Wazuh 위험도는 *{level}*입니다. 이 확인은 2인 승인 및 "
            "실행 단계의 데이터·서비스 검증을 대신하지 않습니다."
        )
    return {
        "title": {"type": "plain_text", "text": "On-Prem DB 덮어쓰기 확인"},
        "text": {"type": "mrkdwn", "text": text},
        "confirm": {"type": "plain_text", "text": "덮어쓰기 확인 후 승인"},
        "deny": {"type": "plain_text", "text": "취소"},
    }


def failback_overwrite_approval_error(state, request_id, admin_ids):
    """Validate the final Failback quorum before granting DB overwrite to a child."""
    if not isinstance(state, dict) or state.get("action") != "failback":
        return "failback_request_invalid"
    if state.get("request_id") != request_id or state.get("status") != "EXECUTING":
        return "failback_request_not_finally_approved"
    try:
        if str(uuid.UUID(str(request_id))) != str(request_id).lower():
            return "failback_request_id_invalid"
    except (TypeError, ValueError, AttributeError):
        return "failback_request_id_invalid"
    approvers = state.get("approvers")
    if (
        state.get("approval_required") != REQUIRED_APPROVALS
        or not isinstance(approvers, list)
        or len(approvers) != REQUIRED_APPROVALS
        or not isinstance(admin_ids, set)
        or any(not isinstance(user_id, str) or user_id not in admin_ids for user_id in approvers)
        or len(set(approvers)) != REQUIRED_APPROVALS
    ):
        return "failback_two_admin_approval_invalid"
    return None


def failback_risk_snapshot_changed(rendered, current):
    """Require a fresh click if its rendered risk differs from click-time risk."""
    if not isinstance(rendered, dict) or not isinstance(current, dict):
        return True
    valid_levels = {"LOW", "MEDIUM", "NORMAL", "HIGH", "CRITICAL", "UNKNOWN"}
    rendered_level = str(rendered.get("wazuh_risk_level") or "").strip().upper()
    current_level = str(current.get("risk_level") or "UNKNOWN").strip().upper()
    if rendered_level not in valid_levels or current_level not in valid_levels:
        return True
    if rendered_level != current_level:
        return True
    if current_level in {"HIGH", "CRITICAL"}:
        rendered_observed = str(rendered.get("wazuh_risk_observed_at") or "-").strip()
        current_observed = str(current.get("risk_observed_at") or "-").strip()
        return rendered_observed != current_observed
    return False


def failback_network_from_state(state):
    """Return the persisted network gate without failing open."""
    if state.get("action") != "failback":
        return "READY", "", "-", {}
    for incident in reversed(state.get("incidents") or []):
        if "network_status" in incident:
            return (
                incident.get("network_status") or "UNKNOWN",
                incident.get("network_reason") or "Network readiness was not evaluated.",
                incident.get("network_source") or "-",
                incident.get("network_devices") or {},
            )
    return "UNKNOWN", "Network readiness was not evaluated.", "-", {}


def failback_stability_from_state(state):
    """Return compatibility metadata for the immediate Recovery policy.

    Older requests may still carry stability fields, so their elapsed value
    is preserved for display.  The active policy has no sustained recovery
    gate; every Failback request is therefore considered timing-ready.
    """
    if state.get("action") != "failback":
        return True, 0, 0
    for incident in reversed(state.get("incidents") or []):
        if "stability_verified" in incident:
            try:
                seconds = int(incident.get("stability_seconds") or 0)
            except (TypeError, ValueError):
                seconds = 0
            return True, seconds, 0
    return True, 0, 0


def evaluate_current_failback_security(app):
    """Evaluate the configured Wazuh snapshot/provider without failing open."""
    try:
        from wazuh_failback_gate import evaluate_failback_risk, evaluate_failback_security

        provider = app.config.get("WAZUH_SECURITY_STATE_PROVIDER")
        snapshot = provider() if callable(provider) else app.config.get("WAZUH_FAILBACK_SECURITY_SNAPSHOT")
        required_agents = app.config.get("WAZUH_FAILBACK_REQUIRED_AGENTS", ())
        if isinstance(required_agents, str):
            required_agents = tuple(item.strip() for item in required_agents.split(",") if item.strip())
        security = evaluate_failback_security(snapshot, required_agents=required_agents)
        provider_owner = getattr(provider, "__self__", None)
        lookback_minutes = getattr(
            provider_owner,
            "lookback_minutes",
            snapshot.get("lookback_minutes", 15) if isinstance(snapshot, dict) else 15,
        )
        try:
            max_age_seconds = int(lookback_minutes) * 60
        except (TypeError, ValueError):
            max_age_seconds = 0
        risk = evaluate_failback_risk(snapshot, max_age_seconds=max_age_seconds)
        if security.get("status") == "UNKNOWN":
            risk.update(
                {
                    "risk_level": "UNKNOWN",
                    "risk_reason": "Wazuh security snapshot is incomplete or stale.",
                }
            )
        return {**security, **risk}
    except Exception:
        return {
            "status": "UNKNOWN",
            "reason": "Wazuh security state could not be evaluated.",
            "agents": "UNKNOWN",
            "critical_incident": "-",
            "risk_level": "UNKNOWN",
            "risk_observed_at": "-",
            "risk_checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "risk_reason": "Wazuh security state could not be evaluated.",
        }


def evaluate_current_network_health(app):
    """Evaluate the read-only Zabbix/SNMP network gate fail-closed."""
    if not app.config.get("NETWORK_DR_HEALTH_ENABLED", True):
        return {
            "status": "UNKNOWN",
            "reason": "Network DR health gate is disabled; Failback is fail-closed.",
            "source": "CONFIGURATION",
            "checked_at": "-",
            "devices": {},
        }
    try:
        provider = app.config.get("NETWORK_DR_HEALTH_PROVIDER")
        snapshot = provider() if callable(provider) else app.config.get("NETWORK_DR_HEALTH_SNAPSHOT")
        if snapshot is None and app.testing:
            # Unit/dry-run applications must supply a fixture in production;
            # this test-only default preserves the existing no-Slack dry-run.
            snapshot = {
                "status": "READY",
                "reason": "test fixture default",
                "source": "TEST_FIXTURE",
                "checked_at": "-",
                "devices": {},
            }
        if not isinstance(snapshot, dict):
            raise ValueError("network health provider returned a non-object")
        status = snapshot.get("status")
        if status not in {"READY", "NOT_READY", "UNKNOWN"}:
            raise ValueError("network health provider returned an invalid status")
        return snapshot
    except Exception:
        return {
            "status": "UNKNOWN",
            "reason": "Zabbix network health could not be evaluated.",
            "source": "ZABBIX_SNMP_AVAILABILITY",
            "checked_at": "-",
            "devices": {},
        }


def _configured_snapshot(app, name):
    snapshot = app.config.get(name)
    return dict(snapshot) if isinstance(snapshot, dict) else None


def evaluate_emergency_precheck(app, action, request_type, backup=None, failback_security=None):
    """Run non-mutating safety checks immediately before an emergency approval."""
    supplied = _configured_snapshot(app, "EMERGENCY_PRECHECK_SNAPSHOT")
    if supplied is not None:
        status = supplied.get("status", "UNKNOWN")
        if status not in {"PASS", "WARNING", "FAILED"}:
            status = "UNKNOWN"
        reason = str(supplied.get("reason") or "Configured pre-check fixture")[:300]
        if action == "failback" and failback_security is not None:
            security_status = str(failback_security.get("status") or "UNKNOWN")
            if security_status == "BLOCKED":
                status = "FAILED"
                reason = f"Wazuh security gate is {security_status}: {failback_security.get('reason') or 'not ready'}"
            elif security_status != "READY":
                if status == "PASS":
                    status = "WARNING"
                reason = f"{reason}; Wazuh is {security_status}: {failback_security.get('reason') or 'status unavailable'}"
        return {
            "status": status,
            "reason": reason[:500],
            "checks": supplied.get("checks") or {},
        }

    checks = {}
    failures = []
    warnings = []
    executing = app.extensions["approval_store"].find_executing()
    checks["execution_lock"] = "PASS" if executing is None else "FAILED"
    if executing is not None:
        failures.append("another DR operation is executing")

    dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
    if action == "failover":
        # The shared full_failover.sh runner only accepts IDLE or FAILED.
        # Keep both normal and emergency approval pre-checks aligned so an
        # approval is not presented as runnable when the runner will reject
        # the persisted state.
        allowed_failover_states = {"IDLE", "FAILED"}
        state_ok = dr_state in allowed_failover_states
    else:
        state_ok = dr_state == "DR_ACTIVE"
    checks["current_state"] = "PASS" if state_ok else "FAILED"
    if not state_ok:
        failures.append(f"current DR state is {dr_state or 'UNKNOWN'}")

    script_name = "full_failover.sh" if action == "failover" else "web_db_failback.sh"
    script_path = os.path.join(app.config["DR_SCRIPT_ROOT"], script_name)
    runtime_ok = os.path.isfile(script_path) and os.access(script_path, os.R_OK)
    checks["iac_runtime"] = "PASS" if runtime_ok else "FAILED"
    if not runtime_ok:
        failures.append("required DR runtime script is unavailable")

    for check_name, config_name in (
        ("aws_access", "EMERGENCY_AWS_STATUS"),
        ("db_access", "EMERGENCY_DB_STATUS"),
    ):
        value = str(app.config.get(config_name) or "UNKNOWN").upper()
        checks[check_name] = value if value in {"PASS", "WARNING", "FAILED"} else "UNKNOWN"
        if checks[check_name] == "FAILED":
            failures.append(f"{check_name} failed")
        elif checks[check_name] != "PASS":
            warnings.append(f"{check_name} is {checks[check_name]}")

    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        selected = backup or {}
        legacy_manual = (
            selected.get("dump_restore_mode", selected.get("restore_mode"))
            == "LEGACY_MANUAL"
        )
        resolved = resolve_dump_backup(
            app.config["DUMP_BACKUP_DIR"],
            selected.get("backup_id"),
            allow_legacy_manual=legacy_manual,
            encryption_key=app.config.get("DB_BACKUP_ENCRYPTION_KEY"),
        )
        checks["dump_backup"] = "PASS" if resolved else "FAILED"
        if not resolved:
            failures.append("selected dump is missing or incomplete")
        expected_checksum = str(
            selected.get("expected_checksum")
            or selected.get("backup_checksum")
            or selected.get("checksum")
            or ""
        ).strip().lower()
        checksum_matches = bool(
            resolved
            and re.fullmatch(r"[0-9a-f]{64}", expected_checksum)
            and hmac.compare_digest(resolved["checksum"].lower(), expected_checksum)
        )
        checks["dump_checksum"] = "PASS" if checksum_matches else "FAILED"
        if not checksum_matches:
            failures.append("selected dump checksum is missing or changed")
        if legacy_manual:
            expected_sidecar_checksum = str(
                selected.get("expected_sidecar_checksum")
                or selected.get("backup_sidecar_checksum")
                or selected.get("sidecar_checksum")
                or ""
            ).strip().lower()
            sidecar_matches = bool(
                resolved
                and re.fullmatch(r"[0-9a-f]{64}", expected_sidecar_checksum)
                and hmac.compare_digest(
                    resolved["sidecar_checksum"].lower(), expected_sidecar_checksum
                )
            )
            checks["dump_sidecar"] = "PASS" if sidecar_matches else "FAILED"
            if not sidecar_matches:
                failures.append("selected Legacy sidecar is missing or changed")
            checks["dump_restore_mode"] = "LEGACY_MANUAL"
            warnings.append(
                "Legacy dump has no Manifest; RPO=NOT_MEASURED. Restore requires its request-bound overwrite grant and two distinct administrator approvals"
            )
        if not app.config.get("DUMP_RESTORE_EXEC_ENABLED"):
            # The executor flag gates destructive execution, not recording the
            # required two-person approval. Keep the UI/approval workflow
            # usable while clearly reporting that the restore will not run.
            checks["dump_executor"] = "DISABLED"
            warnings.append("dump restore executor is disabled; restore will not run")
        else:
            executor_error = dump_restore_executor_error(app.config)
            checks["dump_executor"] = "CONFIGURED" if executor_error is None else "FAILED"
            if executor_error:
                failures.append(f"dump restore executor {executor_error}")

    security = failback_security or evaluate_current_failback_security(app)
    checks["wazuh"] = security.get("status", "UNKNOWN")
    if action == "failback" and checks["wazuh"] == "BLOCKED":
        failures.append(f"Wazuh security gate is {checks['wazuh']}")
    elif checks["wazuh"] != "READY":
        warnings.append(f"Wazuh is {checks['wazuh']}")

    if failures:
        status = "FAILED"
        reason = "; ".join(failures)
    elif warnings:
        status = "WARNING"
        reason = "; ".join(warnings)
    else:
        status = "PASS"
        reason = "all emergency safety checks passed"
    return {
        "status": status,
        "reason": reason[:500],
        "checks": checks,
        "wazuh_risk": {
            "risk_level": security.get("risk_level", "UNKNOWN"),
            "risk_observed_at": security.get("risk_observed_at", "-"),
            "risk_checked_at": security.get("risk_checked_at", "-"),
            "risk_reason": security.get("risk_reason", "Wazuh risk was not evaluated."),
        },
    }


def _status_timestamp(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return "UNKNOWN"


def _execution_record_category(row):
    """Classify a stored request only when its persisted workflow contract agrees."""
    try:
        incidents = json.loads(row.get("incidents") or "[]")
    except (TypeError, json.JSONDecodeError):
        return None, "request_record_invalid"
    if not isinstance(incidents, list) or not incidents or not isinstance(incidents[-1], dict):
        return None, "request_type_unavailable"

    incident = incidents[-1]
    action = str(row.get("action") or "")
    explicit_type = str(incident.get("request_type") or "").strip()
    origin = str(incident.get("request_origin") or "").strip().upper()
    source = str(incident.get("source") or "").strip()
    client_key = str(row.get("slack_client_key") or incident.get("slack_client_key") or "").strip()

    if action == "failover":
        if explicit_type == REQUEST_TYPE_DUMP_RESTORE:
            contracts = {
                "GENERAL": ("failover", "dump_restore_console", "general_dump"),
                "EMERGENCY": (
                    "emergency", "emergency_dump_restore_console", "emergency_dump"
                ),
            }
            contract = contracts.get(origin)
            if contract and (client_key, source) == contract[:2]:
                return contract[2], None
            return None, "dump_request_origin_or_source_mismatch"
        if explicit_type == REQUEST_TYPE_EMERGENCY_FAILOVER:
            if (
                origin == "EMERGENCY"
                and client_key == "emergency"
                and source == "emergency_console"
            ):
                return "emergency_failover", None
            return None, "emergency_failover_source_mismatch"
        if explicit_type not in {"", "NORMAL_FAILOVER"}:
            return None, "failover_request_type_unknown"
        if client_key != "failover" or origin not in {
            "", "GENERAL", ZABBIX_PRODUCTION_ACTION_NAME.upper()
        }:
            return None, "general_failover_source_unverified"
        if source in {"dump_restore_console", "emergency_dump_restore_console", "emergency_console"}:
            return None, "general_failover_source_mismatch"
        if origin == ZABBIX_PRODUCTION_ACTION_NAME.upper() and not (
            source == "zabbix" and incident.get("production_action_verified") is True
        ):
            return None, "production_action_source_unverified"
        if source == "zabbix" and origin != ZABBIX_PRODUCTION_ACTION_NAME.upper():
            return None, "zabbix_failover_source_unverified"
        if source not in {"", "manual", "zabbix"}:
            return None, "general_failover_source_unrecognized"
        return "general_failover", None

    if action == "failback":
        if explicit_type == REQUEST_TYPE_EMERGENCY_FAILBACK:
            if (
                origin == "EMERGENCY"
                and client_key == "emergency"
                and source == "emergency_console"
            ):
                return "failback", None
            return None, "emergency_failback_source_mismatch"
        if explicit_type not in {"", "NORMAL_FAILBACK"}:
            return None, "failback_request_type_unknown"
        if client_key != "failback" or origin not in {"", "GENERAL"}:
            return None, "general_failback_source_unverified"
        if source not in {"", "manual", "zabbix"}:
            return None, "general_failback_source_mismatch"
        return "failback", None

    return None, "request_action_unknown"


def _execution_start_evidence(app, row, is_dump):
    """Use the request-scoped post-Popen log marker, not the approval timestamp."""
    request_id = str(row.get("request_id") or "")
    if not request_id or not row.get("execution_id") or row.get("execution_started_at") is None:
        return "UNVERIFIED"
    path = execution_log_path(app, request_id)
    if path is None:
        return "UNVERIFIED"
    lines, _total, error = read_execution_log(path, limit=500)
    if error:
        return "UNVERIFIED"

    start_marker = (
        "Dump Executor started; Slack log receives only allowlisted structured phase events."
        if is_dump else "Workflow process started; streaming sanitized output."
    )
    if start_marker in lines:
        return "VERIFIED"
    if any(
        "execution was not started" in line
        or "executor_started=false;" in line
        or "before the workflow started" in line
        for line in lines
    ):
        return "NOT_STARTED"
    return "UNVERIFIED"


def _execution_type_label(row, category):
    labels = {
        "general_failover": "GENERAL_FAILOVER",
        "emergency_failover": "EMERGENCY_FAILOVER",
        "general_dump": "GENERAL_DUMP_RESTORE",
        "emergency_dump": "EMERGENCY_DUMP_RESTORE",
    }
    if category != "failback":
        return labels.get(category, "UNKNOWN")
    try:
        incidents = json.loads(row.get("incidents") or "[]")
        incident = incidents[-1] if incidents and isinstance(incidents[-1], dict) else {}
    except (TypeError, json.JSONDecodeError):
        incident = {}
    return (
        "EMERGENCY_FAILBACK"
        if incident.get("request_type") == REQUEST_TYPE_EMERGENCY_FAILBACK
        else "GENERAL_FAILBACK"
    )


def _stored_result_code(value):
    raw = str(value or "UNKNOWN")
    return raw if re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", raw) else "UNVERIFIED"


def _latest_execution_status(app, row, type_label):
    """Render one typed terminal row without inferring a launch from approval."""
    request_id = str(row.get("request_id") or "UNKNOWN")
    raw_status = str(row.get("status") or "UNKNOWN")
    result_code = _stored_result_code(row.get("result"))
    is_dump = type_label in {"GENERAL_DUMP_RESTORE", "EMERGENCY_DUMP_RESTORE"}
    start = _execution_start_evidence(app, row, is_dump)
    try:
        approvers = json.loads(row.get("approvers") or "[]")
        if not isinstance(approvers, list):
            raise ValueError("approver record is not a list")
        approved = len({item for item in approvers if isinstance(item, str) and item})
        required = int(row.get("approval_required") or REQUIRED_APPROVALS)
        if required < 1:
            raise ValueError("approval requirement is invalid")
        approval_text = f"{approved}/{required}"
    except (TypeError, ValueError, json.JSONDecodeError):
        approval_text = "UNVERIFIED"
    finished_at = _status_timestamp(row.get("finished_at"))

    if raw_status == "SUCCEEDED":
        # A terminal ChatOps result proves only that the configured runner
        # returned success. It does not prove DB, application, DNS, and
        # single-writer recovery evidence for the end-to-end workflow.
        display_status = (
            "RUNNER_SUCCEEDED_E2E_UNVERIFIED"
            if start == "VERIFIED"
            else "UNVERIFIED"
        )
    elif raw_status == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        display_status = raw_status if start == "VERIFIED" else "UNVERIFIED"
    elif raw_status == "PARTIAL_FAILURE":
        display_status = "PARTIAL_FAILURE"
    elif raw_status == "FAILED" and is_dump and result_code == "dump_restore_disabled":
        display_status = "UNVERIFIED" if start == "VERIFIED" else "BLOCKED_BEFORE_EXECUTION"
    elif raw_status == "FAILED" and start == "VERIFIED":
        display_status = "FAILED"
    elif raw_status == "FAILED" and start == "NOT_STARTED":
        display_status = "BLOCKED_BEFORE_EXECUTION"
    else:
        display_status = "UNVERIFIED"

    detail = (
        f"유형={type_label}; 기록상태={raw_status}; 기록시각={finished_at}; 승인기록={approval_text}; "
        f"실행 시작={start}; 저장결과={result_code}; 요청ID={request_id}"
    )
    if raw_status == "SUCCEEDED":
        detail += "; E2E=UNVERIFIED (ChatOps 실행기 결과만 확인; 전체 복구 증거는 별도 검증 필요)"
    if is_dump and result_code == "dump_restore_disabled":
        if start == "VERIFIED":
            detail += "; 비활성 차단 코드와 프로세스 시작 증거가 충돌하여 결과 미확정"
        else:
            detail += "; DB 복원 실패가 아니라 실행 전 비활성 차단"
    elif raw_status == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        detail += "; DB 복원 단계만 완료, 전체 Failover 미완료"
    return display_status, detail


def _latest_typed_execution(app, action, categories):
    try:
        rows = app.extensions["approval_store"].peek_terminal_results(action)
    except Exception as exc:
        detail = f"기록 조회 실패 ({type(exc).__name__})"
        return {category: ("UNVERIFIED", detail) for category in categories}, ("UNVERIFIED", detail)

    selected = {category: None for category in categories}
    latest_unclassified = None
    for row in rows:
        category, _reason = _execution_record_category(row)
        if category in selected and selected[category] is None:
            selected[category] = row
        elif category is None and latest_unclassified is None:
            latest_unclassified = row

    result = {}
    for category in categories:
        row = selected[category]
        if row is None:
            result[category] = ("NO_RECORD", "해당 유형의 완료 기록 없음")
        else:
            result[category] = _latest_execution_status(
                app, row, _execution_type_label(row, category)
            )

    if latest_unclassified is None:
        unknown = ("NO_RECORD", "유형이 불명확한 완료 기록 없음")
    else:
        _category, reason = _execution_record_category(latest_unclassified)
        unknown = (
            "UNVERIFIED",
            f"유형/출처 검증 불가; 사유={reason or 'unknown'}; "
            f"기록시각={_status_timestamp(latest_unclassified.get('finished_at'))}; "
            f"요청ID={latest_unclassified.get('request_id') or 'UNKNOWN'}",
        )
    return result, unknown


def _rto_measurement_status(app):
    path = app.config.get("DR_RTO_TIMELINE_FILE") or default_rto_timeline_path()
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        runs = document.get("runs") if isinstance(document, dict) else None
        if not isinstance(runs, list):
            raise ValueError("timeline runs are unavailable")
        if not runs:
            return "UNVERIFIED", "NOT_MEASURED; no correlated RTO run is recorded"
        summary = calculate_rto_run(runs[-1])
    except FileNotFoundError:
        return "UNVERIFIED", "NOT_MEASURED; RTO timeline is missing"
    except (
        OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError,
        RuntimeError, AttributeError, OverflowError,
    ):
        return "UNVERIFIED", "NOT_MEASURED; RTO timeline could not be verified"

    measured = summary.get("total_rto_seconds")
    if measured is None or summary.get("rto_target_result") == "NOT_MEASURED":
        return "UNVERIFIED", "NOT_MEASURED; latest correlated run is incomplete"
    outcome = summary.get("rto_target_result")
    status = "PASS" if outcome == "PASS" else "BLOCKED"
    detail = (
        f"{outcome}: {measured:g}s / target {summary.get('target_seconds')}s; "
        f"basis={summary.get('measurement_basis', 'UNKNOWN')}"
    )
    return status, detail


def _wazuh_failback_status(app):
    provider = app.config.get("WAZUH_SECURITY_STATE_PROVIDER")
    snapshot = app.config.get("WAZUH_FAILBACK_SECURITY_SNAPSHOT")
    required_agents = app.config.get("WAZUH_FAILBACK_REQUIRED_AGENTS", ())
    if isinstance(required_agents, str):
        required_agents = tuple(item.strip() for item in required_agents.split(",") if item.strip())
    if not (callable(provider) or isinstance(snapshot, dict)) or not required_agents:
        return "BLOCKED", "Wazuh source or required-agent configuration is missing; Failback remains fail-closed"
    security = evaluate_current_failback_security(app)
    if security.get("status") == "READY":
        return "PASS", "current configured Wazuh security gate is READY"
    return "BLOCKED", "current Wazuh verification is not READY; Failback remains fail-closed"


def build_emergency_status(app):
    """Build a redacted read-only status response for the console button."""
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    status = {"Checked At (UTC)": checked_at}
    status["Emergency Channel"] = (
        "CONFIGURED" if app.config.get("SLACK_EMERGENCY_CHANNEL_ID") else "NOT_CONFIGURED"
    )

    try:
        state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
        status["DR State"] = state or "UNKNOWN"
        if not state:
            status["DR State Detail"] = "persistent state is missing or unreadable"
    except Exception as exc:
        status["DR State"] = "UNKNOWN"
        status["DR State Detail"] = f"read failed ({type(exc).__name__})"

    # The current status path has no live Zabbix Trigger/Action reader. Never
    # present an earlier report (including Trigger 24712's last-known state)
    # as the current production detection state.
    status["Failover Detection"] = "UNVERIFIED"
    status["Failover Detection Detail"] = (
        "live Production Trigger/Action state is not queried here; prior Trigger 24712 reports are not current state"
    )

    dump_enabled = as_bool(app.config.get("DUMP_RESTORE_EXEC_ENABLED", False))
    dump_executor = str(app.config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
    if not dump_enabled:
        status["Dump Execution Gate"] = "DISABLED"
        status["Dump Execution Gate Detail"] = "DUMP_RESTORE_EXEC_ENABLED is false in this ChatOps process"
    elif dump_executor:
        status["Dump Execution Gate"] = "PASS"
        status["Dump Execution Gate Detail"] = (
            "execution opt-in and executor path are configured; this status check does not execute or validate the executor"
        )
    else:
        status["Dump Execution Gate"] = "BLOCKED"
        status["Dump Execution Gate Detail"] = "execution opt-in is true but no executor path is configured"

    try:
        executing = app.extensions["approval_store"].peek_executing()
        status["Execution Lock"] = (
            "FREE" if executing is None else request_type_from_state(executing)
        )
    except Exception as exc:
        status["Execution Lock"] = "UNKNOWN"
        status["Execution Lock Detail"] = f"read failed ({type(exc).__name__})"

    aws_status = app.config.get("EMERGENCY_AWS_STATUS")
    onprem_status = app.config.get("EMERGENCY_ONPREM_STATUS")
    status["AWS Status"] = str(aws_status or "UNKNOWN")
    status["On-Prem Status"] = str(onprem_status or "UNKNOWN")
    if not aws_status:
        status["AWS Status Detail"] = "live status source is not configured"
    if not onprem_status:
        status["On-Prem Status Detail"] = "live status source is not configured"

    nr_enabled = as_bool(app.config.get("DB_NR_ENABLED", False))
    status["DB NR Status"] = "UNVERIFIED" if nr_enabled else "DISABLED"
    if nr_enabled:
        status["DB NR Status Detail"] = "NR is enabled, but this status path has no live replication-status query"

    try:
        dumps = list_dump_backups(app.config["DUMP_BACKUP_DIR"], limit=1)
        status["Latest Dump"] = (
            str(dumps[0].get("timestamp") or dumps[0].get("backup_timestamp") or "UNKNOWN")
            if dumps
            else "UNKNOWN"
        )
        if not dumps:
            status["Latest Dump Detail"] = "no valid backup pair was found"
    except Exception as exc:
        status["Latest Dump"] = "UNKNOWN"
        status["Latest Dump Detail"] = f"read failed ({type(exc).__name__})"

    network = evaluate_current_network_health(app)
    network_status = str(network.get("status") or "UNKNOWN")
    if network.get("source") == "TEST_FIXTURE":
        status["Failback Network"] = "UNVERIFIED"
        status["Failback Network Detail"] = "test fixture data is not operational evidence"
    else:
        status["Failback Network"] = {
            "READY": "PASS",
            "NOT_READY": "BLOCKED",
            "UNKNOWN": "UNVERIFIED",
        }.get(network_status, "UNVERIFIED")
        if status["Failback Network"] != "PASS":
            status["Failback Network Detail"] = str(
                network.get("reason") or "Failback network status could not be verified"
            )
        else:
            status["Failback Network Detail"] = (
                "read-only SNMP availability for the Failback network gate; not Production Failover detection"
            )

    wazuh_status, wazuh_detail = _wazuh_failback_status(app)
    status["Wazuh Failback Gate"] = wazuh_status
    if wazuh_status != "PASS":
        status["Wazuh Failback Gate Detail"] = wazuh_detail

    failover_results, unknown_failover = _latest_typed_execution(
        app,
        "failover",
        (
            "general_failover",
            "emergency_failover",
            "general_dump",
            "emergency_dump",
        ),
    )
    for category, label in (
        ("general_failover", "Last General Failover Result"),
        ("emergency_failover", "Last Emergency Failover Result"),
        ("general_dump", "Last General Dump Restore Result"),
        ("emergency_dump", "Last Emergency Dump Restore Result"),
    ):
        result_status, result_detail = failover_results[category]
        status[label] = result_status
        status[f"{label} Detail"] = result_detail
    status["Last Unclassified Failover Result"], status[
        "Last Unclassified Failover Result Detail"
    ] = unknown_failover

    failback_results, unknown_failback = _latest_typed_execution(
        app, "failback", ("failback",)
    )
    status["Last Failback Result"], status["Last Failback Result Detail"] = (
        failback_results["failback"]
    )
    status["Last Unclassified Failback Result"], status[
        "Last Unclassified Failback Result Detail"
    ] = unknown_failback

    rto_status, rto_detail = _rto_measurement_status(app)
    status["RTO Measurement"] = rto_status
    status["RTO Measurement Detail"] = rto_detail
    status["RPO Measurement"] = "UNVERIFIED"
    status["RPO Measurement Detail"] = (
        "NOT_MEASURED; no request-correlated RPO evidence source is connected to this status view"
    )
    return status


def format_emergency_status(status):
    return "Hospital DR Status\n" + "\n".join(
        f"{key:16}: {safe_mrkdwn(value, 240)}" for key, value in status.items()
    )


SLACK_RESPONSE_URL_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})


def valid_slack_response_url(value):
    """Accept only Slack's HTTPS interaction response endpoints."""
    try:
        parsed = urlsplit(str(value or ""))
        return (
            parsed.scheme == "https"
            and parsed.hostname in SLACK_RESPONSE_URL_HOSTS
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path.startswith("/actions/")
        )
    except ValueError:
        return False


def send_emergency_status_response(app, response_url):
    """Query status off-request and deliver a private follow-up to the clicker."""
    try:
        with app.app_context():
            text = format_emergency_status(build_emergency_status(app))
    except Exception as exc:
        text = (
            "Hospital DR Status\n"
            f"상태 조회에 실패했습니다. 오류 유형: {type(exc).__name__}. "
            "세부 원인은 ChatOps 서비스 로그를 확인해 주세요."
        )

    sender = app.config.get("EMERGENCY_STATUS_RESPONSE_SENDER") or requests.post
    try:
        response = sender(
            response_url,
            json={
                "response_type": "ephemeral",
                "replace_original": False,
                "text": text,
            },
            timeout=(2, 5),
        )
        response.raise_for_status()
        print("EMERGENCY_STATUS_RESPONSE_SENT", flush=True)
    except Exception as exc:
        # The response_url is a short-lived secret capability; never log it.
        print(
            f"EMERGENCY_STATUS_RESPONSE_FAILED error={type(exc).__name__}",
            flush=True,
        )
    finally:
        lock = app.extensions.get("emergency_status_lock")
        if lock is not None:
            with lock:
                app.extensions["emergency_status_inflight"] = False


def start_emergency_status_check(app, response_url):
    """Start at most one read-only status query and return without blocking Slack."""
    lock = app.extensions["emergency_status_lock"]
    with lock:
        if app.extensions.get("emergency_status_inflight"):
            return "already_running"
        app.extensions["emergency_status_inflight"] = True
    try:
        threading.Thread(
            target=send_emergency_status_response,
            args=(app, response_url),
            daemon=True,
            name="emergency-status-check",
        ).start()
    except Exception as exc:
        with lock:
            app.extensions["emergency_status_inflight"] = False
        print(
            f"EMERGENCY_STATUS_START_FAILED error={type(exc).__name__}",
            flush=True,
        )
        return "start_failed"
    return "started"


def ensure_emergency_console(app):
    """Create or repair the one emergency console message, without duplication."""
    channel_id = app.config.get("SLACK_EMERGENCY_CHANNEL_ID")
    client = app.extensions.get("slack_clients", {}).get("emergency")
    store = app.extensions.get("emergency_console_store")
    if not channel_id:
        print("EMERGENCY_CHANNEL_NOT_CONFIGURED", flush=True)
        return {"status": "DISABLED", "error": "EMERGENCY_CHANNEL_NOT_CONFIGURED"}
    if client is None:
        print("EMERGENCY_BOT_TOKEN_MISSING", flush=True)
        return {"status": "DISABLED", "error": "EMERGENCY_BOT_TOKEN_MISSING"}
    if hasattr(client, "token") and not client.token:
        print("EMERGENCY_BOT_TOKEN_MISSING", flush=True)
        return {"status": "DISABLED", "error": "EMERGENCY_BOT_TOKEN_MISSING"}
    if not client.available or store is None:
        return {"status": "DISABLED"}
    blocks = emergency_console_blocks(button_value)
    text = "Hospital DR Emergency Console"
    current = store.get()
    if current:
        if current.get("channel_id") == channel_id and current.get("message_ts"):
            checker = getattr(client, "message_exists", None)
            if checker is None:
                print("[EMERGENCY CONSOLE] presence check unavailable", flush=True)
                return {"status": "ERROR", "error": "presence_check_unavailable"}
            try:
                if checker(current["channel_id"], current["message_ts"]):
                    return {"status": "READY", "message_ts": current["message_ts"]}
            except SlackApiError as exc:
                if exc.error not in {"cant_find_message", "message_not_found"}:
                    if exc.error == "channel_not_found":
                        print("EMERGENCY_CONSOLE_CHANNEL_NOT_FOUND", flush=True)
                    elif exc.error == "not_in_channel":
                        print("EMERGENCY_CONSOLE_NOT_IN_CHANNEL", flush=True)
                    print(f"[EMERGENCY CONSOLE] presence check failed error={exc.error}", flush=True)
                    return {"status": "ERROR", "error": exc.error}
            except Exception as exc:
                print(
                    f"[EMERGENCY CONSOLE] presence check failed error={type(exc).__name__}",
                    flush=True,
                )
                return {"status": "ERROR", "error": type(exc).__name__}
            print("[EMERGENCY_CONSOLE_MISSING] replacing stale console message", flush=True)
            app.extensions["chatops_audit"].record_event(
                "EMERGENCY_CONSOLE_MISSING",
                {"channel_id": current.get("channel_id"), "message_ts": current.get("message_ts")},
            )
            store.clear()
        else:
            store.clear()
    try:
        result = client.post_message(text, blocks)
        saved = store.save(channel_id, result.get("ts", ""))
        print("EMERGENCY_CONSOLE_CREATED", flush=True)
        app.extensions["chatops_audit"].record_event(
            "EMERGENCY_CONSOLE_READY",
            {"channel_id": channel_id, "message_ts": result.get("ts")},
        )
        try:
            client.pin_message(channel_id, result["ts"])
        except SlackApiError as exc:
            print(f"EMERGENCY_CONSOLE_PIN=SKIPPED_NO_PERMISSION error={exc.error}", flush=True)
        return {"status": "READY", "message_ts": saved["message_ts"] if saved else result.get("ts")}
    except SlackApiError as exc:
        if exc.error == "channel_not_found":
            print("EMERGENCY_CONSOLE_CHANNEL_NOT_FOUND", flush=True)
        elif exc.error == "not_in_channel":
            print("EMERGENCY_CONSOLE_NOT_IN_CHANNEL", flush=True)
        print(f"[EMERGENCY CONSOLE] create failed error={exc.error}", flush=True)
        return {"status": "ERROR", "error": exc.error}


def request_ui_copy(action):
    if action == "failover":
        return (
            "[FAILOVER]",
            "온프레미스 서버 장애가 감지되었습니다.",
            "재해복구 환경으로 전환하시겠습니까?",
        )
    return (
        "[FAILBACK]",
        "온프레미스 서버 정상화가 감지되었습니다.",
        "온프레미스 환경으로 전환하시겠습니까?",
    )


def ui_status_label(status):
    return {
        "PENDING": "승인 대기",
        "PARTIALLY_APPROVED": "추가 승인 대기",
        "EXECUTING": "실행 중",
        "SUCCEEDED": "완료 (SUCCESS)",
        "DB_RESTORED_NOT_FAILOVER_COMPLETE": "DB 복원 완료 (전체 Failover 미완료)",
        "FAILED": "실패",
        "PARTIAL_FAILURE": "PARTIAL_FAILURE (부분 실패)",
        "CANCELLED": "취소",
        "EXPIRED": "만료",
    }.get(status, status)


def latest_incident(state):
    incidents = state.get("incidents") or []
    return incidents[-1] if incidents else {}


def request_type_from_state(state):
    return str(
        latest_incident(state).get("request_type")
        or request_type_for_action(state.get("action"))
    ).strip()


def is_synthetic_mysql_demo_request(state):
    return bool(
        isinstance(state, dict)
        and state.get("action") == "failover"
        and request_type_from_state(state) == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE
    )


def _synthetic_mysql_demo_contract_module(config):
    repo_root = str(config.get("DR_REPO_ROOT") or "").strip()
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("synthetic_demo_repository_untrusted")
    root = root.resolve(strict=True)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from operations.demo import synthetic_mysql_demo_contract
    except Exception as exc:
        raise ValueError("synthetic_demo_contract_unavailable") from exc
    if root != synthetic_mysql_demo_contract.REPOSITORY_ROOT.resolve(strict=True):
        raise ValueError("synthetic_demo_repository_mismatch")
    return synthetic_mysql_demo_contract


def build_synthetic_mysql_demo_binding(config, *, issued_at, mode_expires_at):
    contract = _synthetic_mysql_demo_contract_module(config)
    return contract.build_request_binding(
        str(config.get("DR_REPO_ROOT") or contract.REPOSITORY_ROOT),
        issued_at=issued_at,
        mode_expires_at=mode_expires_at,
    )


def build_synthetic_mysql_demo_child_env(base_env, database):
    """Pass only runtime and AWS credential-provider settings to the demo child."""
    allowed = {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
        "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CA_BUNDLE",
        "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_EC2_METADATA_DISABLED", "AWS_SDK_LOAD_CONFIG", "AWS_STS_REGIONAL_ENDPOINTS",
    }
    child = {key: value for key, value in base_env.items() if key in allowed}
    child.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    child["CHATOPS_STATE_DB"] = str(database)
    return child


def is_test_mode_failover(state):
    return bool(
        isinstance(state, dict)
        and state.get("action") == "failover"
        and any(
            bool(item.get("test_mode"))
            for item in (state.get("incidents") or [])
            if isinstance(item, dict)
        )
    )


def dump_request_execution_guard(state):
    """Validate persisted provenance for the existing-DR Dump runner."""
    if state.get("action") != "failover" or request_type_from_state(state) != REQUEST_TYPE_DUMP_RESTORE:
        return "dump_request_type_invalid"

    incident = latest_incident(state)
    origin = str(incident.get("request_origin") or "").strip().upper()
    source_contracts = {
        "GENERAL": ("failover", "dump_restore_console"),
        "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
    }
    contract = source_contracts.get(origin)
    if contract is None:
        return "dump_request_origin_unverified"
    if (
        str(state.get("slack_client_key") or "").strip() != contract[0]
        or str(incident.get("slack_client_key") or "").strip() != contract[0]
        or str(incident.get("source") or "").strip() != contract[1]
    ):
        return "dump_request_origin_mismatch"
    return None


def is_existing_dr_demo_dump_failover(state):
    return (
        state.get("action") == "failover"
        and request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE
        and dump_request_execution_guard(state) is None
    )


def _safe_dump_receipt_field(value, pattern, fallback):
    value = str(value or "")
    return value if re.fullmatch(pattern, value) else fallback


def _read_dump_executor_receipt(app, state):
    """Read the Executor's request-bound receipt without following symlinks."""
    request_id = str(state.get("request_id") or "")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", request_id):
        return None, "EXECUTOR_RECEIPT_REQUEST_ID_INVALID"

    root = str(
        app.config.get("DUMP_FAILOVER_EXECUTOR_STATE_DIR")
        or DUMP_FAILOVER_EXECUTOR_RECEIPT_ROOT
    )
    if not os.path.isabs(root):
        return None, "EXECUTOR_RECEIPT_PATH_INVALID"
    root_path = os.path.abspath(root)
    operation_path = os.path.join(root_path, request_id)
    receipt_path = os.path.join(operation_path, "executor.json")
    owner_uid = os.geteuid()

    try:
        current_path = os.path.sep
        for component in Path(root_path).parts[1:]:
            current_path = os.path.join(current_path, component)
            component_meta = os.lstat(current_path)
            if stat.S_ISLNK(component_meta.st_mode) or not stat.S_ISDIR(component_meta.st_mode):
                return None, "EXECUTOR_RECEIPT_DIRECTORY_UNTRUSTED"
        for directory in (root_path, operation_path):
            metadata = os.lstat(directory)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                return None, "EXECUTOR_RECEIPT_DIRECTORY_UNTRUSTED"

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(receipt_path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_size < 2
                or metadata.st_size > 1024 * 1024
            ):
                return None, "EXECUTOR_RECEIPT_FILE_UNTRUSTED"
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = None
                receipt = json.load(stream)
        finally:
            if descriptor is not None:
                os.close(descriptor)
    except FileNotFoundError:
        return None, "EXECUTOR_RECEIPT_MISSING"
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None, "EXECUTOR_RECEIPT_UNREADABLE"

    if not isinstance(receipt, dict):
        return None, "EXECUTOR_RECEIPT_INVALID"
    incident = latest_incident(state)
    expected_backup = str(incident.get("backup_id") or "")
    expected_sha = str(incident.get("backup_checksum") or "").strip().lower()
    if (
        not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", expected_backup)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha)
        or receipt.get("request_id") != request_id
        or receipt.get("backup_id") != expected_backup
        or str(receipt.get("sha256") or "").lower() != expected_sha
    ):
        return None, "EXECUTOR_RECEIPT_IDENTITY_MISMATCH"
    return receipt, None


_DUMP_EXECUTOR_LOG_MAX_BYTES = 2 * 1024 * 1024
_DUMP_EXECUTOR_LOG_PHASES = {
    stage.upper().replace("-", "_") for stage in DUMP_FAILOVER_SUCCESS_STAGES
} | {"INITIALIZED", "DR_ACTIVE_COMMIT"}
_DEMO_DUMP_RESTORE_LOG_PHASES = {
    "TARGET_IDENTITY": "대상 신원 확인",
    "SSM_TRANSPORT": "SSM 연결 준비",
    "APPLICATION_FENCE": "Web/EMR 쓰기 차단",
    "PRESNAPSHOT_PREFLIGHT": "기존 DB 백업 사전검사",
    "PRESNAPSHOT": "기존 DB 백업 및 검증",
    "SELECTED_DUMP_REVALIDATION": "선택 Dump 재검증",
    "SELECTED_DUMP_STAGE": "선택 Dump 전달",
    "FINAL_FENCE_AND_AUTHORIZATION_CHECK": "복원 직전 승인·차단 재검증",
    "RESTORE_ATTEMPTED": "기존 DR DB 복원",
    "POST_RESTORE_DB_VERIFICATION": "복원 DB 검증",
}


def _demo_dump_restore_state_root(app):
    explicit = str(app.config.get("DEMO_DUMP_RESTORE_STATE_DIR") or "").strip()
    if explicit:
        return explicit
    state_dir = str(app.config.get("DR_STATE_DIR") or "/var/lib/hospital-dr").strip()
    return os.path.join(state_dir, "demo-dump-restores")


def _read_demo_dump_restore_receipt(app, state):
    """Read the minimal runner's private receipt, bound to this ChatOps request."""
    request_id = str(state.get("request_id") or "")
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        request_id,
    ):
        return None, "REQUEST_ID_INVALID"
    root = _demo_dump_restore_state_root(app)
    if not os.path.isabs(root):
        return None, "RECEIPT_PATH_INVALID"
    root_path = os.path.abspath(root)
    operation_path = os.path.join(root_path, request_id)
    receipt_path = os.path.join(operation_path, "result.json")
    descriptor = None
    try:
        current_path = os.path.sep
        for component in Path(root_path).parts[1:]:
            current_path = os.path.join(current_path, component)
            metadata = os.lstat(current_path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return None, "RECEIPT_DIRECTORY_UNTRUSTED"
        root_metadata = os.lstat(root_path)
        operation_metadata = os.lstat(operation_path)
        if (
            root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
            or operation_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(operation_metadata.st_mode) != 0o700
            or stat.S_ISLNK(root_metadata.st_mode)
            or stat.S_ISLNK(operation_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or not stat.S_ISDIR(operation_metadata.st_mode)
        ):
            return None, "RECEIPT_DIRECTORY_UNTRUSTED"
        descriptor = os.open(
            receipt_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 2 <= metadata.st_size <= 1024 * 1024
        ):
            return None, "RECEIPT_FILE_UNTRUSTED"
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            receipt = json.load(stream)
    except FileNotFoundError:
        return None, "RECEIPT_MISSING"
    except PermissionError:
        return None, "RECEIPT_PERMISSION_DENIED"
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None, "RECEIPT_UNREADABLE"
    finally:
        if descriptor is not None:
            os.close(descriptor)

    incident = latest_incident(state)
    expected_backup = str(incident.get("backup_id") or "")
    expected_sha = str(incident.get("backup_checksum") or "").strip().lower()
    expected_origin = str(incident.get("request_origin") or "").strip().upper()
    provenance = {
        "GENERAL": ("failover", "dump_restore_console"),
        "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
    }.get(expected_origin)
    failover_pipeline = receipt.get("failover_pipeline") if isinstance(receipt, dict) else None
    request_scoped_receipt_state = isinstance(receipt, dict) and ((
        receipt.get("dns_changed") is False
        and receipt.get("dr_active_recorded") is False
    ) or (
        receipt.get("status") == "FAILOVER_COMPLETE"
        and receipt.get("phase") == "FAILOVER_COMPLETE"
        and receipt.get("dns_changed") is True
        and receipt.get("dr_active_recorded") is True
        and isinstance(failover_pipeline, dict)
        and failover_pipeline.get("status") == "SUCCEEDED"
        and failover_pipeline.get("request_id") == request_id
        and failover_pipeline.get("recovery_mode") == "APPROVED_DUMP"
        and failover_pipeline.get("final_dr_state") == "DR_ACTIVE"
        and failover_pipeline.get("completion_marker_verified") is True
    ) or (
        receipt.get("status") == "PARTIAL_FAILURE"
        and receipt.get("failure_code") in {
            "FULL_FAILOVER_FAILED_AFTER_DUMP_RESTORE",
            "DR_ENVIRONMENT_START_FAILED_AFTER_DUMP_RESTORE",
        }
        and receipt.get("restore_attempted") is True
        and receipt.get("dump_restore_status", "PASS") == "PASS"
        and receipt.get("dns_changed") == "UNKNOWN"
        and receipt.get("dr_active_recorded") is False
        and isinstance(failover_pipeline, dict)
        and failover_pipeline.get("status") == "PARTIAL_FAILURE"
        and failover_pipeline.get("request_id") == request_id
        and failover_pipeline.get("recovery_mode") == "APPROVED_DUMP"
    ))
    if (
        not isinstance(receipt, dict)
        or receipt.get("request_id") != request_id
        or receipt.get("backup_id") != expected_backup
        or str(receipt.get("expected_sha256") or "").lower() != expected_sha
        or provenance is None
        or receipt.get("request_origin") != expected_origin
        or receipt.get("request_type") != REQUEST_TYPE_DUMP_RESTORE
        or receipt.get("request_source") != provenance[1]
        or receipt.get("slack_client_key") != provenance[0]
        or receipt.get("target") != {
            "instance_id": "AWS_RESOURCE_ID_REDACTED",
            "private_ip": "IP_REDACTED",
            "port": 3306,
            "database": "hospital_db",
        }
        or not request_scoped_receipt_state
    ):
        return None, "RECEIPT_IDENTITY_OR_SCOPE_MISMATCH"
    return receipt, None


def read_demo_dump_restore_log_events(app, state, offset=0):
    """Translate only the minimal runner's allowlisted, request-bound log events."""
    if not is_existing_dr_demo_dump_failover(state):
        return [], max(0, int(offset)), "not_supported_dump_request"
    receipt, receipt_error = _read_demo_dump_restore_receipt(app, state)
    if receipt_error:
        return [], max(0, int(offset)), receipt_error.lower()
    request_id = str(state.get("request_id") or "")
    path = os.path.join(_demo_dump_restore_state_root(app), request_id, "execution.log")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > _DUMP_EXECUTOR_LOG_MAX_BYTES
        ):
            return [], max(0, int(offset)), "file_untrusted"
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            content = stream.read(_DUMP_EXECUTOR_LOG_MAX_BYTES + 1)
    except FileNotFoundError:
        return [], max(0, int(offset)), "missing"
    except PermissionError:
        return [], max(0, int(offset)), "permission"
    except OSError:
        return [], max(0, int(offset)), "unavailable"
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(content) > _DUMP_EXECUTOR_LOG_MAX_BYTES:
        return [], max(0, int(offset)), "file_untrusted"

    complete_lines = [line for line in content.splitlines(keepends=True) if line.endswith(b"\n")]
    start = min(max(0, int(offset)), len(complete_lines))
    events = []
    for raw_line in complete_lines[start:]:
        try:
            timestamp_text, marker = raw_line.rstrip(b"\r\n").decode("ascii").split(" ", 1)
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except (UnicodeError, ValueError):
            continue
        if timestamp.tzinfo is None or timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
            continue
        display_time = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        phase_match = re.fullmatch(r"([A-Z0-9_]+)_(STARTED|COMPLETE)", marker)
        if marker == "EXECUTION_STARTED":
            message = "기존 DR DB Dump 복원 실행 시작"
        elif marker == "RESTORE_COMMAND_SUBMITTED" and receipt.get("restore_attempted") is True:
            message = "기존 DR DB 복원 명령 제출"
        elif marker == "DB_RESTORED_NOT_FAILOVER_COMPLETE" and receipt.get("status") == marker:
            message = "DB 복원 완료; 전체 Failover는 미완료"
        elif marker.startswith("PARTIAL_FAILURE_"):
            code = marker.removeprefix("PARTIAL_FAILURE_")
            if receipt.get("status") != "PARTIAL_FAILURE" or receipt.get("failure_code") != code:
                continue
            message = f"복원 결과 불명확; 운영자 확인 필요, 오류 코드={code}"
        elif marker.startswith("FAILED_"):
            code = marker.removeprefix("FAILED_")
            if receipt.get("status") != "FAILED" or receipt.get("failure_code") != code:
                continue
            message = f"복원 전 안전 중단, 오류 코드={code}"
        elif phase_match and phase_match.group(1) in _DEMO_DUMP_RESTORE_LOG_PHASES:
            phase_name, event = phase_match.groups()
            stage = (receipt.get("stages") or {}).get(phase_name, {})
            if not isinstance(stage, dict) or not stage.get("started_at_utc"):
                continue
            if event == "COMPLETE" and stage.get("status") != "COMPLETE":
                continue
            verb = "시작" if event == "STARTED" else "완료"
            message = f"단계 {verb}: {_DEMO_DUMP_RESTORE_LOG_PHASES[phase_name]}"
        else:
            continue
        events.append(f"[{display_time}] [DUMP] {message}.")
    return events, len(complete_lines), None


def read_dump_executor_log_events(app, state, offset=0):
    """Read only allowlisted structured markers from this request's private Executor log.

    Executor stdout/stderr is deliberately not used as the Slack log source.  The
    private log is opened without following symlinks and is accepted only when
    its request directory and file retain the Executor's 0700/0600 contract.
    """
    if not is_existing_dr_demo_dump_failover(state):
        return [], max(0, int(offset)), "not_dump_executor"
    if is_demo_dump_executor_configured(app.config):
        return read_demo_dump_restore_log_events(app, state, offset)
    request_id = str(state.get("request_id") or "")
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        request_id,
    ):
        return [], max(0, int(offset)), "request_id_invalid"

    root = str(
        app.config.get("DUMP_FAILOVER_EXECUTOR_STATE_DIR")
        or DUMP_FAILOVER_EXECUTOR_RECEIPT_ROOT
    )
    if not os.path.isabs(root):
        return [], max(0, int(offset)), "path_invalid"
    root_path = os.path.abspath(root)
    operation_path = os.path.join(root_path, request_id)
    log_path = os.path.join(operation_path, f"{request_id}.log")
    owner_uid = os.geteuid()
    descriptor = None
    try:
        current_path = os.path.sep
        for component in Path(root_path).parts[1:]:
            current_path = os.path.join(current_path, component)
            component_meta = os.lstat(current_path)
            if stat.S_ISLNK(component_meta.st_mode) or not stat.S_ISDIR(component_meta.st_mode):
                return [], max(0, int(offset)), "directory_untrusted"
        for directory in (root_path, operation_path):
            metadata = os.lstat(directory)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                return [], max(0, int(offset)), "directory_untrusted"

        descriptor = os.open(
            log_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > _DUMP_EXECUTOR_LOG_MAX_BYTES
        ):
            return [], max(0, int(offset)), "file_untrusted"
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            content = stream.read(_DUMP_EXECUTOR_LOG_MAX_BYTES + 1)
    except FileNotFoundError:
        return [], max(0, int(offset)), "missing"
    except PermissionError:
        return [], max(0, int(offset)), "permission"
    except OSError:
        return [], max(0, int(offset)), "unavailable"
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if len(content) > _DUMP_EXECUTOR_LOG_MAX_BYTES:
        return [], max(0, int(offset)), "file_untrusted"

    complete_lines = [line for line in content.splitlines(keepends=True) if line.endswith(b"\n")]
    start = min(max(0, int(offset)), len(complete_lines))
    events = []
    receipt_checked = False
    verified_receipt = None
    receipt_error = None

    def bound_receipt():
        nonlocal receipt_checked, verified_receipt, receipt_error
        if not receipt_checked:
            verified_receipt, receipt_error = _read_dump_executor_receipt(app, state)
            receipt_checked = True
        return verified_receipt if receipt_error is None else None

    for raw_line in complete_lines[start:]:
        try:
            line = raw_line.rstrip(b"\r\n").decode("ascii")
        except UnicodeDecodeError:
            continue
        timestamp_text, separator, marker = line.partition(" ")
        if not separator or len(timestamp_text) > 40:
            continue
        try:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except ValueError:
            continue
        if timestamp.tzinfo is None or timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
            continue
        display_time = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if marker == "EXECUTOR_STARTED":
            message = "Executor 실행 시작"
        elif marker == "DR_ACTIVE:VERIFIED":
            receipt = bound_receipt()
            if not (
                receipt
                and receipt.get("status") == "SUCCESS"
                and receipt.get("phase") == "DR_ACTIVE_VERIFIED"
                and receipt.get("dr_active_recorded") is True
            ):
                continue
            message = "Executor의 DR_ACTIVE readback 표식 기록 (최종 판정은 ChatOps receipt 검증 기준)"
        elif marker.startswith("EXECUTOR_STATUS:"):
            status = marker.partition(":")[2]
            receipt = bound_receipt()
            if (
                status not in {"SUCCESS", "FAILED", "PARTIAL_FAILURE"}
                or not receipt
                or receipt.get("status") != status
            ):
                continue
            message = f"Executor 종료 표식: {status} (최종 판정은 ChatOps receipt 검증 기준)"
        elif marker.startswith("OPERATOR_INTERVENTION_REQUIRED:"):
            required = marker.partition(":")[2]
            receipt = bound_receipt()
            if (
                required not in {"TRUE", "FALSE"}
                or not receipt
                or receipt.get("operator_intervention_required") is not (required == "TRUE")
            ):
                continue
            message = f"Executor 운영자 개입 필요 표식: {'필요' if required == 'TRUE' else '불필요'}"
        else:
            failure = re.fullmatch(r"([A-Z0-9_]{1,64}):FAIL:([A-Z][A-Z0-9_]{0,95})", marker)
            stage = re.fullmatch(r"([A-Z0-9_]{1,64}):(STARTED|COMPLETE)", marker)
            if failure and failure.group(1) in _DUMP_EXECUTOR_LOG_PHASES:
                receipt = bound_receipt()
                receipt_phase = str((receipt or {}).get("phase") or "").upper().replace("-", "_")
                if not (
                    receipt
                    and receipt.get("status") in {"FAILED", "PARTIAL_FAILURE"}
                    and receipt_phase == failure.group(1)
                    and receipt.get("failure_code") == failure.group(2)
                ):
                    continue
                phase = failure.group(1).lower().replace("_", "-")
                message = f"단계 실패: {phase}; 검증된 오류 코드={failure.group(2)}"
            elif stage and stage.group(1) in _DUMP_EXECUTOR_LOG_PHASES:
                phase = stage.group(1).lower().replace("_", "-")
                verb = "시작" if stage.group(2) == "STARTED" else "성공"
                message = f"단계 {verb}: {phase}"
            else:
                continue
        events.append(f"[{display_time}] [DUMP] {message}.")
    return events, len(complete_lines), None


def sync_dump_executor_log_to_chatops(app, state, offset=0):
    """Append newly verified Executor event summaries to the ChatOps request log."""
    events, next_offset, error = read_dump_executor_log_events(app, state, offset)
    for event in events:
        append_execution_log(app, state.get("request_id"), event)
    return next_offset, error


def _demo_dump_approval_evidence_matches(state, receipt):
    evidence = receipt.get("approval_evidence")
    if not isinstance(evidence, dict):
        return False
    expected_approvers = state.get("approvers") or []
    recorded_approvers = evidence.get("approver_ids") or []
    execution_id = str(state.get("execution_id") or "")
    return (
        evidence.get("approval_required") == 2
        and evidence.get("approval_count") == 2
        and len(expected_approvers) == 2
        and len(set(expected_approvers)) == 2
        and len(recorded_approvers) == 2
        and len(set(recorded_approvers)) == 2
        and set(recorded_approvers) == set(expected_approvers)
        and bool(execution_id)
        and evidence.get("execution_id") == execution_id
    )


def _demo_dump_overwrite_authorization_matches(state, receipt):
    authorization = receipt.get("overwrite_authorization")
    incident = latest_incident(state)
    if not isinstance(authorization, dict):
        return False
    approved_at = authorization.get("approved_at")
    return bool(
        isinstance(authorization.get("authorization_id"), str)
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            authorization["authorization_id"],
        )
        and authorization.get("scope") == DEMO_DUMP_OVERWRITE_SCOPE
        and authorization.get("target") == DEMO_DUMP_OVERWRITE_TARGET
        and authorization.get("backup_id") == incident.get("backup_id")
        and str(authorization.get("sha256") or "").lower()
        == str(incident.get("backup_checksum") or "").lower()
        and authorization.get("execution_id") == state.get("execution_id")
        and isinstance(approved_at, (int, float))
        and not isinstance(approved_at, bool)
        and math.isfinite(float(approved_at))
        and float(approved_at) > 0
        and receipt.get("overwrite_approval_request_id") == state.get("request_id")
    )


def _demo_dump_read_only_standby_verified(value):
    if (
        not isinstance(value, dict)
        or value.get("read_only") is not True
        or value.get("super_read_only") is not True
    ):
        return False
    if (
        value.get("persisted_read_only") == "ON"
        and value.get("persisted_super_read_only") == "ON"
    ):
        return True
    return (
        value.get("persisted_read_only") == "MISSING"
        and value.get("persisted_super_read_only") == "MISSING"
        and value.get("startup_read_only") == "ON"
        and value.get("startup_super_read_only") == "ON"
        and value.get("startup_source_verified") is True
        and value.get("persistence_source") == "MYSQL_STARTUP_CONFIGURATION"
    )


def _demo_dump_restore_recovery_data_valid(state, receipt):
    if not isinstance(receipt, dict) or not isinstance(state, dict):
        return False
    snapshot = receipt.get("presnapshot")
    stages = receipt.get("stages")
    verification = receipt.get("database_verification")
    if not isinstance(snapshot, dict) or not isinstance(stages, dict) or not isinstance(verification, dict):
        return False
    request_id = str(state.get("request_id") or "")
    required_stages = set(_DEMO_DUMP_RESTORE_LOG_PHASES)
    expected_snapshot = f"/home/ubuntu/db_backups/pre-restore/{request_id}/hospital_db.sql.gz.enc"
    identity = verification.get("database_identity")
    counts = verification.get("row_counts")
    tables = {"users", "patients", "doctors", "medicalrecords", "accesslogs", "reservationposts"}
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("sha256") or ""))
        and isinstance(snapshot.get("size_bytes"), int)
        and not isinstance(snapshot.get("size_bytes"), bool)
        and snapshot.get("size_bytes", 0) > 0
        and snapshot.get("integrity") == "OPENSSL_GZIP_PASS"
        and snapshot.get("remote_path") == expected_snapshot
        and all(
            isinstance(stages.get(stage), dict)
            and stages[stage].get("status") == "COMPLETE"
            for stage in required_stages
        )
        and verification.get("mysql_responded") is True
        and isinstance(identity, dict)
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            str(identity.get("server_uuid") or ""),
        )
        and identity.get("server_id") == 20
        and identity.get("port") == 3306
        and {str(value).lower() for value in verification.get("core_tables", [])} == tables
        and isinstance(counts, dict)
        and {str(key).lower() for key in counts} == tables
        and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counts.values())
        and _demo_dump_read_only_standby_verified(verification.get("read_only_standby"))
    )


def classify_demo_dump_restore_result(app, state, return_code):
    """Classify the Dump restore and its same-request common Failover continuation."""
    receipt, receipt_error = _read_demo_dump_restore_receipt(app, state)
    partial = {
        "status": "PARTIAL_FAILURE",
        "result": "demo_dump_restore_outcome_requires_operator_review",
        "phase": "UNKNOWN",
        "failure_code": receipt_error or "EXECUTOR_OUTCOME_UNVERIFIED",
        "automatic_rollback_allowed": False,
        "operator_intervention_required": True,
        "executor_status": "UNKNOWN",
        "executor_kind": "demo-existing-dr",
    }
    if receipt is None:
        return partial

    phase = _safe_dump_receipt_field(receipt.get("phase"), r"[A-Za-z0-9_.:-]{1,64}", "UNKNOWN")
    failure_code = _safe_dump_receipt_field(receipt.get("failure_code"), r"[A-Z0-9_]{1,96}", "UNKNOWN")
    receipt_status = receipt.get("status")
    common_flags = (
        receipt.get("dns_changed") is False
        and receipt.get("dr_active_recorded") is False
        and receipt.get("automatic_db_rollback") is False
        and (receipt.get("restore_attempted") is False or receipt.get("restore_attempted") is True)
        and isinstance(receipt.get("apps_fenced"), bool)
    )
    approval_valid = _demo_dump_approval_evidence_matches(state, receipt)
    overwrite_authorization_valid = _demo_dump_overwrite_authorization_matches(state, receipt)
    pipeline = receipt.get("failover_pipeline")
    recovery_data_valid = _demo_dump_restore_recovery_data_valid(state, receipt)
    if (
        return_code == 0
        and receipt_status == "FAILOVER_COMPLETE"
        and receipt.get("phase") == "FAILOVER_COMPLETE"
        and receipt.get("failure_code") is None
        and receipt.get("restore_attempted") is True
        and receipt.get("apps_fenced") is True
        and receipt.get("apps_fence_state") in {"WEB_AND_EMR_EC2_STOPPED", "VERIFIED"}
        and receipt.get("operator_intervention_required") is False
        and receipt.get("automatic_db_rollback") is False
        and receipt.get("dns_changed") is True
        and receipt.get("dr_active_recorded") is True
        and approval_valid
        and overwrite_authorization_valid
        and recovery_data_valid
        and isinstance(pipeline, dict)
        and pipeline.get("status") == "SUCCEEDED"
        and pipeline.get("request_id") == state.get("request_id")
        and pipeline.get("recovery_mode") == "APPROVED_DUMP"
        and pipeline.get("backup_id") == receipt.get("backup_id")
        and str(pipeline.get("sha256") or "").lower() == str(receipt.get("expected_sha256") or "").lower()
        and pipeline.get("return_code") == 0
        and pipeline.get("final_dr_state") == "DR_ACTIVE"
        and pipeline.get("completion_marker_verified") is True
    ):
        return {
            "status": "SUCCEEDED",
            "result": "approved_dump_restore_and_dr_environment_start_verified",
            "phase": "FAILOVER_COMPLETE",
            "failure_code": "",
            "automatic_rollback_allowed": False,
            "operator_intervention_required": False,
            "executor_status": receipt_status,
            "executor_kind": "demo-existing-dr-environment-start",
            "backup_id": receipt.get("backup_id"),
            "recovery_mode": "APPROVED_DUMP",
            "dump_restore_status": "PASS",
            "dump_failover_status": "PASS",
        }
    if (
        return_code == 2
        and receipt_status == "PARTIAL_FAILURE"
        and receipt.get("restore_attempted") is True
        and receipt.get("operator_intervention_required") is True
        and receipt.get("automatic_db_rollback") is False
        and receipt.get("failure_code") in {
            "FULL_FAILOVER_FAILED_AFTER_DUMP_RESTORE",
            "DR_ENVIRONMENT_START_FAILED_AFTER_DUMP_RESTORE",
        }
        and receipt.get("dump_restore_status", "PASS") == "PASS"
        and recovery_data_valid
        and approval_valid
        and overwrite_authorization_valid
        and isinstance(pipeline, dict)
        and pipeline.get("status") == "PARTIAL_FAILURE"
        and pipeline.get("request_id") == state.get("request_id")
        and pipeline.get("recovery_mode") == "APPROVED_DUMP"
        and pipeline.get("return_code") != 0
        and pipeline.get("completion_marker_verified") is False
        and pipeline.get("final_dr_state") in {
            "IDLE", "FAILOVER_EXECUTING", "FAILED", "PARTIAL_FAILURE", "DR_ACTIVE", "UNKNOWN"
        }
    ):
        return {
            "status": "PARTIAL_FAILURE",
            "result": (
                "dump_restore_succeeded_but_environment_start_incomplete"
                if receipt.get("failure_code") == "DR_ENVIRONMENT_START_FAILED_AFTER_DUMP_RESTORE"
                else "dump_restore_succeeded_but_common_failover_incomplete"
            ),
            "phase": phase,
            "failure_code": failure_code,
            "automatic_rollback_allowed": False,
            "operator_intervention_required": True,
            "executor_status": receipt_status,
            "executor_kind": "demo-existing-dr-environment-start",
            "backup_id": receipt.get("backup_id"),
            "recovery_mode": "APPROVED_DUMP",
            "dump_restore_status": "PASS",
            "dump_failover_status": "PARTIAL_FAILURE",
        }
    if (
        return_code == 10
        and receipt_status == "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        and receipt.get("phase") == "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        and receipt.get("restore_attempted") is True
        and receipt.get("apps_fenced") is True
        and receipt.get("apps_fence_state") in {"WEB_AND_EMR_EC2_STOPPED", "VERIFIED"}
        and receipt.get("operator_intervention_required") is False
        and receipt.get("failure_code") is None
        and approval_valid
        and overwrite_authorization_valid
        and common_flags
    ):
        verification = receipt.get("database_verification")
        counts = verification.get("row_counts") if isinstance(verification, dict) else None
        core_tables = verification.get("core_tables") if isinstance(verification, dict) else None
        snapshot = receipt.get("presnapshot")
        stages = receipt.get("stages")
        required_stages = set(_DEMO_DUMP_RESTORE_LOG_PHASES)
        if (
            isinstance(snapshot, dict)
            and re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("sha256") or ""))
            and isinstance(snapshot.get("size_bytes"), int)
            and snapshot.get("size_bytes", 0) > 0
            and snapshot.get("integrity") == "OPENSSL_GZIP_PASS"
            and snapshot.get("remote_path") == (
                f"/home/ubuntu/db_backups/pre-restore/{state['request_id']}/hospital_db.sql.gz.enc"
            )
            and isinstance(stages, dict)
            and all(
                isinstance(stages.get(stage), dict)
                and stages[stage].get("status") == "COMPLETE"
                for stage in required_stages
            )
            and isinstance(verification, dict)
            and verification.get("mysql_responded") is True
            and isinstance(core_tables, list)
            and {str(item).lower() for item in core_tables} >= {
                "users", "patients", "doctors", "medicalrecords", "accesslogs", "reservationposts"
            }
            and isinstance(counts, dict)
            and all(
                name in {str(key).lower() for key in counts}
                and isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for name in {"users", "patients", "doctors", "medicalrecords", "accesslogs", "reservationposts"}
                for value in [next((v for k, v in counts.items() if str(k).lower() == name), None)]
            )
        ):
            return {
                "status": "DB_RESTORED_NOT_FAILOVER_COMPLETE",
                "result": "demo_dump_db_restore_verified_only",
                "phase": "DB_RESTORED_NOT_FAILOVER_COMPLETE",
                "failure_code": str(
                    (receipt.get("failover_pipeline") or {}).get("failure_code") or ""
                ),
                "automatic_rollback_allowed": False,
                "operator_intervention_required": False,
                "executor_status": receipt_status,
                "executor_kind": "demo-existing-dr",
                "backup_id": receipt.get("backup_id"),
                "dump_restore_status": "PASS",
                "dump_failover_status": receipt.get("dump_failover_status", "NOT_STARTED"),
                "failover_pipeline": receipt.get("failover_pipeline"),
            }
        partial["phase"] = phase
        partial["failure_code"] = "DB_RESTORE_VERIFICATION_RECEIPT_INVALID"
        partial["executor_status"] = receipt_status
        return partial

    if (
        return_code == 1
        and receipt_status == "FAILED"
        and re.fullmatch(r"[A-Z0-9_]{1,96}", str(receipt.get("failure_code") or ""))
        and receipt.get("restore_attempted") is False
        and receipt.get("operator_intervention_required") is bool(receipt.get("apps_fenced"))
        and common_flags
        and receipt.get("apps_fence_state") in {"NOT_STARTED", "VERIFIED"}
    ):
        return {
            "status": "FAILED",
            "result": "demo_dump_restore_safely_stopped_before_restore",
            "phase": phase,
            "failure_code": failure_code,
            "automatic_rollback_allowed": False,
            "operator_intervention_required": bool(receipt.get("operator_intervention_required")),
            "executor_status": receipt_status,
            "executor_kind": "demo-existing-dr",
            "restore_attempted": False,
        }
    if (
        return_code == 2
        and receipt_status == "PARTIAL_FAILURE"
        and receipt.get("operator_intervention_required") is True
        and common_flags
        and re.fullmatch(r"[A-Z0-9_]{1,96}", str(receipt.get("failure_code") or ""))
    ):
        return {
            **partial,
            "phase": phase,
            "failure_code": failure_code,
            "executor_status": receipt_status,
            "executor_kind": "demo-existing-dr",
            "restore_attempted": receipt.get("restore_attempted") is True,
        }
    return {
        **partial,
        "phase": phase,
        "failure_code": (
            "EXECUTOR_EXIT_RECEIPT_MISMATCH"
            if receipt_status in {"FAILED", "PARTIAL_FAILURE", "DB_RESTORED_NOT_FAILOVER_COMPLETE"}
            else "EXECUTOR_OUTCOME_UNVERIFIED"
        ),
        "executor_status": receipt_status if isinstance(receipt_status, str) else "UNKNOWN",
    }


def classify_dump_executor_result(app, state, return_code):
    """Classify only provenance-verified requests for the DB-only demo runner."""
    if not is_existing_dr_demo_dump_failover(state):
        return None
    if is_demo_dump_executor_configured(app.config):
        return classify_demo_dump_restore_result(app, state, return_code)

    receipt, receipt_error = _read_dump_executor_receipt(app, state)
    phase = "UNKNOWN"
    failure_code = receipt_error or "EXECUTOR_OUTCOME_UNVERIFIED"
    receipt_status = None
    phase_valid = False
    failure_code_valid = False
    if receipt is not None:
        receipt_status = receipt.get("status")
        phase_valid = isinstance(receipt.get("phase"), str) and bool(
            re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", receipt["phase"])
        )
        failure_code_valid = isinstance(receipt.get("failure_code"), str) and bool(
            re.fullmatch(r"[A-Z0-9_]{1,96}", receipt["failure_code"])
        )
        phase = _safe_dump_receipt_field(
            receipt.get("phase"), r"[A-Za-z0-9_.:-]{1,64}", "UNKNOWN"
        )
        failure_code = _safe_dump_receipt_field(
            receipt.get("failure_code"), r"[A-Z0-9_]{1,96}", "EXECUTOR_OUTCOME_UNVERIFIED"
        )

    partial = {
        "status": "PARTIAL_FAILURE",
        "result": "dump_executor_outcome_requires_operator_review",
        "phase": phase,
        "failure_code": failure_code,
        "automatic_rollback_allowed": False,
        "operator_intervention_required": True,
        "executor_status": receipt_status or "UNKNOWN",
    }
    if receipt is None:
        return partial

    common_safe_flags = (
        receipt.get("operator_intervention_required") is False
        and receipt.get("automatic_dns_rollback_allowed") is False
        and receipt.get("rollback_to_prior_database_allowed") is False
        and receipt.get("dr_active_recorded") is False
        and receipt.get("dr_state_marked_partial_failure") is not True
    )
    if return_code == 0:
        if (
            receipt_status == "SUCCESS"
            and receipt.get("phase") == "DR_ACTIVE_VERIFIED"
            and receipt.get("completed_stages") == list(DUMP_FAILOVER_SUCCESS_STAGES)
            and receipt.get("dr_state_changed") is True
            and receipt.get("dr_active_recorded") is True
            and receipt.get("operator_intervention_required") is False
            and receipt.get("automatic_dns_rollback_allowed") is False
            and receipt.get("rollback_to_prior_database_allowed") is False
        ):
            return {
                "status": "SUCCEEDED",
                "result": "dump_executor_success_receipt_verified",
                "phase": "DR_ACTIVE_VERIFIED",
                "failure_code": "",
                "automatic_rollback_allowed": False,
                "operator_intervention_required": False,
                "executor_status": "SUCCESS",
            }
        partial["failure_code"] = "EXECUTOR_SUCCESS_RECEIPT_INVALID"
        return partial

    pre_dml_rollback_verified = (
        phase == "service-open"
        and failure_code == "SERVICE_OPEN_PRE_DML_ROLLBACK_VERIFIED"
        and receipt.get("dml_grant_attempted") == "UNKNOWN_OR_ATTEMPTED"
        and receipt.get("dns_mutation_started") is True
    )
    safe_pre_mutation_failure = (
        receipt.get("dml_grant_attempted") is False
        and receipt.get("dns_mutation_started") is False
    )
    if (
        receipt_status == "FAILED"
        and phase_valid
        and failure_code_valid
        and common_safe_flags
        and (safe_pre_mutation_failure or pre_dml_rollback_verified)
    ):
        return {
            "status": "FAILED",
            "result": "dump_executor_safe_failure_receipt_verified",
            "phase": phase,
            "failure_code": failure_code,
            "automatic_rollback_allowed": False,
            "operator_intervention_required": False,
            "executor_status": "FAILED",
        }
    if receipt_status == "PARTIAL_FAILURE":
        partial["failure_code"] = (
            _safe_dump_receipt_field(
                receipt.get("failure_code"), r"[A-Z0-9_]{1,96}", "EXECUTOR_PARTIAL_RECEIPT_INVALID"
            )
            if (
                receipt.get("operator_intervention_required") is True
                and receipt.get("automatic_dns_rollback_allowed") is False
                and receipt.get("rollback_to_prior_database_allowed") is False
            )
            else "EXECUTOR_PARTIAL_RECEIPT_FLAGS_INVALID"
        )
        return partial
    partial["failure_code"] = (
        "EXECUTOR_EXIT_RECEIPT_MISMATCH"
        if receipt_status == "SUCCESS"
        else "EXECUTOR_OUTCOME_UNVERIFIED"
    )
    return partial


def dump_executor_slack_detail(state, outcome):
    request_id = safe_mrkdwn(state.get("request_id") or "UNKNOWN", 80)
    phase = safe_mrkdwn(outcome.get("phase") or "UNKNOWN", 64)
    failure_code = safe_mrkdwn(outcome.get("failure_code") or "-", 96)
    if outcome["status"] == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        backup_id = safe_mrkdwn(
            outcome.get("backup_id") or latest_incident(state).get("backup_id") or "UNKNOWN", 160
        )
        emergency_origin = str(latest_incident(state).get("request_origin") or "").upper() == "EMERGENCY"
        source_note = "요청 출처: EMERGENCY\n" if emergency_origin else ""
        followup_status = safe_mrkdwn(outcome.get("dump_failover_status") or "NOT_STARTED", 32)
        followup_code = safe_mrkdwn(outcome.get("failure_code") or "-", 96)
        return (
            "DUMP_RESTORE: PASS\n"
            f"DUMP_FAILOVER: {followup_status} ({followup_code})\n"
            "상태: DB_RESTORED_NOT_FAILOVER_COMPLETE\n"
            f"{source_note}"
            f"요청 ID: {request_id}\n"
            f"Backup ID: `{backup_id}`\n"
            "DR DB 복원·데이터 검증은 완료되었습니다.\n"
            "Web/EMR Health 및 필요한 DNS 전환은 미완료입니다."
        )
    if outcome.get("executor_kind") == "demo-existing-dr" and outcome["status"] == "FAILED":
        backup_id = safe_mrkdwn(latest_incident(state).get("backup_id") or "UNKNOWN", 160)
        app_note = (
            "Web/EMR: 차단 상태 유지, 운영자 확인 필요"
            if outcome.get("operator_intervention_required")
            else "Web/EMR: 실행 전 차단 단계 미진입"
        )
        return (
            "상태: FAILED (복원 전 안전 중단)\n"
            "DB 복원 단계: 시작되지 않음\n"
            f"요청 ID: {request_id}\n"
            f"Backup ID: `{backup_id}`\n"
            f"실패 단계: {phase}\n"
            f"오류 코드: {failure_code}\n"
            f"{app_note}\n"
            "전체 Failover: 미완료"
        )
    if outcome["status"] == "PARTIAL_FAILURE":
        if outcome.get("dump_restore_status") == "PASS":
            detail = (
                "상태: PARTIAL_FAILURE\n"
                "DUMP_RESTORE: PASS\n"
                "DUMP_FAILOVER: PARTIAL_FAILURE\n"
                "자동 Rollback: 금지\n"
                "운영자 개입: 필요\n"
                f"요청 ID: {request_id}\n"
                f"실패 단계: {phase}\n"
                f"오류 코드: {failure_code}"
            )
        else:
            detail = (
                "상태: PARTIAL_FAILURE\n"
                "DUMP_RESTORE: 확인 필요\n"
                "DUMP_FAILOVER: PARTIAL_FAILURE\n"
                "자동 Rollback: 금지\n"
                "운영자 개입: 필요\n"
                f"요청 ID: {request_id}\n"
                f"실패 단계: {phase}\n"
                f"오류 코드: {failure_code}"
            )
        if outcome.get("executor_kind") == "demo-existing-dr":
            backup_id = safe_mrkdwn(latest_incident(state).get("backup_id") or "UNKNOWN", 160)
            detail += f"\nBackup ID: `{backup_id}`"
        return detail
    if outcome["status"] == "FAILED":
        return (
            "상태: FAILED (안전한 실패/복구 결과 확인)\n"
            f"요청 ID: {request_id}\n"
            f"실패 단계: {phase}\n"
            f"오류 코드: {failure_code}"
        )
    return "DUMP_RESTORE: PASS\nDUMP_FAILOVER: PASS\n전체 서비스 검증 및 DR_ACTIVE 기록 확인"


def audit_dump_executor_outcome(app, state, outcome):
    app.extensions["chatops_audit"].record_event(
        "dump_failover_execution_result",
        {
            "request_id": state.get("request_id"),
            "request_type": REQUEST_TYPE_DUMP_RESTORE,
            "status": outcome.get("status"),
            "result": outcome.get("result"),
            "failure_phase": outcome.get("phase"),
            "failure_code": outcome.get("failure_code"),
            "automatic_rollback_allowed": outcome.get("automatic_rollback_allowed") is True,
            "operator_intervention_required": outcome.get("operator_intervention_required") is True,
        },
    )


def request_client_key_from_state(state):
    return str(
        state.get("slack_client_key")
        or latest_incident(state).get("slack_client_key")
        or state.get("action")
    ).strip()


def render_request_message(state, detail=None):
    request_type = request_type_from_state(state)
    approval_required = int(state.get("approval_required") or REQUIRED_APPROVALS)
    latest = latest_incident(state)
    test_only = is_test_mode_failover(state)
    compact_request = (
        request_type in FAILOVER_RECOVERY_REQUEST_TYPES
        or (
            state.get("action") == "failback"
            and request_type in {"NORMAL_FAILBACK", REQUEST_TYPE_EMERGENCY_FAILBACK}
        )
    )
    if request_type == REQUEST_TYPE_EMERGENCY_FAILOVER:
        title = "[EMERGENCY FAILOVER]"
        description = "긴급 재해복구 사유를 확인했습니다."
        prompt = "재해복구 환경으로 전환하시겠습니까?"
    elif request_type == REQUEST_TYPE_EMERGENCY_FAILBACK:
        title = "[EMERGENCY FAILBACK]"
        description = "긴급 환원 사유를 확인했습니다."
        prompt = "온프레미스 환경으로 전환하시겠습니까?"
    elif request_type == REQUEST_TYPE_DUMP_RESTORE:
        dump_emergency = str(latest.get("request_origin") or "").strip().upper() == "EMERGENCY"
        title = "[EMERGENCY DUMP RESTORE]" if dump_emergency else "[DUMP RESTORE]"
        if dump_emergency:
            description = "긴급 재해복구 사유를 확인했습니다."
            prompt = "재해복구 환경으로 전환하시겠습니까?"
        else:
            description = "Dump 복구 데이터 검증이 완료되었습니다."
            prompt = "재해복구 환경으로 전환하시겠습니까?"
    elif request_type == REQUEST_TYPE_SECURITY:
        title = "🛡️ SECURITY DR ESCALATION"
        description = "파괴적 Critical 보안 이벤트에 대한 DR 승인 후보입니다."
        prompt = "자동 실행하지 않으며 관리자 승인이 필요합니다."
    elif request_type == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
        title = "[SYNTHETIC AWS MYSQL FAILOVER DEMO]"
        description = "운영 DR과 분리된 합성 MySQL 데이터 왕복 시연입니다."
        prompt = (
            "임시 1인 승인은 이 합성 실행기에만 적용됩니다. 승인 시 고정 Canary의 "
            "hospital_demo만 안전 검사 후 재설정하고 A 복원→B 추가→A+B 복귀를 실행합니다."
        )
    else:
        title, description, prompt = request_ui_copy(state["action"])
    if test_only:
        title = "[ZABBIX FAILOVER DELIVERY TEST]"
        description = "서명된 Zabbix→ChatOps 전달과 2인 승인만 확인하는 테스트 요청입니다."
        prompt = "두 관리자가 승인해도 Failover Executor는 호출되지 않으며 AWS/DB/DNS는 변경되지 않습니다."
    if approval_required == 1 and not test_only and request_type != SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
        mode_expiry = state.get("approval_mode_expires_at")
        prompt = (
            "임시 1인 승인 테스트 모드입니다. 승인 인원만 간소화되며 실행 전 안전 검사는 유지됩니다. "
            f"테스트 모드 만료: {format_timestamp(mode_expiry)}"
        )
    approvers = " ".join(f"<@{user_id}>" for user_id in state["approvers"])
    test_incidents = [item for item in state.get("incidents") or [] if item.get("test_mode")]
    emergency_request = (
        request_type in {REQUEST_TYPE_EMERGENCY_FAILOVER, REQUEST_TYPE_EMERGENCY_FAILBACK}
        or (
            request_type == REQUEST_TYPE_DUMP_RESTORE
            and str(latest.get("request_origin") or "").strip().upper() == "EMERGENCY"
        )
    )
    lines = [
        f"*{safe_mrkdwn(title, 160)}*",
        "",
        safe_mrkdwn(description, 300),
        safe_mrkdwn(prompt, 300),
    ]
    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        lines.append("승인 시 기존 AWS DR hospital_db 데이터가 선택한 Dump로 덮어써집니다.")
    if emergency_request:
        if request_type == REQUEST_TYPE_DUMP_RESTORE:
            reason = latest.get("reason_text") or "요청 메시지가 생성되지 않았습니다."
        else:
            reason = latest.get("reason_text") or latest.get("reason_code") or "-"
        lines.append(f"요청 사유: `{safe_mrkdwn(reason, 240)}`")
    approval_status_line = f"승인 상태: *{len(state['approvers'])}/{approval_required}*"
    if approvers:
        approval_status_line = f"{approval_status_line} {approvers}"
    lines.extend(("", approval_status_line))
    if test_incidents:
        latest = test_incidents[-1]
        lines.extend(
            (
                "*[DR TEST MODE] 승인 전달 테스트 전용 — 실제 Failover 실행은 불가능합니다.*",
                f"테스트 Host: `{safe_mrkdwn(latest.get('host'), 120)}`",
                f"Zabbix Event: `{safe_mrkdwn(latest.get('incident_id'), 160)}`",
            )
        )
        if latest.get("trigger_id"):
            lines.append(f"Zabbix Trigger: `{safe_mrkdwn(latest.get('trigger_id'), 80)}`")
    request_id = safe_mrkdwn(state["request_id"], 120)
    lines.append(f"요청 ID: `{request_id}`")
    if compact_request:
        lines.append(
            f"복구 대상: `{DEMO_DUMP_OVERWRITE_TARGET['instance_id']} / "
            f"{DEMO_DUMP_OVERWRITE_TARGET['private_ip']}:{DEMO_DUMP_OVERWRITE_TARGET['port']} / "
            f"{DEMO_DUMP_OVERWRITE_TARGET['database']}`"
        )
        if state["action"] != "failback":
            lines.extend((
                "",
                f"만료 시각: `{safe_mrkdwn(format_kst_timestamp(state.get('expires_at')), 80)}`",
            ))
    if request_type == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
        authorization = latest.get(SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD)
        target = authorization.get("target", {}) if isinstance(authorization, dict) else {}
        lines.extend((
            f"합성 대상: `{safe_mrkdwn(target.get('instance_id') or 'UNVERIFIED', 40)}` / "
            f"`{safe_mrkdwn(target.get('vpc_id') or 'UNVERIFIED', 40)}`",
            f"데이터베이스/범위: `{safe_mrkdwn(target.get('database') or 'UNVERIFIED', 40)}` / "
            "고정 합성 DB에 한정",
            "운영 DR_STATE, 운영 DB, DNS, Production Failover 실행기는 변경하지 않습니다.",
            f"시연 승인 창 만료: `{safe_mrkdwn(format_timestamp(state.get('approval_mode_expires_at')), 80)}`",
        ))
    if not compact_request and request_type in {
        REQUEST_TYPE_EMERGENCY_FAILOVER,
        REQUEST_TYPE_EMERGENCY_FAILBACK,
    }:
        lines.extend(
            (
                f"요청자: `{safe_mrkdwn(latest.get('requested_by') or '-', 80)}`",
                f"긴급 사유: *{safe_mrkdwn(latest.get('reason_text') or latest.get('reason_code') or '-', 240)}*",
                f"자동 감지 조건: *BYPASSED*",
                f"만료 시각: `{safe_mrkdwn(format_timestamp(state.get('expires_at')), 80)}`",
            )
        )
    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        lines.extend(
            (
                "",
                f"Backup ID: `{safe_mrkdwn(latest.get('backup_id') or '-', 160)}`",
                f"Backup timestamp: `{safe_mrkdwn(latest.get('backup_timestamp') or '-', 100)}`",
                f"SHA-256: `{safe_mrkdwn(latest.get('backup_checksum') or '-', 80)}`",
                "",
                f"만료 시각: `{safe_mrkdwn(format_kst_timestamp(state.get('expires_at')), 80)}`",
            )
        )
    if request_type != REQUEST_TYPE_DUMP_RESTORE and not compact_request and latest.get("precheck_status"):
        lines.append(
            f"Pre-check: *{safe_mrkdwn(latest.get('precheck_status'), 20)}* "
            f"{safe_mrkdwn(latest.get('precheck_reason'), 240)}"
        )
    if state["status"] not in APPROVAL_STATUSES:
        if test_only and state.get("result") == "test_mode_executor_suppressed":
            lines.append("상태: *테스트 완료 (Executor 미호출)*")
        else:
            lines.append(f"상태: *{ui_status_label(state['status'])}*")
    if state["action"] == "failback" and compact_request:
        security_status, _, _, _ = failback_security_from_state(state)
        risk_level, _, risk_checked_at, _ = failback_risk_from_state(state)
        network_status, _, _, _ = failback_network_from_state(state)
        lines.extend((
            "",
            f"Network/SNMP: `{safe_mrkdwn(network_status, 20)}`",
            f"보안 상태: `{safe_mrkdwn(security_status, 20)}`",
            f"Wazuh 위험도: `{safe_mrkdwn(risk_level, 12)}` "
            f"(확인: `{safe_mrkdwn(risk_checked_at, 40)}`)",
            "",
            f"만료 시각: `{safe_mrkdwn(format_kst_timestamp(state.get('expires_at')), 80)}`",
        ))
    elif state["action"] == "failback":
        security_status, security_reason, agents, critical_incident = failback_security_from_state(state)
        risk_level, risk_observed_at, risk_checked_at, risk_reason = failback_risk_from_state(state)
        network_status, network_reason, network_source, network_devices = failback_network_from_state(state)
        stability_verified, stability_seconds, stability_required = failback_stability_from_state(state)
        lines.extend(
            (
                f"Network/SNMP: *{safe_mrkdwn(network_status, 20)}*",
                f"Network source: *{safe_mrkdwn(network_source, 60)}*",
                f"Network devices: *{sum(1 for item in network_devices.values() if item.get('status') == 'READY')} ready*",
                f"보안 상태: *{safe_mrkdwn(security_status, 20)}*",
                (
                    f"⚠️ *Wazuh 위험도: {safe_mrkdwn(risk_level, 12)}* "
                    f"(이벤트: `{safe_mrkdwn(risk_observed_at, 40)}`, "
                    f"확인: `{safe_mrkdwn(risk_checked_at, 40)}`) — "
                    "위험도 안내만으로 승인 인원은 변경하지 않습니다."
                    if risk_level in {"HIGH", "CRITICAL"}
                    else f"Wazuh 위험도: *{safe_mrkdwn(risk_level, 12)}* "
                    f"(확인: `{safe_mrkdwn(risk_checked_at, 40)}`)"
                ),
                f"Wazuh Agent: *{safe_mrkdwn(agents, 40)}*",
                f"Critical 보안 이벤트: *{safe_mrkdwn(critical_incident, 160)}*",
                (
                    f"Recovery timing: *{stability_seconds}s immediate (no sustained window)*"
                    if stability_required == 0
                    else f"Stability: *{stability_seconds}s/{stability_required}s {'PASS' if stability_verified else 'NOT VERIFIED'}*"
                ),
            )
        )
        if network_status != "READY":
            lines.append(f"Network 사유: {safe_mrkdwn(network_reason, 240)}")
        if security_status != "READY":
            lines.append(f"사유: {safe_mrkdwn(security_reason, 240)}")
        if risk_level == "UNKNOWN" and risk_reason:
            lines.append(f"Wazuh 위험도 사유: {safe_mrkdwn(risk_reason, 160)}")
    if detail:
        lines.extend(("", f"처리 결과: {safe_mrkdwn(detail, 400)}"))

    text = "\n".join(lines)

    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    if state["status"] in APPROVAL_STATUSES:
        # Keep Approve visible for every pending request. Failback's DR state,
        # Network/SNMP, and security gates are rechecked by the approval handler
        # before an approval is recorded or execution can start.
        if test_only:
            approval_note = "※ 테스트 승인만 기록합니다. 2인 승인 후 실제 실행기·AWS·DB·DNS를 호출하지 않습니다."
            approval_text = "2인 테스트 승인 (실행 없음)"
        elif request_type == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
            approval_note = "※ 1인 승인은 이 고정 합성 MySQL 시연에만 적용되며 운영 Failover에는 적용되지 않습니다."
            approval_text = "합성 시연 1인 승인"
        elif approval_required == 1:
            approval_note = "※ 임시 1인 승인은 이 요청 유형에서 허용되지 않습니다. 새 2인 운영 요청을 사용하세요."
            approval_text = "운영 2인 승인 필요"
        else:
            approval_note = "※ 서로 다른 관리자 2명의 승인이 완료되어야 실행됩니다. 승인 대기 중 관리자 1명이 취소할 수 있습니다."
            approval_text = "Approve"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            approval_note
                        ),
                    }
                ],
            }
        )
        elements = []
        approval_value_extra = {}
        approval_button = {
            "type": "button",
            "action_id": "hospital_dr_approve",
            "text": {"type": "plain_text", "text": approval_text},
            "style": "primary",
        }
        if state["action"] == "failback":
            risk_level, risk_observed_at, _, _ = failback_risk_from_state(state)
            approval_value_extra = {
                "wazuh_risk_level": risk_level,
                "wazuh_risk_observed_at": risk_observed_at,
                "db_failback_overwrite_confirmation": "OVERWRITE_ONPREM_DB",
                "db_failback_overwrite_request_id": state["request_id"],
            }
            approval_button["confirm"] = failback_db_overwrite_confirmation(
                state["request_id"], risk_level
            )
        approval_button["value"] = button_value(
            state["request_id"], state["action"], "approve", **approval_value_extra
        )
        elements.append(approval_button)
        if state["action"] == "failover" and not test_only:
            elements.append(
                {
                    "type": "button",
                    "action_id": "hospital_dr_dump_open",
                    "text": {
                        "type": "plain_text",
                        "text": "Dump 변경" if request_type == REQUEST_TYPE_DUMP_RESTORE else "Dump 복구",
                    },
                    "value": button_value(
                        state["request_id"],
                        state["action"],
                        "dump_open",
                        request_type=REQUEST_TYPE_DUMP_RESTORE,
                    ),
                }
            )
        elements.append(
            {
                "type": "button",
                "action_id": "hospital_dr_cancel",
                "text": {"type": "plain_text", "text": "Cancel"},
                "style": "danger",
                "value": button_value(state["request_id"], state["action"], "cancel"),
                "confirm": {
                    "title": {"type": "plain_text", "text": "요청을 취소하시겠습니까?"},
                    "text": {"type": "mrkdwn", "text": "현재 승인과 요청이 모두 취소됩니다."},
                    "confirm": {"type": "plain_text", "text": "취소"},
                    "deny": {"type": "plain_text", "text": "대기"},
                },
            }
        )
        blocks.append(
            {
                "type": "actions",
                "elements": elements,
            }
        )
    elif state["status"] in {
        "EXECUTING", "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE", "FAILED", "PARTIAL_FAILURE"
    }:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "hospital_dr_execution_log",
                        "text": {"type": "plain_text", "text": "실행 로그 확인"},
                        "value": button_value(
                            state["request_id"], state["action"], "execution_log"
                        ),
                    }
                ],
            }
        )
    return title, blocks


def command_for_action(action, script_root):
    if action == "failover":
        return ["bash", os.path.join(script_root, "full_failover.sh")]
    if action == "failback":
        return ["bash", os.path.join(script_root, "web_db_failback.sh")]
    return None


def dump_restore_executor_error(config):
    """Return a fail-closed configuration error for the optional executor."""
    executor = str(config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
    if not executor:
        return "is not configured"
    if not os.path.isabs(executor):
        return "path must be absolute"
    if os.path.islink(executor) or not os.path.isfile(executor):
        return "file is missing or is not a regular file"
    if not os.access(executor, os.R_OK | os.X_OK):
        return "file is not readable and executable by the ChatOps service user"
    return None


def dump_restore_command_error(state, config):
    """Explain why a Dump command cannot be launched, without invoking it."""
    provenance_error = dump_request_execution_guard(state)
    if provenance_error:
        return provenance_error
    approvers = state.get("approvers")
    if (
        state.get("status") != "EXECUTING"
        or state.get("approval_required") != REQUIRED_APPROVALS
        or not isinstance(approvers, list)
        or len(approvers) != REQUIRED_APPROVALS
        or not all(isinstance(user_id, str) and user_id for user_id in approvers)
        or len(set(approvers)) != REQUIRED_APPROVALS
    ):
        return "dump_restore_two_admin_approval_required"
    incident = latest_incident(state)
    if not config.get("DUMP_RESTORE_EXEC_ENABLED"):
        return "dump_restore_disabled"
    if dump_restore_executor_error(config):
        return "dump_restore_executor_not_ready"
    if not is_demo_dump_executor_configured(config):
        return "existing_dr_demo_dump_executor_not_configured"
    restore_mode = str(incident.get("dump_restore_mode") or "")
    if restore_mode not in {"MANIFEST_VERIFIED", "LEGACY_MANUAL"}:
        return "dump_restore_mode_invalid"
    if restore_mode == "LEGACY_MANUAL":
        expected_rpo = incident.get("expected_rpo")
        sidecar_checksum = str(incident.get("backup_sidecar_checksum") or "").lower()
        if (
            not isinstance(expected_rpo, dict)
            or expected_rpo.get("status") != "NOT_MEASURED"
            or expected_rpo.get("seconds") is not None
            or not re.fullmatch(r"[0-9a-f]{64}", sidecar_checksum)
        ):
            return "legacy_dump_request_validation_invalid"
    backup_id = str(incident.get("backup_id") or "")
    if not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id):
        return "dump_restore_backup_id_invalid"
    checksum = str(incident.get("backup_checksum") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        return "dump_restore_backup_checksum_missing"
    return _dump_overwrite_authorization_error(
        state,
        request_id=state.get("request_id"),
        approved=True,
    )


def command_for_request(state, script_root, config):
    request_type = request_type_from_state(state)
    if request_type == SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE:
        try:
            contract = _synthetic_mysql_demo_contract_module(config)
            root = contract.REPOSITORY_ROOT.resolve(strict=True)
            executor = root / contract.EXECUTOR_RELATIVE_PATH
            static_binding = contract.expected_static_binding(root)
        except Exception:
            return None
        authorization = latest_incident(state).get(SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD)
        if (
            state.get("action") != "failover"
            or not isinstance(authorization, dict)
            or any(authorization.get(key) != value for key, value in static_binding.items())
            or executor.is_symlink()
            or not executor.is_file()
            or not os.access(executor, os.R_OK)
            or not re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                str(state.get("request_id") or ""),
            )
        ):
            return None
        database = str(config.get("CHATOPS_STATE_DB") or "")
        if not os.path.isabs(database):
            return None
        return [
            sys.executable,
            str(executor),
            "--database",
            database,
            "--request-id",
            str(state["request_id"]),
        ]
    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        if dump_restore_command_error(state, config):
            return None
        executor = str(config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
        incident = latest_incident(state)
        return [
            executor,
            "--request-id",
            str(state.get("request_id") or ""),
            "--backup-id",
            str(incident["backup_id"]),
            "--expected-sha256",
            str(incident["backup_checksum"]).lower(),
            "--continue-failover",
        ]
    return command_for_action(state.get("action"), script_root)


def classify_failback_pipeline_result(return_code, timed_out, dr_state):
    """Require a clean runner exit and its final IDLE readback for success.

    Once the failback process has started, a non-zero exit or missing final
    state can follow an On-Prem data write, so ChatOps must preserve it as a
    partial/uncertain result instead of presenting a safe failure or success.
    """
    if not timed_out and return_code == 0 and dr_state == "IDLE":
        return {
            "status": "SUCCEEDED",
            "result": "failback_runner_completed_and_idle_verified",
            "detail": "Failback 실행 완료 및 최종 DR 상태 IDLE 확인",
        }
    return {
        "status": "PARTIAL_FAILURE",
        "result": "failback_result_uncertain_operator_review_required",
        "detail": (
            "PARTIAL_FAILURE: Failback 결과가 불확실합니다. On-Prem DB 쓰기 여부를 확인하고 "
            "운영자 개입이 필요합니다. 자동 재실행/롤백하지 마세요. "
            f"(exit_code={return_code}, DR_STATE={dr_state or 'UNKNOWN'})"
        ),
    }


def should_suppress_log_line(line):
    noisy_patterns = (
        "CryptographyDeprecationWarning",
        "algorithms.TripleDES",
        "The authenticity of host",
        "ED25519 key fingerprint is",
        "This host key is known by the following other names/addresses",
        "Are you sure you want to continue connecting",
        "Warning: Permanently added",
    )
    return any(pattern in line for pattern in noisy_patterns) or "known_hosts:" in line


_EXECUTION_LOG_SECRET_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|token|secret|private[_ -]?key|"
    r"access[_ -]?key|aws_secret_access_key|aws_session_token|"
    r"signing_secret)\b\s*[:=]\s*)[^\s,;]+"
)


def sanitize_execution_log_line(line):
    """Remove common credential-shaped values before persistence or Slack output."""
    sanitized = _EXECUTION_LOG_SECRET_PATTERN.sub(r"\1[REDACTED]", str(line or ""))
    return sanitized[:4000]


def execution_log_path(app, request_id):
    request_id = str(request_id or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", request_id):
        return None
    configured_log_dir = str(app.config.get("CHATOPS_EXECUTION_LOG_DIR") or "").strip()
    if not configured_log_dir:
        return None
    log_dir = os.path.abspath(configured_log_dir)
    return os.path.join(log_dir, f"{request_id}.log")


def append_execution_log(app, request_id, line):
    path = execution_log_path(app, request_id)
    if path is None:
        return
    descriptor = None
    try:
        log_dir = os.path.dirname(path)
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        directory_meta = os.lstat(log_dir)
        if (
            stat.S_ISLNK(directory_meta.st_mode)
            or not stat.S_ISDIR(directory_meta.st_mode)
            or directory_meta.st_uid != os.geteuid()
        ):
            return
        os.chmod(log_dir, 0o700)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            os.close(descriptor)
            descriptor = None
            return
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            descriptor = None
            handle.write(sanitize_execution_log_line(line).rstrip("\n") + "\n")
    except OSError:
        # Logging must never turn a DR workflow failure into a second failure.
        return
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_execution_log_tail(path, limit=DEFAULT_EXECUTION_LOG_TAIL_LINES):
    lines, _total, _error = read_execution_log(path, limit=limit)
    return lines


def read_execution_log(path, limit=DEFAULT_EXECUTION_LOG_TAIL_LINES):
    """Read only a bounded tail while retaining whether older lines exist."""
    result = deque(maxlen=max(1, int(limit)))
    total = 0
    descriptor = None
    try:
        log_dir = os.path.dirname(os.path.abspath(path))
        directory_meta = os.lstat(log_dir)
        if (
            stat.S_ISLNK(directory_meta.st_mode)
            or not stat.S_ISDIR(directory_meta.st_mode)
            or directory_meta.st_uid != os.geteuid()
            or stat.S_IMODE(directory_meta.st_mode) != 0o700
        ):
            return [], 0, "permission"
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            os.close(descriptor)
            descriptor = None
            return [], 0, "permission"
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as handle:
            descriptor = None
            for line in handle:
                total += 1
                if not should_suppress_log_line(line):
                    result.append(sanitize_execution_log_line(line).rstrip("\n"))
    except FileNotFoundError:
        return [], 0, "missing"
    except PermissionError:
        return [], 0, "permission"
    except OSError:
        return [], 0, "unavailable"
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return list(result), total, None


def execution_log_summary(app, state):
    """Return a private, bounded log tail suitable for Slack ephemeral output."""
    request_id = str(state.get("request_id") or "-")
    request_path = execution_log_path(app, request_id)
    status = state.get("status") or "UNKNOWN"
    result = state.get("result") or "-"
    header = (
        "실행 로그 (요청자에게만 표시)\n"
        f"요청 ID: {request_id or '-'}\n"
        f"상태: {status} / 결과: {result}\n"
    )
    if request_path is None:
        return header + "요청 ID 형식이 올바르지 않아 로그를 조회할 수 없습니다."
    lines, total_lines, read_error = read_execution_log(request_path)
    if read_error == "missing":
        return header + "이 요청의 실행 로그 파일이 아직 없습니다. 공용 로그로 대체하지 않았습니다."
    if read_error == "permission":
        return header + "로그 파일 읽기 권한이 없습니다. ChatOps 서비스 사용자와 파일 권한을 확인해 주세요."
    if read_error:
        return header + "로그 파일을 읽을 수 없습니다. ChatOps 서비스 로그에서 파일 접근 오류를 확인해 주세요."
    if not lines:
        return header + "요청별 로그 파일은 있으나 표시할 안전한 내용이 없습니다."
    body = "\n".join(lines)
    body = body[:DEFAULT_EXECUTION_LOG_MAX_CHARS]
    if len(body) == DEFAULT_EXECUTION_LOG_MAX_CHARS:
        body += "\n...[truncated]"
    history_note = (
        f"최근 {len(lines)}개 로그 행을 표시합니다. 이전 로그 {max(0, total_lines - len(lines))}개도 파일에 있습니다.\n"
        if total_lines > len(lines)
        else f"현재 로그 {len(lines)}개를 표시합니다.\n"
    )
    refresh_note = (
        "실행 중입니다. 최신 내용을 보려면 원본 요청의 [실행 로그 확인]을 다시 누르세요.\n"
        if status == "EXECUTING"
        else "종료된 요청의 로그입니다.\n"
    )
    return (
        header
        + history_note
        + refresh_note
        + "최근 실행 로그:\n```\n"
        + safe_mrkdwn(body, DEFAULT_EXECUTION_LOG_MAX_CHARS)
        + "\n```"
    )


def execution_log_response_payload(app, state):
    """Build an ephemeral log view; its close action never edits the approval message."""
    summary = execution_log_summary(app, state)
    blocks = []
    marker = "최근 실행 로그:\n```\n"
    if marker in summary:
        header, tail = summary.split(marker, 1)
        log_body = tail.rsplit("\n```", 1)[0]
        blocks.append({"type": "section", "text": {"type": "plain_text", "text": header}})
        current = []
        current_size = 0
        for line in log_body.splitlines():
            safe_line = line[:2800]
            if current and current_size + len(safe_line) + 1 > 2800:
                blocks.append(
                    {"type": "section", "text": {"type": "plain_text", "text": "\n".join(current)}}
                )
                current, current_size = [], 0
            current.append(safe_line)
            current_size += len(safe_line) + 1
        if current:
            blocks.append(
                {"type": "section", "text": {"type": "plain_text", "text": "\n".join(current)}}
            )
    else:
        blocks.append(
            {"type": "section", "text": {"type": "plain_text", "text": summary[:2800]}}
        )
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "action_id": "hospital_dr_execution_log",
                    "text": {"type": "plain_text", "text": "실행 로그 닫기"},
                    "value": button_value(
                        state["request_id"], state["action"], "execution_log_close"
                    ),
                }
            ],
        }
    )
    return {
        "response_type": "ephemeral",
        "replace_original": False,
        "text": summary[:DEFAULT_EXECUTION_LOG_MAX_CHARS],
        "blocks": blocks,
    }


def send_execution_log_response(app, response_url, request_id, action, user_id, operation):
    """Deliver or close a request-scoped ephemeral log view outside Slack's ACK window."""
    response_payload = None
    try:
        with app.app_context():
            if user_id not in app.extensions.get("admin_user_ids", set()):
                response_payload = {
                    "response_type": "ephemeral",
                    "replace_original": False,
                    "text": "현재 관리자 allowlist에 없는 사용자입니다. 로그를 표시하지 않았습니다.",
                }
            elif operation == "execution_log_close":
                response_payload = {"delete_original": True}
            else:
                state = app.extensions["approval_store"].get(request_id)
                if not state or state.get("action") != action:
                    response_payload = {
                        "response_type": "ephemeral",
                        "replace_original": False,
                        "text": "요청을 찾을 수 없거나 작업 유형이 일치하지 않습니다.",
                    }
                else:
                    response_payload = execution_log_response_payload(app, state)
        sender = app.config.get("EXECUTION_LOG_RESPONSE_SENDER") or requests.post
        response = sender(response_url, json=response_payload, timeout=(2, 5))
        response.raise_for_status()
    except Exception as exc:
        # response_url is a short-lived secret capability; never include it in logs.
        print(
            f"EXECUTION_LOG_RESPONSE_FAILED request_id={request_id} error={type(exc).__name__}",
            flush=True,
        )
    finally:
        key = (str(request_id), str(user_id))
        lock = app.extensions.get("execution_log_lock")
        if lock is not None:
            with lock:
                app.extensions["execution_log_inflight"].discard(key)


def start_execution_log_response(app, response_url, request_id, action, user_id, operation):
    """Schedule an interaction follow-up, with duplicate-click suppression."""
    key = (str(request_id), str(user_id))
    lock = app.extensions["execution_log_lock"]
    with lock:
        if key in app.extensions["execution_log_inflight"]:
            return "already_running"
        app.extensions["execution_log_inflight"].add(key)
    try:
        threading.Thread(
            target=send_execution_log_response,
            args=(app, response_url, request_id, action, user_id, operation),
            daemon=True,
            name="chatops-execution-log",
        ).start()
    except Exception as exc:
        with lock:
            app.extensions["execution_log_inflight"].discard(key)
        print(f"EXECUTION_LOG_START_FAILED error={type(exc).__name__}", flush=True)
        return "start_failed"
    return "started"


REPLACEABLE_MESSAGE_ERRORS = frozenset({"cant_update_message", "message_not_found"})


def register_request_message(app, state):
    try:
        app.extensions["chatops_audit"].register_request_message(state)
    except Exception as exc:
        # Audit failures must never stop an approval or DR workflow.
        print(f"[AUDIT WARN] Request message registration failed: {type(exc).__name__}", flush=True)


def deliver_slack_message(app, state, text, blocks):
    """Update the tracked message, replacing only stale/unowned messages."""
    if not state:
        raise RuntimeError("approval request state is missing")
    store = app.extensions["approval_store"]
    client_key = request_client_key_from_state(state)
    client = app.extensions["slack_clients"].get(client_key)
    if client is None:
        raise RuntimeError(f"Slack client is not configured for request channel {client_key}")
    if not client.available:
        raise RuntimeError(f"Slack client is unavailable for request channel {client_key}")

    if state.get("slack_message_ts") and state.get("slack_channel_id"):
        try:
            client.update_message(state["slack_channel_id"], state["slack_message_ts"], text, blocks)
            register_request_message(app, state)
            return state
        except SlackApiError as exc:
            if exc.error not in REPLACEABLE_MESSAGE_ERRORS:
                raise
            print(
                f"[SLACK WARN] Replacing stale request message action={state['action']} error={exc.error}",
                flush=True,
            )
            state = store.clear_slack_message(state["request_id"])

    result = client.post_message(text, blocks)
    state = store.attach_slack_message(
        state["request_id"], result.get("channel") or client.channel_id, result["ts"]
    )
    register_request_message(app, state)
    return state


def update_slack_message(app, state, detail=None):
    if not state or not state.get("slack_channel_id") or not state.get("slack_message_ts"):
        return False
    text, blocks = render_request_message(state, detail)
    try:
        deliver_slack_message(app, state, text, blocks)
        return True
    except SlackApiError as exc:
        print(
            f"[SLACK ERROR] Request message update failed method={exc.method} error={exc.error}",
            flush=True,
        )
        return False
    except Exception as exc:
        print(f"[SLACK ERROR] Request message update failed: {type(exc).__name__}", flush=True)
        return False


def expire_pending_requests(app, now=None):
    now = utc_timestamp() if now is None else float(now)
    required, active_deadline = approval_policy_from_config(
        app.config,
        "failover",
        request_type=SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE,
        now=now,
    )
    test_mode_expired = app.extensions["approval_store"].expire_single_approval_requests(
        active_mode_expires_at=active_deadline if required == 1 else None,
        now=now,
    )
    for state in test_mode_expired:
        app.extensions["chatops_audit"].record_event(
            "single_approval_test_request_expired",
            {
                "request_id": state["request_id"],
                "approval_required": 1,
                "approval_mode_expires_at": state.get("approval_mode_expires_at"),
                "reason": "test_mode_ended_or_policy_changed",
                "scope": "synthetic_mysql_demo_only",
            },
            now=now,
        )
        update_slack_message(
            app,
            state,
            "임시 1인 승인 테스트 모드가 종료되어 미완료 요청이 만료되었습니다. 새 요청을 생성해 주세요.",
        )

    configured_deadline = app.config.get("APPROVAL_TEST_EXPIRES_AT_EPOCH")
    if (
        app.config.get("APPROVAL_REQUIRED") == 1
        and configured_deadline is not None
        and now >= float(configured_deadline)
    ):
        expiry_lock = app.extensions.get("approval_mode_expiry_audit_lock")
        if expiry_lock is not None:
            with expiry_lock:
                if not app.extensions.get("approval_mode_expiry_audited"):
                    app.extensions["chatops_audit"].record_event(
                        "single_approval_test_mode_expired",
                        {
                            "approval_required": REQUIRED_APPROVALS,
                            "approval_mode_expires_at": configured_deadline,
                            "reason": "configured_test_window_elapsed",
                        },
                        now=now,
                    )
                    app.extensions["approval_mode_expiry_audited"] = True

    expired = app.extensions["approval_store"].expire_due(now=now)
    for state in expired:
        update_slack_message(app, state, "Approval window expired. A new incident will require a new request. / 승인 시간이 만료되었습니다.")
    return test_mode_expired + expired


def cleanup_old_slack_messages(app, now=None, ensure_console=True):
    """Audit and delete old terminal ChatOps messages without affecting DR state."""
    audit = app.extensions["chatops_audit"]
    store = app.extensions["approval_store"]
    if ensure_console:
        ensure_emergency_console(app)
    # Refresh status before selecting candidates so a failed Slack update cannot
    # leave a terminal request stuck with an old ACTIVE registry status.
    for state in store.list_with_messages():
        register_request_message(app, state)
    candidates = audit.candidates(
        now=now,
        ttl_seconds=app.config["CHATOPS_SLACK_CLEANUP_TTL_SECONDS"],
    )
    deleted = 0
    skipped = 0
    failed = 0
    for row in candidates:
        client = None
        audit_payload = row.get("payload")
        if row["kind"] == "request":
            state = store.get(row.get("request_id"))
            if not state or state.get("status") not in TERMINAL_STATUSES:
                skipped += 1
                continue
            state = dict(state)
            state["slack_channel_id"] = row["channel_id"]
            state["slack_message_ts"] = row["message_ts"]
            audit_payload = request_audit_payload(state)
            client = app.extensions["slack_clients"].get(request_client_key_from_state(state))
        elif row["kind"] == "alert":
            client = app.extensions.get("wazuh_alert_client")
        if client is None or not getattr(client, "available", False):
            skipped += 1
            continue
        try:
            prepared = audit.prepare_delete(row["message_key"], now=now, payload=audit_payload)
            if prepared is None:
                skipped += 1
                continue
            client.delete_message(prepared["channel_id"], prepared["message_ts"])
        except SlackApiError as exc:
            if exc.error == "message_not_found":
                audit.mark_deleted(row["message_key"], now=now)
                deleted += 1
                continue
            audit.mark_delete_failed(row["message_key"], exc.error, now=now)
            failed += 1
            print(
                f"[SLACK CLEANUP] Delete failed key={row['message_key']} error={exc.error}",
                flush=True,
            )
            continue
        except Exception as exc:
            audit.mark_delete_failed(row["message_key"], type(exc).__name__, now=now)
            failed += 1
            print(
                f"[SLACK CLEANUP] Delete failed key={row['message_key']} error={type(exc).__name__}",
                flush=True,
            )
            continue
        audit.mark_deleted(row["message_key"], now=now)
        deleted += 1
        print(f"[SLACK CLEANUP] Deleted key={row['message_key']}", flush=True)
    return {"candidates": len(candidates), "deleted": deleted, "skipped": skipped, "failed": failed}


def _create_approval_request_unlocked(app, action, incident, ttl_seconds=None):
    """Create or update an approval request and deliver its control message."""
    if action == "failover":
        dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
        if dr_state == "DR_ACTIVE":
            source = safe_mrkdwn(incident.get("source") or incident.get("request_origin") or "manual", 80)
            print(
                f"[CHATOPS] failover request suppressed reason=DR_ALREADY_ACTIVE source={source}",
                flush=True,
            )
            raise FailoverRequestBlocked()

    store = app.extensions["approval_store"]
    client_key = str(incident.get("slack_client_key") or action)
    slack_client = app.extensions["slack_clients"].get(client_key)
    if slack_client is None:
        raise RuntimeError(f"Slack client is not configured for request channel {client_key}")
    if not slack_client.available:
        raise RuntimeError(f"Slack client is unavailable for request channel {client_key}")

    expire_pending_requests(app)
    approval_required, approval_mode_expires_at = approval_policy_from_config(
        app.config, action, request_type=incident.get("request_type")
    )
    recovery_plan = None
    if (
        action == "failover"
        and str(incident.get("request_type") or "").strip() in FAILOVER_RECOVERY_REQUEST_TYPES
    ):
        incident = dict(incident)
        # Ignore any request payload attempting to provide its own candidate,
        # target, checksum, or overwrite scope.
        incident.pop(FAILOVER_RECOVERY_PLAN_FIELD, None)
        incident.pop(DEMO_DUMP_OVERWRITE_AUTH_FIELD, None)
        recovery_plan = _server_failover_recovery_plan(incident, app.config)
    state, reused = store.create_or_merge(
        action,
        incident,
        ttl_seconds=ttl_seconds,
        approval_required=approval_required,
        approval_mode_expires_at=approval_mode_expires_at,
        recovery_plan=recovery_plan,
    )
    if action == "failover" and incident.get("test_mode") and reused:
        event_id = str(incident.get("zabbix_event_id") or incident.get("incident_id") or "")
        already_recorded = any(
            str(item.get("zabbix_event_id") or item.get("incident_id") or "") == event_id
            for item in state.get("incidents") or []
            if isinstance(item, dict) and item.get("test_mode") is True
        )
        if already_recorded:
            return state, True
    if action == "failover" and not is_synthetic_mysql_demo_request(state):
        if not incident.get("test_mode") and incident.get("source") == "zabbix":
            _record_rto(incident, "incident_at")
            _record_rto(incident, "zabbix_detected_at")
        if not incident.get("test_mode"):
            _record_rto(incident, "failover_approval_created_at", approval_id=state["request_id"])
    if action == "failback" and "security_status" in incident:
        state = store.refresh_failback_security(
            state["request_id"],
            {
                "status": incident.get("security_status"),
                "reason": incident.get("security_reason"),
                "agents": incident.get("security_agents"),
                "critical_incident": incident.get("security_critical_incident"),
                "risk_level": incident.get("wazuh_risk_level"),
                "risk_observed_at": incident.get("wazuh_risk_observed_at"),
                "risk_checked_at": incident.get("wazuh_risk_checked_at"),
                "risk_reason": incident.get("wazuh_risk_reason"),
            },
        )
    if action == "failback" and "network_status" in incident:
        state = store.refresh_failback_network(
            state["request_id"],
            {
                "status": incident.get("network_status"),
                "reason": incident.get("network_reason"),
                "source": incident.get("network_source"),
                "devices": incident.get("network_devices"),
                "checked_at": incident.get("network_checked_at"),
            },
        )
    text, blocks = render_request_message(state)
    try:
        state = deliver_slack_message(app, state, text, blocks)
    except Exception as exc:
        if (
            action == "failover"
            and not reused
            and request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE
            and str(latest_incident(state).get("request_origin") or "").upper() == "EMERGENCY"
            and request_client_key_from_state(state) == "emergency"
        ):
            failed_state = store.fail_request_creation(state["request_id"])
            try:
                app.extensions["chatops_audit"].record_event(
                    "emergency_dump_request_delivery_failed",
                    {
                        "request_id": state["request_id"],
                        "request_type": REQUEST_TYPE_DUMP_RESTORE,
                        "request_origin": "EMERGENCY",
                        "result": "slack_delivery_failed",
                        "error_type": type(exc).__name__,
                    },
                )
            except Exception as audit_exc:
                print(
                    f"[AUDIT WARN] Emergency Dump delivery failure audit failed: {type(audit_exc).__name__}",
                    flush=True,
                )
            state = failed_state or state
        raise
    state = store.get(state["request_id"]) or state
    if state["status"] not in APPROVAL_STATUSES:
        update_slack_message(app, state, "요청 생성 중 더 최신 Dump 요청으로 대체되어 승인할 수 없습니다.")
        return state, reused
    replacement_type = request_type_from_state(state)
    replacement_incident = latest_incident(state)
    emergency_failover_replacement = (
        action == "failover"
        and str(replacement_incident.get("request_origin") or "").upper() == "EMERGENCY"
        and request_client_key_from_state(state) == "emergency"
        and replacement_type in {
            REQUEST_TYPE_EMERGENCY_FAILOVER,
            REQUEST_TYPE_DUMP_RESTORE,
        }
    )
    if action == "failover" and (
        emergency_failover_replacement or replacement_type == REQUEST_TYPE_DUMP_RESTORE
    ):
        cancelled_requests = store.cancel_failover_requests_for_dump(state["request_id"])
        audit = app.extensions.get("chatops_audit")
        for cancelled in cancelled_requests:
            old_type = request_type_from_state(cancelled)
            if audit is not None:
                try:
                    audit.record_event(
                        (
                            "failover_request_cancelled_by_dump"
                            if replacement_type == REQUEST_TYPE_DUMP_RESTORE
                            else "emergency_dump_request_cancelled_by_failover"
                        ),
                        {
                            "request_id": cancelled["request_id"],
                            "request_type": old_type,
                            "approvers": list(cancelled.get("approvers") or []),
                            "incident_ids": [
                                item.get("incident_id") for item in cancelled.get("incidents") or []
                                if item.get("incident_id")
                            ],
                            "cancelled_by": cancelled.get("cancelled_by"),
                            "result": cancelled.get("result"),
                            "superseded_by_request_id": state["request_id"],
                            "reason": (
                                f"superseded by Dump request {state['request_id']}"
                                if replacement_type == REQUEST_TYPE_DUMP_RESTORE
                                else f"superseded by Emergency Failover request {state['request_id']}"
                            ),
                        },
                    )
                except Exception as exc:
                    print(
                        f"[AUDIT WARN] Dump supersede event write failed: {type(exc).__name__}",
                        flush=True,
                    )
            if not update_slack_message(
                app,
                cancelled,
                (
                    "Dump Failover 요청이 생성되어 이 대기 요청은 자동 취소되었습니다."
                    if replacement_type == REQUEST_TYPE_DUMP_RESTORE
                    else "새 긴급 Failover 요청이 생성되어 이 대기 요청은 자동 취소되었습니다."
                ),
            ):
                print(
                    f"[DUMP] superseded request message update failed request_id={cancelled['request_id']}",
                    flush=True,
                )
    return state, reused


def _acquire_emergency_dump_creation_file_lock(app):
    state_db = os.path.abspath(str(app.config["CHATOPS_STATE_DB"]))
    parent = os.path.dirname(state_db)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    path = state_db + ".emergency-dump.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    handle = os.fdopen(descriptor, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        handle.close()
        raise
    return handle


def create_approval_request(app, action, incident, ttl_seconds=None):
    """Serialize Emergency Failover request creation across service workers."""
    emergency_failover = (
        action == "failover"
        and str(incident.get("request_type") or "") in {
            REQUEST_TYPE_EMERGENCY_FAILOVER,
            REQUEST_TYPE_DUMP_RESTORE,
        }
        and str(incident.get("request_origin") or "").upper() == "EMERGENCY"
        and str(incident.get("slack_client_key") or "") == "emergency"
    )
    if not emergency_failover:
        return _create_approval_request_unlocked(app, action, incident, ttl_seconds)

    lock = app.extensions.get("emergency_dump_creation_lock")
    if lock is None:
        return _create_approval_request_unlocked(app, action, incident, ttl_seconds)
    with lock:
        file_lock = _acquire_emergency_dump_creation_file_lock(app)
        try:
            return _create_approval_request_unlocked(app, action, incident, ttl_seconds)
        finally:
            try:
                fcntl.flock(file_lock.fileno(), fcntl.LOCK_UN)
            finally:
                file_lock.close()


def acquire_pipeline_file_lock(path):
    """Acquire a non-blocking lock shared by every ChatOps worker process."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    lock_handle = open(path, "a+", encoding="utf-8")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_handle.close()
        return None
    return lock_handle


def complete_test_mode_failover_approval(app, request_id, action):
    """Consume an approved test request and guarantee no external runner starts."""
    if action != "failover":
        return False
    store = app.extensions["approval_store"]
    state = store.get(request_id)
    if not is_test_mode_failover(state):
        return False
    if state.get("status") == "FAILED" and state.get("result") == "test_mode_executor_suppressed":
        return True
    completed = store.finish_test_approval(request_id)
    if completed is None:
        append_execution_log(
            app,
            request_id,
            "TEST_ONLY_EXECUTOR_SUPPRESSED=true; approval was not a complete two-admin approval.",
        )
        update_slack_message(
            app,
            state,
            "테스트 실행 차단: 유효한 서로 다른 관리자 2인 승인을 확인하지 못했습니다. "
            "실제 Executor는 시작되지 않았습니다. REAL_E2E=NOT_TESTED",
        )
        return True
    append_execution_log(
        app,
        request_id,
        "TEST_APPROVAL_ONLY=PASS; executor_started=false; AWS_DB_DNS=NOT_TOUCHED; REAL_E2E=NOT_TESTED.",
    )
    update_slack_message(
        app,
        completed,
        "TEST_APPROVAL_ONLY=PASS — 서명된 Zabbix 전달과 서로 다른 관리자 2인 승인만 확인했습니다. "
        "executor_started=false; Failover Executor는 호출하지 않았고 AWS/DB/DNS도 변경하지 않았습니다. "
        "REAL_E2E=NOT_TESTED",
    )
    return True


def release_pipeline_file_lock(lock_handle):
    if lock_handle is None:
        return
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    finally:
        lock_handle.close()


def terminate_pipeline(process):
    """Stop the whole workflow process group after a total timeout."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        process.wait(timeout=5)


def failover_recovery_summary(state, selected_mode):
    """Summarize a recovery choice only when the runner emitted its proof line."""
    if state.get("action") != "failover" or request_type_from_state(state) not in FAILOVER_RECOVERY_REQUEST_TYPES:
        return ""
    mode = selected_mode if selected_mode in {"NR", "DUMP", "EXISTING_DR_DATA"} else "UNVERIFIED"
    lines = [f"선택 복구 경로: {mode}"]
    if mode == "EXISTING_DR_DATA":
        lines.append("DB_RECOVERY=NOT_PERFORMED; 기존 AWS DR 데이터 검증 후 사용; 복구 성공으로 기록하지 않음")
    elif mode == "DUMP":
        incident = latest_incident(state)
        plan = incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
        candidate = plan.get("dump") if isinstance(plan, dict) else None
        if isinstance(candidate, dict):
            backup_id = str(candidate.get("backup_id") or "")
            timestamp = str(candidate.get("data_timestamp") or "")
            if re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id):
                lines.append(f"승인된 Backup ID: {backup_id}")
            if re.fullmatch(r"[0-9TtZz:+.\-]{10,40}", timestamp):
                lines.append(f"데이터 기준시각: {timestamp}")
            expected_rpo = candidate.get("expected_rpo")
            if (
                isinstance(expected_rpo, dict)
                and expected_rpo.get("status") == "ESTIMATED_AT_REQUEST"
                and isinstance(expected_rpo.get("seconds"), int)
                and expected_rpo["seconds"] >= 0
            ):
                lines.append(f"요청 시점 추정 RPO: {expected_rpo['seconds']}초")
            else:
                lines.append("요청 시점 추정 RPO: NOT_MEASURED")
    return "\n" + "\n".join(lines)


def run_pipeline(app, request_id, action, final_approver, response_url):
    if complete_test_mode_failover_approval(app, request_id, action):
        return
    pipeline_lock = app.extensions["pipeline_lock"]
    store = app.extensions["approval_store"]
    label = action_label(action)
    initial_state = store.get(request_id) or {}
    synthetic_request = is_synthetic_mysql_demo_request(initial_state)
    if synthetic_request:
        label = "SYNTHETIC MYSQL DEMO"
    command = None
    process_started = False
    dump_executor_request = False
    synthetic_demo_executor_request = False
    synthetic_demo_result_marker = None
    dump_log_offset = 0
    dump_log_read_error = None
    selected_recovery_mode = None
    file_lock = None
    thread_lock_held = False
    append_execution_log(
        app,
        request_id,
        f"[{format_timestamp(utc_timestamp())}] {label} request accepted for execution.",
    )

    if not pipeline_lock.acquire(blocking=False):
        append_execution_log(app, request_id, "Pipeline lock unavailable; execution was not started.")
        state = store.finish(request_id, False, result="in_process_lock_unavailable")
        update_slack_message(app, state, "Another DR workflow is already running. / 다른 DR 작업이 실행 중입니다.")
        return
    thread_lock_held = True

    try:
        try:
            file_lock = acquire_pipeline_file_lock(app.config["CHATOPS_EXECUTION_LOCK_FILE"])
        except OSError as exc:
            print(f"[{label}] Pipeline lock could not be opened: {type(exc).__name__}", flush=True)
        if file_lock is None:
            append_execution_log(app, request_id, "Cross-process pipeline lock unavailable; execution was not started.")
            state = store.finish(request_id, False, result="cross_process_lock_unavailable")
            update_slack_message(app, state, "Another DR workflow is already running. / 다른 DR 작업이 실행 중입니다.")
            return

        if not store.heartbeat(request_id):
            append_execution_log(app, request_id, "Execution lease was lost before the workflow started.")
            state = store.finish(request_id, False, result="execution_lease_lost")
            update_slack_message(app, state, "Execution lease was lost; a new approval is required. / 실행 lease가 만료되어 새 승인이 필요합니다.")
            return

        start_message = f"[{label}] Executing request {request_id} after final approval by <@{final_approver}>."
        print(start_message, flush=True)
        append_execution_log(app, request_id, start_message)
        state = store.get(request_id) or {}
        if action == "failback":
            overwrite_error = failback_overwrite_approval_error(
                state,
                request_id,
                app.extensions.get("admin_user_ids", set()),
            )
            if overwrite_error:
                append_execution_log(
                    app,
                    request_id,
                    f"Failback overwrite grant blocked; executor_started=false; result={overwrite_error}.",
                )
                state = store.finish(request_id, False, result=overwrite_error)
                update_slack_message(
                    app,
                    state,
                    "요청별 DB 덮어쓰기 실행 권한을 검증하지 못해 Failback 실행을 시작하지 않았습니다. 새 요청이 필요합니다.",
                )
                return
        incidents = state.get("incidents") or []
        latest_incident = incidents[-1] if incidents else {}
        auto_failover_request = (
            action == "failover"
            and request_type_from_state(state) in FAILOVER_RECOVERY_REQUEST_TYPES
        )
        synthetic_demo_executor_request = is_synthetic_mysql_demo_request(state)
        if auto_failover_request:
            rpo_policy_error = _failover_rpo_policy_error(latest_incident)
            if rpo_policy_error:
                append_execution_log(
                    app,
                    request_id,
                    f"RPO handling policy was not included in this approved request; executor_started=false; result={rpo_policy_error}.",
                )
                state = store.finish(request_id, False, result=rpo_policy_error)
                update_slack_message(
                    app,
                    state,
                    "요청 생성 시 RPO 처리 정책이 승인 문구에 결합되지 않았습니다. 기존 승인은 재사용하지 않고 새 요청이 필요합니다.",
                )
                return
            rpo_error = _failover_rpo_gate_error(latest_incident)
            if rpo_error in {
                "failover_rpo_target_exceeded", "failover_rpo_not_measured",
            }:
                approvers = state.get("approvers")
                admin_ids = app.extensions.get("admin_user_ids", set())
                if (
                    state.get("approval_required") != REQUIRED_APPROVALS
                    or not isinstance(approvers, list)
                    or len(approvers) != REQUIRED_APPROVALS
                    or any(not isinstance(item, str) or not item.strip() for item in approvers)
                    or len(set(approvers)) != REQUIRED_APPROVALS
                    or not isinstance(admin_ids, set)
                    or any(item not in admin_ids for item in approvers)
                ):
                    append_execution_log(
                        app,
                        request_id,
                        "RPO_RISK_ACCEPTANCE=BLOCKED; executor_started=false; two distinct administrator approvals are required.",
                    )
                    state = store.finish(request_id, False, result="rpo_risk_acceptance_missing")
                    update_slack_message(
                        app,
                        state,
                        "RPO 위험 수용을 확인할 서로 다른 관리자 2인의 승인이 없습니다. 실행기를 시작하지 않았습니다.",
                    )
                    return
                recovery_plan = latest_incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
                dump_candidate = recovery_plan.get("dump") if isinstance(recovery_plan, dict) else None
                expected_rpo = dump_candidate.get("expected_rpo") if isinstance(dump_candidate, dict) else {}
                measured_seconds = expected_rpo.get("seconds") if isinstance(expected_rpo, dict) else None
                if rpo_error == "failover_rpo_target_exceeded":
                    risk_log = (
                        f"RPO=EXCEEDED_900_SECONDS; measured_seconds={measured_seconds}; "
                        "POSSIBLE_DATA_LOSS=true; TWO_ADMIN_RISK_ACCEPTANCE=VERIFIED; "
                        "continuing only to existing-DR data verification; NR/Dump restore is not selected for this risk path."
                    )
                else:
                    risk_log = (
                        "RPO=NOT_MEASURED; POSSIBLE_DATA_LOSS=true; TWO_ADMIN_RISK_ACCEPTANCE=VERIFIED; "
                        "continuing only to existing-DR data verification; NR/Dump restore is not selected for this risk path."
                    )
                append_execution_log(
                    app,
                    request_id,
                    risk_log,
                )
            elif rpo_error:
                append_execution_log(
                    app,
                    request_id,
                    f"RPO_BLOCKED status=INVALID; executor_started=false; result={rpo_error}.",
                )
                state = store.finish(request_id, False, result=rpo_error)
                update_slack_message(
                    app,
                    state,
                    "RPO 정책 상태를 검증하지 못해 운영 Failover 실행기를 시작하지 않았습니다. 기존 승인은 재사용하지 않고 새 요청이 필요합니다.",
                )
                return
        dump_executor_request = is_existing_dr_demo_dump_failover(state)
        command = command_for_request(state, app.config["DR_SCRIPT_ROOT"], app.config)
        if command is None:
            is_dump_request = request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE
            result = "synthetic_demo_executor_not_ready" if synthetic_demo_executor_request else (
                dump_restore_command_error(state, app.config) or "dump_restore_executor_not_ready"
                if is_dump_request
                else "unknown_action"
            )
            append_execution_log(
                app,
                request_id,
                f"Workflow command unavailable; executor_started=false; result={result}.",
            )
            state = store.finish(request_id, False, result=result)
            if is_dump_request:
                blocked_incident = (state.get("incidents") or [{}])[-1]
                try:
                    app.extensions["chatops_audit"].record_event(
                        "dump_executor_launch_blocked",
                        {
                            "request_id": request_id,
                            "request_type": REQUEST_TYPE_DUMP_RESTORE,
                            "request_origin": blocked_incident.get("request_origin"),
                            "result": result,
                            "executor_started": False,
                        },
                    )
                except Exception as audit_exc:
                    append_execution_log(
                        app,
                        request_id,
                        f"Dump launch-block audit append failed: {type(audit_exc).__name__}.",
                    )
            if result in {
                "dump_request_origin_unverified",
                "dump_request_origin_mismatch",
                "dump_request_type_invalid",
            }:
                blocked_detail = (
                    "Dump 요청 출처를 검증하지 못해 어떤 Executor도 실행하지 않았습니다. "
                    f"/ Dump execution was blocked before launch ({result})."
                )
            else:
                blocked_detail = (
                    "Dump 복구 설정 또는 실행기를 확인할 수 없어 안전하게 중단했습니다. "
                    f"/ Dump restore was not started ({result})."
                )
            update_slack_message(
                app,
                state,
                blocked_detail if is_dump_request else (
                    "합성 시연 실행기 또는 요청 계약을 검증하지 못해 실행을 시작하지 않았습니다."
                    if synthetic_demo_executor_request
                    else "요청 실행기를 찾을 수 없어 안전하게 중단했습니다."
                ),
            )
            return
        if auto_failover_request:
            plan = latest_incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
            candidate = plan.get("dump") if isinstance(plan, dict) else None
            if isinstance(candidate, dict) and candidate.get("status") == "READY":
                recovery_error = _failover_recovery_authorization_error(
                    state, approved=True,
                )
                if recovery_error:
                    append_execution_log(
                        app,
                        request_id,
                        f"Conditional Dump fallback grant invalid; executor_started=false; result={recovery_error}.",
                    )
                    state = store.finish(request_id, False, result=recovery_error)
                    update_slack_message(
                        app,
                        state,
                        "NR 우선/조건부 Dump 복구 승인 계약을 재검증하지 못해 실행을 시작하지 않았습니다.",
                    )
                    return
        if action == "failover" and not synthetic_demo_executor_request:
            _record_rto(latest_incident, "failover_approved_at", approval_id=request_id)
        if synthetic_demo_executor_request:
            child_env = build_synthetic_mysql_demo_child_env(
                os.environ, app.config.get("CHATOPS_STATE_DB") or ""
            )
            workflow_config_error = None
        else:
            child_env, workflow_config_error = build_workflow_child_env(
                os.environ,
                app.config["DR_SECRET_FILE"],
                action,
            )
        if workflow_config_error:
            message = f"Workflow configuration validation failed: {workflow_config_error}."
            append_execution_log(app, request_id, message)
            state = store.finish(request_id, False, result="workflow_configuration_invalid")
            update_slack_message(app, state, message)
            return
        if action == "failback":
            overwrite_error = failback_overwrite_approval_error(
                state,
                request_id,
                app.extensions.get("admin_user_ids", set()),
            )
            if overwrite_error:
                append_execution_log(
                    app,
                    request_id,
                    f"Failback overwrite grant blocked; executor_started=false; result={overwrite_error}.",
                )
                state = store.finish(request_id, False, result=overwrite_error)
                update_slack_message(
                    app,
                    state,
                    "요청별 DB 덮어쓰기 실행 권한을 재검증하지 못해 Failback 실행을 시작하지 않았습니다.",
                )
                return
            child_env.pop("DB_FAILBACK_CONFIRM", None)
            child_env.pop("DB_FAILBACK_CONFIRM_REQUEST_ID", None)
            child_env.pop("DR_FAILBACK_REQUEST_ID", None)
            child_env["DB_FAILBACK_CONFIRM"] = "OVERWRITE_ONPREM_DB"
            child_env["DB_FAILBACK_CONFIRM_REQUEST_ID"] = request_id
            child_env["DR_FAILBACK_REQUEST_ID"] = request_id
        child_env.pop("DR_FAILOVER_REQUEST_ID", None)
        if action == "failover" and not synthetic_demo_executor_request and not _bind_failover_request_id(child_env, request_id):
            append_execution_log(
                app,
                request_id,
                "Failover request ID is invalid; executor_started=false.",
            )
            state = store.finish(request_id, False, result="failover_request_id_invalid")
            update_slack_message(
                app,
                state,
                "Failover 요청 ID를 검증하지 못해 실행을 시작하지 않았습니다.",
            )
            return
        if request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE:
            workflow_config_error = configure_dump_workflow_child_env(app, child_env)
            if workflow_config_error:
                message = f"Dump workflow configuration validation failed: {workflow_config_error}."
                append_execution_log(app, request_id, message)
                state = store.finish(request_id, False, result="dump_workflow_configuration_invalid")
                update_slack_message(app, state, message)
                return
        if action == "failover" and not synthetic_demo_executor_request:
            child_env["DR_FAILOVER_RECOVERY_MODE"] = "AUTO"
            child_env.pop("DR_FAILOVER_DUMP_BACKUP_ID", None)
            child_env.pop("DR_FAILOVER_DUMP_SHA256", None)
            child_env.pop("DR_FAILOVER_DUMP_SIDECAR_SHA256", None)
            child_env.pop("DR_FAILOVER_DUMP_AUTHORIZATION_ID", None)
            if auto_failover_request:
                plan = latest_incident.get(FAILOVER_RECOVERY_PLAN_FIELD)
                candidate = plan.get("dump") if isinstance(plan, dict) else None
                grant = latest_incident.get(DEMO_DUMP_OVERWRITE_AUTH_FIELD)
                if isinstance(candidate, dict) and candidate.get("status") == "READY":
                    child_env["DR_FAILOVER_DUMP_BACKUP_ID"] = str(candidate["backup_id"])
                    child_env["DR_FAILOVER_DUMP_SHA256"] = str(candidate["sha256"]).lower()
                    child_env["DR_FAILOVER_DUMP_SIDECAR_SHA256"] = str(candidate["sidecar_sha256"]).lower()
                    child_env["DR_FAILOVER_DUMP_AUTHORIZATION_ID"] = str(grant["authorization_id"])
                    child_env["CHATOPS_STATE_DB"] = str(app.config.get("CHATOPS_STATE_DB") or "")
                    child_env["DUMP_BACKUP_DIR"] = str(app.config.get("DUMP_BACKUP_DIR") or "")
                    child_env["DEMO_DUMP_RESTORE_STATE_DIR"] = str(
                        app.config.get("DEMO_DUMP_RESTORE_STATE_DIR")
                        or (Path(app.config.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "demo-dump-restores")
                    )
                    child_env["DUMP_RESTORE_EXEC_ENABLED"] = (
                        "true" if app.config.get("DUMP_RESTORE_EXEC_ENABLED") else "false"
                    )
                    child_env["SLACK_ADMIN_USER_IDS"] = ",".join(
                        sorted(str(value) for value in app.extensions.get("admin_user_ids", set()))
                    )
                    configured_executor = str(app.config.get("DUMP_RESTORE_EXECUTOR") or "").strip()
                    if configured_executor:
                        child_env["DUMP_RESTORE_EXECUTOR"] = configured_executor
                    else:
                        child_env.pop("DUMP_RESTORE_EXECUTOR", None)
            if request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE:
                backup_id = str(latest_incident.get("backup_id") or "")
                backup_sha = str(latest_incident.get("backup_checksum") or "").lower()
                if not re.fullmatch(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc", backup_id) \
                    or not re.fullmatch(r"[0-9a-f]{64}", backup_sha):
                    state = store.finish(request_id, False, result="dump_recovery_identity_invalid")
                    append_execution_log(app, request_id, "Dump recovery identity invalid; executor_started=false.")
                    update_slack_message(app, state, "승인된 Dump 백업 ID 또는 SHA-256이 유효하지 않아 실행하지 않았습니다.")
                    return
                child_env["DR_FAILOVER_RECOVERY_MODE"] = "APPROVED_DUMP"
                child_env["DR_FAILOVER_DUMP_BACKUP_ID"] = backup_id
                child_env["DR_FAILOVER_DUMP_SHA256"] = backup_sha
        if not synthetic_demo_executor_request:
            child_env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")
            child_env.setdefault("ANSIBLE_DEPRECATION_WARNINGS", "False")
            child_env.setdefault("PYTHONWARNINGS", "ignore")
            child_env.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/ansible-local")
            child_env.setdefault("ANSIBLE_REMOTE_TEMP", "/tmp/ansible-remote")
            child_env.setdefault("ANSIBLE_SSH_CONTROL_PATH_DIR", "/tmp/ansible-cp")
        general_failover_request = (
            action == "failover" and request_type_from_state(state) == "NORMAL_FAILOVER"
        )
        rto_correlation_bound = False
        if general_failover_request:
            rto_correlation_bound = _bind_rto_child_env(child_env, latest_incident, request_id)
        elif action == "failover":
            # Preserve the pre-existing correlation contract for emergency and
            # Dump requests; this correction is scoped to normal Failover.
            run_id = _rto_run_id(latest_incident)
            if run_id:
                child_env.setdefault("DR_RTO_RUN_ID", run_id)
                child_env.setdefault("DR_RTO_EVENT_ID", latest_incident.get("incident_id", ""))
                child_env.setdefault("DR_RTO_APPROVAL_ID", request_id)
        if general_failover_request and not rto_correlation_bound:
            append_execution_log(
                app,
                request_id,
                "[RTO] Request correlation unavailable; timeline completion remains NOT_MEASURED.",
            )

        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            env=child_env,
            start_new_session=True,
        )
        process_started = True
        if general_failover_request or (
            action == "failover" and request_type_from_state(state) == REQUEST_TYPE_DUMP_RESTORE
        ):
            # Record the actual child launch under the approved request. The
            # full workflow may attempt the same stage later; timeline writes
            # are idempotent and preserve this first, request-bound timestamp.
            _record_rto(latest_incident, "failover_started_at", approval_id=request_id)
        if general_failover_request:
            append_execution_log(app, request_id, f"[CORRELATION] request_id={request_id}")
        append_execution_log(
            app,
            request_id,
            (
                "Synthetic MySQL demo started; raw runner output is suppressed."
                if synthetic_demo_executor_request
                else
                "Dump Executor started; Slack log receives only allowlisted structured phase events."
                if dump_executor_request
                else "Workflow process started; streaming sanitized output."
            ),
        )
        output_queue = queue.Queue()

        def stream_output():
            try:
                for raw_line in process.stdout or ():
                    output_queue.put(("line", raw_line))
            finally:
                output_queue.put(("eof", None))

        reader = threading.Thread(target=stream_output, daemon=True, name=f"chatops-output-{request_id}")
        reader.start()
        timeout_seconds = max(1.0, float(app.config["CHATOPS_EXECUTION_TIMEOUT_SECONDS"]))
        heartbeat_seconds = max(1.0, float(app.config["CHATOPS_EXECUTION_HEARTBEAT_SECONDS"]))
        deadline = time.monotonic() + timeout_seconds
        next_heartbeat = time.monotonic() + heartbeat_seconds
        output_eof = False
        timed_out = False

        while process.poll() is None or not output_eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                timeout_message = f"[{label}] Execution total timeout reached for request {request_id}."
                print(timeout_message, flush=True)
                append_execution_log(app, request_id, timeout_message)
                terminate_pipeline(process)
                break
            wait_seconds = min(remaining, max(0.1, next_heartbeat - time.monotonic()))
            try:
                kind, value = output_queue.get(timeout=wait_seconds)
            except queue.Empty:
                if time.monotonic() >= next_heartbeat:
                    store.heartbeat(request_id)
                    next_heartbeat = time.monotonic() + heartbeat_seconds
                if dump_executor_request:
                    dump_log_offset, dump_log_read_error = sync_dump_executor_log_to_chatops(
                        app, store.get(request_id) or {}, dump_log_offset
                    )
                continue
            if kind == "eof":
                output_eof = True
                if dump_executor_request:
                    dump_log_offset, dump_log_read_error = sync_dump_executor_log_to_chatops(
                        app, store.get(request_id) or {}, dump_log_offset
                    )
                continue
            line = value.rstrip("\n")
            if action == "failover":
                recovery_match = re.fullmatch(
                    r"\[DB PROMOTION\] Selected verified recovery mode=(NR|DUMP|EXISTING_DR_DATA)\.",
                    line.strip(),
                )
                if recovery_match:
                    selected_recovery_mode = recovery_match.group(1)
            if dump_executor_request:
                # Executor stdout/stderr is not an approved presentation channel.
                # Stage details come only from its private, mode-checked marker log.
                dump_log_offset, dump_log_read_error = sync_dump_executor_log_to_chatops(
                    app, store.get(request_id) or {}, dump_log_offset
                )
            elif synthetic_demo_executor_request:
                stripped = line.strip()
                if re.fullmatch(r"SYNTHETIC_MYSQL_DEMO=PASS", stripped) or re.fullmatch(
                    r"SYNTHETIC_MYSQL_DEMO=BLOCKED phase=(GATE|RUNNER) reason=[a-z0-9_]{1,96}",
                    stripped,
                ):
                    synthetic_demo_result_marker = stripped
            elif not should_suppress_log_line(line):
                safe_line = sanitize_execution_log_line(line)
                print(safe_line, flush=True)
                append_execution_log(app, request_id, safe_line)
            if time.monotonic() >= next_heartbeat:
                store.heartbeat(request_id)
                next_heartbeat = time.monotonic() + heartbeat_seconds

        reader.join(timeout=1)
        if process.stdout is not None:
            process.stdout.close()

        if dump_executor_request:
            dump_log_offset, dump_log_read_error = sync_dump_executor_log_to_chatops(
                app, store.get(request_id) or {}, dump_log_offset
            )

        if timed_out:
            return_code = process.returncode if process.returncode is not None else -signal.SIGTERM
            result = "timeout"
            succeeded = False
        else:
            return_code = process.wait()
            result = "success" if return_code == 0 else "failed"
            succeeded = return_code == 0
        current_state = store.get(request_id) or {}
        if synthetic_demo_executor_request:
            gate_block = bool(
                synthetic_demo_result_marker
                and "SYNTHETIC_MYSQL_DEMO=BLOCKED phase=GATE "
                in synthetic_demo_result_marker
            )
            if (
                process_started
                and not timed_out
                and return_code == 0
                and synthetic_demo_result_marker == "SYNTHETIC_MYSQL_DEMO=PASS"
            ):
                terminal_status = "SUCCEEDED"
                demo_result = "synthetic_aws_mysql_roundtrip_pass"
                detail = (
                    "AWS 합성 MySQL 시연 PASS: A 복원 → AWS에서 B 추가·조회 → "
                    "원본 역할 MySQL에 A+B 복귀를 확인했습니다. "
                    "운영 Failover, DR_ACTIVE, DNS는 변경하지 않았습니다."
                )
            elif not process_started or gate_block:
                terminal_status = "FAILED"
                demo_result = "synthetic_mysql_demo_launch_blocked"
                reason = (
                    synthetic_demo_result_marker.rsplit("reason=", 1)[-1]
                    if gate_block else "executor_not_started"
                )
                detail = f"합성 시연 실행 전 차단: {reason}. 운영 Failover는 실행하지 않았습니다."
            else:
                terminal_status = "PARTIAL_FAILURE"
                demo_result = "synthetic_mysql_demo_outcome_requires_review"
                marker_reason = (
                    synthetic_demo_result_marker.rsplit("reason=", 1)[-1]
                    if synthetic_demo_result_marker else "result_unverified"
                )
                detail = (
                    f"합성 MySQL 시연 결과 불확실: {marker_reason}. "
                    "자동 재실행은 하지 않았습니다. 고정 Canary 데이터 상태를 읽기 전용 확인하세요."
                )
            state = store.finish(
                request_id,
                terminal_status == "SUCCEEDED",
                result=demo_result,
                terminal_status=terminal_status,
            )
            safe_marker = synthetic_demo_result_marker or "SYNTHETIC_MYSQL_DEMO=NO_VERIFIED_RESULT"
            append_execution_log(
                app,
                request_id,
                f"{safe_marker}; outcome={terminal_status}; executor_started={str(process_started).lower()}.",
            )
            try:
                app.extensions["chatops_audit"].record_event(
                    "synthetic_mysql_demo_execution_result",
                    {
                        "request_id": request_id,
                        "request_type": SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE,
                        "status": terminal_status,
                        "result": demo_result,
                        "executor_started": process_started,
                    },
                )
            except Exception as audit_exc:
                append_execution_log(
                    app, request_id, f"Synthetic demo audit append failed: {type(audit_exc).__name__}."
                )
            if not update_slack_message(app, state, detail) and response_url:
                try:
                    requests.post(
                        response_url,
                        json={"replace_original": False, "text": detail},
                        timeout=10,
                    )
                except Exception:
                    pass
            return
        is_dump_result = request_type_from_state(current_state) == REQUEST_TYPE_DUMP_RESTORE
        if is_existing_dr_demo_dump_failover(current_state):
            dump_outcome = classify_dump_executor_result(app, current_state, return_code)
        elif is_dump_result:
            dump_outcome = {
                "status": "PARTIAL_FAILURE",
                "result": "dump_executor_outcome_requires_operator_review",
                "phase": "UNKNOWN",
                "failure_code": "DUMP_REQUEST_SOURCE_CHANGED_DURING_EXECUTION",
                "automatic_rollback_allowed": False,
                "operator_intervention_required": True,
                "executor_status": "UNKNOWN",
            }
        else:
            dump_outcome = None
        if dump_outcome is not None:
            result = dump_outcome["result"]
            succeeded = dump_outcome["status"] == "SUCCEEDED"
            if dump_log_read_error and dump_log_read_error != "missing":
                append_execution_log(
                    app,
                    request_id,
                    f"Dump Executor structured log unavailable; code={dump_log_read_error}.",
                )
            elif dump_log_read_error == "missing":
                append_execution_log(
                    app,
                    request_id,
                    "Dump Executor structured log unavailable; code=missing.",
                )
            state = store.finish(
                request_id,
                succeeded,
                result=result,
                terminal_status=dump_outcome["status"],
            )
            append_execution_log(
                app,
                request_id,
                f"[{datetime.now(timezone.utc).isoformat()}] "
                "Dump Executor ChatOps-verified final outcome "
                f"status={dump_outcome['status']} phase={dump_outcome['phase']} "
                f"failure_code={dump_outcome['failure_code'] or '-'} "
                f"operator_intervention_required={dump_outcome['operator_intervention_required']}.",
            )
            try:
                audit_dump_executor_outcome(app, state, dump_outcome)
            except Exception as audit_exc:
                append_execution_log(
                    app, request_id, f"Dump Executor audit append failed: {type(audit_exc).__name__}."
                )
            detail = dump_executor_slack_detail(state, dump_outcome)
            if dump_outcome["status"] != "PARTIAL_FAILURE":
                detail += (
                    "\nDetailed workflow output remains in the MSP execution log. / "
                    "상세 실행 로그는 MSP 실행 로그에서 확인하세요."
                )
        else:
            append_execution_log(
                app,
                request_id,
                f"Workflow process finished with exit_code={return_code} result={result}.",
            )
            if action == "failback":
                final_dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
                failback_outcome = classify_failback_pipeline_result(
                    return_code, timed_out, final_dr_state
                )
                succeeded = failback_outcome["status"] == "SUCCEEDED"
                state = store.finish(
                    request_id,
                    succeeded,
                    result=failback_outcome["result"],
                    terminal_status=failback_outcome["status"],
                )
                detail = failback_outcome["detail"]
                append_execution_log(
                    app,
                    request_id,
                    f"Failback final outcome status={failback_outcome['status']} "
                    f"exit_code={return_code} DR_STATE={final_dr_state or 'UNKNOWN'}.",
                )
            else:
                state = store.finish(request_id, succeeded, result=result)
                detail = (
                    f"Exit code: {return_code}\n"
                    + ("Execution total timeout was reached.\n" if timed_out else "")
                    + "Detailed workflow output remains in the MSP execution log. / "
                    "상세 실행 로그는 MSP 실행 로그에서 확인하세요."
                )
                detail += failover_recovery_summary(state, selected_recovery_mode)
        if not update_slack_message(app, state, detail) and response_url:
            try:
                fallback_text = (
                    detail
                    if state.get("status") == "DB_RESTORED_NOT_FAILOVER_COMPLETE"
                    else f"{label} finished with exit code {return_code}."
                )
                requests.post(
                    response_url,
                    json={"replace_original": False, "text": fallback_text},
                    timeout=10,
                )
            except Exception:
                pass
    except Exception as exc:
        append_execution_log(app, request_id, f"Pipeline error: {type(exc).__name__}.")
        current_state = store.get(request_id) or {}
        if dump_executor_request:
            dump_log_offset, dump_log_read_error = sync_dump_executor_log_to_chatops(
                app, current_state, dump_log_offset
            )
            if dump_log_read_error:
                append_execution_log(
                    app,
                    request_id,
                    f"Dump Executor structured log unavailable; code={dump_log_read_error}.",
                )
        if process_started and synthetic_demo_executor_request:
            state = store.finish(
                request_id,
                False,
                result="synthetic_mysql_demo_outcome_requires_review",
                terminal_status="PARTIAL_FAILURE",
            )
            append_execution_log(
                app,
                request_id,
                "Synthetic demo process outcome is unknown; status=PARTIAL_FAILURE; automatic_retry=false.",
            )
            detail = (
                "합성 MySQL 시연 중 결과를 확인하지 못했습니다. "
                "자동 재실행하지 말고 고정 Canary 데이터 상태를 읽기 전용 확인하세요."
            )
        elif process_started and request_type_from_state(current_state) == REQUEST_TYPE_DUMP_RESTORE:
            unknown_outcome = {
                "status": "PARTIAL_FAILURE",
                "result": "dump_executor_outcome_requires_operator_review",
                "phase": "UNKNOWN",
                "failure_code": "CHATOPS_DUMP_EXECUTOR_RESULT_UNKNOWN",
                "automatic_rollback_allowed": False,
                "operator_intervention_required": True,
                "executor_status": "UNKNOWN",
            }
            state = store.finish(
                request_id,
                False,
                result=unknown_outcome["result"],
                terminal_status="PARTIAL_FAILURE",
            )
            try:
                audit_dump_executor_outcome(app, state, unknown_outcome)
            except Exception as audit_exc:
                append_execution_log(
                    app, request_id, f"Dump Executor audit append failed: {type(audit_exc).__name__}."
                )
            detail = dump_executor_slack_detail(state, unknown_outcome)
        elif process_started and action == "failback":
            state = store.finish(
                request_id,
                False,
                result="failback_chatops_result_unknown",
                terminal_status="PARTIAL_FAILURE",
            )
            append_execution_log(
                app,
                request_id,
                "Failback result uncertain after runner start; status=PARTIAL_FAILURE, "
                "operator_intervention_required=true.",
            )
            detail = (
                "PARTIAL_FAILURE: Failback 결과가 불확실합니다. On-Prem DB 상태를 확인하고 "
                "운영자 개입이 필요합니다. 자동 재실행/롤백하지 마세요."
            )
        else:
            state = store.finish(request_id, False, result="execution_error")
            detail = f"Execution error: {type(exc).__name__}"
            detail += failover_recovery_summary(state, selected_recovery_mode)
        update_slack_message(app, state, detail)
        print(f"[{label}] Pipeline error for request {request_id}: {type(exc).__name__}", flush=True)
    finally:
        release_pipeline_file_lock(file_lock)
        if thread_lock_held:
            pipeline_lock.release()


def launch_pipeline(app, request_id, action, final_approver, response_url):
    if complete_test_mode_failover_approval(app, request_id, action):
        return
    test_launcher = app.config.get("PIPELINE_LAUNCHER")
    if test_launcher is not None:
        test_launcher(request_id, action, final_approver)
        return
    threading.Thread(
        target=run_pipeline,
        args=(app, request_id, action, final_approver, response_url),
        daemon=True,
    ).start()


def parse_interaction(payload, store):
    action_item = (payload.get("actions") or [{}])[0]
    raw_value = action_item.get("value", "")
    metadata = {}
    try:
        value = json.loads(raw_value)
        if not isinstance(value, dict):
            raise ValueError("Slack action value is not an object")
        metadata = value
        request_id = value.get("request_id")
        action = value.get("action")
        operation = value.get("operation")
    except (TypeError, json.JSONDecodeError):
        legacy_actions = {"run_restore": "failover", "run_failback": "failback"}
        action = legacy_actions.get(raw_value)
        operation = "approve"
        active = store.find_active(action) if action else None
        request_id = active["request_id"] if active else None
    except ValueError:
        request_id = action = operation = None
    return request_id, action, operation, metadata


def slack_signature_key(app, action, operation=None, metadata=None, channel_id=None):
    """Select the Slack App signing secret without weakening verification."""
    metadata = metadata or {}
    if metadata.get("request_origin") == "EMERGENCY":
        return "emergency"
    if metadata.get("request_type") in {
        REQUEST_TYPE_EMERGENCY_FAILOVER,
        REQUEST_TYPE_EMERGENCY_FAILBACK,
    }:
        return "emergency"
    if operation in {"emergency_status", "emergency_open", "emergency_dump_open"}:
        return "emergency"
    if channel_id and channel_id == app.config.get("SLACK_EMERGENCY_CHANNEL_ID"):
        return "emergency"
    return action


def ephemeral(text):
    return jsonify({"response_type": "ephemeral", "replace_original": False, "text": text})


def _view_state_value(view, block_id, action_id):
    values = ((view.get("state") or {}).get("values") or {}).get(block_id) or {}
    item = values.get(action_id) or {}
    selected = item.get("selected_option") or {}
    if selected.get("value") is not None:
        return selected.get("value")
    selected_values = item.get("selected_options") or []
    if selected_values:
        return selected_values[0].get("value")
    return item.get("value", "")


def _dump_verification_worker(app, client, view_id, task_kind, task_data, task_key):
    """Hash/verify a selected dump and update its modal outside Slack's 3s ACK."""
    try:
        # Let Slack process the immediate response_action=update before this
        # worker attempts views.update on the same modal.
        time.sleep(0.15)
        validation_report = {}
        backup = resolve_dump_backup(
            app.config["DUMP_BACKUP_DIR"],
            task_data["backup_id"],
            allow_legacy_manual=True,
            encryption_key=app.config.get("DB_BACKUP_ENCRYPTION_KEY"),
            validation_report=validation_report,
        )
        if backup is None:
            if validation_report.get("manifest_status") == "ABSENT":
                message = (
                    "Legacy 수동 Dump 검증 실패: "
                    f"Manifest={validation_report.get('manifest_status')}, "
                    f"복호화={validation_report.get('decryption_status')}, "
                    f"gzip={validation_report.get('gzip_status')}, "
                    f"sidecar={validation_report.get('sidecar_status')}, "
                    "RPO=NOT_MEASURED. 승인 요청은 생성되지 않았습니다."
                )
            else:
                message = "백업 파일 또는 master_status를 읽거나 검증하지 못했습니다. 창을 닫고 다시 선택해 주세요."
            client.update_view(
                view_id,
                dump_verification_view(
                    task_data.get("metadata"),
                    message,
                ),
            )
            return

        metadata = dict(task_data.get("metadata") or {})
        if task_kind == "select":
            client.update_view(
                view_id,
                dump_confirm_view(task_data["action"], backup, metadata),
            )
            return

        expected_checksum = str(metadata.get("checksum") or "").strip().lower()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_checksum)
            or not hmac.compare_digest(backup["checksum"].lower(), expected_checksum)
        ):
            client.update_view(
                view_id,
                dump_request_result_view(
                    "선택 후 백업 checksum이 변경되었습니다. 요청은 생성되지 않았습니다. 다시 선택해 주세요."
                ),
            )
            return
        expected_mode = str(metadata.get("dump_restore_mode") or "")
        expected_sidecar_checksum = str(metadata.get("sidecar_checksum") or "").strip().lower()
        if (
            expected_mode != backup["restore_mode"]
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sidecar_checksum)
            or not hmac.compare_digest(
                backup["sidecar_checksum"].lower(), expected_sidecar_checksum
            )
        ):
            client.update_view(
                view_id,
                dump_request_result_view(
                    "선택 후 Legacy 모드 또는 sidecar가 변경되어 요청을 생성하지 않았습니다. 다시 선택해 주세요."
                ),
            )
            return

        request_origin = str(metadata.get("request_origin") or "GENERAL").strip().upper()
        if request_origin not in {"GENERAL", "EMERGENCY"}:
            client.update_view(
                view_id,
                dump_request_result_view("요청 출처를 확인할 수 없어 Dump 요청을 만들지 않았습니다."),
            )
            return

        emergency_dump = request_origin == "EMERGENCY"
        now = utc_timestamp()
        ttl_seconds = app.config.get("EMERGENCY_TTL_SECONDS", EMERGENCY_TTL_SECONDS) if emergency_dump else None
        precheck = evaluate_emergency_precheck(
            app,
            "failover",
            REQUEST_TYPE_DUMP_RESTORE,
            backup=backup,
        )
        incident = {
            "incident_id": f"DUMP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}",
            "summary": "Dump restore failover request",
            "observed_at": format_timestamp(now),
            "source": "emergency_dump_restore_console" if emergency_dump else "dump_restore_console",
            "request_type": REQUEST_TYPE_DUMP_RESTORE,
            "slack_client_key": "emergency" if emergency_dump else (metadata.get("slack_client_key") or "failover"),
            "request_origin": request_origin,
            "requested_by": metadata.get("requested_by") or task_data.get("user_id"),
            "requested_at": now,
            "expires_at": now + ttl_seconds if ttl_seconds else None,
            "reason_code": metadata.get("reason_code") if emergency_dump else None,
            "reason_text": metadata.get("reason_text") if emergency_dump else None,
            "backup_id": backup["backup_id"],
            "backup_filename": backup["filename"],
            "backup_timestamp": backup.get("backup_timestamp") or backup.get("timestamp"),
            "backup_timestamp_source": backup.get("backup_timestamp_source") or "UNKNOWN",
            "backup_checksum": backup["checksum"],
            "backup_sidecar_checksum": backup["sidecar_checksum"],
            "dump_restore_mode": backup["restore_mode"],
            "expected_rpo": backup["expected_rpo"],
            "precheck_status": precheck.get("status"),
            "precheck_reason": precheck.get("reason"),
            "precheck_checks": precheck.get("checks", {}),
        }
        state, _ = create_approval_request(app, "failover", incident, ttl_seconds=ttl_seconds)
        client.update_view(
            view_id,
            dump_request_result_view(
                "Dump Failover 2인 승인 요청이 생성되었습니다. 승인 채널의 요청 메시지를 확인해 주세요.",
                request_id=state.get("request_id"),
                clear_on_close=True,
            ),
        )
    except FailoverRequestBlocked:
        try:
            client.update_view(
                view_id,
                dump_request_result_view("DR 서버가 이미 활성 상태라 Dump Failover 요청을 만들지 않았습니다."),
            )
        except Exception:
            pass
    except Exception as exc:
        print(
            f"[DUMP] background {task_kind} failed error={type(exc).__name__}",
            flush=True,
        )
        try:
            client.update_view(
                view_id,
                dump_request_result_view(
                    "Dump 검증 또는 요청 전달에 실패했습니다. 승인 채널과 ChatOps 서비스 로그를 확인해 주세요."
                ),
            )
        except Exception as update_exc:
            print(
                f"[DUMP] result modal update failed error={type(update_exc).__name__}",
                flush=True,
            )
    finally:
        with app.extensions["dump_background_lock"]:
            app.extensions["dump_background_inflight"].discard(task_key)


def _start_dump_verification(app, client, view_id, task_kind, task_data):
    """Start one bounded-by-view background task after validating its identity."""
    task_key = f"{task_kind}:{view_id}"
    with app.extensions["dump_background_lock"]:
        if task_key in app.extensions["dump_background_inflight"]:
            return "already_running"
        app.extensions["dump_background_inflight"].add(task_key)
    worker = threading.Thread(
        target=_dump_verification_worker,
        args=(app, client, view_id, task_kind, task_data, task_key),
        daemon=True,
        name="chatops-dump-verification",
    )
    try:
        worker.start()
    except Exception:
        with app.extensions["dump_background_lock"]:
            app.extensions["dump_background_inflight"].discard(task_key)
        raise
    return "started"


def handle_view_submission(app, payload, action, admin_ids):
    """Handle emergency/dump modals without executing a workflow."""
    user_id = (payload.get("user") or {}).get("id", "")
    if not admin_ids or user_id not in admin_ids:
        return jsonify({"response_action": "errors", "errors": {"emergency_reason_code": "등록된 관리자만 사용할 수 있습니다."}})
    view = payload.get("view") or {}
    callback_id = view.get("callback_id")
    try:
        metadata = json.loads(view.get("private_metadata") or "{}")
    except json.JSONDecodeError:
        metadata = {}

    if callback_id == "hospital_dr_emergency_reason":
        requested_action = metadata.get("action")
        request_type = metadata.get("request_type")
        if requested_action not in ("failover", "failback"):
            return jsonify({"response_action": "clear"})
        expected_type = (
            REQUEST_TYPE_EMERGENCY_FAILOVER
            if requested_action == "failover"
            else REQUEST_TYPE_EMERGENCY_FAILBACK
        )
        valid_request_type = request_type == expected_type or (
            requested_action == "failover" and request_type == REQUEST_TYPE_DUMP_RESTORE
        )
        if not valid_request_type:
            return jsonify({"response_action": "errors", "errors": {"emergency_reason_code": "요청 유형을 확인할 수 없습니다."}})
        reason_code = _view_state_value(view, "emergency_reason_code", "reason_code")
        reason_text = _view_state_value(view, "emergency_reason_detail", "reason_detail")
        valid, normalized = validate_reason(
            requested_action,
            reason_code,
            reason_text,
            request_type=request_type,
        )
        if not valid:
            block = "emergency_reason_detail" if reason_code == "OTHER" else "emergency_reason_code"
            return jsonify({"response_action": "errors", "errors": {block: normalized}})
        reason_label = dict(reason_options(requested_action, request_type)).get(reason_code, reason_code)
        if request_type == REQUEST_TYPE_DUMP_RESTORE:
            metadata.update(
                {
                    "action": "failover",
                    "request_type": REQUEST_TYPE_DUMP_RESTORE,
                    "request_origin": "EMERGENCY",
                    "slack_client_key": "emergency",
                    "requested_by": user_id,
                    "reason_code": reason_code,
                    "reason_text": normalized if reason_code == "OTHER" else reason_label,
                }
            )
            return jsonify(
                {
                    "response_action": "push",
                    "view": dump_select_view(
                        "failover",
                        app.config["DUMP_BACKUP_DIR"],
                        "emergency",
                        metadata=metadata,
                    ),
                }
            )
        now = utc_timestamp()
        precheck = evaluate_emergency_precheck(app, requested_action, request_type)
        incident = {
            "incident_id": f"EMG-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}",
            "summary": f"Emergency {requested_action} request",
            "observed_at": format_timestamp(now),
            "source": "emergency_console",
            "request_type": request_type,
            "slack_client_key": "emergency",
            "request_origin": "EMERGENCY",
            "reason_code": reason_code,
            "reason_text": normalized if reason_code == "OTHER" else reason_label,
            "requested_by": user_id,
            "requested_at": now,
            "expires_at": now + app.config.get("EMERGENCY_TTL_SECONDS", EMERGENCY_TTL_SECONDS),
            "precheck_status": precheck.get("status"),
            "precheck_reason": precheck.get("reason"),
            "precheck_checks": precheck.get("checks", {}),
        }
        if requested_action == "failback":
            risk = precheck.get("wazuh_risk") or {}
            incident.update(
                {
                    "wazuh_risk_level": risk.get("risk_level", "UNKNOWN"),
                    "wazuh_risk_observed_at": risk.get("risk_observed_at", "-"),
                    "wazuh_risk_checked_at": risk.get("risk_checked_at", "-"),
                    "wazuh_risk_reason": risk.get(
                        "risk_reason", "Wazuh risk was not evaluated."
                    ),
                }
            )
        try:
            create_approval_request(
                app,
                requested_action,
                incident,
                ttl_seconds=app.config.get("EMERGENCY_TTL_SECONDS", EMERGENCY_TTL_SECONDS),
            )
        except FailoverRequestBlocked as exc:
            return jsonify({
                "response_action": "errors",
                "errors": {"emergency_reason_code": "DR 서버가 이미 활성 상태라 Failover 요청을 만들지 않았습니다."},
                "code": exc.code,
            })
        except Exception as exc:
            print(f"[EMERGENCY] request creation failed: {type(exc).__name__}", flush=True)
            return jsonify({"response_action": "errors", "errors": {"emergency_reason_code": "요청 생성에 실패했습니다."}})
        return jsonify({"response_action": "clear"})

    if callback_id == "hospital_dr_dump_select":
        requested_action = metadata.get("action", action)
        backup_id = _view_state_value(view, "dump_backup", "backup_id")
        if requested_action != "failover" or not re.fullmatch(
            r"[A-Za-z0-9_.-]+\.sql\.gz\.enc", str(backup_id or "")
        ):
            return jsonify({"response_action": "errors", "errors": {"dump_backup": "유효한 complete dump를 선택해 주세요."}})
        view_id = str(view.get("id") or "")
        client_key = metadata.get("slack_client_key") or action
        client = app.extensions["slack_clients"].get(client_key)
        if not view_id or client is None or not client.available:
            return jsonify({"response_action": "errors", "errors": {"dump_backup": "검증 창 또는 Slack 연결을 확인할 수 없습니다. 다시 시도해 주세요."}})
        metadata["action"] = requested_action
        metadata["slack_client_key"] = client_key
        try:
            _start_dump_verification(
                app,
                client,
                view_id,
                "select",
                {"action": requested_action, "backup_id": backup_id, "metadata": metadata},
            )
        except Exception as exc:
            print(f"[DUMP] verification start failed error={type(exc).__name__}", flush=True)
            return jsonify({"response_action": "errors", "errors": {"dump_backup": "백업 검증 작업을 시작하지 못했습니다."}})
        return jsonify({"response_action": "update", "view": dump_verification_view(metadata)})

    if callback_id == "hospital_dr_dump_confirm":
        selected = _view_state_value(view, "dump_confirm", "confirm_choice")
        if selected != "YES":
            return jsonify({"response_action": "clear"})
        backup_id = metadata.get("backup_id")
        request_origin = str(metadata.get("request_origin") or "GENERAL").strip().upper()
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+\.sql\.gz\.enc", str(backup_id or ""))
            or request_origin not in {"GENERAL", "EMERGENCY"}
        ):
            return jsonify({"response_action": "errors", "errors": {"dump_confirm": "Dump 요청 정보를 확인할 수 없습니다."}})
        view_id = str(view.get("id") or "")
        client_key = "emergency" if request_origin == "EMERGENCY" else (metadata.get("slack_client_key") or "failover")
        client = app.extensions["slack_clients"].get(client_key)
        if not view_id or client is None or not client.available:
            return jsonify({"response_action": "errors", "errors": {"dump_confirm": "요청 처리 창 또는 Slack 연결을 확인할 수 없습니다. 다시 시도해 주세요."}})
        try:
            metadata["slack_client_key"] = client_key
            _start_dump_verification(
                app,
                client,
                view_id,
                "confirm",
                {"backup_id": backup_id, "metadata": metadata, "user_id": user_id},
            )
        except Exception as exc:
            print(f"[DUMP] request start failed error={type(exc).__name__}", flush=True)
            return jsonify({"response_action": "errors", "errors": {"dump_confirm": "Dump 요청 작업을 시작하지 못했습니다."}})
        return jsonify(
            {
                "response_action": "update",
                "view": dump_verification_view(
                    metadata,
                    "백업 checksum을 재검증하고 승인 요청을 준비하고 있습니다.",
                ),
            }
        )

    return jsonify({"response_action": "clear"})


def create_app(default_state_db, default_secret_file, default_script_root, test_config=None):
    app = Flask(__name__)
    app.config.update(
        CHATOPS_STATE_DB=os.environ.get("CHATOPS_STATE_DB", default_state_db),
        DR_SECRET_FILE=os.environ.get("DR_SECRET_FILE", default_secret_file),
        DR_SCRIPT_ROOT=os.environ.get("DR_SCRIPT_ROOT", default_script_root),
        DR_REPO_ROOT=os.environ.get("DR_REPO_ROOT", ""),
        DR_STATE_DIR=os.environ.get("DR_STATE_DIR", "/var/lib/hospital-dr"),
        DR_LOG_DIR=os.environ.get(
            "DR_LOG_DIR",
            os.path.dirname(os.path.abspath(os.environ.get("CHATOPS_STATE_DB", default_state_db))),
        ),
        CHATOPS_EXECUTION_LOG_DIR=os.environ.get(
            "CHATOPS_EXECUTION_LOG_DIR",
            os.path.join(
                os.path.dirname(os.path.abspath(os.environ.get("CHATOPS_STATE_DB", default_state_db))),
                "execution-logs",
            ),
        ),
        DR_STATE_FILE=os.environ.get(
            "DR_STATE_FILE",
            os.path.join(os.environ.get("DR_STATE_DIR", "/var/lib/hospital-dr"), "dr_state"),
        ),
        CHATOPS_EXECUTION_TIMEOUT_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_TIMEOUT_SECONDS", str(DEFAULT_EXECUTION_TIMEOUT_SECONDS))
        ),
        CHATOPS_EXECUTION_HEARTBEAT_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_HEARTBEAT_SECONDS", str(DEFAULT_EXECUTION_HEARTBEAT_SECONDS))
        ),
        CHATOPS_EXECUTION_LEASE_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_LEASE_SECONDS", str(DEFAULT_EXECUTION_LEASE_SECONDS))
        ),
        CHATOPS_EXECUTION_LOCK_FILE=os.environ.get("CHATOPS_EXECUTION_LOCK_FILE", ""),
        EXPIRY_INTERVAL_SECONDS=int(os.environ.get("CHATOPS_EXPIRY_INTERVAL_SECONDS", "15")),
        CHATOPS_SLACK_CLEANUP_TTL_SECONDS=int(
            os.environ.get("CHATOPS_SLACK_CLEANUP_TTL_SECONDS", "86400")
        ),
        CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS=int(
            os.environ.get("CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS", "300")
        ),
        EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS=int(
            os.environ.get("EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS", "60")
        ),
        ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS=int(
            os.environ.get(
                "ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS",
                str(DEFAULT_TEST_MODE_MAX_EVENT_AGE_SECONDS),
            )
        ),
        ZABBIX_DR_MAX_EVENT_AGE_SECONDS=int(
            os.environ.get(
                "ZABBIX_DR_MAX_EVENT_AGE_SECONDS",
                str(DEFAULT_DR_MAX_EVENT_AGE_SECONDS),
            )
        ),
        ZABBIX_PRODUCTION_ACTION_HMAC_KEY=os.environ.get(
            "ZABBIX_PRODUCTION_ACTION_HMAC_KEY", ""
        ),
        WAZUH_CORRELATION_STATE_FILE=os.environ.get(
            "WAZUH_CORRELATION_STATE_FILE",
            os.path.join(
                os.path.dirname(os.path.abspath(os.environ.get("CHATOPS_STATE_DB", default_state_db))),
                "wazuh_correlation.json",
            ),
        ),
        WAZUH_CORRELATION_WINDOW_SECONDS=int(os.environ.get("WAZUH_CORRELATION_WINDOW_SECONDS", "900")),
        WAZUH_SECURITY_SLACK_ENABLED=os.environ.get("WAZUH_SECURITY_SLACK_ENABLED", "false").lower()
        in {"1", "true", "yes", "on"},
        WAZUH_SECURITY_SLACK_DRY_RUN=os.environ.get("WAZUH_SECURITY_SLACK_DRY_RUN", "false").lower()
        in {"1", "true", "yes", "on"},
        NETWORK_DR_HEALTH_ENABLED=as_bool(os.environ.get("NETWORK_DR_HEALTH_ENABLED", "true")),
        NETWORK_DR_HEALTH_FRESHNESS_SECONDS=int(
            os.environ.get("NETWORK_DR_HEALTH_FRESHNESS_SECONDS", "300")
        ),
        FAILBACK_STABILITY_SECONDS=int(os.environ.get("FAILBACK_STABILITY_SECONDS", "300")),
        SLACK_EMERGENCY_CHANNEL_ID=os.environ.get("SLACK_EMERGENCY_CHANNEL_ID", ""),
        EMERGENCY_TTL_SECONDS=int(os.environ.get("EMERGENCY_TTL_SECONDS", str(EMERGENCY_TTL_SECONDS))),
        DR_APPROVAL_REQUIRED=os.environ.get("DR_APPROVAL_REQUIRED", "2"),
        DR_SINGLE_APPROVAL_TEST_EXPIRES_AT=os.environ.get(
            "DR_SINGLE_APPROVAL_TEST_EXPIRES_AT", ""
        ),
        APPROVAL_REQUIRED=REQUIRED_APPROVALS,
        APPROVAL_TEST_EXPIRES_AT_EPOCH=None,
        APPROVAL_POLICY_CONFIG_REASON="two_person_default",
        DUMP_BACKUP_DIR=os.environ.get(
            "DUMP_BACKUP_DIR", os.environ.get("DB_BACKUP_DIR", "/home/cloud/db_backups")
        ),
        DUMP_RESTORE_EXEC_ENABLED=as_bool(os.environ.get("DUMP_RESTORE_EXEC_ENABLED", "false")),
        DUMP_RESTORE_EXECUTOR=os.environ.get("DUMP_RESTORE_EXECUTOR", ""),
        DEMO_DUMP_RESTORE_STATE_DIR=os.environ.get("DEMO_DUMP_RESTORE_STATE_DIR", ""),
        DUMP_FAILOVER_EXECUTOR_STATE_DIR=os.environ.get(
            "DUMP_FAILOVER_EXECUTOR_STATE_DIR",
            DUMP_FAILOVER_EXECUTOR_RECEIPT_ROOT,
        ),
        DB_NR_ENABLED=as_bool(os.environ.get("DB_NR_ENABLED", "false")),
        DB_BACKUP_ENCRYPTION_KEY=os.environ.get("DB_BACKUP_ENCRYPTION_KEY", ""),
        CHATOPS_AUDIT_FILE=os.environ.get(
            "CHATOPS_AUDIT_FILE",
            os.path.join(
                os.path.dirname(
                    os.path.abspath(os.environ.get("CHATOPS_STATE_DB", default_state_db))
                ),
                "audit",
                "chatops_audit.jsonl",
            ),
        ),
        VERIFY_SLACK_SIGNATURE=True,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("CHATOPS_EXECUTION_LOCK_FILE"):
        app.config["CHATOPS_EXECUTION_LOCK_FILE"] = os.path.join(
            os.path.dirname(os.path.abspath(app.config["CHATOPS_STATE_DB"])),
            "pipeline.lock",
        )

    file_values = load_env_file(app.config["DR_SECRET_FILE"])

    def configured_value(name):
        return file_values.get(name, "")

    if not (test_config and "DB_BACKUP_ENCRYPTION_KEY" in test_config):
        app.config["DB_BACKUP_ENCRYPTION_KEY"] = (
            os.environ.get("DB_BACKUP_ENCRYPTION_KEY")
            or configured_value("DB_BACKUP_ENCRYPTION_KEY")
        )

    if "DUMP_RESTORE_EXEC_ENABLED" in file_values and not (
        test_config and "DUMP_RESTORE_EXEC_ENABLED" in test_config
    ):
        app.config["DUMP_RESTORE_EXEC_ENABLED"] = as_bool(
            file_values["DUMP_RESTORE_EXEC_ENABLED"]
        )

    if not (test_config and "ZABBIX_PRODUCTION_ACTION_HMAC_KEY" in test_config):
        app.config["ZABBIX_PRODUCTION_ACTION_HMAC_KEY"] = (
            os.environ.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY")
            or configured_value("ZABBIX_PRODUCTION_ACTION_HMAC_KEY")
        )

    for key in (
        "SLACK_EMERGENCY_CHANNEL_ID",
        "DUMP_BACKUP_DIR",
        "DUMP_RESTORE_EXECUTOR",
        "DUMP_FAILOVER_EXECUTOR_STATE_DIR",
        "DR_REPO_ROOT",
        "DR_STATE_DIR",
        "DEMO_DUMP_RESTORE_STATE_DIR",
        "DR_LOG_DIR",
        "CHATOPS_EXECUTION_LOG_DIR",
        "DR_APPROVAL_REQUIRED",
        "DR_SINGLE_APPROVAL_TEST_EXPIRES_AT",
    ):
        if key in file_values and not (test_config and key in test_config):
            app.config[key] = file_values[key]
    if "EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS" in file_values and not (
        test_config and "EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS" in test_config
    ):
        try:
            app.config["EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS"] = int(
                file_values["EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS"]
            )
        except ValueError:
            app.config["EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS"] = 60
    for key in (
        "EMERGENCY_TTL_SECONDS", "DUMP_RESTORE_EXEC_ENABLED", "DB_NR_ENABLED",
    ):
        if key in file_values and not (test_config and key in test_config):
            if key == "EMERGENCY_TTL_SECONDS":
                try:
                    app.config[key] = int(file_values[key])
                except ValueError:
                    app.config[key] = EMERGENCY_TTL_SECONDS
            else:
                app.config[key] = as_bool(file_values[key])

    if "NETWORK_DR_HEALTH_ENABLED" in file_values and not (
        test_config and "NETWORK_DR_HEALTH_ENABLED" in test_config
    ):
        app.config["NETWORK_DR_HEALTH_ENABLED"] = as_bool(file_values["NETWORK_DR_HEALTH_ENABLED"])
    if "NETWORK_DR_HEALTH_FRESHNESS_SECONDS" in file_values and not (
        test_config and "NETWORK_DR_HEALTH_FRESHNESS_SECONDS" in test_config
    ):
        try:
            app.config["NETWORK_DR_HEALTH_FRESHNESS_SECONDS"] = int(
                file_values["NETWORK_DR_HEALTH_FRESHNESS_SECONDS"]
            )
        except ValueError:
            app.config["NETWORK_DR_HEALTH_FRESHNESS_SECONDS"] = 300
    if "FAILBACK_STABILITY_SECONDS" in file_values and not (
        test_config and "FAILBACK_STABILITY_SECONDS" in test_config
    ):
        try:
            app.config["FAILBACK_STABILITY_SECONDS"] = int(file_values["FAILBACK_STABILITY_SECONDS"])
        except ValueError:
            app.config["FAILBACK_STABILITY_SECONDS"] = 300

    configured_approval_required = app.config.get("DR_APPROVAL_REQUIRED", "2")
    configured_test_expiry = app.config.get("DR_SINGLE_APPROVAL_TEST_EXPIRES_AT", "")
    try:
        requested_approval_required = int(configured_approval_required)
    except (TypeError, ValueError):
        requested_approval_required = 0
    if requested_approval_required == REQUIRED_APPROVALS:
        app.config["APPROVAL_REQUIRED"] = REQUIRED_APPROVALS
        app.config["APPROVAL_TEST_EXPIRES_AT_EPOCH"] = None
        app.config["APPROVAL_POLICY_CONFIG_REASON"] = "two_person_default"
    elif requested_approval_required == 1:
        expiry = parse_single_approval_expiry(configured_test_expiry)
        now = utc_timestamp()
        if expiry is None:
            policy_reason = "single_approval_expiry_missing_or_invalid"
        elif expiry <= now:
            policy_reason = "single_approval_test_window_expired"
        elif expiry - now > MAX_SINGLE_APPROVAL_TEST_WINDOW_SECONDS:
            policy_reason = "single_approval_test_window_exceeds_four_hours"
        else:
            policy_reason = "single_approval_test_mode_enabled"
        if policy_reason == "single_approval_test_mode_enabled":
            app.config["APPROVAL_REQUIRED"] = 1
            app.config["APPROVAL_TEST_EXPIRES_AT_EPOCH"] = expiry
            app.config["APPROVAL_POLICY_CONFIG_REASON"] = policy_reason
        else:
            app.config["APPROVAL_REQUIRED"] = REQUIRED_APPROVALS
            app.config["APPROVAL_TEST_EXPIRES_AT_EPOCH"] = None
            app.config["APPROVAL_POLICY_CONFIG_REASON"] = policy_reason
    else:
        app.config["APPROVAL_REQUIRED"] = REQUIRED_APPROVALS
        app.config["APPROVAL_TEST_EXPIRES_AT_EPOCH"] = None
        app.config["APPROVAL_POLICY_CONFIG_REASON"] = "invalid_approval_count_defaulted_to_two"

    if app.config.get("NETWORK_DR_HEALTH_PROVIDER") is None and app.config.get("NETWORK_DR_HEALTH_SNAPSHOT") is None:
        try:
            from network_dr_health import build_zabbix_network_provider

            provider = build_zabbix_network_provider(file_values, os.environ)
            if provider is not None:
                app.config["NETWORK_DR_HEALTH_PROVIDER"] = provider
        except Exception:
            # A missing/incomplete read-only identity must remain UNKNOWN.
            pass

    if "ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS" in file_values and not (
        test_config and "ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS" in test_config
    ):
        try:
            app.config["ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS"] = int(
                configured_value("ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS")
            )
        except ValueError:
            app.config["ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS"] = DEFAULT_TEST_MODE_MAX_EVENT_AGE_SECONDS
    if "ZABBIX_DR_MAX_EVENT_AGE_SECONDS" in file_values and not (
        test_config and "ZABBIX_DR_MAX_EVENT_AGE_SECONDS" in test_config
    ):
        try:
            app.config["ZABBIX_DR_MAX_EVENT_AGE_SECONDS"] = int(
                configured_value("ZABBIX_DR_MAX_EVENT_AGE_SECONDS")
            )
        except ValueError:
            app.config["ZABBIX_DR_MAX_EVENT_AGE_SECONDS"] = DEFAULT_DR_MAX_EVENT_AGE_SECONDS

    if "WAZUH_CORRELATION_STATE_FILE" in file_values and not (
        test_config and "WAZUH_CORRELATION_STATE_FILE" in test_config
    ):
        app.config["WAZUH_CORRELATION_STATE_FILE"] = configured_value("WAZUH_CORRELATION_STATE_FILE")
    if "WAZUH_CORRELATION_WINDOW_SECONDS" in file_values and not (
        test_config and "WAZUH_CORRELATION_WINDOW_SECONDS" in test_config
    ):
        try:
            app.config["WAZUH_CORRELATION_WINDOW_SECONDS"] = int(
                configured_value("WAZUH_CORRELATION_WINDOW_SECONDS")
            )
        except ValueError:
            app.config["WAZUH_CORRELATION_WINDOW_SECONDS"] = 900

    if "WAZUH_SECURITY_SLACK_ENABLED" in file_values and not (
        test_config and "WAZUH_SECURITY_SLACK_ENABLED" in test_config
    ):
        app.config["WAZUH_SECURITY_SLACK_ENABLED"] = configured_value(
            "WAZUH_SECURITY_SLACK_ENABLED"
        ).lower() in {"1", "true", "yes", "on"}
    if "WAZUH_SECURITY_SLACK_DRY_RUN" in file_values and not (
        test_config and "WAZUH_SECURITY_SLACK_DRY_RUN" in test_config
    ):
        app.config["WAZUH_SECURITY_SLACK_DRY_RUN"] = configured_value(
            "WAZUH_SECURITY_SLACK_DRY_RUN"
        ).lower() in {"1", "true", "yes", "on"}

    if app.config.get("WAZUH_FAILBACK_REQUIRED_AGENTS") is None:
        app.config["WAZUH_FAILBACK_REQUIRED_AGENTS"] = tuple(
            item.strip()
            for item in configured_value("WAZUH_FAILBACK_REQUIRED_AGENTS").split(",")
            if item.strip()
        )
    if app.config.get("WAZUH_SECURITY_STATE_PROVIDER") is None:
        try:
            from wazuh_live_provider import build_wazuh_provider

            live_provider = build_wazuh_provider(file_values)
            if live_provider is not None:
                app.config["WAZUH_SECURITY_STATE_PROVIDER"] = live_provider.snapshot
        except Exception:
            # A missing or incomplete live provider must remain UNKNOWN.
            pass
    channel_id = configured_value("SLACK_CHANNEL_ID")
    alert_channel_id = configured_value("SLACK_ALERT_CHANNEL_ID") or channel_id
    raw_admin_ids = configured_value("SLACK_ADMIN_USER_IDS")
    token_by_action = {
        "failover": configured_value("SLACK_FAILOVER_BOT_TOKEN"),
        "failback": configured_value("SLACK_FAILBACK_BOT_TOKEN"),
    }
    signing_secret_by_action = {
        "failover": configured_value("SLACK_FAILOVER_SIGNING_SECRET"),
        "failback": configured_value("SLACK_FAILBACK_SIGNING_SECRET"),
        "emergency": configured_value("SLACK_EMERGENCY_SIGNING_SECRET"),
    }
    configured_signing_secrets = app.config.get("SLACK_SIGNING_SECRETS")
    if configured_signing_secrets is not None:
        signing_secret_by_action.update(configured_signing_secrets)
    configured_admin_ids = app.config.get("ADMIN_USER_IDS")
    if configured_admin_ids is None:
        admin_ids = {item.strip() for item in raw_admin_ids.split(",") if item.strip()}
    elif isinstance(configured_admin_ids, str):
        admin_ids = {item.strip() for item in configured_admin_ids.split(",") if item.strip()}
    else:
        admin_ids = set(configured_admin_ids)

    store = ApprovalStore(
        app.config["CHATOPS_STATE_DB"],
        initial_ttl=app.config.get("INITIAL_APPROVAL_TTL_SECONDS", INITIAL_APPROVAL_TTL_SECONDS),
        approved_ttl=app.config.get("FIRST_APPROVAL_TTL_SECONDS", FIRST_APPROVAL_TTL_SECONDS),
        execution_timeout=app.config["CHATOPS_EXECUTION_TIMEOUT_SECONDS"],
        execution_lease_seconds=app.config["CHATOPS_EXECUTION_LEASE_SECONDS"],
    )
    stale_execution_states = store.recover_stale_executions()
    audit = ChatOpsAudit(app.config["CHATOPS_STATE_DB"], app.config["CHATOPS_AUDIT_FILE"])
    audit.backfill_requests(store)
    configured_clients = app.config.get("SLACK_CLIENTS")
    if configured_clients is None and app.config.get("SLACK_CLIENT") is not None:
        configured_clients = {
            "failover": app.config["SLACK_CLIENT"],
            "failback": app.config["SLACK_CLIENT"],
        }
    slack_clients = configured_clients or {
        action: SlackClient(token, channel_id) for action, token in token_by_action.items()
    }
    if configured_clients is not None:
        slack_clients = dict(slack_clients)
    emergency_channel_id = app.config.get("SLACK_EMERGENCY_CHANNEL_ID") or configured_value(
        "SLACK_EMERGENCY_CHANNEL_ID"
    )
    app.config["SLACK_EMERGENCY_CHANNEL_ID"] = emergency_channel_id
    emergency_client = app.config.get("SLACK_EMERGENCY_CLIENT")
    if emergency_client is None and emergency_channel_id:
        emergency_client = SlackClient(
            configured_value("SLACK_EMERGENCY_BOT_TOKEN"),
            emergency_channel_id,
        )
    if emergency_client is not None:
        slack_clients["emergency"] = emergency_client
    alert_client = app.config.get("SLACK_ALERT_CLIENT") or SlackClient(
        configured_value("SLACK_ALERT_BOT_TOKEN"), alert_channel_id
    )
    security_client = app.config.get("WAZUH_SECURITY_SLACK_CLIENT")
    if security_client is None and app.config.get("WAZUH_SECURITY_SLACK_ENABLED"):
        security_token = configured_value("WAZUH_SECURITY_SLACK_TOKEN") or configured_value(
            "SLACK_SECURITY_BOT_TOKEN"
        )
        security_channel = configured_value("WAZUH_SECURITY_SLACK_CHANNEL") or configured_value(
            "SLACK_SECURITY_CHANNEL_ID"
        )
        if security_token and security_channel and not app.config.get("WAZUH_SECURITY_SLACK_DRY_RUN"):
            security_client = SlackClient(security_token, security_channel)
    app.extensions["approval_store"] = store
    app.extensions["emergency_console_store"] = EmergencyConsoleStore(app.config["CHATOPS_STATE_DB"])
    app.extensions["chatops_audit"] = audit
    app.extensions["slack_clients"] = slack_clients
    app.extensions["wazuh_alert_client"] = alert_client
    app.extensions["wazuh_security_client"] = security_client
    app.extensions["admin_user_ids"] = admin_ids
    app.extensions["slack_signing_secrets"] = signing_secret_by_action
    app.extensions["slack_replay_cache"] = {}
    app.extensions["slack_replay_lock"] = threading.Lock()
    app.extensions["emergency_status_lock"] = threading.Lock()
    app.extensions["emergency_status_inflight"] = False
    app.extensions["execution_log_lock"] = threading.Lock()
    app.extensions["execution_log_inflight"] = set()
    app.extensions["dump_background_lock"] = threading.Lock()
    app.extensions["dump_background_inflight"] = set()
    app.extensions["pipeline_lock"] = threading.Lock()
    app.extensions["emergency_dump_creation_lock"] = threading.Lock()
    app.extensions["approval_mode_expiry_audit_lock"] = threading.Lock()
    app.extensions["approval_mode_expiry_audited"] = False
    for stale_state in stale_execution_states:
        if (
            stale_state
            and stale_state.get("status") == "PARTIAL_FAILURE"
            and is_existing_dr_demo_dump_failover(stale_state)
        ):
            unknown_outcome = {
                "status": "PARTIAL_FAILURE",
                "result": "dump_executor_outcome_requires_operator_review",
                "phase": "UNKNOWN",
                "failure_code": "CHATOPS_EXECUTOR_OUTCOME_UNKNOWN",
                "automatic_rollback_allowed": False,
                "operator_intervention_required": True,
                "executor_status": "UNKNOWN",
            }
            try:
                audit_dump_executor_outcome(app, stale_state, unknown_outcome)
            except Exception as audit_exc:
                print(
                    f"[AUDIT WARN] Dump stale execution audit failed: {type(audit_exc).__name__}",
                    flush=True,
                )
            update_slack_message(
                app,
                stale_state,
                dump_executor_slack_detail(stale_state, unknown_outcome),
            )
    initial_required, initial_deadline = approval_policy_from_config(
        app.config,
        "failover",
        request_type=SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE,
    )
    prior_mode_event = audit.latest_event_of(
        {
            "single_approval_test_mode_enabled",
            "single_approval_test_mode_disabled",
            "single_approval_test_mode_expired",
        }
    )
    if initial_required == 1:
        if not (
            prior_mode_event
            and prior_mode_event.get("event") == "single_approval_test_mode_enabled"
            and prior_mode_event.get("approval_mode_expires_at")
            and abs(float(prior_mode_event["approval_mode_expires_at"]) - initial_deadline) < 1
        ):
            audit.record_event(
                "single_approval_test_mode_enabled",
                {
                    "approval_required": 1,
                    "approval_mode_expires_at": initial_deadline,
                    "mode": "temporary_test",
                    "scope": "synthetic_mysql_demo_only",
                },
            )
    elif prior_mode_event and prior_mode_event.get("event") == "single_approval_test_mode_enabled":
        config_reason = app.config.get("APPROVAL_POLICY_CONFIG_REASON", "two_person_default")
        ended_event = (
            "single_approval_test_mode_expired"
            if config_reason == "single_approval_test_window_expired"
            else "single_approval_test_mode_disabled"
        )
        audit.record_event(
            ended_event,
            {
                "approval_required": REQUIRED_APPROVALS,
                "approval_mode_expires_at": prior_mode_event.get("approval_mode_expires_at"),
                "reason": config_reason,
                "mode": "two_person",
            },
        )
    expire_pending_requests(app)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.get("/")
    def index():
        return "<h1>Hospital DR Orchestration Console</h1>"

    @app.post("/chatops/synthetic-mysql-demo/request")
    def create_synthetic_mysql_demo_request():
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"error": "synthetic demo request creation is localhost-only"}), 403
        payload = request.get_json(silent=True)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"confirm_synthetic_mysql_demo"}
            or payload.get("confirm_synthetic_mysql_demo") is not True
        ):
            return jsonify({"error": "explicit synthetic MySQL demo confirmation is required"}), 400
        if not admin_ids:
            return jsonify({"error": "no authorized Slack approver is configured"}), 503

        required, mode_expires_at = approval_policy_from_config(
            app.config, "failover", request_type=SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE
        )
        if required != 1 or mode_expires_at is None:
            return jsonify({"error": "bounded single-admin synthetic demo window is not active"}), 409
        if read_persistent_dr_state(app.config["DR_STATE_FILE"]) != "IDLE":
            return jsonify({"error": "DR state must be IDLE for the isolated synthetic demo"}), 409
        store = app.extensions["approval_store"]
        if (
            store.find_active("failover") is not None
            or store.find_active("failback") is not None
            or store.find_executing() is not None
            or app.extensions["pipeline_lock"].locked()
        ):
            return jsonify({"error": "another ChatOps request or execution is active"}), 409

        now = utc_timestamp()
        try:
            binding = build_synthetic_mysql_demo_binding(
                app.config, issued_at=now, mode_expires_at=mode_expires_at
            )
        except Exception as exc:
            reason = str(exc) if re.fullmatch(r"synthetic_demo_[a-z_]+", str(exc)) else "synthetic_demo_contract_unavailable"
            return jsonify({"error": "synthetic demo contract is unavailable", "code": reason}), 503

        incident = {
            "incident_id": str(uuid.uuid4()),
            "summary": "Isolated synthetic AWS MySQL A/B data roundtrip",
            "observed_at": format_timestamp(now),
            "request_type": SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE,
            "request_origin": SYNTHETIC_MYSQL_DEMO_REQUEST_ORIGIN,
            "source": SYNTHETIC_MYSQL_DEMO_REQUEST_SOURCE,
            "slack_client_key": "failover",
            "test_mode": False,
            SYNTHETIC_MYSQL_DEMO_AUTHORIZATION_FIELD: binding,
        }
        try:
            state, reused = create_approval_request(app, "failover", incident)
        except (RuntimeError, ValueError) as exc:
            reason = str(exc) if re.fullmatch(r"[a-z_]+", str(exc)) else "synthetic_demo_request_rejected"
            return jsonify({"error": "synthetic demo request was not created", "code": reason}), 409
        except SlackApiError:
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        except Exception as exc:
            print(f"[SLACK ERROR] Synthetic demo request failed: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        app.extensions["chatops_audit"].record_event(
            "synthetic_mysql_demo_approval_requested",
            {
                "request_id": state["request_id"],
                "request_type": SYNTHETIC_MYSQL_DEMO_REQUEST_TYPE,
                "approval_required": 1,
                "executor_started": False,
            },
        )
        return jsonify({
            "request_id": state["request_id"],
            "action": "failover",
            "status": state["status"],
            "approval_required": state.get("approval_required"),
            "approval_mode_expires_at": state.get("approval_mode_expires_at"),
            "reused": reused,
            "scope": "synthetic_mysql_demo_only",
        })

    @app.post("/chatops/request")
    def create_request():
        if request.remote_addr not in ("IP_REDACTED", "::1") and not app.config.get("ALLOW_REMOTE_REQUEST_CREATION", False):
            return jsonify({"error": "request creation is restricted to MSP localhost"}), 403
        if not admin_ids:
            return jsonify({
                "error": "SLACK_ADMIN_USER_IDS must contain at least one administrator; two distinct administrators are required to execute"
            }), 503

        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        if action not in ("failover", "failback"):
            return jsonify({"error": "action must be failover or failback"}), 400
        incident = {
            "incident_id": str(payload.get("incident_id") or uuid.uuid4()),
            "summary": safe_mrkdwn(payload.get("summary") or f"{action} request", 300),
            "observed_at": payload.get("observed_at") or format_timestamp(utc_timestamp()),
        }
        if action == "failover":
            # Persist the normal Failover type at the trusted request boundary.
            # The recovery planner only pins NR/Dump policy for explicit
            # NORMAL_FAILOVER / EMERGENCY_FAILOVER requests; deriving it later
            # from the action left signed Zabbix requests without a plan.
            incident["request_type"] = "NORMAL_FAILOVER"
        source = str(payload.get("source") or "").strip().lower()
        test_mode = as_bool(payload.get("test_mode"))
        zabbix_failover_metadata = any(
            key in payload
            for key in ("DR_Escalate", "event_tags_json", "trigger_id", "TriggerID")
        )
        if action == "failover" and source == "zabbix_test_action":
            secret = str(app.config.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY") or "")
            if len(secret.encode("utf-8")) < 32:
                return jsonify({
                    "error": "Zabbix Action authentication is not configured",
                    "code": "ZABBIX_ACTION_AUTH_UNAVAILABLE",
                }), 503
            raw_body = request.get_data(cache=True)
            if not _verify_zabbix_production_action_signature(
                app,
                raw_body,
                request.headers.get("X-ChatOps-Zabbix-Timestamp"),
                request.headers.get("X-ChatOps-Zabbix-Signature"),
            ):
                return jsonify({
                    "error": "Zabbix test Action authentication failed",
                    "code": "ZABBIX_TEST_ACTION_AUTH_FAILED",
                }), 403
            if not _zabbix_test_action_event_contract(payload):
                return jsonify({
                    "error": "Zabbix test Action event contract is invalid",
                    "code": "ZABBIX_TEST_EVENT_CONTRACT_INVALID",
                }), 422
            event_age = parse_event_age(payload.get("event_age_seconds"))
            if event_age is None or event_age < 0 or event_age > app.config["ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS"]:
                return jsonify({"error": "stale or invalid Zabbix test event"}), 422
            incident.update({
                "request_type": ZABBIX_TEST_FAILOVER_REQUEST_TYPE,
                "request_origin": ZABBIX_TEST_ACTION_NAME,
                "source": "zabbix_test_action",
                "production_action_verified": False,
                "test_mode": True,
                "event_age_seconds": event_age,
                "event_id": str(payload["event_id"]),
                "zabbix_event_id": str(payload["event_id"]),
                "trigger_id": str(payload["trigger_id"]),
                "event_source": "0",
                "event_status": "PROBLEM",
                "event_tags_json": payload["event_tags_json"],
                "action_name": ZABBIX_TEST_ACTION_NAME,
                "host": safe_mrkdwn(payload["host"], 120),
                "severity": safe_mrkdwn(payload.get("severity") or "UNKNOWN", 20),
            })
            if payload.get("incident_at"):
                incident["incident_at"] = str(payload["incident_at"])
        elif action == "failover" and (
            source.startswith("zabbix") or zabbix_failover_metadata
        ):
            if source != "zabbix_production_action":
                return jsonify({
                    "error": "Zabbix Failover requires the authenticated Production Action",
                    "code": "UNTRUSTED_ZABBIX_FAILOVER_SOURCE",
                }), 403
            secret = str(app.config.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY") or "")
            if len(secret.encode("utf-8")) < 32:
                return jsonify({
                    "error": "Production Zabbix Action authentication is not configured",
                    "code": "ZABBIX_ACTION_AUTH_UNAVAILABLE",
                }), 503
            raw_body = request.get_data(cache=True)
            if not _verify_zabbix_production_action_signature(
                app,
                raw_body,
                request.headers.get("X-ChatOps-Zabbix-Timestamp"),
                request.headers.get("X-ChatOps-Zabbix-Signature"),
            ):
                return jsonify({
                    "error": "Production Zabbix Action authentication failed",
                    "code": "ZABBIX_ACTION_AUTH_FAILED",
                }), 403
            if not _zabbix_production_event_contract(payload):
                return jsonify({
                    "error": "Production Zabbix event contract is invalid",
                    "code": "ZABBIX_EVENT_CONTRACT_INVALID",
                }), 422
            event_age = parse_event_age(payload.get("event_age_seconds"))
            if event_age is None:
                return jsonify({"error": "zabbix event age is missing or invalid"}), 422
            if event_age < 0 or event_age > app.config["ZABBIX_DR_MAX_EVENT_AGE_SECONDS"]:
                provider = app.config.get("NETWORK_DR_HEALTH_PROVIDER")
                provider_object = getattr(provider, "__self__", None)
                if provider_object is None and hasattr(provider, "onprem_targets_snapshot"):
                    provider_object = provider
                recheck = getattr(provider_object, "onprem_targets_snapshot", None)
                try:
                    current_health = recheck() if callable(recheck) else None
                except Exception:
                    current_health = None
                if not isinstance(current_health, dict) or current_health.get("status") != "PROBLEM":
                    print("[ZABBIX] stale event rejected; current On-Prem failure was not freshly verified", flush=True)
                    return jsonify({"error": "stale zabbix event was not confirmed by fresh On-Prem probes"}), 422
                incident["zabbix_revalidated_at"] = current_health.get("checked_at") or format_timestamp(utc_timestamp())
                incident["zabbix_revalidated_status"] = "PROBLEM"
                incident["zabbix_revalidated_reason"] = safe_mrkdwn(current_health.get("reason") or "fresh probe failure", 200)
                print("[ZABBIX] older active event accepted after fresh On-Prem failure recheck", flush=True)
            incident.update({
                "source": "zabbix",
                "request_origin": ZABBIX_PRODUCTION_ACTION_NAME,
                "production_action_verified": True,
                "event_age_seconds": event_age,
                "rule_id": str(payload["trigger_id"]),
                "host": safe_mrkdwn(payload["host"], 120),
                "severity": safe_mrkdwn(payload.get("severity") or "UNKNOWN", 20),
            })
            if payload.get("incident_at"):
                incident["incident_at"] = str(payload["incident_at"])
        elif source == "zabbix":
            # Production Zabbix approval messages carry EVENT.AGE in their
            # structured operation message. This legacy source remains for
            # Failback only; a source string can no longer authorize Failover.
            event_age = parse_event_age(payload.get("event_age_seconds"))
            if event_age is None:
                return jsonify({"error": "zabbix event age is missing or invalid"}), 422
            if event_age < 0 or event_age > app.config["ZABBIX_DR_MAX_EVENT_AGE_SECONDS"]:
                print("[ZABBIX] stale production event rejected before approval request", flush=True)
                return jsonify({"error": "stale zabbix event rejected"}), 422
            incident.update({"source": "zabbix", "event_age_seconds": event_age})
            if payload.get("incident_at"):
                incident["incident_at"] = str(payload["incident_at"])
            if payload.get("rto_run_id"):
                incident["rto_run_id"] = str(payload["rto_run_id"])
            if action == "failback" and not test_mode:
                dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
                if dr_state != "DR_ACTIVE":
                    print("[ZABBIX] production failback rejected outside DR_ACTIVE", flush=True)
                    return jsonify({"error": "production failback requires DR_ACTIVE"}), 409
                incident["dr_state"] = dr_state
        if test_mode:
            raw_age = payload.get("event_age_seconds")
            event_age = parse_event_age(raw_age)
            if event_age is None:
                return jsonify({"error": "test-mode event age is missing or invalid"}), 422
            if event_age < 0 or event_age > app.config["ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS"]:
                print("[ZABBIX TEST] stale event rejected before approval request", flush=True)
                return jsonify({"error": "stale test-mode event rejected"}), 422
            incident.update(
                {
                    "test_mode": True,
                    "event_age_seconds": event_age,
                    "host": safe_mrkdwn(payload.get("host") or "unknown", 120),
                }
            )
            if action == "failover" and source != "zabbix_test_action":
                # Legacy/local test requests may still verify the approval UI,
                # but receive their own two-admin request type and can never
                # be confused with a production Failover.
                incident.update({
                    "request_type": CHATOPS_TEST_FAILOVER_REQUEST_TYPE,
                    "request_origin": "CHATOPS_TEST_MODE",
                    "source": "chatops_test",
                })
        if action == "failback":
            dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
            # Creating the Slack notification is informational. Keep the
            # current state for audit, but enforce DR_ACTIVE when an admin
            # approves the actual Failback operation below.
            incident["dr_state_at_request"] = dr_state or "UNKNOWN"
            # Recovery candidates are immediate in Demo Freeze.  Keep these
            # compatibility fields at zero for older renderers and audit
            # consumers; they are no longer an approval gate.
            incident.update(
                {
                    "stability_verified": True,
                    "stability_seconds": 0,
                    "stability_required_seconds": 0,
                }
            )

            network = evaluate_current_network_health(app)
            incident.update(
                {
                    "network_status": network["status"],
                    "network_reason": network["reason"],
                    "network_source": network.get("source", "-"),
                    "network_devices": network.get("devices", {}),
                    "network_checked_at": network.get("checked_at", "-"),
                }
            )
            security = evaluate_current_failback_security(app)
            incident.update(
                {
                    "security_status": security["status"],
                    "security_reason": security["reason"],
                    "security_agents": security["agents"],
                    "security_critical_incident": security["critical_incident"],
                    "wazuh_risk_level": security["risk_level"],
                    "wazuh_risk_observed_at": security["risk_observed_at"],
                    "wazuh_risk_checked_at": security["risk_checked_at"],
                    "wazuh_risk_reason": security["risk_reason"],
                }
            )
        try:
            state, reused = create_approval_request(app, action, incident)
        except FailoverRequestBlocked as exc:
            return jsonify({"error": str(exc), "code": exc.code, "dr_state": "DR_ACTIVE"}), 409
        except SlackApiError as exc:
            print(
                f"[SLACK ERROR] Approval request delivery failed method={exc.method} error={exc.error}",
                flush=True,
            )
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        except Exception as exc:
            print(f"[SLACK ERROR] Approval request delivery failed: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        return jsonify(
            {
                "request_id": state["request_id"],
                "action": state["action"],
                "status": state["status"],
                "approval_required": state.get("approval_required", REQUIRED_APPROVALS),
                "approval_mode_expires_at": state.get("approval_mode_expires_at"),
                "incident_count": len(state["incidents"]),
                "reused": reused,
            }
        )

    @app.get("/chatops/network-health")
    def network_health():
        """Return a redacted read-only network gate for the Zabbix guard."""
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"status": "UNKNOWN", "reason": "network health is local-only"}), 403
        return jsonify(evaluate_current_network_health(app))

    @app.post("/wazuh/alert")
    def wazuh_alert():
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"error": "Wazuh alert ingestion is restricted to MSP localhost"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Wazuh alert must be a JSON object"}), 400
        try:
            from wazuh_alerts import process_wazuh_alert

            return jsonify(process_wazuh_alert(app, payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/zabbix/alert")
    def zabbix_alert():
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"error": "Zabbix alert ingestion is restricted to MSP localhost"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Zabbix alert must be a JSON object"}), 400
        try:
            from zabbix_alerts import ZabbixProcessingError, process_zabbix_alert

            return jsonify(process_zabbix_alert(app, payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except ZabbixProcessingError as exc:
            print(f"[ZABBIX ERROR] Alert processing failed: {type(exc).__name__}", flush=True)
            return jsonify({"ok": False, "error": str(exc)}), exc.status_code
        except Exception as exc:
            print(f"[ZABBIX ERROR] Alert processing failed: {type(exc).__name__}", flush=True)
            return jsonify({"ok": False, "error": "Zabbix alert processing failed"}), 502

    def handle_slack_action(expected_action=None):
        raw_body = request.get_data(cache=True)
        try:
            payload = json.loads(request.form.get("payload", "{}"))
        except json.JSONDecodeError:
            return jsonify({"error": "invalid Slack payload"}), 400

        if payload.get("type") == "view_submission":
            try:
                metadata = json.loads((payload.get("view") or {}).get("private_metadata") or "{}")
            except json.JSONDecodeError:
                metadata = {}
            action = metadata.get("action") or "failover"
            if expected_action and action != expected_action:
                return jsonify({"error": "Slack action does not match this endpoint"}), 400
            signature_key = slack_signature_key(app, action, metadata=metadata)
            signing_secret = signing_secret_by_action.get(signature_key, "")
            if app.config["VERIFY_SLACK_SIGNATURE"]:
                if not signing_secret:
                    return jsonify(
                        {"error": f"SLACK_{signature_key.upper()}_SIGNING_SECRET is not configured"}
                    ), 503
                timestamp = request.headers.get("X-Slack-Request-Timestamp")
                signature = request.headers.get("X-Slack-Signature")
                if not valid_slack_signature(signing_secret, raw_body, timestamp, signature):
                    return jsonify({"error": "invalid Slack signature"}), 401
                if not remember_slack_request(
                    app.extensions["slack_replay_cache"],
                    app.extensions["slack_replay_lock"],
                    timestamp,
                    signature,
                ):
                    return jsonify({"error": "replayed Slack request"}), 401
            return handle_view_submission(app, payload, action, admin_ids)

        request_id, action, operation, interaction_metadata = parse_interaction(payload, store)
        if expected_action and action != expected_action:
            return jsonify({"error": "Slack action does not match this endpoint"}), 400
        if action not in ("failover", "failback"):
            return ephemeral("요청 작업을 식별할 수 없습니다.")
        channel_id = (payload.get("channel") or {}).get("id") or (
            payload.get("container") or {}
        ).get("channel_id")
        signature_key = slack_signature_key(
            app,
            action,
            operation=operation,
            channel_id=channel_id,
        )
        signing_secret = signing_secret_by_action.get(signature_key, "")
        if app.config["VERIFY_SLACK_SIGNATURE"]:
            if not signing_secret:
                return jsonify({
                    "error": f"SLACK_{signature_key.upper()}_SIGNING_SECRET is not configured"
                }), 503
            timestamp = request.headers.get("X-Slack-Request-Timestamp")
            signature = request.headers.get("X-Slack-Signature")
            if not valid_slack_signature(
                signing_secret,
                raw_body,
                timestamp,
                signature,
            ):
                return jsonify({"error": "invalid Slack signature"}), 401
            if not remember_slack_request(
                app.extensions["slack_replay_cache"],
                app.extensions["slack_replay_lock"],
                timestamp,
                signature,
            ):
                return jsonify({"error": "replayed Slack request"}), 401

        user_id = (payload.get("user") or {}).get("id", "")
        response_url = payload.get("response_url", "")
        if operation in ("emergency_status", "emergency_open", "emergency_dump_open", "dump_open"):
            if not admin_ids:
                return ephemeral("관리자 승인 목록이 설정되지 않았습니다.")
            if user_id not in admin_ids:
                return ephemeral("등록된 관리자만 사용할 수 있습니다.")
            trigger_id = payload.get("trigger_id")
            if operation == "emergency_status":
                if not valid_slack_response_url(response_url):
                    return ephemeral(
                        "상태 조회 응답 주소가 없거나 Slack 주소가 아닙니다. "
                        "Slack interaction payload와 Request URL 설정을 확인해 주세요."
                    )
                result = start_emergency_status_check(app, response_url)
                if result == "already_running":
                    return ephemeral("이미 상태 조회가 진행 중입니다. 잠시 후 결과를 확인해 주세요.")
                if result != "started":
                    return ephemeral(
                        "상태 조회 작업을 시작하지 못했습니다. "
                        "ChatOps 서비스 로그에서 EMERGENCY_STATUS_START_FAILED를 확인해 주세요."
                    )
                return ephemeral(
                    "상태 조회를 시작했습니다. 조회 결과는 잠시 후 버튼을 누른 관리자에게만 표시됩니다."
                )
            if not trigger_id:
                return ephemeral("Slack trigger_id를 확인할 수 없습니다.")
            request_type = json.loads((payload.get("actions") or [{}])[0].get("value", "{}")).get("request_type")
            if operation in ("emergency_open", "emergency_dump_open"):
                client = app.extensions["slack_clients"].get("emergency")
                if client is None or not client.available:
                    return ephemeral("Emergency channel client가 설정되지 않았습니다.")
                if operation == "emergency_dump_open" and request_type != REQUEST_TYPE_DUMP_RESTORE:
                    return ephemeral("Emergency Dump 요청 유형을 확인할 수 없습니다.")
                try:
                    client.open_view(
                        trigger_id,
                        emergency_reason_view(
                            action,
                            request_type,
                            request_origin="EMERGENCY"
                            if operation == "emergency_dump_open"
                            else None,
                        ),
                    )
                except SlackApiError as exc:
                    return ephemeral(f"Emergency modal을 열 수 없습니다: {exc.error}")
                except requests.RequestException as exc:
                    print(
                        f"[SLACK MODAL] emergency open failed transport_error={type(exc).__name__}",
                        flush=True,
                    )
                    return ephemeral(
                        "Slack 연결이 지연되어 긴급 요청 창을 열지 못했습니다. 잠시 후 다시 시도해 주세요."
                    )
                return "", 200
            channel_id = (payload.get("channel") or {}).get("id") or (payload.get("container") or {}).get("channel_id")
            client_key = "emergency" if channel_id == app.config.get("SLACK_EMERGENCY_CHANNEL_ID") else action
            client = app.extensions["slack_clients"].get(client_key)
            if client is None or not client.available:
                return ephemeral("Dump 승인 채널 client가 설정되지 않았습니다.")
            metadata = {"action": action, "slack_client_key": client_key}
            parent_state = store.get(request_id) if request_id else None
            if parent_state:
                parent_incident = latest_incident(parent_state)
                parent_type = request_type_from_state(parent_state)
                emergency_origin = (
                    client_key == "emergency"
                    or parent_incident.get("request_origin") == "EMERGENCY"
                    or parent_type in {
                        REQUEST_TYPE_EMERGENCY_FAILOVER,
                        REQUEST_TYPE_EMERGENCY_FAILBACK,
                    }
                )
                if emergency_origin:
                    metadata.update(
                        {
                            "request_origin": "EMERGENCY",
                            "requested_by": parent_incident.get("requested_by") or user_id,
                            "reason_code": parent_incident.get("reason_code"),
                            "reason_text": parent_incident.get("reason_text"),
                        }
                    )
                elif parent_type == REQUEST_TYPE_DUMP_RESTORE:
                    metadata["request_origin"] = "GENERAL"
                    metadata["requested_by"] = parent_incident.get("requested_by") or user_id
            try:
                client.open_view(
                    trigger_id,
                    dump_select_view(
                        action,
                        app.config["DUMP_BACKUP_DIR"],
                        client_key,
                        metadata=metadata,
                    ),
                )
            except SlackApiError as exc:
                return ephemeral(f"Dump 선택창을 열 수 없습니다: {exc.error}")
            except requests.RequestException as exc:
                print(
                    f"[SLACK MODAL] dump selector open failed client={client_key} "
                    f"transport_error={type(exc).__name__}",
                    flush=True,
                )
                return ephemeral(
                    "Slack 연결이 지연되어 Dump 선택창을 열지 못했습니다. 잠시 후 다시 시도해 주세요."
                )
            return "", 200
        if not request_id or operation not in (
            "approve",
            "cancel",
            "execution_log",
            "execution_log_close",
        ):
            return ephemeral("요청을 찾을 수 없거나 이미 만료되었습니다. 새 승인 요청을 생성해 주세요.")
        if not admin_ids:
            return ephemeral("관리자 승인 목록이 설정되지 않았습니다. SLACK_ADMIN_USER_IDS를 확인해 주세요.")
        if user_id not in admin_ids:
            return ephemeral("이 작업은 등록된 관리자만 승인하거나 취소할 수 있습니다.")

        # Log viewing is read-only: do not run expiry cleanup, attach message
        # metadata, update approval state, or touch the execution pipeline.
        if operation in ("execution_log", "execution_log_close"):
            if not valid_slack_response_url(response_url):
                return ephemeral("로그 창 응답 주소가 없거나 유효한 Slack 주소가 아닙니다.")
            state = store.get(request_id)
            if operation == "execution_log" and (
                not state
                or state.get("action") != action
                or state.get("status") not in {
                    "EXECUTING", "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE",
                    "FAILED", "PARTIAL_FAILURE",
                }
            ):
                return ephemeral("요청을 찾을 수 없거나 작업 유형이 일치하지 않습니다.")
            result = start_execution_log_response(
                app,
                response_url,
                request_id,
                action,
                user_id,
                operation,
            )
            if result == "already_running":
                return ephemeral("로그 응답을 처리 중입니다. 잠시 후 다시 확인해 주세요.")
            if result != "started":
                return ephemeral("로그 화면 작업을 시작하지 못했습니다. ChatOps 서비스 로그를 확인해 주세요.")
            return "", 200

        expire_pending_requests(app)

        container = payload.get("container") or {}
        channel_id = (payload.get("channel") or {}).get("id") or container.get("channel_id")
        message_ts = container.get("message_ts") or (payload.get("message") or {}).get("ts")
        state = store.get(request_id)
        if state and message_ts and channel_id and not state.get("slack_message_ts"):
            state = store.attach_slack_message(request_id, channel_id, message_ts)

        if operation == "cancel":
            result, state = store.cancel(request_id, action, cancelled_by=user_id)
            if result == "cancelled":
                update_slack_message(app, state, f"Cancelled by <@{user_id}>. All approvals were discarded. / <@{user_id}> 요청 취소, 기존 승인 폐기")
                return "", 200
            if result == "executing":
                return ephemeral("이미 실행 중인 요청은 취소할 수 없습니다.")
            if state and state["status"] == "EXPIRED":
                update_slack_message(app, state)
            return ephemeral("이미 종료되었거나 만료된 요청입니다.")

        state = state or store.get(request_id)
        if action == "failback" and operation == "approve":
            if (
                interaction_metadata.get("db_failback_overwrite_confirmation") != "OVERWRITE_ONPREM_DB"
                or interaction_metadata.get("db_failback_overwrite_request_id") != request_id
            ):
                return ephemeral(
                    "요청별 On-Prem DB 덮어쓰기 확인이 포함된 최신 Failback 버튼을 사용해 주세요."
                )
        current_request_type = request_type_from_state(state or {})
        failback_approval_security = None
        if (
            action == "failback"
            and operation == "approve"
            and state
            and state.get("status") in APPROVAL_STATUSES
        ):
            # Re-evaluate once at click time and share this snapshot with the
            # existing safety checks and stale-warning comparison.
            failback_approval_security = evaluate_current_failback_security(app)
        if current_request_type in {
            REQUEST_TYPE_EMERGENCY_FAILOVER,
            REQUEST_TYPE_EMERGENCY_FAILBACK,
            REQUEST_TYPE_DUMP_RESTORE,
            REQUEST_TYPE_SECURITY,
        }:
            incident = latest_incident(state or {})
            backup = None
            if current_request_type == REQUEST_TYPE_DUMP_RESTORE:
                restore_mode = str(incident.get("dump_restore_mode") or "MANIFEST_VERIFIED")
                backup = resolve_dump_backup(
                    app.config["DUMP_BACKUP_DIR"],
                    incident.get("backup_id"),
                    allow_legacy_manual=restore_mode == "LEGACY_MANUAL",
                    encryption_key=app.config.get("DB_BACKUP_ENCRYPTION_KEY"),
                )
                if backup is not None:
                    backup["expected_checksum"] = incident.get("backup_checksum")
                    backup["expected_sidecar_checksum"] = incident.get("backup_sidecar_checksum")
                    backup["dump_restore_mode"] = restore_mode
            precheck = evaluate_emergency_precheck(
                app,
                action,
                current_request_type,
                backup=backup,
                failback_security=failback_approval_security,
            )
            if precheck["status"] == "FAILED":
                state = store.reset_approvals(
                    request_id,
                    ttl_seconds=app.config.get("EMERGENCY_TTL_SECONDS", EMERGENCY_TTL_SECONDS)
                    if current_request_type != REQUEST_TYPE_SECURITY
                    else None,
                    result="precheck_failed",
                )
                update_slack_message(app, state, f"Pre-check FAILED: {precheck['reason']}")
                return ephemeral(f"실행 전 안전 검사가 실패했습니다: {precheck['reason']}")

        if (
            action == "failback"
            and current_request_type == request_type_for_action("failback")
            and state
            and state.get("status") in APPROVAL_STATUSES
        ):
            dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
            if dr_state != "DR_ACTIVE":
                state = store.reset_approvals(request_id, result="failback_dr_state_changed")
                update_slack_message(
                    app,
                    state,
                    "Failback 승인 중 DR 상태가 DR_ACTIVE가 아니게 되어 기존 승인을 폐기했습니다. "
                    "DR_ACTIVE를 확인한 뒤 새 요청을 생성해 주세요.",
                )
                return ephemeral(
                    f"Failback 승인 차단: 현재 DR 상태는 {dr_state or 'UNKNOWN'}입니다."
                )
            network = evaluate_current_network_health(app)
            state = store.refresh_failback_network(request_id, network)
            if network["status"] != "READY":
                update_slack_message(
                    app, state,
                    f"Network/SNMP Status: {network['status']} (informational). "
                    "Failback continues to rely on DB connectivity, service Health, and DNS verification."
                )
            security = failback_approval_security or evaluate_current_failback_security(app)
            state = store.refresh_failback_security(request_id, security)
            if security["status"] == "BLOCKED":
                update_slack_message(app, state, f"Security Status: {security['status']}. Failback approval remains blocked.")
                return ephemeral(
                    f"Failback Security Gate: {security['status']}. {security['reason']}"
                )
            if security["status"] != "READY":
                update_slack_message(
                    app, state,
                    f"Security Status: {security['status']} (informational). "
                    "No verified destructive Critical incident was reported; operational DB, service, and DNS checks remain required."
                )

        if (
            action == "failback"
            and operation == "approve"
            and state
            and state.get("status") in APPROVAL_STATUSES
            and failback_approval_security is not None
            and failback_risk_snapshot_changed(interaction_metadata, failback_approval_security)
        ):
            state = store.refresh_failback_security(request_id, failback_approval_security)
            update_slack_message(
                app,
                state,
                "Wazuh 위험도가 버튼 표시 이후 변경되었거나 오래된 버튼입니다. 이 클릭은 승인으로 기록되지 않았습니다.",
            )
            return ephemeral(
                "Wazuh 위험도 표시가 최신 상태와 달라 이번 클릭은 승인으로 처리하지 않았습니다. "
                "갱신된 메시지의 위험도를 확인한 뒤 다시 승인해 주세요."
            )

        result, state = store.approve(request_id, action, user_id)
        if result == "global_lock":
            active_id = state.get("request_id") if state else "unknown"
            return ephemeral(f"다른 DR 작업이 실행 중입니다: {active_id}. 현재 작업이 끝난 뒤 다시 시도하세요.")
        if result == "overwrite_authorization_invalid":
            update_slack_message(
                app,
                state,
                "요청별 기존 AWS DR DB 덮어쓰기 승인 기록이 없거나 요청 정보와 일치하지 않아 승인을 기록하지 않았습니다.",
            )
            return ephemeral("요청별 덮어쓰기 승인 정보를 검증하지 못했습니다. 이 클릭은 승인되지 않았습니다.")
        if (
            action == "failover"
            and state
            and not is_test_mode_failover(state)
            and not is_synthetic_mysql_demo_request(state)
        ):
            incidents = state.get("incidents") or []
            latest_incident_data = incidents[-1] if incidents else {}
            if result == "pending":
                _record_rto(latest_incident_data, "first_approval_at", approval_id=request_id)
            elif result == "approved":
                approval_stage = (
                    "first_approval_at"
                    if int(state.get("approval_required") or REQUIRED_APPROVALS) == 1
                    else "second_approval_at"
                )
                _record_rto(latest_incident_data, approval_stage, approval_id=request_id)
        if result == "duplicate":
            return ephemeral(
                f"이미 승인된 요청입니다. 현재 승인: {len(state['approvers'])}/{int(state.get('approval_required') or REQUIRED_APPROVALS)}"
            )
        if result == "pending":
            update_slack_message(app, state)
            return "", 200
        if result == "approved":
            if action == "failover" and complete_test_mode_failover_approval(
                app, request_id, action
            ):
                return "", 200
            if action == "failover" and not is_synthetic_mysql_demo_request(state):
                incidents = (state or {}).get("incidents") or []
                _record_rto(incidents[-1] if incidents else {}, "failover_approved_at", approval_id=request_id)
            required = int((state or {}).get("approval_required") or REQUIRED_APPROVALS)
            if is_synthetic_mysql_demo_request(state):
                completion = (
                    "합성 MySQL 시연 1인 승인 완료. 고정 합성 Runner만 실행합니다. "
                    "운영 Failover/DR_STATE는 변경하지 않습니다."
                )
            elif required == 1:
                completion = (
                    "운영 요청은 1인 승인 실행 대상이 아닙니다. 새 2인 승인이 필요합니다."
                )
            else:
                completion = "Two-person approval completed. Workflow execution started. / 2인 승인 완료, 실행 시작"
            update_slack_message(app, state, completion)
            try:
                launch_pipeline(app, request_id, action, user_id, response_url)
            except Exception as exc:
                state = store.finish(request_id, False, result="launch_error")
                update_slack_message(app, state, "Workflow launch failed; a new approval is required. / 실행 시작에 실패해 새 승인이 필요합니다.")
                print(f"[CHATOPS ERROR] Pipeline launch failed: {type(exc).__name__}", flush=True)
                return ephemeral("실행 시작에 실패했습니다. 새 승인 요청을 생성해 주세요.")
            return "", 200
        if result == "executing":
            return ephemeral("이미 실행 중인 요청입니다.")
        if state and state["status"] == "EXPIRED":
            update_slack_message(app, state)
        return ephemeral("이미 종료되었거나 만료된 요청입니다. 새 요청을 생성해 주세요.")

    @app.post("/slack/action")
    def slack_action():
        return handle_slack_action()

    @app.post("/slack/failover/action")
    def slack_failover_action():
        return handle_slack_action(expected_action="failover")

    @app.post("/slack/failback/action")
    def slack_failback_action():
        return handle_slack_action(expected_action="failback")

    return app


def start_expiry_worker(app):
    def worker():
        next_zabbix_recheck = time.monotonic() + 2.0
        while True:
            try:
                expire_pending_requests(app)
            except Exception as exc:
                print(f"[EXPIRY ERROR] Approval expiry check failed: {type(exc).__name__}", flush=True)
            now = time.monotonic()
            if now >= next_zabbix_recheck:
                from zabbix_alerts import poll_failback_condition, poll_failover_condition

                for condition_poll in (poll_failover_condition, poll_failback_condition):
                    try:
                        result = condition_poll(app)
                        if result.get("status") == "REQUESTED":
                            action = "Failback" if condition_poll is poll_failback_condition else "Failover"
                            print(f"[ZABBIX] {action} approval request created from current monitoring state.", flush=True)
                    except Exception as exc:
                        print(f"[ZABBIX RECHECK ERROR] {type(exc).__name__}", flush=True)
                next_zabbix_recheck = time.monotonic() + 60.0
            sleep_for = min(
                max(1.0, float(app.config["EXPIRY_INTERVAL_SECONDS"])),
                max(0.1, next_zabbix_recheck - time.monotonic()),
            )
            time.sleep(sleep_for)

    threading.Thread(target=worker, daemon=True, name="chatops-expiry-worker").start()


def start_cleanup_worker(app):
    cleanup_interval = max(1.0, float(app.config["CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS"]))
    console_interval = max(1.0, float(app.config["EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS"]))

    def worker():
        next_cleanup = 0.0
        next_console_watchdog = 0.0
        while True:
            now = time.monotonic()
            if now >= next_console_watchdog:
                try:
                    ensure_emergency_console(app)
                except Exception as exc:
                    print(
                        f"[EMERGENCY CONSOLE] watchdog check failed error={type(exc).__name__}",
                        flush=True,
                    )
                next_console_watchdog = now + console_interval
            if now >= next_cleanup:
                try:
                    cleanup_old_slack_messages(app, ensure_console=False)
                except Exception as exc:
                    print(f"[CLEANUP ERROR] Slack retention check failed: {type(exc).__name__}", flush=True)
                next_cleanup = now + cleanup_interval
            sleep_for = min(next_console_watchdog, next_cleanup) - time.monotonic()
            time.sleep(max(0.1, sleep_for))

    threading.Thread(target=worker, daemon=True, name="chatops-cleanup-worker").start()
