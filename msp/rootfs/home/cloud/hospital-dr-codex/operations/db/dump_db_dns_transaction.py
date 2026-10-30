#!/usr/bin/env python3
"""Run a Dump-only Cloudflare DNS transaction while user writes stay fenced.

This controller is deliberately not wired into normal/emergency Failover.  It
revalidates the exact Dump preparation immediately before the first Cloudflare
PUT, reuses the canonical DNS shell helpers, and permits automatic DNS rollback
only after a fresh remote proof that application DML is still impossible.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from operations.db import dump_db_dns_preflight as dns_preflight
from operations.db import dump_db_public_readiness as public_readiness
from operations.db.dump_execution_contract import (
    LockContractError,
    validate_inherited_dr_locks as _validate_inherited_dr_locks,
)
from operations.db.isolated_dump_restore import (
    PRODUCTION_DB_INSTANCE_ID,
    PreflightError,
    validate_aws_isolated_target,
    validate_backup_pair,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DNS_HELPER = REPO_ROOT / "operations/failover/dns_transaction.sh"
PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_dns_transaction.yml"
REMOTE_DB_CLI = REPO_ROOT / "operations/db/dump_db_readonly_health_host.py"
REMOTE_DB_HELPER = REPO_ROOT / "operations/db/isolated_db_service_host.py"
REMOTE_RESTORE_HELPER = REPO_ROOT / "operations/db/isolated_restore_host.py"
REMOTE_APP_PROBE = REPO_ROOT / "operations/db/dump_db_app_fence_probe.py"
REMOTE_FENCE_HELPER = REPO_ROOT / "operations/db/dump_db_external_fence.py"
REMOTE_EXPIRY_HELPER = REPO_ROOT / "operations/db/dump_db_public_readiness_expire.py"
TRANSACTION_ROOT_DEFAULT = Path("/var/lib/hospital-dr/dump-dns-transactions")
READINESS_ROOT_DEFAULT = Path("/var/lib/hospital-dr/dump-public-readiness")
DEFAULT_DR_EIP = "AWS_PUBLIC_IP_REDACTED"
DEFAULT_CHATOPS_STATE_DB = Path("/var/lib/hospital-dr/chatops_state.sqlite3")
EXPECTED_WEB_INSTANCE = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_PRIVATE_IP = "IP_REDACTED"
EXPECTED_DOC_PRIVATE_IP = "IP_REDACTED"
EXPECTED_PRODUCTION_DB_PRIVATE_IPS = {
    "IP_REDACTED", "IP_REDACTED", "IP_REDACTED", "IP_REDACTED",
}
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 1800
DNS_API_TIMEOUT_SECONDS = 30
HEALTH_TIMEOUT_SECONDS = 15
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
BACKUP_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
PROBE_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")
CF_RAY_RE = re.compile(r"[A-Za-z0-9-]{8,80}\Z")

SUCCESS_STATUS = "DUMP_DNS_SWITCHED_MAINTENANCE_WRITES_BLOCKED"
ROLLED_BACK_STATUS = "DUMP_DNS_ROLLED_BACK_WRITES_BLOCKED"
PARTIAL_STATUS = "PARTIAL_FAILURE"


class DNSTransactionError(RuntimeError):
    """Stable, non-secret operator-facing failure identifier."""


def _uuid(value: str, code: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise DNSTransactionError(code) from exc
    normalized = str(parsed)
    if normalized != value.lower() or not UUID_RE.fullmatch(value.lower()):
        raise DNSTransactionError(code)
    return normalized


def _read_private_json(path: Path, *, owner_uid: int, code: str) -> dict:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DNSTransactionError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 2
        or metadata.st_size > 1024 * 1024
    ):
        raise DNSTransactionError(code)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DNSTransactionError(code) from exc
    if not isinstance(value, dict):
        raise DNSTransactionError(code)
    return value


def _read_probe_token(path: Path, *, owner_uid: int) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DNSTransactionError("PUBLIC_READINESS_PROBE_TOKEN_UNAVAILABLE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 40
        or metadata.st_size > 64
    ):
        raise DNSTransactionError("PUBLIC_READINESS_PROBE_TOKEN_PERMISSIONS_INVALID")
    try:
        token = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise DNSTransactionError("PUBLIC_READINESS_PROBE_TOKEN_UNAVAILABLE") from exc
    if not PROBE_TOKEN_RE.fullmatch(token):
        raise DNSTransactionError("PUBLIC_READINESS_PROBE_TOKEN_INVALID")
    return token


def _parse_time(value: object, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise DNSTransactionError(code) from exc
    if parsed.tzinfo is None:
        raise DNSTransactionError(code)
    return parsed.astimezone(timezone.utc)


def _load_ready_capability(
    *, args: argparse.Namespace, now: datetime, owner_uid: int
) -> tuple[dict, str]:
    receipt_path = Path(args.readiness_state_dir) / f"{args.cutover_id}.json"
    receipt = _read_private_json(
        receipt_path, owner_uid=owner_uid, code="PUBLIC_READINESS_RECEIPT_INVALID"
    )
    token_path = Path(args.readiness_state_dir) / f"{args.cutover_id}.probe-token"
    token = _read_probe_token(token_path, owner_uid=owner_uid)
    if (
        receipt.get("status") != "DUMP_PUBLIC_READINESS_PREPARED_NOT_DNS_AUTHORIZED"
        or receipt.get("promotion_id") != args.promotion_id
        or receipt.get("cutover_id") != args.cutover_id
        or receipt.get("backup_id") != Path(args.backup).name
        or str(receipt.get("sha256", "")).lower() != args.expected_sha256.lower()
        or receipt.get("isolated_instance_id") != args.instance_id
        or receipt.get("isolated_private_ip") != args.private_ip
        or receipt.get("data_volume_id") != args.data_volume_id
        or receipt.get("stage_volume_id") != args.stage_volume_id
        or receipt.get("service_security_group_id") != args.service_security_group_id
        or receipt.get("db_server_uuid_verified") is not True
        or receipt.get("apps_health_receipt_revalidated") is not True
        or receipt.get("user_traffic") != "MAINTENANCE"
        or receipt.get("application_dml_allowed") is not False
        or receipt.get("dns_change_authorized") is not False
        or receipt.get("dr_state_changed") is not False
        or receipt.get("dns_origin_pair_read_only_verified") is not True
        or receipt.get("health_probe_authenticated") is not True
        or receipt.get("health_probe_bodyless") is not True
        or receipt.get("automatic_strict_fence_timer_on_web_and_emr") is not True
        or receipt.get("probe_token_path") != str(token_path)
        or receipt.get("probe_token_sha256") != hashlib.sha256(token.encode("ascii")).hexdigest()
    ):
        raise DNSTransactionError("PUBLIC_READINESS_RECEIPT_MISMATCH")
    created = _parse_time(receipt.get("created_at_utc"), "PUBLIC_READINESS_RECEIPT_TIME_INVALID")
    expires = _parse_time(receipt.get("expires_at_utc"), "PUBLIC_READINESS_RECEIPT_TIME_INVALID")
    ttl = receipt.get("ttl_seconds")
    if (
        not isinstance(ttl, int)
        or isinstance(ttl, bool)
        or not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS
        or expires <= created
        or (expires - created).total_seconds() > ttl + 2
        or now.tzinfo is None
        or now.astimezone(timezone.utc) >= expires
    ):
        raise DNSTransactionError("PUBLIC_READINESS_EXPIRED")
    if receipt.get("dr_state_observed") not in {"IDLE", "FAILED"}:
        raise DNSTransactionError("PUBLIC_READINESS_DR_STATE_UNSAFE")
    return receipt, token


def validate_request(args: argparse.Namespace, env: Mapping[str, str]) -> None:
    for variable, code in (
        ("DUMP_DB_DNS_TRANSACTION_ENABLED", "DUMP_DNS_TRANSACTION_NOT_EXPLICITLY_ENABLED"),
        ("DUMP_DB_PUBLIC_READINESS_ENABLED", "DUMP_PUBLIC_READINESS_NOT_ENABLED"),
        ("DUMP_DB_READONLY_HEALTH_ENABLED", "DUMP_READONLY_HEALTH_NOT_ENABLED"),
        ("DUMP_DB_DNS_PREFLIGHT_ENABLED", "DUMP_DNS_PREFLIGHT_NOT_ENABLED"),
    ):
        if env.get(variable, "false").strip().lower() != "true":
            raise DNSTransactionError(code)
    if env.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise DNSTransactionError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if env.get("DR_WORKFLOW_LOCK_HELD") != "1" or env.get("DR_FAILOVER_LOCK_HELD") != "1":
        raise DNSTransactionError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise DNSTransactionError("DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise DNSTransactionError("DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if not args.confirm_dns_transaction:
        raise DNSTransactionError("EXPLICIT_DUMP_DNS_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise DNSTransactionError("AWS_REGION_NOT_APPROVED")
    if not INSTANCE_RE.fullmatch(args.instance_id) or args.instance_id == PRODUCTION_DB_INSTANCE_ID:
        raise DNSTransactionError("ISOLATED_INSTANCE_ID_INVALID")
    if (
        not VOLUME_RE.fullmatch(args.data_volume_id)
        or not VOLUME_RE.fullmatch(args.stage_volume_id)
        or args.data_volume_id == args.stage_volume_id
        or not SG_RE.fullmatch(args.service_security_group_id)
    ):
        raise DNSTransactionError("ISOLATED_RESOURCE_IDENTITY_INVALID")
    if args.private_ip in EXPECTED_PRODUCTION_DB_PRIVATE_IPS:
        raise DNSTransactionError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    try:
        isolated_ip = ipaddress.ip_address(args.private_ip)
        dr_eip = ipaddress.IPv4Address(args.dr_web_eip)
    except ValueError as exc:
        raise DNSTransactionError("DNS_TARGET_ADDRESS_INVALID") from exc
    if (
        not isinstance(isolated_ip, ipaddress.IPv4Address)
        or not isolated_ip.is_private
        or isolated_ip not in ipaddress.ip_network("IP_REDACTED/24")
        or not dr_eip.is_global
        or str(dr_eip) != str(args.dr_web_eip)
    ):
        raise DNSTransactionError("DNS_TARGET_ADDRESS_INVALID")
    if not SHA256_RE.fullmatch(args.expected_sha256):
        raise DNSTransactionError("EXPECTED_CHECKSUM_INVALID")
    if not BACKUP_RE.fullmatch(Path(args.backup).name):
        raise DNSTransactionError("BACKUP_ID_INVALID")
    for value, code in (
        (args.request_id, "REQUEST_ID_INVALID"),
        (args.promotion_id, "PROMOTION_ID_INVALID"),
        (args.cutover_id, "CUTOVER_ID_INVALID"),
    ):
        _uuid(value, code)
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", args.web_domain) or not re.fullmatch(
        r"[A-Za-z0-9.-]{1,253}", args.emr_domain
    ):
        raise DNSTransactionError("PUBLIC_HEALTH_HOST_INVALID")
    if args.web_domain.lower() == args.emr_domain.lower():
        raise DNSTransactionError("PUBLIC_HEALTH_HOST_COLLISION")
    if not 1 <= int(args.health_attempts) <= 12 or not 1 <= int(args.health_interval_seconds) <= 60:
        raise DNSTransactionError("PUBLIC_HEALTH_RETRY_POLICY_INVALID")
    if not args.zone_id or not re.fullmatch(r"[0-9a-fA-F]{32}", args.zone_id):
        raise DNSTransactionError("CLOUDFLARE_ZONE_ID_INVALID")
    for value in (args.web_record_id, args.emr_record_id):
        if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
            raise DNSTransactionError("CLOUDFLARE_RECORD_ID_INVALID")
    if args.web_record_id == args.emr_record_id:
        raise DNSTransactionError("CLOUDFLARE_RECORD_ID_COLLISION")
    if not args.onprem_tunnel_host or not args.onprem_emr_ip:
        raise DNSTransactionError("APPROVED_ORIGIN_CONFIGURATION_MISSING")
    for path, code in (
        (Path(args.backup), "BACKUP_ARTIFACT_UNAVAILABLE"),
        (Path(args.inventory), "ANSIBLE_INVENTORY_UNAVAILABLE"),
        (Path(args.ssh_key), "SSH_KEY_UNAVAILABLE"),
        (Path(args.ssh_config), "SSH_TRANSPORT_CONFIG_UNAVAILABLE"),
        (Path(args.known_hosts), "SSH_KNOWN_HOSTS_UNAVAILABLE"),
        (Path(args.origin_snapshot_dir), "APPROVED_ORIGIN_SNAPSHOT_UNAVAILABLE"),
    ):
        if path.is_symlink() or not path.exists() or not os.access(path, os.R_OK):
            raise DNSTransactionError(code)
    if not env.get("CLOUDFLARE_API_TOKEN"):
        raise DNSTransactionError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")


def validate_inherited_dr_locks(environment: Mapping[str, str] | None = None) -> None:
    """Require the wrapper's inherited descriptors to refer to busy shared locks."""
    try:
        _validate_inherited_dr_locks(environment)
    except LockContractError as exc:
        raise DNSTransactionError(str(exc)) from exc


def validate_approved_chatops_request(
    database: Path,
    args: argparse.Namespace,
    *,
    now: datetime,
    owner_uid: int | None = None,
) -> dict:
    """Read-only authorization check binding approval, Dump ID, and checksum."""
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    if now.tzinfo is None:
        raise DNSTransactionError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    try:
        metadata = database.lstat()
    except OSError as exc:
        raise DNSTransactionError("CHATOPS_APPROVAL_STATE_UNAVAILABLE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise DNSTransactionError("CHATOPS_APPROVAL_STATE_PERMISSIONS_INVALID")

    uri = database.absolute().as_uri() + "?mode=ro"
    timestamp = now.astimezone(timezone.utc).timestamp()
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            other_executing = connection.execute(
                "SELECT request_id FROM approval_requests "
                "WHERE status = 'EXECUTING' AND request_id != ? LIMIT 1",
                (args.request_id,),
            ).fetchone()
            if row is None:
                raise DNSTransactionError("CHATOPS_APPROVED_REQUEST_NOT_FOUND")
            try:
                incidents = json.loads(row["incidents"])
                approvers = json.loads(row["approvers"])
                approval_required = int(row["approval_required"])
                execution_lease_until = float(row["execution_lease_until"])
                execution_started_at = float(row["execution_started_at"])
                execution_id = str(row["execution_id"] or "")
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise DNSTransactionError("CHATOPS_APPROVAL_STATE_INVALID") from exc
            if (
                row["action"] != "failover"
                or row["status"] != "EXECUTING"
                or row["slack_client_key"] not in {"failover", "emergency"}
                or other_executing is not None
                or not isinstance(incidents, list)
                or not incidents
                or not isinstance(approvers, list)
                or not all(isinstance(item, str) and item.strip() for item in approvers)
                or len(approvers) != len(set(approvers))
                or approval_required not in {1, 2}
                or len(approvers) < approval_required
                or not math.isfinite(execution_lease_until)
                or execution_lease_until <= timestamp
                or not math.isfinite(execution_started_at)
                or execution_started_at > timestamp
                or not UUID_RE.fullmatch(execution_id)
            ):
                raise DNSTransactionError("CHATOPS_APPROVAL_NOT_CURRENT_OR_GLOBAL_LOCKED")
            if approval_required == 1:
                try:
                    mode_expiry = float(row["approval_mode_expires_at"])
                except (TypeError, ValueError) as exc:
                    raise DNSTransactionError("CHATOPS_SINGLE_APPROVAL_MODE_EXPIRED") from exc
                if not math.isfinite(mode_expiry) or mode_expiry <= timestamp:
                    raise DNSTransactionError("CHATOPS_SINGLE_APPROVAL_MODE_EXPIRED")
            latest = incidents[-1]
            conditional_fallback = bool(getattr(args, "allow_conditional_failover_fallback", False))
            if not isinstance(latest, dict):
                raise DNSTransactionError("CHATOPS_DUMP_APPROVAL_IDENTITY_MISMATCH")
            if conditional_fallback:
                request_type = str(latest.get("request_type") or "")
                origin = str(latest.get("request_origin") or "GENERAL").upper()
                source = str(latest.get("source") or "")
                client_key = str(row["slack_client_key"] or "")
                plan = latest.get("failover_recovery_plan")
                candidate = plan.get("dump") if isinstance(plan, dict) else None
                grant = latest.get("existing_dr_overwrite_authorization")
                target = {
                    "instance_id": "AWS_RESOURCE_ID_REDACTED",
                    "private_ip": "IP_REDACTED",
                    "port": 3306,
                    "database": "hospital_db",
                }
                normal_source = (
                    request_type == "NORMAL_FAILOVER"
                    and client_key == "failover"
                    and (
                        (origin in {"GENERAL", ""} and source in {"", "manual", "zabbix"})
                        or (
                            origin == "CLOUD_SLACK_DR_TRIGGER"
                            and source == "zabbix"
                            and latest.get("production_action_verified") is True
                        )
                    )
                )
                emergency_source = (
                    request_type == "EMERGENCY_FAILOVER"
                    and origin == "EMERGENCY"
                    and client_key == "emergency"
                    and source == "emergency_console"
                )
                if (
                    not (normal_source or emergency_source)
                    or approval_required != 2
                    or len(approvers) != 2
                    or not isinstance(plan, dict)
                    or plan.get("version") != 1
                    or plan.get("policy") != "NR_FIRST_DUMP_FALLBACK"
                    or plan.get("target") != target
                    or plan.get("overwrite_scope") != "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB"
                    or not isinstance(candidate, dict)
                    or candidate.get("status") != "READY"
                    or candidate.get("backup_id") != Path(args.backup).name
                    or str(candidate.get("sha256") or "").lower() != args.expected_sha256.lower()
                    or not isinstance(grant, dict)
                    or grant.get("grant_kind") != "CONDITIONAL_DUMP_FALLBACK"
                    or grant.get("status") != "APPROVED_BY_TWO_DISTINCT_ADMINS"
                    or grant.get("request_id") != args.request_id
                    or grant.get("target") != target
                    or grant.get("backup_id") != candidate.get("backup_id")
                    or str(grant.get("sha256") or "").lower() != str(candidate.get("sha256") or "").lower()
                    or str(grant.get("sidecar_sha256") or "").lower() != str(candidate.get("sidecar_sha256") or "").lower()
                    or grant.get("master_status") != candidate.get("master_status")
                    or grant.get("request_type") != request_type
                    or grant.get("request_origin") != origin
                    or grant.get("request_source") != source
                    or grant.get("slack_client_key") != client_key
                    or not re.fullmatch(r"[0-9a-f]{64}", str(grant.get("sidecar_sha256") or ""))
                ):
                    raise DNSTransactionError("CHATOPS_CONDITIONAL_DUMP_FALLBACK_NOT_APPROVED")
                result = {
                    "request_id": args.request_id,
                    "execution_id": execution_id,
                    "approval_required": approval_required,
                    "approval_count": len(approvers),
                    "approver_ids": list(approvers),
                    "backup_id": candidate["backup_id"],
                    "sha256": str(candidate["sha256"]).lower(),
                    "sidecar_sha256": str(candidate["sidecar_sha256"]).lower(),
                    "recovery_plan": plan,
                    "request_type": request_type,
                    "request_origin": origin,
                    "request_source": source,
                    "slack_client_key": client_key,
                    "production_action_verified": latest.get("production_action_verified") is True,
                    "overwrite_authorization": grant,
                }
                return result
            if (
                latest.get("request_type") != "DUMP_RESTORE_FAILOVER"
                or latest.get("slack_client_key", row["slack_client_key"])
                != row["slack_client_key"]
                or (
                    row["slack_client_key"] == "emergency"
                    and str(latest.get("request_origin", "")).upper() != "EMERGENCY"
                )
                or (
                    row["slack_client_key"] == "failover"
                    and str(latest.get("request_origin", "GENERAL")).upper() != "GENERAL"
                )
                or latest.get("backup_id") != Path(args.backup).name
                or str(latest.get("backup_checksum", "")).lower() != args.expected_sha256.lower()
            ):
                raise DNSTransactionError("CHATOPS_DUMP_APPROVAL_IDENTITY_MISMATCH")
            return {
                "request_id": args.request_id,
                "execution_id": execution_id,
                "approval_required": approval_required,
                "approval_count": len(approvers),
                "approver_ids": list(approvers),
                "backup_id": latest["backup_id"],
                "sha256": str(latest["backup_checksum"]).lower(),
            }
    except DNSTransactionError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise DNSTransactionError("CHATOPS_APPROVAL_STATE_UNAVAILABLE") from exc


def _validate_record_snapshot(path: Path, *, owner_uid: int) -> dict:
    return _read_private_json(path, owner_uid=owner_uid, code="DNS_TRANSACTION_SNAPSHOT_INVALID")


def _snapshot_matches_origin(snapshot: dict, origin: dict) -> bool:
    if snapshot.get("id") != origin.get("id"):
        return False
    actual = snapshot.get("payload")
    expected = origin.get("payload")
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        return False
    return all(actual.get(key) == expected.get(key) for key in ("type", "name", "content", "ttl", "proxied"))


def _record_matches_payload(record: dict, record_id: str, expected: dict) -> bool:
    return record.get("id") == record_id and all(record.get(key) == value for key, value in expected.items())


class DNSHelperClient:
    """Invoke only the existing DNS helper functions; credentials stay in env."""

    def __init__(self, *, zone_id: str, token: str, runner: Callable = subprocess.run,
                 helper: Path = DNS_HELPER):
        self.zone_id = zone_id
        self.token = token
        self.runner = runner
        self.helper = helper

    def _call(self, function: str, *arguments: str) -> str:
        script = 'source "$1"; shift; ' + function + ' "$@"'
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "CF_ZONE_ID": self.zone_id,
            "CLOUDFLARE_API_TOKEN": self.token,
        }
        command = [
            "timeout", "--signal=TERM", "--kill-after=2", f"{DNS_API_TIMEOUT_SECONDS}s",
            "bash", "-c", script, "dump-dns-helper", str(self.helper), *map(str, arguments),
        ]
        try:
            result = self.runner(command, capture_output=True, text=True, check=False, env=env)
        except OSError as exc:
            raise DNSTransactionError("CLOUDFLARE_DNS_HELPER_UNAVAILABLE") from exc
        if result.returncode != 0:
            raise DNSTransactionError("CLOUDFLARE_DNS_HELPER_OPERATION_FAILED")
        return result.stdout.strip()

    def snapshot(self, record_name: str, path: Path, record_id: str) -> str:
        return self._call("dr_dns_snapshot_record", record_name, str(path), record_id)

    def payload(self, record_name: str, dr_ip: str) -> dict:
        raw = self._call("dr_dns_payload", "A", record_name, dr_ip)
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise DNSTransactionError("DR_DNS_PAYLOAD_INVALID") from exc
        expected = {"type": "A", "name": record_name, "content": dr_ip, "ttl": 1, "proxied": True}
        if payload != expected:
            raise DNSTransactionError("DR_DNS_PAYLOAD_INVALID")
        return payload

    def update(self, record_id: str, payload: dict, label: str) -> None:
        self._call("dr_dns_update_record", record_id, json.dumps(payload, separators=(",", ":")), label)

    def rollback(self, snapshot_dir: Path) -> bool:
        try:
            self._call("dr_dns_rollback_snapshots", str(snapshot_dir))
            return True
        except DNSTransactionError:
            return False


def _cloudflare_resolved_ipv4(host: str) -> tuple[str, ...]:
    try:
        rows = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        raise DNSTransactionError("PUBLIC_DNS_RESOLUTION_FAILED") from exc
    addresses = tuple(sorted({row[4][0] for row in rows}))
    if not addresses:
        raise DNSTransactionError("PUBLIC_DNS_RESOLUTION_FAILED")
    return addresses


def _is_cloudflare_edge(addresses: tuple[str, ...], cidrs: tuple[str, ...]) -> bool:
    networks = tuple(ipaddress.ip_network(item) for item in cidrs)
    try:
        parsed = tuple(ipaddress.IPv4Address(value) for value in addresses)
    except ValueError:
        return False
    return bool(parsed) and all(any(address in network for network in networks) for address in parsed)


def check_public_health(
    *, host: str, token: str, cloudflare_ipv4_cidrs: tuple[str, ...], attempts: int,
    interval_seconds: int, resolver: Callable = _cloudflare_resolved_ipv4,
    transport: Callable | None = None, sleep: Callable = time.sleep,
) -> dict:
    """Pin the request to a resolved Cloudflare IPv4 edge and verify TLS/204."""
    if transport is None:
        transport = _pinned_https_get
    last_reason = "PUBLIC_HEALTH_UNAVAILABLE"
    for attempt in range(1, attempts + 1):
        try:
            addresses = resolver(host)
            if not _is_cloudflare_edge(addresses, cloudflare_ipv4_cidrs):
                raise DNSTransactionError("PUBLIC_DNS_NOT_CLOUDFLARE")
            edge_ip = addresses[(attempt - 1) % len(addresses)]
            status, headers, body_prefix = transport(
                host=host,
                address=edge_ip,
                path="/__hospital_dr/health",
                headers={
                    "X-Hospital-DR-Probe": token,
                    "Accept": "*/*",
                    "Cache-Control": "no-cache",
                    "User-Agent": "Hospital-DR-Dump-Health/1",
                },
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            ray = headers.get("CF-Ray", "") if headers is not None else ""
            server = headers.get("Server", "") if headers is not None else ""
            cache_control = headers.get("Cache-Control", "") if headers is not None else ""
            if (
                status != 204
                or not CF_RAY_RE.fullmatch(str(ray).strip())
                or str(server).strip().lower() != "cloudflare"
                or "no-store" not in str(cache_control).lower()
                or (headers.get("Set-Cookie") if headers is not None else None) is not None
                or body_prefix != b""
            ):
                raise DNSTransactionError("PUBLIC_HEALTH_RESPONSE_INVALID")
            return {"host": host, "status": 204, "cloudflare_edge": True, "tls_verified": True}
        except DNSTransactionError as exc:
            last_reason = str(exc)
        except (OSError, TimeoutError, ssl.SSLError, ValueError, http.client.HTTPException):
            last_reason = "PUBLIC_HEALTH_TRANSPORT_FAILED"
        if attempt < attempts:
            sleep(interval_seconds)
    raise DNSTransactionError(last_reason)


def _pinned_https_get(
    *, host: str, address: str, path: str, headers: Mapping[str, str], timeout: int
) -> tuple[int, object, bytes]:
    """HTTPS to the validated edge IP while retaining hostname SNI/cert checks."""
    context = ssl.create_default_context()

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((address, self.port), self.timeout)
            self.sock = context.wrap_socket(raw, server_hostname=host)

    connection = PinnedHTTPSConnection(host, 443, timeout=timeout, context=context)
    try:
        connection.request("GET", path, headers=dict(headers))
        response = connection.getresponse()
        return response.status, response.headers, response.read(1)
    finally:
        connection.close()


def _secure_state_dir(path: Path, *, owner_uid: int) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise DNSTransactionError("DNS_TRANSACTION_STATE_DIR_INVALID")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise DNSTransactionError("DNS_TRANSACTION_STATE_DIR_PERMISSIONS_INVALID")


def _atomic_json(path: Path, value: dict, *, owner_uid: int) -> None:
    fd = -1
    temporary: Path | None = None
    try:
        fd, raw_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(raw_path)
        os.fchmod(fd, 0o600)
        if hasattr(os, "fchown"):
            os.fchown(fd, owner_uid, -1)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise DNSTransactionError("DNS_TRANSACTION_RECEIPT_WRITE_FAILED") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _write_receipt(path: Path, receipt: dict, *, owner_uid: int) -> None:
    if path.exists() or path.is_symlink():
        _atomic_json(path, receipt, owner_uid=owner_uid)
    else:
        # Initial state is exclusive to prevent reusing a cutover id.
        payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
            if hasattr(os, "fchown"):
                os.fchown(fd, owner_uid, -1)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise DNSTransactionError("DNS_TRANSACTION_RECEIPT_WRITE_FAILED") from exc


def _append_operation_log(path: Path, message: str, *, owner_uid: int) -> None:
    """Append a bounded, non-secret controller event to its request-scoped log."""
    if len(message) > 1024 or "\n" in message or "\r" in message:
        raise DNSTransactionError("DNS_TRANSACTION_LOG_EVENT_INVALID")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise DNSTransactionError("DNS_TRANSACTION_LOG_PERMISSIONS_INVALID")
            payload = (message + "\n").encode("utf-8")
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
    except DNSTransactionError:
        raise
    except OSError as exc:
        raise DNSTransactionError("DNS_TRANSACTION_LOG_WRITE_FAILED") from exc


@contextmanager
def _transaction_lock(path: Path, *, owner_uid: int):
    _secure_state_dir(path.parent, owner_uid=owner_uid)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise DNSTransactionError("DNS_TRANSACTION_LOCK_UNAVAILABLE") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise DNSTransactionError("DNS_TRANSACTION_LOCK_PERMISSIONS_INVALID")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DNSTransactionError("DNS_TRANSACTION_ALREADY_RUNNING") from exc
        yield
    finally:
        os.close(fd)


def _origin_pair(args: argparse.Namespace) -> dict:
    try:
        return dns_preflight.load_origin_pair(
            Path(args.origin_snapshot_dir),
            web_name=args.web_domain,
            emr_name=args.emr_domain,
            tunnel_host=args.onprem_tunnel_host,
            emr_origin_ip=args.onprem_emr_ip,
            dr_eip=args.dr_web_eip,
            web_record_id=args.web_record_id,
            emr_record_id=args.emr_record_id,
        )
    except Exception as exc:
        if isinstance(exc, (dns_preflight.DNSPreflightError, DNSTransactionError)):
            raise
        raise DNSTransactionError("APPROVED_ONPREM_DNS_SNAPSHOT_INVALID") from exc


def _verify_external(
    args: argparse.Namespace, *, env: Mapping[str, str], state_reader: Callable,
    dns_reader: Callable, aws_target_validator: Callable, app_sg_validator: Callable,
    aws_runner: Callable,
) -> dict:
    try:
        cloudflare_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=env)
        management_cidrs = public_readiness.load_management_ipv4_cidrs(env)
        zabbix_cidrs = public_readiness.load_terraform_ipv4_cidrs(
            "zabbix_agent_source_ipv4_cidrs", environment=env
        )
        wg_cidrs = public_readiness.load_terraform_ipv4_cidrs(
            "aws_dr_wg_peer_ingress_ipv4_cidrs", environment=env
        )
        wg_enabled = env.get("TF_VAR_aws_dr_wg_enabled", "false").strip().lower() == "true"
        result = public_readiness._verify_external_inputs(
            args,
            token=env["CLOUDFLARE_API_TOKEN"],
            cloudflare_cidrs=cloudflare_cidrs,
            management_cidrs=management_cidrs,
            zabbix_cidrs=zabbix_cidrs,
            wireguard_peer_cidrs=wg_cidrs,
            wireguard_enabled=wg_enabled,
            state_reader=state_reader,
            dns_reader=dns_reader,
            aws_target_validator=aws_target_validator,
            app_sg_validator=app_sg_validator,
            aws_runner=aws_runner,
        )
        return {**result, "cloudflare_ipv4_cidrs": cloudflare_cidrs}
    except Exception as exc:
        if isinstance(exc, (DNSTransactionError, dns_preflight.DNSPreflightError)):
            raise DNSTransactionError(str(exc)) from exc
        raise DNSTransactionError("DUMP_DNS_PRETRANSACTION_REVALIDATION_FAILED") from exc


def _aws_readonly_runner(source_environment: Mapping[str, str]) -> Callable:
    safe_environment = public_readiness._safe_child_environment(source_environment)

    def run(command, **kwargs):
        kwargs["env"] = safe_environment
        return subprocess.run(command, **kwargs)

    return run


def run_remote_transaction_phase(
    args: argparse.Namespace, phase: str, *,
    cloudflare_ipv4_cidrs: tuple[str, ...], environment: Mapping[str, str],
    expected_binlog: dict | None = None,
    runner: Callable = subprocess.run, tmpfs_root: str = "/dev/shm",
) -> dict:
    if phase not in {"verify-dns-transaction", "verify-dml-fence"} or not PLAYBOOK.is_file():
        raise DNSTransactionError("DNS_TRANSACTION_REMOTE_CHECK_UNAVAILABLE")
    try:
        tmpfs = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", tmpfs_root],
            capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        raise DNSTransactionError("DNS_TRANSACTION_SECRET_TMPFS_UNAVAILABLE") from exc
    if tmpfs.returncode != 0 or tmpfs.stdout.strip() != "tmpfs":
        raise DNSTransactionError("DNS_TRANSACTION_SECRET_TMPFS_UNAVAILABLE")
    marker = "DUMP_DNS_TRANSACTION_REMOTE=PASS" if phase == "verify-dns-transaction" else "DUMP_DNS_TRANSACTION_DML_FENCE=PASS"
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-dump-dns-transaction-", dir=tmpfs_root) as temp:
            root = Path(temp)
            root.chmod(0o700)
            inventory = root / "isolated-inventory.ini"
            ssh_config = root / "isolated-ssh-config"
            variables = root / "transaction-vars.json"
            public_readiness._build_overlay(
                path=inventory,
                ssh_config_path=ssh_config,
                ssh_config=Path(args.ssh_config),
                ssh_key=args.ssh_key,
                known_hosts=str(args.known_hosts),
                private_ip=args.private_ip,
            )
            extra = {
                "dump_dns_transaction_phase": phase,
                "dump_dns_transaction_instance_id": args.instance_id,
                "dump_dns_transaction_private_ip": args.private_ip,
                "dump_dns_transaction_data_volume_id": args.data_volume_id,
                "dump_dns_transaction_stage_volume_id": args.stage_volume_id,
                "dump_dns_transaction_service_sg_id": args.service_security_group_id,
                "dump_dns_transaction_expected_sha256": args.expected_sha256.lower(),
                "dump_dns_transaction_backup_id": Path(args.backup).name,
                "dump_dns_transaction_promotion_id": args.promotion_id,
                "dump_dns_transaction_cutover_id": args.cutover_id,
                "dump_dns_transaction_cloudflare_ipv4_cidrs": list(cloudflare_ipv4_cidrs),
                "dump_dns_transaction_expected_binlog_file": (
                    expected_binlog.get("file", "") if expected_binlog else ""
                ),
                "dump_dns_transaction_expected_binlog_position": (
                    expected_binlog.get("position", 0) if expected_binlog else 0
                ),
                "dump_dns_transaction_db_cli_sha256": hashlib.sha256(REMOTE_DB_CLI.read_bytes()).hexdigest(),
                "dump_dns_transaction_db_helper_sha256": hashlib.sha256(REMOTE_DB_HELPER.read_bytes()).hexdigest(),
                "dump_dns_transaction_restore_helper_sha256": hashlib.sha256(REMOTE_RESTORE_HELPER.read_bytes()).hexdigest(),
                "dump_dns_transaction_app_probe_sha256": hashlib.sha256(REMOTE_APP_PROBE.read_bytes()).hexdigest(),
                "dump_dns_transaction_fence_helper_sha256": hashlib.sha256(REMOTE_FENCE_HELPER.read_bytes()).hexdigest(),
                "dump_dns_transaction_expiry_helper_sha256": hashlib.sha256(REMOTE_EXPIRY_HELPER.read_bytes()).hexdigest(),
            }
            public_readiness._write_private(variables, json.dumps(extra, sort_keys=True))
            result = runner(
                [
                    "timeout", "--signal=TERM", "--kill-after=5", "180s",
                    "ansible-playbook", "-i", str(args.inventory), "-i", str(inventory),
                    "-e", f"@{variables}", str(PLAYBOOK),
                ],
                cwd=str(REPO_ROOT / "automation/ansible"),
                env=public_readiness._safe_child_environment(environment),
                capture_output=True, text=True, check=False,
            )
    except OSError as exc:
        raise DNSTransactionError("DNS_TRANSACTION_REMOTE_CHECK_UNAVAILABLE") from exc
    # Ansible output is never relayed: it may include remote diagnostics or vars.
    if result.returncode != 0:
        return {"ok": False}
    match = re.search(
        rf"{re.escape(marker)} binlog_file=([A-Za-z0-9._-]{{1,128}}) binlog_position=([1-9][0-9]{{0,19}})",
        result.stdout,
    )
    if not match:
        return {"ok": False}
    return {
        "ok": True,
        "file": match.group(1),
        "position": int(match.group(2)),
    }


def _dns_payload_for_snapshot(snapshot_path: Path, *, owner_uid: int) -> tuple[str, dict]:
    record = _validate_record_snapshot(snapshot_path, owner_uid=owner_uid)
    payload = record.get("payload")
    if not isinstance(payload, dict) or any(
        key not in payload for key in ("type", "name", "content", "ttl", "proxied")
    ):
        raise DNSTransactionError("DNS_TRANSACTION_SNAPSHOT_INVALID")
    return str(record.get("id", "")), payload


def _make_operation_receipt(args: argparse.Namespace, *, now: datetime) -> dict:
    return {
        "status": "DUMP_DNS_TRANSACTION_IN_PROGRESS",
        "request_id": args.request_id,
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "web_record_id": args.web_record_id,
        "emr_record_id": args.emr_record_id,
        "target_eip": args.dr_web_eip,
        "maintenance_mode": True,
        "application_dml_allowed": False,
        "dr_active_recorded": False,
        "dns_change_authorized": False,
        "phase": "PREPARING_SNAPSHOTS",
        "changed_records": [],
        "started_at_utc": now.astimezone(timezone.utc).isoformat(),
    }


def _emit(logger: Callable[[str], None], request_id: str, phase: str, result: str) -> None:
    logger(f"DUMP_DNS_TRANSACTION request_id={request_id} phase={phase} result={result}")


def _verified_binlog(result: object, expected: dict | None = None) -> dict | None:
    if not isinstance(result, dict) or result.get("ok") is not True:
        return None
    filename = result.get("file")
    position = result.get("position")
    if (
        not isinstance(filename, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", filename)
        or not isinstance(position, int)
        or isinstance(position, bool)
        or position < 1
    ):
        return None
    current = {"file": filename, "position": position}
    return current if expected is None or current == expected else None


def execute_dns_transaction(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    backup_validator: Callable = validate_backup_pair,
    state_reader: Callable = dns_preflight.read_dr_state,
    dns_reader: Callable = dns_preflight.cloudflare_get_record,
    aws_target_validator: Callable = validate_aws_isolated_target,
    app_sg_validator: Callable = public_readiness.read_and_validate_app_security_groups,
    phase_runner: Callable | None = None,
    public_health_checker: Callable = check_public_health,
    snapshotter: Callable | None = None,
    updater: Callable | None = None,
    readback_verifier: Callable | None = None,
    rollbacker: Callable | None = None,
    clock: Callable = lambda: datetime.now(timezone.utc),
    aws_runner: Callable | None = None,
    lock_validator: Callable = validate_inherited_dr_locks,
    approval_validator: Callable = validate_approved_chatops_request,
    owner_uid: int | None = None,
    logger: Callable[[str], None] = print,
) -> dict:
    env = environment if environment is not None else os.environ
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    aws_runner = aws_runner or _aws_readonly_runner(env)
    validate_request(args, env)
    lock_validator(env)
    if not DNS_HELPER.is_file():
        raise DNSTransactionError("CANONICAL_DNS_TRANSACTION_HELPER_MISSING")
    try:
        backup = backup_validator(Path(args.backup), args.expected_sha256)
    except Exception as exc:
        raise DNSTransactionError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID") from exc
    if not isinstance(backup, dict) or str(backup.get("sha256", "")).lower() != args.expected_sha256.lower():
        raise DNSTransactionError("BACKUP_CHECKSUM_MISMATCH")

    now = clock()
    if now.tzinfo is None:
        raise DNSTransactionError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    readiness, probe_token = _load_ready_capability(args=args, now=now, owner_uid=owner_uid)
    origin = _origin_pair(args)
    current_state = state_reader(Path(args.state_file))
    if current_state != readiness.get("dr_state_observed"):
        raise DNSTransactionError("DR_STATE_CHANGED_SINCE_PUBLIC_READINESS")
    cloudflare_token = env.get("CLOUDFLARE_API_TOKEN", "")
    if not cloudflare_token:
        raise DNSTransactionError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")
    if phase_runner is None:
        phase_runner = lambda phase, **kwargs: run_remote_transaction_phase(
            args, phase,
            cloudflare_ipv4_cidrs=kwargs["cloudflare_ipv4_cidrs"],
            expected_binlog=kwargs.get("expected_binlog"),
            environment=env,
        )
    cloudflare_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=env)
    helper = DNSHelperClient(zone_id=args.zone_id, token=cloudflare_token)
    snapshotter = snapshotter or helper.snapshot
    updater = updater or helper.update
    rollbacker = rollbacker or helper.rollback
    if readback_verifier is None:
        readback_verifier = lambda rec_id: dns_reader(
            zone_id=args.zone_id, record_id=rec_id, token=cloudflare_token
        )

    lock_path = Path(args.transaction_lock_file)
    with _transaction_lock(lock_path, owner_uid=owner_uid):
        approved_request = approval_validator(
            args.chatops_state_db, args, now=clock(), owner_uid=owner_uid
        )

        def revalidate_approval() -> None:
            current_approval = approval_validator(
                args.chatops_state_db, args, now=clock(), owner_uid=owner_uid
            )
            if (
                current_approval.get("execution_id") != approved_request.get("execution_id")
                or current_approval.get("backup_id") != Path(args.backup).name
                or current_approval.get("sha256") != args.expected_sha256.lower()
            ):
                raise DNSTransactionError("CHATOPS_APPROVAL_CHANGED_DURING_DNS_TRANSACTION")

        revalidate_approval()
        external = _verify_external(
            args, env=env, state_reader=state_reader, dns_reader=dns_reader,
            aws_target_validator=aws_target_validator, app_sg_validator=app_sg_validator,
            aws_runner=aws_runner,
        )
        if external["dr_state"] != current_state:
            raise DNSTransactionError("DR_STATE_CHANGED_BEFORE_DNS_TRANSACTION")
        remote_initial = phase_runner(
            "verify-dns-transaction",
            cloudflare_ipv4_cidrs=cloudflare_cidrs,
            expected_binlog=None,
        )
        binlog_baseline = _verified_binlog(remote_initial)
        if binlog_baseline is None:
            raise DNSTransactionError("DUMP_PREPARED_STATE_OR_WRITE_FENCE_INVALID")
        readiness, probe_token = _load_ready_capability(args=args, now=clock(), owner_uid=owner_uid)
        if hashlib.sha256(probe_token.encode("ascii")).hexdigest() != readiness.get("probe_token_sha256"):
            raise DNSTransactionError("PUBLIC_READINESS_PROBE_TOKEN_CHANGED")

        state_root = Path(args.transaction_state_dir)
        _secure_state_dir(state_root, owner_uid=owner_uid)
        operation_dir = state_root / args.cutover_id
        try:
            operation_dir.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise DNSTransactionError("DNS_TRANSACTION_ALREADY_RECORDED") from exc
        except OSError as exc:
            raise DNSTransactionError("DNS_TRANSACTION_STATE_DIR_CREATE_FAILED") from exc
        metadata = operation_dir.stat()
        if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise DNSTransactionError("DNS_TRANSACTION_STATE_DIR_PERMISSIONS_INVALID")
        snapshot_dir = operation_dir / "snapshot"
        snapshot_dir.mkdir(mode=0o700)
        receipt_path = operation_dir / "transaction.json"
        operation_log_path = operation_dir / f"{args.request_id}.log"

        def operation_logger(message: str) -> None:
            _append_operation_log(operation_log_path, message, owner_uid=owner_uid)
            logger(message)

        receipt = _make_operation_receipt(args, now=clock())
        receipt["mysql_binlog_baseline"] = binlog_baseline
        receipt["execution_log_path"] = str(operation_log_path)
        receipt["chatops_approval"] = {
            "execution_id": approved_request["execution_id"],
            "approval_required": approved_request["approval_required"],
            "approval_count": approved_request["approval_count"],
        }
        _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
        _emit(operation_logger, args.request_id, "snapshot", "STARTED")

        mutation_attempted = False
        try:
            origin_dns = external["dns"]["snapshot"]
            snapshots = {}
            for alias, record_id, domain in (
                ("web", args.web_record_id, args.web_domain),
                ("emr", args.emr_record_id, args.emr_domain),
            ):
                path = snapshot_dir / f"{alias}.json"
                returned_id = snapshotter(domain, path, record_id)
                snap = _validate_record_snapshot(path, owner_uid=owner_uid)
                if returned_id != record_id or not _snapshot_matches_origin(snap, origin_dns[alias]):
                    raise DNSTransactionError("DNS_ORIGIN_SNAPSHOT_MISMATCH")
                snapshots[alias] = snap
            receipt["phase"] = "SNAPSHOTS_VERIFIED"
            receipt["snapshots"] = {
                alias: {
                    "record_id": snapshots[alias]["id"],
                    "type": snapshots[alias]["payload"]["type"],
                    "name": snapshots[alias]["payload"]["name"],
                    "content": snapshots[alias]["payload"]["content"],
                    "proxied": snapshots[alias]["payload"]["proxied"],
                }
                for alias in snapshots
            }
            _write_receipt(receipt_path, receipt, owner_uid=owner_uid)

            # Catch intervening manual DNS/state changes after snapshots.
            fresh = _verify_external(
                args, env=env, state_reader=state_reader, dns_reader=dns_reader,
                aws_target_validator=aws_target_validator, app_sg_validator=app_sg_validator,
                aws_runner=aws_runner,
            )
            if fresh["dr_state"] != current_state or fresh["dns"]["current"] != external["dns"]["current"]:
                raise DNSTransactionError("DNS_OR_DR_STATE_CHANGED_AFTER_SNAPSHOT")
            revalidate_approval()
            readiness, probe_token = _load_ready_capability(args=args, now=clock(), owner_uid=owner_uid)
            remote_after_snapshot = phase_runner(
                "verify-dns-transaction",
                cloudflare_ipv4_cidrs=cloudflare_cidrs,
                expected_binlog=binlog_baseline,
            )
            if _verified_binlog(remote_after_snapshot, binlog_baseline) is None:
                raise DNSTransactionError("DUMP_PREPARED_STATE_OR_WRITE_FENCE_EXPIRED")

            desired = {
                "web": helper.payload(args.web_domain, args.dr_web_eip),
                "emr": helper.payload(args.emr_domain, args.dr_web_eip),
            }
            receipt["phase"] = "DNS_PUTS_IN_PROGRESS"
            receipt["target_records"] = desired
            _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
            _emit(operation_logger, args.request_id, "dns-update", "STARTED")
            updated_aliases: set[str] = set()
            for alias, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
                revalidate_approval()
                readiness, probe_token = _load_ready_capability(
                    args=args, now=clock(), owner_uid=owner_uid
                )
                if state_reader(Path(args.state_file)) != current_state:
                    raise DNSTransactionError("DR_STATE_CHANGED_DURING_DNS_TRANSACTION")
                remote_before_put = phase_runner(
                    "verify-dns-transaction",
                    cloudflare_ipv4_cidrs=cloudflare_cidrs,
                    expected_binlog=binlog_baseline,
                )
                if _verified_binlog(remote_before_put, binlog_baseline) is None:
                    raise DNSTransactionError("DUMP_PREPARED_STATE_OR_WRITE_FENCE_EXPIRED")
                for check_alias, check_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
                    observed = readback_verifier(check_id)
                    expected_before = desired[check_alias] if check_alias in updated_aliases else snapshots[check_alias]["payload"]
                    if not _record_matches_payload(observed, check_id, expected_before):
                        raise DNSTransactionError("CLOUDFLARE_DNS_CHANGED_DURING_TRANSACTION")
                # Recheck approval and short-lived readiness immediately before
                # a Cloudflare mutation, after all network/readback work.
                revalidate_approval()
                readiness, probe_token = _load_ready_capability(
                    args=args, now=clock(), owner_uid=owner_uid
                )
                # Mark attempted before the helper call: a timed-out PUT may
                # have reached Cloudflare even if its response was lost.
                mutation_attempted = True
                updater(record_id, desired[alias], f"dump-cutover:{alias}")
                receipt["changed_records"].append(alias)
                receipt["phase"] = f"{alias.upper()}_UPDATED_AND_READBACK_VERIFIED"
                _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
                updated_aliases.add(alias)
            for alias, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
                actual = readback_verifier(record_id)
                if not _record_matches_payload(actual, record_id, desired[alias]):
                    raise DNSTransactionError("CLOUDFLARE_DNS_PAIR_READBACK_MISMATCH")

            receipt["phase"] = "PUBLIC_HEALTH_CHECK"
            _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
            for host in (args.web_domain, args.emr_domain):
                public_health_checker(
                    host=host,
                    token=probe_token,
                    cloudflare_ipv4_cidrs=cloudflare_cidrs,
                    attempts=args.health_attempts,
                    interval_seconds=args.health_interval_seconds,
                )
                _emit(operation_logger, args.request_id, f"public-health-{host}", "PASS_204_CLOUDFLARE_TLS_VERIFIED")

            if _verified_binlog(
                phase_runner(
                    "verify-dns-transaction",
                    cloudflare_ipv4_cidrs=cloudflare_cidrs,
                    expected_binlog=binlog_baseline,
                ),
                binlog_baseline,
            ) is None:
                raise DNSTransactionError("DUMP_PREPARED_STATE_OR_WRITE_FENCE_EXPIRED")
            if _verified_binlog(
                phase_runner(
                    "verify-dml-fence",
                    cloudflare_ipv4_cidrs=cloudflare_cidrs,
                    expected_binlog=binlog_baseline,
                ),
                binlog_baseline,
            ) is None:
                raise DNSTransactionError("APPLICATION_DML_FENCE_NO_LONGER_VERIFIED")
            revalidate_approval()
            latest, _ = _load_ready_capability(args=args, now=clock(), owner_uid=owner_uid)
            receipt.update({
                "status": SUCCESS_STATUS,
                "phase": "COMPLETE_MAINTENANCE_WRITES_BLOCKED",
                "maintenance_mode": True,
                "application_dml_allowed": False,
                "dns_records_switched": True,
                "public_health": {"web": 204, "emr": 204, "cloudflare_edge_verified": True, "tls_verified": True},
                "write_fence_revalidated": True,
                "readiness_expires_at_utc": latest["expires_at_utc"],
                "dr_active_recorded": False,
                "final_service_open": False,
                "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
            _emit(operation_logger, args.request_id, "complete", SUCCESS_STATUS)
            return receipt
        except Exception as exc:
            candidate_code = str(exc) if isinstance(exc, DNSTransactionError) else ""
            code = (
                candidate_code
                if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", candidate_code)
                else "DNS_TRANSACTION_OPERATION_FAILED"
            )
            if not mutation_attempted:
                receipt.update({
                    "status": "DUMP_DNS_TRANSACTION_FAILED_NO_DNS_CHANGE",
                    "phase": "FAILED_BEFORE_FIRST_PUT",
                    "failure_code": code,
                    "dns_records_switched": False,
                    "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
                })
                _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
                _emit(operation_logger, args.request_id, "failed", code)
                return receipt

            _emit(operation_logger, args.request_id, "rollback-gate", "VERIFYING_DML_FENCE")
            dml_still_blocked = False
            try:
                dml_still_blocked = bool(
                    _verified_binlog(
                        phase_runner(
                            "verify-dml-fence",
                            cloudflare_ipv4_cidrs=cloudflare_cidrs,
                            expected_binlog=binlog_baseline,
                        ),
                        binlog_baseline,
                    )
                )
            except Exception:
                dml_still_blocked = False
            if not dml_still_blocked:
                receipt.update({
                    "status": PARTIAL_STATUS,
                    "phase": "OPERATOR_INTERVENTION_REQUIRED_WRITES_OPEN_OR_UNKNOWN",
                    "failure_code": code,
                    "rollback": "NOT_ATTEMPTED_DML_STATE_UNKNOWN",
                    "dns_records_switched": "UNKNOWN_OR_PARTIAL",
                    "application_dml_allowed": "UNKNOWN",
                    "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
                })
                _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
                _emit(operation_logger, args.request_id, "partial-failure", "DML_STATE_UNKNOWN_NO_AUTOMATIC_ROLLBACK")
                return receipt

            rolled_back = False
            try:
                rolled_back = bool(rollbacker(snapshot_dir))
                if rolled_back:
                    for alias, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
                        actual = readback_verifier(record_id)
                        if not _record_matches_payload(actual, record_id, snapshots[alias]["payload"]):
                            rolled_back = False
                            break
            except Exception:
                # A failed API readback is not proof that rollback succeeded.
                rolled_back = False
            if rolled_back:
                receipt.update({
                    "status": ROLLED_BACK_STATUS,
                    "phase": "ROLLED_BACK_ORIGIN_PAIR_READBACK_VERIFIED",
                    "failure_code": code,
                    "rollback": "SUCCESS_AND_READBACK_VERIFIED",
                    "application_dml_allowed": False,
                    "dns_records_switched": False,
                    "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
                })
                _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
                _emit(operation_logger, args.request_id, "rollback", "PASS_ORIGIN_PAIR_RESTORED")
                return receipt
            receipt.update({
                "status": PARTIAL_STATUS,
                "phase": "ROLLBACK_FAILED_OR_READBACK_UNVERIFIED",
                "failure_code": code,
                "rollback": "FAILED_OR_UNVERIFIED",
                "dns_records_switched": "UNKNOWN_OR_PARTIAL",
                "application_dml_allowed": False,
                "operator_intervention_required": True,
                "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, receipt, owner_uid=owner_uid)
            _emit(operation_logger, args.request_id, "partial-failure", "ROLLBACK_FAILED_OPERATOR_ACTION_REQUIRED")
            return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--service-security-group-id", required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--confirm-dns-transaction", action="store_true")
    parser.add_argument("--inventory", type=Path, default=REPO_ROOT / "automation/ansible/inventory.ini")
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY", ""))
    parser.add_argument("--ssh-config", type=Path, default=Path(os.environ.get("DR_SSH_CONFIG_FILE", "/var/lib/hospital-dr/ssh/config")))
    parser.add_argument("--known-hosts", type=Path, default=Path(os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts")))
    parser.add_argument("--origin-snapshot-dir", type=Path, default=Path(os.environ.get("DR_DNS_ORIGIN_SNAPSHOT_DIR", "/var/lib/hospital-dr/dns/origin")))
    parser.add_argument("--state-file", type=Path, default=Path(os.environ.get("DR_STATE_FILE", "/var/lib/hospital-dr/dr_state")))
    parser.add_argument("--zone-id", default=os.environ.get("CF_ZONE_ID", ""))
    parser.add_argument("--web-record-id", default=os.environ.get("CF_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--emr-record-id", default=os.environ.get("CF_EMR_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--web-domain", default=os.environ.get("DR_DOMAIN", "hospital-web.pp.ua"))
    parser.add_argument("--emr-domain", default=os.environ.get("EMR_DOMAIN", "emr.hospital-web.pp.ua"))
    parser.add_argument("--onprem-tunnel-host", default=os.environ.get("ONPREM_TUNNEL_HOST", ""))
    parser.add_argument("--onprem-emr-ip", default=os.environ.get("ONPREM_EMR_DNS_IP_EXPECTED", ""))
    parser.add_argument("--dr-web-eip", default=os.environ.get("DR_WEB_EIP_EXPECTED", DEFAULT_DR_EIP))
    parser.add_argument("--readiness-state-dir", type=Path, default=Path(os.environ.get("DUMP_DB_PUBLIC_READINESS_STATE_DIR", str(READINESS_ROOT_DEFAULT))))
    parser.add_argument("--transaction-state-dir", type=Path, default=Path(os.environ.get("DUMP_DB_DNS_TRANSACTION_STATE_DIR", str(TRANSACTION_ROOT_DEFAULT))))
    parser.add_argument(
        "--chatops-state-db", type=Path,
        default=Path(os.environ.get("CHATOPS_STATE_DB", str(DEFAULT_CHATOPS_STATE_DB))),
    )
    default_state_dir = Path(os.environ.get("DUMP_DB_DNS_TRANSACTION_STATE_DIR", str(TRANSACTION_ROOT_DEFAULT)))
    parser.add_argument(
        "--transaction-lock-file", type=Path,
        default=Path(os.environ.get("DUMP_DB_DNS_TRANSACTION_LOCK_FILE", str(default_state_dir / ".lock"))),
    )
    parser.add_argument("--health-attempts", type=int, default=int(os.environ.get("DUMP_DB_DNS_HEALTH_ATTEMPTS", "4")))
    parser.add_argument("--health-interval-seconds", type=int, default=int(os.environ.get("DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS", "5")))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_dns_transaction(args)
    except (DNSTransactionError, dns_preflight.DNSPreflightError, PreflightError) as exc:
        print(f"DUMP_DNS_TRANSACTION=BLOCKED request_id={args.request_id} reason={exc}", file=sys.stderr, flush=True)
        return 1
    print(
        "DUMP_DNS_TRANSACTION=" + json.dumps(
            {key: result.get(key) for key in (
                "status", "request_id", "cutover_id", "backup_id", "sha256",
                "dns_records_switched", "maintenance_mode", "application_dml_allowed",
                "dr_active_recorded", "rollback", "failure_code", "operator_intervention_required",
            ) if key in result},
            sort_keys=True, separators=(",", ":"),
        ),
        flush=True,
    )
    return 0 if result.get("status") in {SUCCESS_STATUS, ROLLED_BACK_STATUS} else 1


if __name__ == "__main__":
    raise SystemExit(main())
