#!/usr/bin/env python3
"""Open Dump-only service DML after verified DNS/health, then release maintenance.

This command is deliberately not a ChatOps executor. It requires the existing
two-admin failover execution lease and shared locks, and has no DR-state or DNS
write path except the tightly gated pre-DML snapshot rollback.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from operations.db import dump_db_dns_preflight as dns_preflight
from operations.db import dump_db_dns_transaction as dns_transaction
from operations.db import dump_db_public_readiness as public_readiness
from operations.db.isolated_dump_restore import (
    PRODUCTION_DB_INSTANCE_ID,
    PreflightError,
    validate_aws_isolated_target,
    validate_backup_pair,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_service_open.yml"
REMOTE_DB_HELPER = REPO_ROOT / "operations/db/dump_db_service_open_host.py"
REMOTE_DB_SERVICE_HELPER = REPO_ROOT / "operations/db/isolated_db_service_host.py"
REMOTE_RESTORE_HELPER = REPO_ROOT / "operations/db/isolated_restore_host.py"
REMOTE_APP_PROBE = REPO_ROOT / "operations/db/dump_db_app_fence_probe.py"
REMOTE_APP_WRITE_PROBE = REPO_ROOT / "operations/db/dump_db_service_open_app_probe.js"
REMOTE_FENCE_HELPER = REPO_ROOT / "operations/db/dump_db_external_fence.py"
REMOTE_WEB_HELPER = REPO_ROOT / "operations/db/dump_db_service_open_web.py"
SERVICE_FENCE_UNIT = REPO_ROOT / "operations/db/systemd/hospital-dr-dump-service-fence@.service"

DEFAULT_STATE_ROOT = Path("/var/lib/hospital-dr/dump-service-open")
DEFAULT_TRANSACTION_ROOT = Path("/var/lib/hospital-dr/dump-dns-transactions")
DEFAULT_READINESS_ROOT = Path("/var/lib/hospital-dr/dump-public-readiness")
DEFAULT_APPROVAL_DB = Path("/var/lib/hospital-dr/chatops_state.sqlite3")
DEFAULT_DR_EIP = "AWS_PUBLIC_IP_REDACTED"
WEB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
WEB_PRIVATE_IP = "IP_REDACTED"
EMR_PRIVATE_IP = "IP_REDACTED"
PROTECTED_DB_IPS = {"IP_REDACTED", "IP_REDACTED", "IP_REDACTED", "IP_REDACTED"}
MIN_REMAINING_SECONDS = 120
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
BACKUP_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")

SUCCESS_STATUS = "DUMP_SERVICE_WRITES_OPEN_NOT_DR_ACTIVE"
PRE_DML_ROLLBACK_STATUS = "DUMP_SERVICE_OPEN_FAILED_ROLLED_BACK_WRITES_BLOCKED"
PARTIAL_STATUS = "PARTIAL_FAILURE"


class ServiceOpenError(RuntimeError):
    """Stable, non-secret refusal or operation failure."""


def _uuid(value: str, code: str) -> str:
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ServiceOpenError(code) from exc
    if canonical != value.lower() or not UUID_RE.fullmatch(canonical):
        raise ServiceOpenError(code)
    return canonical


def _parse_utc(value: object, code: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ServiceOpenError(code) from exc
    if result.tzinfo is None:
        raise ServiceOpenError(code)
    return result.astimezone(timezone.utc)


def _read_private_json(path: Path, *, owner_uid: int, code: str) -> dict:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ServiceOpenError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 2 or metadata.st_size > 1024 * 1024
    ):
        raise ServiceOpenError(code)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ServiceOpenError(code) from exc
    if not isinstance(value, dict):
        raise ServiceOpenError(code)
    return value


def _secure_dir(path: Path, *, owner_uid: int) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ServiceOpenError("SERVICE_OPEN_STATE_DIRECTORY_INVALID")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ServiceOpenError("SERVICE_OPEN_STATE_DIRECTORY_PERMISSIONS_INVALID")


@contextmanager
def _operation_lock(path: Path, *, owner_uid: int):
    _secure_dir(path.parent, owner_uid=owner_uid)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise ServiceOpenError("SERVICE_OPEN_LOCK_UNAVAILABLE") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ServiceOpenError("SERVICE_OPEN_LOCK_PERMISSIONS_INVALID")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ServiceOpenError("SERVICE_OPEN_ALREADY_RUNNING") from exc
        yield
    finally:
        os.close(fd)


def _write_receipt(path: Path, value: dict, *, owner_uid: int) -> None:
    if path.exists() or path.is_symlink():
        dns_transaction._atomic_json(path, value, owner_uid=owner_uid)
    else:
        dns_transaction._write_receipt(path, value, owner_uid=owner_uid)


def _emit(log_path: Path, request_id: str, phase: str, result: str, *, owner_uid: int, logger) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_:-]{1,128}", phase) or not re.fullmatch(r"[A-Za-z0-9_:-]{1,128}", result):
        raise ServiceOpenError("SERVICE_OPEN_AUDIT_EVENT_INVALID")
    message = f"DUMP_SERVICE_OPEN request_id={request_id} phase={phase} result={result}"
    dns_transaction._append_operation_log(log_path, message, owner_uid=owner_uid)
    logger(message)


def validate_request(args: argparse.Namespace, env: Mapping[str, str]) -> None:
    for key, code in (
        ("DUMP_DB_SERVICE_OPEN_ENABLED", "DUMP_SERVICE_OPEN_NOT_EXPLICITLY_ENABLED"),
        ("DUMP_DB_SERVICE_CUTOVER_ENABLED", "DB_SERVICE_CUTOVER_NOT_ENABLED"),
        ("DUMP_DB_SERVICE_PROMOTION_ENABLED", "DB_SERVICE_PROMOTION_NOT_ENABLED"),
        ("DUMP_DB_DNS_TRANSACTION_ENABLED", "DUMP_DNS_TRANSACTION_NOT_ENABLED"),
        ("DUMP_DB_PUBLIC_READINESS_ENABLED", "DUMP_PUBLIC_READINESS_NOT_ENABLED"),
        ("DUMP_DB_READONLY_HEALTH_ENABLED", "DUMP_READONLY_HEALTH_NOT_ENABLED"),
        ("DUMP_DB_DNS_PREFLIGHT_ENABLED", "DUMP_DNS_PREFLIGHT_NOT_ENABLED"),
    ):
        if env.get(key, "false").strip().lower() != "true":
            raise ServiceOpenError(code)
    if env.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise ServiceOpenError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise ServiceOpenError("DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise ServiceOpenError("DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if env.get("DR_WORKFLOW_LOCK_HELD") != "1" or env.get("DR_FAILOVER_LOCK_HELD") != "1":
        raise ServiceOpenError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
    if not args.confirm_service_open:
        raise ServiceOpenError("EXPLICIT_SERVICE_WRITE_OPEN_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise ServiceOpenError("AWS_REGION_NOT_APPROVED")
    if (
        not INSTANCE_RE.fullmatch(args.instance_id) or args.instance_id == PRODUCTION_DB_INSTANCE_ID
        or args.private_ip in PROTECTED_DB_IPS
        or not VOLUME_RE.fullmatch(args.data_volume_id) or not VOLUME_RE.fullmatch(args.stage_volume_id)
        or args.data_volume_id == args.stage_volume_id or not SG_RE.fullmatch(args.service_security_group_id)
        or not SHA_RE.fullmatch(args.expected_sha256.lower()) or not BACKUP_RE.fullmatch(Path(args.backup).name)
    ):
        raise ServiceOpenError("ISOLATED_DB_IDENTITY_OR_BACKUP_INVALID")
    try:
        ip = ipaddress.ip_address(args.private_ip)
    except ValueError as exc:
        raise ServiceOpenError("ISOLATED_DB_IP_INVALID") from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private or ip not in ipaddress.ip_network("AWS_PUBLIC_IP_REDACTED/24"):
        raise ServiceOpenError("ISOLATED_DB_IP_INVALID")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", args.zone_id):
        raise ServiceOpenError("CLOUDFLARE_ZONE_ID_INVALID")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", args.web_record_id) or not re.fullmatch(r"[0-9a-fA-F]{32}", args.emr_record_id):
        raise ServiceOpenError("CLOUDFLARE_RECORD_ID_INVALID")
    if args.web_record_id == args.emr_record_id or args.dr_web_eip != DEFAULT_DR_EIP:
        raise ServiceOpenError("APPROVED_DNS_TARGET_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", args.web_domain) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", args.emr_domain):
        raise ServiceOpenError("PUBLIC_DOMAIN_INVALID")
    if not 1 <= args.health_attempts <= 12 or not 1 <= args.health_interval_seconds <= 60:
        raise ServiceOpenError("PUBLIC_HEALTH_RETRY_POLICY_INVALID")
    for field, code in (
        ("request_id", "REQUEST_ID_INVALID"), ("promotion_id", "PROMOTION_ID_INVALID"),
        ("cutover_id", "CUTOVER_ID_INVALID"),
    ):
        _uuid(getattr(args, field), code)
    for field, code in (
        ("backup", "BACKUP_ARTIFACT_UNAVAILABLE"), ("inventory", "ANSIBLE_INVENTORY_UNAVAILABLE"),
        ("ssh_config", "SSH_TRANSPORT_CONFIG_UNAVAILABLE"), ("known_hosts", "SSH_KNOWN_HOSTS_UNAVAILABLE"),
        ("origin_snapshot_dir", "APPROVED_ORIGIN_SNAPSHOT_UNAVAILABLE"),
    ):
        path = Path(getattr(args, field))
        if (
            path.is_symlink()
            or (field != "origin_snapshot_dir" and not path.is_file())
            or not path.exists()
            or not os.access(path, os.R_OK)
        ):
            raise ServiceOpenError(code)
    if Path(args.origin_snapshot_dir).is_symlink() or not Path(args.origin_snapshot_dir).is_dir():
        raise ServiceOpenError("APPROVED_ORIGIN_SNAPSHOT_UNAVAILABLE")
    if not args.ssh_key or Path(args.ssh_key).is_symlink() or not Path(args.ssh_key).is_file() or not os.access(args.ssh_key, os.R_OK):
        raise ServiceOpenError("SSH_KEY_UNAVAILABLE")
    if not env.get("CLOUDFLARE_API_TOKEN"):
        raise ServiceOpenError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")
    if not args.state_file or not Path(args.state_file).is_file() or Path(args.state_file).is_symlink():
        raise ServiceOpenError("DR_STATE_FILE_UNAVAILABLE")


def validate_inherited_locks(env: Mapping[str, str]) -> None:
    try:
        dns_transaction.validate_inherited_dr_locks(env)
    except dns_transaction.DNSTransactionError as exc:
        raise ServiceOpenError(str(exc)) from exc


def _transaction_receipt(args: argparse.Namespace, *, owner_uid: int, now: datetime) -> tuple[dict, Path]:
    directory = Path(args.transaction_state_dir) / _uuid(args.cutover_id, "CUTOVER_ID_INVALID")
    receipt_path = directory / "transaction.json"
    receipt = _read_private_json(receipt_path, owner_uid=owner_uid, code="DNS_TRANSACTION_RECEIPT_INVALID")
    expected = {
        "status": dns_transaction.SUCCESS_STATUS,
        "request_id": _uuid(args.request_id, "REQUEST_ID_INVALID"),
        "promotion_id": _uuid(args.promotion_id, "PROMOTION_ID_INVALID"),
        "cutover_id": _uuid(args.cutover_id, "CUTOVER_ID_INVALID"),
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "target_eip": args.dr_web_eip,
        "maintenance_mode": True,
        "application_dml_allowed": False,
        "dns_records_switched": True,
        "dr_active_recorded": False,
        "final_service_open": False,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ServiceOpenError("DNS_TRANSACTION_RECEIPT_MISMATCH")
    if receipt.get("phase") != "COMPLETE_MAINTENANCE_WRITES_BLOCKED" or receipt.get("write_fence_revalidated") is not True:
        raise ServiceOpenError("DNS_TRANSACTION_NOT_COMPLETE_OR_FENCED")
    if receipt.get("public_health") != {
        "web": 204, "emr": 204, "cloudflare_edge_verified": True, "tls_verified": True,
    }:
        raise ServiceOpenError("DNS_TRANSACTION_PUBLIC_HEALTH_RECEIPT_INVALID")
    completed = _parse_utc(receipt.get("completed_at_utc"), "DNS_TRANSACTION_RECEIPT_TIME_INVALID")
    expiry = _parse_utc(receipt.get("readiness_expires_at_utc"), "PUBLIC_READINESS_EXPIRY_INVALID")
    if completed > now or now >= expiry or (expiry - now).total_seconds() < MIN_REMAINING_SECONDS:
        raise ServiceOpenError("DUMP_SERVICE_PREPARATION_EXPIRED_OR_TOO_CLOSE")
    baseline = receipt.get("mysql_binlog_baseline")
    if (
        not isinstance(baseline, dict)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(baseline.get("file", "")))
        or not isinstance(baseline.get("position"), int)
        or isinstance(baseline.get("position"), bool)
        or baseline.get("position", 0) < 1
    ):
        raise ServiceOpenError("DNS_TRANSACTION_WRITE_BASELINE_INVALID")
    snapshot_dir = directory / "snapshot"
    snapshots = receipt.get("snapshots")
    if not isinstance(snapshots, dict) or set(snapshots) != {"web", "emr"}:
        raise ServiceOpenError("DNS_TRANSACTION_SNAPSHOT_MISMATCH")
    for alias, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
        snap = dns_transaction._validate_record_snapshot(snapshot_dir / f"{alias}.json", owner_uid=owner_uid)
        compact = {
            "record_id": snap.get("id"),
            "type": snap.get("payload", {}).get("type"),
            "name": snap.get("payload", {}).get("name"),
            "content": snap.get("payload", {}).get("content"),
            "proxied": snap.get("payload", {}).get("proxied"),
        }
        if snap.get("id") != record_id or snapshots.get(alias) != compact:
            raise ServiceOpenError("DNS_TRANSACTION_SNAPSHOT_MISMATCH")
    return receipt, snapshot_dir


def _verify_live_dns(
    args: argparse.Namespace, *, token: str, dns_reader: Callable,
) -> dict:
    expected = {
        "web": (args.web_record_id, args.web_domain),
        "emr": (args.emr_record_id, args.emr_domain),
    }
    output = {}
    for alias, (record_id, name) in expected.items():
        live = dns_reader(zone_id=args.zone_id, record_id=record_id, token=token)
        target = {"type": "A", "name": name, "content": args.dr_web_eip, "ttl": 1, "proxied": True}
        if not dns_transaction._record_matches_payload(live, record_id, target):
            raise ServiceOpenError("CLOUDFLARE_DNS_NOT_APPROVED_DR_PAIR")
        output[alias] = {"id": record_id, **target}
    return output


def _verify_dr_state(args: argparse.Namespace, *, expected: str, state_reader: Callable) -> None:
    try:
        current = state_reader(Path(args.state_file))
    except Exception as exc:
        raise ServiceOpenError("DR_STATE_READ_ONLY_CHECK_FAILED") from exc
    if current != expected or current not in {"IDLE", "FAILED"}:
        raise ServiceOpenError("DR_STATE_CHANGED_DURING_SERVICE_OPEN")


def _verify_aws_and_sgs(args, env, aws_runner, *, aws_validator, app_sg_validator) -> dict:
    try:
        isolated = aws_validator(
            region=args.region, instance_id=args.instance_id, private_ip=args.private_ip,
            data_volume_id=args.data_volume_id, stage_volume_id=args.stage_volume_id,
            service_security_group_id=args.service_security_group_id,
            require_service_sg_attached=True, runner=aws_runner,
        )
        if any(isolated.get(key) != value for key, value in {
            "instance_id": args.instance_id, "private_ip": args.private_ip,
            "data_volume_id": args.data_volume_id, "stage_volume_id": args.stage_volume_id,
            "service_security_group_id": args.service_security_group_id,
            "service_security_group_attached": True,
        }.items()):
            raise ServiceOpenError("ISOLATED_AWS_IDENTITY_MISMATCH")
        cf_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=env)
        mgmt = public_readiness.load_management_ipv4_cidrs(env)
        zabbix = public_readiness.load_terraform_ipv4_cidrs("zabbix_agent_source_ipv4_cidrs", environment=env)
        wg = public_readiness.load_terraform_ipv4_cidrs("aws_dr_wg_peer_ingress_ipv4_cidrs", environment=env)
        wg_enabled = env.get("TF_VAR_aws_dr_wg_enabled", "false").strip().lower() == "true"
        groups = app_sg_validator(
            region=args.region, cloudflare_ipv4_cidrs=cf_cidrs,
            management_ipv4_cidrs=mgmt, zabbix_ipv4_cidrs=zabbix,
            wireguard_peer_ipv4_cidrs=wg, wireguard_enabled=wg_enabled,
            expected_eip=args.dr_web_eip, runner=aws_runner,
        )
        if (
            groups.get("ipv6_ingress") is not False or groups.get("world_ingress") is not False
            or groups.get("app_port_3000_ingress") is not False
            or groups.get("web_instance_id") != WEB_INSTANCE_ID
        ):
            raise ServiceOpenError("DR_APP_INGRESS_CONTRACT_UNSAFE")
        return {"isolated": isolated, "app_groups": groups, "cloudflare_ipv4_cidrs": cf_cidrs}
    except ServiceOpenError:
        raise
    except Exception as exc:
        raise ServiceOpenError("AWS_IDENTITY_OR_SECURITY_GROUP_CHECK_FAILED") from exc


def validate_approved_two_admins(
    approval: dict, *, environment: Mapping[str, str],
) -> dict:
    approvers = approval.get("approver_ids")
    allowlist = {item.strip() for item in environment.get("SLACK_ADMIN_USER_IDS", "").split(",") if item.strip()}
    if (
        approval.get("approval_required") != 2 or approval.get("approval_count") != 2
        or not isinstance(approvers, list) or len(approvers) != 2
        or len(set(approvers)) != 2 or not allowlist or not set(approvers).issubset(allowlist)
    ):
        raise ServiceOpenError("CURRENT_TWO_ADMIN_APPROVAL_REQUIRED")
    return approval


def _validate_approval(args, env, *, now, approval_validator) -> dict:
    try:
        approval = approval_validator(Path(args.chatops_state_db), args, now=now, owner_uid=os.geteuid())
    except Exception as exc:
        raise ServiceOpenError(str(exc) if isinstance(exc, dns_transaction.DNSTransactionError) else "CHATOPS_APPROVAL_NOT_CURRENT") from exc
    return validate_approved_two_admins(approval, environment=env)


def _public_route_check(
    *, host: str, path: str, expected_status: int, cloudflare_ipv4_cidrs: tuple[str, ...],
    attempts: int, interval_seconds: int, resolver: Callable, transport: Callable,
    sleep: Callable,
) -> dict:
    last = "PUBLIC_SERVICE_ROUTE_UNAVAILABLE"
    for attempt in range(1, attempts + 1):
        try:
            addresses = resolver(host)
            if not dns_transaction._is_cloudflare_edge(addresses, cloudflare_ipv4_cidrs):
                raise ServiceOpenError("PUBLIC_DNS_NOT_CLOUDFLARE")
            address = addresses[(attempt - 1) % len(addresses)]
            status, headers, _body = transport(
                host=host, address=address, path=path,
                headers={"Accept": "text/html", "Cache-Control": "no-cache", "User-Agent": "Hospital-DR-Service-Open/1"},
                timeout=dns_transaction.HEALTH_TIMEOUT_SECONDS,
            )
            ray = headers.get("CF-Ray", "") if headers is not None else ""
            server = headers.get("Server", "") if headers is not None else ""
            if status != expected_status or not dns_transaction.CF_RAY_RE.fullmatch(str(ray).strip()) or server.lower() != "cloudflare":
                raise ServiceOpenError("PUBLIC_SERVICE_ROUTE_RESPONSE_INVALID")
            return {"host": host, "path": path, "status": status, "cloudflare_edge": True, "tls_verified": True}
        except (ServiceOpenError, OSError, TimeoutError, ValueError, Exception) as exc:
            last = str(exc) if isinstance(exc, ServiceOpenError) else "PUBLIC_SERVICE_ROUTE_TRANSPORT_FAILED"
        if attempt < attempts:
            sleep(interval_seconds)
    raise ServiceOpenError(last)


def _safe_receipt(args, status: str, now: datetime, *, approval: dict) -> dict:
    return {
        "status": status,
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
        "service_account": "hospital_dr_service",
        "schema": "hospital_db",
        "privileges": ["SELECT"],
        "service_account_privileges": {
            WEB_PRIVATE_IP: ["SELECT"],
            EMR_PRIVATE_IP: ["SELECT"],
        },
        "approval": {
            "execution_id": approval.get("execution_id"),
            "approval_required": 2,
            "approval_count": 2,
        },
        "application_writes_allowed": False,
        "user_service_writes_open": False,
        "service_account_dml_enabled": False,
        "dns_records_switched": True,
        "maintenance_mode": True,
        "service_accounts_locked": False,
        "dr_active_recorded": False,
        "rollback_to_prior_database_allowed": False,
        "automatic_dns_rollback_allowed": False,
        "dr_state_changed": False,
        "started_at_utc": now.astimezone(timezone.utc).isoformat(),
    }


def _remote_phase_args(
    args, phase, token, cidrs, expected_binlog=None, expected_db_server_uuid="",
) -> dict:
    return {
        "dump_open_phase": phase,
        "dump_open_request_id": args.request_id,
        "dump_open_promotion_id": args.promotion_id,
        "dump_open_cutover_id": args.cutover_id,
        "dump_open_instance_id": args.instance_id,
        "dump_open_private_ip": args.private_ip,
        "dump_open_data_volume_id": args.data_volume_id,
        "dump_open_stage_volume_id": args.stage_volume_id,
        "dump_open_service_sg_id": args.service_security_group_id,
        "dump_open_expected_sha256": args.expected_sha256.lower(),
        "dump_open_backup_id": Path(args.backup).name,
        "dump_open_web_domain": args.web_domain,
        "dump_open_emr_domain": args.emr_domain,
        "dump_open_dr_eip": args.dr_web_eip,
        "dump_open_probe_token": token,
        "dump_open_cloudflare_ipv4_cidrs": list(cidrs),
        "dump_open_expected_binlog_file": (expected_binlog or {}).get("file", ""),
        "dump_open_expected_binlog_position": (expected_binlog or {}).get("position", 0),
        "dump_open_db_server_uuid": expected_db_server_uuid,
        "dump_open_remote_db_helper_sha256": hashlib.sha256(REMOTE_DB_HELPER.read_bytes()).hexdigest(),
        "dump_open_remote_service_helper_sha256": hashlib.sha256(REMOTE_DB_SERVICE_HELPER.read_bytes()).hexdigest(),
        "dump_open_remote_restore_helper_sha256": hashlib.sha256(REMOTE_RESTORE_HELPER.read_bytes()).hexdigest(),
        "dump_open_remote_app_probe_sha256": hashlib.sha256(REMOTE_APP_PROBE.read_bytes()).hexdigest(),
        "dump_open_remote_write_probe_sha256": hashlib.sha256(REMOTE_APP_WRITE_PROBE.read_bytes()).hexdigest(),
        "dump_open_remote_fence_helper_sha256": hashlib.sha256(REMOTE_FENCE_HELPER.read_bytes()).hexdigest(),
        "dump_open_remote_web_helper_sha256": hashlib.sha256(REMOTE_WEB_HELPER.read_bytes()).hexdigest(),
        "dump_open_service_fence_unit_sha256": hashlib.sha256(SERVICE_FENCE_UNIT.read_bytes()).hexdigest(),
    }


def run_remote_service_open_phase(
    args, phase: str, *, token: str, cloudflare_ipv4_cidrs: tuple[str, ...],
    expected_binlog: dict | None = None, expected_db_server_uuid: str = "",
    environment: Mapping[str, str],
    runner: Callable = subprocess.run, tmpfs_root: str = "/dev/shm",
) -> dict:
    valid = {
        "install", "verify", "stop-apps", "verify-no-dml", "lock-accounts",
        "handoff-fence", "pre-grant-check",
        "grant-dml", "unlock-accounts", "verify-unlocked", "verify-live", "app-probe", "release-maintenance",
        "start-apps", "contain-app-pre-dml", "contain-db-pre-dml",
        "contain-app-after-dml", "contain-db-after-dml", "record-success",
    }
    if phase not in valid or not PLAYBOOK.is_file():
        raise ServiceOpenError("SERVICE_OPEN_REMOTE_PHASE_UNAVAILABLE")
    check = runner(["findmnt", "-n", "-o", "FSTYPE", "--target", tmpfs_root], capture_output=True, text=True, check=False)
    if check.returncode != 0 or check.stdout.strip() != "tmpfs":
        raise ServiceOpenError("SECRET_TMPFS_UNAVAILABLE")
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-service-open-", dir=tmpfs_root) as temp:
            root = Path(temp)
            root.chmod(0o700)
            inventory = root / "inventory.ini"
            ssh_config = root / "ssh-config"
            vars_path = root / "vars.json"
            public_readiness._build_overlay(
                path=inventory, ssh_config_path=ssh_config,
                ssh_config=Path(args.ssh_config), ssh_key=args.ssh_key,
                known_hosts=str(args.known_hosts), private_ip=args.private_ip,
            )
            vars_path.write_text(
                json.dumps(
                    _remote_phase_args(
                        args, phase, token, cloudflare_ipv4_cidrs,
                        expected_binlog, expected_db_server_uuid,
                    ),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            vars_path.chmod(0o600)
            command = [
                "timeout", "--signal=TERM", "--kill-after=5", "180s", "ansible-playbook",
                "-i", str(args.inventory), "-i", str(inventory), "-e", f"@{vars_path}",
            ]
            command.append(str(PLAYBOOK))
            result = runner(
                command,
                cwd=str(REPO_ROOT / "automation/ansible"),
                env=public_readiness._safe_child_environment(environment),
                capture_output=True, text=True, check=False,
            )
    except OSError as exc:
        raise ServiceOpenError("SERVICE_OPEN_REMOTE_PHASE_UNAVAILABLE") from exc
    if result.returncode != 0:
        return {"ok": False}
    marker = f"DUMP_SERVICE_OPEN_REMOTE=PASS phase={phase}"
    if marker not in result.stdout:
        return {"ok": False}
    if phase in {"verify", "lock-accounts", "unlock-accounts", "verify-no-dml", "pre-grant-check", "verify-unlocked", "verify-live", "contain-db-pre-dml"}:
        match = re.search(
            r"binlog_file=([A-Za-z0-9._-]{1,128}) binlog_position=([1-9][0-9]{0,19}) db_server_uuid=([0-9a-f-]{36})",
            result.stdout,
        )
        if phase == "verify":
            if not match:
                return {"ok": False}
            return {"ok": True, "file": match.group(1), "position": int(match.group(2)), "db_server_uuid": match.group(3)}
        if phase in {"lock-accounts", "unlock-accounts"}:
            if not match:
                return {"ok": False}
            return {"ok": True, "file": match.group(1), "position": int(match.group(2)), "db_server_uuid": match.group(3)}
        if phase in {"verify-no-dml", "pre-grant-check", "verify-unlocked", "verify-live", "contain-db-pre-dml"}:
            if not match:
                return {"ok": False}
            return {"ok": True, "file": match.group(1), "position": int(match.group(2)), "db_server_uuid": match.group(3)}
    return {"ok": True}


def execute_service_open(
    args: argparse.Namespace, *, environment: Mapping[str, str] | None = None,
    backup_validator: Callable = validate_backup_pair,
    state_reader: Callable = dns_preflight.read_dr_state,
    dns_reader: Callable = dns_preflight.cloudflare_get_record,
    aws_validator: Callable = validate_aws_isolated_target,
    app_sg_validator: Callable = public_readiness.read_and_validate_app_security_groups,
    approval_validator: Callable = dns_transaction.validate_approved_chatops_request,
    lock_validator: Callable = validate_inherited_locks,
    phase_runner: Callable | None = None,
    public_health_checker: Callable = dns_transaction.check_public_health,
    public_route_checker: Callable | None = None,
    snapshot_rollbacker: Callable | None = None,
    readback_verifier: Callable | None = None,
    aws_runner: Callable | None = None,
    clock: Callable = lambda: datetime.now(timezone.utc),
    sleep: Callable = __import__("time").sleep,
    owner_uid: int | None = None,
    logger: Callable[[str], None] = print,
) -> dict:
    env = environment if environment is not None else os.environ
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    validate_request(args, env)
    lock_validator(env)
    try:
        backup = backup_validator(Path(args.backup), args.expected_sha256)
    except Exception as exc:
        raise ServiceOpenError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID") from exc
    if not isinstance(backup, dict) or str(backup.get("sha256", "")).lower() != args.expected_sha256.lower():
        raise ServiceOpenError("BACKUP_CHECKSUM_MISMATCH")

    now = clock()
    if now.tzinfo is None:
        raise ServiceOpenError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    readiness, probe_token = dns_transaction._load_ready_capability(
        args=args, now=now, owner_uid=owner_uid
    )
    transaction_receipt, snapshot_dir = _transaction_receipt(args, owner_uid=owner_uid, now=now)
    if readiness.get("expires_at_utc") != transaction_receipt.get("readiness_expires_at_utc"):
        raise ServiceOpenError("PUBLIC_READINESS_EXPIRY_MISMATCH")
    expected_dr_state = transaction_receipt.get("dr_state_observed")
    if expected_dr_state not in {"IDLE", "FAILED"}:
        raise ServiceOpenError("DR_STATE_OBSERVED_UNSAFE")
    _verify_dr_state(args, expected=expected_dr_state, state_reader=state_reader)
    token = env.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        raise ServiceOpenError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")
    cf_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=env)
    aws_runner = aws_runner or dns_transaction._aws_readonly_runner(env)
    client = dns_transaction.DNSHelperClient(zone_id=args.zone_id, token=token)
    snapshot_rollbacker = snapshot_rollbacker or client.rollback
    readback_verifier = readback_verifier or (lambda rec_id: dns_reader(zone_id=args.zone_id, record_id=rec_id, token=token))
    if public_route_checker is None:
        public_route_checker = lambda **kw: _public_route_check(
            **kw, resolver=dns_transaction._cloudflare_resolved_ipv4,
            transport=dns_transaction._pinned_https_get, sleep=sleep,
        )
    if phase_runner is None:
        phase_runner = lambda phase, expected_binlog=None, expected_db_server_uuid="": run_remote_service_open_phase(
            args, phase, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
            expected_binlog=expected_binlog,
            expected_db_server_uuid=expected_db_server_uuid, environment=env,
        )

    _secure_dir(Path(args.state_dir), owner_uid=owner_uid)
    operation_dir = Path(args.state_dir) / _uuid(args.request_id, "REQUEST_ID_INVALID")
    receipt_path = operation_dir / "service-open.json"
    log_path = operation_dir / f"{args.request_id}.log"
    lock_path = Path(args.service_open_lock_file)

    with _operation_lock(lock_path, owner_uid=owner_uid):
        try:
            operation_dir.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ServiceOpenError("SERVICE_OPEN_ALREADY_RECORDED") from exc
        if operation_dir.stat().st_uid != owner_uid or stat.S_IMODE(operation_dir.stat().st_mode) != 0o700:
            raise ServiceOpenError("SERVICE_OPEN_STATE_DIRECTORY_PERMISSIONS_INVALID")
        approval = _validate_approval(args, env, now=clock(), approval_validator=approval_validator)
        execution_id = approval.get("execution_id")
        def revalidate_approval():
            fresh = _validate_approval(args, env, now=clock(), approval_validator=approval_validator)
            if fresh.get("execution_id") != execution_id or fresh.get("approver_ids") != approval.get("approver_ids"):
                raise ServiceOpenError("CHATOPS_APPROVAL_CHANGED_DURING_SERVICE_OPEN")
            return fresh

        def check_live_state(*, health: bool):
            fresh_now = clock()
            _parse_utc(transaction_receipt.get("readiness_expires_at_utc"), "PUBLIC_READINESS_EXPIRY_INVALID")
            if fresh_now >= _parse_utc(transaction_receipt["readiness_expires_at_utc"], "PUBLIC_READINESS_EXPIRY_INVALID"):
                raise ServiceOpenError("DUMP_SERVICE_PREPARATION_EXPIRED")
            revalidate_approval()
            _verify_dr_state(args, expected=expected_dr_state, state_reader=state_reader)
            _verify_live_dns(args, token=token, dns_reader=dns_reader)
            external = _verify_aws_and_sgs(args, env, aws_runner, aws_validator=aws_validator, app_sg_validator=app_sg_validator)
            if health:
                for host in (args.web_domain, args.emr_domain):
                    public_health_checker(
                        host=host, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
                        attempts=args.health_attempts, interval_seconds=args.health_interval_seconds,
                    )
            return external

        check_live_state(health=True)
        _emit(log_path, args.request_id, "initial-live-validation", "PASS", owner_uid=owner_uid, logger=logger)
        record = _safe_receipt(args, "DUMP_SERVICE_OPEN_IN_PROGRESS", clock(), approval=approval)
        record.update({
            "phase": "PRE_DML_VALIDATION",
            "write_open_started": False,
            "dml_grant_attempted": False,
            "preparation_expires_at_utc": transaction_receipt["readiness_expires_at_utc"],
            "mysql_binlog_baseline": transaction_receipt["mysql_binlog_baseline"],
            "execution_log_path": str(log_path),
        })
        _write_receipt(receipt_path, record, owner_uid=owner_uid)
        irreversible = False
        safe_binlog = transaction_receipt["mysql_binlog_baseline"]
        db_server_uuid = ""
        try:
            install = phase_runner("install", expected_binlog=None)
            if not install.get("ok"):
                raise ServiceOpenError("SERVICE_OPEN_HELPER_INSTALL_FAILED")
            revalidate_approval()
            external = check_live_state(health=True)
            remote = phase_runner("verify", expected_binlog=None)
            if not remote.get("ok") or {"file": remote.get("file"), "position": remote.get("position")} != safe_binlog:
                raise ServiceOpenError("MYSQL_OR_DNS_WRITE_BASELINE_MISMATCH")
            db_server_uuid = remote.get("db_server_uuid", "")
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", db_server_uuid):
                raise ServiceOpenError("ISOLATED_DB_SERVER_UUID_INVALID")
            record["db_server_uuid"] = db_server_uuid
            record["phase"] = "LIVE_DNS_DB_APP_AND_TIMER_PRECHECK"
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "live-precheck", "PASS", owner_uid=owner_uid, logger=logger)

            revalidate_approval()
            stopped = phase_runner("stop-apps", expected_binlog=None)
            if not stopped.get("ok"):
                raise ServiceOpenError("APP_MAINTENANCE_STOP_FAILED")
            no_dml_before_lock = phase_runner("verify-no-dml", expected_binlog=safe_binlog)
            if (
                not no_dml_before_lock.get("ok")
                or {"file": no_dml_before_lock.get("file"), "position": no_dml_before_lock.get("position")} != safe_binlog
            ):
                raise ServiceOpenError("MYSQL_CHANGED_BEFORE_ACCOUNT_LOCK")

            revalidate_approval()
            locked = phase_runner("lock-accounts", expected_binlog=safe_binlog)
            if not locked.get("ok"):
                raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_FAILED")
            safe_binlog = {"file": locked["file"], "position": locked["position"]}
            record["mysql_containment_binlog_baseline"] = safe_binlog
            record["phase"] = "SERVICE_ACCOUNTS_LOCKED_SELECT_ONLY"
            record["service_accounts_locked"] = True
            record["service_account_privileges"] = {
                WEB_PRIVATE_IP: ["SELECT"], EMR_PRIVATE_IP: ["SELECT"],
            }
            record["privileges"] = ["SELECT"]
            record["service_account_dml_enabled"] = False
            record["application_writes_allowed"] = False
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "accounts-locked", "PASS", owner_uid=owner_uid, logger=logger)

            revalidate_approval()
            handoff = phase_runner("handoff-fence", expected_binlog=safe_binlog)
            if not handoff.get("ok"):
                raise ServiceOpenError("DURABLE_SERVICE_FENCE_HANDOFF_FAILED")
            record["durable_service_fence"] = "CLOUDFLARE_WEB_TO_EMR_ONLY_VERIFIED"
            record["preparation_timer"] = "CANCELLED_AFTER_DURABLE_FENCE_HANDOFF"
            record["phase"] = "DURABLE_FENCE_ACTIVE_MAINTENANCE_ON"
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "fence-handoff", "PASS", owner_uid=owner_uid, logger=logger)

            revalidate_approval()
            external = check_live_state(health=False)
            pregrant = phase_runner("pre-grant-check", expected_binlog=safe_binlog)
            if (
                not pregrant.get("ok")
                or {"file": pregrant.get("file"), "position": pregrant.get("position")} != safe_binlog
            ):
                raise ServiceOpenError("PRE_DML_OPEN_GATES_FAILED")
            if clock() >= _parse_utc(transaction_receipt["readiness_expires_at_utc"], "PUBLIC_READINESS_EXPIRY_INVALID"):
                raise ServiceOpenError("DUMP_SERVICE_PREPARATION_EXPIRED_BEFORE_DML")

            revalidate_approval()
            check_live_state(health=False)

            # Irreversible boundary is durably recorded before any grant request.
            record.update({
                "phase": "DML_GRANT_ATTEMPTED",
                "write_open_started": True,
                "dml_grant_attempted": True,
                "privileges": ["UNKNOWN_DML_ATTEMPT"],
                "service_account_dml_enabled": "UNKNOWN_OR_ATTEMPTED",
                "application_writes_allowed": False,
                "user_service_writes_open": False,
                "automatic_dns_rollback_allowed": False,
                "rollback_to_prior_database_allowed": False,
                "dml_grant_intent_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            irreversible = True
            _emit(log_path, args.request_id, "write-boundary", "IRREVERSIBLE_DML_GRANT_STARTED", owner_uid=owner_uid, logger=logger)
            grant = phase_runner("grant-dml", expected_binlog=safe_binlog)
            if not grant.get("ok"):
                raise ServiceOpenError("DML_GRANT_OR_READBACK_FAILED")
            record["phase"] = "DML_GRANTED_ACCOUNTS_STILL_LOCKED"
            record["service_account_privileges"] = {
                WEB_PRIVATE_IP: ["SELECT", "INSERT", "UPDATE", "DELETE"],
                EMR_PRIVATE_IP: ["SELECT", "INSERT", "UPDATE", "DELETE"],
            }
            record["privileges"] = ["DELETE", "INSERT", "SELECT", "UPDATE"]
            record["service_account_dml_enabled"] = True
            record["application_writes_allowed"] = False
            record["user_service_writes_open"] = False
            record["service_accounts_locked"] = True
            _write_receipt(receipt_path, record, owner_uid=owner_uid)

            revalidate_approval()
            external = check_live_state(health=False)
            unlock = phase_runner("unlock-accounts", expected_binlog=None)
            if not unlock.get("ok"):
                raise ServiceOpenError("SERVICE_DB_ACCOUNT_UNLOCK_FAILED")
            unlocked_binlog = {"file": unlock.get("file"), "position": unlock.get("position")}
            if (
                not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(unlocked_binlog["file"] or ""))
                or not isinstance(unlocked_binlog["position"], int)
                or isinstance(unlocked_binlog["position"], bool)
                or unlocked_binlog["position"] < 1
            ):
                raise ServiceOpenError("SERVICE_DB_UNLOCK_BINLOG_BASELINE_INVALID")
            record["phase"] = "ACCOUNTS_UNLOCKED_MAINTENANCE_ON"
            record["write_open_binlog_baseline"] = unlocked_binlog
            record["service_accounts_locked"] = False
            record["service_account_dml_enabled"] = True
            record["application_writes_allowed"] = False
            record["user_service_writes_open"] = False
            _write_receipt(receipt_path, record, owner_uid=owner_uid)

            revalidate_approval()
            verified_unlock = phase_runner("verify-unlocked", expected_binlog=None)
            if (
                not verified_unlock.get("ok")
                or verified_unlock.get("db_server_uuid") != db_server_uuid
                or {"file": verified_unlock.get("file"), "position": verified_unlock.get("position")} != unlocked_binlog
            ):
                raise ServiceOpenError("SERVICE_DB_UNLOCKED_STATE_REVERIFICATION_FAILED")

            revalidate_approval()
            started = phase_runner(
                "start-apps", expected_binlog=None,
                expected_db_server_uuid=db_server_uuid,
            )
            if not started.get("ok"):
                raise ServiceOpenError("FENCED_APP_START_OR_HEALTH_FAILED")

            revalidate_approval()
            app_probe = phase_runner(
                "app-probe", expected_binlog=None,
                expected_db_server_uuid=db_server_uuid,
            )
            if not app_probe.get("ok"):
                raise ServiceOpenError("WEB_EMR_DML_ACCOUNT_CONNECTION_CHECK_FAILED")
            revalidate_approval()
            check_live_state(health=True)
            for host in (args.web_domain, args.emr_domain):
                public_health_checker(
                    host=host, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
                    attempts=args.health_attempts, interval_seconds=args.health_interval_seconds,
                )
            live_verified = phase_runner(
                "verify-live", expected_binlog=unlocked_binlog,
                expected_db_server_uuid=db_server_uuid,
            )
            if (
                not live_verified.get("ok")
                or live_verified.get("db_server_uuid") != db_server_uuid
                or {"file": live_verified.get("file"), "position": live_verified.get("position")} != unlocked_binlog
            ):
                raise ServiceOpenError("LIVE_APP_DB_WRITE_FENCE_REVALIDATION_FAILED")
            record["phase"] = "DML_ENABLED_MAINTENANCE_ON_APP_PROBES_PASS"
            _write_receipt(receipt_path, record, owner_uid=owner_uid)

            revalidate_approval()
            check_live_state(health=True)
            _verify_live_dns(args, token=token, dns_reader=dns_reader)
            record.update({
                "phase": "MAINTENANCE_RELEASE_ATTEMPTED",
                "application_writes_allowed": "UNKNOWN_OR_OPEN",
                "user_service_writes_open": "UNKNOWN_OR_OPEN",
                "maintenance_release_attempted": True,
                "maintenance_release_intent_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "maintenance-release", "ATTEMPTED_AFTER_DML_NO_ROLLBACK", owner_uid=owner_uid, logger=logger)
            released = phase_runner("release-maintenance", expected_binlog=None)
            if not released.get("ok"):
                raise ServiceOpenError("MAINTENANCE_RELEASE_FAILED")
            if public_route_checker is None:
                raise ServiceOpenError("PUBLIC_SERVICE_ROUTE_CHECK_UNAVAILABLE")
            web_status = public_route_checker(
                host=args.web_domain, path="/", expected_status=200,
                cloudflare_ipv4_cidrs=cf_cidrs, attempts=args.health_attempts,
                interval_seconds=args.health_interval_seconds,
            )
            emr_status = public_route_checker(
                host=args.emr_domain, path="/", expected_status=200,
                cloudflare_ipv4_cidrs=cf_cidrs, attempts=args.health_attempts,
                interval_seconds=args.health_interval_seconds,
            )
            for host in (args.web_domain, args.emr_domain):
                public_health_checker(
                    host=host, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
                    attempts=args.health_attempts, interval_seconds=args.health_interval_seconds,
                )
            _verify_live_dns(args, token=token, dns_reader=dns_reader)
            check_live_state(health=True)
            _verify_dr_state(args, expected=expected_dr_state, state_reader=state_reader)
            revalidate_approval()
            finalized = phase_runner("record-success", expected_binlog=None)
            if not finalized.get("ok"):
                raise ServiceOpenError("SERVICE_OPEN_FINAL_AUDIT_FAILED")
            record.update({
                "status": SUCCESS_STATUS,
                "phase": "COMPLETE_SERVICE_OPEN_NOT_DR_ACTIVE",
                "application_writes_allowed": True,
                "user_service_writes_open": True,
                "service_account_dml_enabled": True,
                "maintenance_mode": False,
                "public_service_health": {"web": web_status, "emr": emr_status},
                "cloudflare_health_204": {"web": True, "emr": True},
                "service_account_lock_state": "UNLOCKED_VERIFIED",
                "rollback_to_prior_database_allowed": False,
                "automatic_dns_rollback_allowed": False,
                "dr_active_recorded": False,
                "dr_state_changed": False,
                "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "complete", SUCCESS_STATUS, owner_uid=owner_uid, logger=logger)
            return record
        except Exception as exc:
            code = str(exc) if isinstance(exc, ServiceOpenError) else "SERVICE_OPEN_OPERATION_FAILED"
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code):
                code = "SERVICE_OPEN_OPERATION_FAILED"
            record["failure_code"] = code
            if irreversible:
                # Containment may re-lock accounts and restore maintenance. It
                # never revokes granted DML privileges or rolls DNS to another DB.
                try:
                    app_containment = phase_runner("contain-app-after-dml", expected_binlog=None)
                except Exception:
                    app_containment = {"ok": False}
                try:
                    db_containment = phase_runner("contain-db-after-dml", expected_binlog=None)
                except Exception:
                    db_containment = {"ok": False}
                app_contained = bool(app_containment.get("ok"))
                db_contained = bool(db_containment.get("ok"))
                record.update({
                    "status": PARTIAL_STATUS,
                    "phase": "OPERATOR_INTERVENTION_REQUIRED_DML_OPEN_OR_UNKNOWN",
                    "application_writes_allowed": False if app_contained else "UNKNOWN_OR_ENABLED",
                    "user_service_writes_open": False if app_contained else "UNKNOWN_OR_OPEN",
                    "service_account_dml_enabled": True,
                    "maintenance_mode": True if app_contained else "RESTORE_REQUIRED_OR_UNKNOWN",
                    "service_accounts_locked": True if db_contained else "UNKNOWN_OR_RELOCK_ATTEMPTED",
                    "service_sessions_quiesced": db_contained,
                    "rollback_to_prior_database_allowed": False,
                    "automatic_dns_rollback_allowed": False,
                    "operator_intervention_required": True,
                    "dr_active_recorded": False,
                    "dr_state_changed": False,
                    "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
                })
                _write_receipt(receipt_path, record, owner_uid=owner_uid)
                _emit(log_path, args.request_id, "partial-failure", "DML_OPEN_OR_UNKNOWN_NO_DATABASE_ROLLBACK", owner_uid=owner_uid, logger=logger)
                return record

            # Before the DML write-ahead marker, close the service path and
            # restore maintenance. DNS rollback is attempted only with a fresh
            # no-DML proof, unchanged DR DNS pair, and verified snapshots.
            try:
                app_containment = phase_runner("contain-app-pre-dml", expected_binlog=None)
            except Exception:
                app_containment = {"ok": False}
            try:
                db_containment = phase_runner("contain-db-pre-dml", expected_binlog=None)
            except Exception:
                db_containment = {"ok": False}
            contained = bool(app_containment.get("ok") and db_containment.get("ok"))
            rolled_back = False
            rollback_status = "NOT_ATTEMPTED_NO_SAFE_PROOF"
            try:
                live = _verify_live_dns(args, token=token, dns_reader=dns_reader)
                no_dml = phase_runner("verify-no-dml", expected_binlog=safe_binlog)
                no_dml_matches = (
                    no_dml.get("ok")
                    and {"file": no_dml.get("file"), "position": no_dml.get("position")} == safe_binlog
                )
                can_rollback = contained and no_dml_matches and live.get("web") and live.get("emr")
                # If no lock phase ran, require the original DNS transaction
                # binlog baseline. A changed/unknown position is never proof.
                if can_rollback:
                    rollback_status = "ATTEMPTED"
                    rolled_back = bool(snapshot_rollbacker(snapshot_dir))
                    if rolled_back:
                        for alias, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
                            snapshot = dns_transaction._validate_record_snapshot(
                                snapshot_dir / f"{alias}.json", owner_uid=owner_uid
                            )
                            if not dns_transaction._record_matches_payload(
                                readback_verifier(record_id), record_id, snapshot["payload"]
                            ):
                                rolled_back = False
                                break
                    rollback_status = "SUCCESS_AND_READBACK_VERIFIED" if rolled_back else "FAILED_OR_UNVERIFIED"
            except Exception:
                rolled_back = False
                rollback_status = "FAILED_OR_UNVERIFIED"
            if rolled_back:
                record.update({
                    "status": PRE_DML_ROLLBACK_STATUS,
                    "phase": "PRE_DML_FAILED_ORIGIN_DNS_RESTORED",
                    "application_writes_allowed": False,
                    "user_service_writes_open": False,
                    "service_account_dml_enabled": False,
                    "maintenance_mode": True,
                    "service_accounts_locked": True,
                    "dns_rollback": rollback_status,
                    "automatic_dns_rollback_allowed": True,
                    "rollback_to_prior_database_allowed": False,
                    "operator_intervention_required": False,
                    "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
                })
                _write_receipt(receipt_path, record, owner_uid=owner_uid)
                _emit(log_path, args.request_id, "pre-dml-rollback", "ORIGIN_DNS_READBACK_VERIFIED", owner_uid=owner_uid, logger=logger)
                return record
            record.update({
                "status": PARTIAL_STATUS,
                "phase": "PRE_DML_FAILURE_DNS_ROLLBACK_NOT_PROVEN_OR_FAILED",
                "application_writes_allowed": False,
                "user_service_writes_open": False,
                "service_account_dml_enabled": False,
                "maintenance_mode": True if contained else "UNKNOWN",
                "service_accounts_locked": True if contained else "UNKNOWN",
                "dns_rollback": rollback_status,
                "automatic_dns_rollback_allowed": False,
                "rollback_to_prior_database_allowed": False,
                "operator_intervention_required": True,
                "dr_active_recorded": False,
                "dr_state_changed": False,
                "completed_at_utc": clock().astimezone(timezone.utc).isoformat(),
            })
            _write_receipt(receipt_path, record, owner_uid=owner_uid)
            _emit(log_path, args.request_id, "partial-failure", "PRE_DML_ROLLBACK_NOT_PROVEN_OR_FAILED", owner_uid=owner_uid, logger=logger)
            return record


def verify_final_service_open(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    backup_validator: Callable = validate_backup_pair,
    state_reader: Callable = dns_preflight.read_dr_state,
    dns_reader: Callable = dns_preflight.cloudflare_get_record,
    aws_validator: Callable = validate_aws_isolated_target,
    app_sg_validator: Callable = public_readiness.read_and_validate_app_security_groups,
    approval_validator: Callable = dns_transaction.validate_approved_chatops_request,
    lock_validator: Callable = validate_inherited_locks,
    phase_runner: Callable | None = None,
    public_health_checker: Callable = dns_transaction.check_public_health,
    public_route_checker: Callable | None = None,
    aws_runner: Callable | None = None,
    clock: Callable = lambda: datetime.now(timezone.utc),
    sleep: Callable = __import__("time").sleep,
    owner_uid: int | None = None,
) -> dict:
    """Fresh, read-only confirmation after DML/service opening; never writes DR state."""
    env = environment if environment is not None else os.environ
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    validate_request(args, env)
    lock_validator(env)
    now = clock()
    if now.tzinfo is None:
        raise ServiceOpenError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    try:
        backup = backup_validator(Path(args.backup), args.expected_sha256)
    except Exception as exc:
        raise ServiceOpenError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID") from exc
    if not isinstance(backup, dict) or str(backup.get("sha256", "")).lower() != args.expected_sha256.lower():
        raise ServiceOpenError("BACKUP_CHECKSUM_MISMATCH")

    open_path = Path(args.state_dir) / _uuid(args.request_id, "REQUEST_ID_INVALID") / "service-open.json"
    opened = _read_private_json(open_path, owner_uid=owner_uid, code="SERVICE_OPEN_SUCCESS_RECEIPT_INVALID")
    expected_open = {
        "status": SUCCESS_STATUS,
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
        "application_writes_allowed": True,
        "user_service_writes_open": True,
        "service_account_dml_enabled": True,
        "maintenance_mode": False,
        "service_accounts_locked": False,
        "dr_active_recorded": False,
        "dr_state_changed": False,
        "automatic_dns_rollback_allowed": False,
        "rollback_to_prior_database_allowed": False,
        "durable_service_fence": "CLOUDFLARE_WEB_TO_EMR_ONLY_VERIFIED",
        "preparation_timer": "CANCELLED_AFTER_DURABLE_FENCE_HANDOFF",
    }
    if any(opened.get(key) != value for key, value in expected_open.items()):
        raise ServiceOpenError("SERVICE_OPEN_SUCCESS_RECEIPT_MISMATCH")
    if opened.get("dml_grant_attempted") is not True or not re.fullmatch(
        r"[0-9a-fA-F-]{36}", str(opened.get("db_server_uuid", ""))
    ):
        raise ServiceOpenError("SERVICE_OPEN_IRREVERSIBLE_STATE_UNVERIFIED")
    approval_record = opened.get("approval")
    if (
        not isinstance(approval_record, dict)
        or approval_record.get("approval_required") != 2
        or approval_record.get("approval_count") != 2
    ):
        raise ServiceOpenError("SERVICE_OPEN_APPROVAL_RECEIPT_INVALID")
    approval = _validate_approval(args, env, now=now, approval_validator=approval_validator)
    if approval.get("execution_id") != approval_record.get("execution_id"):
        raise ServiceOpenError("CHATOPS_APPROVAL_CHANGED_AFTER_SERVICE_OPEN")

    transaction_dir = Path(args.transaction_state_dir) / _uuid(args.cutover_id, "CUTOVER_ID_INVALID")
    transaction = _read_private_json(
        transaction_dir / "transaction.json", owner_uid=owner_uid,
        code="DNS_TRANSACTION_SUCCESS_RECEIPT_INVALID",
    )
    expected_transaction = {
        "status": dns_transaction.SUCCESS_STATUS,
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
        "target_eip": args.dr_web_eip,
        "dns_records_switched": True,
        "maintenance_mode": True,
        "application_dml_allowed": False,
        "dr_active_recorded": False,
    }
    if any(transaction.get(key) != value for key, value in expected_transaction.items()):
        raise ServiceOpenError("DNS_TRANSACTION_SUCCESS_RECEIPT_MISMATCH")
    if transaction.get("phase") != "COMPLETE_MAINTENANCE_WRITES_BLOCKED":
        raise ServiceOpenError("DNS_TRANSACTION_COMPLETION_UNVERIFIED")
    observed_state = transaction.get("dr_state_observed")
    if observed_state not in {"IDLE", "FAILED"} or state_reader(Path(args.state_file)) != observed_state:
        raise ServiceOpenError("DR_STATE_CHANGED_AFTER_SERVICE_OPEN")

    readiness_path = Path(args.readiness_state_dir) / f"{args.cutover_id}.json"
    readiness = _read_private_json(
        readiness_path, owner_uid=owner_uid, code="PUBLIC_READINESS_RECEIPT_INVALID"
    )
    if any(readiness.get(key) != value for key, value in {
        "status": "DUMP_PUBLIC_READINESS_PREPARED_NOT_DNS_AUTHORIZED",
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
    }.items()):
        raise ServiceOpenError("PUBLIC_READINESS_RECEIPT_MISMATCH")
    token_path = Path(args.readiness_state_dir) / f"{args.cutover_id}.probe-token"
    probe_token = dns_transaction._read_probe_token(token_path, owner_uid=owner_uid)
    if readiness.get("probe_token_path") != str(token_path) or readiness.get("probe_token_sha256") != hashlib.sha256(probe_token.encode("ascii")).hexdigest():
        raise ServiceOpenError("PUBLIC_READINESS_PROBE_TOKEN_MISMATCH")

    token = env.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        raise ServiceOpenError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")
    _verify_live_dns(args, token=token, dns_reader=dns_reader)
    aws_runner = aws_runner or dns_transaction._aws_readonly_runner(env)
    external = _verify_aws_and_sgs(
        args, env, aws_runner, aws_validator=aws_validator,
        app_sg_validator=app_sg_validator,
    )
    cf_cidrs = external["cloudflare_ipv4_cidrs"]
    if public_route_checker is None:
        public_route_checker = lambda **kw: _public_route_check(
            **kw, resolver=dns_transaction._cloudflare_resolved_ipv4,
            transport=dns_transaction._pinned_https_get, sleep=sleep,
        )
    for host in (args.web_domain, args.emr_domain):
        public_route_checker(
            host=host, path="/", expected_status=200,
            cloudflare_ipv4_cidrs=cf_cidrs, attempts=args.health_attempts,
            interval_seconds=args.health_interval_seconds,
        )
        public_health_checker(
            host=host, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
            attempts=args.health_attempts, interval_seconds=args.health_interval_seconds,
        )
    if phase_runner is None:
        phase_runner = lambda phase, expected_binlog=None, expected_db_server_uuid="": run_remote_service_open_phase(
            args, phase, token=probe_token, cloudflare_ipv4_cidrs=cf_cidrs,
            expected_binlog=expected_binlog,
            expected_db_server_uuid=expected_db_server_uuid, environment=env,
        )
    live = phase_runner(
        "verify-live", expected_binlog=None,
        expected_db_server_uuid=opened["db_server_uuid"],
    )
    if not live.get("ok") or live.get("db_server_uuid") != opened["db_server_uuid"]:
        raise ServiceOpenError("FINAL_LIVE_DB_OR_APP_IDENTITY_CHECK_FAILED")
    if state_reader(Path(args.state_file)) != observed_state:
        raise ServiceOpenError("DR_STATE_CHANGED_DURING_FINAL_SERVICE_VERIFY")
    latest_approval = _validate_approval(args, env, now=clock(), approval_validator=approval_validator)
    if latest_approval.get("execution_id") != approval.get("execution_id") or latest_approval.get("approver_ids") != approval.get("approver_ids"):
        raise ServiceOpenError("CHATOPS_APPROVAL_CHANGED_DURING_FINAL_SERVICE_VERIFY")
    verification = {
        "status": "DUMP_FINAL_SERVICE_VERIFIED_NOT_DR_ACTIVE",
        "request_id": args.request_id,
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "isolated_instance_id": args.instance_id,
        "private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "db_server_uuid": opened["db_server_uuid"],
        "approval": {
            "execution_id": latest_approval["execution_id"],
            "approver_ids": list(latest_approval["approver_ids"]),
            "approval_required": 2,
            "approval_count": 2,
        },
        "db_server_uuid_verified": True,
        "web_public_health": 200,
        "emr_public_health": 200,
        "cloudflare_health_204": True,
        "application_writes_allowed": True,
        "maintenance_mode": False,
        "dr_state_changed": False,
        "dr_active_recorded": False,
    }
    verification_path = open_path.parent / "final-service-verification.json"
    _write_receipt(verification_path, verification, owner_uid=owner_uid)
    _emit(
        open_path.parent / f"{args.request_id}.log", args.request_id,
        "final-verify", "PASS_NOT_DR_ACTIVE", owner_uid=owner_uid, logger=print,
    )
    return verification


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
    parser.add_argument("--confirm-service-open", action="store_true")
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
    parser.add_argument("--dr-web-eip", default=os.environ.get("DR_WEB_EIP_EXPECTED", DEFAULT_DR_EIP))
    parser.add_argument("--readiness-state-dir", type=Path, default=Path(os.environ.get("DUMP_DB_PUBLIC_READINESS_STATE_DIR", str(DEFAULT_READINESS_ROOT))))
    parser.add_argument("--transaction-state-dir", type=Path, default=Path(os.environ.get("DUMP_DB_DNS_TRANSACTION_STATE_DIR", str(DEFAULT_TRANSACTION_ROOT))))
    parser.add_argument("--chatops-state-db", type=Path, default=Path(os.environ.get("CHATOPS_STATE_DB", str(DEFAULT_APPROVAL_DB))))
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("DUMP_DB_SERVICE_OPEN_STATE_DIR", str(DEFAULT_STATE_ROOT))))
    parser.add_argument("--service-open-lock-file", type=Path, default=Path(os.environ.get("DUMP_DB_SERVICE_OPEN_LOCK_FILE", str(DEFAULT_STATE_ROOT / ".lock"))))
    parser.add_argument("--health-attempts", type=int, default=3)
    parser.add_argument("--health-interval-seconds", type=int, default=3)
    parser.add_argument("--verify-final-service-open", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = (
            verify_final_service_open(args)
            if args.verify_final_service_open
            else execute_service_open(args)
        )
    except (ServiceOpenError, dns_transaction.DNSTransactionError, dns_preflight.DNSPreflightError, PreflightError) as exc:
        code = str(exc) if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", str(exc)) else "SERVICE_OPEN_BLOCKED"
        print(f"DUMP_SERVICE_OPEN=BLOCKED request_id={args.request_id} reason={code}", file=sys.stderr, flush=True)
        return 1
    print("DUMP_SERVICE_OPEN=" + json.dumps({
        key: result.get(key) for key in (
            "status", "request_id", "cutover_id", "backup_id", "sha256",
            "application_writes_allowed", "maintenance_mode", "dr_active_recorded",
            "user_service_writes_open", "service_account_dml_enabled",
            "rollback_to_prior_database_allowed", "automatic_dns_rollback_allowed",
            "dns_rollback", "operator_intervention_required",
        ) if key in result
    }, sort_keys=True, separators=(",", ":")), flush=True)
    return 0 if result.get("status") in {
        SUCCESS_STATUS,
        PRE_DML_ROLLBACK_STATUS,
        "DUMP_FINAL_SERVICE_VERIFIED_NOT_DR_ACTIVE",
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
