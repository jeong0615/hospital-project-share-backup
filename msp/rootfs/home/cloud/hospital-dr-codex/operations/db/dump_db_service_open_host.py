#!/usr/bin/env python3
"""Isolated-host half of the Dump-only, write-open state machine.

The only DML privileges granted here are INSERT/UPDATE/DELETE on
hospital_db.* for the two exact Web/EMR service source addresses. A durable
write-ahead receipt is fsynced before the first GRANT; after that point this
helper never revokes privileges or authorizes a return to another database.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from . import isolated_db_service_host as dbhost
    from .isolated_restore_host import (
        find_mounted_mysql_source, find_mounted_stage_source, read_instance_metadata,
        read_nvme_volume_serials, validate_target_identity, validate_volume_mount,
    )
except ImportError:  # pragma: no cover - deployed as a standalone remote script
    import isolated_db_service_host as dbhost
    from isolated_restore_host import (
        find_mounted_mysql_source, find_mounted_stage_source, read_instance_metadata,
        read_nvme_volume_serials, validate_target_identity, validate_volume_mount,
    )

SERVICE_USER = dbhost.SERVICE_USER
CLIENTS = dbhost.SERVICE_CLIENT_IPS
WRITE_PRIVILEGES = {"SELECT", "INSERT", "UPDATE", "DELETE"}
SELECT_PRIVILEGES = {"SELECT"}
OPEN_STATUS_ROOT = Path("/var/lib/hospital-dr-dump-restore/status/service-open")
ACCOUNT_HOST_RE = re.compile(r"10\.20\.(?:10|20)\.10\Z")


class ServiceOpenError(RuntimeError):
    """Stable, non-secret reason for refusing a write-open transition."""


def _uuid(value: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ServiceOpenError("REQUEST_ID_INVALID") from exc
    if parsed != value.lower():
        raise ServiceOpenError("REQUEST_ID_INVALID")
    return parsed


def _write_receipt(path: Path, record: dict, *, owner_uid: int) -> None:
    """Use an exclusive, durable receipt for first write and atomic replacement later."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != owner_uid:
        raise ServiceOpenError("SERVICE_OPEN_STATE_DIRECTORY_UNSAFE")
    path.parent.chmod(0o700)
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    if path.exists() or path.is_symlink():
        dbhost._write_status(path, record)
        return
    try:
        fd = __import__("os").open(
            path, __import__("os").O_WRONLY | __import__("os").O_CREAT
            | __import__("os").O_EXCL | getattr(__import__("os"), "O_NOFOLLOW", 0), 0o600,
        )
        with __import__("os").fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            __import__("os").fsync(stream.fileno())
    except FileExistsError as exc:
        raise ServiceOpenError("SERVICE_OPEN_ALREADY_RECORDED") from exc
    except OSError as exc:
        raise ServiceOpenError("SERVICE_OPEN_RECEIPT_WRITE_FAILED") from exc


def _receipt_path(request_id: str, root: Path) -> Path:
    return root / f"{_uuid(request_id)}.json"


def _read_open_receipt(path: Path, *, request_id: str, owner_uid: int) -> dict:
    record = dbhost._read_private_json(
        path, owner_uid=owner_uid, error_code="SERVICE_OPEN_RECEIPT_INVALID"
    )
    if record.get("request_id") != _uuid(request_id):
        raise ServiceOpenError("SERVICE_OPEN_RECEIPT_MISMATCH")
    return record


def _validate_health_receipt(
    *, promotion_id: str, cutover_id: str, backup_id: str, sha256: str,
    instance_id: str, private_ip: str, data_volume_id: str, stage_volume_id: str,
    promotion_root: Path, owner_uid: int,
) -> dict:
    path = promotion_root / f"{dbhost._canonical_uuid(promotion_id, 'SERVICE_PROMOTION_ID_INVALID')}.readonly-health.json"
    health = dbhost._read_private_json(
        path, owner_uid=owner_uid, error_code="READONLY_HEALTH_RECEIPT_INVALID"
    )
    if any((
        health.get("status") != "APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED",
        health.get("promotion_id") != promotion_id,
        health.get("cutover_id") != cutover_id,
        health.get("backup_id") != backup_id,
        str(health.get("expected_sha256", "")).lower() != sha256.lower(),
        health.get("instance_id") != instance_id,
        health.get("private_ip") != private_ip,
        health.get("data_volume_id") != data_volume_id,
        health.get("stage_volume_id") != stage_volume_id,
        health.get("db_port") != dbhost.SERVICE_PORT,
        health.get("db_writable") is not True,
        health.get("service_account_privileges") != {ip: ["SELECT"] for ip in CLIENTS},
        health.get("service_accounts_locked") is not False,
        health.get("application_writes_allowed") is not False,
        health.get("external_traffic_fenced") is not True,
        health.get("dns_authorized") is not False,
        health.get("dr_state_changed") is not False,
    )):
        raise ServiceOpenError("READONLY_HEALTH_RECEIPT_MISMATCH")
    try:
        completed = datetime.fromisoformat(str(health.get("completed_at_utc", "")).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ServiceOpenError("READONLY_HEALTH_RECEIPT_INVALID") from exc
    if completed.tzinfo is None or completed > datetime.now(timezone.utc):
        raise ServiceOpenError("READONLY_HEALTH_RECEIPT_INVALID")
    apps = health.get("apps")
    if not isinstance(apps, dict) or set(apps) != {"web", "emr"}:
        raise ServiceOpenError("READONLY_HEALTH_RECEIPT_MISMATCH")
    for key, host, ip in (("web", "dr-web", "IP_REDACTED"), ("emr", "dr-doc", "IP_REDACTED")):
        app = apps[key]
        if (
            not isinstance(app, dict) or app.get("status") != "PASS"
            or app.get("host") != host or app.get("source_ip") != ip
            or app.get("cutover_id") != cutover_id
            or app.get("db_host") != private_ip or app.get("db_port") != dbhost.SERVICE_PORT
            or app.get("db_server_uuid") != health.get("db_server_uuid")
            or app.get("external_fence") is not True
            or app.get("container_running") is not True
        ):
            raise ServiceOpenError("READONLY_HEALTH_RECEIPT_MISMATCH")
    return health


def _validate_db_state(
    *, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str,
    expected_sha256: str, backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider, data_mount_provider, stage_mount_provider, serial_provider,
    interface_provider, backend, receipt_path: Path, service_receipt_path: Path,
    promotion_root: Path, config_path: Path, owner_uid: int,
    require_locked: bool | None, expected_privileges: set[str] | None = None,
    allow_service_sessions: bool = False,
) -> tuple[dict, dict, dict[str, set[str]], dict[str, str]]:
    if expected_instance_id == dbhost.PRODUCTION_DB_INSTANCE_ID or expected_private_ip in dbhost.PROTECTED_PRIVATE_IPS:
        raise ServiceOpenError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise ServiceOpenError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")
    restore = dbhost.validate_restore_receipt(
        receipt_path, expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip, expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id, expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    if restore.get("request_id") and restore.get("request_id") != cutover_id:
        raise ServiceOpenError("RESTORE_REQUEST_ID_MISMATCH")
    if restore.get("backup_id") != backup_id:
        raise ServiceOpenError("RESTORE_BACKUP_ID_MISMATCH")
    dbhost.validate_service_receipt(
        service_receipt_path, restore=restore, expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip, expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id, expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    promotion, app_fence_path = dbhost._read_write_promotion_receipt(
        promotion_id=promotion_id, cutover_id=cutover_id, restore=restore,
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, promotion_root=promotion_root, owner_uid=owner_uid,
    )
    dbhost._read_app_fence_receipt(
        app_fence_path, promotion_id=promotion_id, cutover_id=cutover_id,
        expected_private_ip=expected_private_ip, owner_uid=owner_uid,
    )
    health = _validate_health_receipt(
        promotion_id=promotion_id, cutover_id=cutover_id, backup_id=backup_id,
        sha256=expected_sha256, instance_id=expected_instance_id, private_ip=expected_private_ip,
        data_volume_id=expected_data_volume_id, stage_volume_id=expected_stage_volume_id,
        promotion_root=promotion_root, owner_uid=owner_uid,
    )
    if config_path.is_symlink() or not config_path.is_file():
        raise ServiceOpenError("SERVICE_MYSQL_CONFIG_INVALID")
    if config_path.stat().st_uid != owner_uid or config_path.stat().st_mode & 0o777 != 0o644:
        raise ServiceOpenError("SERVICE_MYSQL_CONFIG_INVALID")
    if config_path.read_text(encoding="utf-8") != dbhost._expected_config(expected_private_ip):
        raise ServiceOpenError("SERVICE_MYSQL_CONFIG_MISMATCH")

    db = backend or dbhost.ServiceMySQLBackend()
    status = db.status()
    identity = dbhost._readonly_health_identity(db, expected_private_ip=expected_private_ip)
    if (
        identity.get("server_uuid") != health.get("db_server_uuid")
        or identity.get("port") != dbhost.SERVICE_PORT
        or status.get("port") != dbhost.SERVICE_PORT
        or status.get("datadir") != "/var/lib/mysql"
        or set(status.get("bind_addresses", ())) != {"IP_REDACTED", expected_private_ip}
        or status.get("read_only") or status.get("super_read_only")
        or db.table_count() != restore.get("table_count")
        or not dbhost._listener_addresses(db.listener_output(), expected_private_ip, service_ready=True)
    ):
        raise ServiceOpenError("ISOLATED_DB_RUNTIME_IDENTITY_MISMATCH")
    grants = dbhost._parse_service_grants(db.service_account_grants())
    locks = db.service_account_state()
    if set(locks) != set(CLIENTS):
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_STATE_MISMATCH")
    if require_locked is not None:
        expected_locks = "Y" if require_locked else "N"
        if any(locks.get(ip) != expected_locks for ip in CLIENTS):
            raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_STATE_MISMATCH")
    elif any(locks.get(ip) not in {"Y", "N"} for ip in CLIENTS):
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_STATE_MISMATCH")
    expected_privs = expected_privileges if expected_privileges is not None else SELECT_PRIVILEGES
    if any(privileges != expected_privs for privileges in grants.values()):
        raise ServiceOpenError("SERVICE_DB_PRIVILEGE_STATE_MISMATCH")
    if require_locked is None:
        accounts = {(user, host): (locked, plugin) for user, host, locked, plugin in db.account_inventory()}
        expected_service = {(SERVICE_USER, ip) for ip in CLIENTS}
        if (
            not expected_service.issubset(accounts)
            or accounts.get(("root", "localhost")) != ("N", "auth_socket")
            or accounts.get(("hospital_dr_import", "localhost"), ("N", ""))[0] != "Y"
        ):
            raise ServiceOpenError("MYSQL_ACCOUNT_INVENTORY_UNSAFE")
        internal = {"mysql.infoschema", "mysql.session", "mysql.sys"}
        if any(
            (user, host) not in expected_service
            and (user, host) not in {("root", "localhost"), ("hospital_dr_import", "localhost")}
            and not (user in internal and host == "localhost" and locked == "Y")
            for (user, host), (locked, _plugin) in accounts.items()
        ):
            raise ServiceOpenError("MYSQL_ACCOUNT_INVENTORY_UNSAFE")
    else:
        dbhost._verify_health_database_accounts(db, unlocked=not require_locked)
    service_sessions = db.service_account_sessions()
    foreground_sessions = db.foreground_sessions()
    if allow_service_sessions:
        if service_sessions != foreground_sessions:
            raise ServiceOpenError("UNAPPROVED_MYSQL_SESSION_PRESENT")
    elif service_sessions != 0 or foreground_sessions != 0:
        raise ServiceOpenError("MYSQL_ACTIVE_SESSION_PRESENT")
    scheduler, enabled_events = db.event_scheduler_state()
    if scheduler != "OFF" or enabled_events:
        raise ServiceOpenError("MYSQL_BACKGROUND_EVENT_WRITER_PRESENT")
    dbhost._verify_no_scheduled_writer_paths()
    return restore, promotion, grants, locks


def _binlog(db) -> dict:
    text = db.query("SHOW MASTER STATUS").splitlines()
    if len(text) != 1:
        raise ServiceOpenError("MYSQL_BINLOG_STATE_UNAVAILABLE")
    fields = text[0].split("\t")
    if len(fields) < 2 or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", fields[0]) or not fields[1].isdigit() or int(fields[1]) < 1:
        raise ServiceOpenError("MYSQL_BINLOG_STATE_UNAVAILABLE")
    return {"file": fields[0], "position": int(fields[1])}


def verify_write_open_preconditions(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    request_id = _uuid(request_id)
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=False,
        expected_privileges=SELECT_PRIVILEGES, allow_service_sessions=True,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    return {
        "status": "DUMP_SERVICE_OPEN_PRECONDITIONS_VERIFIED",
        "request_id": request_id,
        "db_server_uuid": db.endpoint_identity()["server_uuid"],
        "binlog": _binlog(db),
        "service_account_privileges": {ip: ["SELECT"] for ip in CLIENTS},
        "service_accounts_locked": False,
    }


def verify_no_dml_state(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    expected_binlog: dict,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    locked = False
    if path.exists() or path.is_symlink():
        record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
        if record.get("dml_grant_attempted") is not False or record.get("status") not in {
            "DUMP_SERVICE_OPEN_LOCKING_ACCOUNTS", "DUMP_SERVICE_OPEN_ACCOUNTS_LOCKED",
            "DUMP_SERVICE_OPEN_PRE_DML_FAILED",
        }:
            raise ServiceOpenError("DML_STATE_UNKNOWN_NO_AUTOMATIC_ROLLBACK")
        expected_binlog = record.get("containment_binlog_baseline", expected_binlog)
        locked = record.get("service_accounts_locked") is True or record.get("status") == "DUMP_SERVICE_OPEN_ACCOUNTS_LOCKED"
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=True if locked else False,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    current = _binlog(db)
    if current != expected_binlog:
        raise ServiceOpenError("MYSQL_CHANGED_BEFORE_DML_GRANT")
    grants = dbhost._parse_service_grants(db.service_account_grants())
    if any(privileges != SELECT_PRIVILEGES for privileges in grants.values()):
        raise ServiceOpenError("SERVICE_DB_DML_ALREADY_AVAILABLE")
    return {"status": "DUMP_SERVICE_OPEN_NO_DML_VERIFIED", "binlog": current}


def prepare_accounts_locked(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    if path.exists() or path.is_symlink():
        raise ServiceOpenError("SERVICE_OPEN_ALREADY_RECORDED")
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=False,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    current_grants = dbhost._parse_service_grants(db.service_account_grants())
    if any(privileges != SELECT_PRIVILEGES for privileges in current_grants.values()):
        raise ServiceOpenError("SERVICE_DB_DML_ALREADY_AVAILABLE")
    dbhost._verify_health_database_accounts(db, unlocked=True)
    if db.service_account_sessions() or db.foreground_sessions():
        raise ServiceOpenError("MYSQL_ACTIVE_SESSION_PRESENT")
    # Record intent before changing lock state. This is reversible containment,
    # not a database rollback and never changes grants or DB identity.
    record = {
        "status": "DUMP_SERVICE_OPEN_LOCKING_ACCOUNTS",
        "request_id": request_id, "promotion_id": promotion_id, "cutover_id": cutover_id,
        "backup_id": backup_id, "sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id, "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id, "stage_volume_id": expected_stage_volume_id,
        "db_server_uuid": db.endpoint_identity()["server_uuid"],
        "service_account_privileges": {ip: ["SELECT"] for ip in CLIENTS},
        "service_accounts_locked": True, "dml_grant_attempted": False,
        "automatic_rollback_allowed": True, "dr_state_changed": False,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_receipt(path, record, owner_uid=owner_uid)
    try:
        for ip in CLIENTS:
            db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT LOCK")
        locks = db.service_account_state()
        if set(locks) != set(CLIENTS) or any(locks.get(ip) != "Y" for ip in CLIENTS):
            raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_FAILED")
        if db.service_account_sessions() or db.foreground_sessions():
            raise ServiceOpenError("MYSQL_ACTIVE_SESSION_PRESENT")
        record["status"] = "DUMP_SERVICE_OPEN_ACCOUNTS_LOCKED"
        record["containment_binlog_baseline"] = _binlog(db)
        record["accounts_locked_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_receipt(path, record, owner_uid=owner_uid)
        return record
    except Exception as exc:
        try:
            for ip in CLIENTS:
                db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT LOCK")
            locks = db.service_account_state()
            contained = set(locks) == set(CLIENTS) and all(locks.get(ip) == "Y" for ip in CLIENTS)
        except Exception:
            contained = False
        record.update({
            "status": "DUMP_SERVICE_OPEN_PRE_DML_FAILED",
            "service_accounts_locked": contained,
            "failure_code": str(exc) if isinstance(exc, ServiceOpenError) else "ACCOUNT_LOCK_FAILED",
            "operator_intervention_required": not contained,
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_receipt(path, record, owner_uid=owner_uid)
        if isinstance(exc, ServiceOpenError):
            raise
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_FAILED") from exc


def grant_dml_while_locked(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
    if record.get("status") != "DUMP_SERVICE_OPEN_ACCOUNTS_LOCKED" or record.get("dml_grant_attempted") is not False:
        raise ServiceOpenError("SERVICE_OPEN_STATE_NOT_PREPARED")
    if any((record.get(key) != expected for key, expected in {
        "promotion_id": promotion_id, "cutover_id": cutover_id, "backup_id": backup_id,
        "sha256": expected_sha256.lower(), "instance_id": expected_instance_id,
        "private_ip": expected_private_ip, "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
    }.items())):
        raise ServiceOpenError("SERVICE_OPEN_STATE_MISMATCH")
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=True,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    if _binlog(db) != record.get("containment_binlog_baseline"):
        raise ServiceOpenError("MYSQL_CHANGED_BEFORE_DML_GRANT")
    # Write-ahead boundary: from this durable marker onward all failures are
    # treated as potentially writable. No DNS rollback/retry is safe.
    record.update({
        "status": "DUMP_SERVICE_OPEN_DML_GRANT_STARTED",
        "dml_grant_attempted": True,
        "automatic_rollback_allowed": False,
        "dml_grant_started_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    _write_receipt(path, record, owner_uid=owner_uid)
    try:
        for ip in CLIENTS:
            db.query(
                f"GRANT INSERT, UPDATE, DELETE ON hospital_db.* "
                f"TO '{SERVICE_USER}'@'{ip}'"
            )
        grants = dbhost._parse_service_grants(db.service_account_grants())
        locks = db.service_account_state()
        if (
            any(privileges != WRITE_PRIVILEGES for privileges in grants.values())
            or set(locks) != set(CLIENTS)
            or any(locks.get(ip) != "Y" for ip in CLIENTS)
            or db.service_account_sessions() != 0
        ):
            raise ServiceOpenError("SERVICE_DB_DML_GRANT_VERIFY_FAILED")
        record.update({
            "status": "DUMP_SERVICE_OPEN_DML_GRANTED_ACCOUNTS_LOCKED",
            "service_account_privileges": {ip: sorted(WRITE_PRIVILEGES) for ip in CLIENTS},
            "service_accounts_locked": True,
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_receipt(path, record, owner_uid=owner_uid)
        return record
    except Exception as exc:
        try:
            for ip in CLIENTS:
                db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT LOCK")
        except Exception:
            pass
        record.update({
            "status": "PARTIAL_FAILURE_DML_STATE_UNKNOWN",
            "service_accounts_locked": "UNKNOWN",
            "operator_intervention_required": True,
            "automatic_rollback_allowed": False,
            "failure_code": str(exc) if isinstance(exc, ServiceOpenError) else "DML_GRANT_STATE_UNKNOWN",
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_receipt(path, record, owner_uid=owner_uid)
        if isinstance(exc, ServiceOpenError):
            raise
        raise ServiceOpenError("DML_GRANT_STATE_UNKNOWN") from exc


def unlock_write_accounts(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
    if record.get("status") != "DUMP_SERVICE_OPEN_DML_GRANTED_ACCOUNTS_LOCKED" or record.get("dml_grant_attempted") is not True:
        raise ServiceOpenError("SERVICE_OPEN_DML_GRANT_NOT_VERIFIED")
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=True,
        expected_privileges=WRITE_PRIVILEGES,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    for ip in CLIENTS:
        db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT UNLOCK")
    locks = db.service_account_state()
    grants = dbhost._parse_service_grants(db.service_account_grants())
    if (
        set(locks) != set(CLIENTS) or any(locks.get(ip) != "N" for ip in CLIENTS)
        or any(privileges != WRITE_PRIVILEGES for privileges in grants.values())
        or db.service_account_sessions() != 0
    ):
        record.update({
            "status": "PARTIAL_FAILURE_DML_STATE_UNKNOWN", "service_accounts_locked": "UNKNOWN",
            "operator_intervention_required": True, "automatic_rollback_allowed": False,
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_receipt(path, record, owner_uid=owner_uid)
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_UNLOCK_VERIFY_FAILED")
    record.update({
        "status": "DUMP_SERVICE_OPEN_ACCOUNTS_UNLOCKED_DML_ENABLED",
        "service_account_privileges": {ip: sorted(WRITE_PRIVILEGES) for ip in CLIENTS},
        "service_accounts_locked": False,
        "write_open_binlog_baseline": _binlog(db),
        "automatic_rollback_allowed": False,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    record["binlog"] = record["write_open_binlog_baseline"]
    _write_receipt(path, record, owner_uid=owner_uid)
    return record


def verify_unlocked_write_accounts(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0, allow_service_sessions=False,
) -> dict:
    """Re-read exact DML grants; live mode permits only app service sessions."""
    request_id = _uuid(request_id)
    record = _read_open_receipt(
        _receipt_path(request_id, state_root), request_id=request_id, owner_uid=owner_uid
    )
    if record.get("status") != "DUMP_SERVICE_OPEN_ACCOUNTS_UNLOCKED_DML_ENABLED" or record.get("dml_grant_attempted") is not True:
        raise ServiceOpenError("SERVICE_OPEN_DML_GRANT_NOT_VERIFIED")
    if any((record.get(key) != expected for key, expected in {
        "promotion_id": promotion_id, "cutover_id": cutover_id, "backup_id": backup_id,
        "sha256": expected_sha256.lower(), "instance_id": expected_instance_id,
        "private_ip": expected_private_ip, "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
    }.items())):
        raise ServiceOpenError("SERVICE_OPEN_STATE_MISMATCH")
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=False,
        expected_privileges=WRITE_PRIVILEGES, allow_service_sessions=allow_service_sessions,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    if db.service_account_state() != {ip: "N" for ip in CLIENTS}:
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_UNLOCK_VERIFY_FAILED")
    identity = db.endpoint_identity()
    if identity.get("server_uuid") != record.get("db_server_uuid"):
        raise ServiceOpenError("ISOLATED_DB_RUNTIME_IDENTITY_MISMATCH")
    current_binlog = _binlog(db)
    baseline = record.get("write_open_binlog_baseline")
    if not isinstance(baseline, dict) or current_binlog != baseline:
        raise ServiceOpenError("MYSQL_CHANGED_AFTER_WRITE_OPEN_BEFORE_SERVICE_RELEASE")
    service_sessions = db.service_account_sessions()
    foreground_sessions = db.foreground_sessions()
    if allow_service_sessions:
        if service_sessions != foreground_sessions:
            raise ServiceOpenError("UNAPPROVED_MYSQL_SESSION_PRESENT")
    elif service_sessions != 0 or foreground_sessions != 0:
        raise ServiceOpenError("MYSQL_SESSION_PRESENT_BEFORE_APP_START")
    return {
        "status": "DUMP_SERVICE_OPEN_UNLOCKED_ACCOUNTS_REVERIFIED",
        "db_server_uuid": identity["server_uuid"],
        "binlog": current_binlog,
        "service_account_privileges": {ip: sorted(WRITE_PRIVILEGES) for ip in CLIENTS},
        "service_accounts_locked": False,
        "write_open_binlog_baseline": record.get("write_open_binlog_baseline"),
        "service_account_sessions": service_sessions,
        "foreground_sessions": foreground_sessions,
    }


def contain_after_dml_attempt(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, promotion_root=dbhost.PROMOTION_STATUS_ROOT,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    """Best-effort containment only; never revoke grants, change DNS, or claim rollback."""
    path = _receipt_path(request_id, state_root)
    record = None
    if path.exists() or path.is_symlink():
        record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
        # The controller writes its own durable DML-intent marker before
        # invoking this remote helper. A remote receipt can still say
        # "accounts locked" when SSH failed before the helper ran; that is
        # exactly why containment must relock rather than refuse to act.
        if record.get("status") not in {
            "DUMP_SERVICE_OPEN_ACCOUNTS_LOCKED",
            "DUMP_SERVICE_OPEN_DML_GRANT_STARTED",
            "DUMP_SERVICE_OPEN_DML_GRANTED_ACCOUNTS_LOCKED",
            "DUMP_SERVICE_OPEN_ACCOUNTS_UNLOCKED_DML_ENABLED",
            "PARTIAL_FAILURE_DML_STATE_UNKNOWN",
        }:
            raise ServiceOpenError("SERVICE_OPEN_STATE_NOT_CONTAINABLE")
        if any((record.get(key) != expected for key, expected in {
            "promotion_id": promotion_id, "cutover_id": cutover_id, "backup_id": backup_id,
            "sha256": expected_sha256.lower(), "instance_id": expected_instance_id,
            "private_ip": expected_private_ip, "data_volume_id": expected_data_volume_id,
            "stage_volume_id": expected_stage_volume_id,
        }.items())):
            raise ServiceOpenError("SERVICE_OPEN_STATE_MISMATCH")
    if expected_instance_id == dbhost.PRODUCTION_DB_INSTANCE_ID or expected_private_ip in dbhost.PROTECTED_PRIVATE_IPS:
        raise ServiceOpenError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise ServiceOpenError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")
    db = backend or dbhost.ServiceMySQLBackend()
    health = _validate_health_receipt(
        promotion_id=promotion_id, cutover_id=cutover_id, backup_id=backup_id,
        sha256=expected_sha256, instance_id=expected_instance_id, private_ip=expected_private_ip,
        data_volume_id=expected_data_volume_id, stage_volume_id=expected_stage_volume_id,
        promotion_root=promotion_root, owner_uid=owner_uid,
    )
    identity = dbhost._readonly_health_identity(db, expected_private_ip=expected_private_ip)
    if identity.get("server_uuid") != health.get("db_server_uuid") or identity.get("port") != dbhost.SERVICE_PORT:
        raise ServiceOpenError("ISOLATED_DB_RUNTIME_IDENTITY_MISMATCH")
    if set(db.service_account_state()) != set(CLIENTS):
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_SET_INVALID")
    grants = dbhost._parse_service_grants(db.service_account_grants())
    if set(grants) != set(CLIENTS) or any(
        frozenset(privileges) not in {frozenset(SELECT_PRIVILEGES), frozenset(WRITE_PRIVILEGES)}
        for privileges in grants.values()
    ):
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_SCOPE_UNSAFE")
    locked = False
    try:
        for ip in CLIENTS:
            db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT LOCK")
        state = db.service_account_state()
        locked = set(state) == set(CLIENTS) and all(state.get(ip) == "Y" for ip in CLIENTS)
    except Exception:
        locked = False
    try:
        active_service_sessions = db.service_account_sessions()
        sessions_quiesced = active_service_sessions == 0
    except Exception:
        active_service_sessions = None
        sessions_quiesced = False
    if record is None:
        record = {
            "request_id": request_id, "promotion_id": promotion_id, "cutover_id": cutover_id,
            "backup_id": backup_id, "sha256": expected_sha256.lower(),
            "instance_id": expected_instance_id, "private_ip": expected_private_ip,
            "data_volume_id": expected_data_volume_id, "stage_volume_id": expected_stage_volume_id,
            "db_server_uuid": identity["server_uuid"], "dml_grant_attempted": True,
        }
    record.update({
        "status": "OPERATOR_INTERVENTION_REQUIRED_DML_OPEN_OR_UNKNOWN",
        "service_accounts_locked": locked if locked else "UNKNOWN",
        "active_service_sessions": active_service_sessions,
        "sessions_quiesced": sessions_quiesced,
        "maintenance_mode_required": True,
        "automatic_rollback_allowed": False,
        "operator_intervention_required": True,
        "contained_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    _write_receipt(path, record, owner_uid=owner_uid)
    return record


def contain_before_dml(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    """Fence exact app accounts before DML intent; never changes their grants."""
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    record = None
    if path.exists() or path.is_symlink():
        record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
        if record.get("dml_grant_attempted") is not False:
            raise ServiceOpenError("DML_STATE_UNKNOWN_NO_AUTOMATIC_ROLLBACK")
        if any((record.get(key) != expected for key, expected in {
            "promotion_id": promotion_id, "cutover_id": cutover_id, "backup_id": backup_id,
            "sha256": expected_sha256.lower(), "instance_id": expected_instance_id,
            "private_ip": expected_private_ip, "data_volume_id": expected_data_volume_id,
            "stage_volume_id": expected_stage_volume_id,
        }.items())):
            raise ServiceOpenError("SERVICE_OPEN_STATE_MISMATCH")

    # Validate the AWS identity/volumes/receipts even if the per-operation
    # containment record was never created. A failure here must not target an
    # arbitrary or protected MySQL host.
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid,
        require_locked=None,
        expected_privileges=SELECT_PRIVILEGES,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    grants = dbhost._parse_service_grants(db.service_account_grants())
    if any(privileges != SELECT_PRIVILEGES for privileges in grants.values()):
        raise ServiceOpenError("SERVICE_DB_DML_ALREADY_AVAILABLE")
    for ip in CLIENTS:
        db.query(f"ALTER USER '{SERVICE_USER}'@'{ip}' ACCOUNT LOCK")
    locks = db.service_account_state()
    if set(locks) != set(CLIENTS) or any(locks.get(ip) != "Y" for ip in CLIENTS):
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_LOCK_FAILED")
    if db.service_account_sessions() or db.foreground_sessions():
        raise ServiceOpenError("MYSQL_ACTIVE_SESSION_PRESENT")
    baseline = _binlog(db)
    if record is None:
        record = {
            "request_id": request_id, "promotion_id": promotion_id, "cutover_id": cutover_id,
            "backup_id": backup_id, "sha256": expected_sha256.lower(),
            "instance_id": expected_instance_id, "private_ip": expected_private_ip,
            "data_volume_id": expected_data_volume_id, "stage_volume_id": expected_stage_volume_id,
            "db_server_uuid": db.endpoint_identity()["server_uuid"],
            "dml_grant_attempted": False,
        }
    record.update({
        "status": "DUMP_SERVICE_OPEN_PRE_DML_FAILED",
        "service_account_privileges": {ip: ["SELECT"] for ip in CLIENTS},
        "service_accounts_locked": True,
        "containment_binlog_baseline": baseline,
        "automatic_rollback_allowed": True,
        "dr_state_changed": False,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    _write_receipt(path, record, owner_uid=owner_uid)
    return record


def record_open_success(
    *, request_id: str, expected_instance_id: str, expected_private_ip: str,
    expected_data_volume_id: str, expected_stage_volume_id: str, expected_sha256: str,
    backup_id: str, promotion_id: str, cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source, stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials, interface_provider=dbhost._assigned_ipv4,
    backend=None, receipt_path=dbhost.RESTORE_RESULT, service_receipt_path=dbhost.SERVICE_RESULT,
    promotion_root=dbhost.PROMOTION_STATUS_ROOT, config_path=dbhost.SERVICE_CONFIG,
    state_root=OPEN_STATUS_ROOT, owner_uid=0,
) -> dict:
    """Record verified open state; deliberately does not alter DR state."""
    request_id = _uuid(request_id)
    path = _receipt_path(request_id, state_root)
    record = _read_open_receipt(path, request_id=request_id, owner_uid=owner_uid)
    if record.get("status") != "DUMP_SERVICE_OPEN_ACCOUNTS_UNLOCKED_DML_ENABLED" or record.get("dml_grant_attempted") is not True:
        raise ServiceOpenError("SERVICE_OPEN_DML_GRANT_NOT_VERIFIED")
    if any((record.get(key) != expected for key, expected in {
        "promotion_id": promotion_id, "cutover_id": cutover_id, "backup_id": backup_id,
        "sha256": expected_sha256.lower(), "instance_id": expected_instance_id,
        "private_ip": expected_private_ip, "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
    }.items())):
        raise ServiceOpenError("SERVICE_OPEN_STATE_MISMATCH")
    _validate_db_state(
        expected_instance_id=expected_instance_id, expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id, expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256, backup_id=backup_id, promotion_id=promotion_id,
        cutover_id=cutover_id, identity_provider=identity_provider, data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider, serial_provider=serial_provider,
        interface_provider=interface_provider, backend=backend, receipt_path=receipt_path,
        service_receipt_path=service_receipt_path, promotion_root=promotion_root,
        config_path=config_path, owner_uid=owner_uid, require_locked=False,
        expected_privileges=WRITE_PRIVILEGES, allow_service_sessions=True,
    )
    db = backend or dbhost.ServiceMySQLBackend()
    if db.service_account_state() != {ip: "N" for ip in CLIENTS}:
        raise ServiceOpenError("SERVICE_DB_ACCOUNT_UNLOCK_VERIFY_FAILED")
    record.update({
        "status": "DUMP_SERVICE_OPEN_SUCCESS_NOT_DR_ACTIVE",
        "service_account_privileges": {ip: sorted(WRITE_PRIVILEGES) for ip in CLIENTS},
        "service_accounts_locked": False,
        "automatic_rollback_allowed": False,
        "operator_intervention_required": False,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "dr_state_changed": False,
    })
    _write_receipt(path, record, owner_uid=owner_uid)
    return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "verify", "prepare-accounts", "grant-dml", "unlock-accounts", "verify-unlocked", "verify-live",
        "contain-pre-dml", "record-success",
    ):
        command = sub.add_parser(name)
        for arg in (
            "request-id", "instance-id", "private-ip", "data-volume-id", "stage-volume-id",
            "expected-sha256", "backup-id", "promotion-id", "cutover-id",
        ):
            command.add_argument(f"--{arg}", required=True)
    verify_no_dml = sub.add_parser("verify-no-dml")
    for arg in (
        "request-id", "instance-id", "private-ip", "data-volume-id", "stage-volume-id",
        "expected-sha256", "backup-id", "promotion-id", "cutover-id",
        "expected-binlog-file", "expected-binlog-position",
    ):
        verify_no_dml.add_argument(f"--{arg}", required=True)
    contain = sub.add_parser("contain")
    for arg in (
        "request-id", "instance-id", "private-ip", "data-volume-id", "stage-volume-id",
        "expected-sha256", "backup-id", "promotion-id", "cutover-id",
    ):
        contain.add_argument(f"--{arg}", required=True)
    args = parser.parse_args(argv)
    values = {
        "request_id": args.request_id, "expected_instance_id": getattr(args, "instance_id", ""),
        "expected_private_ip": getattr(args, "private_ip", ""),
        "expected_data_volume_id": getattr(args, "data_volume_id", ""),
        "expected_stage_volume_id": getattr(args, "stage_volume_id", ""),
        "expected_sha256": getattr(args, "expected_sha256", ""),
        "backup_id": getattr(args, "backup_id", ""),
        "promotion_id": getattr(args, "promotion_id", ""), "cutover_id": getattr(args, "cutover_id", ""),
    }
    if args.command == "verify-no-dml":
        values["expected_binlog"] = {
            "file": args.expected_binlog_file,
            "position": int(args.expected_binlog_position),
        }
    try:
        if args.command == "contain":
            result = contain_after_dml_attempt(**values)
        elif args.command == "contain-pre-dml":
            result = contain_before_dml(**values)
        elif args.command == "record-success":
            result = record_open_success(**values)
        elif args.command == "verify-no-dml":
            result = verify_no_dml_state(**values)
        elif args.command == "verify":
            result = verify_write_open_preconditions(**values)
        elif args.command == "prepare-accounts":
            result = prepare_accounts_locked(**values)
        elif args.command == "grant-dml":
            result = grant_dml_while_locked(**values)
        elif args.command == "verify-unlocked":
            result = verify_unlocked_write_accounts(**values)
        elif args.command == "verify-live":
            result = verify_unlocked_write_accounts(**values, allow_service_sessions=True)
        else:
            result = unlock_write_accounts(**values)
        output = {key: result.get(key) for key in (
            "status", "request_id", "cutover_id", "backup_id", "sha256",
            "db_server_uuid", "service_account_privileges", "service_accounts_locked",
            "dml_grant_attempted", "automatic_rollback_allowed", "operator_intervention_required",
            "active_service_sessions", "sessions_quiesced",
            "service_account_sessions", "foreground_sessions",
            "write_open_binlog_baseline",
        ) if key in result}
        binlog = result.get("binlog") or result.get("write_open_binlog_baseline") or result.get("containment_binlog_baseline")
        if isinstance(binlog, dict):
            output["binlog_file"] = binlog.get("file")
            output["binlog_position"] = binlog.get("position")
        print(json.dumps(output, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except (dbhost.RestoreError, ServiceOpenError) as exc:
        code = getattr(exc, "code", None) or str(exc)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code):
            code = "SERVICE_OPEN_BLOCKED"
        print(f"DUMP_SERVICE_OPEN=BLOCKED reason={code}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print("DUMP_SERVICE_OPEN=BLOCKED reason=SERVICE_OPEN_STATE_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
