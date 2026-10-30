#!/usr/bin/env python3
"""Fail-closed service-listener preparation for the isolated Dump DB only."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:  # package import in tests/controller; sibling import on the isolated EC2 host
    from .isolated_restore_host import (
        PRODUCTION_DB_INSTANCE_ID,
        PROTECTED_PRIVATE_IPS,
        RestoreError,
        SystemMySQLBackend,
        _write_status,
        find_mounted_mysql_source,
        find_mounted_stage_source,
        read_instance_metadata,
        read_nvme_volume_serials,
        validate_target_identity,
        validate_volume_mount,
    )
except ImportError:  # pragma: no cover - exercised by the remote CLI
    from isolated_restore_host import (
        PRODUCTION_DB_INSTANCE_ID,
        PROTECTED_PRIVATE_IPS,
        RestoreError,
        SystemMySQLBackend,
        _write_status,
        find_mounted_mysql_source,
        find_mounted_stage_source,
        read_instance_metadata,
        read_nvme_volume_serials,
        validate_target_identity,
        validate_volume_mount,
    )

SERVICE_PORT = 3307
SERVICE_USER = "hospital_dr_service"
SERVICE_CLIENT_IPS = ("IP_REDACTED", "IP_REDACTED")
RESTORE_RESULT = Path("/var/lib/hospital-dr-dump-restore/status/restore.json")
SERVICE_RESULT = Path("/var/lib/hospital-dr-dump-restore/status/service.json")
PROMOTION_STATUS_ROOT = Path("/var/lib/hospital-dr-dump-restore/status/promotions")
SERVICE_CONFIG = Path("/etc/mysql/mysql.conf.d/zz-hospital-dr-service-listener.cnf")
APP_CUTOVER_ROOT = Path("/var/lib/hospital-dr/db-endpoint-cutovers")
BACKUP_ID_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def validate_restore_receipt(
    path: Path,
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_request_id: str | None = None,
    owner_uid: int = 0,
) -> dict:
    """Accept only a root-owned, private, successful receipt for this exact restore."""
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID:
        raise RestoreError("PRODUCTION_DB_TARGET_FORBIDDEN")
    if expected_private_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DB_IP_FORBIDDEN")
    if not SHA256_RE.fullmatch(expected_sha256.lower()):
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_INVALID")
    if path != RESTORE_RESULT or path.is_symlink() or not path.is_file():
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_MISSING")
    metadata = path.stat()
    if (
        metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size < 2
        or metadata.st_size > 65536
    ):
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_PERMISSIONS_INVALID")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        completed = datetime.fromisoformat(str(record.get("completed_at_utc", "")).replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_INVALID") from exc
    if completed.tzinfo is None or completed > datetime.now(timezone.utc):
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_TIMESTAMP_INVALID")
    if (
        record.get("status") != "SUCCESS"
        or record.get("instance_id") != expected_instance_id
        or record.get("private_ip") != expected_private_ip
        or record.get("data_volume_id") != expected_data_volume_id
        or record.get("stage_volume_id") != expected_stage_volume_id
        or str(record.get("expected_sha256", "")).lower() != expected_sha256.lower()
        or (expected_request_id is not None and record.get("request_id") != expected_request_id)
        or not BACKUP_ID_RE.fullmatch(str(record.get("backup_id", "")))
        or not isinstance(record.get("table_count"), int)
        or record["table_count"] < 1
        or not re.fullmatch(r"[A-Za-z0-9._-]+", str(record.get("master_status_file", "")))
        or not isinstance(record.get("master_status_position"), int)
        or record["master_status_position"] < 1
    ):
        raise RestoreError("RESTORE_SUCCESS_RECEIPT_MISMATCH")
    return record


def validate_service_receipt(
    path: Path,
    *,
    restore: dict,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    owner_uid: int = 0,
) -> dict:
    if path != SERVICE_RESULT or path.is_symlink() or not path.is_file():
        raise RestoreError("SERVICE_PREPARED_RECEIPT_INVALID")
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_size < 2 or metadata.st_size > 65536:
        raise RestoreError("SERVICE_PREPARED_RECEIPT_INVALID")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        completed = datetime.fromisoformat(str(record.get("completed_at_utc", "")).replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RestoreError("SERVICE_PREPARED_RECEIPT_INVALID") from exc
    if (
        completed.tzinfo is None
        or completed > datetime.now(timezone.utc)
        or record.get("status") != "SUCCESS"
        or record.get("service_prepared") is not True
        or record.get("instance_id") != expected_instance_id
        or record.get("private_ip") != expected_private_ip
        or record.get("data_volume_id") != expected_data_volume_id
        or record.get("stage_volume_id") != expected_stage_volume_id
        or str(record.get("expected_sha256", "")).lower() != expected_sha256.lower()
        or record.get("backup_id") != restore.get("backup_id")
        or record.get("request_id", "") != restore.get("request_id", "")
        or record.get("mysql_port") != SERVICE_PORT
        or record.get("bind_addresses") != ["IP_REDACTED", expected_private_ip]
        or record.get("read_only") is not True
        or record.get("super_read_only") is not True
    ):
        raise RestoreError("SERVICE_PREPARED_RECEIPT_MISMATCH")
    return record


def _mysql_version_supported(version: str) -> bool:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+.]|$)", version)
    return bool(match and tuple(map(int, match.groups())) >= (8, 0, 13) and "mariadb" not in version.lower())


def _listener_addresses(output: str, private_ip: str, *, service_ready: bool) -> bool:
    mysql = set()
    mysqlx = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address = fields[3]
        if address.endswith(":3306"):
            return False
        if address.endswith(":3307"):
            mysql.add(address)
        elif address.endswith(":33060"):
            mysqlx.add(address)
    expected_mysql = {"IP_REDACTED:3307"}
    if service_ready:
        expected_mysql.add(f"{private_ip}:3307")
    return mysql == expected_mysql and mysqlx.issubset({"IP_REDACTED:33060"})


def _assigned_ipv4(private_ip: str, runner=subprocess.run) -> bool:
    result = runner(["ip", "-o", "-4", "addr", "show"], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RestoreError("ISOLATED_INTERFACE_CHECK_FAILED")
    return any(
        len(fields) > 3 and fields[3].split("/", 1)[0] == private_ip
        for fields in (line.split() for line in result.stdout.splitlines())
    )


def _mysql_literal(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", value):
        raise RestoreError("SERVICE_DB_PASSWORD_INVALID")
    return f"'{value}'"


def read_service_password(path: Path, *, owner_uid: int = 0) -> str:
    if path.is_symlink() or not path.is_file():
        raise RestoreError("SERVICE_DB_PASSWORD_FILE_UNAVAILABLE")
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_size < 32 or metadata.st_size > 4096:
        raise RestoreError("SERVICE_DB_PASSWORD_FILE_PERMISSIONS_INVALID")
    try:
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as exc:
        raise RestoreError("SERVICE_DB_PASSWORD_FILE_UNAVAILABLE") from exc
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", value):
        raise RestoreError("SERVICE_DB_PASSWORD_INVALID")
    return value


class ServiceMySQLBackend(SystemMySQLBackend):
    def status(self) -> dict:
        fields = self.query(
            "SELECT VERSION(), @@port, @@datadir, @@bind_address, @@read_only, @@super_read_only"
        ).split("\t")
        if len(fields) != 6:
            raise RestoreError("ISOLATED_MYSQL_STATUS_INVALID")
        version, port, datadir, bind_address, read_only, super_read_only = fields
        if port != str(SERVICE_PORT) or os.path.realpath(datadir) != "/var/lib/mysql":
            raise RestoreError("ISOLATED_MYSQL_RUNTIME_MISMATCH")
        if not _mysql_version_supported(version):
            raise RestoreError("MYSQL_MULTI_BIND_VERSION_UNSUPPORTED")
        return {
            "version": version,
            "port": int(port),
            "datadir": os.path.realpath(datadir),
            "bind_addresses": tuple(part.strip() for part in bind_address.split(",") if part.strip()),
            "read_only": read_only == "1",
            "super_read_only": super_read_only == "1",
        }

    def listener_output(self) -> str:
        result = subprocess.run(["ss", "-lntH"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RestoreError("MYSQL_LISTENER_CHECK_FAILED")
        return result.stdout

    def table_count(self) -> int:
        value = self.query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA='hospital_db' AND TABLE_TYPE='BASE TABLE'"
        )
        if not value.isdigit() or int(value) < 1:
            raise RestoreError("RESTORED_SCHEMA_HAS_NO_TABLES")
        return int(value)

    def create_service_accounts(self, password: str) -> None:
        literal = _mysql_literal(password)
        statements = []
        for client_ip in SERVICE_CLIENT_IPS:
            statements.extend((
                f"CREATE USER IF NOT EXISTS '{SERVICE_USER}'@'{client_ip}' IDENTIFIED BY {literal};",
                f"ALTER USER '{SERVICE_USER}'@'{client_ip}' IDENTIFIED BY {literal};",
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON hospital_db.* TO '{SERVICE_USER}'@'{client_ip}';",
            ))
        command = ["mysql", "--protocol=socket", "-uroot", "--batch"]
        result = subprocess.run(
            command,
            input="\n".join(statements) + "\n",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            raise RestoreError("SERVICE_DB_ACCOUNT_PREPARATION_FAILED")

    def service_account_grants(self) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for client_ip in SERVICE_CLIENT_IPS:
            output = self.query(f"SHOW GRANTS FOR '{SERVICE_USER}'@'{client_ip}'")
            values[client_ip] = [line.strip() for line in output.splitlines() if line.strip()]
        return values

    def service_account_state(self) -> dict[str, str]:
        output = self.query(
            "SELECT CONCAT(host, '\\t', account_locked) FROM mysql.user "
            "WHERE user='hospital_dr_service' ORDER BY host"
        )
        values: dict[str, str] = {}
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) == 2:
                values[fields[0]] = fields[1]
        return values

    def service_account_sessions(self) -> int:
        value = self.query(
            "SELECT COUNT(*) FROM information_schema.processlist "
            "WHERE USER='hospital_dr_service'"
        )
        if not value.isdigit():
            raise RestoreError("SERVICE_DB_SESSION_COUNT_INVALID")
        return int(value)

    def account_inventory(self) -> list[tuple[str, str, str, str]]:
        output = self.query(
            "SELECT CONCAT(user, '\\t', host, '\\t', account_locked, '\\t', plugin) "
            "FROM mysql.user ORDER BY user, host"
        )
        rows = []
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) != 4:
                raise RestoreError("MYSQL_ACCOUNT_INVENTORY_INVALID")
            rows.append(tuple(fields))
        if not rows:
            raise RestoreError("MYSQL_ACCOUNT_INVENTORY_INVALID")
        return rows

    def foreground_sessions(self) -> int:
        value = self.query(
            "SELECT COUNT(*) FROM performance_schema.threads "
            "WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID IS NOT NULL "
            "AND PROCESSLIST_ID <> CONNECTION_ID()"
        )
        if not value.isdigit():
            raise RestoreError("MYSQL_FOREGROUND_SESSION_COUNT_INVALID")
        return int(value)

    def event_scheduler_state(self) -> tuple[str, int]:
        fields = self.query(
            "SELECT @@event_scheduler, "
            "(SELECT COUNT(*) FROM information_schema.EVENTS WHERE STATUS='ENABLED')"
        ).split("\t")
        if len(fields) != 2 or not fields[1].isdigit():
            raise RestoreError("MYSQL_EVENT_SCHEDULER_STATE_INVALID")
        return fields[0].upper(), int(fields[1])

    def endpoint_identity(self) -> dict[str, str | int]:
        fields = self.query(
            "SELECT @@server_uuid, @@hostname, @@port, @@datadir"
        ).split("\t")
        if len(fields) != 4 or not fields[0] or not fields[1]:
            raise RestoreError("MYSQL_ENDPOINT_IDENTITY_INVALID")
        if not fields[2].isdigit():
            raise RestoreError("MYSQL_ENDPOINT_IDENTITY_INVALID")
        return {
            "server_uuid": fields[0].lower(),
            "hostname": fields[1],
            "port": int(fields[2]),
            "datadir": os.path.realpath(fields[3]),
        }

    def non_admin_sessions(self) -> list[tuple[str, str, str]]:
        output = self.query(
            "SELECT CONCAT(USER, '\\t', COALESCE(HOST, ''), '\\t', COALESCE(DB, '')) "
            "FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID() "
            "ORDER BY USER, HOST, DB"
        )
        rows = []
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                raise RestoreError("MYSQL_SESSION_INVENTORY_INVALID")
            rows.append(tuple(fields))
        return rows

    def table_integrity_check(self) -> None:
        result = subprocess.run(
            ["mysqlcheck", "--protocol=socket", "-uroot", "--check", "hospital_db"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            raise RestoreError("MYSQL_TABLE_INTEGRITY_CHECK_FAILED")


def _verify_no_scheduled_writer_paths(runner=subprocess.run, *, cron_directories=None, cron_spool=None) -> None:
    """Fail closed on non-standard timers or any user cron entry on the isolated DB."""
    try:
        services = runner(
            ["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
    if services.returncode != 0:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE")
    for line in services.stdout.splitlines():
        unit = line.split()[0].lower() if line.split() else ""
        if any(token in unit for token in ("hospital", "pm2", "backup", "replica", "dump-restore")):
            raise RestoreError("UNAPPROVED_BACKGROUND_SERVICE_PRESENT")

    try:
        containers = runner(
            ["/bin/bash", "-c", "if ! command -v docker >/dev/null 2>&1; then exit 77; fi; docker ps -q"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
    if containers.returncode not in (0, 77) or containers.stdout.strip():
        raise RestoreError("UNAPPROVED_BACKGROUND_CONTAINER_PRESENT")

    try:
        timers = runner(
            ["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
    if timers.returncode != 0:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE")
    safe_timers = {
        "apt-daily.timer", "apt-daily-upgrade.timer", "fstrim.timer",
        "logrotate.timer", "man-db.timer", "motd-news.timer",
        "systemd-tmpfiles-clean.timer", "ua-timer.timer",
    }
    for line in timers.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        timer = next((field for field in reversed(fields) if field.endswith(".timer")), "")
        if not timer or timer not in safe_timers:
            raise RestoreError("UNAPPROVED_SYSTEMD_TIMER_PRESENT")
    for user in ("root", "mysql", "ubuntu"):
        try:
            cron = runner(
                ["crontab", "-l", "-u", user],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
        if cron.returncode not in (0, 1):
            raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE")
        if any(line.strip() and not line.lstrip().startswith("#") for line in cron.stdout.splitlines()):
            raise RestoreError("UNAPPROVED_CRON_JOB_PRESENT")
    safe_cron_jobs = {
        "apt-compat", "dpkg", "e2scrub_all", "logrotate", "man-db", "passwd", "sysstat",
    }
    spool = Path("/var/spool/cron/crontabs") if cron_spool is None else Path(cron_spool)
    try:
        spool_entries = list(spool.iterdir()) if spool.is_dir() else []
    except OSError as exc:
        raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
    if spool_entries:
        raise RestoreError("UNAPPROVED_CRON_JOB_PRESENT")
    directories = cron_directories or (
        Path("/etc/cron.d"), Path("/etc/cron.hourly"), Path("/etc/cron.daily"),
        Path("/etc/cron.weekly"), Path("/etc/cron.monthly"),
    )
    for directory in directories:
        try:
            entries = list(directory.iterdir()) if directory.is_dir() else []
        except OSError as exc:
            raise RestoreError("BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
        for entry in entries:
            if entry.name == ".placeholder":
                continue
            if entry.is_symlink() or not entry.is_file() or entry.name not in safe_cron_jobs:
                raise RestoreError("UNAPPROVED_SYSTEM_CRON_JOB_PRESENT")


def _expected_config(private_ip: str, *, quarantine: bool = False) -> str:
    address = "IP_REDACTED" if quarantine else f"IP_REDACTED,{private_ip}"
    return (
        "# Managed by Hospital DR isolated DB service preparation. Do not edit.\n"
        "[mysqld]\n"
        f"bind-address = {address}\n"
        f"port = {SERVICE_PORT}\n"
        "datadir = /var/lib/mysql\n"
        "mysqlx-bind-address = IP_REDACTED\n"
        "local_infile = 0\n"
        "read_only = ON\n"
        "super_read_only = ON\n"
    )


def _write_managed_config(path: Path, content: str, *, allowed_existing: set[str] | None = None) -> None:
    if path.is_symlink():
        raise RestoreError("SERVICE_MYSQL_CONFIG_SYMLINK_FORBIDDEN")
    if path.exists():
        current = path.read_text(encoding="utf-8")
        if current not in (allowed_existing or set()):
            raise RestoreError("SERVICE_MYSQL_CONFIG_ALREADY_PRESENT")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".hospital-dr-mysql-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o644)
    finally:
        temporary.unlink(missing_ok=True)


def _restart_mysql(runner=subprocess.run) -> None:
    result = runner(
        ["systemctl", "restart", "mysql"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RestoreError("MYSQL_SERVICE_RESTART_FAILED")


def _write_service_receipt(record: dict, path: Path = SERVICE_RESULT) -> None:
    _write_status(path, record)


def _canonical_uuid(value: str, code: str) -> str:
    import uuid

    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise RestoreError(code) from exc
    if str(parsed) != value.lower():
        raise RestoreError(code)
    return str(parsed)


def _promotion_paths(promotion_id: str, root: Path = PROMOTION_STATUS_ROOT) -> tuple[Path, Path]:
    normalized = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    return (
        root / f"{normalized}.apps-fenced.json",
        root / f"{normalized}.json",
    )


def _read_private_json(path: Path, *, owner_uid: int, error_code: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise RestoreError(error_code)
    metadata = path.stat()
    if (
        metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 2
        or metadata.st_size > 65536
    ):
        raise RestoreError(error_code)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RestoreError(error_code) from exc
    if not isinstance(value, dict):
        raise RestoreError(error_code)
    return value


def _read_app_fence_receipt(
    path: Path,
    *,
    promotion_id: str,
    cutover_id: str,
    expected_private_ip: str,
    owner_uid: int,
) -> dict:
    normalized_promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    normalized_cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    expected_path, _ = _promotion_paths(normalized_promotion_id, path.parent)
    if path != expected_path:
        raise RestoreError("APP_WRITE_FENCE_RECEIPT_INVALID")
    record = _read_private_json(
        path, owner_uid=owner_uid, error_code="APP_WRITE_FENCE_RECEIPT_INVALID"
    )
    try:
        completed = datetime.fromisoformat(str(record.get("completed_at_utc", "")).replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise RestoreError("APP_WRITE_FENCE_RECEIPT_INVALID") from exc
    if (
        completed.tzinfo is None
        or completed > datetime.now(timezone.utc)
        or record.get("status") != "APPS_FENCED"
        or record.get("promotion_id") != normalized_promotion_id
        or record.get("cutover_id") != normalized_cutover_id
    ):
        raise RestoreError("APP_WRITE_FENCE_RECEIPT_MISMATCH")
    apps = record.get("apps")
    if not isinstance(apps, dict) or set(apps) != {"web", "emr"}:
        raise RestoreError("APP_WRITE_FENCE_RECEIPT_MISMATCH")
    expected = {
        "web": ("dr-web", "IP_REDACTED"),
        "emr": ("dr-doc", "IP_REDACTED"),
    }
    for name, (host, source_ip) in expected.items():
        app = apps[name]
        if (
            not isinstance(app, dict)
            or app.get("host") != host
            or app.get("source_ip") != source_ip
            or app.get("container_id") is None
            or not re.fullmatch(r"[0-9a-f]{64}", str(app.get("container_id", "")))
            or app.get("cutover_id") != normalized_cutover_id
            or app.get("db_host") != expected_private_ip
            or app.get("db_port") != SERVICE_PORT
            or app.get("db_user") != SERVICE_USER
            or app.get("db_name") != "hospital_db"
            or app.get("health_probe") != "PASS"
            or app.get("stopped") is not True
        ):
            raise RestoreError("APP_WRITE_FENCE_RECEIPT_MISMATCH")
    return record


def _read_write_promotion_receipt(
    *,
    promotion_id: str,
    cutover_id: str,
    restore: dict,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    promotion_root: Path,
    owner_uid: int,
) -> tuple[dict, Path]:
    app_path, result_path = _promotion_paths(promotion_id, promotion_root)
    record = _read_private_json(
        result_path, owner_uid=owner_uid, error_code="WRITE_PROMOTION_RECEIPT_INVALID"
    )
    try:
        completed = datetime.fromisoformat(
            str(record.get("completed_at_utc", "")).replace("Z", "+00:00")
        )
    except (ValueError, TypeError) as exc:
        raise RestoreError("WRITE_PROMOTION_RECEIPT_INVALID") from exc
    grants = record.get("service_account_privileges")
    expected_grants = {ip: ["SELECT"] for ip in SERVICE_CLIENT_IPS}
    if (
        completed.tzinfo is None
        or completed > datetime.now(timezone.utc)
        or record.get("status") != "WRITE_PROMOTED_APPS_FENCED"
        or record.get("promotion_id") != promotion_id
        or record.get("cutover_id") != cutover_id
        or record.get("backup_id") != restore.get("backup_id")
        or str(record.get("expected_sha256", "")).lower() != expected_sha256.lower()
        or record.get("instance_id") != expected_instance_id
        or record.get("private_ip") != expected_private_ip
        or record.get("data_volume_id") != expected_data_volume_id
        or record.get("stage_volume_id") != expected_stage_volume_id
        or record.get("apps_fenced") is not True
        or record.get("db_writable") is not True
        or record.get("service_accounts_locked") is not True
        or record.get("application_writes_allowed") is not False
        or record.get("dns_authorized") is not False
        or grants != expected_grants
        or (
            bool(restore.get("request_id"))
            and (restore.get("request_id") != promotion_id or restore.get("request_id") != cutover_id)
        )
    ):
        raise RestoreError("WRITE_PROMOTION_RECEIPT_MISMATCH")
    return record, app_path


def _verify_closed_database_accounts(db) -> None:
    rows = db.account_inventory()
    accounts = {(user, host): (locked, plugin) for user, host, locked, plugin in rows}
    expected_service = {(SERVICE_USER, ip) for ip in SERVICE_CLIENT_IPS}
    if not expected_service.issubset(accounts):
        raise RestoreError("SERVICE_DB_ACCOUNT_SET_INVALID")
    if any(accounts[(SERVICE_USER, ip)][0] != "Y" for ip in SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_ACCOUNT_UNLOCKED")
    root = accounts.get(("root", "localhost"))
    if root != ("N", "auth_socket"):
        raise RestoreError("MYSQL_LOCAL_ROOT_AUTH_CONTRACT_UNSAFE")
    import_account = accounts.get(("hospital_dr_import", "localhost"))
    if not import_account or import_account[0] != "Y":
        raise RestoreError("MYSQL_IMPORT_ACCOUNT_NOT_LOCKED")
    internal = {"mysql.infoschema", "mysql.session", "mysql.sys"}
    for key, (locked, _plugin) in accounts.items():
        user, host = key
        if key in expected_service or key in {
            ("root", "localhost"), ("hospital_dr_import", "localhost")
        }:
            continue
        if user in internal and host == "localhost" and locked == "Y":
            continue
        # No unknown or remotely-addressable account can retain a write path.
        raise RestoreError("MYSQL_UNAPPROVED_ACCOUNT_PRESENT")


def _verify_health_database_accounts(db, *, unlocked: bool) -> None:
    rows = db.account_inventory()
    accounts = {(user, host): (locked, plugin) for user, host, locked, plugin in rows}
    expected_service = {(SERVICE_USER, ip) for ip in SERVICE_CLIENT_IPS}
    if not expected_service.issubset(accounts):
        raise RestoreError("SERVICE_DB_ACCOUNT_SET_INVALID")
    expected_lock = "N" if unlocked else "Y"
    if any(accounts[(SERVICE_USER, ip)][0] != expected_lock for ip in SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_ACCOUNT_LOCK_STATE_MISMATCH")
    if accounts.get(("root", "localhost")) != ("N", "auth_socket"):
        raise RestoreError("MYSQL_LOCAL_ROOT_AUTH_CONTRACT_UNSAFE")
    importer = accounts.get(("hospital_dr_import", "localhost"))
    if not importer or importer[0] != "Y":
        raise RestoreError("MYSQL_IMPORT_ACCOUNT_NOT_LOCKED")
    internal = {"mysql.infoschema", "mysql.session", "mysql.sys"}
    for key, (locked, _plugin) in accounts.items():
        user, host = key
        if key in expected_service or key in {
            ("root", "localhost"), ("hospital_dr_import", "localhost")
        }:
            continue
        if user in internal and host == "localhost" and locked == "Y":
            continue
        raise RestoreError("MYSQL_UNAPPROVED_ACCOUNT_PRESENT")


def _readonly_health_identity(db, *, expected_private_ip: str) -> dict:
    identity = db.endpoint_identity()
    try:
        normalized_uuid = str(__import__("uuid").UUID(str(identity.get("server_uuid", ""))))
    except (ValueError, TypeError, AttributeError) as exc:
        raise RestoreError("MYSQL_ENDPOINT_IDENTITY_INVALID") from exc
    if (
        normalized_uuid != str(identity.get("server_uuid", "")).lower()
        or identity.get("port") != SERVICE_PORT
        or identity.get("datadir") != "/var/lib/mysql"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", str(identity.get("hostname", "")))
        or expected_private_ip in PROTECTED_PRIVATE_IPS
    ):
        raise RestoreError("MYSQL_ENDPOINT_IDENTITY_MISMATCH")
    return identity


def verify_readonly_health_preconditions(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_backup_id: str,
    promotion_id: str,
    cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
    background_job_check=_verify_no_scheduled_writer_paths,
) -> dict:
    """Recheck the exact fenced state immediately before app activation."""
    current = verify_dump_dns_preflight(
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        expected_backup_id=expected_backup_id,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        identity_provider=identity_provider,
        data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider,
        serial_provider=serial_provider,
        backend=backend,
        interface_provider=interface_provider,
        receipt_path=receipt_path,
        service_receipt_path=service_receipt_path,
        config_path=config_path,
        promotion_root=promotion_root,
        owner_uid=owner_uid,
        background_job_check=background_job_check,
    )
    receipt_path = promotion_root / f"{_canonical_uuid(promotion_id, 'SERVICE_PROMOTION_ID_INVALID')}.readonly-health.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        raise RestoreError("READONLY_HEALTH_ALREADY_RECORDED")
    db = backend or ServiceMySQLBackend()
    identity = _readonly_health_identity(db, expected_private_ip=expected_private_ip)
    return {**current, "db_identity": identity}


def unlock_readonly_health_accounts(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_backup_id: str,
    promotion_id: str,
    cutover_id: str,
    **kwargs,
) -> dict:
    """Unlock only SELECT-only Web/EMR accounts for the fenced health window."""
    gate = verify_readonly_health_preconditions(
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        expected_backup_id=expected_backup_id,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        **kwargs,
    )
    db = kwargs.get("backend") or ServiceMySQLBackend()
    grants = _parse_service_grants(db.service_account_grants())
    if any(privileges != {"SELECT"} for privileges in grants.values()):
        raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
    _verify_health_database_accounts(db, unlocked=False)
    if db.non_admin_sessions():
        raise RestoreError("MYSQL_ACTIVE_SESSION_PRESENT")

    try:
        for client_ip in SERVICE_CLIENT_IPS:
            db.query(f"ALTER USER '{SERVICE_USER}'@'{client_ip}' ACCOUNT UNLOCK")
        account_state = db.service_account_state()
        if set(account_state) != set(SERVICE_CLIENT_IPS) or any(
            account_state[ip] != "N" for ip in SERVICE_CLIENT_IPS
        ):
            raise RestoreError("SERVICE_DB_READONLY_UNLOCK_VERIFY_FAILED")
        _verify_health_database_accounts(db, unlocked=True)
        restricted = _parse_service_grants(db.service_account_grants())
        if any(privileges != {"SELECT"} for privileges in restricted.values()):
            raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
        if db.status()["read_only"] or db.status()["super_read_only"]:
            raise RestoreError("MYSQL_WRITE_PROMOTION_STATE_CHANGED")
        if db.non_admin_sessions():
            raise RestoreError("MYSQL_UNEXPECTED_SESSION_PRESENT")
        return {"db_identity": gate["db_identity"], "service_accounts": "UNLOCKED_SELECT_ONLY"}
    except (RestoreError, OSError, subprocess.SubprocessError) as exc:
        try:
            for client_ip in SERVICE_CLIENT_IPS:
                db.query(f"ALTER USER '{SERVICE_USER}'@'{client_ip}' ACCOUNT LOCK")
            state = db.service_account_state()
            if set(state) != set(SERVICE_CLIENT_IPS) or any(state[ip] != "Y" for ip in SERVICE_CLIENT_IPS):
                raise RestoreError("SERVICE_DB_READONLY_LOCK_VERIFY_FAILED")
        except (RestoreError, OSError, subprocess.SubprocessError) as rollback_error:
            raise RestoreError("READONLY_HEALTH_ACCOUNT_ROLLBACK_FAILED") from rollback_error
        if isinstance(exc, RestoreError):
            raise
        raise RestoreError("SERVICE_DB_READONLY_UNLOCK_FAILED") from exc


def relock_readonly_health_accounts(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    backend=None,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    interface_provider=_assigned_ipv4,
) -> dict:
    """Rollback path: lock the two app accounts without changing DB write mode."""
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID or expected_private_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    db = backend or ServiceMySQLBackend()
    for client_ip in SERVICE_CLIENT_IPS:
        db.query(f"ALTER USER '{SERVICE_USER}'@'{client_ip}' ACCOUNT LOCK")
    state = db.service_account_state()
    if set(state) != set(SERVICE_CLIENT_IPS) or any(state[ip] != "Y" for ip in SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_READONLY_LOCK_VERIFY_FAILED")
    if db.non_admin_sessions():
        raise RestoreError("SERVICE_DB_SESSION_REMAINS_AFTER_APP_STOP")
    return {"service_accounts": "LOCKED_VERIFIED"}


def record_readonly_health_receipt(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_backup_id: str,
    promotion_id: str,
    cutover_id: str,
    expected_db_server_uuid: str,
    apps: dict,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
    background_job_check=_verify_no_scheduled_writer_paths,
) -> dict:
    """Persist a distinct, non-authorizing receipt only after both apps pass."""
    promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    expected_path = promotion_root / f"{promotion_id}.readonly-health.json"
    if expected_path.exists() or expected_path.is_symlink():
        raise RestoreError("READONLY_HEALTH_ALREADY_RECORDED")
    if not SHA256_RE.fullmatch(expected_sha256.lower()):
        raise RestoreError("EXPECTED_CHECKSUM_INVALID")
    if not isinstance(apps, dict) or set(apps) != {"web", "emr"}:
        raise RestoreError("READONLY_HEALTH_APP_RECEIPT_INVALID")
    for kind, host, source in (
        ("web", "dr-web", "IP_REDACTED"),
        ("emr", "dr-doc", "IP_REDACTED"),
    ):
        app = apps[kind]
        if (
            not isinstance(app, dict)
            or app.get("status") != "PASS"
            or app.get("host") != host
            or app.get("source_ip") != source
            or app.get("cutover_id") != cutover_id
            or app.get("db_host") != expected_private_ip
            or app.get("db_port") != SERVICE_PORT
            or app.get("db_server_uuid") != expected_db_server_uuid
            or app.get("health_endpoint") != "/__hospital_dr/health"
            or app.get("external_fence") is not True
            or app.get("container_running") is not True
            or app.get("restart_policy") != "no"
            or app.get("select_only_probe") is not True
        ):
            raise RestoreError("READONLY_HEALTH_APP_RECEIPT_INVALID")

    # Revalidate all data/identity receipts. The earlier locked-account gate is
    # expected to fail now, so validate the immutable source records directly.
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID or expected_private_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise RestoreError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")
    restore = validate_restore_receipt(
        receipt_path,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    if restore.get("request_id") and restore.get("request_id") != cutover_id:
        raise RestoreError("RESTORE_REQUEST_ID_MISMATCH")
    if restore.get("backup_id") != expected_backup_id:
        raise RestoreError("RESTORE_BACKUP_ID_MISMATCH")
    validate_service_receipt(
        service_receipt_path,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    promotion, app_path = _read_write_promotion_receipt(
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        promotion_root=promotion_root,
        owner_uid=owner_uid,
    )
    _read_app_fence_receipt(
        app_path,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        expected_private_ip=expected_private_ip,
        owner_uid=owner_uid,
    )
    db = backend or ServiceMySQLBackend()
    status = db.status()
    identity = _readonly_health_identity(db, expected_private_ip=expected_private_ip)
    if (
        identity["server_uuid"] != expected_db_server_uuid
        or status["read_only"]
        or status["super_read_only"]
        or status["port"] != SERVICE_PORT
        or set(status["bind_addresses"]) != {"IP_REDACTED", expected_private_ip}
        or db.table_count() != restore["table_count"]
    ):
        raise RestoreError("READONLY_HEALTH_DB_STATE_MISMATCH")
    if not _listener_addresses(db.listener_output(), expected_private_ip, service_ready=True):
        raise RestoreError("MYSQL_SERVICE_LISTENER_UNSAFE")
    grants = _parse_service_grants(db.service_account_grants())
    if any(privileges != {"SELECT"} for privileges in grants.values()):
        raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
    _verify_health_database_accounts(db, unlocked=True)
    sessions = db.non_admin_sessions()
    allowed_hosts = set(SERVICE_CLIENT_IPS)
    for user, host, database in sessions:
        source_ip = host.rsplit(":", 1)[0] if ":" in host else host
        if (
            user != SERVICE_USER
            or source_ip not in allowed_hosts
            or database != "hospital_db"
        ):
            raise RestoreError("MYSQL_UNAPPROVED_SESSION_PRESENT")
    scheduler, enabled_events = db.event_scheduler_state()
    if scheduler != "OFF" or enabled_events:
        raise RestoreError("MYSQL_BACKGROUND_EVENT_WRITER_PRESENT")
    background_job_check()

    record = {
        "status": "APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED",
        "promotion_id": promotion_id,
        "cutover_id": cutover_id,
        "backup_id": expected_backup_id,
        "expected_sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "db_server_uuid": identity["server_uuid"],
        "db_hostname": identity["hostname"],
        "db_port": SERVICE_PORT,
        "db_writable": True,
        "service_account_privileges": {ip: ["SELECT"] for ip in SERVICE_CLIENT_IPS},
        "service_accounts_locked": False,
        "application_writes_allowed": False,
        "external_traffic_fenced": True,
        "apps": apps,
        "dns_authorized": False,
        "dr_state_changed": False,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_status(expected_path, record)
    return record


def verify_existing_readonly_health_state(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_backup_id: str,
    promotion_id: str,
    cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
    background_job_check=_verify_no_scheduled_writer_paths,
) -> dict:
    """Revalidate the successful read-only health state without changing it."""
    promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    if (
        expected_instance_id == PRODUCTION_DB_INSTANCE_ID
        or expected_private_ip in PROTECTED_PRIVATE_IPS
        or expected_data_volume_id == expected_stage_volume_id
    ):
        raise RestoreError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(
        expected_instance_id, expected_private_ip, identity_provider()
    )
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise RestoreError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")

    restore = validate_restore_receipt(
        receipt_path,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    if restore.get("backup_id") != expected_backup_id:
        raise RestoreError("RESTORE_BACKUP_ID_MISMATCH")
    validate_service_receipt(
        service_receipt_path,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    promotion, app_path = _read_write_promotion_receipt(
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        promotion_root=promotion_root,
        owner_uid=owner_uid,
    )
    _read_app_fence_receipt(
        app_path,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        expected_private_ip=expected_private_ip,
        owner_uid=owner_uid,
    )

    health_path = promotion_root / f"{promotion_id}.readonly-health.json"
    health = _read_private_json(
        health_path, owner_uid=owner_uid, error_code="READONLY_HEALTH_RECEIPT_INVALID"
    )
    try:
        completed = datetime.fromisoformat(
            str(health.get("completed_at_utc", "")).replace("Z", "+00:00")
        )
    except (ValueError, TypeError) as exc:
        raise RestoreError("READONLY_HEALTH_RECEIPT_INVALID") from exc
    if (
        completed.tzinfo is None
        or completed > datetime.now(timezone.utc)
        or health.get("status") != "APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED"
        or health.get("promotion_id") != promotion_id
        or health.get("cutover_id") != cutover_id
        or health.get("backup_id") != expected_backup_id
        or str(health.get("expected_sha256", "")).lower() != expected_sha256.lower()
        or health.get("instance_id") != expected_instance_id
        or health.get("private_ip") != expected_private_ip
        or health.get("data_volume_id") != expected_data_volume_id
        or health.get("stage_volume_id") != expected_stage_volume_id
        or health.get("db_port") != SERVICE_PORT
        or health.get("db_writable") is not True
        or health.get("service_account_privileges")
        != {ip: ["SELECT"] for ip in SERVICE_CLIENT_IPS}
        or health.get("service_accounts_locked") is not False
        or health.get("application_writes_allowed") is not False
        or health.get("external_traffic_fenced") is not True
        or health.get("dns_authorized") is not False
        or health.get("dr_state_changed") is not False
    ):
        raise RestoreError("READONLY_HEALTH_RECEIPT_MISMATCH")
    apps = health.get("apps")
    if not isinstance(apps, dict) or set(apps) != {"web", "emr"}:
        raise RestoreError("READONLY_HEALTH_RECEIPT_MISMATCH")
    for name, host, source_ip in (
        ("web", "dr-web", "IP_REDACTED"),
        ("emr", "dr-doc", "IP_REDACTED"),
    ):
        app = apps[name]
        if (
            not isinstance(app, dict)
            or app.get("status") != "PASS"
            or app.get("host") != host
            or app.get("source_ip") != source_ip
            or app.get("cutover_id") != cutover_id
            or app.get("db_host") != expected_private_ip
            or app.get("db_port") != SERVICE_PORT
            or app.get("health_endpoint") != "/__hospital_dr/health"
            or app.get("external_fence") is not True
            or app.get("container_running") is not True
            or app.get("restart_policy") != "no"
            or app.get("select_only_probe") is not True
            or app.get("db_server_uuid") != health.get("db_server_uuid")
        ):
            raise RestoreError("READONLY_HEALTH_RECEIPT_MISMATCH")

    if config_path.is_symlink() or not config_path.is_file():
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID")
    metadata = config_path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID")
    try:
        if config_path.read_text(encoding="utf-8") != _expected_config(expected_private_ip):
            raise RestoreError("SERVICE_MYSQL_CONFIG_MISMATCH")
    except OSError as exc:
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID") from exc

    db = backend or ServiceMySQLBackend()
    status = db.status()
    identity = _readonly_health_identity(db, expected_private_ip=expected_private_ip)
    if (
        identity.get("server_uuid") != health.get("db_server_uuid")
        or status.get("port") != SERVICE_PORT
        or status.get("datadir") != "/var/lib/mysql"
        or set(status.get("bind_addresses", ())) != {"IP_REDACTED", expected_private_ip}
        or status.get("read_only")
        or status.get("super_read_only")
        or db.table_count() != restore.get("table_count")
    ):
        raise RestoreError("READONLY_HEALTH_DB_STATE_MISMATCH")
    if not _listener_addresses(db.listener_output(), expected_private_ip, service_ready=True):
        raise RestoreError("MYSQL_SERVICE_LISTENER_UNSAFE")
    grants = _parse_service_grants(db.service_account_grants())
    if any(privileges != {"SELECT"} for privileges in grants.values()):
        raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
    _verify_health_database_accounts(db, unlocked=True)
    sessions = db.non_admin_sessions()
    for user, host, database in sessions:
        source_ip = host.rsplit(":", 1)[0] if ":" in host else host
        if (
            user != SERVICE_USER
            or source_ip not in SERVICE_CLIENT_IPS
            or database != "hospital_db"
        ):
            raise RestoreError("MYSQL_UNAPPROVED_SESSION_PRESENT")
    scheduler, enabled_events = db.event_scheduler_state()
    if scheduler != "OFF" or enabled_events:
        raise RestoreError("MYSQL_BACKGROUND_EVENT_WRITER_PRESENT")
    background_job_check()
    return {
        "status": "APPS_READONLY_HEALTH_REVALIDATED_NOT_DNS_AUTHORIZED",
        "promotion_id": promotion_id,
        "cutover_id": cutover_id,
        "backup_id": expected_backup_id,
        "sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "db_server_uuid": identity["server_uuid"],
        "app_accounts": "SELECT_ONLY",
        "app_accounts_unlocked": True,
        "application_writes_allowed": False,
        "dns_authorized": False,
    }


def revoke_readonly_health_receipt(
    *, promotion_id: str, cutover_id: str, promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
) -> None:
    promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    path = promotion_root / f"{promotion_id}.readonly-health.json"
    if not path.exists() and not path.is_symlink():
        return
    record = _read_private_json(
        path, owner_uid=owner_uid, error_code="READONLY_HEALTH_RECEIPT_INVALID"
    )
    if record.get("promotion_id") != promotion_id or record.get("cutover_id") != cutover_id:
        raise RestoreError("READONLY_HEALTH_RECEIPT_MISMATCH")
    if record.get("status") != "APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED":
        raise RestoreError("READONLY_HEALTH_RECEIPT_STATE_INVALID")
    record.update({
        "status": "READONLY_HEALTH_REVOKED_ROLLED_BACK_NOT_DNS_AUTHORIZED",
        "application_writes_allowed": False,
        "dns_authorized": False,
        "revoked_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    _write_status(path, record)


def verify_dump_dns_preflight(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_backup_id: str,
    promotion_id: str,
    cutover_id: str,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
    background_job_check=_verify_no_scheduled_writer_paths,
) -> dict:
    """Read-only proof required before a separate Dump DNS transaction may be considered."""
    promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID or expected_private_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    if expected_data_volume_id == expected_stage_volume_id:
        raise RestoreError("ISOLATED_RESOURCE_COLLISION")
    if promotion_root.is_symlink() or not promotion_root.is_dir():
        raise RestoreError("SERVICE_PROMOTION_STATUS_PATH_INVALID")
    promotion_root_metadata = promotion_root.stat()
    if (
        promotion_root_metadata.st_uid != owner_uid
        or stat.S_IMODE(promotion_root_metadata.st_mode) != 0o700
    ):
        raise RestoreError("SERVICE_PROMOTION_STATUS_PATH_INVALID")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise RestoreError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")

    restore = validate_restore_receipt(
        receipt_path,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    if restore.get("backup_id") != expected_backup_id:
        raise RestoreError("RESTORE_BACKUP_ID_MISMATCH")
    validate_service_receipt(
        service_receipt_path,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        owner_uid=owner_uid,
    )
    promotion, app_path = _read_write_promotion_receipt(
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        restore=restore,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        promotion_root=promotion_root,
        owner_uid=owner_uid,
    )
    fence = _read_app_fence_receipt(
        app_path,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        expected_private_ip=expected_private_ip,
        owner_uid=owner_uid,
    )

    if config_path.is_symlink() or not config_path.is_file():
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID")
    config_metadata = config_path.stat()
    if config_metadata.st_uid != owner_uid or stat.S_IMODE(config_metadata.st_mode) != 0o644:
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID")
    try:
        if config_path.read_text(encoding="utf-8") != _expected_config(expected_private_ip):
            raise RestoreError("SERVICE_MYSQL_CONFIG_MISMATCH")
    except OSError as exc:
        raise RestoreError("SERVICE_MYSQL_CONFIG_INVALID") from exc

    db = backend or ServiceMySQLBackend()
    status = db.status()
    if (
        status["port"] != SERVICE_PORT
        or status["datadir"] != "/var/lib/mysql"
        or set(status["bind_addresses"]) != {"IP_REDACTED", expected_private_ip}
        or status["read_only"]
        or status["super_read_only"]
    ):
        raise RestoreError("PROMOTED_MYSQL_RUNTIME_STATE_MISMATCH")
    if not _listener_addresses(db.listener_output(), expected_private_ip, service_ready=True):
        raise RestoreError("MYSQL_SERVICE_LISTENER_UNSAFE")
    if db.table_count() != restore["table_count"]:
        raise RestoreError("RESTORED_SCHEMA_TABLE_COUNT_MISMATCH")
    db.table_integrity_check()

    grants = _parse_service_grants(db.service_account_grants())
    if any(privileges != {"SELECT"} for privileges in grants.values()):
        raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
    _verify_closed_database_accounts(db)
    if db.service_account_sessions() != 0 or db.foreground_sessions() != 0:
        raise RestoreError("MYSQL_ACTIVE_SESSION_PRESENT")
    scheduler, enabled_events = db.event_scheduler_state()
    if scheduler != "OFF" or enabled_events:
        raise RestoreError("MYSQL_BACKGROUND_EVENT_WRITER_PRESENT")
    background_job_check()
    return {
        "status": "DUMP_DNS_PREFLIGHT_PASSED_NOT_AUTHORIZATION",
        "backup_id": restore["backup_id"],
        "expected_sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "promotion_id": promotion_id,
        "cutover_id": cutover_id,
        "apps": fence["apps"],
        "db_writable": True,
        "application_accounts_locked": True,
        "application_writes_allowed": False,
        "dns_change_authorized": False,
        "application_health_checked": False,
        "table_integrity": "MYSQLCHECK_PASS",
    }


_SCHEMA_GRANT_RE = re.compile(
    r"^GRANT (?P<privileges>[A-Z, ]+) ON `?hospital_db`?\.\* TO "
    r"(?:'|`)hospital_dr_service(?:'|`)@(?:'|`)(?P<host>10\.20\.(?:10|20)\.10)(?:'|`)$",
    re.IGNORECASE,
)
_USAGE_GRANT_RE = re.compile(
    r"^GRANT USAGE ON \*\.\* TO "
    r"(?:'|`)hospital_dr_service(?:'|`)@(?:'|`)(?P<host>10\.20\.(?:10|20)\.10)(?:'|`)$",
    re.IGNORECASE,
)
_ALLOWED_SERVICE_PRIVILEGES = {"SELECT", "INSERT", "UPDATE", "DELETE"}
_WRITE_PRIVILEGES = {"INSERT", "UPDATE", "DELETE"}


def _parse_service_grants(grants: dict[str, list[str]]) -> dict[str, set[str]]:
    if set(grants) != set(SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_ACCOUNT_SET_INVALID")
    parsed: dict[str, set[str]] = {}
    for client_ip, lines in grants.items():
        global_usage = 0
        privileges: set[str] = set()
        schema_grants = 0
        if not lines:
            raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_INVALID")
        for line in lines:
            if "WITH GRANT OPTION" in line.upper():
                raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_UNSAFE")
            usage = _USAGE_GRANT_RE.fullmatch(line.strip())
            if usage:
                if usage.group("host") != client_ip:
                    raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_UNSAFE")
                global_usage += 1
                continue
            schema = _SCHEMA_GRANT_RE.fullmatch(line.strip())
            if not schema or schema.group("host") != client_ip:
                # Reject global privileges, roles, grants to other schemas,
                # table grants, and any unrecognized MySQL privilege syntax.
                raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_UNSAFE")
            schema_grants += 1
            current = {item.strip().upper() for item in schema.group("privileges").split(",")}
            if not current or not current.issubset(_ALLOWED_SERVICE_PRIVILEGES):
                raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_UNSAFE")
            privileges.update(current)
        if global_usage != 1 or schema_grants != 1 or "SELECT" not in privileges:
            raise RestoreError("SERVICE_DB_ACCOUNT_GRANTS_INVALID")
        parsed[client_ip] = privileges
    return parsed


def _restrict_service_accounts_to_select(db) -> dict[str, set[str]]:
    current = _parse_service_grants(db.service_account_grants())
    for client_ip in SERVICE_CLIENT_IPS:
        writable = sorted(current[client_ip] & _WRITE_PRIVILEGES)
        if writable:
            db.query(
                f"REVOKE {', '.join(writable)} ON hospital_db.* "
                f"FROM '{SERVICE_USER}'@'{client_ip}'"
            )
    restricted = _parse_service_grants(db.service_account_grants())
    if any(privileges != {"SELECT"} for privileges in restricted.values()):
        raise RestoreError("SERVICE_DB_WRITE_PRIVILEGE_FENCE_FAILED")
    return restricted


def verify_write_promotion_preconditions(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    promotion_id: str | None = None,
    expected_request_id: str | None = None,
    require_no_service_sessions: bool = False,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
) -> dict:
    """Read-only gate; require exact isolated identity, receipts, RO DB, and safe app grants."""
    current = verify_service_preconditions(
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        expected_request_id=expected_request_id,
        identity_provider=identity_provider,
        data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider,
        serial_provider=serial_provider,
        backend=backend,
        interface_provider=interface_provider,
        receipt_path=receipt_path,
        service_receipt_path=service_receipt_path,
        config_path=config_path,
        owner_uid=owner_uid,
    )
    if current["state"] != "SERVICE_PREPARED":
        raise RestoreError("ISOLATED_DB_NOT_SERVICE_PREPARED")
    restore_request_id = current["restore"].get("request_id", "")
    if restore_request_id and promotion_id and restore_request_id != promotion_id:
        raise RestoreError("RESTORE_REQUEST_ID_MISMATCH")
    db = backend or ServiceMySQLBackend()
    grants = _parse_service_grants(db.service_account_grants())
    account_state = db.service_account_state()
    if set(account_state) != set(SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_ACCOUNT_SET_INVALID")
    if any(account_state[ip] != "N" for ip in SERVICE_CLIENT_IPS):
        raise RestoreError("SERVICE_DB_ACCOUNT_STATE_UNSAFE")
    if require_no_service_sessions and db.service_account_sessions() != 0:
        raise RestoreError("SERVICE_DB_ACCOUNT_SESSION_ACTIVE")
    if promotion_root.is_symlink() or (not promotion_root.is_dir() and promotion_root.exists()):
        raise RestoreError("SERVICE_PROMOTION_STATUS_PATH_INVALID")
    if promotion_id is not None:
        app_path, result_path = _promotion_paths(promotion_id, promotion_root)
        if any(path.exists() or path.is_symlink() for path in (app_path, result_path)):
            raise RestoreError("SERVICE_PROMOTION_ALREADY_RECORDED")
    return {**current, "service_privileges": grants}


def promote_service_db_write_fenced(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    promotion_id: str,
    cutover_id: str,
    app_fence_receipt_path: Path,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    promotion_root: Path = PROMOTION_STATUS_ROOT,
    owner_uid: int = 0,
) -> dict:
    """Make the isolated DB writable only after app containers and service accounts are fenced.

    This never starts apps, unlocks service accounts, changes DNS, or changes DR state.
    Once persistent writable mode is attempted, failures are recorded as uncertain and
    must not trigger automatic rollback to another database.
    """
    promotion_id = _canonical_uuid(promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    app_receipt_expected, promotion_result_path = _promotion_paths(promotion_id, promotion_root)
    if app_fence_receipt_path != app_receipt_expected:
        raise RestoreError("APP_WRITE_FENCE_RECEIPT_INVALID")
    if promotion_result_path.exists() or promotion_result_path.is_symlink():
        raise RestoreError("SERVICE_PROMOTION_ALREADY_RECORDED")

    gate = verify_write_promotion_preconditions(
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        require_no_service_sessions=True,
        identity_provider=identity_provider,
        data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider,
        serial_provider=serial_provider,
        backend=backend,
        interface_provider=interface_provider,
        receipt_path=receipt_path,
        service_receipt_path=service_receipt_path,
        config_path=config_path,
        promotion_root=promotion_root,
        owner_uid=owner_uid,
    )
    restore = gate["restore"]
    _read_app_fence_receipt(
        app_fence_receipt_path,
        promotion_id=promotion_id,
        cutover_id=cutover_id,
        expected_private_ip=expected_private_ip,
        owner_uid=owner_uid,
    )
    db = backend or ServiceMySQLBackend()
    record = {
        "status": "PREPARED_READ_ONLY",
        "promotion_id": promotion_id,
        "cutover_id": cutover_id,
        "backup_id": restore["backup_id"],
        "expected_sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "apps_fenced": True,
        "service_accounts_locked": False,
        "service_account_lock_state": "NOT_LOCKED",
        "service_account_privilege_state": "UNCHANGED_OR_PARTIAL",
        "db_writable": False,
        "application_writes_allowed": False,
        "dns_authorized": False,
        "automatic_rollback_allowed": False,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_status(promotion_result_path, record)

    try:
        # Narrow privileges and lock the exact application accounts before
        # changing global DB flags. No session may survive the app container stop.
        restricted = _restrict_service_accounts_to_select(db)
        record.update({
            "status": "APP_PRIVILEGES_RESTRICTED",
            "service_account_privilege_state": "SELECT_ONLY_VERIFIED",
            "service_account_privileges": {ip: sorted(values) for ip, values in restricted.items()},
        })
        _write_status(promotion_result_path, record)
        for client_ip in SERVICE_CLIENT_IPS:
            db.query(f"ALTER USER '{SERVICE_USER}'@'{client_ip}' ACCOUNT LOCK")
        locked = db.service_account_state()
        if set(locked) != set(SERVICE_CLIENT_IPS) or any(locked[ip] != "Y" for ip in SERVICE_CLIENT_IPS):
            raise RestoreError("SERVICE_DB_ACCOUNT_LOCK_VERIFICATION_FAILED")
        record.update({
            "status": "APPLICATION_ACCOUNTS_LOCKED",
            "service_accounts_locked": True,
            "service_account_lock_state": "LOCKED_VERIFIED",
        })
        _write_status(promotion_result_path, record)
        if db.service_account_sessions() != 0:
            raise RestoreError("SERVICE_DB_ACCOUNT_SESSION_ACTIVE")

        record.update({
            "status": "WRITE_ENABLE_PENDING",
            "service_accounts_locked": True,
            "write_enable_attempted_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_status(promotion_result_path, record)

        # Persist the state for reboot safety. Application accounts remain locked.
        db.query("SET PERSIST super_read_only=OFF")
        db.query("SET PERSIST read_only=OFF")
        status = db.status()
        if status["read_only"] or status["super_read_only"]:
            raise RestoreError("MYSQL_WRITE_PROMOTION_VERIFICATION_FAILED")
        grants = _parse_service_grants(db.service_account_grants())
        locked = db.service_account_state()
        if (
            set(locked) != set(SERVICE_CLIENT_IPS)
            or any(locked[ip] != "Y" for ip in SERVICE_CLIENT_IPS)
            or db.service_account_sessions() != 0
            or any(privileges != {"SELECT"} for privileges in grants.values())
            or set(status["bind_addresses"]) != {"IP_REDACTED", expected_private_ip}
            or status["port"] != SERVICE_PORT
            or status["datadir"] != "/var/lib/mysql"
            or db.table_count() != restore["table_count"]
        ):
            raise RestoreError("MYSQL_WRITE_PROMOTION_POSTCHECK_FAILED")
        record.update({
            "status": "WRITE_PROMOTED_APPS_FENCED",
            "db_writable": True,
            "application_writes_allowed": False,
            "service_accounts_locked": True,
            "service_account_privileges": {ip: sorted(values) for ip, values in grants.items()},
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        _write_status(promotion_result_path, record)
        return record
    except (RestoreError, OSError, subprocess.SubprocessError) as exc:
        # Do not automatically turn writable mode back off: once a persistent
        # write-enable command is attempted, write activity cannot be proven absent.
        try:
            status = db.status()
            still_read_only = status["read_only"] and status["super_read_only"]
        except (RestoreError, OSError, subprocess.SubprocessError):
            still_read_only = False
        try:
            observed_locks = db.service_account_state()
            if set(observed_locks) == set(SERVICE_CLIENT_IPS) and all(
                observed_locks[ip] == "Y" for ip in SERVICE_CLIENT_IPS
            ):
                record["service_account_lock_state"] = "LOCKED_VERIFIED"
                record["service_accounts_locked"] = True
            elif set(observed_locks) == set(SERVICE_CLIENT_IPS) and all(
                observed_locks[ip] == "N" for ip in SERVICE_CLIENT_IPS
            ):
                record["service_account_lock_state"] = "UNLOCKED_VERIFIED"
            else:
                record["service_account_lock_state"] = "PARTIAL_OR_UNKNOWN"
        except (RestoreError, OSError, subprocess.SubprocessError):
            record["service_account_lock_state"] = "PARTIAL_OR_UNKNOWN"
        record.update({
            "status": "FAILED_READ_ONLY" if still_read_only else "WRITE_STATE_UNKNOWN",
            "db_writable": not still_read_only,
            "application_writes_allowed": False,
            "automatic_rollback_allowed": False,
            "error_code": exc.code if isinstance(exc, RestoreError) else "SERVICE_PROMOTION_INTERNAL_ERROR",
            "failed_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        try:
            _write_status(promotion_result_path, record)
        except OSError:
            # The previously fsynced PREPARED/WRITE_ENABLE_PENDING receipt remains
            # a fail-closed signal for operators and future controllers.
            pass
        raise RestoreError(str(record["error_code"])) from exc


def verify_service_preconditions(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    expected_request_id: str | None = None,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    backend=None,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    allow_unrecorded_prepared: bool = False,
    owner_uid: int = 0,
) -> dict:
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID or expected_private_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    validate_target_identity(expected_instance_id, expected_private_ip, identity_provider())
    validate_volume_mount(expected_data_volume_id, data_mount_provider(), serial_provider())
    validate_volume_mount(expected_stage_volume_id, stage_mount_provider(), serial_provider())
    if not interface_provider(expected_private_ip):
        raise RestoreError("ISOLATED_PRIVATE_IP_NOT_ASSIGNED")
    restore = validate_restore_receipt(
        receipt_path,
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        expected_request_id=expected_request_id,
        owner_uid=owner_uid,
    )
    db = backend or ServiceMySQLBackend()
    status = db.status()
    if db.table_count() != restore["table_count"]:
        raise RestoreError("RESTORED_SCHEMA_TABLE_COUNT_MISMATCH")
    listener_output = db.listener_output()
    configured_addresses = set(status["bind_addresses"])
    if configured_addresses == {"IP_REDACTED"} and not status["read_only"] and not status["super_read_only"]:
        if config_path.exists() or config_path.is_symlink():
            raise RestoreError("SERVICE_MYSQL_CONFIG_ALREADY_PRESENT")
        if not _listener_addresses(listener_output, expected_private_ip, service_ready=False):
            raise RestoreError("ISOLATED_MYSQL_LISTENER_EXPOSED")
        state = "RESTORE_LOCAL_ONLY_READY"
    elif configured_addresses == {"IP_REDACTED", expected_private_ip} and status["read_only"] and status["super_read_only"]:
        if not _listener_addresses(listener_output, expected_private_ip, service_ready=True):
            raise RestoreError("ISOLATED_MYSQL_LISTENER_SET_INVALID")
        if not allow_unrecorded_prepared:
            validate_service_receipt(
                service_receipt_path,
                restore=restore,
                expected_instance_id=expected_instance_id,
                expected_private_ip=expected_private_ip,
                expected_data_volume_id=expected_data_volume_id,
                expected_stage_volume_id=expected_stage_volume_id,
                expected_sha256=expected_sha256,
                owner_uid=owner_uid,
            )
        state = "SERVICE_PREPARED"
    else:
        raise RestoreError("ISOLATED_MYSQL_SERVICE_STATE_UNSAFE")
    return {"state": state, "restore": restore, "mysql": status}


def prepare_service_listener(
    *,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_data_volume_id: str,
    expected_stage_volume_id: str,
    expected_sha256: str,
    password_file: Path,
    request_id: str = "",
    backend=None,
    restart=_restart_mysql,
    identity_provider=read_instance_metadata,
    data_mount_provider=find_mounted_mysql_source,
    stage_mount_provider=find_mounted_stage_source,
    serial_provider=read_nvme_volume_serials,
    interface_provider=_assigned_ipv4,
    receipt_path: Path = RESTORE_RESULT,
    service_receipt_path: Path = SERVICE_RESULT,
    config_path: Path = SERVICE_CONFIG,
    owner_uid: int = 0,
) -> dict:
    current = verify_service_preconditions(
        expected_instance_id=expected_instance_id,
        expected_private_ip=expected_private_ip,
        expected_data_volume_id=expected_data_volume_id,
        expected_stage_volume_id=expected_stage_volume_id,
        expected_sha256=expected_sha256,
        expected_request_id=request_id or None,
        identity_provider=identity_provider,
        data_mount_provider=data_mount_provider,
        stage_mount_provider=stage_mount_provider,
        serial_provider=serial_provider,
        backend=backend,
        interface_provider=interface_provider,
        receipt_path=receipt_path,
        service_receipt_path=service_receipt_path,
        config_path=config_path,
        owner_uid=owner_uid,
    )
    if current["state"] == "SERVICE_PREPARED":
        return {"status": "SUCCESS", "service_prepared": True, "idempotent": True}

    password = read_service_password(password_file, owner_uid=owner_uid)
    db = backend or ServiceMySQLBackend()
    mutation_started = False
    record = {
        "status": "FAILED",
        "service_prepared": False,
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_data_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "expected_sha256": expected_sha256.lower(),
        "backup_id": current["restore"]["backup_id"],
        "request_id": current["restore"].get("request_id", ""),
        "attempt_started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if config_path.exists() or config_path.is_symlink():
            raise RestoreError("SERVICE_MYSQL_CONFIG_ALREADY_PRESENT")
        mutation_started = True
        db.create_service_accounts(password)
        db.query("SET GLOBAL super_read_only=ON")
        _write_managed_config(config_path, _expected_config(expected_private_ip))
        restart()
        prepared = verify_service_preconditions(
            expected_instance_id=expected_instance_id,
            expected_private_ip=expected_private_ip,
            expected_data_volume_id=expected_data_volume_id,
            expected_stage_volume_id=expected_stage_volume_id,
            expected_sha256=expected_sha256,
            expected_request_id=request_id or None,
            identity_provider=identity_provider,
            data_mount_provider=data_mount_provider,
            stage_mount_provider=stage_mount_provider,
            serial_provider=serial_provider,
            backend=db,
            interface_provider=interface_provider,
            receipt_path=receipt_path,
            service_receipt_path=service_receipt_path,
            config_path=config_path,
            allow_unrecorded_prepared=True,
            owner_uid=owner_uid,
        )
        if prepared["state"] != "SERVICE_PREPARED":
            raise RestoreError("SERVICE_LISTENER_VERIFICATION_FAILED")
        record.update(
            {
                "status": "SUCCESS",
                "service_prepared": True,
                "mysql_port": SERVICE_PORT,
                "bind_addresses": ["IP_REDACTED", expected_private_ip],
                "read_only": True,
                "super_read_only": True,
                "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            }
        )
        _write_service_receipt(record, service_receipt_path)
        return record
    except (RestoreError, OSError, subprocess.SubprocessError) as exc:
        error_code = exc.code if isinstance(exc, RestoreError) else "SERVICE_PREPARE_INTERNAL_ERROR"
        if mutation_started:
            try:
                _write_managed_config(
                    config_path,
                    _expected_config(expected_private_ip, quarantine=True),
                    allowed_existing={
                        _expected_config(expected_private_ip),
                        _expected_config(expected_private_ip, quarantine=True),
                    },
                )
                restart()
                state = db.status()
                listeners = db.listener_output()
                if (
                    set(state["bind_addresses"]) != {"IP_REDACTED"}
                    or not state["read_only"]
                    or not state["super_read_only"]
                    or not _listener_addresses(listeners, expected_private_ip, service_ready=False)
                ):
                    raise RestoreError("SERVICE_QUARANTINE_VERIFICATION_FAILED")
                record.update({"status": "QUARANTINED", "error_code": error_code})
                _write_service_receipt(record, service_receipt_path)
                raise RestoreError("SERVICE_PREPARE_FAILED_QUARANTINED") from exc
            except (RestoreError, OSError, subprocess.SubprocessError) as rollback_error:
                if (
                    isinstance(rollback_error, RestoreError)
                    and rollback_error.code == "SERVICE_PREPARE_FAILED_QUARANTINED"
                ):
                    raise
                record.update({"status": "PARTIAL_FAILURE", "error_code": "SERVICE_PREPARE_ROLLBACK_FAILED"})
                try:
                    _write_service_receipt(record, service_receipt_path)
                except OSError:
                    pass
                raise RestoreError("SERVICE_PREPARE_ROLLBACK_FAILED") from exc
        record["error_code"] = error_code
        try:
            _write_service_receipt(record, service_receipt_path)
        except OSError:
            pass
        raise RestoreError(error_code) from exc
    finally:
        # Drop the local reference as soon as the service account setup ends.
        password = ""


def _command_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--request-id", default="")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-service-preconditions")
    _command_args(verify)
    prepare = sub.add_parser("prepare-service-listener")
    _command_args(prepare)
    prepare.add_argument("--service-password-file", required=True)
    promotion_preflight = sub.add_parser("verify-write-promotion-preconditions")
    _command_args(promotion_preflight)
    promotion_preflight.add_argument("--promotion-id")
    dns_preflight = sub.add_parser("verify-dump-dns-preflight")
    _command_args(dns_preflight)
    dns_preflight.add_argument("--expected-backup-id", required=True)
    dns_preflight.add_argument("--promotion-id", required=True)
    dns_preflight.add_argument("--cutover-id", required=True)
    promotion = sub.add_parser("promote-service-write-fenced")
    _command_args(promotion)
    promotion.add_argument("--promotion-id", required=True)
    promotion.add_argument("--cutover-id", required=True)
    promotion.add_argument("--app-fence-receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        values = {
            "expected_instance_id": args.instance_id,
            "expected_private_ip": args.private_ip,
            "expected_data_volume_id": args.data_volume_id,
            "expected_stage_volume_id": args.stage_volume_id,
            "expected_sha256": args.expected_sha256,
        }
        if args.command == "verify-service-preconditions":
            result = verify_service_preconditions(**values, expected_request_id=args.request_id or None)
            print(f"ISOLATED_DB_SERVICE_PREFLIGHT=PASS state={result['state']}", flush=True)
            return 0
        if args.command == "verify-write-promotion-preconditions":
            result = verify_write_promotion_preconditions(
                **values,
                promotion_id=args.promotion_id,
                expected_request_id=args.request_id or None,
            )
            print(
                "ISOLATED_DB_WRITE_PROMOTION_PREFLIGHT=PASS "
                f"state={result['state']} service_accounts=verified_readonly_capable",
                flush=True,
            )
            return 0
        if args.command == "verify-dump-dns-preflight":
            result = verify_dump_dns_preflight(
                **values,
                expected_backup_id=args.expected_backup_id,
                promotion_id=args.promotion_id,
                cutover_id=args.cutover_id,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
            return 0
        if args.command == "promote-service-write-fenced":
            result = promote_service_db_write_fenced(
                **values,
                promotion_id=args.promotion_id,
                cutover_id=args.cutover_id,
                app_fence_receipt_path=args.app_fence_receipt,
            )
            print(
                "ISOLATED_DB_SERVICE_PROMOTION=SUCCESS "
                "state=WRITE_PROMOTED_APPS_FENCED db_writable=true "
                "apps_stopped=true service_accounts_locked=true "
                "application_writes_allowed=false dns_authorized=false",
                flush=True,
            )
            return 0
        result = prepare_service_listener(
            **values,
            password_file=Path(args.service_password_file),
            request_id=args.request_id,
        )
        print(f"ISOLATED_DB_SERVICE_PREPARED={result['status']}", flush=True)
        return 0
    except RestoreError as exc:
        print(f"ISOLATED_DB_SERVICE=BLOCKED reason={exc.code}", file=sys.stderr, flush=True)
        return 1
    except OSError:
        print("ISOLATED_DB_SERVICE=BLOCKED reason=LOCAL_TOOL_OR_FILE_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
