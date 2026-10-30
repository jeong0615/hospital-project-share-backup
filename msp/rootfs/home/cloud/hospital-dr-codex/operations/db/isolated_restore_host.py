#!/usr/bin/env python3
"""Identity and restore checks that run only on the isolated restore host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


PRODUCTION_DB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
PROTECTED_PRIVATE_IPS = {"IP_REDACTED", "IP_REDACTED"}
BACKUP_ID_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class RestoreError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_master_status(path: Path) -> tuple[str, int]:
    text = path.read_text(encoding="utf-8", errors="strict")
    file_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", text, re.I)
    pos_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_POS\s*=\s*([0-9]+)", text, re.I)
    if not file_match or not pos_match:
        file_match = re.search(r"^\s*(?:File|BinlogFile)\s*:\s*(\S+)\s*$", text, re.I | re.M)
        pos_match = re.search(r"^\s*(?:Position|BinlogPosition)\s*:\s*([0-9]+)\s*$", text, re.I | re.M)
    if not file_match or not pos_match:
        raise RestoreError("MASTER_STATUS_INVALID")
    file_name, position = file_match.group(1), int(pos_match.group(1))
    if not re.fullmatch(r"[A-Za-z0-9._-]+", file_name) or position < 1:
        raise RestoreError("MASTER_STATUS_INVALID")
    return file_name, position


def parse_embedded_dump_position(path: Path) -> tuple[str, int]:
    try:
        with path.open("r", encoding="utf-8", errors="strict") as stream:
            for line in stream:
                if "CHANGE MASTER TO" not in line and "CHANGE REPLICATION SOURCE TO" not in line:
                    continue
                file_match = re.search(r"(?:MASTER|SOURCE)_LOG_FILE='([^']+)'", line, re.I)
                pos_match = re.search(r"(?:MASTER|SOURCE)_LOG_POS=([0-9]+)", line, re.I)
                if file_match and pos_match:
                    file_name = file_match.group(1)
                    position = int(pos_match.group(1))
                    if re.fullmatch(r"[A-Za-z0-9._-]+", file_name) and position >= 1:
                        return file_name, position
    except (OSError, UnicodeError) as exc:
        raise RestoreError("DUMP_SQL_UNREADABLE") from exc
    raise RestoreError("DUMP_BINLOG_POSITION_MISSING")


def validate_target_identity(expected_instance_id: str, expected_private_ip: str, actual: dict) -> None:
    actual_id = str(actual.get("instance_id") or "")
    actual_ip = str(actual.get("private_ip") or "")
    if expected_instance_id == PRODUCTION_DB_INSTANCE_ID or actual_id == PRODUCTION_DB_INSTANCE_ID:
        raise RestoreError("PRODUCTION_DB_TARGET_FORBIDDEN")
    if expected_private_ip in PROTECTED_PRIVATE_IPS or actual_ip in PROTECTED_PRIVATE_IPS:
        raise RestoreError("PROTECTED_DB_IP_FORBIDDEN")
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", expected_instance_id):
        raise RestoreError("EXPECTED_INSTANCE_ID_INVALID")
    if not re.fullmatch(r"10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])", expected_private_ip):
        raise RestoreError("EXPECTED_ISOLATED_PRIVATE_IP_INVALID")
    if actual_id != expected_instance_id or actual_ip != expected_private_ip:
        raise RestoreError("ISOLATED_INSTANCE_IDENTITY_MISMATCH")
    tags = actual.get("tags") or {}
    if tags.get("Name") != "Hospital-DR-Dump-Restore-Isolated" or tags.get("Role") != "isolated-dump-restore-validation":
        raise RestoreError("ISOLATED_INSTANCE_TAG_MISMATCH")


def _normalized_volume_id(value: str) -> str:
    return str(value or "").lower().replace("-", "")


def validate_volume_mount(expected_volume_id: str, mount_source: str, serial_by_device: dict[str, str]) -> None:
    if not re.fullmatch(r"vol-[0-9a-f]{8,32}", expected_volume_id):
        raise RestoreError("EXPECTED_VOLUME_ID_INVALID")
    source = os.path.realpath(mount_source)
    serial = serial_by_device.get(source) or serial_by_device.get(mount_source) or ""
    if _normalized_volume_id(serial) != _normalized_volume_id(expected_volume_id):
        raise RestoreError("ISOLATED_DATA_VOLUME_MISMATCH")


def _metadata_get(url: str, token: str | None = None, method: str = "GET") -> str:
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    request = urllib.request.Request(url, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.read(512).decode("ascii").strip()


def read_instance_metadata() -> dict[str, str]:
    base = "http://IP_REDACTED/latest"
    request = urllib.request.Request(
        f"{base}/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            token = response.read(512).decode("ascii").strip()
        return {
            "instance_id": _metadata_get(f"{base}/meta-data/instance-id", token),
            "private_ip": _metadata_get(f"{base}/meta-data/local-ipv4", token),
            "tags": {
                "Name": _metadata_get(f"{base}/meta-data/tags/instance/Name", token),
                "Role": _metadata_get(f"{base}/meta-data/tags/instance/Role", token),
            },
        }
    except Exception as exc:
        raise RestoreError("EC2_METADATA_UNAVAILABLE") from exc


def find_mounted_mysql_source(mountpoint: str = "/var/lib/mysql") -> str:
    result = subprocess.run(
        ["findmnt", "-n", "-o", "SOURCE", "--target", mountpoint],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RestoreError("MYSQL_DATA_VOLUME_NOT_MOUNTED")
    return os.path.realpath(result.stdout.strip())


def find_mounted_stage_source(mountpoint: str = "/var/lib/hospital-dr-dump-restore") -> str:
    result = subprocess.run(
        ["findmnt", "-n", "-o", "SOURCE", "--target", mountpoint],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RestoreError("RESTORE_STAGE_VOLUME_NOT_MOUNTED")
    return os.path.realpath(result.stdout.strip())


def verify_mounted_volume(volume_id: str, mountpoint: str) -> None:
    if mountpoint == "/var/lib/mysql":
        source = find_mounted_mysql_source(mountpoint)
    elif mountpoint == "/var/lib/hospital-dr-dump-restore":
        source = find_mounted_stage_source(mountpoint)
    else:
        raise RestoreError("ISOLATED_MOUNTPOINT_NOT_ALLOWED")
    validate_volume_mount(volume_id, source, read_nvme_volume_serials())


def read_nvme_volume_serials() -> dict[str, str]:
    serials = {}
    for serial_path in Path("/sys/block").glob("nvme*n1/device/serial"):
        try:
            device = "/dev/" + serial_path.parents[1].name
            serials[os.path.realpath(device)] = serial_path.read_text(encoding="ascii").strip()
        except OSError:
            continue
    return serials


def find_nvme_volume_device(expected_volume_id: str, serial_by_device: dict[str, str]) -> str:
    if not re.fullmatch(r"vol-[0-9a-f]{8,32}", expected_volume_id):
        raise RestoreError("EXPECTED_VOLUME_ID_INVALID")
    matches = [
        device
        for device, serial in serial_by_device.items()
        if _normalized_volume_id(serial) == _normalized_volume_id(expected_volume_id)
    ]
    if len(matches) != 1:
        raise RestoreError("ISOLATED_VOLUME_DEVICE_NOT_UNIQUE")
    return matches[0]


def verify_runtime_target(
    expected_instance_id: str,
    expected_private_ip: str,
    expected_volume_id: str,
    expected_stage_volume_id: str,
) -> None:
    if expected_volume_id == expected_stage_volume_id:
        raise RestoreError("ISOLATED_DATA_AND_STAGE_VOLUMES_MUST_DIFFER")
    validate_target_identity(expected_instance_id, expected_private_ip, read_instance_metadata())
    validate_volume_mount(
        expected_volume_id,
        find_mounted_mysql_source(),
        read_nvme_volume_serials(),
    )
    validate_volume_mount(
        expected_stage_volume_id,
        find_mounted_stage_source(),
        read_nvme_volume_serials(),
    )


class SystemMySQLBackend:
    """Use only the isolated Ubuntu host's local root socket authentication."""

    def _run(self, command: list[str], *, stdin=None, capture_output=True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            command,
            stdin=stdin,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=stdin is None,
        )
        if result.returncode != 0:
            raise RestoreError("MYSQL_COMMAND_FAILED")
        return result

    def query(self, sql: str) -> str:
        output = self._run([
            "mysql", "--protocol=socket", "-uroot", "--batch", "--skip-column-names", "-e", sql
        ]).stdout
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="strict")
        return output.strip()

    def ready(self) -> None:
        values = self.query("SELECT @@port, @@datadir, @@bind_address, @@read_only, @@super_read_only")
        fields = values.split("\t")
        if len(fields) != 5:
            raise RestoreError("ISOLATED_MYSQL_STATUS_INVALID")
        port, datadir, bind_address, read_only, super_read_only = fields
        if port != "3307" or os.path.realpath(datadir) != "/var/lib/mysql":
            raise RestoreError("ISOLATED_MYSQL_RUNTIME_MISMATCH")
        if bind_address not in {"IP_REDACTED", "localhost"}:
            raise RestoreError("ISOLATED_MYSQL_NOT_LOOPBACK_ONLY")
        if read_only != "0" or super_read_only != "0":
            raise RestoreError("ISOLATED_MYSQL_NOT_WRITABLE")
        listeners = subprocess.run(
            ["ss", "-lntH"], capture_output=True, text=True, check=False
        )
        if listeners.returncode != 0:
            raise RestoreError("MYSQL_LISTENER_CHECK_FAILED")
        for line in listeners.stdout.splitlines():
            local_address = line.split()[3] if len(line.split()) > 3 else ""
            if not any(local_address.endswith(f":{port}") for port in ("3306", "3307", "33060")):
                continue
            if local_address.endswith(":3306"):
                raise RestoreError("UNEXPECTED_MYSQL_3306_LISTENER")
            if local_address not in {
                "IP_REDACTED:3307", "[::1]:3307", "IP_REDACTED:33060", "[::1]:33060"
            }:
                raise RestoreError("ISOLATED_MYSQL_LISTENER_EXPOSED")

    def schema_exists(self) -> bool:
        return self.query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='hospital_db'"
        ) != "0"

    def create_schema(self) -> None:
        self.query("CREATE DATABASE hospital_db DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")

    def prepare_import_user(self) -> None:
        self.query(
            "CREATE USER IF NOT EXISTS 'hospital_dr_import'@'localhost' "
            "IDENTIFIED WITH auth_socket AS 'mysql'"
        )
        plugin = self.query(
            "SELECT plugin FROM mysql.user WHERE user='hospital_dr_import' AND host='localhost'"
        )
        if plugin != "auth_socket":
            raise RestoreError("ISOLATED_IMPORT_AUTH_PLUGIN_MISMATCH")
        self.query(
            "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, "
            "CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, "
            "TRIGGER, EVENT, CREATE ROUTINE, ALTER ROUTINE "
            "ON hospital_db.* TO 'hospital_dr_import'@'localhost'"
        )

    def import_sql(self, path: Path) -> None:
        with path.open("rb") as stream:
            result = subprocess.run(
                ["runuser", "-u", "mysql", "--", "mysql", "--protocol=socket", "-uhospital_dr_import", "hospital_db"],
                stdin=stream,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        if result.returncode != 0:
            raise RestoreError("MYSQL_IMPORT_FAILED")

    def validate_schema(self) -> int:
        tables = self.query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA='hospital_db' AND TABLE_TYPE='BASE TABLE'"
        )
        if not tables.isdigit() or int(tables) < 1:
            raise RestoreError("RESTORED_SCHEMA_HAS_NO_TABLES")
        result = subprocess.run(
            ["runuser", "-u", "mysql", "--", "mysqlcheck", "--protocol=socket", "-uhospital_dr_import", "--check", "hospital_db"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            raise RestoreError("RESTORED_SCHEMA_CHECK_FAILED")
        return int(tables)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_status(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def execute_restore(
    *,
    backup_path: Path,
    status_path: Path,
    expected_sha256: str,
    encryption_key_file: Path,
    expected_instance_id: str,
    expected_private_ip: str,
    expected_volume_id: str,
    expected_stage_volume_id: str,
    request_id: str = "",
    stage_mount_source_provider=find_mounted_stage_source,
    stage_serial_provider=read_nvme_volume_serials,
    result_path: Path = Path("/var/lib/hospital-dr-dump-restore/status/restore.json"),
    backend=None,
    identity_provider=read_instance_metadata,
    mount_source_provider=find_mounted_mysql_source,
    serial_provider=read_nvme_volume_serials,
    work_root=Path("/var/lib/hospital-dr-dump-restore/work"),
    stage_mountpoint=Path("/var/lib/hospital-dr-dump-restore"),
) -> dict:
    if request_id:
        try:
            parsed_request_id = str(uuid.UUID(request_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise RestoreError("RESTORE_REQUEST_ID_INVALID") from exc
        if parsed_request_id != request_id.lower():
            raise RestoreError("RESTORE_REQUEST_ID_INVALID")
    record = {
        "status": "FAILED",
        "backup_id": backup_path.name,
        "expected_sha256": expected_sha256.lower(),
        "instance_id": expected_instance_id,
        "private_ip": expected_private_ip,
        "data_volume_id": expected_volume_id,
        "stage_volume_id": expected_stage_volume_id,
        "request_id": request_id,
        "attempt_started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    result_path_is_safe = False
    try:
        if expected_volume_id == expected_stage_volume_id:
            raise RestoreError("ISOLATED_DATA_AND_STAGE_VOLUMES_MUST_DIFFER")
        validate_target_identity(
            expected_instance_id,
            expected_private_ip,
            identity_provider(),
        )
        validate_volume_mount(expected_volume_id, mount_source_provider(), serial_provider())
        validate_volume_mount(
            expected_stage_volume_id,
            stage_mount_source_provider(),
            stage_serial_provider(),
        )
        stage_root = stage_mountpoint.resolve()
        for controlled_path in (backup_path.resolve(), status_path.resolve(), work_root.resolve(), result_path.resolve()):
            try:
                controlled_path.relative_to(stage_root)
            except ValueError as exc:
                raise RestoreError("RESTORE_PATH_OUTSIDE_ISOLATED_STAGE") from exc
        result_path_is_safe = True
        # Replace any previous success receipt before this restore attempt can
        # mutate the isolated database. A later service-preparation gate must
        # never mistake an older attempt for the current one.
        _write_status(result_path, record)
        if not BACKUP_ID_RE.fullmatch(backup_path.name) or backup_path.is_symlink() or not backup_path.is_file():
            raise RestoreError("BACKUP_ARTIFACT_INVALID")
        if not SHA256_RE.fullmatch(expected_sha256.lower()):
            raise RestoreError("EXPECTED_CHECKSUM_INVALID")
        if not hmac_compare(_sha256(backup_path), expected_sha256.lower()):
            raise RestoreError("CHECKSUM_MISMATCH")
        matching_status = backup_path.with_name(
            backup_path.name.removesuffix(".sql.gz.enc") + ".master_status"
        )
        if status_path.resolve() != matching_status.resolve():
            raise RestoreError("BACKUP_PAIR_MISMATCH")
        with backup_path.open("rb") as encrypted_stream:
            if backup_path.stat().st_size < 8 or encrypted_stream.read(8) != b"Salted__":
                raise RestoreError("ENCRYPTED_CONTAINER_INVALID")
        if status_path.is_symlink() or not status_path.is_file():
            raise RestoreError("MASTER_STATUS_MISSING")
        binlog_file, binlog_position = parse_master_status(status_path)
        if encryption_key_file.is_symlink() or not encryption_key_file.is_file() or not os.access(encryption_key_file, os.R_OK):
            raise RestoreError("ENCRYPTION_KEY_FILE_UNAVAILABLE")
        key_stat = encryption_key_file.stat()
        if key_stat.st_size < 1 or key_stat.st_uid != os.geteuid() or stat.S_IMODE(key_stat.st_mode) & 0o077:
            raise RestoreError("ENCRYPTION_KEY_FILE_PERMISSIONS_INVALID")

        db = backend or SystemMySQLBackend()
        db.ready()
        if db.schema_exists():
            raise RestoreError("ISOLATED_SCHEMA_ALREADY_EXISTS")
        work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(work_root, 0o700)
        with tempfile.TemporaryDirectory(prefix="restore-", dir=work_root) as temp_dir:
            compressed = Path(temp_dir) / "payload.sql.gz"
            sql_file = Path(temp_dir) / "payload.sql"
            decrypt = subprocess.run(
                [
                    "openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-pbkdf2",
                    "-in", str(backup_path), "-out", str(compressed),
                    "-pass", f"file:{encryption_key_file}",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if decrypt.returncode != 0:
                raise RestoreError("DECRYPTION_FAILED")
            gzip_test = subprocess.run(
                ["gzip", "-t", str(compressed)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if gzip_test.returncode != 0:
                raise RestoreError("GZIP_INTEGRITY_FAILED")
            with sql_file.open("wb") as stream:
                os.chmod(sql_file, 0o600)
                decompress = subprocess.run(
                    ["gzip", "-dc", str(compressed)],
                    check=False,
                    stdout=stream,
                    stderr=subprocess.DEVNULL,
                )
            if decompress.returncode != 0 or sql_file.stat().st_size == 0:
                raise RestoreError("SQL_DECOMPRESSION_FAILED")

            embedded_file, embedded_position = parse_embedded_dump_position(sql_file)
            if (embedded_file, embedded_position) != (binlog_file, binlog_position):
                raise RestoreError("MASTER_STATUS_DUMP_COORDINATE_MISMATCH")

            db.create_schema()
            db.prepare_import_user()
            db.import_sql(sql_file)
            table_count = db.validate_schema()
        record.update(
            {
                "status": "SUCCESS",
                "master_status_file": binlog_file,
                "master_status_position": binlog_position,
                "table_count": table_count,
                "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            }
        )
        _write_status(result_path, record)
        print(f"ISOLATED_DUMP_RESTORE=SUCCESS tables={table_count} backup_id={backup_path.name}", flush=True)
        return record
    except RestoreError as exc:
        record["error_code"] = exc.code
        if result_path_is_safe:
            _write_status(result_path, record)
        print(f"ISOLATED_DUMP_RESTORE=FAILED error={exc.code}", file=sys.stderr, flush=True)
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        record["error_code"] = "ISOLATED_RESTORE_INTERNAL_ERROR"
        if result_path_is_safe:
            _write_status(result_path, record)
        print("ISOLATED_DUMP_RESTORE=FAILED error=ISOLATED_RESTORE_INTERNAL_ERROR", file=sys.stderr, flush=True)
        raise RestoreError("ISOLATED_RESTORE_INTERNAL_ERROR") from exc


def hmac_compare(left: str, right: str) -> bool:
    # Avoid importing a larger workflow module on the isolated host.
    import hmac

    return hmac.compare_digest(left.lower(), right.lower())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    instance = subparsers.add_parser("verify-instance")
    instance.add_argument("--instance-id", required=True)
    instance.add_argument("--private-ip", required=True)
    volume = subparsers.add_parser("resolve-volume")
    volume.add_argument("--volume-id", required=True)
    mounted = subparsers.add_parser("verify-volume")
    mounted.add_argument("--volume-id", required=True)
    mounted.add_argument("--mountpoint", required=True)
    verify = subparsers.add_parser("verify-target")
    verify.add_argument("--instance-id", required=True)
    verify.add_argument("--private-ip", required=True)
    verify.add_argument("--volume-id", required=True)
    verify.add_argument("--stage-volume-id", required=True)
    restore = subparsers.add_parser("restore")
    restore.add_argument("--instance-id", required=True)
    restore.add_argument("--private-ip", required=True)
    restore.add_argument("--volume-id", required=True)
    restore.add_argument("--stage-volume-id", required=True)
    restore.add_argument("--backup", required=True)
    restore.add_argument("--master-status", required=True)
    restore.add_argument("--expected-sha256", required=True)
    restore.add_argument("--request-id", default="")
    restore.add_argument("--encryption-key-file", required=True)
    restore.add_argument("--result-path", default="/var/lib/hospital-dr-dump-restore/status/restore.json")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-instance":
            validate_target_identity(args.instance_id, args.private_ip, read_instance_metadata())
            print("ISOLATED_INSTANCE=PASS")
            return 0
        if args.command == "resolve-volume":
            print(find_nvme_volume_device(args.volume_id, read_nvme_volume_serials()))
            return 0
        if args.command == "verify-volume":
            verify_mounted_volume(args.volume_id, args.mountpoint)
            print("ISOLATED_VOLUME_MOUNT=PASS")
            return 0
        if args.command == "verify-target":
            verify_runtime_target(
                args.instance_id,
                args.private_ip,
                args.volume_id,
                args.stage_volume_id,
            )
            print("ISOLATED_TARGET=PASS")
            return 0
        execute_restore(
            backup_path=Path(args.backup),
            status_path=Path(args.master_status),
            expected_sha256=args.expected_sha256,
            encryption_key_file=Path(args.encryption_key_file),
            expected_instance_id=args.instance_id,
            expected_private_ip=args.private_ip,
            expected_volume_id=args.volume_id,
            expected_stage_volume_id=args.stage_volume_id,
            request_id=args.request_id,
            stage_mount_source_provider=find_mounted_stage_source,
            stage_serial_provider=read_nvme_volume_serials,
            result_path=Path(args.result_path),
        )
        return 0
    except RestoreError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
