"""Safe, side-effect-free helpers for the Emergency DR ChatOps surface.

This module intentionally does not execute a DR workflow, restore a database,
or call Slack.  It builds validated Block Kit views, persists the emergency
console coordinate, and inventories complete local backup pairs with
parseable replication metadata and an OpenSSL encrypted-container marker.  The
existing ChatOps approval engine remains the only approval/execution path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath


EMERGENCY_TTL_SECONDS = 15 * 60
MAX_DUMP_OPTIONS = 20

REQUEST_TYPE_EMERGENCY_FAILOVER = "EMERGENCY_FAILOVER"
REQUEST_TYPE_EMERGENCY_FAILBACK = "EMERGENCY_FAILBACK"
REQUEST_TYPE_DUMP_RESTORE = "DUMP_RESTORE_FAILOVER"
REQUEST_TYPE_SECURITY = "SECURITY_DR_ESCALATION"

FAILOVER_REASONS = (
    ("REQUEST_NOT_CREATED", "요청 메시지가 생성되지 않았습니다."),
    ("REQUEST_EXPIRED", "요청 메시지가 만료되었습니다."),
    ("REQUEST_CANCELLED_ACCIDENTALLY", "요청 메시지를 실수로 취소했습니다."),
    ("IMMEDIATE_RECOVERY_REQUIRED", "즉시 복구가 필요하여 대기할 수 없습니다."),
    ("OTHER", "기타"),
)

DUMP_FAILOVER_REASONS = (
    *FAILOVER_REASONS[:-1],
    ("POINT_IN_TIME_DUMP_REQUIRED", "현재 NR 복제본 대신 특정 백업 시점 복구가 필요합니다."),
    FAILOVER_REASONS[-1],
)

FAILBACK_REASONS = (
    ("REQUEST_NOT_CREATED", "Failback 요청 메시지가 생성되지 않았습니다."),
    ("REQUEST_EXPIRED", "요청 메시지가 만료되었습니다."),
    ("REQUEST_CANCELLED_ACCIDENTALLY", "요청 메시지를 실수로 취소했습니다."),
    ("ONPREM_RECOVERED_IMMEDIATELY", "On-Prem 정상화가 확인되어 즉시 복귀가 필요합니다."),
    ("STATE_MISMATCH", "자동 상태 검증 결과와 실제 상태가 일치하지 않습니다."),
    ("OTHER", "기타"),
)


def _safe_text(value, limit=500):
    return " ".join(str(value or "").split())[:limit]


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest field")
        result[key] = value
    return result


def request_type_for(action, emergency=False, dump_restore=False):
    if dump_restore:
        return REQUEST_TYPE_DUMP_RESTORE
    if emergency and action == "failover":
        return REQUEST_TYPE_EMERGENCY_FAILOVER
    if emergency and action == "failback":
        return REQUEST_TYPE_EMERGENCY_FAILBACK
    return "NORMAL_FAILOVER" if action == "failover" else "NORMAL_FAILBACK"


def reason_options(action, request_type=None):
    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        return DUMP_FAILOVER_REASONS
    return FAILOVER_REASONS if action == "failover" else FAILBACK_REASONS


def validate_reason(action, reason_code, reason_text="", request_type=None):
    allowed = {code for code, _ in reason_options(action, request_type)}
    code = str(reason_code or "").strip()
    detail = _safe_text(reason_text, 500)
    if code not in allowed:
        return False, "사유를 반드시 선택해주십시오."
    if code == "OTHER" and not detail:
        return False, "기타 사유를 입력해주십시오."
    return True, detail


class EmergencyConsoleStore:
    """Persist exactly one emergency console coordinate in the ChatOps DB."""

    def __init__(self, state_db):
        self.state_db = state_db
        parent = os.path.dirname(os.path.abspath(state_db))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.state_db, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS emergency_console (
                    console_id INTEGER PRIMARY KEY CHECK (console_id = 1),
                    channel_id TEXT NOT NULL,
                    message_ts TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_checked_at REAL NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )

    def get(self):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM emergency_console WHERE console_id = 1"
            ).fetchone()
        return dict(row) if row else None

    def save(self, channel_id, message_ts, created_at=None, status="READY", checked_at=None):
        now = time.time() if checked_at is None else float(checked_at)
        created_at = now if created_at is None else float(created_at)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO emergency_console
                    (console_id, channel_id, message_ts, created_at, last_checked_at, status)
                VALUES (1, ?, ?, ?, ?, ?)
                ON CONFLICT(console_id) DO UPDATE SET
                    channel_id = excluded.channel_id,
                    message_ts = excluded.message_ts,
                    created_at = excluded.created_at,
                    last_checked_at = excluded.last_checked_at,
                    status = excluded.status
                """,
                (channel_id, message_ts, created_at, now, status),
            )
        return self.get()

    def mark_checked(self, status="READY", checked_at=None):
        now = time.time() if checked_at is None else float(checked_at)
        with self._connect() as connection:
            connection.execute(
                "UPDATE emergency_console SET last_checked_at = ?, status = ? WHERE console_id = 1",
                (now, status),
            )
        return self.get()

    def clear(self):
        with self._connect() as connection:
            connection.execute("DELETE FROM emergency_console WHERE console_id = 1")


def emergency_console_blocks(button_value):
    """Build the pinned console without approval controls."""
    text = (
        "*Hospital DR Emergency Console*\n\n"
        "자동 감지 또는 일반 ChatOps 요청 경로를 사용할 수 없는 경우에만 사용하십시오.\n"
        "긴급 요청도 관리자 2인 승인과 실행 전 안전 검사를 유지합니다."
    )
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "action_id": "hospital_dr_emergency_status",
                    "text": {"type": "plain_text", "text": "상태 점검"},
                    "value": button_value("", "failover", "emergency_status"),
                },
                {
                    "type": "button",
                    "action_id": "hospital_dr_emergency_failover",
                    "text": {"type": "plain_text", "text": "긴급 Failover 요청"},
                    "style": "danger",
                    "value": button_value(
                        "", "failover", "emergency_open",
                        request_type=REQUEST_TYPE_EMERGENCY_FAILOVER,
                    ),
                },
                {
                    "type": "button",
                    "action_id": "hospital_dr_emergency_failback",
                    "text": {"type": "plain_text", "text": "긴급 Failback 요청"},
                    "style": "primary",
                    "value": button_value(
                        "", "failback", "emergency_open",
                        request_type=REQUEST_TYPE_EMERGENCY_FAILBACK,
                    ),
                },
                {
                    "type": "button",
                    "action_id": "hospital_dr_emergency_dump",
                    "text": {"type": "plain_text", "text": "긴급 Failover (Dump)"},
                    "value": button_value(
                        "", "failover", "emergency_dump_open",
                        request_type=REQUEST_TYPE_DUMP_RESTORE,
                    ),
                },
            ],
        },
    ]


def emergency_reason_view(action, request_type, request_origin=None):
    options = [
        {"text": {"type": "plain_text", "text": label}, "value": code}
        for code, label in reason_options(action, request_type)
    ]
    if request_type == REQUEST_TYPE_DUMP_RESTORE:
        title = "긴급 Failover (Dump) 요청"
        submit_text = "다음"
    else:
        title = "긴급 Failover 요청" if action == "failover" else "긴급 Failback 요청"
        submit_text = "요청 생성"
    return {
        "type": "modal",
        "callback_id": "hospital_dr_emergency_reason",
        "private_metadata": json.dumps(
            {
                "action": action,
                "request_type": request_type,
                **({"request_origin": request_origin} if request_origin else {}),
            },
            separators=(",", ":"),
        ),
        "title": {"type": "plain_text", "text": title},
        "submit": {"type": "plain_text", "text": submit_text},
        "close": {"type": "plain_text", "text": "취소"},
        "blocks": [
            {
                "type": "input",
                "block_id": "emergency_reason_code",
                "label": {"type": "plain_text", "text": "긴급 사유"},
                "element": {
                    "type": "static_select",
                    "action_id": "reason_code",
                    "placeholder": {"type": "plain_text", "text": "사유를 선택하세요"},
                    "options": options,
                },
            },
            {
                "type": "input",
                "block_id": "emergency_reason_detail",
                "optional": True,
                "label": {"type": "plain_text", "text": "상세 사유"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "reason_detail",
                    "multiline": True,
                    "max_length": 500,
                },
            },
        ],
    }


def _parse_backup_timestamp(name, mtime):
    match = re.search(r"db_backup_(\d{8}_(?:\d{4}|\d{6}))\.sql\.gz\.enc$", name)
    if match:
        try:
            format_string = "%Y%m%d_%H%M" if len(match.group(1).rsplit("_", 1)[1]) == 4 else "%Y%m%d_%H%M%S"
            parsed = datetime.strptime(match.group(1), format_string)
            return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return datetime.fromtimestamp(float(mtime), timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_master_status(status_path):
    try:
        text = status_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    file_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", text, re.IGNORECASE)
    position_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_POS\s*=\s*([0-9]+)", text, re.IGNORECASE)
    if file_match and position_match:
        file_name = file_match.group(1)
        position = int(position_match.group(1))
    else:
        file_match = re.search(r"^\s*(?:File|BinlogFile)\s*:\s*(\S+)\s*$", text, re.IGNORECASE | re.MULTILINE)
        position_match = re.search(r"^\s*(?:Position|BinlogPosition)\s*:\s*([0-9]+)\s*$", text, re.IGNORECASE | re.MULTILINE)
        if not file_match or not position_match:
            return None
        file_name = file_match.group(1)
        position = int(position_match.group(1))

    if not re.fullmatch(r"[A-Za-z0-9._-]+", file_name) or position < 0:
        return None

    timestamp_match = re.search(r"^\s*BackupTimestamp\s*:\s*(\S+)\s*$", text, re.IGNORECASE | re.MULTILINE)
    return {
        "backup_timestamp": _safe_text(timestamp_match.group(1), 80) if timestamp_match else "UNKNOWN",
        "master_status_file": file_name,
        "master_status_position": position,
    }


def _encrypted_container_status(path):
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
        return "PASS" if header == b"Salted__" else "FAIL"
    except OSError:
        return "FAIL"


def _verify_legacy_payload(path, encryption_key):
    """Check a selected Legacy artifact without persisting decrypted bytes."""
    if (
        not isinstance(encryption_key, str)
        or not encryption_key
        or "\n" in encryption_key
        or "\r" in encryption_key
    ):
        return "UNAVAILABLE", "NOT_RUN"

    decrypt = None
    gzip_check = None
    try:
        decrypt = subprocess.Popen(
            [
                "openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-pbkdf2",
                "-in", str(path), "-pass", "stdin",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        gzip_check = subprocess.Popen(
            ["gzip", "-t"],
            stdin=decrypt.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        decrypt.stdout.close()
        decrypt.stdin.write(encryption_key.encode("utf-8") + b"\n")
        decrypt.stdin.close()
        decrypt_status = decrypt.wait(timeout=120)
        gzip_status = gzip_check.wait(timeout=120)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        for process in (gzip_check, decrypt):
            if process is not None and process.poll() is None:
                process.kill()
        for process in (gzip_check, decrypt):
            if process is not None:
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        return "FAIL", "FAIL"

    return (
        "PASS" if decrypt_status == 0 else "FAIL",
        "PASS" if gzip_status == 0 else "FAIL",
    )


def _inspect_dump_backup(path, compute_checksum=True):
    """Validate a dump, legacy sidecar, and optional v1 Manifest metadata."""
    if path.is_symlink() or not path.is_file():
        return None
    status_path = path.with_name(path.name[: -len(".sql.gz.enc")] + ".master_status")
    manifest_path = path.with_name(path.name[: -len(".sql.gz.enc")] + ".manifest.json")
    try:
        stat = path.stat()
        status_stat = status_path.stat()
    except OSError:
        return None
    if (
        not status_path.is_file()
        or status_path.is_symlink()
        or stat.st_size <= 0
        or status_stat.st_size <= 0
    ):
        return None
    status_metadata = _parse_master_status(status_path)
    if status_metadata is None or _encrypted_container_status(path) != "PASS":
        return None
    try:
        sidecar_digest = hashlib.sha256(status_path.read_bytes()).hexdigest()
    except OSError:
        return None
    sidecar_status = "PARSED_SHA256_COMPUTED_UNATTESTED"
    manifest_status = "LEGACY"
    manifest_sha256 = ""
    manifest_cutoff_status = "UNVERIFIED"
    integrity_status = "LEGACY_UNVERIFIED"
    checksum = ""
    manifest_data = None
    if manifest_path.is_symlink():
        return None
    if manifest_path.is_file():
        try:
            if manifest_path.stat().st_size <= 0 or manifest_path.stat().st_size > 64 * 1024:
                return None
            manifest_data = json.loads(
                manifest_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(manifest_data, dict):
            return None
        base = path.name[: -len(".sql.gz.enc")]
        expected_fields = {
            "schema_version", "backup_id", "database_name", "dump_object_key",
            "sidecar_object_key", "manifest_object_key", "ciphertext_sha256",
            "ciphertext_size", "sidecar_sha256", "sidecar_size", "binlog_file",
            "binlog_position", "backup_started_at", "backup_completed_at",
            "data_reference_at", "data_reference_evidence", "manifest_created_at",
        }
        dump_key = str(manifest_data.get("dump_object_key") or "")
        sidecar_key = str(manifest_data.get("sidecar_object_key") or "")
        manifest_key = str(manifest_data.get("manifest_object_key") or "")
        safe_digest = re.compile(r"^[0-9a-f]{64}$")
        try:
            started = datetime.fromisoformat(str(manifest_data.get("backup_started_at", "")).replace("Z", "+00:00"))
            completed = datetime.fromisoformat(str(manifest_data.get("backup_completed_at", "")).replace("Z", "+00:00"))
            created = datetime.fromisoformat(str(manifest_data.get("manifest_created_at", "")).replace("Z", "+00:00"))
            expected_start = datetime.strptime(base.removeprefix("db_backup_"), "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
        evidence = manifest_data.get("data_reference_evidence")
        object_keys = (dump_key, sidecar_key, manifest_key)
        keys_match = (
            all(
                value
                and not value.startswith("/")
                and "\\" not in value
                and str(PurePosixPath(value)) == value
                and not any(part in {"", ".", ".."} for part in value.split("/"))
                for value in object_keys
            )
            and
            Path(dump_key).name == path.name
            and Path(sidecar_key).name == status_path.name
            and Path(manifest_key).name == manifest_path.name
            and len({str(PurePosixPath(value).parent) for value in object_keys}) == 1
        )
        try:
            raw_sidecar_stamp = str(status_metadata.get("backup_timestamp") or "")
            sidecar_started = datetime.fromisoformat(raw_sidecar_stamp.replace("Z", "+00:00"))
            if sidecar_started.tzinfo is None:
                sidecar_started = sidecar_started.replace(tzinfo=timezone.utc)
            sidecar_started = sidecar_started.astimezone(timezone.utc)
        except ValueError:
            try:
                sidecar_started = datetime.strptime(raw_sidecar_stamp, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        if (
            not expected_fields.issubset(manifest_data)
            or manifest_data.get("schema_version") != 1
            or manifest_data.get("backup_id") != path.name
            or manifest_data.get("database_name") != "hospital_db"
            or not keys_match
            or not safe_digest.fullmatch(str(manifest_data.get("ciphertext_sha256", "")))
            or not safe_digest.fullmatch(str(manifest_data.get("sidecar_sha256", "")))
            or isinstance(manifest_data.get("ciphertext_size"), bool)
            or not isinstance(manifest_data.get("ciphertext_size"), int)
            or manifest_data.get("ciphertext_size") != stat.st_size
            or isinstance(manifest_data.get("sidecar_size"), bool)
            or not isinstance(manifest_data.get("sidecar_size"), int)
            or manifest_data.get("sidecar_size") != status_stat.st_size
            or isinstance(manifest_data.get("binlog_position"), bool)
            or not isinstance(manifest_data.get("binlog_position"), int)
            or manifest_data.get("binlog_position") < 1
            or manifest_data.get("sidecar_sha256") != sidecar_digest
            or manifest_data.get("binlog_file") != status_metadata["master_status_file"]
            or manifest_data.get("binlog_position") != status_metadata["master_status_position"]
            or started.utcoffset() != timedelta(0)
            or completed.utcoffset() != timedelta(0)
            or created.utcoffset() != timedelta(0)
            or started != expected_start
            or completed < started
            or created < completed
            or not isinstance(evidence, dict)
            or sidecar_started != started
        ):
            return None
        reference = manifest_data.get("data_reference_at")
        if reference is None and (evidence.get("status") != "UNVERIFIED" or evidence.get("source") is not None):
            return None
        if reference is not None:
            if (
                not isinstance(reference, str)
                or not reference.endswith("Z")
                or evidence.get("status") not in {"VERIFIED", "UNVERIFIED"}
                or not str(evidence.get("source") or "").strip()
            ):
                return None
            try:
                reference_time = datetime.fromisoformat(reference[:-1] + "+00:00")
            except ValueError:
                return None
            if reference_time > completed:
                return None
        manifest_status = "PASS"
        integrity_status = "MANIFEST_METADATA_MATCHED_CIPHERTEXT_HASH_PENDING"
        if compute_checksum:
            try:
                checksum = _sha256(path)
                manifest_sha256 = _sha256(manifest_path)
            except OSError:
                return None
            if checksum != manifest_data["ciphertext_sha256"]:
                return None
            sidecar_status = "MANIFEST_SHA256_MATCHED"
            integrity_status = "MANIFEST_AND_CIPHERTEXT_SHA256_PASS"
    artifact_timestamp = _parse_backup_timestamp(path.name, stat.st_mtime)
    backup_timestamp = status_metadata["backup_timestamp"]
    timestamp_source = "MASTER_STATUS"
    if not backup_timestamp or backup_timestamp.upper() == "UNKNOWN":
        # Older .master_status files may carry only File/Position. Preserve a
        # truthful artifact timestamp rather than propagating the literal
        # string "UNKNOWN" (which is truthy and defeats `or` fallbacks).
        backup_timestamp = artifact_timestamp
        timestamp_source = "ARTIFACT_TIMESTAMP"
    if compute_checksum and not checksum:
        try:
            checksum = _sha256(path)
        except OSError:
            return None
    return {
        "backup_id": path.name,
        "filename": path.name,
        "status_filename": status_path.name,
        "timestamp": artifact_timestamp,
        "backup_timestamp": backup_timestamp,
        "backup_timestamp_source": timestamp_source,
        "size_bytes": stat.st_size,
        "checksum": checksum,
        "checksum_status": "MATCHED_MANIFEST" if checksum and manifest_status == "PASS" else "COMPUTED" if checksum else "NOT_COMPUTED",
        "manifest_status": manifest_status,
        "restore_mode": "LEGACY_MANUAL" if manifest_status == "LEGACY" else "MANIFEST_VERIFIED",
        "legacy_manual": manifest_status == "LEGACY",
        "manifest_filename": manifest_path.name,
        "manifest_checksum": manifest_sha256,
        "sidecar_checksum": sidecar_digest,
        "sidecar_status": sidecar_status,
        "data_reference_time_status": manifest_cutoff_status,
        "data_reference_at": None,
        "data_reference_evidence": {"status": "UNVERIFIED", "source": None},
        "backup_started_at": manifest_data.get("backup_started_at") if manifest_data else None,
        "encrypted": True,
        "encryption_status": "CONTAINER_MARKER_PASS",
        "decryption_status": "NOT_CHECKED" if manifest_status == "LEGACY" else "NOT_REQUIRED",
        "gzip_status": "NOT_CHECKED" if manifest_status == "LEGACY" else "NOT_REQUIRED",
        "integrity_status": integrity_status,
        "master_status_file": status_metadata["master_status_file"],
        "master_status_position": status_metadata["master_status_position"],
        "expected_rpo": (
            {"status": "NOT_MEASURED", "seconds": None}
            if manifest_status == "LEGACY"
            else "UNKNOWN_UNTIL_INCIDENT_TIMESTAMP"
        ),
        "path": str(path),
    }


def list_dump_backups(
    directory,
    limit=MAX_DUMP_OPTIONS,
    compute_checksum=True,
    include_legacy=False,
):
    """Return validated Manifest pairs, plus optional Legacy manual candidates.

    Slack's modal-open acknowledgement has a strict response deadline. The
    selection modal can list Legacy pairs from their parsed sidecar and
    encrypted-container marker. A selected Legacy dump must pass request-time
    OpenSSL decryption and gzip validation before a confirmation is offered.
    """
    root = Path(directory).expanduser()
    if not root.is_dir():
        return []
    results = []
    for path in root.glob("*.sql.gz.enc"):
        item = _inspect_dump_backup(path, compute_checksum=False)
        if item is not None and (
            item["manifest_status"] == "PASS"
            or (include_legacy and item["manifest_status"] == "LEGACY")
        ):
            results.append(item)
    results.sort(key=lambda item: (item["timestamp"], item["backup_id"]), reverse=True)
    results = results[: max(1, int(limit))]
    if compute_checksum:
        verified = []
        for item in results:
            checked = _inspect_dump_backup(Path(item["path"]), compute_checksum=True)
            if checked is not None:
                verified.append(checked)
        return verified
    return results


def resolve_dump_backup(
    directory,
    backup_id,
    *,
    allow_legacy_manual=False,
    encryption_key=None,
    validation_report=None,
):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.sql\.gz\.enc", str(backup_id or "")):
        return None
    root = Path(directory).expanduser()
    result = _inspect_dump_backup(root / backup_id, compute_checksum=True)
    if result is None:
        return None
    if result["manifest_status"] == "PASS":
        return result
    if result["manifest_status"] != "LEGACY" or not allow_legacy_manual:
        return None

    decryption_status, gzip_status = _verify_legacy_payload(result["path"], encryption_key)
    result["decryption_status"] = decryption_status
    result["gzip_status"] = gzip_status
    result["encryption_status"] = "OPENSSL_DECRYPT_" + decryption_status
    result["integrity_status"] = (
        "LEGACY_OPENSSL_AND_GZIP_PASS_UNATTESTED"
        if decryption_status == "PASS" and gzip_status == "PASS"
        else "LEGACY_VERIFICATION_FAILED"
    )
    result["expected_rpo"] = {"status": "NOT_MEASURED", "seconds": None}
    if validation_report is not None:
        validation_report.update(
            {
                "decryption_status": decryption_status,
                "gzip_status": gzip_status,
                "sidecar_status": result["sidecar_status"],
                "manifest_status": "ABSENT",
                "expected_rpo": "NOT_MEASURED",
            }
        )
    if decryption_status != "PASS" or gzip_status != "PASS":
        return None
    return result


def dump_select_view(action, directory, slack_client_key=None, metadata=None):
    metadata = dict(metadata or {})
    metadata.update(
        {
            "action": action,
            "slack_client_key": slack_client_key or metadata.get("slack_client_key") or action,
        }
    )
    backups = list_dump_backups(directory, compute_checksum=False, include_legacy=True)
    options = [
        {
            "text": {
                "type": "plain_text",
                "text": _safe_text(
                    (
                        f"수동 검증 필요 | 시점 미측정 | {item['timestamp']}"
                        if item.get("legacy_manual")
                        else f"{item['timestamp']} | {item['size_bytes']} B | {item['backup_id']}"
                    ),
                    75,
                ),
            },
            "value": item["backup_id"],
        }
        for item in backups
    ]
    if not options:
        options = [{"text": {"type": "plain_text", "text": "선택할 수 있는 백업이 없습니다"}, "value": "NONE"}]
    return {
        "type": "modal",
        "callback_id": "hospital_dr_dump_select",
        "private_metadata": json.dumps(metadata, separators=(",", ":")),
        "title": {"type": "plain_text", "text": "Dump 복구"},
        "submit": {"type": "plain_text", "text": "선택"},
        "close": {"type": "plain_text", "text": "취소"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "복구할 백업을 선택하세요. 공식 백업 검증 정보(Manifest)로 인증되지는 않습니다. "
                        "복구 시점은 미측정(RPO=NOT_MEASURED)입니다."
                    ),
                },
            },
            {
                "type": "input",
                "block_id": "dump_backup",
                "label": {"type": "plain_text", "text": "백업"},
                "element": {
                    "type": "static_select",
                    "action_id": "backup_id",
                    "placeholder": {"type": "plain_text", "text": "복구할 백업을 선택하세요"},
                    "options": options,
                },
            },
        ],
    }


def dump_confirm_view(action, backup, metadata=None):
    metadata = dict(metadata or {})
    legacy_manual = backup.get("restore_mode") == "LEGACY_MANUAL"
    metadata.update(
        {
            "action": action,
            "backup_id": backup["backup_id"],
            "checksum": backup["checksum"],
            "sidecar_checksum": backup.get("sidecar_checksum", ""),
            "timestamp": backup["timestamp"],
            "dump_restore_mode": backup.get("restore_mode", "MANIFEST_VERIFIED"),
        }
    )
    expected_rpo = backup.get("expected_rpo")
    if isinstance(expected_rpo, dict):
        expected_rpo = expected_rpo.get("status") or "NOT_MEASURED"
    text = (
        f"*{backup['timestamp']}* 백업을 선택했습니다.\n"
        f"Backup ID: `{_safe_text(backup['backup_id'], 160)}`\n"
        f"Size: `{backup['size_bytes']}` bytes\n"
        f"Checksum: `{backup['checksum'][:16]}…`\n"
        f"Master status: `{_safe_text(backup['master_status_file'], 100)}:{backup['master_status_position']}`\n"
        f"Encryption: `{backup['encryption_status']}`\n"
        f"Integrity: `{backup['integrity_status']}`\n"
        f"Expected RPO: `{expected_rpo}`\n"
        f"Restore mode: `{backup.get('restore_mode', 'MANIFEST_VERIFIED')}`\n"
        f"Manifest: `{('ABSENT' if backup.get('legacy_manual') else backup.get('manifest_status', 'PASS'))}`\n"
        f"Decryption: `{backup.get('decryption_status', 'NOT_CHECKED')}` | Gzip: `{backup.get('gzip_status', 'NOT_CHECKED')}`\n"
        f"Sidecar: `{backup.get('sidecar_status', 'UNKNOWN')}`\n\n"
        +
        (
            "별도 스키마 Legacy 수동 복원 검토를 위한 2인 승인 요청을 만드시겠습니까? "
            "자동 복원과 hospital_db 덮어쓰기는 실행되지 않습니다."
            if legacy_manual
            else "선택한 Dump 백업 파일로 Failover 승인 요청을 진행하시겠습니까?"
        )
    )
    return {
        "type": "modal",
        "callback_id": "hospital_dr_dump_confirm",
        "private_metadata": json.dumps(metadata, separators=(",", ":")),
        "title": {
            "type": "plain_text",
            "text": "Legacy 수동 복원 확인" if legacy_manual else "Dump 복구 확인",
        },
        "submit": {"type": "plain_text", "text": "제출"},
        "close": {"type": "plain_text", "text": "아니오"},
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {
                "type": "input",
                "block_id": "dump_confirm",
                "label": {"type": "plain_text", "text": "확인"},
                "element": {
                    "type": "radio_buttons",
                    "action_id": "confirm_choice",
                    "options": [
                        {"text": {"type": "plain_text", "text": "예"}, "value": "YES"},
                        {"text": {"type": "plain_text", "text": "아니오"}, "value": "NO"},
                    ],
                },
            },
        ],
    }


def dump_verification_view(metadata=None, message="선택한 백업을 검증하고 있습니다. 잠시만 기다려 주세요."):
    """Build a short-lived modal while a selected dump is hashed off-request."""
    return {
        "type": "modal",
        "callback_id": "hospital_dr_dump_verification",
        "private_metadata": json.dumps(dict(metadata or {}), separators=(",", ":")),
        "title": {"type": "plain_text", "text": "백업 확인"},
        "close": {"type": "plain_text", "text": "닫기"},
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": _safe_text(message, 500)}}],
    }


def dump_request_result_view(message, request_id=None, clear_on_close=False):
    """Build the final read-only result shown after asynchronous dump handling."""
    text = _safe_text(message, 500)
    if request_id:
        text = f"{text}\n요청 ID: `{_safe_text(request_id, 120)}`"
    view = {
        "type": "modal",
        "callback_id": "hospital_dr_dump_result",
        "title": {"type": "plain_text", "text": "Dump 요청 결과"},
        "close": {"type": "plain_text", "text": "닫기"},
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }
    if clear_on_close:
        view["clear_on_close"] = True
    return view
