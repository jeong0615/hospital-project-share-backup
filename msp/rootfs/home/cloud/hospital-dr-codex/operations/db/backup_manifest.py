#!/usr/bin/env python3
"""Create and validate immutable metadata for encrypted database backups.

The existing ``.master_status`` remains a MySQL-compatible replication
coordinate artifact. This JSON manifest binds that sidecar to the exact
encrypted bytes and object keys. It never infers a recovered-data cutoff from
the backup job clock or binlog coordinates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


BACKUP_ID_RE = re.compile(r"db_backup_(\d{8}_\d{6})\.sql\.gz\.enc\Z")
BINLOG_FILE_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SERVER_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.I)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIDECAR_BYTES = 16 * 1024
MAX_SOURCE_OBSERVATION_BYTES = 4096
REQUIRED_FIELDS = {
    "schema_version", "backup_id", "database_name", "dump_object_key",
    "sidecar_object_key", "manifest_object_key", "ciphertext_sha256",
    "ciphertext_size", "sidecar_sha256", "sidecar_size", "binlog_file",
    "binlog_position", "backup_started_at", "backup_completed_at",
    "data_reference_at", "data_reference_evidence", "manifest_created_at",
}


class ManifestError(ValueError):
    """Stable, safe failure category; never contains artifact contents."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if not raw.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed.astimezone(timezone.utc)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise ManifestError("ARTIFACT_UNREADABLE") from exc
    return digest.hexdigest(), size


def _safe_key(value: Any) -> str:
    key = str(value or "")
    path = PurePosixPath(key)
    if not key or key.startswith("/") or "\\" in key or any(part in {"", ".", ".."} for part in key.split("/")):
        raise ManifestError("OBJECT_KEY_INVALID")
    if str(path) != key:
        raise ManifestError("OBJECT_KEY_INVALID")
    return key


def _key_names(backup_id: str, dump_key: str, sidecar_key: str, manifest_key: str) -> None:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ManifestError("BACKUP_ID_INVALID")
    dump_key = _safe_key(dump_key)
    sidecar_key = _safe_key(sidecar_key)
    manifest_key = _safe_key(manifest_key)
    expected_sidecar = backup_id.removesuffix(".sql.gz.enc") + ".master_status"
    expected_manifest = backup_id.removesuffix(".sql.gz.enc") + ".manifest.json"
    parents = {str(PurePosixPath(key).parent) for key in (dump_key, sidecar_key, manifest_key)}
    if (
        PurePosixPath(dump_key).name != backup_id
        or PurePosixPath(sidecar_key).name != expected_sidecar
        or PurePosixPath(manifest_key).name != expected_manifest
        or len(parents) != 1
    ):
        raise ManifestError("OBJECT_KEY_IDENTITY_MISMATCH")


def parse_sidecar_text(text: str) -> dict[str, Any]:
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ManifestError("SIDECAR_INVALID_FORMAT") from exc
    if len(encoded) > MAX_SIDECAR_BYTES:
        raise ManifestError("SIDECAR_INVALID_FORMAT")
    file_match = re.search(r"^\s*(?:BinlogFile|File)\s*:\s*(\S+)\s*$", text, re.I | re.M)
    pos_match = re.search(r"^\s*(?:BinlogPosition|Position)\s*:\s*([0-9]+)\s*$", text, re.I | re.M)
    timestamp_match = re.search(r"^\s*BackupTimestamp\s*:\s*(\S+)\s*$", text, re.I | re.M)
    if not file_match or not pos_match:
        statement = re.search(
            r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b(?P<body>.*?)(?:;|$)",
            text, re.I | re.S,
        )
        body = statement.group("body") if statement else ""
        file_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", body, re.I)
        pos_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_POS\s*=\s*([0-9]+)", body, re.I)
    if not file_match or not pos_match:
        raise ManifestError("MISSING_BINLOG_COORDINATES")
    binlog_file = file_match.group(1)
    try:
        binlog_position = int(pos_match.group(1))
    except (TypeError, ValueError) as exc:
        raise ManifestError("BINLOG_COORDINATES_INVALID") from exc
    if not BINLOG_FILE_RE.fullmatch(binlog_file) or binlog_position < 1:
        raise ManifestError("BINLOG_COORDINATES_INVALID")
    return {
        "binlog_file": binlog_file,
        "binlog_position": binlog_position,
        "backup_timestamp": timestamp_match.group(1) if timestamp_match else None,
        "format": "MASTER_STATUS_TEXT" if timestamp_match else "LEGACY_COORDINATES_ONLY",
    }


def parse_sidecar(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ManifestError("SIDECAR_MISSING")
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ManifestError("SIDECAR_UNREADABLE") from exc
    return parse_sidecar_text(text)


def parse_source_observation_text(text: str) -> dict[str, Any]:
    """Parse a metadata-only MySQL UTC clock/identity sample taken before dump.

    This is intentionally an observation, not proof of the mysqldump snapshot
    cutoff. It remains UNVERIFIED until an independent consistency proof exists.
    """
    if len(text.encode("utf-8", errors="strict")) > MAX_SOURCE_OBSERVATION_BYTES:
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    lines = text.splitlines()
    if len(lines) != 1:
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    fields = lines[0].split("\t")
    if len(fields) != 3:
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    observed_at, server_uuid, raw_server_id = fields
    if parse_utc(observed_at) is None or not SERVER_UUID_RE.fullmatch(server_uuid):
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    if not raw_server_id.isascii() or not raw_server_id.isdigit():
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    server_id = int(raw_server_id)
    if server_id > 4294967295:
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    return {
        "observed_at": observed_at,
        "server_uuid": server_uuid.lower(),
        "server_id": server_id,
    }


def parse_source_observation(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ManifestError("SOURCE_OBSERVATION_INVALID")
    try:
        if path.stat().st_size > MAX_SOURCE_OBSERVATION_BYTES:
            raise ManifestError("SOURCE_OBSERVATION_INVALID")
        return parse_source_observation_text(path.read_text(encoding="utf-8", errors="strict"))
    except ManifestError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ManifestError("SOURCE_OBSERVATION_INVALID") from exc


def parse_embedded_dump_position(path: Path) -> tuple[str, int]:
    try:
        with path.open("r", encoding="utf-8", errors="strict") as stream:
            collecting = False
            statement = ""
            for line in stream:
                if not collecting:
                    if not re.search(r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b", line, re.I):
                        continue
                    collecting = True
                statement += line
                if len(statement.encode("utf-8")) > 16 * 1024:
                    raise ManifestError("DUMP_BINLOG_COORDINATES_INVALID")
                match = re.search(
                    r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b(?P<body>.*?)(?:;|$)",
                    statement, re.I | re.S,
                )
                if match:
                    body = match.group("body")
                    file_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", body, re.I)
                    pos_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_POS\s*=\s*([0-9]+)", body, re.I)
                    if file_match and pos_match:
                        filename = file_match.group(1)
                        position = int(pos_match.group(1))
                        if BINLOG_FILE_RE.fullmatch(filename) and position > 0:
                            return filename, position
                    if ";" in statement:
                        collecting = False
                        statement = ""
    except ManifestError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ManifestError("DUMP_SQL_UNREADABLE") from exc
    raise ManifestError("DUMP_BINLOG_COORDINATES_MISSING")


def _duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("MANIFEST_DUPLICATE_FIELD")
        result[key] = value
    return result


def parse_manifest_text(text: str) -> dict[str, Any]:
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ManifestError("MANIFEST_INVALID_FORMAT") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ManifestError("MANIFEST_INVALID_FORMAT")
    try:
        document = json.loads(text, object_pairs_hook=_duplicate_rejecting_pairs)
    except ManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("MANIFEST_INVALID_FORMAT") from exc
    if not isinstance(document, dict):
        raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    missing = REQUIRED_FIELDS - set(document)
    if missing:
        raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    return document


def validate_snapshot_boundary_candidate(document: dict[str, Any]) -> dict[str, Any] | None:
    """Validate artifact/Position binding without promoting time to RPO proof."""
    candidate = document.get("snapshot_boundary_candidate")
    if candidate is None:
        return None
    observation = document.get("data_reference_observation")
    if (
        not isinstance(candidate, dict)
        or not isinstance(observation, dict)
        or candidate.get("status") != "UNVERIFIED"
        or candidate.get("method") != "MYSQLDUMP_SINGLE_TRANSACTION_SOURCE_DATA"
        or candidate.get("time_relation") != "PRE_DUMP_OBSERVATION_PRECEDES_DUMP_INVOCATION_ONLY"
        or candidate.get("reason") != "SOURCE_ID_CLOCK_AND_SNAPSHOT_BOUNDARY_NOT_AUTHENTICATED"
        or candidate.get("observed_at") != observation.get("observed_at")
        or candidate.get("server_uuid") != observation.get("server_uuid")
        or candidate.get("server_id") != observation.get("server_id")
        or candidate.get("binlog_file") != document.get("binlog_file")
        or candidate.get("binlog_position") != document.get("binlog_position")
        or candidate.get("ciphertext_sha256") != document.get("ciphertext_sha256")
        or candidate.get("ciphertext_size") != document.get("ciphertext_size")
        or candidate.get("sidecar_sha256") != document.get("sidecar_sha256")
        or candidate.get("sidecar_size") != document.get("sidecar_size")
        or parse_utc(candidate.get("observed_at")) is None
    ):
        raise ManifestError("MANIFEST_SNAPSHOT_BOUNDARY_BINDING_INVALID")
    return candidate


def load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ManifestError("BACKUP_MANIFEST_LEGACY_UNVERIFIED")
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("MANIFEST_INVALID_FORMAT")
        text = path.read_text(encoding="utf-8")
    except ManifestError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ManifestError("MANIFEST_INVALID_FORMAT") from exc
    return parse_manifest_text(text)


def validate_manifest_document(
    document: dict[str, Any], *, backup_id: str, dump_key: str, sidecar_key: str,
    manifest_key: str, dump_size: int | None = None, sidecar_size: int | None = None,
    expected_sha256: str = "", expected_sidecar_sha256: str = "",
) -> dict[str, Any]:
    if document.get("schema_version") != 1 or document.get("database_name") != "hospital_db":
        raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    _key_names(backup_id, dump_key, sidecar_key, manifest_key)
    if (
        document.get("backup_id") != backup_id
        or document.get("dump_object_key") != dump_key
        or document.get("sidecar_object_key") != sidecar_key
        or document.get("manifest_object_key") != manifest_key
    ):
        raise ManifestError("MANIFEST_OBJECT_IDENTITY_MISMATCH")
    for field in ("ciphertext_sha256", "sidecar_sha256"):
        if not isinstance(document.get(field), str) or not SHA256_RE.fullmatch(document[field]):
            raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    for field in ("ciphertext_size", "sidecar_size", "binlog_position"):
        value = document.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    if not BINLOG_FILE_RE.fullmatch(str(document.get("binlog_file") or "")):
        raise ManifestError("MANIFEST_SCHEMA_MISMATCH")
    if dump_size is not None and document["ciphertext_size"] != dump_size:
        raise ManifestError("MANIFEST_DUMP_SIZE_MISMATCH")
    if sidecar_size is not None and document["sidecar_size"] != sidecar_size:
        raise ManifestError("MANIFEST_SIDECAR_SIZE_MISMATCH")
    if expected_sha256 and document["ciphertext_sha256"] != expected_sha256.lower():
        raise ManifestError("CHECKSUM_MISMATCH")
    if expected_sidecar_sha256 and document["sidecar_sha256"] != expected_sidecar_sha256.lower():
        raise ManifestError("SIDECAR_CHECKSUM_MISMATCH")

    match = BACKUP_ID_RE.fullmatch(backup_id)
    stamp = datetime.strptime(match.group(1), "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
    start = parse_utc(document.get("backup_started_at"))
    completed = parse_utc(document.get("backup_completed_at"))
    created = parse_utc(document.get("manifest_created_at"))
    if not all((start, completed, created)) or start != stamp or completed < start or created < completed:
        raise ManifestError("MANIFEST_TIMESTAMP_INVALID")

    reference = document.get("data_reference_at")
    evidence = document.get("data_reference_evidence")
    if reference is None:
        if not isinstance(evidence, dict) or evidence.get("status") != "UNVERIFIED" or evidence.get("source") is not None:
            raise ManifestError("MANIFEST_DATA_REFERENCE_EVIDENCE_INVALID")
        reference_status = "UNVERIFIED"
    else:
        reference_time = parse_utc(reference)
        if (
            reference_time is None or reference_time > completed or not isinstance(evidence, dict)
            or not str(evidence.get("source") or "").strip()
            or evidence.get("status") not in {"VERIFIED", "UNVERIFIED"}
        ):
            raise ManifestError("MANIFEST_DATA_REFERENCE_EVIDENCE_INVALID")
        # A manifest claim alone is not an independently authenticated proof.
        reference_status = "UNVERIFIED"
    source_observation = document.get("data_reference_observation")
    if source_observation is not None:
        observed_server_id = source_observation.get("server_id") if isinstance(source_observation, dict) else None
        if (
            not isinstance(source_observation, dict)
            or isinstance(observed_server_id, bool)
            or not isinstance(observed_server_id, int)
            or source_observation.get("source") != "mysql_utc_clock_before_mysqldump"
            or source_observation.get("phase") != "PRE_DUMP_SEPARATE_CONNECTION"
            or source_observation.get("status") != "UNVERIFIED"
            or source_observation.get("reason") != "NOT_PROVEN_SNAPSHOT_CUTOFF"
        ):
            raise ManifestError("MANIFEST_DATA_REFERENCE_EVIDENCE_INVALID")
        parse_source_observation_text("\t".join((
            str(source_observation.get("observed_at") or ""),
            str(source_observation.get("server_uuid") or ""),
            str(observed_server_id),
        )))
    validate_snapshot_boundary_candidate(document)
    return {
        "status": "PASS",
        "backup_id": backup_id,
        "dump_object_key": dump_key,
        "sidecar_object_key": sidecar_key,
        "manifest_object_key": manifest_key,
        "ciphertext_sha256": document["ciphertext_sha256"],
        "ciphertext_size": document["ciphertext_size"],
        "sidecar_sha256": document["sidecar_sha256"],
        "sidecar_size": document["sidecar_size"],
        "binlog_file": document["binlog_file"],
        "binlog_position": document["binlog_position"],
        "data_reference_time_status": reference_status,
        "data_reference_at": reference if reference_status == "VERIFIED" else None,
    }


def validate_manifest_sidecar_content(
    document: dict[str, Any], *, backup_id: str, dump_key: str,
    sidecar_key: str, manifest_key: str, sidecar_content: str,
    dump_size: int | None = None, sidecar_size: int | None = None,
    expected_sha256: str = "", expected_sidecar_sha256: str = "",
) -> dict[str, Any]:
    encoded = sidecar_content.encode("utf-8", errors="strict")
    result = validate_manifest_document(
        document, backup_id=backup_id, dump_key=dump_key,
        sidecar_key=sidecar_key, manifest_key=manifest_key,
        dump_size=dump_size, sidecar_size=sidecar_size,
        expected_sha256=expected_sha256,
        expected_sidecar_sha256=expected_sidecar_sha256,
    )
    if len(encoded) != document["sidecar_size"] or len(encoded) > MAX_SIDECAR_BYTES:
        raise ManifestError("MANIFEST_SIDECAR_SIZE_MISMATCH")
    if hashlib.sha256(encoded).hexdigest() != document["sidecar_sha256"]:
        raise ManifestError("SIDECAR_CHECKSUM_MISMATCH")
    sidecar = parse_sidecar_text(sidecar_content)
    if (sidecar["binlog_file"], sidecar["binlog_position"]) != (
        document["binlog_file"], document["binlog_position"]
    ):
        raise ManifestError("MANIFEST_SIDECAR_COORDINATE_MISMATCH")
    start = parse_utc(document["backup_started_at"])
    sidecar_stamp = sidecar.get("backup_timestamp")
    parsed_stamp = parse_utc(sidecar_stamp)
    if parsed_stamp is None and sidecar_stamp:
        try:
            parsed_stamp = datetime.strptime(sidecar_stamp, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            parsed_stamp = None
    if start is None or parsed_stamp != start:
        raise ManifestError("SIDECAR_BACKUP_ID_MISMATCH")
    return result


def create_manifest_document(
    *, backup_id: str, database_name: str, dump_path: Path, sidecar_path: Path,
    object_prefix: str, backup_started_at: str, backup_completed_at: str,
    dump_sql_path: Path | None = None, source_observation_path: Path | None = None,
) -> dict[str, Any]:
    if database_name != "hospital_db":
        raise ManifestError("DATABASE_NAME_INVALID")
    match = BACKUP_ID_RE.fullmatch(backup_id)
    if not match or dump_path.name != backup_id:
        raise ManifestError("BACKUP_ID_INVALID")
    try:
        with dump_path.open("rb") as stream:
            if stream.read(8) != b"Salted__":
                raise ManifestError("ENCRYPTED_CONTAINER_INVALID")
    except OSError as exc:
        raise ManifestError("ARTIFACT_UNREADABLE") from exc
    started = parse_utc(backup_started_at)
    completed = parse_utc(backup_completed_at)
    expected_start = datetime.strptime(match.group(1), "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
    if started is None or started != expected_start or completed is None or completed < started:
        raise ManifestError("MANIFEST_TIMESTAMP_INVALID")
    sidecar = parse_sidecar(sidecar_path)
    sidecar_stamp = sidecar.get("backup_timestamp")
    parsed_sidecar_stamp = None
    if sidecar_stamp:
        parsed_sidecar_stamp = parse_utc(sidecar_stamp)
        if parsed_sidecar_stamp is None:
            try:
                parsed_sidecar_stamp = datetime.strptime(sidecar_stamp, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                raise ManifestError("SIDECAR_TIMESTAMP_INVALID")
    if parsed_sidecar_stamp != started:
        raise ManifestError("SIDECAR_BACKUP_ID_MISMATCH")
    if dump_sql_path is None:
        raise ManifestError("DUMP_SQL_COORDINATE_SOURCE_REQUIRED")
    embedded_file, embedded_position = parse_embedded_dump_position(dump_sql_path)
    if (embedded_file, embedded_position) != (sidecar["binlog_file"], sidecar["binlog_position"]):
        raise ManifestError("DUMP_SIDECAR_COORDINATE_MISMATCH")

    dump_sha, dump_size = sha256_file(dump_path)
    sidecar_sha, sidecar_size = sha256_file(sidecar_path)
    prefix = str(object_prefix or "").strip("/")
    dump_key = f"{prefix}/{backup_id}" if prefix else backup_id
    base = backup_id.removesuffix(".sql.gz.enc")
    sidecar_key = f"{prefix}/{base}.master_status" if prefix else f"{base}.master_status"
    manifest_key = f"{prefix}/{base}.manifest.json" if prefix else f"{base}.manifest.json"
    _key_names(backup_id, dump_key, sidecar_key, manifest_key)
    source_observation = (
        parse_source_observation(source_observation_path)
        if source_observation_path is not None else None
    )
    snapshot_boundary_candidate = None
    if source_observation is not None:
        # This records only a potential lower-bound ordering candidate: the
        # sample is captured before invoking mysqldump and the Dump embeds a
        # Position. It is not a snapshot timestamp or trusted RPO proof. The
        # separate sample does not authenticate clock sync, endpoint identity
        # at snapshot time, or the transactional-engine/no-DDL assumptions.
        snapshot_boundary_candidate = {
            "status": "UNVERIFIED",
            "method": "MYSQLDUMP_SINGLE_TRANSACTION_SOURCE_DATA",
            "time_relation": "PRE_DUMP_OBSERVATION_PRECEDES_DUMP_INVOCATION_ONLY",
            "observed_at": source_observation["observed_at"],
            "server_uuid": source_observation["server_uuid"],
            "server_id": source_observation["server_id"],
            "binlog_file": embedded_file,
            "binlog_position": embedded_position,
            "ciphertext_sha256": dump_sha,
            "ciphertext_size": dump_size,
            "sidecar_sha256": sidecar_sha,
            "sidecar_size": sidecar_size,
            "reason": "SOURCE_ID_CLOCK_AND_SNAPSHOT_BOUNDARY_NOT_AUTHENTICATED",
        }
    return {
        "schema_version": 1,
        "backup_id": backup_id,
        "database_name": database_name,
        "dump_object_key": dump_key,
        "sidecar_object_key": sidecar_key,
        "manifest_object_key": manifest_key,
        "ciphertext_sha256": dump_sha,
        "ciphertext_size": dump_size,
        "sidecar_sha256": sidecar_sha,
        "sidecar_size": sidecar_size,
        "binlog_file": embedded_file,
        "binlog_position": embedded_position,
        "backup_started_at": started.isoformat().replace("+00:00", "Z"),
        "backup_completed_at": completed.isoformat().replace("+00:00", "Z"),
        "data_reference_at": None,
        "data_reference_evidence": {
            "status": "UNVERIFIED",
            "source": None,
            "reason": "NO_TRUSTED_DATA_CUTOFF_SOURCE",
        },
        "data_reference_observation": (
            {
                **source_observation,
                "source": "mysql_utc_clock_before_mysqldump",
                "phase": "PRE_DUMP_SEPARATE_CONNECTION",
                "status": "UNVERIFIED",
                "reason": "NOT_PROVEN_SNAPSHOT_CUTOFF",
            }
            if source_observation is not None else None
        ),
        "snapshot_boundary_candidate": snapshot_boundary_candidate,
        "manifest_created_at": utc_now(),
    }


def write_manifest(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ManifestError("MANIFEST_OUTPUT_ALREADY_EXISTS")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=True, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        path.chmod(0o600)
    except FileExistsError as exc:
        raise ManifestError("MANIFEST_OUTPUT_ALREADY_EXISTS") from exc
    except OSError as exc:
        raise ManifestError("MANIFEST_WRITE_FAILED") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def verify_manifest_files(
    dump_path: Path, sidecar_path: Path, manifest_path: Path, *, expected_sha256: str,
    expected_sidecar_sha256: str = "", expected_manifest_sha256: str = "",
    expected_object_prefix: str | None = None,
) -> dict[str, Any]:
    if dump_path.is_symlink() or not dump_path.is_file():
        raise ManifestError("DUMP_MISSING")
    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        raise ManifestError("SIDECAR_MISSING")
    document = load_manifest(manifest_path)
    try:
        with dump_path.open("rb") as stream:
            if stream.read(8) != b"Salted__":
                raise ManifestError("ENCRYPTED_CONTAINER_INVALID")
    except OSError as exc:
        raise ManifestError("ARTIFACT_UNREADABLE") from exc
    backup_id = dump_path.name
    base = backup_id.removesuffix(".sql.gz.enc")
    dump_key = document.get("dump_object_key")
    sidecar_key = document.get("sidecar_object_key")
    manifest_key = document.get("manifest_object_key")
    result = validate_manifest_document(
        document, backup_id=backup_id, dump_key=str(dump_key or ""),
        sidecar_key=str(sidecar_key or ""), manifest_key=str(manifest_key or ""),
        dump_size=dump_path.stat().st_size, sidecar_size=sidecar_path.stat().st_size,
        expected_sha256=expected_sha256,
        expected_sidecar_sha256=expected_sidecar_sha256,
    )
    if expected_object_prefix is not None:
        prefix = str(expected_object_prefix).strip("/")
        expected_parent = prefix or "."
        if any(str(PurePosixPath(document[key]).parent) != expected_parent for key in (
            "dump_object_key", "sidecar_object_key", "manifest_object_key"
        )):
            raise ManifestError("MANIFEST_OBJECT_PREFIX_MISMATCH")
    expected_manifest_path = manifest_path.with_name(f"{base}.manifest.json")
    expected_sidecar_path = manifest_path.with_name(f"{base}.master_status")
    if sidecar_path.resolve() != expected_sidecar_path.resolve() or manifest_path.name != expected_manifest_path.name:
        raise ManifestError("LOCAL_ARTIFACT_IDENTITY_MISMATCH")
    try:
        sidecar_content = sidecar_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ManifestError("SIDECAR_UNREADABLE") from exc
    validate_manifest_sidecar_content(
        document, backup_id=backup_id, dump_key=str(dump_key or ""),
        sidecar_key=str(sidecar_key or ""), manifest_key=str(manifest_key or ""),
        sidecar_content=sidecar_content, dump_size=dump_path.stat().st_size,
        sidecar_size=sidecar_path.stat().st_size,
        expected_sha256=expected_sha256,
        expected_sidecar_sha256=expected_sidecar_sha256,
    )
    actual_dump_sha, actual_dump_size = sha256_file(dump_path)
    if actual_dump_size != result["ciphertext_size"] or actual_dump_sha != result["ciphertext_sha256"]:
        raise ManifestError("CHECKSUM_MISMATCH")
    actual_sidecar_sha, actual_sidecar_size = sha256_file(sidecar_path)
    if actual_sidecar_size != result["sidecar_size"] or actual_sidecar_sha != result["sidecar_sha256"]:
        raise ManifestError("SIDECAR_CHECKSUM_MISMATCH")
    manifest_sha, _ = sha256_file(manifest_path)
    if expected_manifest_sha256 and manifest_sha != expected_manifest_sha256.lower():
        raise ManifestError("MANIFEST_CHECKSUM_MISMATCH")
    return {**result, "manifest_sha256": manifest_sha, "data_reference_time_status": "UNVERIFIED"}


def evaluate_rpo(
    *, data_reference_at: str | None, incident_at: str | None,
    evidence_status: str, evidence_source: str | None,
    evidence_authenticated: bool = False, target_seconds: int = 900,
) -> dict[str, Any]:
    """Compute RPO only from independently authenticated cutoff evidence."""
    base = {"target_seconds": target_seconds, "rpo_seconds": None, "data_reference_at": None}
    if not evidence_authenticated or evidence_status != "VERIFIED" or not evidence_source:
        return {**base, "status": "NOT_MEASURED", "reason": "RECOVERED_DATA_CUTOFF_NOT_VERIFIED"}
    cutoff = parse_utc(data_reference_at)
    incident = parse_utc(incident_at)
    if cutoff is None or incident is None or cutoff > incident:
        return {**base, "status": "NOT_MEASURED", "reason": "RPO_TIMESTAMPS_INVALID"}
    seconds = int((incident - cutoff).total_seconds())
    if seconds < 0:
        return {**base, "status": "NOT_MEASURED", "reason": "RPO_TIMESTAMPS_INVALID"}
    status = "PASS" if seconds <= target_seconds else "RPO_NOT_GUARANTEED"
    return {
        "target_seconds": target_seconds,
        "rpo_seconds": seconds,
        "data_reference_at": cutoff.isoformat().replace("+00:00", "Z"),
        "evidence_source": evidence_source,
        "status": status,
        "reason": "MEASURED_FROM_VERIFIED_DATA_CUTOFF",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_observation = subparsers.add_parser("check-source-observation")
    check_observation.add_argument("--source-observation", required=True)
    create = subparsers.add_parser("create")
    for option in ("dump", "dump-sql", "sidecar", "output", "backup-id", "object-prefix", "backup-started-at", "backup-completed-at"):
        create.add_argument(f"--{option}", required=True)
    create.add_argument("--database-name", default="hospital_db")
    create.add_argument("--source-observation", default=None)
    verify = subparsers.add_parser("verify")
    for option in ("dump", "sidecar", "manifest"):
        verify.add_argument(f"--{option}", required=True)
    verify.add_argument("--expected-sha256", default="")
    verify.add_argument("--expected-sidecar-sha256", default="")
    verify.add_argument("--expected-manifest-sha256", default="")
    verify.add_argument("--expected-object-prefix", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "check-source-observation":
            parse_source_observation(Path(args.source_observation))
            print("SOURCE_OBSERVATION=VALID_UNVERIFIED")
            return 0
        if args.command == "create":
            document = create_manifest_document(
                backup_id=args.backup_id, database_name=args.database_name,
                dump_path=Path(args.dump), sidecar_path=Path(args.sidecar),
                object_prefix=args.object_prefix, backup_started_at=args.backup_started_at,
                backup_completed_at=args.backup_completed_at, dump_sql_path=Path(args.dump_sql),
                source_observation_path=(Path(args.source_observation) if args.source_observation else None),
            )
            write_manifest(Path(args.output), document)
            print("BACKUP_MANIFEST=CREATED")
            return 0
        result = verify_manifest_files(
            Path(args.dump), Path(args.sidecar), Path(args.manifest),
            expected_sha256=args.expected_sha256,
            expected_sidecar_sha256=args.expected_sidecar_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_object_prefix=args.expected_object_prefix,
        )
        print(
            "BACKUP_MANIFEST=VERIFIED "
            f"BACKUP_ID={result['backup_id']} BINLOG_COORDINATES=PASS "
            "DATA_REFERENCE_TIME=UNVERIFIED"
        )
        return 0
    except (ManifestError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, ManifestError) else "MANIFEST_VALIDATION_FAILED"
        print(f"BACKUP_MANIFEST=BLOCKED reason={code}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
