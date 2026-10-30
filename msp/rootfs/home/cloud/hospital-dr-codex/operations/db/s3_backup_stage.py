#!/usr/bin/env python3
"""Stage one request-pinned S3 backup set into the local Dump restore directory.

This utility only downloads encrypted backup artifacts. It never decrypts a
Dump or invokes a database/restore command. The named AWS profile must resolve
to the dedicated restore Reader Role, and all three artifact hashes/identities
are revalidated before any final path is created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from operations.db.backup_manifest import (  # noqa: E402
    MAX_MANIFEST_BYTES,
    MAX_SIDECAR_BYTES,
    ManifestError,
    parse_manifest_text,
    verify_manifest_files,
)

BACKUP_ID_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{6}\.sql\.gz\.enc\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
PROFILE_RE = re.compile(r"[A-Za-z0-9_+=,.@-]{1,128}\Z")
DEFAULT_PREFIX = "mysql/hospital_db"
AWS_TIMEOUT_SECONDS = 90
MIN_FREE_BYTES = 16 * 1024 * 1024
AWS_CREDENTIAL_ENV = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_PROFILE",
)


class StageError(RuntimeError):
    """Stable failure code that never includes AWS output or artifact bytes."""


def _safe_id(value: str) -> str:
    if not BACKUP_ID_RE.fullmatch(str(value or "")) or Path(value).name != value:
        raise StageError("BACKUP_ID_INVALID")
    return value


def _safe_sha(value: str, code: str) -> str:
    normalized = str(value or "").lower()
    if not SHA256_RE.fullmatch(normalized):
        raise StageError(code)
    return normalized


def _safe_directory(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise StageError("DUMP_BACKUP_DIR_UNAVAILABLE") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StageError("DUMP_BACKUP_DIR_PERMISSIONS_UNSAFE")
    return path.resolve(strict=True)


def _role_parts(role_arn: str) -> tuple[str, str]:
    match = re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/(.+)", str(role_arn or ""))
    if not match or any(part in {"", ".", ".."} for part in match.group(2).split("/")):
        raise StageError("RESTORE_ROLE_ARN_INVALID")
    return match.group(1), match.group(2)


def _aws_environment() -> dict[str, str]:
    child = dict(os.environ)
    for name in AWS_CREDENTIAL_ENV:
        child.pop(name, None)
    child["AWS_PAGER"] = ""
    child["AWS_CLI_AUTO_PROMPT"] = "off"
    return child


def _failure_code(stderr: str) -> str:
    value = str(stderr or "").lower()
    if "accessdenied" in value or "access denied" in value or "403" in value:
        return "S3_GET_ACCESS_DENIED"
    if "nosuchkey" in value or "not found" in value or "404" in value:
        return "S3_OBJECT_MISSING"
    if "expiredtoken" in value or "invalidclienttokenid" in value:
        return "RESTORE_PROFILE_AUTH_FAILED"
    return "AWS_CALL_FAILED"


def _aws_json(
    profile: str,
    region: str,
    arguments: list[str],
    *,
    runner: Callable = subprocess.run,
) -> dict:
    try:
        result = runner(
            ["aws", "--profile", profile, "--region", region, "--output", "json", *arguments],
            env=_aws_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=AWS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise StageError("AWS_CALL_TIMEOUT") from exc
    except OSError as exc:
        raise StageError("AWS_CLI_UNAVAILABLE") from exc
    if result.returncode != 0:
        raise StageError(_failure_code(result.stderr))
    try:
        value = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise StageError("AWS_RESPONSE_INVALID") from exc
    if not isinstance(value, dict):
        raise StageError("AWS_RESPONSE_INVALID")
    return value


def _verify_reader_identity(
    *, profile: str, role_arn: str, region: str, runner: Callable,
) -> str:
    account, role_path = _role_parts(role_arn)
    identity = _aws_json(profile, region, ["sts", "get-caller-identity"], runner=runner)
    expected_prefix = f"arn:aws:sts::{account}:assumed-role/{role_path}/"
    arn = str(identity.get("Arn") or "")
    if identity.get("Account") != account or not arn.startswith(expected_prefix):
        raise StageError("RESTORE_ROLE_IDENTITY_MISMATCH")
    return arn.split("/")[-1]  # Safe session name only; no credentials are returned.


def _head_size(
    *, profile: str, region: str, bucket: str, key: str, runner: Callable,
    limit: int | None = None,
) -> int:
    response = _aws_json(
        profile, region,
        ["s3api", "head-object", "--bucket", bucket, "--key", key],
        runner=runner,
    )
    size = response.get("ContentLength")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise StageError("S3_OBJECT_SIZE_INVALID")
    if limit is not None and size > limit:
        raise StageError("S3_METADATA_OBJECT_TOO_LARGE")
    return size


def _download(
    *, profile: str, region: str, bucket: str, key: str, path: Path,
    expected_size: int, runner: Callable,
) -> dict:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    except OSError as exc:
        raise StageError("STAGING_TEMP_CREATE_FAILED") from exc
    response = _aws_json(
        profile, region,
        ["s3api", "get-object", "--bucket", bucket, "--key", key, str(path)],
        runner=runner,
    )
    try:
        os.chmod(path, 0o600, follow_symlinks=False)
        actual_size = path.stat(follow_symlinks=False).st_size
    except OSError as exc:
        raise StageError("S3_DOWNLOAD_INCOMPLETE") from exc
    if (
        isinstance(response.get("ContentLength"), bool)
        or not isinstance(response.get("ContentLength"), int)
        or response["ContentLength"] != expected_size
        or actual_size != expected_size
    ):
        raise StageError("S3_OBJECT_SIZE_MISMATCH")
    digest = _sha256(path)
    return {"sha256": digest, "size_bytes": actual_size, "version_id": response.get("VersionId")}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise StageError("STAGED_ARTIFACT_UNREADABLE") from exc
    return digest.hexdigest()


def _write_receipt(path: Path, document: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp_path, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise StageError("STAGING_RECEIPT_EXISTS") from exc
    except OSError as exc:
        raise StageError("STAGING_RECEIPT_WRITE_FAILED") from exc
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def stage_backup(
    *, backup_id: str, expected_dump_sha256: str, expected_sidecar_sha256: str,
    expected_manifest_sha256: str, backup_dir: Path, bucket: str, prefix: str,
    profile: str, role_arn: str, region: str = "ap-northeast-2",
    runner: Callable = subprocess.run,
) -> dict:
    backup_id = _safe_id(backup_id)
    dump_sha = _safe_sha(expected_dump_sha256, "EXPECTED_DUMP_SHA256_INVALID")
    sidecar_sha = _safe_sha(expected_sidecar_sha256, "EXPECTED_SIDECAR_SHA256_INVALID")
    manifest_sha = _safe_sha(expected_manifest_sha256, "EXPECTED_MANIFEST_SHA256_INVALID")
    if not BUCKET_RE.fullmatch(bucket or ""):
        raise StageError("S3_BUCKET_INVALID")
    if prefix.strip("/") != DEFAULT_PREFIX:
        raise StageError("S3_BACKUP_PREFIX_OUT_OF_SCOPE")
    if not PROFILE_RE.fullmatch(profile or ""):
        raise StageError("RESTORE_PROFILE_INVALID")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region or ""):
        raise StageError("AWS_REGION_INVALID")
    account, _ = _role_parts(role_arn)
    if profile == os.environ.get("S3_BACKUP_AWS_PROFILE"):
        raise StageError("UPLOADER_PROFILE_FORBIDDEN")

    target = _safe_directory(backup_dir)
    lock = target / ".s3-backup-stage.lock"
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise StageError("STAGING_LOCK_BUSY") from exc
    except OSError as exc:
        raise StageError("STAGING_LOCK_UNAVAILABLE") from exc

    created: list[tuple[Path, int, int]] = []
    try:
        with os.fdopen(lock_fd, "w", encoding="ascii") as lock_stream:
            lock_stream.write(f"pid={os.getpid()}\n")
            lock_stream.flush()
            os.fsync(lock_stream.fileno())
        session_name = _verify_reader_identity(
            profile=profile, role_arn=role_arn, region=region, runner=runner,
        )
        base = backup_id.removesuffix(".sql.gz.enc")
        keys = {
            "dump": f"{DEFAULT_PREFIX}/{backup_id}",
            "sidecar": f"{DEFAULT_PREFIX}/{base}.master_status",
            "manifest": f"{DEFAULT_PREFIX}/{base}.manifest.json",
        }
        final_paths = {
            "dump": target / backup_id,
            "sidecar": target / f"{base}.master_status",
            "manifest": target / f"{base}.manifest.json",
        }
        receipt_path = target / f".s3-stage-{base}.json"
        if receipt_path.exists() or receipt_path.is_symlink():
            raise StageError("STAGING_RECEIPT_EXISTS")

        with tempfile.TemporaryDirectory(prefix=".s3-stage-", dir=target) as temporary:
            private = Path(temporary)
            os.chmod(private, 0o700)
            manifest_path = private / final_paths["manifest"].name
            manifest_head = _head_size(
                profile=profile, region=region, bucket=bucket,
                key=keys["manifest"], runner=runner, limit=MAX_MANIFEST_BYTES,
            )
            manifest_object = _download(
                profile=profile, region=region, bucket=bucket,
                key=keys["manifest"], path=manifest_path,
                expected_size=manifest_head, runner=runner,
            )
            if manifest_object["sha256"] != manifest_sha:
                raise StageError("MANIFEST_CHECKSUM_MISMATCH")
            try:
                document = parse_manifest_text(manifest_path.read_text(encoding="utf-8", errors="strict"))
            except (OSError, UnicodeError, ManifestError) as exc:
                code = exc.code if isinstance(exc, ManifestError) else "MANIFEST_INVALID_FORMAT"
                raise StageError(code) from exc

            expected_names = {
                "dump_object_key": keys["dump"],
                "sidecar_object_key": keys["sidecar"],
                "manifest_object_key": keys["manifest"],
            }
            if document.get("backup_id") != backup_id or any(
                document.get(field) != expected for field, expected in expected_names.items()
            ):
                raise StageError("MANIFEST_OBJECT_IDENTITY_MISMATCH")
            if document.get("ciphertext_sha256") != dump_sha:
                raise StageError("CHECKSUM_MISMATCH")
            if document.get("sidecar_sha256") != sidecar_sha:
                raise StageError("SIDECAR_CHECKSUM_MISMATCH")
            dump_size = document.get("ciphertext_size")
            sidecar_size = document.get("sidecar_size")
            for value in (dump_size, sidecar_size):
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise StageError("MANIFEST_SCHEMA_MISMATCH")
            if sidecar_size > MAX_SIDECAR_BYTES:
                raise StageError("MANIFEST_SIDECAR_SIZE_MISMATCH")

            sizes = {
                "dump": _head_size(
                    profile=profile, region=region, bucket=bucket,
                    key=keys["dump"], runner=runner,
                ),
                "sidecar": _head_size(
                    profile=profile, region=region, bucket=bucket,
                    key=keys["sidecar"], runner=runner, limit=MAX_SIDECAR_BYTES,
                ),
            }
            if sizes["dump"] != dump_size or sizes["sidecar"] != sidecar_size:
                raise StageError("S3_OBJECT_SIZE_MISMATCH")
            required_space = dump_size + sidecar_size + manifest_head + MIN_FREE_BYTES
            if shutil.disk_usage(target).free < required_space:
                raise StageError("STAGING_DISK_SPACE_INSUFFICIENT")

            temp_paths = {
                "dump": private / final_paths["dump"].name,
                "sidecar": private / final_paths["sidecar"].name,
            }
            downloaded = {
                "manifest": manifest_object,
                "dump": _download(
                    profile=profile, region=region, bucket=bucket,
                    key=keys["dump"], path=temp_paths["dump"],
                    expected_size=dump_size, runner=runner,
                ),
                "sidecar": _download(
                    profile=profile, region=region, bucket=bucket,
                    key=keys["sidecar"], path=temp_paths["sidecar"],
                    expected_size=sidecar_size, runner=runner,
                ),
            }
            if downloaded["dump"]["sha256"] != dump_sha:
                raise StageError("CHECKSUM_MISMATCH")
            if downloaded["sidecar"]["sha256"] != sidecar_sha:
                raise StageError("SIDECAR_CHECKSUM_MISMATCH")

            verification = verify_manifest_files(
                temp_paths["dump"], temp_paths["sidecar"], manifest_path,
                expected_sha256=dump_sha,
                expected_sidecar_sha256=sidecar_sha,
                expected_manifest_sha256=manifest_sha,
                expected_object_prefix=DEFAULT_PREFIX,
            )
            existing = [path.exists() or path.is_symlink() for path in final_paths.values()]
            if any(existing) and not all(existing):
                raise StageError("STAGING_TARGET_PARTIAL")
            stage_mode = "DOWNLOADED_AND_VERIFIED"
            if all(existing):
                for name, path in final_paths.items():
                    try:
                        metadata = path.lstat()
                    except OSError as exc:
                        raise StageError("STAGING_TARGET_INVALID") from exc
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                    ):
                        raise StageError("STAGING_TARGET_PERMISSIONS_UNSAFE")
                    actual_sha = _sha256(path)
                    if actual_sha != downloaded[name]["sha256"]:
                        raise StageError("STAGING_TARGET_CONTENT_MISMATCH")
                verify_manifest_files(
                    final_paths["dump"], final_paths["sidecar"], final_paths["manifest"],
                    expected_sha256=dump_sha,
                    expected_sidecar_sha256=sidecar_sha,
                    expected_manifest_sha256=manifest_sha,
                    expected_object_prefix=DEFAULT_PREFIX,
                )
                stage_mode = "EXISTING_SET_MATCHED_S3"
            else:
                try:
                    for name in ("dump", "sidecar", "manifest"):
                        source = temp_paths[name] if name != "manifest" else manifest_path
                        os.link(source, final_paths[name], follow_symlinks=False)
                        metadata = final_paths[name].lstat()
                        created.append((final_paths[name], metadata.st_dev, metadata.st_ino))
                except OSError as exc:
                    raise StageError("STAGING_INSTALL_FAILED") from exc
                verify_manifest_files(
                    final_paths["dump"], final_paths["sidecar"], final_paths["manifest"],
                    expected_sha256=dump_sha,
                    expected_sidecar_sha256=sidecar_sha,
                    expected_manifest_sha256=manifest_sha,
                    expected_object_prefix=DEFAULT_PREFIX,
                )

            receipt = {
                "schema_version": 1,
                "status": "STAGED_INTEGRITY_VERIFIED",
                "stage_mode": stage_mode,
                "staged_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "aws_account_id": account,
                "aws_region": region,
                "restore_profile": profile,
                "assumed_role_session_name": session_name,
                "expected_hashes_source": "CALLER_SUPPLIED_PINNED_INPUTS",
                "chatops_approval_binding": "NOT_PERFORMED",
                "bucket": bucket,
                "object_keys": keys,
                "backup_id": backup_id,
                "artifacts": {
                    name: {
                        "sha256": downloaded[name]["sha256"],
                        "size_bytes": downloaded[name]["size_bytes"],
                        "s3_version_id": downloaded[name]["version_id"],
                        "local_path": str(final_paths[name]),
                    }
                    for name in ("dump", "sidecar", "manifest")
                },
                "binlog_file": verification["binlog_file"],
                "binlog_position": verification["binlog_position"],
                "manifest_integrity": "PASS",
                "data_reference_time_status": "UNVERIFIED",
                "rpo_status": "NOT_MEASURED",
            }
            try:
                _write_receipt(receipt_path, receipt)
            except StageError:
                raise
            return receipt
    except BaseException:
        for path, device, inode in reversed(created):
            try:
                current = path.lstat()
                if current.st_dev == device and current.st_ino == inode:
                    path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise StageError("STAGING_LOCK_CLEANUP_FAILED") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-sidecar-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = stage_backup(
            backup_id=args.backup_id,
            expected_dump_sha256=args.expected_sha256,
            expected_sidecar_sha256=args.expected_sidecar_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
            backup_dir=Path(os.environ.get("DUMP_BACKUP_DIR", "")),
            bucket=os.environ.get("S3_BACKUP_BUCKET", ""),
            prefix=os.environ.get("S3_BACKUP_PREFIX", DEFAULT_PREFIX),
            profile=os.environ.get("RESTORE_AWS_PROFILE", ""),
            role_arn=os.environ.get("RESTORE_AWS_ROLE_ARN", ""),
            region=os.environ.get("AWS_REGION", "ap-northeast-2"),
        )
    except (StageError, ManifestError, OSError, ValueError) as exc:
        reason = str(exc) if re.fullmatch(r"[A-Z0-9_]{1,96}", str(exc)) else "S3_STAGING_BLOCKED"
        print(json.dumps({"status": "BLOCKED", "reason_code": reason}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
