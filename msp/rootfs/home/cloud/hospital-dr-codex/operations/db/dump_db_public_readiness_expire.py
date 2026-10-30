#!/usr/bin/env python3
"""Fail closed and revoke one Dump public-readiness probe after its TTL."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

FENCE_HELPER = Path("/usr/local/sbin/hospital-dr-dump-external-fence")
NGINX_MODE_FILE = Path("/etc/nginx/conf.d/hospital-dr-dump-mode.conf")
MODE_MARKER = "# hospital-dr-dump-cutover={}"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
def _disabled_mode(cutover_id: str) -> str:
    return f"""{MODE_MARKER.format(cutover_id)}
# Dump maintenance is disabled; the strict nftables fence remains authoritative.
map $host $hospital_dr_dump_maintenance {{
    default 0;
}}
map $hospital_dr_dump_maintenance $hospital_dr_dump_maintenance_cache_control {{
    default "";
    1 "no-store, private";
}}
map $http_x_hospital_dr_probe $hospital_dr_dump_probe_authorized {{
    default 0;
}}
"""


class ExpiryError(RuntimeError):
    """Safe, non-secret failure identifier."""


def expire_readiness(
    *, role: str, cutover_id: str, runner: Callable = subprocess.run,
    fence_helper: Path = FENCE_HELPER, mode_file: Path = NGINX_MODE_FILE,
    owner_uid: int | None = None,
) -> str:
    if role not in {"web", "emr"}:
        raise ExpiryError("APP_ROLE_INVALID")
    try:
        normalized = str(uuid.UUID(cutover_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExpiryError("CUTOVER_ID_INVALID") from exc
    if normalized != cutover_id.lower() or not UUID_RE.fullmatch(cutover_id):
        raise ExpiryError("CUTOVER_ID_INVALID")

    try:
        fenced = runner(
            [str(fence_helper), "restore-strict"], capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise ExpiryError("STRICT_FENCE_RESTORE_FAILED") from exc
    if fenced.returncode != 0:
        raise ExpiryError("STRICT_FENCE_RESTORE_FAILED")
    if role == "emr":
        return "STRICT_FENCE_RESTORED"

    expected_marker = MODE_MARKER.format(normalized)
    if not mode_file.exists():
        return "STRICT_FENCE_RESTORED_NO_PROBE_CONFIG"
    if mode_file.is_symlink() or not mode_file.is_file():
        raise ExpiryError("PROBE_CONFIG_UNAVAILABLE")
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    metadata = mode_file.stat()
    if metadata.st_uid != owner_uid or metadata.st_mode & 0o777 != 0o600:
        raise ExpiryError("PROBE_CONFIG_PERMISSIONS_INVALID")
    try:
        current = mode_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ExpiryError("PROBE_CONFIG_UNAVAILABLE") from exc
    lines = [line.strip() for line in current.splitlines()]
    if expected_marker not in lines:
        return "STRICT_FENCE_RESTORED_DIFFERENT_CUTOVER"
    if (
        "default 0;" in lines
        and "map $http_x_hospital_dr_probe $hospital_dr_dump_probe_authorized {" in lines
        and not any(re.fullmatch(r'"[A-Za-z0-9_-]{40,64}" 1;', line) for line in lines)
    ):
        return "STRICT_FENCE_RESTORED_PROBE_ALREADY_DISABLED"

    temp_path: Path | None = None
    try:
        fd, raw_path = tempfile.mkstemp(prefix=".hospital-dr-dump-mode-", dir=mode_file.parent)
        temp_path = Path(raw_path)
        os.fchmod(fd, 0o600)
        if hasattr(os, "fchown"):
            os.fchown(fd, owner_uid, -1)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_disabled_mode(normalized))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, mode_file)
        temp_path = None
    except OSError as exc:
        raise ExpiryError("PROBE_CONFIG_REVOKE_FAILED") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    for command, failure in (
        (["nginx", "-t"], "NGINX_CONFIG_VALIDATION_FAILED"),
        (["systemctl", "reload", "nginx"], "NGINX_PROBE_REVOCATION_FAILED"),
    ):
        try:
            result = runner(command, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise ExpiryError(failure) from exc
        if result.returncode != 0:
            # nftables has already restored the strict deny, so an old in-memory
            # Nginx probe map cannot create an external path.
            raise ExpiryError(failure)
    return "STRICT_FENCE_RESTORED_PROBE_REVOKED"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("web", "emr"))
    parser.add_argument("--cutover-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = expire_readiness(role=args.role, cutover_id=args.cutover_id)
    except ExpiryError as exc:
        print(f"DUMP_PUBLIC_READINESS_EXPIRE=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1
    print(f"DUMP_PUBLIC_READINESS_EXPIRE=PASS result={result}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
