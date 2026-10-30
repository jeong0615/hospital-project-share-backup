#!/usr/bin/env python3
"""Atomically maintain/release only the matching Dump Nginx maintenance map."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

MODE_FILE = Path("/etc/nginx/conf.d/hospital-dr-dump-mode.conf")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")


class WebOpenError(RuntimeError):
    """Safe, stable Nginx maintenance transition error."""


def _canonical(value: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WebOpenError("CUTOVER_ID_INVALID") from exc
    if normalized != value.lower():
        raise WebOpenError("CUTOVER_ID_INVALID")
    return normalized


def _render(cutover_id: str, token: str, *, maintenance: bool) -> str:
    normalized = _canonical(cutover_id)
    if not TOKEN_RE.fullmatch(token):
        raise WebOpenError("PROBE_TOKEN_INVALID")
    enabled = 1 if maintenance else 0
    return (
        f"# hospital-dr-dump-cutover={normalized}\n"
        "map $host $hospital_dr_dump_maintenance {\n"
        f"    default {enabled};\n"
        "}\n"
        "map $hospital_dr_dump_maintenance $hospital_dr_dump_maintenance_cache_control {\n"
        '    default "";\n'
        '    1 "no-store, private";\n'
        "}\n"
        "map $http_x_hospital_dr_probe $hospital_dr_dump_probe_authorized {\n"
        "    default 0;\n"
        f'    "{token}" 1;\n'
        "}\n"
    )


def _render_expired(cutover_id: str) -> str:
    normalized = _canonical(cutover_id)
    return (
        f"# hospital-dr-dump-cutover={normalized}\n"
        "# Dump maintenance expired; strict nftables fence is authoritative.\n"
        "map $host $hospital_dr_dump_maintenance {\n    default 0;\n}\n"
        "map $hospital_dr_dump_maintenance $hospital_dr_dump_maintenance_cache_control {\n"
        '    default "";\n    1 "no-store, private";\n}\n'
        "map $http_x_hospital_dr_probe $hospital_dr_dump_probe_authorized {\n    default 0;\n}\n"
    )


def _read_current(path: Path, *, owner_uid: int, cutover_id: str, token: str) -> tuple[str, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WebOpenError("MAINTENANCE_CONFIG_UNAVAILABLE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 16384
    ):
        raise WebOpenError("MAINTENANCE_CONFIG_PERMISSIONS_INVALID")
    try:
        current = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise WebOpenError("MAINTENANCE_CONFIG_UNAVAILABLE") from exc
    enabled = _render(cutover_id, token, maintenance=True)
    disabled = _render(cutover_id, token, maintenance=False)
    expired = _render_expired(cutover_id)
    if current not in {enabled, disabled, expired}:
        raise WebOpenError("MAINTENANCE_CONFIG_MISMATCH")
    return current, 1 if current == enabled else (-1 if current == expired else 0)


def _atomic_write(path: Path, text: str, *, owner_uid: int) -> None:
    fd = -1
    temporary = None
    try:
        fd, raw = tempfile.mkstemp(prefix=".hospital-dr-dump-mode-", dir=path.parent)
        temporary = Path(raw)
        os.fchmod(fd, 0o600)
        if hasattr(os, "fchown"):
            os.fchown(fd, owner_uid, -1)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(text)
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
        raise WebOpenError("MAINTENANCE_CONFIG_WRITE_FAILED") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _run(command: list[str], *, runner: Callable) -> None:
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise WebOpenError("NGINX_MAINTENANCE_TRANSITION_FAILED") from exc
    if result.returncode != 0:
        raise WebOpenError("NGINX_MAINTENANCE_TRANSITION_FAILED")


def verify_expiry_timer(
    *, unit: str, min_remaining_seconds: int = 120,
    runner: Callable = subprocess.run, uptime_path: Path = Path("/proc/uptime"),
) -> int:
    if not re.fullmatch(r"hospital-dr-dump-expire-[0-9a-f]{32}\.timer", unit):
        raise WebOpenError("EXPIRY_TIMER_ID_INVALID")
    if not 60 <= min_remaining_seconds <= 600:
        raise WebOpenError("EXPIRY_TIMER_POLICY_INVALID")
    state = runner(["systemctl", "is-active", unit], capture_output=True, text=True, check=False)
    if state.returncode != 0 or state.stdout.strip() != "active":
        raise WebOpenError("EXPIRY_TIMER_NOT_ACTIVE")
    next_time = runner(
        ["systemctl", "show", "--property=NextElapseUSecMonotonic", "--value", unit],
        capture_output=True, text=True, check=False,
    )
    if next_time.returncode != 0 or not re.fullmatch(r"[0-9]{1,20}", next_time.stdout.strip()):
        raise WebOpenError("EXPIRY_TIMER_DEADLINE_UNAVAILABLE")
    try:
        uptime = float(uptime_path.read_text(encoding="ascii").split()[0])
        next_seconds = int(next_time.stdout.strip()) / 1_000_000
    except (OSError, ValueError, IndexError) as exc:
        raise WebOpenError("EXPIRY_TIMER_DEADLINE_UNAVAILABLE") from exc
    remaining = int(next_seconds - uptime)
    if remaining < min_remaining_seconds:
        raise WebOpenError("EXPIRY_TIMER_TOO_CLOSE_TO_DEADLINE")
    return remaining


def set_maintenance(
    *, cutover_id: str, probe_token: str, maintenance: bool,
    path: Path = MODE_FILE, owner_uid: int = 0,
    runner: Callable = subprocess.run,
) -> dict:
    current, state = _read_current(path, owner_uid=owner_uid, cutover_id=cutover_id, token=probe_token)
    if not maintenance and state != 1:
        raise WebOpenError("MAINTENANCE_MODE_NOT_ACTIVE")
    desired = _render(cutover_id, probe_token, maintenance=maintenance)
    if state == (1 if maintenance else 0):
        _run(["nginx", "-t"], runner=runner)
        return {"maintenance": maintenance, "changed": False}
    _atomic_write(path, desired, owner_uid=owner_uid)
    try:
        _run(["nginx", "-t"], runner=runner)
        _run(["systemctl", "reload", "nginx"], runner=runner)
        observed, observed_state = _read_current(
            path, owner_uid=owner_uid, cutover_id=cutover_id, token=probe_token
        )
        if observed != desired or observed_state != (1 if maintenance else 0):
            raise WebOpenError("MAINTENANCE_MODE_READBACK_FAILED")
    except Exception as exc:
        try:
            _atomic_write(path, current, owner_uid=owner_uid)
            _run(["nginx", "-t"], runner=runner)
            _run(["systemctl", "reload", "nginx"], runner=runner)
        except Exception as restore_error:
            raise WebOpenError("MAINTENANCE_MODE_RESTORE_FAILED") from restore_error
        if isinstance(exc, WebOpenError):
            raise
        raise WebOpenError("NGINX_MAINTENANCE_TRANSITION_FAILED") from exc
    return {"maintenance": maintenance, "changed": True}


def verify_released(
    *, cutover_id: str, probe_token: str, path: Path = MODE_FILE,
    owner_uid: int = 0, runner: Callable = subprocess.run,
) -> None:
    """Require this operation's exact maintenance map to be released and valid."""
    _current, state = _read_current(path, owner_uid=owner_uid, cutover_id=cutover_id, token=probe_token)
    if state != 0:
        raise WebOpenError("MAINTENANCE_MODE_NOT_RELEASED")
    _run(["nginx", "-t"], runner=runner)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-maintenance", "release", "contain", "verify-timer", "verify-released"))
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--probe-token-file", type=Path)
    parser.add_argument("--config", type=Path, default=MODE_FILE)
    parser.add_argument("--timer-unit")
    parser.add_argument("--min-remaining-seconds", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-timer":
            if not args.timer_unit:
                raise WebOpenError("EXPIRY_TIMER_ID_INVALID")
            remaining = verify_expiry_timer(
                unit=args.timer_unit, min_remaining_seconds=args.min_remaining_seconds
            )
            print(f"DUMP_SERVICE_OPEN_TIMER=PASS remaining_seconds={remaining}", flush=True)
            return 0
        if not args.probe_token_file:
            raise WebOpenError("PROBE_TOKEN_FILE_UNAVAILABLE")
        token_meta = args.probe_token_file.lstat()
        if (
            stat.S_ISLNK(token_meta.st_mode) or not stat.S_ISREG(token_meta.st_mode)
            or token_meta.st_uid != 0 or stat.S_IMODE(token_meta.st_mode) != 0o600
            or token_meta.st_size < 40 or token_meta.st_size > 64
        ):
            raise WebOpenError("PROBE_TOKEN_FILE_UNSAFE")
        token = args.probe_token_file.read_text(encoding="ascii")
        if not TOKEN_RE.fullmatch(token):
            raise WebOpenError("PROBE_TOKEN_INVALID")
        if args.command == "verify-maintenance":
            _current, state = _read_current(args.config, owner_uid=0, cutover_id=args.cutover_id, token=token)
            if state != 1:
                raise WebOpenError("MAINTENANCE_MODE_NOT_ACTIVE")
            print("DUMP_SERVICE_OPEN_MAINTENANCE=PASS", flush=True)
        elif args.command == "verify-released":
            verify_released(
                cutover_id=args.cutover_id, probe_token=token,
                path=args.config, owner_uid=0,
            )
            print("DUMP_SERVICE_OPEN_MAINTENANCE=RELEASED_VERIFIED", flush=True)
        else:
            result = set_maintenance(
                cutover_id=args.cutover_id, probe_token=token,
                maintenance=args.command == "contain", path=args.config,
            )
            marker = "MAINTENANCE_RESTORED" if result["maintenance"] else "MAINTENANCE_RELEASED"
            print(f"DUMP_SERVICE_OPEN_MAINTENANCE={marker}", flush=True)
        return 0
    except WebOpenError as exc:
        print(f"DUMP_SERVICE_OPEN_MAINTENANCE=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        try:
            if args.probe_token_file:
                args.probe_token_file.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
