#!/usr/bin/env python3
"""Read-only, secret-free check that ChatOps and Zabbix use the same HMAC key."""

from __future__ import annotations

import argparse
import hmac
import os
import stat
import sys
from pathlib import Path


KEY_NAME = "ZABBIX_PRODUCTION_ACTION_HMAC_KEY"
MINIMUM_KEY_BYTES = 32
MAX_ENV_FILE_BYTES = 1024 * 1024


class KeyFileError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def read_key(path: str | Path) -> bytes:
    """Read only the named key after rejecting symlinks and broad permissions."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(path), flags)
    except FileNotFoundError as exc:
        raise KeyFileError("file_missing") from exc
    except OSError as exc:
        raise KeyFileError("file_unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise KeyFileError("not_regular_file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise KeyFileError("permissions_or_owner_invalid")
        if metadata.st_size > MAX_ENV_FILE_BYTES:
            raise KeyFileError("file_too_large")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            content = stream.read(MAX_ENV_FILE_BYTES + 1)
        after_read = os.fstat(descriptor)
        if len(content.encode("utf-8")) > MAX_ENV_FILE_BYTES or after_read.st_size != metadata.st_size:
            raise KeyFileError("file_changed_or_too_large")
        lines = content.splitlines()
    except UnicodeError as exc:
        raise KeyFileError("file_encoding_invalid") from exc
    finally:
        os.close(descriptor)

    values: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() != KEY_NAME:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values.append(value)

    if len(values) != 1:
        raise KeyFileError("key_missing_or_duplicated")
    key = values[0].encode("utf-8")
    if len(key) < MINIMUM_KEY_BYTES:
        raise KeyFileError("key_too_short")
    return key


def verify(chatops_env: str | Path, zabbix_env: str | Path) -> tuple[bool, str, str, str]:
    try:
        chatops_key = read_key(chatops_env)
        chatops_status = "PASS"
        chatops_reason = "ok"
    except KeyFileError as exc:
        chatops_key = b""
        chatops_status = "BLOCKED"
        chatops_reason = exc.code
    try:
        zabbix_key = read_key(zabbix_env)
        zabbix_status = "PASS"
        zabbix_reason = "ok"
    except KeyFileError as exc:
        zabbix_key = b""
        zabbix_status = "BLOCKED"
        zabbix_reason = exc.code

    if chatops_status != "PASS" or zabbix_status != "PASS":
        return False, f"{chatops_status}:{chatops_reason}", f"{zabbix_status}:{zabbix_reason}", "UNVERIFIED"
    matches = hmac.compare_digest(chatops_key, zabbix_key)
    return (
        matches,
        "PASS:ok",
        "PASS:ok",
        "MATCH" if matches else "MISMATCH",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chatops-env", required=True, help="ChatOps DR_SECRET_FILE")
    parser.add_argument("--zabbix-env", required=True, help="Zabbix server env_file")
    args = parser.parse_args(argv)
    matches, chatops, zabbix, result = verify(args.chatops_env, args.zabbix_env)
    print(f"CHATOPS_HMAC_SOURCE={chatops}")
    print(f"ZABBIX_HMAC_SOURCE={zabbix}")
    print(f"HMAC_KEYS={result}")
    return 0 if matches else 1


if __name__ == "__main__":
    sys.exit(main())
