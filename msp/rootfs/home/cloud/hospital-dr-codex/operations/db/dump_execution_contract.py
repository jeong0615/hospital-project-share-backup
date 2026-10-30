#!/usr/bin/env python3
"""Shared, fail-closed lock contract for Dump executor child processes.

The parent Dump executor owns descriptors 7 and 8 for the canonical DR workflow
and failover locks. Children may reuse them only when the descriptors still
refer to the configured, owned, non-writable-by-others lock files and a second
open cannot acquire either lock.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import stat
import sys
from pathlib import Path
from typing import Mapping


class LockContractError(RuntimeError):
    """Safe lock validation failure; never includes path or secret contents."""


def validate_inherited_dr_locks(environment: Mapping[str, str] | None = None) -> None:
    env = environment if environment is not None else os.environ
    _validate_lock_descriptors(env, (
        (7, "DR_WORKFLOW_LOCK_FILE", "DR_WORKFLOW_LOCK_HELD"),
        (8, "DR_FAILOVER_LOCK_FILE", "DR_FAILOVER_LOCK_HELD"),
    ))


def validate_inherited_failover_locks(environment: Mapping[str, str] | None = None) -> None:
    """Validate locks inherited from full_failover.sh (FD 7 workflow, FD 9 failover)."""
    env = environment if environment is not None else os.environ
    _validate_lock_descriptors(env, (
        (7, "DR_WORKFLOW_LOCK_FILE", "DR_WORKFLOW_LOCK_HELD"),
        (9, "DR_FAILOVER_LOCK_FILE", "DR_FAILOVER_LOCK_HELD"),
    ))


def _validate_lock_descriptors(env: Mapping[str, str], locks: tuple[tuple[int, str, str], ...]) -> None:
    for descriptor, variable, marker in locks:
        raw_path = env.get(variable, "")
        if not raw_path or env.get(marker) != "1":
            raise LockContractError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
        path = Path(raw_path)
        probe_fd = -1
        try:
            path_stat = path.lstat()
            descriptor_stat = os.fstat(descriptor)
            if (
                stat.S_ISLNK(path_stat.st_mode)
                or not stat.S_ISREG(path_stat.st_mode)
                or path_stat.st_uid != os.geteuid()
                or stat.S_IMODE(path_stat.st_mode) & 0o022
                or (path_stat.st_dev, path_stat.st_ino)
                != (descriptor_stat.st_dev, descriptor_stat.st_ino)
            ):
                raise LockContractError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
            probe_fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            fcntl.flock(probe_fd, fcntl.LOCK_UN)
            raise LockContractError("SHARED_DR_EXECUTION_LOCK_NOT_HELD")
        except LockContractError:
            raise
        except OSError as exc:
            raise LockContractError("SHARED_DR_EXECUTION_LOCK_REQUIRED") from exc
        finally:
            if probe_fd >= 0:
                os.close(probe_fd)


def acquire_shared_dr_locks(environment: Mapping[str, str] | None = None) -> tuple[int, int]:
    """Acquire pre-existing canonical lock files in fixed FD slots 7 and 8."""
    env = environment if environment is not None else os.environ
    paths = (
        env.get("DR_WORKFLOW_LOCK_FILE", ""),
        env.get("DR_FAILOVER_LOCK_FILE", ""),
    )
    if not all(paths) or paths[0] == paths[1]:
        raise LockContractError("SHARED_DR_EXECUTION_LOCK_CONFIGURATION_INVALID")
    descriptors: list[int] = []
    try:
        for path_text, target_fd in zip(paths, (7, 8)):
            path = Path(path_text)
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise LockContractError("SHARED_DR_EXECUTION_LOCK_CONFIGURATION_INVALID")
            opened = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            opened_stat = os.fstat(opened)
            if (metadata.st_dev, metadata.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
                os.close(opened)
                raise LockContractError("SHARED_DR_EXECUTION_LOCK_CONFIGURATION_INVALID")
            try:
                fcntl.flock(opened, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                os.close(opened)
                raise LockContractError("ACTIVE_DR_WORKFLOW") from exc
            if opened != target_fd:
                os.dup2(opened, target_fd, inheritable=True)
                os.close(opened)
                opened = target_fd
            else:
                os.set_inheritable(opened, True)
            descriptors.append(opened)
        return descriptors[0], descriptors[1]
    except Exception:
        for descriptor in descriptors:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            except OSError:
                pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-inherited", action="store_true")
    args = parser.parse_args(argv)
    if not args.verify_inherited:
        print("DUMP_LOCK=BLOCKED reason=VERIFY_MODE_REQUIRED", file=sys.stderr)
        return 2
    try:
        validate_inherited_dr_locks()
    except LockContractError as exc:
        print(f"DUMP_LOCK=BLOCKED reason={exc}", file=sys.stderr)
        return 1
    print("DUMP_LOCK=PASS inherited_workflow_and_failover_locks=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
