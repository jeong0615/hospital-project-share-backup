#!/usr/bin/env python3
"""Canonical request binding for the isolated AWS synthetic MySQL demo."""

from __future__ import annotations

import hashlib
import importlib
import os
import sys
from pathlib import Path


REQUEST_TYPE = "SYNTHETIC_MYSQL_DEMO_FAILOVER"
REQUEST_ORIGIN = "CHATOPS_SYNTHETIC_MYSQL_DEMO"
REQUEST_SOURCE = "chatops_synthetic_mysql_demo"
AUTHORIZATION_FIELD = "synthetic_mysql_demo_authorization"
AUTHORIZATION_VERSION = 1
AUTHORIZATION_KIND = "SYNTHETIC_AWS_MYSQL_A_B_ROUNDTRIP"
RUNNER_RELATIVE_PATH = "operations/demo/aws_mysql_data_roundtrip.py"
EXECUTOR_RELATIVE_PATH = "operations/demo/aws_mysql_chatops_executor.py"
SHARED_RUNNER_RELATIVE_PATH = "operations/demo/aws_synthetic_data_roundtrip.py"
LAUNCH_GATE_RELATIVE_PATH = "operations/failover/chatops_launch_gate.py"
CHATOPS_CORE_RELATIVE_PATH = "operations/chatops/chatops_core.py"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class SyntheticDemoContractError(ValueError):
    pass


def _sha256_regular_file(root: Path, relative_path: str) -> str:
    path = root / relative_path
    try:
        if path.is_symlink() or path.resolve(strict=True) != path or not path.is_file():
            raise SyntheticDemoContractError("synthetic_demo_executor_path_untrusted")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        raise SyntheticDemoContractError("synthetic_demo_executor_unavailable") from exc


def build_request_binding(repo_root: str | os.PathLike[str], *, issued_at: float, mode_expires_at: float) -> dict:
    """Build immutable, server-side scope and pin both executable files."""
    try:
        supplied_root = Path(repo_root).resolve(strict=True)
        canonical_root = REPOSITORY_ROOT.resolve(strict=True)
    except OSError as exc:
        raise SyntheticDemoContractError("synthetic_demo_repository_unavailable") from exc
    if supplied_root != canonical_root:
        raise SyntheticDemoContractError("synthetic_demo_repository_mismatch")

    root_text = str(canonical_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        runner = importlib.import_module("operations.demo.aws_mysql_data_roundtrip")
    except Exception as exc:
        raise SyntheticDemoContractError("synthetic_demo_runner_contract_unavailable") from exc

    if getattr(runner, "DATABASE_NAME", None) != "hospital_demo":
        raise SyntheticDemoContractError("synthetic_demo_database_scope_mismatch")
    return {
        "version": AUTHORIZATION_VERSION,
        "kind": AUTHORIZATION_KIND,
        "status": "PENDING",
        "approval_required": 1,
        "issued_at": float(issued_at),
        "approval_mode_expires_at": float(mode_expires_at),
        "repository_root": root_text,
        "target": {
            "account_id": runner.common.ACCOUNT_ID,
            "region": runner.common.REGION,
            "instance_id": runner.INSTANCE_ID,
            "vpc_id": runner.VPC_ID,
            "canary_run_id": runner.CANARY_RUN_ID,
            "database": runner.DATABASE_NAME,
            "reset_scope": "ONLY_KNOWN_SYNTHETIC_DATABASE_ROWS",
        },
        "code": {
            relative_path: {
                "path": relative_path,
                "sha256": _sha256_regular_file(canonical_root, relative_path),
            }
            for relative_path in (
                CHATOPS_CORE_RELATIVE_PATH,
                LAUNCH_GATE_RELATIVE_PATH,
                "operations/demo/synthetic_mysql_demo_contract.py",
                SHARED_RUNNER_RELATIVE_PATH,
                RUNNER_RELATIVE_PATH,
                EXECUTOR_RELATIVE_PATH,
            )
        },
    }


def expected_static_binding(repo_root: str | os.PathLike[str]) -> dict:
    """Return the static scope/path/hash fields used to revalidate an approval."""
    binding = build_request_binding(repo_root, issued_at=1.0, mode_expires_at=2.0)
    binding.pop("status")
    binding.pop("approval_required")
    binding.pop("issued_at")
    binding.pop("approval_mode_expires_at")
    return binding
