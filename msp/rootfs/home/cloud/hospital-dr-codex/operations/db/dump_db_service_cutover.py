#!/usr/bin/env python3
"""Prepare the DR Web/EMR containers to use a verified isolated Dump DB.

This controller is deliberately separate from the normal Failover runner.  It
validates the isolated restore/service receipts, snapshots the current app
configuration, performs a read-only connection probe from both app containers,
and only then switches their DB endpoint.  It never changes DNS or DR state.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable, Mapping

from operations.db.isolated_db_service_host import read_service_password
from operations.db.isolated_dump_restore import validate_backup_pair

REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_DIR = REPO_ROOT / "automation/ansible"
PLAYBOOK = ANSIBLE_DIR / "dump_db_service_cutover.yml"
PROBE_SCRIPT = Path(__file__).with_name("readonly_mysql_probe.js")
PREFLIGHT_WRAPPER = Path(__file__).with_name("isolated_dump_restore.sh")
SERVICE_USER = "hospital_dr_service"
SERVICE_PORT = 3307
PRODUCTION_DB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
PROTECTED_DB_IPS = {"IP_REDACTED", "IP_REDACTED", "IP_REDACTED", "IP_REDACTED"}
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")


class CutoverError(RuntimeError):
    """Non-secret, operator-safe failure code."""


def _validate_private_endpoint(instance_id: str, private_ip: str) -> None:
    if not INSTANCE_RE.fullmatch(instance_id) or instance_id == PRODUCTION_DB_INSTANCE_ID:
        raise CutoverError("ISOLATED_INSTANCE_ID_INVALID_OR_PROTECTED")
    try:
        address = ipaddress.ip_address(private_ip)
    except ValueError as exc:
        raise CutoverError("ISOLATED_PRIVATE_IP_INVALID") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address not in ipaddress.ip_network("IP_REDACTED/24")
        or private_ip in PROTECTED_DB_IPS
    ):
        raise CutoverError("ISOLATED_PRIVATE_IP_INVALID_OR_PROTECTED")


def validate_request(args: argparse.Namespace, environment: Mapping[str, str]) -> str:
    """Validate explicit opt-in and all controller-local, non-secret inputs."""
    if environment.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise CutoverError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if environment.get("DUMP_DB_SERVICE_CUTOVER_ENABLED", "false").strip().lower() != "true":
        raise CutoverError("DB_SERVICE_CUTOVER_DISABLED")
    if environment.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise CutoverError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if environment.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise CutoverError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if not args.confirm_db_service_switch:
        raise CutoverError("EXPLICIT_DB_SERVICE_SWITCH_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise CutoverError("AWS_REGION_NOT_APPROVED")
    _validate_private_endpoint(args.instance_id, args.private_ip)
    if not VOLUME_RE.fullmatch(args.data_volume_id) or not VOLUME_RE.fullmatch(args.stage_volume_id):
        raise CutoverError("ISOLATED_VOLUME_ID_INVALID")
    if args.data_volume_id == args.stage_volume_id:
        raise CutoverError("ISOLATED_RESOURCE_COLLISION")
    if not SG_RE.fullmatch(args.service_security_group_id):
        raise CutoverError("ISOLATED_SERVICE_SECURITY_GROUP_ID_INVALID")
    if not SHA256_RE.fullmatch(args.expected_sha256):
        raise CutoverError("EXPECTED_CHECKSUM_INVALID")
    try:
        parsed_run_id = uuid.UUID(args.cutover_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise CutoverError("CUTOVER_ID_INVALID") from exc
    if str(parsed_run_id) != args.cutover_id.lower():
        raise CutoverError("CUTOVER_ID_INVALID")
    if not args.backup.is_file() or args.backup.is_symlink():
        raise CutoverError("BACKUP_ARTIFACT_INVALID")
    if not args.service_password_file.is_file() or args.service_password_file.is_symlink():
        raise CutoverError("SERVICE_DB_PASSWORD_FILE_UNAVAILABLE")
    if not args.inventory.is_file() or not os.access(args.inventory, os.R_OK):
        raise CutoverError("ANSIBLE_INVENTORY_UNAVAILABLE")
    if not args.ssh_config.is_file() or not os.access(args.ssh_config, os.R_OK):
        raise CutoverError("SSH_TRANSPORT_CONFIG_UNAVAILABLE")
    if not args.ssh_key or not Path(args.ssh_key).is_file() or not os.access(args.ssh_key, os.R_OK):
        raise CutoverError("SSH_KEY_UNAVAILABLE")
    if not args.known_hosts or not Path(args.known_hosts).is_file() or not os.access(args.known_hosts, os.R_OK):
        raise CutoverError("SSH_KNOWN_HOSTS_UNAVAILABLE")
    return str(parsed_run_id)


def _write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def _run_checked(
    command: list[str],
    *,
    runner: Callable = subprocess.run,
    cwd: Path | None = None,
    expected_output: str | None = None,
) -> None:
    try:
        result = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
        )
    except OSError as exc:
        raise CutoverError("CUTOVER_TOOL_UNAVAILABLE") from exc
    if result.returncode != 0 or (expected_output and expected_output not in result.stdout):
        # Never forward Ansible/AWS output: it can contain remote environment data.
        raise CutoverError("CUTOVER_PHASE_FAILED")


def _require_tmpfs(*, runner: Callable) -> None:
    try:
        result = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", "/dev/shm"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise CutoverError("SECRET_TMPFS_UNAVAILABLE") from exc
    if result.returncode != 0 or result.stdout.strip() != "tmpfs":
        raise CutoverError("SECRET_TMPFS_UNAVAILABLE")


def _service_preflight(args: argparse.Namespace, *, runner: Callable) -> None:
    command = [
        "bash", str(PREFLIGHT_WRAPPER), "service-preflight",
        "--region", args.region,
        "--instance-id", args.instance_id,
        "--private-ip", args.private_ip,
        "--data-volume-id", args.data_volume_id,
        "--stage-volume-id", args.stage_volume_id,
        "--service-security-group-id", args.service_security_group_id,
        "--backup", str(args.backup),
        "--expected-sha256", args.expected_sha256.lower(),
        "--ssh-key", args.ssh_key,
        "--ssh-config", str(args.ssh_config),
        "--known-hosts", args.known_hosts,
    ]
    if os.environ.get("DR_DUMP_EXECUTOR_CHILD") == "1":
        command.extend(("--request-id", args.cutover_id))
    _run_checked(
        command,
        runner=runner,
        expected_output="ISOLATED_DB_SERVICE_PREFLIGHT=PASS network_group_validated=true",
    )


def _ansible_phase(
    *, phase: str, vars_path: Path, args: argparse.Namespace, runner: Callable
) -> None:
    command = [
        "ansible-playbook",
        "-i", str(args.inventory),
        "-e", f"@{vars_path}",
        str(PLAYBOOK),
    ]
    _run_checked(command, runner=runner, cwd=ANSIBLE_DIR)


def execute_cutover(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> str:
    """Switch Web/EMR to the verified read-only isolated DB, or roll back.

    No DNS or DR-state operation is present here. Automatic rollback is only
    reached while this pre-DNS command is still running and its checks fail.
    A successful return intentionally leaves the prior containers/config backup
    in place; a later DNS stage must not invoke this rollback after traffic can
    write to the isolated database.
    """
    env = environment if environment is not None else os.environ
    run_id = validate_request(args, env)

    try:
        backup = validate_backup_pair(args.backup, args.expected_sha256)
        password = read_service_password(args.service_password_file, owner_uid=os.geteuid())
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code:
            raise CutoverError(str(code)) from exc
        raise CutoverError("BACKUP_OR_SERVICE_CREDENTIAL_INVALID") from exc
    if backup["sha256"].lower() != args.expected_sha256.lower():
        raise CutoverError("CHECKSUM_MISMATCH")

    _require_tmpfs(runner=runner)
    _service_preflight(args, runner=runner)

    vars_data = {
        "dump_db_service_cutover_id": run_id,
        "dump_db_service_cutover_phase": "",
        "dump_db_service_host": args.private_ip,
        "dump_db_service_port": SERVICE_PORT,
        "dump_db_service_user": SERVICE_USER,
        "dump_db_service_password": password,
        "dump_db_service_name": "hospital_db",
        "dump_db_service_expected_sha256": backup["sha256"],
        "dump_db_service_instance_id": args.instance_id,
        "dump_db_service_data_volume_id": args.data_volume_id,
        "dump_db_service_stage_volume_id": args.stage_volume_id,
        "dump_db_service_probe_script": str(PROBE_SCRIPT),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-db-cutover-", dir="/dev/shm") as tmp:
            tmpdir = Path(tmp)
            tmpdir.chmod(0o700)
            vars_path = tmpdir / "cutover-vars.json"
            for phase in ("snapshot-probe", "switch"):
                vars_data["dump_db_service_cutover_phase"] = phase
                _write_private(vars_path, json.dumps(vars_data, sort_keys=True))
                try:
                    _ansible_phase(phase=phase, vars_path=vars_path, args=args, runner=runner)
                except BaseException as switch_error:
                    if phase == "snapshot-probe":
                        if isinstance(switch_error, KeyboardInterrupt):
                            raise
                        raise CutoverError("DB_SERVICE_READ_ONLY_PRECHECK_FAILED")
                    vars_data["dump_db_service_cutover_phase"] = "rollback"
                    vars_data["dump_db_service_password"] = ""
                    _write_private(vars_path, json.dumps(vars_data, sort_keys=True))
                    try:
                        _ansible_phase(phase="rollback", vars_path=vars_path, args=args, runner=runner)
                    except CutoverError as rollback_error:
                        raise CutoverError("DB_SERVICE_SWITCH_ROLLBACK_FAILED") from rollback_error
                    if isinstance(switch_error, KeyboardInterrupt):
                        raise
                    raise CutoverError("DB_SERVICE_SWITCH_FAILED_ROLLED_BACK")
    finally:
        # Best-effort Python reference release; the only serialized copy is in tmpfs.
        password = ""
        vars_data["dump_db_service_password"] = ""

    return "DB_SERVICE_CUTOVER=READY_FOR_DNS_GATE dns_changed=false dr_state_changed=false db_writable=false"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--service-security-group-id", required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--service-password-file", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=Path(os.environ.get("INVENTORY", ANSIBLE_DIR / "inventory.ini")))
    parser.add_argument("--ssh-config", type=Path, default=Path(os.environ.get("DR_SSH_CONFIG_FILE", "/var/lib/hospital-dr/ssh/config")))
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY", ""))
    parser.add_argument("--known-hosts", default=os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts"))
    parser.add_argument("--confirm-db-service-switch", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(execute_cutover(args), flush=True)
        return 0
    except CutoverError as exc:
        print(f"DB_SERVICE_CUTOVER=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
