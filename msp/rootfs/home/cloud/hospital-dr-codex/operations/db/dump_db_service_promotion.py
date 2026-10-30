#!/usr/bin/env python3
"""Promote the isolated Dump DB while keeping Web/EMR application writes fenced.

This is a separately gated, operator-invoked control path. It never releases the
application accounts, starts app containers, changes DNS, or updates DR state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Callable, Mapping

from operations.db.dump_db_service_cutover import (
    CutoverError,
    PRODUCTION_DB_INSTANCE_ID,
    PROTECTED_DB_IPS,
    _run_checked,
    _service_preflight,
    _validate_private_endpoint,
)
from operations.db.isolated_dump_restore import validate_backup_pair

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_service_promotion.yml"
SERVICE_HELPER = Path(__file__).with_name("isolated_db_service_host.py")
SERVICE_PORT = 3307
SERVICE_USER = "hospital_dr_service"
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")


def _canonical_uuid(value: str, code: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise CutoverError(code) from exc
    if str(parsed) != value.lower():
        raise CutoverError(code)
    return str(parsed)


def validate_request(args: argparse.Namespace, environment: Mapping[str, str]) -> tuple[str, str]:
    if environment.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise CutoverError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if environment.get("DUMP_DB_SERVICE_PROMOTION_ENABLED", "false").strip().lower() != "true":
        raise CutoverError("DB_SERVICE_WRITE_PROMOTION_DISABLED")
    if environment.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise CutoverError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if environment.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise CutoverError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if not args.confirm_write_promotion:
        raise CutoverError("EXPLICIT_WRITE_PROMOTION_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise CutoverError("AWS_REGION_NOT_APPROVED")
    _validate_private_endpoint(args.instance_id, args.private_ip)
    if args.instance_id == PRODUCTION_DB_INSTANCE_ID or args.private_ip in PROTECTED_DB_IPS:
        raise CutoverError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    if not VOLUME_RE.fullmatch(args.data_volume_id) or not VOLUME_RE.fullmatch(args.stage_volume_id):
        raise CutoverError("ISOLATED_VOLUME_ID_INVALID")
    if args.data_volume_id == args.stage_volume_id:
        raise CutoverError("ISOLATED_RESOURCE_COLLISION")
    if not SG_RE.fullmatch(args.service_security_group_id):
        raise CutoverError("ISOLATED_SERVICE_SECURITY_GROUP_ID_INVALID")
    if not SHA256_RE.fullmatch(args.expected_sha256):
        raise CutoverError("EXPECTED_CHECKSUM_INVALID")
    if not args.backup.is_file() or args.backup.is_symlink():
        raise CutoverError("BACKUP_ARTIFACT_INVALID")
    for selected_path, code in (
        (args.inventory, "ANSIBLE_INVENTORY_UNAVAILABLE"),
        (args.ssh_config, "SSH_TRANSPORT_CONFIG_UNAVAILABLE"),
        (args.ssh_key, "SSH_KEY_UNAVAILABLE"),
        (args.known_hosts, "SSH_KNOWN_HOSTS_UNAVAILABLE"),
    ):
        path = Path(selected_path) if selected_path else None
        if path is None or not path.is_file() or not os.access(path, os.R_OK):
            raise CutoverError(code)
    promotion_id = _canonical_uuid(args.promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    cutover_id = _canonical_uuid(args.cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    return promotion_id, cutover_id


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


def _write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def _build_overlay(
    *,
    path: Path,
    ssh_config_path: Path,
    ssh_config: Path,
    ssh_key: str,
    known_hosts: str,
    private_ip: str,
) -> None:
    proxy = shlex.join(["ssh", "-F", str(ssh_config), "-W", "%h:%p", "dr-web"])
    _write_private(
        ssh_config_path,
        "\n".join((
            "Host isolated-dump-restore",
            f"  HostName {private_ip}",
            f"  HostKeyAlias {private_ip}",
            "  User ubuntu",
            f"  IdentityFile {ssh_key}",
            "  IdentitiesOnly yes",
            "  BatchMode yes",
            "  ConnectTimeout 15",
            "  StrictHostKeyChecking accept-new",
            f"  UserKnownHostsFile {known_hosts}",
            "  GlobalKnownHostsFile /dev/null",
            f"  ProxyCommand {proxy}",
            "",
        )),
    )
    inventory_line = " ".join((
        "isolated-dump-restore",
        "ansible_connection=ssh",
        "ansible_host=isolated-dump-restore",
        "ansible_user=ubuntu",
        f"ansible_ssh_private_key_file={shlex.quote(ssh_key)}",
        f"ansible_ssh_common_args={shlex.quote('-F ' + str(ssh_config_path))}",
    ))
    _write_private(path, "[isolated_dump_restore]\n" + inventory_line + "\n")


def execute_promotion(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> str:
    promotion_id, cutover_id = validate_request(
        args, environment if environment is not None else os.environ
    )
    try:
        backup = validate_backup_pair(args.backup, args.expected_sha256)
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise CutoverError(str(code or "BACKUP_ARTIFACT_INVALID")) from exc
    if backup["sha256"].lower() != args.expected_sha256.lower():
        raise CutoverError("CHECKSUM_MISMATCH")

    _require_tmpfs(runner=runner)
    _service_preflight(args, runner=runner)

    vars_data = {
        "dump_db_promotion_id": promotion_id,
        "dump_db_promotion_cutover_id": cutover_id,
        "dump_db_promotion_request_id": (
            promotion_id if os.environ.get("DR_DUMP_EXECUTOR_CHILD") == "1" else ""
        ),
        "dump_db_promotion_instance_id": args.instance_id,
        "dump_db_promotion_private_ip": args.private_ip,
        "dump_db_promotion_data_volume_id": args.data_volume_id,
        "dump_db_promotion_stage_volume_id": args.stage_volume_id,
        "dump_db_promotion_service_sg_id": args.service_security_group_id,
        "dump_db_promotion_expected_sha256": backup["sha256"].lower(),
        "dump_db_promotion_port": SERVICE_PORT,
        "dump_db_promotion_user": SERVICE_USER,
        "dump_db_promotion_name": "hospital_db",
        "dump_db_promotion_helper_source": str(SERVICE_HELPER),
        "dump_db_promotion_app_fence_path": (
            f"/var/lib/hospital-dr-dump-restore/status/promotions/{promotion_id}.apps-fenced.json"
        ),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-db-promotion-", dir="/dev/shm") as tmp:
            tmpdir = Path(tmp)
            tmpdir.chmod(0o700)
            vars_path = tmpdir / "promotion-vars.json"
            overlay_path = tmpdir / "isolated-inventory.ini"
            isolated_ssh_config = tmpdir / "isolated-ssh-config"
            _build_overlay(
                path=overlay_path,
                ssh_config_path=isolated_ssh_config,
                ssh_config=args.ssh_config,
                ssh_key=args.ssh_key,
                known_hosts=args.known_hosts,
                private_ip=args.private_ip,
            )
            _write_private(vars_path, json.dumps(vars_data, sort_keys=True))
            command = [
                "ansible-playbook",
                "-i", str(args.inventory),
                "-i", str(overlay_path),
                "-e", f"@{vars_path}",
                str(PLAYBOOK),
            ]
            _run_checked(
                command,
                runner=runner,
                cwd=REPO_ROOT / "automation/ansible",
                expected_output=(
                    "ISOLATED_DB_SERVICE_PROMOTION=SUCCESS "
                    "state=WRITE_PROMOTED_APPS_FENCED db_writable=true "
                    "apps_stopped=true service_accounts_locked=true "
                    "application_writes_allowed=false dns_authorized=false"
                ),
            )
    except CutoverError:
        raise
    return (
        "DB_SERVICE_PROMOTION=WRITE_PROMOTED_APPS_FENCED\n"
        "db_writable=true\n"
        "apps_stopped=true\n"
        "service_accounts_locked=true\n"
        "application_writes_allowed=false\n"
        "dns_changed=false\n"
        "dr_state_changed=false\n"
        "automatic_rollback_allowed=false"
    )


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
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--inventory", type=Path, default=REPO_ROOT / "automation/ansible/inventory.ini")
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY"))
    parser.add_argument("--ssh-config", type=Path, default=os.environ.get("DR_SSH_CONFIG_FILE"))
    parser.add_argument("--known-hosts", default=os.environ.get("DR_SSH_KNOWN_HOSTS_FILE"))
    parser.add_argument("--confirm-write-promotion", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_promotion(args)
        print(result, flush=True)
        return 0
    except CutoverError as exc:
        print(f"DB_SERVICE_PROMOTION=BLOCKED reason={exc}", file=os.sys.stderr, flush=True)
        return 1
    except OSError:
        print("DB_SERVICE_PROMOTION=BLOCKED reason=LOCAL_TOOL_OR_FILE_UNAVAILABLE", file=os.sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
