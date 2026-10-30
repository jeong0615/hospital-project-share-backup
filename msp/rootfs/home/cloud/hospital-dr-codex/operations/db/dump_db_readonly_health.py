#!/usr/bin/env python3
"""Activate Dump-cutover Web/EMR read-only behind a persistent ingress fence.

This operation re-runs the Dump DNS preflight under the shared DR workflow
locks. It starts only the already-switched app containers, keeps their MySQL
accounts SELECT-only, and records a non-authorizing health receipt. It has no
DNS transaction or DR-state transition path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping

from operations.db import dump_db_dns_preflight as dns_preflight
from operations.db.dump_execution_contract import validate_inherited_dr_locks
from operations.db.dump_db_service_promotion import _build_overlay, _write_private
from operations.db.isolated_dump_restore import validate_backup_pair

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_readonly_health.yml"
APP_PROBE = REPO_ROOT / "operations/db/dump_db_readonly_app_probe.js"
APP_FENCE = REPO_ROOT / "operations/db/dump_db_external_fence.py"
FENCE_UNIT = REPO_ROOT / "operations/db/systemd/hospital-dr-dump-readonly-fence.service"
REMOTE_HOST_HELPER = REPO_ROOT / "operations/db/dump_db_readonly_health_host.py"
REMOTE_DB_HELPER = REPO_ROOT / "operations/db/isolated_db_service_host.py"
REMOTE_RESTORE_HELPER = REPO_ROOT / "operations/db/isolated_restore_host.py"
REMOTE_APP_PROBE = REPO_ROOT / "operations/db/dump_db_app_fence_probe.py"
SERVICE_PORT = 3307
PRODUCTION_DB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
PROTECTED_DB_IPS = {"IP_REDACTED", "IP_REDACTED", "IP_REDACTED", "IP_REDACTED"}
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class ReadonlyHealthError(RuntimeError):
    """Stable operator-safe failure code."""


def _uuid(value: str, code: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReadonlyHealthError(code) from exc
    if str(parsed) != value.lower():
        raise ReadonlyHealthError(code)
    return str(parsed)


def validate_request(args: argparse.Namespace, env: Mapping[str, str]) -> None:
    if env.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise ReadonlyHealthError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if env.get("DR_DUMP_EXECUTOR_CHILD") == "1":
        try:
            validate_inherited_dr_locks(env)
        except Exception as exc:
            raise ReadonlyHealthError("SHARED_DR_EXECUTION_LOCK_REQUIRED") from exc
    if env.get("DUMP_DB_READONLY_HEALTH_ENABLED", "false").strip().lower() != "true":
        raise ReadonlyHealthError("READONLY_HEALTH_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_DB_DNS_PREFLIGHT_ENABLED", "false").strip().lower() != "true":
        raise ReadonlyHealthError("DUMP_DNS_PREFLIGHT_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise ReadonlyHealthError("DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise ReadonlyHealthError("DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if env.get("DR_WORKFLOW_LOCK_HELD") != "1" or env.get("DR_FAILOVER_LOCK_HELD") != "1":
        raise ReadonlyHealthError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
    if not args.confirm_readonly_health:
        raise ReadonlyHealthError("EXPLICIT_READONLY_HEALTH_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise ReadonlyHealthError("AWS_REGION_NOT_APPROVED")
    if not INSTANCE_RE.fullmatch(args.instance_id) or args.instance_id == PRODUCTION_DB_INSTANCE_ID:
        raise ReadonlyHealthError("ISOLATED_INSTANCE_ID_INVALID_OR_PROTECTED")
    if not VOLUME_RE.fullmatch(args.data_volume_id) or not VOLUME_RE.fullmatch(args.stage_volume_id):
        raise ReadonlyHealthError("ISOLATED_VOLUME_ID_INVALID")
    if args.data_volume_id == args.stage_volume_id or not SG_RE.fullmatch(args.service_security_group_id):
        raise ReadonlyHealthError("ISOLATED_RESOURCE_IDENTITY_INVALID")
    if not re.fullmatch(r"10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])", args.private_ip):
        raise ReadonlyHealthError("ISOLATED_PRIVATE_IP_INVALID")
    if args.private_ip in PROTECTED_DB_IPS:
        raise ReadonlyHealthError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    if not SHA256_RE.fullmatch(args.expected_sha256):
        raise ReadonlyHealthError("EXPECTED_CHECKSUM_INVALID")
    _uuid(args.promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    _uuid(args.cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    for attr, code in (
        ("backup", "BACKUP_ARTIFACT_INVALID"),
        ("inventory", "ANSIBLE_INVENTORY_UNAVAILABLE"),
        ("ssh_key", "SSH_KEY_UNAVAILABLE"),
        ("ssh_config", "SSH_TRANSPORT_CONFIG_UNAVAILABLE"),
        ("known_hosts", "SSH_KNOWN_HOSTS_UNAVAILABLE"),
    ):
        path = Path(getattr(args, attr, ""))
        if not path.is_file() or path.is_symlink() or not os.access(path, os.R_OK):
            raise ReadonlyHealthError(code)


def _dns_preflight_args(args: argparse.Namespace) -> SimpleNamespace:
    return SimpleNamespace(
        region=args.region,
        instance_id=args.instance_id,
        private_ip=args.private_ip,
        data_volume_id=args.data_volume_id,
        stage_volume_id=args.stage_volume_id,
        service_security_group_id=args.service_security_group_id,
        backup=Path(args.backup),
        expected_sha256=args.expected_sha256,
        promotion_id=args.promotion_id,
        cutover_id=args.cutover_id,
        inventory=Path(args.inventory),
        ssh_key=args.ssh_key,
        ssh_config=Path(args.ssh_config),
        known_hosts=Path(args.known_hosts),
        origin_snapshot_dir=Path(args.origin_snapshot_dir),
        state_file=Path(args.state_file),
        zone_id=args.zone_id,
        web_record_id=args.web_record_id,
        emr_record_id=args.emr_record_id,
        web_domain=args.web_domain,
        emr_domain=args.emr_domain,
        onprem_tunnel_host=args.onprem_tunnel_host,
        onprem_emr_ip=args.onprem_emr_ip,
        dr_web_eip=args.dr_web_eip,
    )


def validate_fresh_preflight(result: dict, args: argparse.Namespace) -> None:
    expected = {
        "status": "DUMP_DNS_PREFLIGHT_PASSED_NOT_AUTHORIZATION",
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "cloudflare_dns": "APPROVED_ONPREM_PAIR_READ_ONLY_VERIFIED",
        "db_write_mode": "ENABLED_APPS_AND_SERVICE_ACCOUNTS_FENCED",
        "dns_change_authorized": False,
        "application_writes_allowed": False,
        "dr_state_changed": False,
        "application_health_checked": False,
    }
    if not isinstance(result, dict) or any(result.get(key) != value for key, value in expected.items()):
        raise ReadonlyHealthError("FRESH_DUMP_DNS_PREFLIGHT_RESULT_MISMATCH")
    if result.get("dr_state_observed") not in {"IDLE", "FAILED"}:
        raise ReadonlyHealthError("DR_STATE_CHANGED_SINCE_PREFLIGHT")


def _safe_child_environment(source: Mapping[str, str]) -> dict[str, str]:
    # AWS identity and SSH transport only. No DB, Slack, Cloudflare, encryption,
    # or application passwords are forwarded to Ansible.
    allowed = {
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONNOUSERSITE",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
        "SSH_AUTH_SOCK", "ANSIBLE_CONFIG", "ANSIBLE_HOST_KEY_CHECKING",
    }
    return {key: value for key, value in source.items() if key in allowed}


def _check_tmpfs(*, runner: Callable) -> None:
    try:
        result = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", "/dev/shm"],
            capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        raise ReadonlyHealthError("SECRET_TMPFS_UNAVAILABLE") from exc
    if result.returncode != 0 or result.stdout.strip() != "tmpfs":
        raise ReadonlyHealthError("SECRET_TMPFS_UNAVAILABLE")


def _phase_vars(args: argparse.Namespace, phase: str) -> dict:
    values = {
        "dump_readonly_health_phase": phase,
        "dump_readonly_health_instance_id": args.instance_id,
        "dump_readonly_health_private_ip": args.private_ip,
        "dump_readonly_health_data_volume_id": args.data_volume_id,
        "dump_readonly_health_stage_volume_id": args.stage_volume_id,
        "dump_readonly_health_service_sg_id": args.service_security_group_id,
        "dump_readonly_health_expected_sha256": args.expected_sha256.lower(),
        "dump_readonly_health_backup_id": Path(args.backup).name,
        "dump_readonly_health_promotion_id": args.promotion_id,
        "dump_readonly_health_cutover_id": args.cutover_id,
        "dump_readonly_health_helper_sha256": hashlib.sha256(REMOTE_HOST_HELPER.read_bytes()).hexdigest(),
        "dump_readonly_health_service_helper_sha256": hashlib.sha256(REMOTE_DB_HELPER.read_bytes()).hexdigest(),
        "dump_readonly_health_restore_helper_sha256": hashlib.sha256(REMOTE_RESTORE_HELPER.read_bytes()).hexdigest(),
        "dump_readonly_health_app_probe_sha256": hashlib.sha256(REMOTE_APP_PROBE.read_bytes()).hexdigest(),
        "dump_readonly_health_external_fence_sha256": hashlib.sha256(APP_FENCE.read_bytes()).hexdigest(),
        "dump_readonly_health_fence_unit_sha256": hashlib.sha256(FENCE_UNIT.read_bytes()).hexdigest(),
        "dump_readonly_health_app_js_sha256": hashlib.sha256(APP_PROBE.read_bytes()).hexdigest(),
    }
    return values


def _run_phase(
    args: argparse.Namespace,
    phase: str,
    *,
    runner: Callable = subprocess.run,
    environment: Mapping[str, str] | None = None,
    tmpfs_root: str = "/dev/shm",
) -> bool:
    _check_tmpfs(runner=runner)
    if not PLAYBOOK.is_file():
        raise ReadonlyHealthError("READONLY_HEALTH_PLAYBOOK_MISSING")
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-readonly-health-", dir=tmpfs_root) as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            inventory = root / "isolated-inventory.ini"
            ssh_config = root / "isolated-ssh-config"
            extra_vars = root / "readonly-health-vars.json"
            _build_overlay(
                path=inventory,
                ssh_config_path=ssh_config,
                ssh_config=Path(args.ssh_config),
                ssh_key=args.ssh_key,
                known_hosts=str(args.known_hosts),
                private_ip=args.private_ip,
            )
            _write_private(extra_vars, json.dumps(_phase_vars(args, phase), sort_keys=True))
            command = [
                "ansible-playbook", "-i", str(args.inventory), "-i", str(inventory),
                "-e", f"@{extra_vars}", str(PLAYBOOK),
            ]
            result = runner(
                command,
                cwd=str(REPO_ROOT / "automation/ansible"),
                env=_safe_child_environment(environment if environment is not None else os.environ),
                capture_output=True,
                text=True,
                check=False,
            )
    except OSError as exc:
        raise ReadonlyHealthError("READONLY_HEALTH_REMOTE_PHASE_UNAVAILABLE") from exc
    marker = {
        "prepare": "DUMP_READONLY_HEALTH_PREPARE=PASS",
        "activate": "DUMP_READONLY_HEALTH=APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED",
        "rollback-apps": "DUMP_READONLY_HEALTH_APP_ROLLBACK=PASS",
        "rollback-db": "DUMP_READONLY_HEALTH_DB_ROLLBACK=PASS",
    }[phase]
    return result.returncode == 0 and marker in result.stdout


def _rollback_app_and_db(
    args: argparse.Namespace,
    *,
    phase_runner: Callable,
    environment: Mapping[str, str],
) -> tuple[bool, bool]:
    outcomes = []
    for phase in ("rollback-apps", "rollback-db"):
        try:
            outcomes.append(bool(phase_runner(args, phase, environment=environment)))
        except Exception:
            outcomes.append(False)
    return outcomes[0], outcomes[1]


def execute_readonly_health_gate(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    preflight: Callable = dns_preflight.execute_preflight,
    phase_runner: Callable = _run_phase,
    backup_validator: Callable = validate_backup_pair,
) -> dict:
    env = environment if environment is not None else os.environ
    validate_request(args, env)
    try:
        backup = backup_validator(Path(args.backup), args.expected_sha256)
    except Exception as exc:
        raise ReadonlyHealthError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID") from exc
    if not isinstance(backup, dict):
        raise ReadonlyHealthError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID")
    if backup.get("sha256", "").lower() != args.expected_sha256.lower():
        raise ReadonlyHealthError("BACKUP_CHECKSUM_MISMATCH")

    # The old CLI success string is never accepted as a capability. Re-run the
    # complete read-only DNS/AWS/receipt/app-fence preflight under shared locks.
    try:
        fresh = preflight(_dns_preflight_args(args), environment=env)
    except Exception as exc:
        if isinstance(exc, ReadonlyHealthError):
            raise
        raise ReadonlyHealthError("FRESH_DUMP_DNS_PREFLIGHT_FAILED") from exc
    validate_fresh_preflight(fresh, args)

    try:
        prepared = phase_runner(args, "prepare", environment=env)
    except Exception:
        prepared = False
    if not prepared:
        app_rollback, db_rollback = _rollback_app_and_db(
            args, phase_runner=phase_runner, environment=env
        )
        if not app_rollback or not db_rollback:
            raise ReadonlyHealthError("READONLY_HEALTH_ROLLBACK_FAILED")
        raise ReadonlyHealthError("READONLY_HEALTH_PREPARE_FAILED_APPS_AND_DB_RELOCKED")

    # Preparation changes only the external fence and container restart policy.
    # Re-read DNS, AWS identity/SG/EBS and all DB/app receipts after those steps,
    # and reject any drift before unlocking the SELECT-only app accounts.
    try:
        refreshed = preflight(_dns_preflight_args(args), environment=env)
        validate_fresh_preflight(refreshed, args)
        if refreshed != fresh:
            raise ReadonlyHealthError("FRESH_PREFLIGHT_CHANGED_AFTER_PREPARE")
    except Exception as exc:
        app_rollback, db_rollback = _rollback_app_and_db(
            args, phase_runner=phase_runner, environment=env
        )
        if not app_rollback or not db_rollback:
            raise ReadonlyHealthError("READONLY_HEALTH_ROLLBACK_FAILED") from exc
        if isinstance(exc, ReadonlyHealthError):
            raise
        raise ReadonlyHealthError("FRESH_DUMP_DNS_PREFLIGHT_FAILED_AFTER_PREPARE") from exc

    try:
        if not phase_runner(args, "activate", environment=env):
            raise ReadonlyHealthError("READONLY_APP_HEALTH_GATE_FAILED")
    except Exception as exc:
        app_rollback, db_rollback = _rollback_app_and_db(
            args, phase_runner=phase_runner, environment=env
        )
        if not app_rollback or not db_rollback:
            raise ReadonlyHealthError("READONLY_HEALTH_ROLLBACK_FAILED") from exc
        if isinstance(exc, ReadonlyHealthError):
            raise ReadonlyHealthError("READONLY_APP_HEALTH_FAILED_APPS_AND_DB_RELOCKED") from exc
        raise ReadonlyHealthError("READONLY_APP_HEALTH_FAILED_APPS_AND_DB_RELOCKED") from exc

    return {
        "status": "APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED",
        "backup_id": Path(args.backup).name,
        "expected_sha256": args.expected_sha256.lower(),
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "instance_id": args.instance_id,
        "private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "apps_health_checked": True,
        "external_traffic_fenced": True,
        "application_writes_allowed": False,
        "dns_authorized": False,
        "dr_state_changed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--service-security-group-id", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--confirm-readonly-health", action="store_true")
    parser.add_argument("--inventory", default=os.environ.get("INVENTORY", str(REPO_ROOT / "automation/ansible/inventory.ini")))
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY", ""))
    parser.add_argument("--ssh-config", default=os.environ.get("DR_SSH_CONFIG_FILE", "/var/lib/hospital-dr/ssh/config"))
    parser.add_argument("--known-hosts", default=os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts"))
    parser.add_argument("--origin-snapshot-dir", default=os.environ.get("DR_DNS_ORIGIN_SNAPSHOT_DIR", "/var/lib/hospital-dr/dns/origin"))
    parser.add_argument("--state-file", default=os.environ.get("DR_STATE_FILE", "/var/lib/hospital-dr/dr_state"))
    parser.add_argument("--zone-id", default=os.environ.get("CF_ZONE_ID", ""))
    parser.add_argument("--web-record-id", default=os.environ.get("CF_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--emr-record-id", default=os.environ.get("CF_EMR_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--web-domain", default=os.environ.get("DR_DOMAIN", "hospital-web.pp.ua"))
    parser.add_argument("--emr-domain", default=os.environ.get("EMR_DOMAIN", "emr.hospital-web.pp.ua"))
    parser.add_argument("--onprem-tunnel-host", default=os.environ.get("ONPREM_TUNNEL_HOST", ""))
    parser.add_argument("--onprem-emr-ip", default=os.environ.get("ONPREM_EMR_DNS_IP_EXPECTED", ""))
    parser.add_argument("--dr-web-eip", default=os.environ.get("DR_WEB_EIP_EXPECTED", "AWS_PUBLIC_IP_REDACTED"))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_readonly_health_gate(args)
        print("DUMP_READONLY_HEALTH=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except ReadonlyHealthError as exc:
        print(f"DUMP_READONLY_HEALTH=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("DUMP_READONLY_HEALTH=BLOCKED reason=READONLY_HEALTH_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
