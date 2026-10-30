#!/usr/bin/env python3
"""Read-only preflight for a Dump-based DR DNS cutover.

PASS is a point-in-time validation result only. This command cannot authorize or
perform DNS changes, start applications, enable account writes, or update DR state.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operations.db.dump_db_service_promotion import _build_overlay, _write_private  # noqa: E402
from operations.db.dump_execution_contract import validate_inherited_dr_locks  # noqa: E402
from operations.db.isolated_dump_restore import (  # noqa: E402
    WEB_NAME,
    DOC_NAME,
    WEB_PRIVATE_IP,
    DOC_PRIVATE_IP,
    PreflightError,
    _aws_json,
    _instances,
    _tags,
    validate_aws_isolated_target,
    validate_backup_pair,
)

PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_dns_preflight.yml"
REMOTE_HELPER = Path(__file__).with_name("isolated_db_service_host.py")
RESTORE_HELPER = Path(__file__).with_name("isolated_restore_host.py")
APP_PROBE = Path(__file__).with_name("dump_db_app_fence_probe.py")
DNS_DR_EIP_DEFAULT = "AWS_PUBLIC_IP_REDACTED"
ZONE_RE = re.compile(r"[0-9a-fA-F]{32}\Z")
RECORD_ID_RE = re.compile(r"[0-9a-fA-F]{32}\Z")
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class DNSPreflightError(RuntimeError):
    """Safe failure code; never contains credentials or raw provider output."""


def _secure_json(path: Path, *, owner_uid: int) -> dict:
    if path.is_symlink() or not path.is_file():
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_MISSING")
    metadata = path.stat()
    if (
        metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 2
        or metadata.st_size > 65536
    ):
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_PERMISSIONS_INVALID")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_INVALID") from exc
    if not isinstance(value, dict):
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_INVALID")
    return value


def load_origin_pair(
    directory: Path,
    *,
    web_name: str,
    emr_name: str,
    tunnel_host: str,
    emr_origin_ip: str,
    dr_eip: str,
    web_record_id: str,
    emr_record_id: str,
    owner_uid: int | None = None,
) -> dict[str, dict]:
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    if directory.is_symlink() or not directory.is_dir():
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_MISSING")
    directory_mode = directory.stat()
    if directory_mode.st_uid != owner_uid or stat.S_IMODE(directory_mode.st_mode) != 0o700:
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_PERMISSIONS_INVALID")
    result = {}
    expectations = (
        ("web", web_name, web_record_id),
        ("emr", emr_name, emr_record_id),
    )
    for filename, expected_name, expected_id in expectations:
        record = _secure_json(directory / f"{filename}.json", owner_uid=owner_uid)
        payload = record.get("payload")
        if (
            not RECORD_ID_RE.fullmatch(str(record.get("id", "")))
            or record.get("id") != expected_id
            or not isinstance(payload, dict)
            or payload.get("name") != expected_name
            or not isinstance(payload.get("proxied"), bool)
            or not isinstance(payload.get("ttl"), int)
        ):
            raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_MISMATCH")
        result[filename] = record

    web = result["web"]["payload"]
    emr = result["emr"]["payload"]
    try:
        origin_ip = str(ipaddress.IPv4Address(emr_origin_ip))
        approved_dr_ip = str(ipaddress.IPv4Address(dr_eip))
        emr_snapshot_ip = str(ipaddress.IPv4Address(emr.get("content", "")))
    except ipaddress.AddressValueError as exc:
        raise DNSPreflightError("DNS_ORIGIN_CONTRACT_INVALID") from exc
    if (
        web.get("type") != "CNAME"
        or web.get("proxied") is not True
        or str(web.get("content", "")).rstrip(".").lower()
        != tunnel_host.rstrip(".").lower()
        or emr.get("type") != "A"
        or emr.get("proxied") is not True
        or emr_snapshot_ip != origin_ip
        or emr_snapshot_ip == approved_dr_ip
    ):
        raise DNSPreflightError("ONPREM_DNS_SNAPSHOT_NOT_APPROVED_ORIGIN")
    return result


def cloudflare_get_record(
    *, zone_id: str, record_id: str, token: str, opener: Callable = urlopen
) -> dict:
    if not ZONE_RE.fullmatch(zone_id) or not RECORD_ID_RE.fullmatch(record_id) or not token:
        raise DNSPreflightError("CLOUDFLARE_READ_CONFIGURATION_INVALID")
    request = Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    try:
        with opener(request, timeout=15) as response:
            payload = json.loads(response.read(65536).decode("utf-8"))
    except (OSError, URLError, TimeoutError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DNSPreflightError("CLOUDFLARE_RECORD_READ_FAILED") from exc
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DNSPreflightError("CLOUDFLARE_RECORD_READ_FAILED")
    record = payload.get("result")
    if not isinstance(record, dict):
        raise DNSPreflightError("CLOUDFLARE_RECORD_READ_FAILED")
    return record


def validate_live_origin_record(live: dict, snapshot: dict, *, dr_eip: str) -> None:
    expected = snapshot.get("payload", {})
    try:
        dr_ip = str(ipaddress.IPv4Address(dr_eip))
    except ipaddress.AddressValueError as exc:
        raise DNSPreflightError("DR_EIP_INVALID") from exc
    if (
        live.get("id") != snapshot.get("id")
        or any(live.get(key) != expected.get(key) for key in ("type", "name", "ttl", "proxied"))
    ):
        raise DNSPreflightError("CLOUDFLARE_LIVE_RECORD_MISMATCH")
    if expected.get("type") == "CNAME":
        actual_content = str(live.get("content", "")).rstrip(".").lower()
        expected_content = str(expected.get("content", "")).rstrip(".").lower()
        if actual_content != expected_content:
            raise DNSPreflightError("CLOUDFLARE_LIVE_RECORD_MISMATCH")
    elif expected.get("type") == "A":
        try:
            actual_ip = str(ipaddress.IPv4Address(live.get("content", "")))
        except ipaddress.AddressValueError as exc:
            raise DNSPreflightError("CLOUDFLARE_LIVE_RECORD_MISMATCH") from exc
        if actual_ip != expected.get("content") or actual_ip == dr_ip:
            raise DNSPreflightError("CLOUDFLARE_LIVE_RECORD_ALREADY_DR_OR_MISMATCH")
    else:
        raise DNSPreflightError("CLOUDFLARE_LIVE_RECORD_TYPE_UNEXPECTED")


def read_dr_state(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DNSPreflightError("DR_STATE_UNAVAILABLE")
    try:
        data = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise DNSPreflightError("DR_STATE_UNAVAILABLE") from exc
    if len(data) > 128 or data.count("\n") > 1:
        raise DNSPreflightError("DR_STATE_INVALID")
    current = data.strip()
    if current not in {"IDLE", "FAILED"}:
        raise DNSPreflightError("DR_STATE_NOT_SAFE_FOR_DUMP_DNS_PREFLIGHT")
    return current


def validate_no_world_app_ingress(*, region: str, runner: Callable = subprocess.run) -> None:
    web = _instances(_aws_json([
        "ec2", "describe-instances", "--region", region,
        "--filters", f"Name=tag:Name,Values={WEB_NAME}",
    ], runner=runner))
    doc = _instances(_aws_json([
        "ec2", "describe-instances", "--region", region,
        "--filters", f"Name=tag:Name,Values={DOC_NAME}",
    ], runner=runner))
    if len(web) != 1 or len(doc) != 1:
        raise DNSPreflightError("DR_APP_INSTANCE_IDENTITY_NOT_UNIQUE")
    web_instance, doc_instance = web[0], doc[0]
    if (
        web_instance.get("PrivateIpAddress") != WEB_PRIVATE_IP
        or doc_instance.get("PrivateIpAddress") != DOC_PRIVATE_IP
        or web_instance.get("State", {}).get("Name") != "running"
        or doc_instance.get("State", {}).get("Name") != "running"
        or web_instance.get("VpcId") != doc_instance.get("VpcId")
    ):
        raise DNSPreflightError("DR_APP_INSTANCE_STATE_OR_IDENTITY_UNSAFE")
    web_sgs = {str(x.get("GroupId", "")) for x in web_instance.get("SecurityGroups", [])}
    doc_sgs = {str(x.get("GroupId", "")) for x in doc_instance.get("SecurityGroups", [])}
    if not web_sgs or not doc_sgs or "" in web_sgs | doc_sgs:
        raise DNSPreflightError("DR_APP_SECURITY_GROUP_SET_INVALID")
    group_ids = sorted(web_sgs | doc_sgs)
    groups = _aws_json([
        "ec2", "describe-security-groups", "--region", region,
        "--group-ids", *group_ids,
    ], runner=runner).get("SecurityGroups", [])
    by_id = {str(group.get("GroupId", "")): group for group in groups}
    if set(by_id) != set(group_ids):
        raise DNSPreflightError("DR_APP_SECURITY_GROUP_UNAVAILABLE")
    web_group_names = {str(group.get("GroupName", "")) for group in groups if group.get("GroupId") in web_sgs}
    doc_group_names = {str(group.get("GroupName", "")) for group in groups if group.get("GroupId") in doc_sgs}
    if "hospital-dr-web-sg" not in web_group_names or "hospital-dr-doc-sg" not in doc_group_names:
        raise DNSPreflightError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
    for group in groups:
        for rule in group.get("IpPermissions", []):
            for item in rule.get("IpRanges", []):
                try:
                    network = ipaddress.ip_network(item.get("CidrIp", ""), strict=False)
                except ValueError:
                    raise DNSPreflightError("DR_APP_SECURITY_GROUP_RULE_INVALID")
                if network.prefixlen == 0:
                    raise DNSPreflightError("DR_APP_PUBLIC_INGRESS_PRESENT")
            for item in rule.get("Ipv6Ranges", []):
                try:
                    network = ipaddress.ip_network(item.get("CidrIpv6", ""), strict=False)
                except ValueError:
                    raise DNSPreflightError("DR_APP_SECURITY_GROUP_RULE_INVALID")
                if network.prefixlen == 0:
                    raise DNSPreflightError("DR_APP_PUBLIC_INGRESS_PRESENT")
    # EMR's service listener must be reachable only from the Web security group.
    doc_group_ids = {group_id for group_id in doc_sgs if by_id[group_id].get("GroupName") == "hospital-dr-doc-sg"}
    if len(doc_group_ids) != 1:
        raise DNSPreflightError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
    doc_group = by_id[next(iter(doc_group_ids))]
    service_rules = [
        rule for rule in doc_group.get("IpPermissions", [])
        if rule.get("FromPort") == 80 or rule.get("ToPort") == 80 or rule.get("IpProtocol") == "-1"
    ]
    if len(service_rules) != 1:
        raise DNSPreflightError("DR_EMR_SERVICE_INGRESS_NOT_WEB_ONLY")
    rule = service_rules[0]
    sources = {str(pair.get("GroupId", "")) for pair in rule.get("UserIdGroupPairs", [])}
    if (
        rule.get("IpProtocol") != "tcp"
        or rule.get("FromPort") != 80
        or rule.get("ToPort") != 80
        or sources != web_sgs
        or len(rule.get("UserIdGroupPairs", [])) != len(web_sgs)
        or rule.get("IpRanges")
        or rule.get("Ipv6Ranges")
        or rule.get("PrefixListIds")
    ):
        raise DNSPreflightError("DR_EMR_SERVICE_INGRESS_NOT_WEB_ONLY")


def _validate_args(args: argparse.Namespace, env: Mapping[str, str]) -> None:
    if env.get("DUMP_DB_DNS_PREFLIGHT_ENABLED", "false").strip().lower() != "true":
        raise DNSPreflightError("DUMP_DNS_PREFLIGHT_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
        raise DNSPreflightError("DUMP_RESTORE_EXECUTOR_MUST_REMAIN_DISABLED")
    if env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise DNSPreflightError("DUMP_RESTORE_EXECUTOR_MUST_REMAIN_UNSET")
    if env.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise DNSPreflightError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if env.get("DR_DUMP_EXECUTOR_CHILD") == "1":
        try:
            validate_inherited_dr_locks(env)
        except Exception as exc:
            raise DNSPreflightError("SHARED_DR_EXECUTION_LOCK_REQUIRED") from exc
    if args.region != "ap-northeast-2":
        raise DNSPreflightError("AWS_REGION_NOT_APPROVED")
    if not INSTANCE_RE.fullmatch(args.instance_id):
        raise DNSPreflightError("ISOLATED_INSTANCE_ID_INVALID")
    if not VOLUME_RE.fullmatch(args.data_volume_id) or not VOLUME_RE.fullmatch(args.stage_volume_id):
        raise DNSPreflightError("ISOLATED_VOLUME_ID_INVALID")
    if args.data_volume_id == args.stage_volume_id or not SG_RE.fullmatch(args.service_security_group_id):
        raise DNSPreflightError("ISOLATED_RESOURCE_IDENTITY_INVALID")
    if not SHA256_RE.fullmatch(args.expected_sha256):
        raise DNSPreflightError("EXPECTED_CHECKSUM_INVALID")
    try:
        import uuid

        for value in (args.promotion_id, args.cutover_id):
            if str(uuid.UUID(value)) != value.lower():
                raise ValueError("non-canonical uuid")
    except (ValueError, TypeError, AttributeError) as exc:
        raise DNSPreflightError("PROMOTION_OR_CUTOVER_ID_INVALID") from exc
    if not ZONE_RE.fullmatch(args.zone_id):
        raise DNSPreflightError("CLOUDFLARE_ZONE_ID_INVALID")
    for path, code in (
        (args.inventory, "ANSIBLE_INVENTORY_UNAVAILABLE"),
        (args.ssh_config, "SSH_TRANSPORT_CONFIG_UNAVAILABLE"),
        (Path(args.ssh_key) if args.ssh_key else None, "SSH_KEY_UNAVAILABLE"),
        (args.known_hosts, "SSH_KNOWN_HOSTS_UNAVAILABLE"),
    ):
        if path is None or not path.is_file() or not os.access(path, os.R_OK):
            raise DNSPreflightError(code)
    if not args.origin_snapshot_dir or not args.state_file:
        raise DNSPreflightError("DNS_OR_DR_STATE_PATH_MISSING")


def _run_remote_checks(args, backup: dict, *, runner: Callable = subprocess.run) -> None:
    if not PLAYBOOK.is_file() or not REMOTE_HELPER.is_file() or not RESTORE_HELPER.is_file() or not APP_PROBE.is_file():
        raise DNSPreflightError("DUMP_DNS_PREFLIGHT_CODE_MISSING")
    try:
        tmpfs = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", "/dev/shm"],
            capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        raise DNSPreflightError("SECRET_TMPFS_UNAVAILABLE") from exc
    if tmpfs.returncode != 0 or tmpfs.stdout.strip() != "tmpfs":
        raise DNSPreflightError("SECRET_TMPFS_UNAVAILABLE")
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-dump-dns-preflight-", dir="/dev/shm") as temp:
            root = Path(temp)
            root.chmod(0o700)
            inventory = root / "isolated-inventory.ini"
            ssh_config = root / "isolated-ssh-config"
            variables = root / "preflight-vars.json"
            _build_overlay(
                path=inventory,
                ssh_config_path=ssh_config,
                ssh_config=args.ssh_config,
                ssh_key=args.ssh_key,
                known_hosts=str(args.known_hosts),
                private_ip=args.private_ip,
            )
            vars_data = {
                "dump_dns_instance_id": args.instance_id,
                "dump_dns_private_ip": args.private_ip,
                "dump_dns_data_volume_id": args.data_volume_id,
                "dump_dns_stage_volume_id": args.stage_volume_id,
                "dump_dns_service_sg_id": args.service_security_group_id,
                "dump_dns_backup_id": args.backup.name,
                "dump_dns_expected_sha256": backup["sha256"].lower(),
                "dump_dns_promotion_id": args.promotion_id,
                "dump_dns_cutover_id": args.cutover_id,
                "dump_dns_expected_service_helper_sha256": hashlib.sha256(REMOTE_HELPER.read_bytes()).hexdigest(),
                "dump_dns_expected_restore_helper_sha256": hashlib.sha256(RESTORE_HELPER.read_bytes()).hexdigest(),
                "dump_dns_expected_app_probe_sha256": hashlib.sha256(APP_PROBE.read_bytes()).hexdigest(),
            }
            _write_private(variables, json.dumps(vars_data, sort_keys=True))
            command = [
                "ansible-playbook",
                "-i", str(args.inventory),
                "-i", str(inventory),
                "-e", f"@{variables}",
                str(PLAYBOOK),
            ]
            # The remote playbook needs AWS/SSM identity and SSH transport, not
            # Cloudflare, DB, Slack, or encryption secrets.
            allowed_env = {
                "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONNOUSERSITE",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE",
                "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                "SSH_AUTH_SOCK", "ANSIBLE_CONFIG", "ANSIBLE_HOST_KEY_CHECKING",
            }
            child_env = {key: value for key, value in os.environ.items() if key in allowed_env}
            result = runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT / "automation/ansible"),
                env=child_env,
            )
    except OSError as exc:
        raise DNSPreflightError("REMOTE_READ_ONLY_PREFLIGHT_UNAVAILABLE") from exc
    if result.returncode != 0 or "DUMP_DNS_PREFLIGHT_REMOTE=PASS" not in result.stdout:
        raise DNSPreflightError("REMOTE_READ_ONLY_PREFLIGHT_FAILED")


def execute_preflight(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    backup_validator: Callable = validate_backup_pair,
    state_reader: Callable = read_dr_state,
    dns_reader: Callable = cloudflare_get_record,
    aws_target_validator: Callable = validate_aws_isolated_target,
    app_access_validator: Callable = validate_no_world_app_ingress,
    remote_validator: Callable = _run_remote_checks,
    aws_runner: Callable = subprocess.run,
) -> dict:
    env = environment if environment is not None else os.environ
    _validate_args(args, env)
    backup = backup_validator(args.backup, args.expected_sha256)
    if backup.get("sha256", "").lower() != args.expected_sha256.lower():
        raise DNSPreflightError("CHECKSUM_MISMATCH")
    state = state_reader(args.state_file)

    origin = load_origin_pair(
        args.origin_snapshot_dir,
        web_name=args.web_domain,
        emr_name=args.emr_domain,
        tunnel_host=args.onprem_tunnel_host,
        emr_origin_ip=args.onprem_emr_ip,
        dr_eip=args.dr_web_eip,
        web_record_id=args.web_record_id,
        emr_record_id=args.emr_record_id,
    )
    token = env.get("CLOUDFLARE_API_TOKEN", "")
    zone_id = args.zone_id
    for key, snapshot in ((args.web_record_id, origin["web"]), (args.emr_record_id, origin["emr"])):
        live = dns_reader(zone_id=zone_id, record_id=key, token=token)
        validate_live_origin_record(live, snapshot, dr_eip=args.dr_web_eip)

    try:
        aws_target = aws_target_validator(
            region=args.region,
            instance_id=args.instance_id,
            private_ip=args.private_ip,
            data_volume_id=args.data_volume_id,
            stage_volume_id=args.stage_volume_id,
            service_security_group_id=args.service_security_group_id,
            require_service_sg_attached=True,
            runner=aws_runner,
        )
    except Exception as exc:
        if isinstance(exc, DNSPreflightError):
            raise
        raise DNSPreflightError("AWS_ISOLATED_TARGET_READ_ONLY_CHECK_FAILED") from exc
    if (
        aws_target.get("instance_id") != args.instance_id
        or aws_target.get("private_ip") != args.private_ip
        or aws_target.get("data_volume_id") != args.data_volume_id
        or aws_target.get("stage_volume_id") != args.stage_volume_id
        or aws_target.get("service_security_group_id") != args.service_security_group_id
        or aws_target.get("service_security_group_attached") is not True
    ):
        raise DNSPreflightError("AWS_ISOLATED_TARGET_READ_ONLY_CHECK_MISMATCH")
    try:
        app_access_validator(region=args.region, runner=aws_runner)
    except Exception as exc:
        if isinstance(exc, DNSPreflightError):
            raise
        raise DNSPreflightError("AWS_APP_ACCESS_READ_ONLY_CHECK_FAILED") from exc
    try:
        remote_validator(args, backup, runner=aws_runner)
    except DNSPreflightError:
        raise
    except Exception as exc:
        raise DNSPreflightError("REMOTE_READ_ONLY_PREFLIGHT_FAILED") from exc

    return {
        "status": "DUMP_DNS_PREFLIGHT_PASSED_NOT_AUTHORIZATION",
        "dr_state_observed": state,
        "backup_id": args.backup.name,
        "sha256": backup["sha256"].lower(),
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "cloudflare_dns": "APPROVED_ONPREM_PAIR_READ_ONLY_VERIFIED",
        "db_write_mode": "ENABLED_APPS_AND_SERVICE_ACCOUNTS_FENCED",
        "apps_health_checked": False,
        "dns_change_authorized": False,
        "application_writes_allowed": False,
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
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--inventory", type=Path, default=REPO_ROOT / "automation/ansible/inventory.ini")
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY", ""))
    parser.add_argument("--ssh-config", type=Path, default=Path(os.environ.get("DR_SSH_CONFIG_FILE", "/var/lib/hospital-dr/ssh/config")))
    parser.add_argument("--known-hosts", type=Path, default=Path(os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts")))
    parser.add_argument("--origin-snapshot-dir", type=Path, default=Path(os.environ.get("DR_DNS_ORIGIN_SNAPSHOT_DIR", "/var/lib/hospital-dr/dns/origin")))
    parser.add_argument("--state-file", type=Path, default=Path(os.environ.get("DR_STATE_FILE", "/var/lib/hospital-dr/dr_state")))
    parser.add_argument("--zone-id", default=os.environ.get("CF_ZONE_ID", ""))
    parser.add_argument("--web-record-id", default=os.environ.get("CF_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--emr-record-id", default=os.environ.get("CF_EMR_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--web-domain", default=os.environ.get("DR_DOMAIN", "hospital-web.pp.ua"))
    parser.add_argument("--emr-domain", default=os.environ.get("EMR_DOMAIN", "emr.hospital-web.pp.ua"))
    parser.add_argument("--onprem-tunnel-host", default=os.environ.get("ONPREM_TUNNEL_HOST", ""))
    parser.add_argument("--onprem-emr-ip", default=os.environ.get("ONPREM_EMR_DNS_IP_EXPECTED", ""))
    parser.add_argument("--dr-web-eip", default=os.environ.get("DR_WEB_EIP_EXPECTED", DNS_DR_EIP_DEFAULT))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_preflight(args)
        print("DUMP_DNS_PREFLIGHT=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except (DNSPreflightError, PreflightError) as exc:
        reason = getattr(exc, "code", str(exc))
        print(f"DUMP_DNS_PREFLIGHT=BLOCKED reason={reason}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("DUMP_DNS_PREFLIGHT=BLOCKED reason=READ_ONLY_PREFLIGHT_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
