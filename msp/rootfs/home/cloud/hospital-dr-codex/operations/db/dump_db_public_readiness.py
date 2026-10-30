#!/usr/bin/env python3
"""Prepare a time-bounded, maintenance-only Dump DR public network path.

This operation never changes DNS, DR state, DB grants, or application write
permissions. A successful receipt is preparation evidence, not authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping

from operations.db import dump_db_dns_preflight as dns_preflight
from operations.db.dump_execution_contract import validate_inherited_dr_locks
from operations.db.dump_db_service_promotion import _build_overlay, _write_private
from operations.db.isolated_dump_restore import (
    DOC_NAME,
    DOC_PRIVATE_IP,
    PRODUCTION_DB_INSTANCE_ID,
    WEB_NAME,
    WEB_PRIVATE_IP,
    PreflightError,
    _aws_json,
    _instances,
    validate_aws_isolated_target,
    validate_backup_pair,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO_ROOT / "automation/ansible/dump_db_public_readiness.yml"
TERRAFORM_MAIN = REPO_ROOT / "infra/terraform/main.tf"
REMOTE_DB_HELPER = REPO_ROOT / "operations/db/isolated_db_service_host.py"
REMOTE_DB_CLI = REPO_ROOT / "operations/db/dump_db_readonly_health_host.py"
REMOTE_RESTORE_HELPER = REPO_ROOT / "operations/db/isolated_restore_host.py"
REMOTE_APP_PROBE = REPO_ROOT / "operations/db/dump_db_app_fence_probe.py"
REMOTE_DB_PROBE_JS = REPO_ROOT / "operations/db/dump_db_readonly_app_probe.js"
FENCE_HELPER = REPO_ROOT / "operations/db/dump_db_external_fence.py"
EXPIRY_HELPER = REPO_ROOT / "operations/db/dump_db_public_readiness_expire.py"
STATE_ROOT_DEFAULT = Path("/var/lib/hospital-dr/dump-public-readiness")
DR_WEB_EIP_DEFAULT = "AWS_PUBLIC_IP_REDACTED"
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 1800
INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
VOLUME_RE = re.compile(r"vol-[0-9a-f]{8,32}\Z")
SG_RE = re.compile(r"sg-[0-9a-f]{8,32}\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
BACKUP_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")


class PublicReadinessError(RuntimeError):
    """Stable, non-secret failure reason for the operator-facing command."""


def _uuid(value: str, code: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise PublicReadinessError(code) from exc
    if normalized != value.lower():
        raise PublicReadinessError(code)
    return normalized


def _parse_ipv4_list(value: str, *, code: str) -> tuple[str, ...]:
    try:
        decoded = json.loads(value)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise PublicReadinessError(code) from exc
    if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
        raise PublicReadinessError(code)
    result = []
    for item in decoded:
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise PublicReadinessError(code) from exc
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen == 0:
            raise PublicReadinessError(code)
        result.append(str(network))
    if len(set(result)) != len(result):
        raise PublicReadinessError(code)
    return tuple(result)


def load_configured_cloudflare_ipv4_cidrs(
    *, terraform_main: Path = TERRAFORM_MAIN, environment: Mapping[str, str] | None = None
) -> tuple[str, ...]:
    env = environment if environment is not None else os.environ
    override = env.get("TF_VAR_cloudflare_ipv4_cidrs", "").strip()
    if override:
        values = _parse_ipv4_list(override, code="CLOUDFLARE_IPV4_CONFIG_INVALID")
    else:
        try:
            source = terraform_main.read_text(encoding="utf-8")
        except OSError as exc:
            raise PublicReadinessError("CLOUDFLARE_IPV4_CONFIG_UNAVAILABLE") from exc
        block = re.search(
            r'variable\s+"cloudflare_ipv4_cidrs"\s*\{(.*?)\n\}', source, re.S
        )
        default = re.search(r"default\s*=\s*\[(.*?)\]", block.group(1), re.S) if block else None
        if not default:
            raise PublicReadinessError("CLOUDFLARE_IPV4_CONFIG_INVALID")
        raw = re.findall(r'"([^"\n]+)"', default.group(1))
        values = tuple(raw)
    normalized = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise PublicReadinessError("CLOUDFLARE_IPV4_CONFIG_INVALID") from exc
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen < 8
            or network.network_address.is_private
            or network.network_address.is_loopback
            or network.network_address.is_link_local
            or network.network_address.is_multicast
            or network.network_address.is_reserved
        ):
            raise PublicReadinessError("CLOUDFLARE_IPV4_CONFIG_UNSAFE")
        normalized.append(str(network))
    if not normalized or len(set(normalized)) != len(normalized):
        raise PublicReadinessError("CLOUDFLARE_IPV4_CONFIG_INVALID")
    return tuple(sorted(normalized, key=lambda item: ipaddress.ip_network(item).network_address))


def load_management_ipv4_cidrs(environment: Mapping[str, str]) -> tuple[str, ...]:
    raw = environment.get("TF_VAR_management_ipv4_cidrs", "").strip()
    if not raw:
        return ()
    return _parse_ipv4_list(raw, code="MANAGEMENT_IPV4_CONFIG_INVALID")


def load_terraform_ipv4_cidrs(
    variable_name: str, *, terraform_main: Path = TERRAFORM_MAIN,
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    env = environment if environment is not None else os.environ
    override = env.get(f"TF_VAR_{variable_name}", "").strip()
    if override:
        return _parse_ipv4_list(override, code=f"{variable_name.upper()}_CONFIG_INVALID")
    try:
        source = terraform_main.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublicReadinessError("TERRAFORM_NETWORK_CONFIG_UNAVAILABLE") from exc
    block = re.search(rf'variable\s+"{re.escape(variable_name)}"\s*\{{(.*?)\n\}}', source, re.S)
    default = re.search(r"default\s*=\s*\[(.*?)\]", block.group(1), re.S) if block else None
    if not default:
        raise PublicReadinessError(f"{variable_name.upper()}_CONFIG_INVALID")
    raw = re.findall(r'"([^"\n]+)"', default.group(1))
    if not raw:
        return ()
    return _parse_ipv4_list(json.dumps(raw), code=f"{variable_name.upper()}_CONFIG_INVALID")


def validate_dump_app_ingress_contract(
    *,
    web_instance: dict,
    doc_instance: dict,
    security_groups: list[dict],
    cloudflare_ipv4_cidrs: tuple[str, ...],
    management_ipv4_cidrs: tuple[str, ...] = (),
    zabbix_ipv4_cidrs: tuple[str, ...] = (),
    wireguard_peer_ipv4_cidrs: tuple[str, ...] = (),
    wireguard_enabled: bool = False,
) -> dict:
    """Reject ingress drift that bypasses the Dump-specific network contract."""
    if (
        web_instance.get("PrivateIpAddress") != WEB_PRIVATE_IP
        or doc_instance.get("PrivateIpAddress") != DOC_PRIVATE_IP
        or web_instance.get("State", {}).get("Name") != "running"
        or doc_instance.get("State", {}).get("Name") != "running"
        or web_instance.get("VpcId") != doc_instance.get("VpcId")
    ):
        raise PublicReadinessError("DR_APP_INSTANCE_IDENTITY_UNSAFE")
    web_ids = {str(group.get("GroupId", "")) for group in web_instance.get("SecurityGroups", [])}
    doc_ids = {str(group.get("GroupId", "")) for group in doc_instance.get("SecurityGroups", [])}
    by_id = {str(group.get("GroupId", "")): group for group in security_groups}
    if not web_ids or not doc_ids or "" in web_ids | doc_ids or set(by_id) != web_ids | doc_ids:
        raise PublicReadinessError("DR_APP_SECURITY_GROUP_SET_INVALID")
    web_app_ids = {gid for gid in web_ids if by_id[gid].get("GroupName") == "hospital-dr-web-sg"}
    doc_app_ids = {gid for gid in doc_ids if by_id[gid].get("GroupName") == "hospital-dr-doc-sg"}
    if len(web_app_ids) != 1 or len(doc_app_ids) != 1 or web_ids != web_app_ids or doc_ids != doc_app_ids:
        raise PublicReadinessError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")

    cf = set(cloudflare_ipv4_cidrs)
    mgmt = set(management_ipv4_cidrs)
    web_https_sources: set[str] = set()
    for gid in web_ids | doc_ids:
        group = by_id[gid]
        if group.get("VpcId") != web_instance.get("VpcId"):
            raise PublicReadinessError("DR_APP_SECURITY_GROUP_VPC_MISMATCH")
        for rule in group.get("IpPermissions", []):
            protocol = str(rule.get("IpProtocol", ""))
            start, end = rule.get("FromPort"), rule.get("ToPort")
            raw_ipv4 = {str(item.get("CidrIp", "")) for item in rule.get("IpRanges", [])}
            ipv6 = rule.get("Ipv6Ranges", [])
            sources = {str(item.get("GroupId", "")) for item in rule.get("UserIdGroupPairs", [])}
            prefixes = rule.get("PrefixListIds", [])
            if any(value == "IP_REDACTED/0" for value in raw_ipv4):
                raise PublicReadinessError("DR_APP_PUBLIC_INGRESS_PRESENT")
            if ipv6:
                # No IPv6 ingress is part of the approved DR public path.
                raise PublicReadinessError("DR_APP_IPV6_INGRESS_PRESENT")
            if protocol == "-1":
                # The only accepted all-protocol rule is private VPC NAT support.
                if sources or prefixes or not raw_ipv4:
                    raise PublicReadinessError("DR_APP_BROAD_INGRESS_UNSAFE")
                try:
                    if any(
                        not ipaddress.ip_network(cidr, strict=False).subnet_of(
                            ipaddress.ip_network("IP_REDACTED/16")
                        )
                        for cidr in ipv4
                    ):
                        raise PublicReadinessError("DR_APP_BROAD_INGRESS_UNSAFE")
                except ValueError as exc:
                    raise PublicReadinessError("DR_APP_SECURITY_GROUP_RULE_INVALID") from exc
                continue
            if start is None or end is None:
                raise PublicReadinessError("DR_APP_SECURITY_GROUP_RULE_INVALID")
            start, end = int(start), int(end)
            if start <= 3000 <= end and (gid in web_ids | doc_ids):
                raise PublicReadinessError("APP_CONTAINER_PORT_3000_NOT_PRIVATE")
            try:
                networks = {str(ipaddress.ip_network(cidr, strict=True)) for cidr in raw_ipv4}
            except ValueError as exc:
                raise PublicReadinessError("DR_APP_SECURITY_GROUP_RULE_INVALID") from exc
            if prefixes:
                raise PublicReadinessError("DR_APP_PREFIX_LIST_INGRESS_UNAPPROVED")
            if gid in doc_ids and start in {80, 22}:
                if (
                    protocol != "tcp" or start != end or networks or prefixes
                    or sources != web_app_ids
                    or len(rule.get("UserIdGroupPairs", [])) != len(web_app_ids)
                ):
                    raise PublicReadinessError("DR_EMR_SERVICE_INGRESS_NOT_WEB_ONLY")
                continue
            if sources or not networks or protocol not in {"tcp", "udp"} or start != end:
                raise PublicReadinessError("DR_APP_INGRESS_RULE_UNAPPROVED")
            port_key = (protocol, start)
            if gid in doc_ids:
                if port_key != ("tcp", 10050) or not networks.issubset(set(zabbix_ipv4_cidrs)):
                    raise PublicReadinessError("DR_DOC_INGRESS_RULE_UNAPPROVED")
            elif port_key == ("tcp", 80):
                if not networks.issubset(cf):
                    raise PublicReadinessError("DR_WEB_HTTP_SOURCE_NOT_APPROVED")
            elif port_key == ("tcp", 443):
                if not networks.issubset(cf | mgmt):
                    raise PublicReadinessError("DR_WEB_HTTPS_SOURCE_NOT_APPROVED")
                web_https_sources.update(networks)
            elif port_key == ("tcp", 22):
                if not networks.issubset(mgmt):
                    raise PublicReadinessError("DR_WEB_SSH_SOURCE_NOT_APPROVED")
            elif port_key == ("tcp", 10050):
                if not zabbix_ipv4_cidrs or not networks.issubset(set(zabbix_ipv4_cidrs)):
                    raise PublicReadinessError("DR_WEB_ZABBIX_SOURCE_NOT_APPROVED")
            elif port_key == ("tcp", 3306):
                if not wireguard_enabled or networks != {"IP_REDACTED/32"}:
                    raise PublicReadinessError("DR_WEB_DB_INGRESS_UNAPPROVED")
            elif port_key == ("udp", 51820):
                if networks != {"IP_REDACTED/32"}:
                    raise PublicReadinessError("DR_WEB_LEGACY_WG_SOURCE_UNAPPROVED")
            elif port_key == ("udp", 51821):
                if not wireguard_enabled or not set(wireguard_peer_ipv4_cidrs) or not networks.issubset(set(wireguard_peer_ipv4_cidrs)):
                    raise PublicReadinessError("DR_WEB_NEW_WG_SOURCE_UNAPPROVED")
            else:
                raise PublicReadinessError("DR_APP_INGRESS_RULE_UNAPPROVED")

    if not cf.issubset(web_https_sources):
        raise PublicReadinessError("CLOUDFLARE_HTTPS_INGRESS_INCOMPLETE")

    doc_service_rules = [
        rule for gid in doc_ids for rule in by_id[gid].get("IpPermissions", [])
        if rule.get("FromPort") == 80 or rule.get("ToPort") == 80 or rule.get("IpProtocol") == "-1"
    ]
    if len(doc_service_rules) != 1:
        raise PublicReadinessError("DR_EMR_SERVICE_INGRESS_NOT_WEB_ONLY")
    rule = doc_service_rules[0]
    if (
        rule.get("IpProtocol") != "tcp"
        or rule.get("FromPort") != 80
        or rule.get("ToPort") != 80
        or {str(pair.get("GroupId", "")) for pair in rule.get("UserIdGroupPairs", [])} != web_app_ids
        or len(rule.get("UserIdGroupPairs", [])) != len(web_app_ids)
        or rule.get("IpRanges")
        or rule.get("Ipv6Ranges")
        or rule.get("PrefixListIds")
    ):
        raise PublicReadinessError("DR_EMR_SERVICE_INGRESS_NOT_WEB_ONLY")
    return {
        "web_instance_id": str(web_instance.get("InstanceId", "")),
        "doc_instance_id": str(doc_instance.get("InstanceId", "")),
        "web_security_group_ids": sorted(web_ids),
        "doc_security_group_ids": sorted(doc_ids),
        "cloudflare_ipv4_cidrs": sorted(cf),
        "ipv6_ingress": False,
        "world_ingress": False,
        "app_port_3000_ingress": False,
    }


def read_and_validate_app_security_groups(
    *, region: str, cloudflare_ipv4_cidrs: tuple[str, ...], management_ipv4_cidrs: tuple[str, ...],
    zabbix_ipv4_cidrs: tuple[str, ...] = (), wireguard_peer_ipv4_cidrs: tuple[str, ...] = (),
    wireguard_enabled: bool = False, expected_eip: str, runner: Callable = subprocess.run,
) -> dict:
    web = _instances(_aws_json([
        "ec2", "describe-instances", "--region", region,
        "--filters", f"Name=tag:Name,Values={WEB_NAME}",
    ], runner=runner))
    doc = _instances(_aws_json([
        "ec2", "describe-instances", "--region", region,
        "--filters", f"Name=tag:Name,Values={DOC_NAME}",
    ], runner=runner))
    if len(web) != 1 or len(doc) != 1:
        raise PublicReadinessError("DR_APP_INSTANCE_IDENTITY_NOT_UNIQUE")
    web_instance, doc_instance = web[0], doc[0]
    ids = {
        str(item.get("GroupId", ""))
        for instance in (web_instance, doc_instance)
        for item in instance.get("SecurityGroups", [])
    }
    groups = _aws_json([
        "ec2", "describe-security-groups", "--region", region, "--group-ids", *sorted(ids),
    ], runner=runner).get("SecurityGroups", [])
    result = validate_dump_app_ingress_contract(
        web_instance=web_instance,
        doc_instance=doc_instance,
        security_groups=groups,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
        management_ipv4_cidrs=management_ipv4_cidrs,
        zabbix_ipv4_cidrs=zabbix_ipv4_cidrs,
        wireguard_peer_ipv4_cidrs=wireguard_peer_ipv4_cidrs,
        wireguard_enabled=wireguard_enabled,
    )
    eip_result = _aws_json([
        "ec2", "describe-addresses", "--region", region, "--public-ips", expected_eip,
    ], runner=runner).get("Addresses", [])
    if (
        len(eip_result) != 1
        or eip_result[0].get("PublicIp") != expected_eip
        or eip_result[0].get("InstanceId") != result["web_instance_id"]
        or not eip_result[0].get("AssociationId")
    ):
        raise PublicReadinessError("DR_WEB_EIP_ASSOCIATION_MISMATCH")
    return result


def validate_request(args: argparse.Namespace, env: Mapping[str, str]) -> None:
    if env.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
        raise PublicReadinessError("APPROVED_SECRET_WRAPPER_REQUIRED")
    if env.get("DR_DUMP_EXECUTOR_CHILD") == "1":
        try:
            validate_inherited_dr_locks(env)
        except Exception as exc:
            raise PublicReadinessError("SHARED_DR_EXECUTION_LOCK_REQUIRED") from exc
    if env.get("DUMP_DB_PUBLIC_READINESS_ENABLED", "false").lower() != "true":
        raise PublicReadinessError("PUBLIC_READINESS_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_DB_READONLY_HEALTH_ENABLED", "false").lower() != "true":
        raise PublicReadinessError("READONLY_HEALTH_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_DB_DNS_PREFLIGHT_ENABLED", "false").lower() != "true":
        raise PublicReadinessError("DUMP_DNS_PREFLIGHT_NOT_EXPLICITLY_ENABLED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").lower() != "false":
        raise PublicReadinessError("DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
    if env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise PublicReadinessError("DUMP_EXECUTOR_MUST_REMAIN_UNSET")
    if env.get("DR_WORKFLOW_LOCK_HELD") != "1" or env.get("DR_FAILOVER_LOCK_HELD") != "1":
        raise PublicReadinessError("SHARED_DR_EXECUTION_LOCK_REQUIRED")
    if not args.confirm_public_readiness:
        raise PublicReadinessError("EXPLICIT_PUBLIC_READINESS_CONFIRMATION_REQUIRED")
    if args.region != "ap-northeast-2":
        raise PublicReadinessError("AWS_REGION_NOT_APPROVED")
    if (
        not INSTANCE_RE.fullmatch(args.instance_id)
        or args.instance_id == PRODUCTION_DB_INSTANCE_ID
        or not VOLUME_RE.fullmatch(args.data_volume_id)
        or not VOLUME_RE.fullmatch(args.stage_volume_id)
        or args.data_volume_id == args.stage_volume_id
        or not SG_RE.fullmatch(args.service_security_group_id)
        or not SHA256_RE.fullmatch(args.expected_sha256)
        or not BACKUP_RE.fullmatch(Path(args.backup).name)
        or not 1 <= int(args.ttl_seconds) <= MAX_TTL_SECONDS
        or int(args.ttl_seconds) < MIN_TTL_SECONDS
    ):
        raise PublicReadinessError("PUBLIC_READINESS_REQUEST_INVALID")
    _uuid(args.promotion_id, "SERVICE_PROMOTION_ID_INVALID")
    _uuid(args.cutover_id, "DB_SERVICE_CUTOVER_ID_INVALID")
    for name, code in (
        ("inventory", "ANSIBLE_INVENTORY_UNAVAILABLE"),
        ("ssh_config", "SSH_TRANSPORT_CONFIG_UNAVAILABLE"),
        ("known_hosts", "SSH_KNOWN_HOSTS_UNAVAILABLE"),
    ):
        path = Path(getattr(args, name))
        if path.is_symlink() or not path.is_file() or not os.access(path, os.R_OK):
            raise PublicReadinessError(code)
    key = Path(args.ssh_key)
    if not args.ssh_key or key.is_symlink() or not key.is_file() or not os.access(key, os.R_OK):
        raise PublicReadinessError("SSH_KEY_UNAVAILABLE")
    if not Path(args.backup).is_file() or Path(args.backup).is_symlink():
        raise PublicReadinessError("BACKUP_ARTIFACT_UNAVAILABLE")
    if not args.origin_snapshot_dir or not args.state_file:
        raise PublicReadinessError("DNS_OR_DR_STATE_PATH_MISSING")


def _origin_and_live_dns(args: argparse.Namespace, *, token: str, dns_reader: Callable) -> dict:
    try:
        origin = dns_preflight.load_origin_pair(
            Path(args.origin_snapshot_dir),
            web_name=args.web_domain,
            emr_name=args.emr_domain,
            tunnel_host=args.onprem_tunnel_host,
            emr_origin_ip=args.onprem_emr_ip,
            dr_eip=args.dr_web_eip,
            web_record_id=args.web_record_id,
            emr_record_id=args.emr_record_id,
        )
        current = {}
        for name, record_id in (("web", args.web_record_id), ("emr", args.emr_record_id)):
            record = dns_reader(zone_id=args.zone_id, record_id=record_id, token=token)
            dns_preflight.validate_live_origin_record(record, origin[name], dr_eip=args.dr_web_eip)
            current[name] = {
                key: record.get(key)
                for key in ("id", "type", "name", "content", "ttl", "proxied")
            }
        return {"snapshot": origin, "current": current}
    except Exception as exc:
        if isinstance(exc, (dns_preflight.DNSPreflightError, PublicReadinessError)):
            raise
        raise PublicReadinessError("CLOUDFLARE_ORIGIN_READ_ONLY_CHECK_FAILED") from exc


def _verify_external_inputs(
    args: argparse.Namespace,
    *,
    token: str,
    cloudflare_cidrs: tuple[str, ...],
    management_cidrs: tuple[str, ...],
    zabbix_cidrs: tuple[str, ...],
    wireguard_peer_cidrs: tuple[str, ...],
    wireguard_enabled: bool,
    state_reader: Callable,
    dns_reader: Callable,
    aws_target_validator: Callable,
    app_sg_validator: Callable,
    aws_runner: Callable,
) -> dict:
    try:
        state = state_reader(Path(args.state_file))
    except Exception as exc:
        raise PublicReadinessError("DR_STATE_READ_ONLY_CHECK_FAILED") from exc
    if state not in {"IDLE", "FAILED"}:
        raise PublicReadinessError("DR_STATE_NOT_SAFE_FOR_DUMP_PUBLIC_READINESS")
    dns = _origin_and_live_dns(args, token=token, dns_reader=dns_reader)
    try:
        isolated = aws_target_validator(
            region=args.region,
            instance_id=args.instance_id,
            private_ip=args.private_ip,
            data_volume_id=args.data_volume_id,
            stage_volume_id=args.stage_volume_id,
            service_security_group_id=args.service_security_group_id,
            require_service_sg_attached=True,
            runner=aws_runner,
        )
        if (
            isolated.get("instance_id") != args.instance_id
            or isolated.get("private_ip") != args.private_ip
            or isolated.get("data_volume_id") != args.data_volume_id
            or isolated.get("stage_volume_id") != args.stage_volume_id
            or isolated.get("service_security_group_id") != args.service_security_group_id
            or isolated.get("service_security_group_attached") is not True
        ):
            raise PublicReadinessError("AWS_ISOLATED_TARGET_READ_ONLY_CHECK_MISMATCH")
        app_groups = app_sg_validator(
            region=args.region,
            cloudflare_ipv4_cidrs=cloudflare_cidrs,
            management_ipv4_cidrs=management_cidrs,
            zabbix_ipv4_cidrs=zabbix_cidrs,
            wireguard_peer_ipv4_cidrs=wireguard_peer_cidrs,
            wireguard_enabled=wireguard_enabled,
            expected_eip=args.dr_web_eip,
            runner=aws_runner,
        )
    except Exception as exc:
        if isinstance(exc, PublicReadinessError):
            raise
        raise PublicReadinessError("AWS_TARGET_OR_INGRESS_READ_ONLY_CHECK_FAILED") from exc
    return {"dr_state": state, "dns": dns, "isolated": isolated, "app_groups": app_groups}


def _safe_child_environment(source: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONNOUSERSITE",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "SSH_AUTH_SOCK", "ANSIBLE_CONFIG",
        "ANSIBLE_HOST_KEY_CHECKING",
    }
    return {key: value for key, value in source.items() if key in allowed}


def _phase_vars(args: argparse.Namespace, phase: str, *, token: str, cidrs: tuple[str, ...]) -> dict:
    values = {
        "dump_public_phase": phase,
        "dump_public_instance_id": args.instance_id,
        "dump_public_private_ip": args.private_ip,
        "dump_public_data_volume_id": args.data_volume_id,
        "dump_public_stage_volume_id": args.stage_volume_id,
        "dump_public_service_sg_id": args.service_security_group_id,
        "dump_public_expected_sha256": args.expected_sha256.lower(),
        "dump_public_backup_id": Path(args.backup).name,
        "dump_public_promotion_id": args.promotion_id,
        "dump_public_cutover_id": args.cutover_id,
        "dump_public_ttl_seconds": int(args.ttl_seconds),
        "dump_public_web_domain": args.web_domain,
        "dump_public_emr_domain": args.emr_domain,
        "dump_public_cloudflare_ipv4_cidrs": list(cidrs),
        "dump_public_host_cli_sha256": hashlib.sha256(REMOTE_DB_CLI.read_bytes()).hexdigest(),
        "dump_public_db_helper_sha256": hashlib.sha256(REMOTE_DB_HELPER.read_bytes()).hexdigest(),
        "dump_public_restore_helper_sha256": hashlib.sha256(REMOTE_RESTORE_HELPER.read_bytes()).hexdigest(),
        "dump_public_fence_helper_sha256": hashlib.sha256(FENCE_HELPER.read_bytes()).hexdigest(),
        "dump_public_expiry_helper_sha256": hashlib.sha256(EXPIRY_HELPER.read_bytes()).hexdigest(),
    }
    if phase in {"maintenance", "verify-prepared"}:
        values["dump_public_probe_token"] = token
    return values


def run_remote_phase(
    args: argparse.Namespace,
    phase: str,
    *,
    token: str,
    cidrs: tuple[str, ...],
    environment: Mapping[str, str],
    runner: Callable = subprocess.run,
    tmpfs_root: str = "/dev/shm",
) -> bool:
    if not PLAYBOOK.is_file():
        raise PublicReadinessError("PUBLIC_READINESS_PLAYBOOK_MISSING")
    for path in (REMOTE_DB_HELPER, REMOTE_DB_CLI, REMOTE_RESTORE_HELPER, REMOTE_APP_PROBE, REMOTE_DB_PROBE_JS, FENCE_HELPER, EXPIRY_HELPER):
        if not path.is_file():
            raise PublicReadinessError("PUBLIC_READINESS_CODE_MISSING")
    try:
        tmpfs = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", tmpfs_root],
            capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        raise PublicReadinessError("SECRET_TMPFS_UNAVAILABLE") from exc
    if tmpfs.returncode != 0 or tmpfs.stdout.strip() != "tmpfs":
        raise PublicReadinessError("SECRET_TMPFS_UNAVAILABLE")
    marker = {
        "verify": "VERIFY_PASS",
        "maintenance": "MAINTENANCE_PASS",
        "open-network": "NETWORK_PASS",
        "verify-prepared": "PREPARED_PASS",
        "rollback": "ROLLBACK_PASS",
    }[phase]
    try:
        with tempfile.TemporaryDirectory(prefix="hospital-dr-dump-public-", dir=tmpfs_root) as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            inventory = root / "isolated-inventory.ini"
            ssh_config = root / "isolated-ssh-config"
            extra_vars = root / "public-readiness-vars.json"
            _build_overlay(
                path=inventory,
                ssh_config_path=ssh_config,
                ssh_config=Path(args.ssh_config),
                ssh_key=args.ssh_key,
                known_hosts=str(args.known_hosts),
                private_ip=args.private_ip,
            )
            _write_private(extra_vars, json.dumps(_phase_vars(args, phase, token=token, cidrs=cidrs), sort_keys=True))
            result = runner(
                ["ansible-playbook", "-i", str(args.inventory), "-i", str(inventory), "-e", f"@{extra_vars}", str(PLAYBOOK)],
                cwd=str(REPO_ROOT / "automation/ansible"),
                env=_safe_child_environment(environment),
                capture_output=True,
                text=True,
                check=False,
            )
    except OSError as exc:
        raise PublicReadinessError("PUBLIC_READINESS_REMOTE_PHASE_UNAVAILABLE") from exc
    # Never print/copy raw Ansible logs: they may contain remote diagnostics.
    return result.returncode == 0 and f"DUMP_PUBLIC_READINESS_REMOTE={marker}" in result.stdout


def _ensure_private_state_dir(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise PublicReadinessError("PUBLIC_READINESS_STATE_DIR_INVALID")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PublicReadinessError("PUBLIC_READINESS_STATE_DIR_PERMISSIONS_INVALID")


def _create_private_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise PublicReadinessError("PUBLIC_READINESS_RECEIPT_WRITE_FAILED") from exc


def _persist_capability(
    *, args: argparse.Namespace, token: str, now: datetime, ttl_seconds: int,
    external: dict, cidrs: tuple[str, ...], state_dir: Path,
) -> dict:
    _ensure_private_state_dir(state_dir)
    token_path = state_dir / f"{args.cutover_id}.probe-token"
    receipt_path = state_dir / f"{args.cutover_id}.json"
    if token_path.exists() or token_path.is_symlink() or receipt_path.exists() or receipt_path.is_symlink():
        raise PublicReadinessError("PUBLIC_READINESS_OPERATION_ALREADY_RECORDED")
    _create_private_file(token_path, token.encode("ascii"))
    expiry = now + timedelta(seconds=ttl_seconds)
    receipt = {
        "status": "DUMP_PUBLIC_READINESS_PREPARED_NOT_DNS_AUTHORIZED",
        "promotion_id": args.promotion_id,
        "cutover_id": args.cutover_id,
        "backup_id": Path(args.backup).name,
        "sha256": args.expected_sha256.lower(),
        "isolated_instance_id": args.instance_id,
        "isolated_private_ip": args.private_ip,
        "data_volume_id": args.data_volume_id,
        "stage_volume_id": args.stage_volume_id,
        "service_security_group_id": args.service_security_group_id,
        "db_server_uuid_verified": True,
        "apps_health_receipt_revalidated": True,
        "cloudflare_ipv4_cidrs": list(cidrs),
        "ipv6_ingress": False,
        "web_ingress": "CLOUDFLARE_IPV4_TCP_443_ONLY",
        "emr_ingress": "WEB_PRIVATE_IP_TCP_80_ONLY",
        "user_traffic": "MAINTENANCE",
        "health_probe_authenticated": True,
        "health_probe_bodyless": True,
        "application_dml_allowed": False,
        "dns_change_authorized": False,
        "dr_state_changed": False,
        "dr_state_observed": external["dr_state"],
        "dns_origin_pair_read_only_verified": True,
        "web_instance_id": external["app_groups"]["web_instance_id"],
        "doc_instance_id": external["app_groups"]["doc_instance_id"],
        "probe_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "probe_token_path": str(token_path),
        "created_at_utc": now.isoformat(),
        "expires_at_utc": expiry.isoformat(),
        "ttl_seconds": ttl_seconds,
        "automatic_strict_fence_timer_on_web_and_emr": True,
        "finops_policy_changed": False,
    }
    try:
        _create_private_file(receipt_path, json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except Exception:
        try:
            token_path.unlink()
        except OSError:
            pass
        raise
    return receipt


def execute_public_readiness(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    backup_validator: Callable = validate_backup_pair,
    state_reader: Callable = dns_preflight.read_dr_state,
    dns_reader: Callable = dns_preflight.cloudflare_get_record,
    aws_target_validator: Callable = validate_aws_isolated_target,
    app_sg_validator: Callable = read_and_validate_app_security_groups,
    phase_runner: Callable = run_remote_phase,
    token_factory: Callable = lambda: secrets.token_urlsafe(32),
    clock: Callable = lambda: datetime.now(timezone.utc),
    aws_runner: Callable = subprocess.run,
) -> dict:
    env = environment if environment is not None else os.environ
    validate_request(args, env)
    try:
        backup = backup_validator(Path(args.backup), args.expected_sha256)
    except Exception as exc:
        raise PublicReadinessError("BACKUP_ARTIFACT_OR_CHECKSUM_INVALID") from exc
    if not isinstance(backup, dict) or str(backup.get("sha256", "")).lower() != args.expected_sha256.lower():
        raise PublicReadinessError("BACKUP_CHECKSUM_MISMATCH")
    cf_cidrs = load_configured_cloudflare_ipv4_cidrs(environment=env)
    management_cidrs = load_management_ipv4_cidrs(env)
    zabbix_cidrs = load_terraform_ipv4_cidrs("zabbix_agent_source_ipv4_cidrs", environment=env)
    wireguard_peer_cidrs = load_terraform_ipv4_cidrs("aws_dr_wg_peer_ingress_ipv4_cidrs", environment=env)
    wireguard_enabled = env.get("TF_VAR_aws_dr_wg_enabled", "false").strip().lower() == "true"
    token = token_factory()
    if not TOKEN_RE.fullmatch(token):
        raise PublicReadinessError("PROBE_TOKEN_GENERATION_INVALID")
    cloudflare_token = env.get("CLOUDFLARE_API_TOKEN", "")
    if not cloudflare_token:
        raise PublicReadinessError("CLOUDFLARE_READ_CREDENTIAL_UNAVAILABLE")

    def verify_external() -> dict:
        return _verify_external_inputs(
            args,
            token=cloudflare_token,
            cloudflare_cidrs=cf_cidrs,
            management_cidrs=management_cidrs,
            zabbix_cidrs=zabbix_cidrs,
            wireguard_peer_cidrs=wireguard_peer_cidrs,
            wireguard_enabled=wireguard_enabled,
            state_reader=state_reader,
            dns_reader=dns_reader,
            aws_target_validator=aws_target_validator,
            app_sg_validator=app_sg_validator,
            aws_runner=aws_runner,
        )

    external = verify_external()
    try:
        initial_ok = phase_runner(
            args, "verify", token=token, cidrs=cf_cidrs, environment=env
        )
    except Exception as exc:
        raise PublicReadinessError("DUMP_READONLY_HEALTH_STATE_REVALIDATION_FAILED") from exc
    if not initial_ok:
        raise PublicReadinessError("DUMP_READONLY_HEALTH_STATE_REVALIDATION_FAILED")

    mutation_started = False
    token_written = False
    receipt_written = False
    state_dir = Path(args.readiness_state_dir)
    now = clock()
    if now.tzinfo is None:
        raise PublicReadinessError("SYSTEM_CLOCK_TIMEZONE_INVALID")
    try:
        mutation_started = True
        if not phase_runner(args, "maintenance", token=token, cidrs=cf_cidrs, environment=env):
            raise PublicReadinessError("DUMP_MAINTENANCE_OR_EXPIRY_PREPARATION_FAILED")
        before_open = verify_external()
        if before_open["dr_state"] != external["dr_state"] or before_open["dns"]["current"] != external["dns"]["current"]:
            raise PublicReadinessError("DNS_OR_DR_STATE_CHANGED_BEFORE_NETWORK_OPEN")
        if not phase_runner(args, "verify", token=token, cidrs=cf_cidrs, environment=env):
            raise PublicReadinessError("DUMP_READONLY_HEALTH_STATE_CHANGED_BEFORE_NETWORK_OPEN")
        if not phase_runner(args, "open-network", token=token, cidrs=cf_cidrs, environment=env):
            raise PublicReadinessError("LIMITED_NETWORK_PREPARATION_FAILED")
        if not phase_runner(args, "verify-prepared", token=token, cidrs=cf_cidrs, environment=env):
            raise PublicReadinessError("LIMITED_NETWORK_OR_MAINTENANCE_VERIFICATION_FAILED")
        after_open = verify_external()
        if after_open["dr_state"] != external["dr_state"] or after_open["dns"]["current"] != external["dns"]["current"]:
            raise PublicReadinessError("DNS_OR_DR_STATE_CHANGED_DURING_PREPARATION")
        external = after_open
        result = _persist_capability(
            args=args,
            token=token,
            now=now,
            ttl_seconds=int(args.ttl_seconds),
            external=external,
            cidrs=cf_cidrs,
            state_dir=state_dir,
        )
        token_written = True
        receipt_written = True
        return result
    except Exception as exc:
        rollback_ok = False
        if mutation_started:
            try:
                rollback_ok = bool(
                    phase_runner(args, "rollback", token=token, cidrs=cf_cidrs, environment=env)
                )
            except Exception:
                rollback_ok = False
        if token_written or receipt_written:
            for path in (
                state_dir / f"{args.cutover_id}.probe-token",
                state_dir / f"{args.cutover_id}.json",
            ):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    rollback_ok = False
        if mutation_started and not rollback_ok:
            raise PublicReadinessError("STRICT_FENCE_ROLLBACK_FAILED") from exc
        if isinstance(exc, PublicReadinessError):
            raise
        raise PublicReadinessError("PUBLIC_READINESS_PREPARATION_FAILED") from exc


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
    parser.add_argument("--confirm-public-readiness", action="store_true")
    parser.add_argument("--ttl-seconds", type=int, default=int(os.environ.get("DUMP_DB_PUBLIC_READINESS_TTL_SECONDS", "600")))
    parser.add_argument("--inventory", default=os.environ.get("INVENTORY", str(REPO_ROOT / "automation/ansible/inventory.ini")))
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY", ""))
    parser.add_argument("--ssh-config", default=os.environ.get("DR_SSH_CONFIG_FILE", "/var/lib/hospital-dr/ssh/config"))
    parser.add_argument("--known-hosts", default=os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts"))
    parser.add_argument("--origin-snapshot-dir", default=os.environ.get("DR_DNS_ORIGIN_SNAPSHOT_DIR", "/var/lib/hospital-dr/dns/origin"))
    parser.add_argument("--state-file", default=os.environ.get("DR_STATE_FILE", "/var/lib/hospital-dr/dr_state"))
    parser.add_argument("--readiness-state-dir", default=os.environ.get("DUMP_DB_PUBLIC_READINESS_STATE_DIR", str(STATE_ROOT_DEFAULT)))
    parser.add_argument("--zone-id", default=os.environ.get("CF_ZONE_ID", ""))
    parser.add_argument("--web-record-id", default=os.environ.get("CF_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--emr-record-id", default=os.environ.get("CF_EMR_RECORD_ID_EXPECTED", ""))
    parser.add_argument("--web-domain", default=os.environ.get("DR_DOMAIN", "hospital-web.pp.ua"))
    parser.add_argument("--emr-domain", default=os.environ.get("EMR_DOMAIN", "emr.hospital-web.pp.ua"))
    parser.add_argument("--onprem-tunnel-host", default=os.environ.get("ONPREM_TUNNEL_HOST", ""))
    parser.add_argument("--onprem-emr-ip", default=os.environ.get("ONPREM_EMR_DNS_IP_EXPECTED", ""))
    parser.add_argument("--dr-web-eip", default=os.environ.get("DR_WEB_EIP_EXPECTED", DR_WEB_EIP_DEFAULT))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_public_readiness(args)
        print("DUMP_PUBLIC_READINESS=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except (PublicReadinessError, dns_preflight.DNSPreflightError, PreflightError) as exc:
        code = getattr(exc, "code", str(exc))
        print(f"DUMP_PUBLIC_READINESS=BLOCKED reason={code}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("DUMP_PUBLIC_READINESS=BLOCKED reason=PUBLIC_READINESS_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
