#!/usr/bin/env python3
"""Explicitly gated runner for the isolated synthetic Terraform NAT stack.

Default invocation is inert.  AWS reads require --aws-read-only; AWS mutations
require --run/--restore/--cleanup plus the exact Run ID confirmation.  This
module intentionally has no production Failover, DB, Cloudflare, or DNS API
mutation path.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
TF_DIR = ROOT / "infra" / "terraform" / "synthetic_nat_canary"
PROBE_TF_DIR = ROOT / "infra" / "terraform" / "synthetic_nat_probe"
DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "hospital-dr-synthetic-nat"
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,31}$")
AWS_ID_RE = re.compile(r"^(?:vpc|subnet|igw|rtb|eni|sg|acl|i|eipalloc|vpce|rslvr-frgassoc|rslvr-frg|rslvr-fdl)-[A-Za-z0-9-]+$")
MAX_RUN_SECONDS = 30 * 60
AMAZON_LINUX_OWNER_ID = "137112412989"
APPROVED_AMI_ID = "AWS_RESOURCE_ID_REDACTED"
APPROVED_PROBE_DOMAIN = "nat-probe.hospital-web.pp.ua"
API_TIMEOUT_SECONDS = 20
CANARY_FIREWALL_ASSOCIATION_PRIORITY = 200
AWS_AUTODEFINED_INTERNET_RESOLVER_RULE_ID = "rslvr-autodefined-rr-internet-resolver"
PRODUCTION_STATE_KEYS = frozenset(
    {"NAT_INSTANCE_STATUS", "CURRENT_EGRESS_MODE", "DR_ACTIVE", "DR_STATE"}
)
CLEANUP_IDENTITY_ERRORS = frozenset({
    "AWS_ACCOUNT_MISMATCH", "AWS_REGION_MISMATCH", "VPC_IDENTITY_MISMATCH", "VPC_RUN_TAG_MISMATCH",
    "WEB_INSTANCE_IDENTITY_MISMATCH", "EMR_INSTANCE_IDENTITY_MISMATCH", "WEB_RUN_TAG_MISMATCH", "EMR_RUN_TAG_MISMATCH",
    "WEB_NETWORK_IDENTITY_MISMATCH", "EMR_NETWORK_IDENTITY_MISMATCH", "WEB_ENI_IDENTITY_OR_TAG_MISMATCH",
    "EMR_ENI_IDENTITY_OR_TAG_MISMATCH", "SECURITY_GROUP_IDENTITY_MISMATCH", "RUN_ID_TAG_MISSING_OR_MISMATCH",
    "PUBLIC_SUBNET_IDENTITY_MISMATCH", "PRIVATE_SUBNET_IDENTITY_MISMATCH", "ROUTE_TABLE_VPC_MISMATCH",
    "ROUTE_TABLE_SUBNET_ASSOCIATION_MISMATCH", "INTERNET_GATEWAY_ATTACHMENT_MISMATCH", "WEB_EIP_MISMATCH",
    "WEB_EIP_ENI_MISMATCH", "NETWORK_ACL_IDENTITY_MISMATCH", "NETWORK_ACL_SUBNET_ASSOCIATION_MISMATCH",
    "DEFAULT_SECURITY_GROUP_IDENTITY_MISMATCH", "DEFAULT_NETWORK_ACL_IDENTITY_MISMATCH",
    "DEFAULT_ROUTE_TABLE_IDENTITY_MISMATCH",
    "UNEXPECTED_INSTANCE_IN_VPC", "UNEXPECTED_NETWORK_INTERFACE_IN_VPC", "ROUTE_TABLE_ROUTE_SET_MISMATCH",
    "SYNTHETIC_AMI_IDENTITY_MISMATCH", "SYNTHETIC_AMI_PROVENANCE_INVALID",
    "UNEXPECTED_SUBNET_IN_VPC", "UNEXPECTED_VPC_CONNECTIVITY_ATTACHMENT",
    "SSM_ENDPOINT_ENI_IDENTITY_MISMATCH", "SSM_ENDPOINT_ENI_IDENTITY_OR_TAG_MISMATCH",
    "UNEXPECTED_SECURITY_GROUP_IN_VPC", "UNEXPECTED_ROUTE_TABLE_IN_VPC", "UNEXPECTED_NETWORK_ACL_IN_VPC",
})


class CanaryError(RuntimeError):
    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.detail = detail


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_run_id(value: str) -> str:
    if not RUN_ID_RE.fullmatch(value or ""):
        raise CanaryError("RUN_ID_INVALID")
    return value


def _value(outputs: dict[str, Any], key: str) -> Any:
    value = outputs.get(key)
    # Terraform output -json wraps values in {value, type, sensitive}.
    return value.get("value") if isinstance(value, dict) and "value" in value else value


def normalize_outputs(raw: dict[str, Any], requested_run_id: str | None = None) -> dict[str, Any]:
    outputs = {key: _value(raw, key) for key in raw}
    required = {
        "account_id", "region", "run_id", "vpc_id", "vpc_cidr",
        "public_subnet_id", "public_subnet_cidr", "private_subnet_id",
        "private_subnet_cidr", "web_instance_id", "web_eni_id", "web_private_ip",
        "web_eip", "web_eip_allocation_id", "emr_instance_id", "emr_eni_id",
        "emr_private_ip", "web_sg_id", "emr_sg_id", "ssm_endpoint_sg_id",
        "default_sg_id", "default_network_acl_id", "default_route_table_id",
        "ssm_endpoint_ids", "ssm_endpoint_eni_ids", "public_route_table_id", "private_route_table_id",
        "internet_gateway_id", "web_network_acl_id", "emr_network_acl_id",
        "firewall_rule_group_id", "firewall_allow_domain_list_id",
        "firewall_block_domain_list_id", "firewall_association_id", "probe_ipv4", "probe_domain",
        "ssm_role_name", "ssm_instance_profile_name", "synthetic_ami_id",
        "synthetic_ami_owner_id", "root_volume_size_gib",
    }
    missing = sorted(name for name in required if outputs.get(name) in (None, "", {}))
    if missing:
        raise CanaryError("TERRAFORM_OUTPUT_MISSING")
    run_id = safe_run_id(str(outputs["run_id"]))
    if requested_run_id and run_id != requested_run_id:
        raise CanaryError("RUN_ID_OUTPUT_MISMATCH")
    if outputs["region"] != "ap-northeast-2":
        raise CanaryError("REGION_NOT_APPROVED")
    if not re.fullmatch(r"[0-9]{12}", str(outputs["account_id"])):
        raise CanaryError("AWS_ACCOUNT_ID_INVALID")
    if not isinstance(outputs["synthetic_ami_id"], str) or not re.fullmatch(r"ami-[0-9a-f]{8,17}", outputs["synthetic_ami_id"]):
        raise CanaryError("SYNTHETIC_AMI_ID_INVALID")
    if outputs["synthetic_ami_owner_id"] != AMAZON_LINUX_OWNER_ID:
        raise CanaryError("SYNTHETIC_AMI_OWNER_NOT_APPROVED")
    if outputs["synthetic_ami_id"] != APPROVED_AMI_ID:
        raise CanaryError("SYNTHETIC_AMI_ID_NOT_APPROVED")
    if not isinstance(outputs["root_volume_size_gib"], int) or not 8 <= outputs["root_volume_size_gib"] <= 30:
        raise CanaryError("ROOT_VOLUME_SIZE_INVALID")
    for name in (
        "vpc_id", "public_subnet_id", "private_subnet_id", "web_instance_id", "web_eni_id",
        "emr_instance_id", "emr_eni_id", "web_sg_id", "emr_sg_id", "ssm_endpoint_sg_id", "default_sg_id",
        "public_route_table_id", "private_route_table_id", "default_route_table_id", "internet_gateway_id", "web_network_acl_id", "emr_network_acl_id", "default_network_acl_id",
        "firewall_rule_group_id", "firewall_allow_domain_list_id", "firewall_block_domain_list_id",
        "firewall_association_id", "web_eip_allocation_id",
    ):
        if not isinstance(outputs[name], str) or not AWS_ID_RE.fullmatch(outputs[name]):
            raise CanaryError("TERRAFORM_RESOURCE_ID_INVALID")
    try:
        vpc = ipaddress.ip_network(outputs["vpc_cidr"], strict=True)
        public = ipaddress.ip_network(outputs["public_subnet_cidr"], strict=True)
        private = ipaddress.ip_network(outputs["private_subnet_cidr"], strict=True)
        web_ip = ipaddress.ip_address(outputs["web_private_ip"])
        emr_ip = ipaddress.ip_address(outputs["emr_private_ip"])
        probe_ip = ipaddress.ip_address(outputs["probe_ipv4"])
    except (ValueError, TypeError):
        raise CanaryError("CIDR_OR_IP_INVALID") from None
    if any(network.version != 4 for network in (vpc, public, private)) or any(
        address.version != 4 for address in (web_ip, emr_ip, probe_ip)
    ):
        raise CanaryError("IPV6_NOT_ALLOWED")
    if not public.subnet_of(vpc) or not private.subnet_of(vpc) or public.overlaps(private):
        raise CanaryError("SYNTHETIC_CIDR_CONTRACT_INVALID")
    if web_ip not in public or emr_ip not in private or not probe_ip.is_global:
        raise CanaryError("SYNTHETIC_ADDRESS_CONTRACT_INVALID")
    if str(outputs["probe_domain"]).lower() != APPROVED_PROBE_DOMAIN:
        raise CanaryError("PROBE_DOMAIN_INVALID")
    if not isinstance(outputs["ssm_endpoint_ids"], dict) or not {"ssm", "ssmmessages"}.issubset(outputs["ssm_endpoint_ids"]):
        raise CanaryError("SSM_ENDPOINT_OUTPUT_INVALID")
    if not isinstance(outputs["ssm_endpoint_eni_ids"], dict) or set(outputs["ssm_endpoint_eni_ids"]) != set(outputs["ssm_endpoint_ids"]):
        raise CanaryError("SSM_ENDPOINT_ENI_OUTPUT_INVALID")
    if any(not isinstance(eni_id, str) or not AWS_ID_RE.fullmatch(eni_id) or not eni_id.startswith("eni-") for eni_id in outputs["ssm_endpoint_eni_ids"].values()):
        raise CanaryError("SSM_ENDPOINT_ENI_ID_INVALID")
    return outputs


def _rule(protocol: str, from_port: int | None, to_port: int | None, source: str) -> tuple[Any, ...]:
    return protocol, from_port, to_port, source


def _tag_value(resource: dict[str, Any], key: str = "CanaryRunId") -> str | None:
    tags = resource.get("Tags")
    if tags is None:
        tags = resource.get("TagSet", [])
    for tag in tags or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _canonical_dns_domains(domains: Any) -> set[str]:
    if not isinstance(domains, list):
        return {"\x00invalid-domain-list"}
    normalized: set[str] = set()
    for domain in domains:
        if not isinstance(domain, str) or not domain or any(character.isspace() for character in domain):
            normalized.add("\x00invalid-domain")
        else:
            normalized.add(domain.lower().rstrip("."))
    return normalized


def _custom_resolver_associations(associations: Any) -> list[dict[str, Any]]:
    if not isinstance(associations, list):
        raise CanaryError("RESOLVER_RULE_ASSOCIATIONS_INVALID")
    return [
        item for item in associations
        if not isinstance(item, dict)
        or item.get("ResolverRuleId") != AWS_AUTODEFINED_INTERNET_RESOLVER_RULE_ID
    ]


def _attached_internet_gateway_vpc_ids(internet_gateway: dict[str, Any]) -> list[str]:
    return sorted({
        attachment.get("VpcId")
        for attachment in internet_gateway.get("Attachments", [])
        if attachment.get("State") == "available" and attachment.get("VpcId")
    })


def normalize_sg_permissions(permissions: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    rules: set[tuple[Any, ...]] = set()
    for permission in permissions or []:
        protocol = str(permission.get("IpProtocol", "-1"))
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        for item in permission.get("IpRanges", []):
            rules.add(_rule(protocol, from_port, to_port, f"cidr:{item.get('CidrIp', '')}"))
        for item in permission.get("Ipv6Ranges", []):
            rules.add(_rule(protocol, from_port, to_port, f"ipv6:{item.get('CidrIpv6', '')}"))
        for item in permission.get("UserIdGroupPairs", []):
            rules.add(_rule(protocol, from_port, to_port, f"sg:{item.get('GroupId', '')}"))
        for item in permission.get("PrefixListIds", []):
            rules.add(_rule(protocol, from_port, to_port, f"prefix:{item.get('PrefixListId', '')}"))
    return rules


def normalize_sg_rule(item: dict[str, Any]) -> tuple[Any, ...] | None:
    source = None
    if item.get("CidrIpv4"):
        source = f"cidr:{item['CidrIpv4']}"
    elif item.get("CidrIpv6"):
        source = f"ipv6:{item['CidrIpv6']}"
    elif item.get("PrefixListId"):
        source = f"prefix:{item['PrefixListId']}"
    elif item.get("ReferencedGroupInfo", {}).get("GroupId"):
        source = f"sg:{item['ReferencedGroupInfo']['GroupId']}"
    if source is None:
        return None
    protocol = str(item.get("IpProtocol", "-1")).lower()
    return (
        item.get("GroupId"), bool(item.get("IsEgress")), protocol,
        item.get("FromPort"), item.get("ToPort"), source,
    )


def expected_security_groups(outputs: dict[str, Any]) -> dict[str, tuple[set[tuple[Any, ...]], set[tuple[Any, ...]]]]:
    tcp443 = lambda source: _rule("tcp", 443, 443, source)
    endpoints = outputs["ssm_endpoint_ids"]
    expected_endpoints = {
        tcp443(f"cidr:{outputs['probe_ipv4']}/32"),
        tcp443(f"sg:{outputs['ssm_endpoint_sg_id']}"),
    }
    endpoint_ingress = {
        tcp443(f"sg:{outputs['web_sg_id']}"),
        tcp443(f"sg:{outputs['emr_sg_id']}"),
    }
    return {
        outputs["web_sg_id"]: (
            {tcp443(f"cidr:{outputs['emr_private_ip']}/32")}, expected_endpoints
        ),
        outputs["emr_sg_id"]: (set(), expected_endpoints),
        outputs["ssm_endpoint_sg_id"]: (endpoint_ingress, set()),
        outputs["default_sg_id"]: (set(), set()),
    }


def expected_network_acl_rules(outputs: dict[str, Any]) -> dict[str, set[tuple[Any, ...]]]:
    tcp, allow = "6", "allow"
    probe = f"{outputs['probe_ipv4']}/32"
    web = f"{outputs['web_private_ip']}/32"
    emr = f"{outputs['emr_private_ip']}/32"
    private = outputs["private_subnet_cidr"]
    web_rules = {
        (False, 100, tcp, allow, emr, 443, 443),
        (False, 110, tcp, allow, probe, 1024, 65535),
        (False, 120, tcp, allow, private, 1024, 65535),
        (True, 100, tcp, allow, probe, 443, 443),
        (True, 110, tcp, allow, private, 443, 443),
        (True, 120, tcp, allow, emr, 1024, 65535),
    }
    emr_rules = {
        (False, 100, tcp, allow, web, 443, 443),
        (False, 110, tcp, allow, emr, 443, 443),
        (False, 120, tcp, allow, probe, 1024, 65535),
        (False, 130, tcp, allow, private, 1024, 65535),
        (True, 100, tcp, allow, probe, 443, 443),
        (True, 110, tcp, allow, web, 1024, 65535),
        (True, 120, tcp, allow, emr, 1024, 65535),
        (True, 130, tcp, allow, private, 443, 443),
    }
    # DescribeNetworkAcls returns the implicit terminal IPv4 deny entries too.
    # They are not editable, but checking them makes the readback exact and
    # catches unexpected explicit deny/IPv6 rules instead of ignoring them.
    implicit_deny = {
        (False, 32767, "-1", "deny", "IP_REDACTED/0", None, None),
        (True, 32767, "-1", "deny", "IP_REDACTED/0", None, None),
    }
    return {"web": web_rules | implicit_deny, "emr": emr_rules | implicit_deny, "default": implicit_deny}


def _normalize_network_acl_entries(entries: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    rules: set[tuple[Any, ...]] = set()
    for entry in entries or []:
        action = str(entry.get("RuleAction", "")).lower()
        ports = entry.get("PortRange", {}) or {}
        cidr = entry.get("CidrBlock", "")
        if entry.get("Ipv6CidrBlock"):
            cidr = f"ipv6:{entry['Ipv6CidrBlock']}"
        rules.add((
            bool(entry.get("Egress")), int(entry.get("RuleNumber", -1)),
            str(entry.get("Protocol", "")), action, cidr,
            ports.get("From"), ports.get("To"),
        ))
    return rules


def _normalize_routes(routes: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    target_keys = (
        "GatewayId", "NatGatewayId", "NetworkInterfaceId", "VpcPeeringConnectionId",
        "TransitGatewayId", "EgressOnlyInternetGatewayId", "LocalGatewayId", "CarrierGatewayId",
        "VpcEndpointId", "CoreNetworkArn",
    )
    normalized: set[tuple[str, str, str]] = set()
    for route in routes or []:
        destination = (
            route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
            or route.get("DestinationPrefixListId") or ""
        )
        target = next((str(route[key]) for key in target_keys if route.get(key)), "")
        normalized.add((destination, target, str(route.get("State", ""))))
    return normalized


def validate_ssm_role_policy(
    document: dict[str, Any], outputs: dict[str, Any], *, include_ec2messages: bool
) -> bool:
    """Require the exact Run-ID-scoped SSM policy emitted by the Canary stack."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if document.get("Version") != "2012-10-17" or not isinstance(statements, list):
        return False

    expected = [
        {
            "Effect": "Allow",
            "Action": ("ssm:UpdateInstanceInformation",),
            "Resource": (
                f"arn:aws:ec2:{outputs['region']}:{outputs['account_id']}:instance/*",
            ),
            "Condition": {"StringEquals": {"aws:ResourceTag/CanaryRunId": outputs["run_id"]}},
        },
        {
            "Effect": "Allow",
            "Action": tuple(sorted((
                "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
            ))),
            "Resource": ("*",),
            "Condition": {},
        },
    ]
    if include_ec2messages:
        expected.append({
            "Effect": "Allow",
            "Action": tuple(sorted((
                "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage",
                "ec2messages:FailMessage", "ec2messages:GetEndpoint",
                "ec2messages:GetMessages", "ec2messages:SendReply",
            ))),
            "Resource": ("*",),
            "Condition": {},
        })

    normalized = []
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) - {"Effect", "Action", "Resource", "Condition"}:
            return False
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        condition = statement.get("Condition", {})
        if (
            not isinstance(actions, list)
            or not all(isinstance(action, str) for action in actions)
            or not isinstance(resources, list)
            or not all(isinstance(resource, str) for resource in resources)
            or not isinstance(condition, dict)
        ):
            return False
        normalized.append({
            "Effect": statement.get("Effect"),
            "Action": tuple(sorted(actions)),
            "Resource": tuple(sorted(resources)),
            "Condition": condition,
        })
    return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        expected, key=lambda item: json.dumps(item, sort_keys=True)
    )


def validate_snapshot(outputs: dict[str, Any], observed: dict[str, Any], *, after_web_start: bool = False, during_cleanup: bool = False) -> list[str]:
    """Validate normalized readback; returns non-secret reason codes."""
    blocked: list[str] = []
    if observed.get("account_id") != outputs["account_id"]:
        blocked.append("AWS_ACCOUNT_MISMATCH")
    if observed.get("region") != outputs["region"]:
        blocked.append("AWS_REGION_MISMATCH")
    vpc = observed.get("vpc", {})
    if (
        vpc.get("id") != outputs["vpc_id"] or vpc.get("cidr") != outputs["vpc_cidr"]
        or vpc.get("ipv4_cidrs") != [outputs["vpc_cidr"]]
    ):
        blocked.append("VPC_IDENTITY_MISMATCH")
    if vpc.get("run_id") != outputs["run_id"]:
        blocked.append("VPC_RUN_TAG_MISMATCH")
    if not vpc.get("dns_support") or not vpc.get("dns_hostnames") or vpc.get("ipv6_associated"):
        blocked.append("VPC_DNS_OR_IPV6_CONTRACT_INVALID")

    for key, expected in (("web", outputs["web_instance_id"]), ("emr", outputs["emr_instance_id"])):
        instance = observed.get("instances", {}).get(key, {})
        if instance.get("id") != expected or instance.get("vpc_id") != outputs["vpc_id"]:
            blocked.append(f"{key.upper()}_INSTANCE_IDENTITY_MISMATCH")
        if instance.get("image_id") != outputs["synthetic_ami_id"]:
            blocked.append("SYNTHETIC_AMI_IDENTITY_MISMATCH")
        if instance.get("run_id") != outputs["run_id"]:
            blocked.append(f"{key.upper()}_RUN_TAG_MISMATCH")
        expected_subnet = outputs["public_subnet_id"] if key == "web" else outputs["private_subnet_id"]
        expected_ip = outputs["web_private_ip"] if key == "web" else outputs["emr_private_ip"]
        expected_eni = outputs["web_eni_id"] if key == "web" else outputs["emr_eni_id"]
        expected_sg = outputs["web_sg_id"] if key == "web" else outputs["emr_sg_id"]
        if (instance.get("subnet_id"), instance.get("private_ip"), instance.get("eni_id"), instance.get("security_group_ids")) != (
            expected_subnet, expected_ip, expected_eni, [expected_sg]
        ):
            blocked.append(f"{key.upper()}_NETWORK_IDENTITY_MISMATCH")
        if key == "web" and instance.get("source_dest_check") is not False:
            blocked.append("WEB_SOURCE_DEST_CHECK_NOT_DISABLED")
        if key == "emr" and instance.get("source_dest_check") is not True:
            blocked.append("EMR_SOURCE_DEST_CHECK_UNEXPECTED")
        root_volume = instance.get("root_volume", {})
        if (
            not root_volume.get("volume_id")
            or root_volume.get("encrypted") is not True
            or root_volume.get("volume_type") != "gp3"
            or root_volume.get("size_gib") != outputs["root_volume_size_gib"]
            or root_volume.get("delete_on_termination") is not True
            or root_volume.get("run_id") != outputs["run_id"]
        ):
            blocked.append(f"{key.upper()}_ROOT_VOLUME_CONTRACT_INVALID")
        if (
            instance.get("eni_run_id") != outputs["run_id"]
            or instance.get("eni_vpc_id") != outputs["vpc_id"]
            or instance.get("eni_subnet_id") != expected_subnet
            or instance.get("eni_private_ip") != expected_ip
            or instance.get("eni_sg_ids") != [expected_sg]
        ):
            blocked.append(f"{key.upper()}_ENI_IDENTITY_OR_TAG_MISMATCH")
        if instance.get("ipv6_addresses"):
            blocked.append(f"{key.upper()}_IPV6_PRESENT")
        if during_cleanup and instance.get("state") not in {"stopped", "running", "pending", "stopping"}:
            blocked.append(f"{key.upper()}_STATE_NOT_CLEANUP_SAFE")
        elif not during_cleanup and not after_web_start and instance.get("state") != "stopped":
            blocked.append(f"{key.upper()}_MUST_START_STOPPED")
        if not during_cleanup and key == "web" and after_web_start and instance.get("state") != "running":
            blocked.append("WEB_NOT_RUNNING")
        if not during_cleanup and key == "emr" and after_web_start and instance.get("state") != "stopped":
            blocked.append("EMR_STARTED_BEFORE_NAT_VERIFICATION")
    if set(observed.get("instance_ids", [])) != {outputs["web_instance_id"], outputs["emr_instance_id"]}:
        blocked.append("UNEXPECTED_INSTANCE_IN_VPC")
    if set(observed.get("subnet_ids", [])) != {outputs["public_subnet_id"], outputs["private_subnet_id"]}:
        blocked.append("UNEXPECTED_SUBNET_IN_VPC")
    if observed.get("unexpected_connectivity_attachments"):
        blocked.append("UNEXPECTED_VPC_CONNECTIVITY_ATTACHMENT")
    expected_enis = {
        outputs["web_eni_id"], outputs["emr_eni_id"], *outputs["ssm_endpoint_eni_ids"].values()
    }
    if set(observed.get("network_interface_ids", [])) != expected_enis:
        blocked.append("UNEXPECTED_NETWORK_INTERFACE_IN_VPC")
    ami = observed.get("ami", {})
    if (
        ami.get("id") != outputs["synthetic_ami_id"]
        or ami.get("owner_id") != AMAZON_LINUX_OWNER_ID
        or outputs.get("synthetic_ami_owner_id") != AMAZON_LINUX_OWNER_ID
        or ami.get("public") is not True
        or ami.get("state") != "available"
        or ami.get("architecture") != "x86_64"
        or ami.get("virtualization_type") != "hvm"
        or ami.get("root_device_type") != "ebs"
        or ami.get("platform_details") != "Linux/UNIX"
        or not re.fullmatch(r"al2023-ami-.+-x86_64", str(ami.get("name", "")))
    ):
        blocked.append("SYNTHETIC_AMI_PROVENANCE_INVALID")

    groups = observed.get("security_groups", {})
    expected_groups = expected_security_groups(outputs)
    for group_id, (expected_ingress, expected_egress) in expected_groups.items():
        group = groups.get(group_id, {})
        if group.get("vpc_id") != outputs["vpc_id"] or group.get("run_id") != outputs["run_id"]:
            blocked.append(
                "DEFAULT_SECURITY_GROUP_IDENTITY_MISMATCH"
                if group_id == outputs["default_sg_id"]
                else "SECURITY_GROUP_IDENTITY_MISMATCH"
            )
            continue
        ingress = normalize_sg_permissions(group.get("ingress", []))
        egress = normalize_sg_permissions(group.get("egress", []))
        if ingress != expected_ingress:
            blocked.append("SECURITY_GROUP_INGRESS_MISMATCH")
        if egress != expected_egress:
            blocked.append("SECURITY_GROUP_EGRESS_MISMATCH")
    if set(groups) != set(expected_groups):
        blocked.append("UNEXPECTED_SECURITY_GROUP_IN_VPC")

    expected_sg_rules = []
    for group_id, (ingress, egress) in expected_groups.items():
        expected_sg_rules.extend((group_id, False, *rule) for rule in ingress)
        expected_sg_rules.extend((group_id, True, *rule) for rule in egress)
    actual_sg_rules = [
        normalized for item in observed.get("security_group_rules", [])
        if (normalized := normalize_sg_rule(item)) is not None
    ]
    if len(actual_sg_rules) != len(expected_sg_rules) or set(actual_sg_rules) != set(expected_sg_rules):
        blocked.append("SECURITY_GROUP_RULE_SET_MISMATCH")
    sg_rule_tags = observed.get("security_group_rule_run_tags", {})
    sg_rule_ids = {item.get("SecurityGroupRuleId") for item in observed.get("security_group_rules", [])}
    if None in sg_rule_ids or set(sg_rule_tags) != sg_rule_ids or any(value != outputs["run_id"] for value in sg_rule_tags.values()):
        blocked.append("SECURITY_GROUP_RULE_RUN_TAG_MISMATCH")

    expected_tagged = {
        "public_subnet": outputs["public_subnet_id"],
        "private_subnet": outputs["private_subnet_id"],
        "web_eni": outputs["web_eni_id"],
        "emr_eni": outputs["emr_eni_id"],
        "public_route_table": outputs["public_route_table_id"],
        "private_route_table": outputs["private_route_table_id"],
        "internet_gateway": outputs["internet_gateway_id"],
        "web_network_acl": outputs["web_network_acl_id"],
        "emr_network_acl": outputs["emr_network_acl_id"],
        "default_sg": outputs["default_sg_id"],
        "default_network_acl": outputs["default_network_acl_id"],
        "default_route_table": outputs["default_route_table_id"],
        "eip": outputs["web_eip_allocation_id"],
        "iam_role": outputs["ssm_role_name"],
        "iam_instance_profile": outputs["ssm_instance_profile_name"],
        "firewall_rule_group": outputs["firewall_rule_group_id"],
        "firewall_allow_list": outputs["firewall_allow_domain_list_id"],
        "firewall_block_list": outputs["firewall_block_domain_list_id"],
        "firewall_association": outputs["firewall_association_id"],
    }
    for service, endpoint_id in outputs["ssm_endpoint_ids"].items():
        expected_tagged[f"endpoint_{service}"] = endpoint_id
        expected_tagged[f"endpoint_eni_{service}"] = outputs["ssm_endpoint_eni_ids"][service]
    for name, resource_id in expected_tagged.items():
        if observed.get("resource_run_tags", {}).get(name) != outputs["run_id"]:
            blocked.append("RUN_ID_TAG_MISSING_OR_MISMATCH")

    subnets = observed.get("subnets", {})
    if subnets.get("public") != {
        "vpc_id": outputs["vpc_id"], "cidr": outputs["public_subnet_cidr"], "run_id": outputs["run_id"],
        "map_public_ip": False, "ipv6_associated": False,
    }:
        blocked.append("PUBLIC_SUBNET_IDENTITY_MISMATCH")
    if subnets.get("private") != {
        "vpc_id": outputs["vpc_id"], "cidr": outputs["private_subnet_cidr"], "run_id": outputs["run_id"],
        "map_public_ip": False, "ipv6_associated": False,
    }:
        blocked.append("PRIVATE_SUBNET_IDENTITY_MISMATCH")
    if observed.get("route_table_vpc_ids") != {
        "public": outputs["vpc_id"], "private": outputs["vpc_id"], "default": outputs["vpc_id"]
    }:
        blocked.append("ROUTE_TABLE_VPC_MISMATCH")
    if observed.get("route_table_associations") != {
        "public": [outputs["public_subnet_id"]], "private": [outputs["private_subnet_id"]], "default": []
    }:
        blocked.append("ROUTE_TABLE_SUBNET_ASSOCIATION_MISMATCH")
    default_route_table = observed.get("default_route_table", {})
    if (
        default_route_table.get("id") != outputs["default_route_table_id"]
        or default_route_table.get("vpc_id") != outputs["vpc_id"]
        or default_route_table.get("run_id") != outputs["run_id"]
        or default_route_table.get("main_association") is not True
        or default_route_table.get("subnet_ids") != []
        or default_route_table.get("internet_default_routes") != []
    ):
        blocked.append("DEFAULT_ROUTE_TABLE_IDENTITY_MISMATCH")
    if set(observed.get("route_table_ids", [])) != {
        outputs["public_route_table_id"], outputs["private_route_table_id"], outputs["default_route_table_id"]
    }:
        blocked.append("UNEXPECTED_ROUTE_TABLE_IN_VPC")
    expected_vpc_route = (outputs["vpc_cidr"], "local", "active")
    expected_route_sets = {
        "public": {
            expected_vpc_route,
            ("IP_REDACTED/0", outputs["internet_gateway_id"], "active"),
        },
        "private": {
            expected_vpc_route,
            ("IP_REDACTED/0", outputs["web_eni_id"], "active" if after_web_start else "blackhole"),
        },
        "default": {expected_vpc_route},
    }
    for name in ("public", "private", "default"):
        if _normalize_routes(observed.get("route_table_routes", {}).get(name, [])) != expected_route_sets[name]:
            blocked.append("ROUTE_TABLE_ROUTE_SET_MISMATCH")
    for name, expected_id, expected_subnet in (
        ("web", outputs["web_network_acl_id"], outputs["public_subnet_id"]),
        ("emr", outputs["emr_network_acl_id"], outputs["private_subnet_id"]),
        ("default", outputs["default_network_acl_id"], None),
    ):
        acl = observed.get("network_acls", {}).get(name, {})
        if acl.get("id") != expected_id or acl.get("vpc_id") != outputs["vpc_id"] or acl.get("run_id") != outputs["run_id"]:
            blocked.append(
                "DEFAULT_NETWORK_ACL_IDENTITY_MISMATCH"
                if name == "default"
                else "NETWORK_ACL_IDENTITY_MISMATCH"
            )
        if acl.get("subnet_ids") != ([expected_subnet] if expected_subnet else []):
            blocked.append("NETWORK_ACL_SUBNET_ASSOCIATION_MISMATCH")
        if _normalize_network_acl_entries(acl.get("entries", [])) != expected_network_acl_rules(outputs)[name]:
            blocked.append("NETWORK_ACL_RULE_SET_MISMATCH")
    if set(observed.get("network_acl_ids", [])) != {
        outputs["web_network_acl_id"], outputs["emr_network_acl_id"], outputs["default_network_acl_id"]
    }:
        blocked.append("UNEXPECTED_NETWORK_ACL_IN_VPC")
    if sorted(observed.get("internet_gateway_vpc_ids", [])) != [outputs["vpc_id"]]:
        blocked.append("INTERNET_GATEWAY_ATTACHMENT_MISMATCH")
    if observed.get("custom_resolver_rule_association_count", 0) != 0:
        blocked.append("CUSTOM_DNS_FORWARDING_RULE_PRESENT")

    if observed.get("public_route") != {
        "destination": "AWS_PUBLIC_IP_REDACTED/0", "target": outputs["internet_gateway_id"], "state": "active"
    }:
        blocked.append("PUBLIC_DEFAULT_ROUTE_INVALID")
    private_route = observed.get("private_route", {})
    if (private_route.get("destination"), private_route.get("target")) != ("AWS_PUBLIC_IP_REDACTED/0", outputs["web_eni_id"]):
        blocked.append("PRIVATE_DEFAULT_ROUTE_TARGET_INVALID")
    if after_web_start and private_route.get("state") != "active":
        blocked.append("PRIVATE_DEFAULT_ROUTE_NOT_ACTIVE")

    endpoints = observed.get("endpoints", {})
    for service, endpoint_id in outputs["ssm_endpoint_ids"].items():
        endpoint = endpoints.get(service, {})
        if endpoint.get("id") != endpoint_id or endpoint.get("state") != "available":
            blocked.append("SSM_ENDPOINT_NOT_AVAILABLE")
        if endpoint.get("private_dns_enabled") is not True:
            blocked.append("SSM_ENDPOINT_PRIVATE_DNS_DISABLED")
        if endpoint.get("subnet_ids") != [outputs["private_subnet_id"]]:
            blocked.append("SSM_ENDPOINT_SUBNET_MISMATCH")
        if endpoint.get("security_group_ids") != [outputs["ssm_endpoint_sg_id"]]:
            blocked.append("SSM_ENDPOINT_SG_MISMATCH")
        if endpoint.get("network_interface_ids") != [outputs["ssm_endpoint_eni_ids"][service]]:
            blocked.append("SSM_ENDPOINT_ENI_IDENTITY_MISMATCH")
        endpoint_eni = observed.get("endpoint_enis", {}).get(service, {})
        if (
            endpoint_eni.get("id") != outputs["ssm_endpoint_eni_ids"][service]
            or endpoint_eni.get("vpc_id") != outputs["vpc_id"]
            or endpoint_eni.get("subnet_id") != outputs["private_subnet_id"]
            or endpoint_eni.get("security_group_ids") != [outputs["ssm_endpoint_sg_id"]]
            or endpoint_eni.get("requester_managed") is not True
            or endpoint_id not in str(endpoint_eni.get("description", ""))
            or endpoint_eni.get("run_id") != outputs["run_id"]
            or endpoint_eni.get("ipv6_addresses")
        ):
            blocked.append("SSM_ENDPOINT_ENI_IDENTITY_OR_TAG_MISMATCH")

    firewall = observed.get("firewall", {})
    if firewall.get("vpc_id") != outputs["vpc_id"] or firewall.get("association_status") != "COMPLETE":
        blocked.append("DNS_FIREWALL_ASSOCIATION_NOT_COMPLETE")
    if firewall.get("rule_group_id") != outputs["firewall_rule_group_id"]:
        blocked.append("DNS_FIREWALL_RULE_GROUP_MISMATCH")
    if firewall.get("association_priority") != CANARY_FIREWALL_ASSOCIATION_PRIORITY:
        blocked.append("DNS_FIREWALL_ASSOCIATION_PRIORITY_INVALID")
    if firewall.get("mutation_protection") != "DISABLED":
        blocked.append("DNS_FIREWALL_CLEANUP_PROTECTION_STATE_INVALID")
    if firewall.get("fail_open") != "DISABLED":
        blocked.append("DNS_FIREWALL_NOT_FAIL_CLOSED")
    expected_allow_domains = {
        f"ssm.{outputs['region']}.amazonaws.com",
        f"ssmmessages.{outputs['region']}.amazonaws.com",
        outputs["probe_domain"],
    }
    if "ec2messages" in outputs["ssm_endpoint_ids"]:
        expected_allow_domains.add(f"ec2messages.{outputs['region']}.amazonaws.com")
    rules = firewall.get("rules", [])
    allow = [r for r in rules if r.get("action") == "ALLOW" and r.get("priority") == 10]
    block = [r for r in rules if r.get("action") == "BLOCK" and r.get("priority") == 100]
    if len(rules) != 2 or len(allow) != 1 or _canonical_dns_domains(allow[0].get("domains", [])) != expected_allow_domains:
        blocked.append("DNS_FIREWALL_ALLOWLIST_MISMATCH")
    if len(block) != 1 or _canonical_dns_domains(block[0].get("domains", [])) != {"*"} or block[0].get("block_response") != "NXDOMAIN":
        blocked.append("DNS_FIREWALL_CATCH_ALL_BLOCK_MISSING")
    if firewall.get("unexpected_associations") or firewall.get("foreign_group_associations"):
        blocked.append("UNEXPECTED_DNS_FIREWALL_ASSOCIATION")

    if observed.get("eip", {}).get("public_ip") != outputs["web_eip"]:
        blocked.append("WEB_EIP_MISMATCH")
    if observed.get("eip", {}).get("eni_id") != outputs["web_eni_id"]:
        blocked.append("WEB_EIP_ENI_MISMATCH")
    return sorted(set(blocked))


@dataclass
class AwsResult:
    value: dict[str, Any]


class AwsCli:
    def __init__(self, region: str, timeout: int = API_TIMEOUT_SECONDS) -> None:
        self.region = region
        self.timeout = timeout

    def json(self, service: str, operation: str, *args: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        command = ["aws", service, operation, "--region", self.region, "--output", "json"]
        command.extend(args)
        environment = os.environ.copy()
        # Keep CLI v1 compatibility; AWS_PAGER is a no-op in v1 and disables
        # the interactive pager used by CLI v2.
        environment["AWS_PAGER"] = ""
        temp_name: str | None = None
        try:
            if payload is not None:
                fd, temp_name = tempfile.mkstemp(prefix="synthetic-nat-ssm-", suffix=".json")
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(payload, stream)
                command.extend(["--cli-input-json", f"file://{temp_name}"])
            result = subprocess.run(command, text=True, capture_output=True, timeout=self.timeout, check=False, env=environment)
        except subprocess.TimeoutExpired:
            raise CanaryError(f"AWS_{service}_{operation}_TIMEOUT") from None
        except OSError:
            raise CanaryError(f"AWS_{service}_{operation}_EXEC_FAILED") from None
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass
        if result.returncode:
            stderr = result.stderr or ""
            code_match = re.search(r"An error occurred \(([^()]{1,80})\) when calling the [A-Za-z0-9]+ operation", stderr)
            if code_match:
                code = re.sub(r"[^A-Za-z0-9_-]", "", code_match.group(1))
            elif re.search(r"unknown options?|unrecognized arguments?|error parsing parameter", stderr, re.IGNORECASE):
                code = "CLI_ARGUMENT_ERROR"
            elif re.search(r"unable to locate credentials|no credential providers", stderr, re.IGNORECASE):
                code = "CREDENTIALS_UNAVAILABLE"
            else:
                code = "CLI_OR_API_ERROR"
            raise CanaryError(f"AWS_{service}_{operation}_{code or 'ERROR'}")
        try:
            parsed = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            raise CanaryError(f"AWS_{service}_{operation}_INVALID_JSON") from None
        if not isinstance(parsed, dict):
            raise CanaryError(f"AWS_{service}_{operation}_INVALID_RESPONSE")
        return parsed

    def output(self, *args: str, timeout: int = API_TIMEOUT_SECONDS, workspace: str | None = None, cwd: Path = TF_DIR) -> dict[str, Any]:
        environment = _terraform_environment(workspace)
        try:
            result = subprocess.run(list(args), cwd=cwd, env=environment, text=True, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise CanaryError("TERRAFORM_COMMAND_TIMEOUT") from None
        except OSError:
            raise CanaryError("TERRAFORM_COMMAND_EXEC_FAILED") from None
        if result.returncode:
            raise CanaryError("TERRAFORM_COMMAND_FAILED")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise CanaryError("TERRAFORM_OUTPUT_INVALID_JSON") from None
        if not isinstance(payload, dict):
            raise CanaryError("TERRAFORM_OUTPUT_INVALID")
        return payload


def _tagged_resource_arns(response: dict[str, Any]) -> list[str]:
    mappings = response.get("ResourceTagMappingList")
    if not isinstance(mappings, list):
        raise CanaryError("AWS_resourcegroupstaggingapi_get-resources_INVALID_RESPONSE")
    arns: list[str] = []
    for item in mappings:
        if not isinstance(item, dict) or not isinstance(item.get("ResourceARN"), str) or not item["ResourceARN"].strip():
            raise CanaryError("AWS_resourcegroupstaggingapi_get-resources_INVALID_RESPONSE")
        arns.append(item["ResourceARN"])
    return sorted(arns)


def _terraform_environment(workspace: str | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    if any(
        name in {"TF_DATA_DIR", "TF_CLI_CONFIG_FILE"}
        or name.startswith("TF_CLI_ARGS")
        or name.startswith("TF_VAR_")
        for name, value in environment.items() if value.strip()
    ):
        raise CanaryError("TERRAFORM_ENVIRONMENT_OVERRIDE_PRESENT")
    for name in ("TF_DATA_DIR", "TF_CLI_CONFIG_FILE", "TF_WORKSPACE"):
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("TF_CLI_ARGS") or name.startswith("TF_VAR_"):
            environment.pop(name, None)
    if workspace:
        environment["TF_WORKSPACE"] = _terraform_workspace(workspace)
    return environment


def _terraform_workspace(value: str) -> str:
    """Allow the explicit default workspace or a Run-ID workspace only."""
    if value == "default":
        return value
    return safe_run_id(value)


def _one(items: list[dict[str, Any]], resource_id: str) -> dict[str, Any]:
    identity_fields = (
        "InstanceId", "ImageId", "NetworkInterfaceId", "GroupId", "VpcEndpointId", "VpcId",
        "RouteTableId", "AllocationId", "FirewallRuleGroupId", "FirewallDomainListId",
        "SubnetId", "InternetGatewayId", "NetworkAclId",
    )
    matches = [item for item in items if any(item.get(field) == resource_id for field in identity_fields)]
    if len(matches) != 1:
        raise CanaryError("AWS_RESOURCE_READBACK_MISMATCH")
    return matches[0]


def _validate_instance_profile_response(
    response: dict[str, Any], expected_profile_name: str, expected_role_name: str,
) -> dict[str, Any]:
    """Validate the singular shape returned by IAM GetInstanceProfile."""
    profile = response.get("InstanceProfile") if isinstance(response, dict) else None
    if not isinstance(profile, dict) or profile.get("InstanceProfileName") != expected_profile_name:
        raise CanaryError("SSM_INSTANCE_PROFILE_READBACK_INVALID")
    roles = profile.get("Roles")
    if (
        not isinstance(roles, list)
        or len(roles) != 1
        or not isinstance(roles[0], dict)
        or roles[0].get("RoleName") != expected_role_name
    ):
        raise CanaryError("SSM_ROLE_IDENTITY_MISMATCH")
    return profile


class AwsOperations:
    def __init__(self, outputs: dict[str, Any], state_dir: Path) -> None:
        self.outputs = outputs
        self.aws = AwsCli(outputs["region"])
        self.state_dir = state_dir

    def _describe_instances(self) -> tuple[dict[str, Any], dict[str, Any]]:
        response = self.aws.json("ec2", "describe-instances", "--instance-ids", self.outputs["web_instance_id"], self.outputs["emr_instance_id"])
        instances = [instance for reservation in response.get("Reservations", []) for instance in reservation.get("Instances", [])]
        mapped: dict[str, dict[str, Any]] = {}
        for key, instance_id in (("web", self.outputs["web_instance_id"]), ("emr", self.outputs["emr_instance_id"])):
            item = _one(instances, instance_id)
            interfaces = item.get("NetworkInterfaces", [])
            if len(interfaces) != 1:
                raise CanaryError("INSTANCE_ENI_COUNT_INVALID")
            eni = interfaces[0]
            root_mappings = [
                mapping for mapping in item.get("BlockDeviceMappings", [])
                if mapping.get("DeviceName") == item.get("RootDeviceName")
                and mapping.get("Ebs", {}).get("VolumeId")
            ]
            if len(root_mappings) != 1:
                raise CanaryError("ROOT_VOLUME_MAPPING_INVALID")
            root_mapping = root_mappings[0]
            root_ebs = root_mapping["Ebs"]
            mapped[key] = {
                "id": item.get("InstanceId"),
                "image_id": item.get("ImageId"),
                "vpc_id": item.get("VpcId"),
                "subnet_id": item.get("SubnetId"),
                "private_ip": item.get("PrivateIpAddress"),
                "eni_id": eni.get("NetworkInterfaceId"),
                "security_group_ids": sorted(group.get("GroupId", "") for group in item.get("SecurityGroups", [])),
                "state": item.get("State", {}).get("Name"),
                "run_id": next((tag.get("Value") for tag in item.get("Tags", []) if tag.get("Key") == "CanaryRunId"), None),
                "ipv6_addresses": item.get("Ipv6Address"),
                "root_volume": {
                    "volume_id": root_ebs.get("VolumeId"),
                    "delete_on_termination": root_ebs.get("DeleteOnTermination"),
                },
            }
        root_volume_ids = [mapped[key]["root_volume"]["volume_id"] for key in ("web", "emr")]
        volume_response = self.aws.json("ec2", "describe-volumes", "--volume-ids", *root_volume_ids)
        volumes = volume_response.get("Volumes", [])
        if {volume.get("VolumeId") for volume in volumes} != set(root_volume_ids):
            raise CanaryError("ROOT_VOLUME_READBACK_MISMATCH")
        volumes_by_id = {volume.get("VolumeId"): volume for volume in volumes}
        for key in ("web", "emr"):
            volume = volumes_by_id[mapped[key]["root_volume"]["volume_id"]]
            attached_instance_ids = {
                attachment.get("InstanceId") for attachment in volume.get("Attachments", [])
            }
            if attached_instance_ids != {mapped[key]["id"]}:
                raise CanaryError("ROOT_VOLUME_ATTACHMENT_MISMATCH")
            mapped[key]["root_volume"].update({
                "encrypted": volume.get("Encrypted"),
                "volume_type": volume.get("VolumeType"),
                "size_gib": volume.get("Size"),
                "run_id": next((tag.get("Value") for tag in volume.get("Tags", []) if tag.get("Key") == "CanaryRunId"), None),
            })
        eni_response = self.aws.json("ec2", "describe-network-interfaces", "--network-interface-ids", self.outputs["web_eni_id"], self.outputs["emr_eni_id"])
        enis = eni_response.get("NetworkInterfaces", [])
        web_eni = _one(enis, self.outputs["web_eni_id"])
        emr_eni = _one(enis, self.outputs["emr_eni_id"])
        mapped["web"]["source_dest_check"] = web_eni.get("SourceDestCheck")
        mapped["emr"]["source_dest_check"] = emr_eni.get("SourceDestCheck")
        mapped["web"]["ipv6_addresses"] = web_eni.get("Ipv6Addresses", [])
        mapped["emr"]["ipv6_addresses"] = emr_eni.get("Ipv6Addresses", [])
        for key, eni in (("web", web_eni), ("emr", emr_eni)):
            mapped[key]["eni_run_id"] = _tag_value(eni)
            mapped[key]["eni_vpc_id"] = eni.get("VpcId")
            mapped[key]["eni_subnet_id"] = eni.get("SubnetId")
            mapped[key]["eni_private_ip"] = eni.get("PrivateIpAddress")
            mapped[key]["eni_sg_ids"] = sorted(group.get("GroupId", "") for group in eni.get("Groups", []))
        return mapped, instances

    def inspect(self, *, after_web_start: bool = False, during_cleanup: bool = False) -> tuple[dict[str, Any], list[str]]:
        caller = self.aws.json("sts", "get-caller-identity")
        if caller.get("Account") != self.outputs["account_id"]:
            raise CanaryError("AWS_ACCOUNT_MISMATCH")
        ami_response = self.aws.json("ec2", "describe-images", "--image-ids", self.outputs["synthetic_ami_id"])
        ami = _one(ami_response.get("Images", []), self.outputs["synthetic_ami_id"])
        vpc_resp = self.aws.json("ec2", "describe-vpcs", "--vpc-ids", self.outputs["vpc_id"])
        vpc_raw = _one(vpc_resp.get("Vpcs", []), self.outputs["vpc_id"])
        peer_requester = self.aws.json(
            "ec2", "describe-vpc-peering-connections", "--filters",
            f"Name=requester-vpc-info.vpc-id,Values={self.outputs['vpc_id']}",
        ).get("VpcPeeringConnections", [])
        peer_accepter = self.aws.json(
            "ec2", "describe-vpc-peering-connections", "--filters",
            f"Name=accepter-vpc-info.vpc-id,Values={self.outputs['vpc_id']}",
        ).get("VpcPeeringConnections", [])
        tgw_attachments = self.aws.json(
            "ec2", "describe-transit-gateway-vpc-attachments", "--filters",
            f"Name=vpc-id,Values={self.outputs['vpc_id']}",
        ).get("TransitGatewayVpcAttachments", [])
        vpn_gateways = self.aws.json(
            "ec2", "describe-vpn-gateways", "--filters",
            f"Name=attachment.vpc-id,Values={self.outputs['vpc_id']}",
        ).get("VpnGateways", [])
        connectivity_attachments = [
            *[
                f"peering:{item.get('VpcPeeringConnectionId')}"
                for item in [*peer_requester, *peer_accepter]
                if item.get("Status", {}).get("Code") not in {"deleted", "rejected"}
            ],
            *[
                f"tgw:{item.get('TransitGatewayAttachmentId')}"
                for item in tgw_attachments
                if item.get("State") not in {"deleted", "rejected", "failed"}
            ],
            *[
                f"vgw:{item.get('VpnGatewayId')}"
                for item in vpn_gateways
                if any(
                    attachment.get("VpcId") == self.outputs["vpc_id"]
                    and attachment.get("State") != "detached"
                    for attachment in item.get("VpcAttachments", [])
                )
            ],
        ]
        dns_support = self.aws.json("ec2", "describe-vpc-attribute", "--vpc-id", self.outputs["vpc_id"], "--attribute", "enableDnsSupport")
        dns_hostnames = self.aws.json("ec2", "describe-vpc-attribute", "--vpc-id", self.outputs["vpc_id"], "--attribute", "enableDnsHostnames")
        instances, _ = self._describe_instances()
        all_instances_response = self.aws.json(
            "ec2", "describe-instances", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"]
        )
        all_instance_ids = sorted(
            instance.get("InstanceId", "")
            for reservation in all_instances_response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        )
        all_eni_response = self.aws.json(
            "ec2", "describe-network-interfaces", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"]
        )
        all_eni_ids = sorted(
            eni.get("NetworkInterfaceId", "") for eni in all_eni_response.get("NetworkInterfaces", [])
        )

        sg_resp = self.aws.json("ec2", "describe-security-groups", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"])
        security_groups = {}
        for group in sg_resp.get("SecurityGroups", []):
            gid = group.get("GroupId")
            security_groups[gid] = {
                "vpc_id": group.get("VpcId"),
                "run_id": next((tag.get("Value") for tag in group.get("Tags", []) if tag.get("Key") == "CanaryRunId"), None),
                "ingress": group.get("IpPermissions", []),
                "egress": group.get("IpPermissionsEgress", []),
            }
        sg_rule_resp = self.aws.json(
            "ec2", "describe-security-group-rules", "--filters",
            "Name=group-id,Values=" + ",".join(sorted(expected_security_groups(self.outputs))),
        )
        security_group_rules = sg_rule_resp.get("SecurityGroupRules", [])
        security_group_rule_run_tags = {
            item.get("SecurityGroupRuleId"): _tag_value({"Tags": item.get("Tags", [])})
            for item in security_group_rules
        }

        route_resp = self.aws.json("ec2", "describe-route-tables", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"])
        routes = {}
        route_views = {}
        route_tables = {}
        route_table_ids = {table.get("RouteTableId") for table in route_resp.get("RouteTables", [])}
        for route_table_id, target_kind, target_id in (
            (self.outputs["public_route_table_id"], "GatewayId", self.outputs["internet_gateway_id"]),
            (self.outputs["private_route_table_id"], "NetworkInterfaceId", self.outputs["web_eni_id"]),
        ):
            table = _one(route_resp.get("RouteTables", []), route_table_id)
            route_tables["public" if target_kind == "GatewayId" else "private"] = table
            route_views["public" if target_kind == "GatewayId" else "private"] = table.get("Routes", [])
            route = next((r for r in table.get("Routes", []) if r.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0"), {})
            routes["public" if target_kind == "GatewayId" else "private"] = {
                "destination": route.get("DestinationCidrBlock"),
                "target": route.get(target_kind),
                "state": route.get("State"),
            }
        default_table = _one(route_resp.get("RouteTables", []), self.outputs["default_route_table_id"])
        route_tables["default"] = default_table
        default_associations = default_table.get("Associations", [])
        default_route_view = {
            "id": default_table.get("RouteTableId"),
            "vpc_id": default_table.get("VpcId"),
            "run_id": _tag_value(default_table),
            "main_association": len(default_associations) == 1 and default_associations[0].get("Main") is True,
            "subnet_ids": sorted(a.get("SubnetId") for a in default_associations if not a.get("Main") and a.get("SubnetId")),
            "internet_default_routes": sorted(
                route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
                for route in default_table.get("Routes", [])
                if route.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0" or route.get("DestinationIpv6CidrBlock") == "::/0"
            ),
            "routes": default_table.get("Routes", []),
        }
        route_views["default"] = default_table.get("Routes", [])

        acl_resp = self.aws.json("ec2", "describe-network-acls", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"])
        acl_items = acl_resp.get("NetworkAcls", [])
        network_acl_ids = {acl.get("NetworkAclId") for acl in acl_items}
        network_acls = {}
        for name, acl_id in (
            ("web", self.outputs["web_network_acl_id"]),
            ("emr", self.outputs["emr_network_acl_id"]),
            ("default", self.outputs["default_network_acl_id"]),
        ):
            acl = _one(acl_items, acl_id)
            network_acls[name] = {
                "id": acl.get("NetworkAclId"),
                "vpc_id": acl.get("VpcId"),
                "run_id": _tag_value(acl),
                "subnet_ids": sorted(a.get("SubnetId") for a in acl.get("Associations", []) if a.get("SubnetId")),
                "entries": acl.get("Entries", []),
            }

        subnet_resp = self.aws.json("ec2", "describe-subnets", "--subnet-ids", self.outputs["public_subnet_id"], self.outputs["private_subnet_id"])
        subnets = {_one(subnet_resp.get("Subnets", []), sid).get("SubnetId"): _one(subnet_resp.get("Subnets", []), sid) for sid in (self.outputs["public_subnet_id"], self.outputs["private_subnet_id"])}
        all_subnets_response = self.aws.json(
            "ec2", "describe-subnets", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"]
        )
        all_subnet_ids = sorted(item.get("SubnetId", "") for item in all_subnets_response.get("Subnets", []))
        igw_resp = self.aws.json("ec2", "describe-internet-gateways", "--internet-gateway-ids", self.outputs["internet_gateway_id"])
        igw = _one(igw_resp.get("InternetGateways", []), self.outputs["internet_gateway_id"])

        ep_resp = self.aws.json("ec2", "describe-vpc-endpoints", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"])
        endpoints = {}
        for service, endpoint_id in self.outputs["ssm_endpoint_ids"].items():
            ep = _one(ep_resp.get("VpcEndpoints", []), endpoint_id)
            endpoints[service] = {
                "id": ep.get("VpcEndpointId"),
                "state": ep.get("State", "").lower(),
                "private_dns_enabled": ep.get("PrivateDnsEnabled"),
                "subnet_ids": sorted(ep.get("SubnetIds", [])),
                "security_group_ids": sorted(group.get("GroupId", "") for group in ep.get("Groups", [])),
                "network_interface_ids": sorted(ep.get("NetworkInterfaceIds", [])),
                "run_id": _tag_value(ep),
            }
        endpoint_eni_resp = self.aws.json(
            "ec2", "describe-network-interfaces", "--network-interface-ids",
            *[self.outputs["ssm_endpoint_eni_ids"][service] for service in sorted(self.outputs["ssm_endpoint_eni_ids"])],
        )
        endpoint_enis = {}
        for service, eni_id in self.outputs["ssm_endpoint_eni_ids"].items():
            eni = _one(endpoint_eni_resp.get("NetworkInterfaces", []), eni_id)
            endpoint_enis[service] = {
                "id": eni.get("NetworkInterfaceId"),
                "vpc_id": eni.get("VpcId"),
                "subnet_id": eni.get("SubnetId"),
                "security_group_ids": sorted(group.get("GroupId", "") for group in eni.get("Groups", [])),
                "requester_managed": eni.get("RequesterManaged"),
                "description": eni.get("Description"),
                "run_id": _tag_value(eni),
                "ipv6_addresses": eni.get("Ipv6Addresses", []),
            }

        associations_resp = self.aws.json("route53resolver", "list-firewall-rule-group-associations")
        associations = associations_resp.get("FirewallRuleGroupAssociations", [])
        matching_associations = [a for a in associations if a.get("VpcId") == self.outputs["vpc_id"]]
        association = next((a for a in matching_associations if a.get("FirewallRuleGroupId") == self.outputs["firewall_rule_group_id"]), {})
        foreign_group_associations = [
            a for a in associations
            if a.get("FirewallRuleGroupId") == self.outputs["firewall_rule_group_id"] and a.get("VpcId") != self.outputs["vpc_id"]
        ]
        resolver_associations = self.aws.json(
            "route53resolver", "list-resolver-rule-associations",
            "--filters", f"Name=VPC_ID,Values={self.outputs['vpc_id']}",
        ).get("ResolverRuleAssociations", [])
        rules_resp = self.aws.json("route53resolver", "list-firewall-rules", "--firewall-rule-group-id", self.outputs["firewall_rule_group_id"])
        rule_views = []
        for rule in rules_resp.get("FirewallRules", []):
            domain_id = rule.get("FirewallDomainListId")
            domain_resp = self.aws.json("route53resolver", "list-firewall-domains", "--firewall-domain-list-id", domain_id)
            domain_names = [d if isinstance(d, str) else d.get("Name", "") for d in domain_resp.get("Domains", [])]
            rule_views.append({
                "action": rule.get("Action"),
                "priority": rule.get("Priority"),
                "block_response": rule.get("BlockResponse"),
                "domains": sorted(domain_names),
            })
        firewall_config = self.aws.json("route53resolver", "get-firewall-config", "--resource-id", self.outputs["vpc_id"])
        config_payload = firewall_config.get("FirewallConfig", {})

        eip_resp = self.aws.json("ec2", "describe-addresses", "--allocation-ids", self.outputs["web_eip_allocation_id"])
        eip = _one(eip_resp.get("Addresses", []), self.outputs["web_eip_allocation_id"])
        profile_resp = self.aws.json("iam", "get-instance-profile", "--instance-profile-name", self.outputs["ssm_instance_profile_name"])
        profile = _validate_instance_profile_response(
            profile_resp, self.outputs["ssm_instance_profile_name"], self.outputs["ssm_role_name"],
        )
        policy_resp = self.aws.json(
            "iam", "get-role-policy", "--role-name", self.outputs["ssm_role_name"],
            "--policy-name", "synthetic-ssm-agent-minimum",
        )
        policy_document = policy_resp.get("PolicyDocument", {})
        if isinstance(policy_document, str):
            from urllib.parse import unquote
            try:
                policy_document = json.loads(unquote(policy_document))
            except json.JSONDecodeError:
                raise CanaryError("SSM_ROLE_POLICY_INVALID") from None
        role_policy_valid = validate_ssm_role_policy(
            policy_document,
            self.outputs,
            include_ec2messages="ec2messages" in self.outputs["ssm_endpoint_ids"],
        )
        role_resp = self.aws.json("iam", "get-role", "--role-name", self.outputs["ssm_role_name"])
        role = role_resp.get("Role", {})
        trust = role.get("AssumeRolePolicyDocument", {})
        trust_statements = trust.get("Statement", [])
        trust_valid = len(trust_statements) == 1 and trust_statements[0].get("Effect") == "Allow" and trust_statements[0].get("Action") == "sts:AssumeRole" and trust_statements[0].get("Principal", {}).get("Service") == "ec2.amazonaws.com"
        attached = self.aws.json("iam", "list-attached-role-policies", "--role-name", self.outputs["ssm_role_name"]).get("AttachedPolicies", [])
        inline = self.aws.json("iam", "list-role-policies", "--role-name", self.outputs["ssm_role_name"]).get("PolicyNames", [])
        role_policy_valid = role_policy_valid and trust_valid and not attached and inline == ["synthetic-ssm-agent-minimum"]

        partition = "aws"
        firewall_tag_ids = {
            "firewall_rule_group": ("firewall-rule-group", self.outputs["firewall_rule_group_id"]),
            "firewall_allow_list": ("firewall-domain-list", self.outputs["firewall_allow_domain_list_id"]),
            "firewall_block_list": ("firewall-domain-list", self.outputs["firewall_block_domain_list_id"]),
            "firewall_association": ("firewall-rule-group-association", self.outputs["firewall_association_id"]),
        }
        resource_run_tags = {
            "public_subnet": _tag_value(subnets[self.outputs["public_subnet_id"]]),
            "private_subnet": _tag_value(subnets[self.outputs["private_subnet_id"]]),
            "web_eni": instances["web"].get("eni_run_id"),
            "emr_eni": instances["emr"].get("eni_run_id"),
            "web_network_acl": network_acls["web"].get("run_id"),
            "emr_network_acl": network_acls["emr"].get("run_id"),
            "public_route_table": _tag_value(route_tables["public"]),
            "private_route_table": _tag_value(route_tables["private"]),
            "default_route_table": _tag_value(route_tables["default"]),
            "default_sg": security_groups.get(self.outputs["default_sg_id"], {}).get("run_id"),
            "default_network_acl": network_acls["default"].get("run_id"),
            "internet_gateway": _tag_value(igw),
            "eip": _tag_value(eip),
            "iam_role": _tag_value(role),
            "iam_instance_profile": _tag_value(profile),
        }
        for service, endpoint in endpoints.items():
            resource_run_tags[f"endpoint_{service}"] = endpoint.get("run_id")
            resource_run_tags[f"endpoint_eni_{service}"] = endpoint_enis[service].get("run_id")
        for name, (resource_type, resource_id) in firewall_tag_ids.items():
            arn = f"arn:{partition}:route53resolver:{self.outputs['region']}:{self.outputs['account_id']}:{resource_type}/{resource_id}"
            tags_response = self.aws.json("route53resolver", "list-tags-for-resource", "--resource-arn", arn)
            resource_run_tags[name] = _tag_value({"Tags": tags_response.get("Tags", [])})
        observed = {
            "account_id": caller.get("Account"),
            "region": self.outputs["region"],
            "vpc": {
                "id": vpc_raw.get("VpcId"),
                "cidr": vpc_raw.get("CidrBlock"),
                "dns_support": dns_support.get("EnableDnsSupport", {}).get("Value"),
                "dns_hostnames": dns_hostnames.get("EnableDnsHostnames", {}).get("Value"),
                "ipv6_associated": bool(vpc_raw.get("Ipv6CidrBlockAssociationSet")),
                "ipv4_cidrs": sorted(
                    association.get("CidrBlock")
                    for association in vpc_raw.get("CidrBlockAssociationSet", [])
                    if association.get("CidrBlockState", {}).get("State") == "associated"
                ),
                "run_id": _tag_value(vpc_raw),
            },
            "instances": instances,
            "ami": {
                "id": ami.get("ImageId"),
                "owner_id": ami.get("OwnerId"),
                "name": ami.get("Name"),
                "public": ami.get("Public"),
                "state": ami.get("State"),
                "architecture": ami.get("Architecture"),
                "virtualization_type": ami.get("VirtualizationType"),
                "root_device_type": ami.get("RootDeviceType"),
                "platform_details": ami.get("PlatformDetails"),
            },
            "instance_ids": all_instance_ids,
            "network_interface_ids": all_eni_ids,
            "subnet_ids": all_subnet_ids,
            "unexpected_connectivity_attachments": connectivity_attachments,
            "security_groups": security_groups,
            "security_group_rules": security_group_rules,
            "security_group_rule_run_tags": security_group_rule_run_tags,
            "public_route": routes.get("public"),
            "private_route": routes.get("private"),
            "resource_run_tags": resource_run_tags,
            "subnets": {
                "public": {"vpc_id": subnets[self.outputs["public_subnet_id"]].get("VpcId"), "cidr": subnets[self.outputs["public_subnet_id"]].get("CidrBlock"), "run_id": _tag_value(subnets[self.outputs["public_subnet_id"]]), "map_public_ip": subnets[self.outputs["public_subnet_id"]].get("MapPublicIpOnLaunch"), "ipv6_associated": bool(subnets[self.outputs["public_subnet_id"]].get("Ipv6CidrBlockAssociationSet"))},
                "private": {"vpc_id": subnets[self.outputs["private_subnet_id"]].get("VpcId"), "cidr": subnets[self.outputs["private_subnet_id"]].get("CidrBlock"), "run_id": _tag_value(subnets[self.outputs["private_subnet_id"]]), "map_public_ip": subnets[self.outputs["private_subnet_id"]].get("MapPublicIpOnLaunch"), "ipv6_associated": bool(subnets[self.outputs["private_subnet_id"]].get("Ipv6CidrBlockAssociationSet"))},
            },
            "internet_gateway_vpc_ids": _attached_internet_gateway_vpc_ids(igw),
            "endpoints": endpoints,
            "endpoint_enis": endpoint_enis,
            "firewall": {
                "vpc_id": association.get("VpcId"),
                "rule_group_id": association.get("FirewallRuleGroupId"),
                "association_status": association.get("Status"),
                "association_priority": association.get("Priority"),
                "mutation_protection": association.get("MutationProtection"),
                "fail_open": config_payload.get("FirewallFailOpen"),
                "rules": rule_views,
                "unexpected_associations": [a.get("FirewallRuleGroupId") for a in matching_associations if a.get("FirewallRuleGroupId") != self.outputs["firewall_rule_group_id"]],
                "foreign_group_associations": [a.get("VpcId") for a in foreign_group_associations],
            },
            "route_table_vpc_ids": {key: table.get("VpcId") for key, table in route_tables.items()},
            "route_table_associations": {
                key: sorted(a.get("SubnetId") for a in table.get("Associations", []) if not a.get("Main") and a.get("SubnetId"))
                for key, table in route_tables.items()
            },
            "route_table_ids": sorted(route_table_ids),
            "route_table_routes": route_views,
            "default_route_table": default_route_view,
            "network_acls": network_acls,
            "network_acl_ids": sorted(network_acl_ids),
            "custom_resolver_rule_association_count": len(_custom_resolver_associations(resolver_associations)),
            "eip": {"public_ip": eip.get("PublicIp"), "eni_id": eip.get("NetworkInterfaceId")},
            "ssm_role_policy_valid": role_policy_valid,
        }
        blocked = validate_snapshot(self.outputs, observed, after_web_start=after_web_start, during_cleanup=during_cleanup)
        if not role_policy_valid:
            blocked.append("SSM_ROLE_POLICY_CONTRACT_MISMATCH")
        return observed, blocked

    def _describe_state(self, instance_id: str) -> str:
        response = self.aws.json("ec2", "describe-instances", "--instance-ids", instance_id)
        items = [i for r in response.get("Reservations", []) for i in r.get("Instances", [])]
        return _one(items, instance_id).get("State", {}).get("Name", "unknown")

    def start_instance(self, instance_id: str) -> None:
        self.aws.json("ec2", "start-instances", "--instance-ids", instance_id)

    def stop_instance(self, instance_id: str) -> None:
        state = self._describe_state(instance_id)
        if state == "stopped":
            return
        if state not in {"running", "pending", "stopping"}:
            raise CanaryError("INSTANCE_STATE_NOT_SAFE_TO_STOP")
        self.aws.json("ec2", "stop-instances", "--instance-ids", instance_id)
        self.wait_instance_state(instance_id, "stopped", 180)

    def wait_instance_state(self, instance_id: str, desired: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._describe_state(instance_id) == desired:
                return
            time.sleep(3)
        raise CanaryError("INSTANCE_STATE_TIMEOUT")

    def wait_status_ok(self, instance_id: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.aws.json("ec2", "describe-instance-status", "--instance-ids", instance_id, "--include-all-instances")
            items = response.get("InstanceStatuses", [])
            if items and all(x.get("InstanceStatus", {}).get("Status") == "ok" and x.get("SystemStatus", {}).get("Status") == "ok" for x in items):
                return
            time.sleep(5)
        raise CanaryError("EC2_STATUS_CHECK_TIMEOUT")

    def wait_ssm(self, instance_id: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.aws.json(
                "ssm", "describe-instance-information",
                "--filters", f"Key=InstanceIds,Values={instance_id}",
            )
            items = response.get("InstanceInformationList", [])
            if any(x.get("InstanceId") == instance_id and x.get("PingStatus") == "Online" for x in items):
                return
            time.sleep(5)
        raise CanaryError("SSM_INSTANCE_OFFLINE_TIMEOUT")

    def send_shell(self, instance_id: str, script: str, timeout: int) -> str:
        payload = {
            "DocumentName": "AWS-RunShellScript",
            "InstanceIds": [instance_id],
            "Parameters": {"commands": [script]},
            "TimeoutSeconds": max(30, min(timeout, 600)),
        }
        response = self.aws.json("ssm", "send-command", payload=payload)
        command = response.get("Command", {})
        command_id = command.get("CommandId")
        if not command_id:
            raise CanaryError("SSM_COMMAND_ID_MISSING")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                invocation = self.aws.json("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance_id)
            except CanaryError as exc:
                if "InvocationDoesNotExist" in exc.reason_code:
                    time.sleep(2)
                    continue
                raise
            status = invocation.get("Status")
            if status == "Success":
                return str(invocation.get("StandardOutputContent", ""))
            if status in {"Cancelled", "TimedOut", "Failed", "Cancelling"}:
                raise CanaryError("SSM_GUEST_COMMAND_FAILED")
            time.sleep(3)
        raise CanaryError("SSM_GUEST_COMMAND_TIMEOUT")

    def inventory_run_id(self, run_id: str) -> list[str]:
        response = self.aws.json(
            "resourcegroupstaggingapi", "get-resources",
            "--tag-filters", f"Key=CanaryRunId,Values={run_id}",
        )
        return _tagged_resource_arns(response)

    def verify_cleanup_identity(self, run_id: str) -> None:
        current_outputs = normalize_outputs(self.aws_output(), run_id)
        if any(current_outputs.get(key) != self.outputs.get(key) for key in self.outputs):
            raise CanaryError("RUN_ID_STATE_MISMATCH")
        _, blockers = self.inspect(during_cleanup=True)
        if CLEANUP_IDENTITY_ERRORS.intersection(blockers):
            raise CanaryError("CLEANUP_RESOURCE_OWNERSHIP_UNVERIFIED")

    def destroy_stack(self, run_id: str, expected_vars_sha256: str) -> None:
        tfstate = TF_DIR / "terraform.tfstate.d" / run_id / "terraform.tfstate"
        tfvars = _terraform_vars_file(run_id)
        if not tfstate.is_file():
            raise CanaryError("TERRAFORM_STATE_OR_VARS_MISSING")
        if hashlib.sha256(tfvars.read_bytes()).hexdigest() != expected_vars_sha256:
            raise CanaryError("TERRAFORM_VARS_CHANGED_SINCE_APPROVAL")
        environment = _terraform_environment(run_id)
        try:
            state_result = subprocess.run(["terraform", "state", "list"], cwd=TF_DIR, env=environment, text=True, capture_output=True, timeout=30, check=False)
        except subprocess.TimeoutExpired:
            raise CanaryError("TERRAFORM_STATE_READ_TIMEOUT") from None
        except OSError:
            raise CanaryError("TERRAFORM_STATE_READ_EXEC_FAILED") from None
        if state_result.returncode:
            raise CanaryError("TERRAFORM_STATE_READ_FAILED")
        addresses = [line.strip() for line in state_result.stdout.splitlines() if line.strip()]
        if not addresses or any(not re.fullmatch(r"(?:data\.)?aws_[A-Za-z0-9_]+\.[A-Za-z0-9_]+(?:\[[^\n]+\])?", address) for address in addresses):
            raise CanaryError("TERRAFORM_STATE_CONTRACT_INVALID")
        self.verify_cleanup_identity(run_id)
        command = ["terraform", "destroy", "-auto-approve", "-input=false", "-var-file", tfvars.name]
        try:
            result = subprocess.run(command, cwd=TF_DIR, env=environment, text=True, capture_output=True, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise CanaryError("TERRAFORM_DESTROY_TIMEOUT") from None
        except OSError:
            raise CanaryError("TERRAFORM_DESTROY_EXEC_FAILED") from None
        if result.returncode:
            raise CanaryError("TERRAFORM_DESTROY_FAILED")
        self.verify_destroy_complete(run_id, environment)

    def verify_destroy_complete(self, run_id: str, environment: dict[str, str]) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                state_result = subprocess.run(
                    ["terraform", "state", "list"], cwd=TF_DIR, env=environment,
                    text=True, capture_output=True, timeout=20, check=False,
                )
            except subprocess.TimeoutExpired:
                raise CanaryError("TERRAFORM_POST_DESTROY_STATE_READ_TIMEOUT") from None
            except OSError:
                raise CanaryError("TERRAFORM_POST_DESTROY_STATE_READ_EXEC_FAILED") from None
            if state_result.returncode:
                raise CanaryError("TERRAFORM_POST_DESTROY_STATE_READ_FAILED")
            state_addresses = [line.strip() for line in state_result.stdout.splitlines() if line.strip()]
            inventory = self.inventory_run_id(run_id)
            try:
                vpc_response = self.aws.json("ec2", "describe-vpcs", "--vpc-ids", self.outputs["vpc_id"])
                vpc_remains = any(vpc.get("VpcId") == self.outputs["vpc_id"] for vpc in vpc_response.get("Vpcs", []))
            except CanaryError as exc:
                if "InvalidVpcIDNotFound" in exc.reason_code:
                    vpc_remains = False
                else:
                    raise
            endpoint_response = self.aws.json(
                "ec2", "describe-vpc-endpoints", "--filters", "Name=vpc-id,Values=" + self.outputs["vpc_id"]
            )
            endpoints_remain = bool(endpoint_response.get("VpcEndpoints", []))
            association_response = self.aws.json("route53resolver", "list-firewall-rule-group-associations")
            firewall_remains = any(
                item.get("VpcId") == self.outputs["vpc_id"]
                for item in association_response.get("FirewallRuleGroupAssociations", [])
            )
            eip_remains = False
            try:
                address_response = self.aws.json(
                    "ec2", "describe-addresses", "--allocation-ids", self.outputs["web_eip_allocation_id"]
                )
                eip_remains = any(
                    address.get("AllocationId") == self.outputs["web_eip_allocation_id"]
                    for address in address_response.get("Addresses", [])
                )
            except CanaryError as exc:
                if "InvalidAllocationIDNotFound" not in exc.reason_code:
                    raise
            volume_response = self.aws.json(
                "ec2", "describe-volumes", "--filters", f"Name=tag:CanaryRunId,Values={run_id}"
            )
            volumes_remain = bool(volume_response.get("Volumes", []))
            snapshot_response = self.aws.json(
                "ec2", "describe-snapshots", "--owner-ids", "self",
                "--filters", f"Name=tag:CanaryRunId,Values={run_id}",
            )
            snapshots_remain = bool(snapshot_response.get("Snapshots", []))
            if not (
                state_addresses or inventory or vpc_remains or endpoints_remain or firewall_remains
                or eip_remains or volumes_remain or snapshots_remain
            ):
                return
            time.sleep(5)
        raise CanaryError("CLEANUP_RESOURCES_REMAIN")

    def aws_output(self) -> dict[str, Any]:
        return AwsCli(self.outputs["region"]).output("terraform", "output", "-json", workspace=self.outputs["run_id"])


def _guest_identity_script(*, require_nat_tools: bool = False) -> str:
    nat_tools = "iptables iptables-save " if require_nat_tools else ""
    script = r'''set -eu
T=$(curl -fsS --connect-timeout 3 --max-time 6 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://AWS_PUBLIC_IP_REDACTED/latest/api/token)
M=http://IP_REDACTED/latest/meta-data
getm(){ curl -fsS --connect-timeout 3 --max-time 6 -H "X-aws-ec2-metadata-token: $T" "$M/$1"; }
IID=$(getm instance-id); IP=$(getm local-ipv4); MAC=$(getm mac)
VPC=$(getm "network/interfaces/macs/$MAC/vpc-id"); SUBNET=$(getm "network/interfaces/macs/$MAC/subnet-id"); ENI=$(getm "network/interfaces/macs/$MAC/interface-id")
printf 'INSTANCE_ID=%s\nPRIVATE_IP=%s\nVPC_ID=%s\nSUBNET_ID=%s\nENI_ID=%s\n' "$IID" "$IP" "$VPC" "$SUBNET" "$ENI"
printf 'IP_FORWARD=%s\n' "$(sysctl -n net.ipv4.ip_forward)"
printf 'UPLINK=%s\n' "$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
for svc in docker containerd cloudflared wg-quick@wg0 hospital-web.service hospital-emr.service; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then printf 'UNEXPECTED_SERVICE=%s\n' "$svc"; fi
done
if pgrep -x node >/dev/null 2>&1 || pgrep -x nodejs >/dev/null 2>&1; then echo UNEXPECTED_NODE_PROCESS=1; fi
if pgrep -x cloudflared >/dev/null 2>&1 || pgrep -x dockerd >/dev/null 2>&1 || pgrep -x containerd >/dev/null 2>&1; then echo UNEXPECTED_TUNNEL_OR_CONTAINER_PROCESS=1; fi
if command -v wg >/dev/null 2>&1 && [ -n "$(wg show interfaces 2>/dev/null)" ]; then echo WG_INTERFACE_ACTIVE=1; else echo WG_INTERFACE_ACTIVE=0; fi
for bin in curl __NAT_TOOLS__sysctl ip systemctl pgrep awk grep sha256sum getent; do command -v "$bin" >/dev/null 2>&1 || printf 'MISSING_TOOL=%s\n' "$bin"; done
'''
    return script.replace("__NAT_TOOLS__", nat_tools)


def _baseline_script() -> str:
    return r'''set -eu
command -v iptables >/dev/null 2>&1; command -v iptables-save >/dev/null 2>&1; command -v sysctl >/dev/null 2>&1
F=$(iptables -S FORWARD | sha256sum | awk '{print $1}')
N=$(iptables -t nat -S POSTROUTING | sha256sum | awk '{print $1}')
FR=$(iptables -S FORWARD | awk '$1=="-A"{n++} END{print n+0}')
NR=$(iptables -t nat -S POSTROUTING | awk '$1=="-A"{n++} END{print n+0}')
printf 'BASELINE_IP_FORWARD=%s\nBASELINE_FORWARD_SHA256=%s\nBASELINE_POSTROUTING_SHA256=%s\n' "$(sysctl -n net.ipv4.ip_forward)" "$F" "$N"
printf 'BASELINE_FORWARD_RULE_COUNT=%s\nBASELINE_POSTROUTING_RULE_COUNT=%s\n' "$FR" "$NR"
printf 'UPLINK=%s\n' "$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
'''


def _dns_firewall_test_script(outputs: dict[str, Any]) -> str:
    probe = shlex.quote(outputs["probe_domain"])
    probe_ip = shlex.quote(outputs["probe_ipv4"])
    ssm_domain = shlex.quote(f"ssm.{outputs['region']}.amazonaws.com")
    return f'''set -eu
getent ahostsv4 {ssm_domain} >/dev/null
getent ahostsv4 {probe} | awk '{{print $1}}' | grep -Fx {probe_ip} >/dev/null
if getent ahostsv4 example.com >/dev/null 2>&1; then
  echo DNS_FIREWALL_BLOCK_TEST=FAIL
  exit 1
fi
echo DNS_FIREWALL_BLOCK_TEST=PASS
'''


def _chain_names(run_id: str) -> tuple[str, str]:
    suffix = hashlib.sha256(run_id.encode("ascii")).hexdigest()[:8].upper()
    return f"SYNF{suffix}", f"SYNN{suffix}"


def _nat_apply_script(outputs: dict[str, Any], baseline: dict[str, str]) -> str:
    filter_chain, nat_chain = _chain_names(outputs["run_id"])
    uplink = baseline["UPLINK"]
    emr = outputs["emr_private_ip"]
    probe = outputs["probe_ipv4"]
    fhash = baseline["BASELINE_FORWARD_SHA256"]
    nhash = baseline["BASELINE_POSTROUTING_SHA256"]
    return f'''set -Eeuo pipefail
F={shlex.quote(filter_chain)}; N={shlex.quote(nat_chain)}; U={shlex.quote(uplink)}
EMR={shlex.quote(emr)}; PROBE={shlex.quote(probe)}
test "$(iptables -S FORWARD | sha256sum | awk '{{print $1}}')" = {shlex.quote(fhash)}
test "$(iptables -t nat -S POSTROUTING | sha256sum | awk '{{print $1}}')" = {shlex.quote(nhash)}
! iptables -S "$F" >/dev/null 2>&1; ! iptables -t nat -S "$N" >/dev/null 2>&1
! iptables -C FORWARD -j "$F" >/dev/null 2>&1; ! iptables -t nat -C POSTROUTING -j "$N" >/dev/null 2>&1
rollback_partial() {{
  if [ "$NH" = 1 ]; then iptables -t nat -D POSTROUTING -j "$N" >/dev/null 2>&1 || true; fi
  if [ "$FH" = 1 ]; then iptables -D FORWARD -j "$F" >/dev/null 2>&1 || true; fi
  if [ "$NC" = 1 ]; then iptables -t nat -F "$N" >/dev/null 2>&1 && iptables -t nat -X "$N" >/dev/null 2>&1 || true; fi
  if [ "$FC" = 1 ]; then iptables -F "$F" >/dev/null 2>&1 && iptables -X "$F" >/dev/null 2>&1 || true; fi
  if [ "$IP_CHANGED" = 1 ] && [ {shlex.quote(baseline['BASELINE_IP_FORWARD'])} = 0 ]; then sysctl -w net.ipv4.ip_forward=0 >/dev/null || true; fi
}}
FC=0; NC=0; FH=0; NH=0; IP_CHANGED=0
trap rollback_partial ERR
sysctl -w net.ipv4.ip_forward=1 >/dev/null
IP_CHANGED=1
iptables -N "$F"; FC=1
iptables -t nat -N "$N"; NC=1
iptables -A "$F" -d "$EMR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A "$F" -s "$EMR" -d "$PROBE" -o "$U" -p tcp --dport 443 -j ACCEPT
iptables -A "$F" -j DROP
iptables -t nat -A "$N" -s "$EMR" -d "$PROBE" -o "$U" -p tcp --dport 443 -j MASQUERADE
iptables -t nat -A "$N" -j RETURN
iptables -I FORWARD 1 -j "$F"; FH=1
iptables -t nat -I POSTROUTING 1 -j "$N"; NH=1
test "$(iptables -S "$F" | awk '$1==\"-A\"{{n++}} END{{print n+0}}')" = 3
test "$(iptables -t nat -S "$N" | awk '$1==\"-A\"{{n++}} END{{print n+0}}')" = 2
trap - ERR
echo NAT_APPLY=PASS
'''


def _nat_restore_script(outputs: dict[str, Any], baseline: dict[str, str]) -> str:
    filter_chain, nat_chain = _chain_names(outputs["run_id"])
    original_ip_forward = baseline["BASELINE_IP_FORWARD"]
    uplink = baseline["UPLINK"]
    emr = outputs["emr_private_ip"]
    probe = outputs["probe_ipv4"]
    fhash = baseline["BASELINE_FORWARD_SHA256"]
    nhash = baseline["BASELINE_POSTROUTING_SHA256"]
    return f'''set -Eeuo pipefail
F={shlex.quote(filter_chain)}; N={shlex.quote(nat_chain)}; U={shlex.quote(uplink)}
EMR={shlex.quote(emr)}; PROBE={shlex.quote(probe)}
if iptables -S "$F" >/dev/null 2>&1; then
  test "$(iptables -S "$F" | awk '$1==\"-A\"{{n++}} END{{print n+0}}')" = 3
  iptables -C "$F" -d "$EMR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -C "$F" -s "$EMR" -d "$PROBE" -o "$U" -p tcp --dport 443 -j ACCEPT
  iptables -C "$F" -j DROP
  test "$(iptables -S FORWARD | grep -Fc -- \"-A FORWARD -j $F\")" = 1
  iptables -D FORWARD -j "$F"
  iptables -F "$F"; iptables -X "$F"
else
  ! iptables -C FORWARD -j "$F" >/dev/null 2>&1
fi
if iptables -t nat -S "$N" >/dev/null 2>&1; then
  test "$(iptables -t nat -S "$N" | awk '$1==\"-A\"{{n++}} END{{print n+0}}')" = 2
  iptables -t nat -C "$N" -s "$EMR" -d "$PROBE" -o "$U" -p tcp --dport 443 -j MASQUERADE
  iptables -t nat -C "$N" -j RETURN
  test "$(iptables -t nat -S POSTROUTING | grep -Fc -- \"-A POSTROUTING -j $N\")" = 1
  iptables -t nat -D POSTROUTING -j "$N"
  iptables -t nat -F "$N"; iptables -t nat -X "$N"
else
  ! iptables -t nat -C POSTROUTING -j "$N" >/dev/null 2>&1
fi
test "$(iptables -S FORWARD | sha256sum | awk '{{print $1}}')" = {shlex.quote(fhash)}
test "$(iptables -t nat -S POSTROUTING | sha256sum | awk '{{print $1}}')" = {shlex.quote(nhash)}
CURRENT=$(sysctl -n net.ipv4.ip_forward)
if [ {shlex.quote(original_ip_forward)} = 0 ]; then
  if [ "$CURRENT" = 1 ]; then
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
  elif [ "$CURRENT" != 0 ]; then
    exit 1
  fi
else
  test "$CURRENT" = 1
fi
echo NAT_BASELINE_RESTORE=PASS
'''


class RunState:
    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "schema_version": 1,
            "run_id": run_id,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "status": "INITIALIZED",
            "phase": "INITIALIZED",
            "synthetic_only": True,
            "real_failover": "NOT_TOUCHED",
            "outputs": {},
            "baseline": {},
            "web_start_attempted": False,
            "emr_start_attempted": False,
            "web_started": False,
            "emr_started": False,
            "nat_apply_attempted": False,
            "nat_restored": False,
            "events": [],
        }

    def load(self) -> None:
        try:
            stat = self.path.lstat()
            if not self.path.is_file() or self.path.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                raise CanaryError("STATE_FILE_PERMISSIONS_INVALID")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise CanaryError("STATE_FILE_MISSING") from None
        except json.JSONDecodeError:
            raise CanaryError("STATE_FILE_INVALID") from None
        if not isinstance(payload, dict) or payload.get("run_id") != self.data["run_id"] or payload.get("synthetic_only") is not True:
            raise CanaryError("STATE_FILE_IDENTITY_MISMATCH")
        if any(key in payload for key in PRODUCTION_STATE_KEYS):
            raise CanaryError("STATE_FILE_CONTAINS_PRODUCTION_STATE")
        self.data = payload

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self.data["updated_at"] = utc_now()
        fd, name = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, sort_keys=True, indent=2)
                stream.write("\n")
            os.replace(name, self.path)
            os.chmod(self.path, 0o600)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    def event(self, phase: str, status: str, reason: str | None = None) -> None:
        self.data["phase"] = phase
        item = {"at": utc_now(), "phase": phase, "status": status, "reason_code": reason}
        self.data["events"].append(item)
        self.data["status"] = status
        self.save()
        _write_event_log(self.path.with_suffix(".jsonl"), item)
        detail = f" reason={reason}" if reason else ""
        print(f"SYNTHETIC_CANARY phase={phase} status={status}{detail}", file=sys.stderr, flush=True)


class ExecutionLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stream: Any = None

    def __enter__(self) -> "ExecutionLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self.stream = self.path.open("a+")
        os.chmod(self.path, 0o600)
        try:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.stream.close()
            raise CanaryError("RUN_ID_ALREADY_LOCKED") from None
        return self

    def __exit__(self, *_: Any) -> None:
        if self.stream:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()


class CanaryTransaction:
    def __init__(self, outputs: dict[str, Any], ops: Any, state: RunState, deadline: float) -> None:
        self.outputs, self.ops, self.state, self.deadline = outputs, ops, state, deadline

    def _remaining(self, maximum: int) -> int:
        remaining = int(self.deadline - time.monotonic())
        if remaining <= 0:
            raise CanaryError("CANARY_TOTAL_TIMEOUT")
        return max(1, min(maximum, remaining))

    def run(self) -> None:
        self.state.data["outputs"] = self.outputs
        _, blocked = self.ops.inspect()
        if blocked:
            self.state.data["checks"] = blocked
            raise CanaryError("PREFLIGHT_BLOCKED")
        self.state.data["isolation_verified"] = True
        self.state.save()
        self.state.event("ISOLATION_AND_DNS_SG_VALIDATED", "PASS")
        web, emr = self.outputs["web_instance_id"], self.outputs["emr_instance_id"]
        self.state.data["web_start_attempted"] = True
        self.state.save()
        self.state.event("WEB_START_REQUESTED", "IN_PROGRESS")
        self.ops.start_instance(web)
        self.state.data["web_started"] = True
        self.state.event("WEB_START_API_ACCEPTED", "PASS")
        self.ops.wait_instance_state(web, "running", self._remaining(180))
        self.ops.wait_status_ok(web, self._remaining(240))
        self.ops.wait_ssm(web, self._remaining(240))
        self.state.event("WEB_SSM_ONLINE", "PASS")
        identity = self.ops.send_shell(web, _guest_identity_script(require_nat_tools=True), self._remaining(60))
        self._validate_guest_identity(identity, "web")
        if (
            "UNEXPECTED_SERVICE=" in identity or "WG_INTERFACE_ACTIVE=1" in identity
            or "MISSING_TOOL=" in identity or "UNEXPECTED_NODE_PROCESS=1" in identity
            or "UNEXPECTED_TUNNEL_OR_CONTAINER_PROCESS=1" in identity
        ):
            raise CanaryError("SYNTHETIC_WEB_IMAGE_NOT_CLEAN")
        dns_result = self.ops.send_shell(web, _dns_firewall_test_script(self.outputs), self._remaining(45))
        if "DNS_FIREWALL_BLOCK_TEST=PASS" not in dns_result:
            raise CanaryError("WEB_DNS_FIREWALL_TEST_FAILED")
        self.state.event("WEB_DNS_FIREWALL_TEST", "PASS")
        baseline_output = self.ops.send_shell(web, _baseline_script(), self._remaining(60))
        baseline = _parse_key_values(baseline_output)
        for field in ("BASELINE_IP_FORWARD", "BASELINE_FORWARD_SHA256", "BASELINE_POSTROUTING_SHA256", "BASELINE_FORWARD_RULE_COUNT", "BASELINE_POSTROUTING_RULE_COUNT", "UPLINK"):
            if field not in baseline:
                raise CanaryError("NAT_BASELINE_INCOMPLETE")
        if baseline["BASELINE_IP_FORWARD"] not in {"0", "1"} or baseline["BASELINE_FORWARD_RULE_COUNT"] != "0" or baseline["BASELINE_POSTROUTING_RULE_COUNT"] != "0":
            raise CanaryError("NAT_BASELINE_NOT_CLEAN")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", baseline["UPLINK"]):
            raise CanaryError("NAT_UPLINK_INVALID")
        self.state.data["baseline"] = baseline
        self.state.save()
        self.state.event("NAT_BASELINE_CAPTURED", "PASS")
        self.state.data["nat_apply_attempted"] = True
        self.state.save()
        self.state.event("NAT_APPLY", "IN_PROGRESS")
        apply_result = self.ops.send_shell(web, _nat_apply_script(self.outputs, baseline), self._remaining(90))
        if "NAT_APPLY=PASS" not in apply_result:
            raise CanaryError("NAT_ROLE_APPLY_FAILED")
        self.state.event("NAT_APPLIED", "PASS")
        _, blocked_after_web = self.ops.inspect(after_web_start=True)
        if blocked_after_web:
            self.state.data["checks"] = blocked_after_web
            raise CanaryError("POST_WEB_ROUTE_OR_ISOLATION_BLOCKED")
        self.state.data["emr_start_attempted"] = True
        self.state.save()
        self.state.event("EMR_START_REQUESTED", "IN_PROGRESS")
        self.ops.start_instance(emr)
        self.state.data["emr_started"] = True
        self.state.event("EMR_START_API_ACCEPTED", "PASS")
        self.ops.wait_instance_state(emr, "running", self._remaining(180))
        self.ops.wait_status_ok(emr, self._remaining(240))
        self.ops.wait_ssm(emr, self._remaining(240))
        self.state.event("EMR_SSM_ONLINE", "PASS")
        identity = self.ops.send_shell(emr, _guest_identity_script(require_nat_tools=False), self._remaining(60))
        self._validate_guest_identity(identity, "emr")
        if (
            "UNEXPECTED_SERVICE=" in identity or "WG_INTERFACE_ACTIVE=1" in identity
            or "MISSING_TOOL=" in identity or "UNEXPECTED_NODE_PROCESS=1" in identity
            or "UNEXPECTED_TUNNEL_OR_CONTAINER_PROCESS=1" in identity
        ):
            raise CanaryError("SYNTHETIC_EMR_IMAGE_NOT_CLEAN")
        dns_result = self.ops.send_shell(emr, _dns_firewall_test_script(self.outputs), self._remaining(45))
        if "DNS_FIREWALL_BLOCK_TEST=PASS" not in dns_result:
            raise CanaryError("EMR_DNS_FIREWALL_TEST_FAILED")
        self.state.event("EMR_DNS_FIREWALL_TEST", "PASS")
        probe = self._probe_script()
        response = self.ops.send_shell(emr, probe, self._remaining(45))
        if f"PROBE_EGRESS_IP={self.outputs['web_eip']}" not in response:
            raise CanaryError("PROBE_EGRESS_IP_MISMATCH")
        self.state.event("EMR_EGRESS_MATCHED_WEB_EIP", "PASS")
        self.state.data["result"] = "SYNTHETIC_NAT_CANARY_PASS"
        self.state.event("SYNTHETIC_NAT_CANARY_PASS", "PASS")

    def _validate_guest_identity(self, result: str, host: str) -> None:
        values = _parse_key_values(result)
        expected = {
            "web": (self.outputs["web_instance_id"], self.outputs["web_private_ip"], self.outputs["vpc_id"], self.outputs["public_subnet_id"], self.outputs["web_eni_id"]),
            "emr": (self.outputs["emr_instance_id"], self.outputs["emr_private_ip"], self.outputs["vpc_id"], self.outputs["private_subnet_id"], self.outputs["emr_eni_id"]),
        }[host]
        actual = tuple(values.get(key) for key in ("INSTANCE_ID", "PRIVATE_IP", "VPC_ID", "SUBNET_ID", "ENI_ID"))
        if actual != expected:
            raise CanaryError(f"{host.upper()}_GUEST_IDENTITY_MISMATCH")

    def _probe_script(self) -> str:
        host = self.outputs["probe_domain"]
        ip = self.outputs["probe_ipv4"]
        return (
            "set -eu\n"
            "command -v python3 >/dev/null 2>&1 || { echo PROBE_JSON_PARSER_MISSING; exit 1; }\n"
            f"BODY=$(curl -4fsS --connect-timeout 5 --max-time 12 --resolve {shlex.quote(host + ':443:' + ip)} "
            f"https://{shlex.quote(host)}/v1/source-ip)\n"
            "SOURCE_IP=$(printf '%s' \"$BODY\" | python3 -c 'import ipaddress,json,sys; data=json.load(sys.stdin); assert set(data)=={\"source_ipv4\"}; addr=ipaddress.ip_address(data[\"source_ipv4\"]); assert addr.version==4; print(addr)')\n"
            "printf 'PROBE_EGRESS_IP=%s\\n' \"$SOURCE_IP\"\n"
        )


def _parse_key_values(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if re.fullmatch(r"[A-Z0-9_]+", key):
                result[key] = value.strip()
    return result


def _write_event_log(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(item, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def _state_path(state_dir: Path, run_id: str) -> Path:
    return state_dir / f"{safe_run_id(run_id)}.json"


def _terraform_vars_file(run_id: str) -> Path:
    path = TF_DIR / f"terraform.{safe_run_id(run_id)}.tfvars"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise CanaryError("TERRAFORM_VARS_MISSING") from None
    if not path.is_file() or path.is_symlink() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise CanaryError("TERRAFORM_VARS_PERMISSIONS_INVALID")
    return path


def _assert_state_binding(state: RunState, outputs: dict[str, Any]) -> None:
    saved_raw = state.data.get("outputs")
    if not isinstance(saved_raw, dict):
        raise CanaryError("STATE_OUTPUT_BINDING_MISSING")
    saved = normalize_outputs(saved_raw, state.data.get("run_id"))
    if any(saved.get(key) != outputs.get(key) for key in outputs):
        raise CanaryError("STATE_OUTPUT_BINDING_MISMATCH")


def _restore_guest_and_stop(outputs: dict[str, Any], state: RunState, ops: AwsOperations) -> list[str]:
    failures: list[str] = []
    # EMR first; the Web host must remain up while its transient NAT baseline is restored.
    if state.data.get("emr_start_attempted") or state.data.get("emr_started"):
        try:
            ops.stop_instance(outputs["emr_instance_id"])
            state.data["emr_started"] = False
            state.data["emr_start_attempted"] = False
            state.event("EMR_STOPPED", "PASS")
        except CanaryError as exc:
            failures.append(exc.reason_code)
    baseline = state.data.get("baseline") or {}
    if state.data.get("nat_apply_attempted") and baseline and not state.data.get("nat_restored"):
        try:
            current = ops._describe_state(outputs["web_instance_id"])
            if current == "stopping":
                ops.wait_instance_state(outputs["web_instance_id"], "stopped", 120)
                current = "stopped"
            if current == "stopped":
                state.event("RESTORE_WEB_START", "IN_PROGRESS")
                ops.start_instance(outputs["web_instance_id"])
                ops.wait_instance_state(outputs["web_instance_id"], "running", 180)
                ops.wait_status_ok(outputs["web_instance_id"], 180)
                ops.wait_ssm(outputs["web_instance_id"], 180)
                current = "running"
            elif current == "pending":
                ops.wait_instance_state(outputs["web_instance_id"], "running", 180)
                ops.wait_status_ok(outputs["web_instance_id"], 180)
                ops.wait_ssm(outputs["web_instance_id"], 180)
                current = "running"
            if current != "running":
                raise CanaryError("WEB_NOT_RUNNING_FOR_NAT_RESTORE")
            result = ops.send_shell(outputs["web_instance_id"], _nat_restore_script(outputs, baseline), 90)
            if "NAT_BASELINE_RESTORE=PASS" not in result:
                raise CanaryError("NAT_BASELINE_RESTORE_FAILED")
            state.data["nat_restored"] = True
            state.event("NAT_BASELINE_RESTORED", "PASS")
        except CanaryError as exc:
            failures.append(exc.reason_code)
    if state.data.get("web_start_attempted") or state.data.get("web_started"):
        try:
            ops.stop_instance(outputs["web_instance_id"])
            state.data["web_started"] = False
            state.data["web_start_attempted"] = False
            state.event("WEB_STOPPED", "PASS")
        except CanaryError as exc:
            failures.append(exc.reason_code)
    return failures


def execute_transaction(
    outputs: dict[str, Any],
    ops: Any,
    state: RunState,
    deadline: float,
    *,
    preserve_stack: bool = False,
) -> dict[str, Any]:
    failure: str | None = None
    transaction = CanaryTransaction(outputs, ops, state, deadline)
    try:
        transaction.run()
    except (CanaryError, KeyboardInterrupt) as exc:
        failure = exc.reason_code if isinstance(exc, CanaryError) else "INTERRUPTED"
        state.event(state.data.get("phase", "UNKNOWN"), "BLOCKED", failure)
    except Exception as exc:
        failure = f"UNEXPECTED_{type(exc).__name__}"
        state.event(state.data.get("phase", "UNKNOWN"), "BLOCKED", failure)

    restore_failures: list[str] = []
    # Before the isolation contract is read back, no EC2 state is touched and
    # no cleanup is attempted against a potentially mismatched stack.
    if state.data.get("isolation_verified") is True:
        restore_failures = _restore_guest_and_stop(outputs, state, ops)
        state.data["restore_failures"] = restore_failures
        if restore_failures:
            state.event("RESTORE", "BLOCKED", "RESTORE_INCOMPLETE")
        else:
            state.event("RESTORE", "PASS")
        if preserve_stack:
            state.event("STACK_PRESERVED", "PASS", "EXPLICIT_PRESERVE_STACK")
        else:
            try:
                ops.destroy_stack(state.data["run_id"], state.data.get("terraform_vars_sha256", ""))
                state.event("STACK_DESTROY", "PASS")
            except Exception as exc:
                reason = exc.reason_code if isinstance(exc, CanaryError) else f"UNEXPECTED_{type(exc).__name__}"
                restore_failures.append(reason)
                try:
                    state.data["inventory_after_cleanup_failure"] = ops.inventory_run_id(state.data["run_id"])
                except Exception:
                    state.data["inventory_after_cleanup_failure"] = "UNAVAILABLE"
                state.event("STACK_DESTROY", "BLOCKED", reason)
    elif isinstance(state.data.get("outputs"), dict) and state.data.get("outputs"):
        # A failed policy preflight may still leave billable, stopped synthetic
        # resources from Terraform provisioning. Destroy only after an
        # independent ownership readback and only while both instances remain
        # stopped; never terminate an unexpected running host automatically.
        if preserve_stack:
            state.event("PREFLIGHT_STACK_PRESERVED", "PASS", "EXPLICIT_PRESERVE_STACK")
        else:
            try:
                ops.verify_cleanup_identity(state.data["run_id"])
                instance_states = [
                    ops._describe_state(outputs["web_instance_id"]),
                    ops._describe_state(outputs["emr_instance_id"]),
                ]
                if instance_states != ["stopped", "stopped"]:
                    raise CanaryError("PREFLIGHT_CLEANUP_INSTANCE_NOT_STOPPED")
                ops.destroy_stack(state.data["run_id"], state.data.get("terraform_vars_sha256", ""))
                state.event("PREFLIGHT_STACK_DESTROY", "PASS")
            except Exception as exc:
                reason = exc.reason_code if isinstance(exc, CanaryError) else f"UNEXPECTED_{type(exc).__name__}"
                restore_failures.append(reason)
                try:
                    state.data["inventory_after_cleanup_failure"] = ops.inventory_run_id(state.data["run_id"])
                except Exception:
                    state.data["inventory_after_cleanup_failure"] = "UNAVAILABLE"
                state.event("PREFLIGHT_STACK_DESTROY", "BLOCKED", reason)

    final = "PASS" if state.data.get("result") == "SYNTHETIC_NAT_CANARY_PASS" and not failure and not restore_failures else "BLOCKED"
    state.data["status"] = final
    state.data["phase"] = "COMPLETE" if final == "PASS" else "BLOCKED"
    state.data["reason_code"] = failure or (restore_failures[0] if restore_failures else None)
    state.save()
    return _report(
        final,
        state.data["phase"],
        state.data["reason_code"],
        result=state.data.get("result"),
        checks=state.data.get("checks", []),
        state_file=str(state.path),
        stack_destroyed=any(e.get("phase") in {"STACK_DESTROY", "PREFLIGHT_STACK_DESTROY"} and e.get("status") == "PASS" for e in state.data.get("events", [])),
        stack_preserved=preserve_stack,
    )


def _default_json_outputs(ops: AwsOperations) -> dict[str, Any]:
    return ops.aws_output()


def _report(status: str, phase: str, reason: str | None = None, **fields: Any) -> dict[str, Any]:
    return {"status": status, "phase": phase, "reason_code": reason, "synthetic_only": True, **fields}


def _inventory(ops: AwsOperations, run_id: str) -> dict[str, Any]:
    arns = ops.inventory_run_id(run_id)
    return _report("READ_ONLY", "RUN_ID_INVENTORY", resource_count=len(arns), resource_arns=arns)


def run_cli(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = Path(args.state_dir).expanduser()
    if not any((args.aws_read_only, args.run, args.restore, args.cleanup, args.inventory_run_id)):
        return _report("NO_CHANGE", "DEFAULT")
    run_id = safe_run_id(args.run_id or "")
    if args.inventory_run_id:
        # The inventory path intentionally needs only region/account credentials, not Terraform state.
        aws = AwsCli(args.region)
        response = aws.json(
            "resourcegroupstaggingapi", "get-resources",
            "--tag-filters", f"Key=CanaryRunId,Values={run_id}",
        )
        arns = _tagged_resource_arns(response)
        return _report("READ_ONLY", "RUN_ID_INVENTORY", resource_count=len(arns), resource_arns=arns)

    raw = AwsCli(args.region).output("terraform", "output", "-json", workspace=run_id)
    outputs = normalize_outputs(raw, run_id)
    state = RunState(_state_path(state_dir, run_id), run_id)
    ops = AwsOperations(outputs, state_dir)

    if args.aws_read_only:
        observed, blocked = ops.inspect()
        return _report("BLOCKED" if blocked else "PENDING_STOPPED_SSM", "READ_ONLY_PREFLIGHT", "PREFLIGHT_BLOCKED" if blocked else None, checks=blocked, expected_run_id=run_id, live_instance_states={k: v.get("state") for k, v in observed.get("instances", {}).items()}, dns_firewall_association=observed.get("firewall", {}).get("association_status"))

    if args.run:
        if not args.preserve_stack:
            raise CanaryError("RUN_PRESERVE_STACK_REQUIRED")
        if args.confirm_run_id != run_id or not args.confirm_synthetic_network_cost:
            raise CanaryError("RUN_CONFIRMATION_REQUIRED")
        probe_run_id = safe_run_id(args.probe_run_id or "")
        if probe_run_id == run_id:
            raise CanaryError("PROBE_AND_CANARY_RUN_IDS_MUST_DIFFER")
        probe_workspace = _terraform_workspace(args.probe_workspace or probe_run_id)
        probe_raw = AwsCli(args.region).output("terraform", "output", "-json", workspace=probe_workspace, cwd=PROBE_TF_DIR)
        probe = {key: _value(probe_raw, key) for key in probe_raw}
        required_probe = {
            "account_id", "region", "run_id", "probe_eip", "probe_domain",
            "allowed_web_eip_ipv4", "probe_sg_ingress_enabled",
            "synthetic_ami_id", "synthetic_ami_owner_id",
        }
        if required_probe - probe.keys() or probe.get("run_id") != probe_run_id:
            raise CanaryError("PROBE_STACK_OUTPUT_INVALID")
        if probe.get("account_id") != outputs["account_id"] or probe.get("region") != outputs["region"]:
            raise CanaryError("PROBE_STACK_ACCOUNT_OR_REGION_MISMATCH")
        if probe.get("probe_eip") != outputs["probe_ipv4"]:
            raise CanaryError("PROBE_STACK_IP_MISMATCH")
        if (
            probe.get("synthetic_ami_id") != outputs["synthetic_ami_id"]
            or probe.get("synthetic_ami_id") != APPROVED_AMI_ID
            or probe.get("synthetic_ami_owner_id") != AMAZON_LINUX_OWNER_ID
        ):
            raise CanaryError("PROBE_STACK_AMI_MISMATCH")
        if str(probe.get("probe_domain", "")).lower() != str(outputs["probe_domain"]).lower():
            raise CanaryError("PROBE_STACK_DOMAIN_MISMATCH")
        if probe.get("allowed_web_eip_ipv4") != f"{outputs['web_eip']}/32" or not probe.get("probe_sg_ingress_enabled"):
            raise CanaryError("PROBE_STACK_WEB_EIP_BINDING_MISMATCH")
        if state.path.exists():
            raise CanaryError("RUN_STATE_ALREADY_EXISTS")
        with ExecutionLock(state_dir / "runner.lock"), ExecutionLock(state_dir / f"{run_id}.lock"):
            tfvars = _terraform_vars_file(run_id)
            # Bind the resource identity before the first state write so an
            # interruption in the narrow pre-transaction window is diagnosable.
            state.data["outputs"] = outputs
            state.data["terraform_vars_sha256"] = hashlib.sha256(tfvars.read_bytes()).hexdigest()
            state.save()
            deadline = time.monotonic() + MAX_RUN_SECONDS
            report = execute_transaction(outputs, ops, state, deadline, preserve_stack=True)
            _write_event_log(state_dir / f"{run_id}.jsonl", {"at": utc_now(), "event": "FINAL", "status": report["status"], "reason_code": report.get("reason_code")})
            return report

    if args.restore:
        if args.confirm_run_id != run_id:
            raise CanaryError("RESTORE_CONFIRMATION_REQUIRED")
        with ExecutionLock(state_dir / "runner.lock"), ExecutionLock(state_dir / f"{run_id}.lock"):
            state.load()
            _assert_state_binding(state, outputs)
            ops.verify_cleanup_identity(run_id)
            failures = _restore_guest_and_stop(outputs, state, ops)
            state.event("RESTORE", "BLOCKED" if failures else "PASS", failures[0] if failures else None)
            return _report("BLOCKED" if failures else "PASS", "RESTORE", failures[0] if failures else None, state_file=str(state.path), failures=failures)

    if args.cleanup:
        if args.confirm_run_id != run_id:
            raise CanaryError("CLEANUP_CONFIRMATION_REQUIRED")
        with ExecutionLock(state_dir / "runner.lock"), ExecutionLock(state_dir / f"{run_id}.lock"):
            try:
                state.load()
                _assert_state_binding(state, outputs)
                ops.verify_cleanup_identity(run_id)
                failures = _restore_guest_and_stop(outputs, state, ops)
            except CanaryError as exc:
                if exc.reason_code == "STATE_FILE_MISSING":
                    return _report("BLOCKED", "CLEANUP", "STATE_FILE_MISSING_USE_INVENTORY")
                raise
            if failures:
                raise CanaryError("RESTORE_INCOMPLETE")
            ops.destroy_stack(run_id, state.data.get("terraform_vars_sha256", ""))
            state.event("STACK_DESTROY", "PASS")
            return _report("PASS", "CLEANUP", state_file=str(state.path))
    return _report("NO_CHANGE", "DEFAULT")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--run-id")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--aws-read-only", action="store_true")
    group.add_argument("--run", action="store_true")
    group.add_argument("--restore", action="store_true")
    group.add_argument("--cleanup", action="store_true")
    group.add_argument("--inventory-run-id", action="store_true")
    parser.add_argument("--confirm-run-id")
    parser.add_argument("--confirm-synthetic-network-cost", action="store_true")
    parser.add_argument(
        "--preserve-stack",
        action="store_true",
        help="Keep the Terraform stack after the guest restore/stop transaction; required for --run.",
    )
    parser.add_argument("--probe-run-id", help="Separate Probe stack Run ID; mandatory for --run.")
    parser.add_argument(
        "--probe-workspace",
        help="Explicit Probe Terraform workspace (defaults to --probe-run-id; use 'default' only when its state is there).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    args = build_parser().parse_args(argv)
    try:
        report = run_cli(args)
        print(json.dumps(report, sort_keys=True))
        return 0 if report.get("status") in {"PASS", "NO_CHANGE", "PENDING_STOPPED_SSM", "READ_ONLY"} else 1
    except CanaryError as exc:
        print(json.dumps(_report("BLOCKED", "EXECUTION", exc.reason_code), sort_keys=True))
        return 1
    except KeyboardInterrupt:
        print(json.dumps(_report("BLOCKED", "INTERRUPTED", "INTERRUPTED"), sort_keys=True))
        return 130
    except Exception as exc:  # Redact details; never dump subprocess/env data.
        print(json.dumps(_report("BLOCKED", "UNEXPECTED", type(exc).__name__), sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
