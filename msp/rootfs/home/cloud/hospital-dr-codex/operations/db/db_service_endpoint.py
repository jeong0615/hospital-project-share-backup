#!/usr/bin/env python3
"""Resolve and validate the application DB endpoint independently of SSH aliases.

The default service target is the existing AWS DR MySQL instance. An isolated
Dump-validation instance is accepted only when its explicit AWS identity and
private subnet are confirmed with read-only Describe API calls.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from operations.db.isolated_restore_host import (  # noqa: E402
    PRODUCTION_DB_INSTANCE_ID,
    PROTECTED_PRIVATE_IPS,
)
from operations.db.isolated_dump_restore import (  # noqa: E402
    DOC_NAME,
    DOC_PRIVATE_IP,
    ISOLATED_SERVICE_PORT,
    WEB_NAME,
    WEB_PRIVATE_IP,
    _sg_port_is_only_from_groups,
)

DEFAULT_DB_HOST = "IP_REDACTED"
DEFAULT_DB_PORT = 3306
ISOLATED_INSTANCE_NAME = "Hospital-DR-Dump-Restore-Isolated"
ISOLATED_INSTANCE_ROLE = "isolated-dump-restore-validation"
ISOLATED_SUBNET_NAME = "Hospital-DR-Private-DB-Subnet"
ISOLATED_SECURITY_GROUP_NAME = "hospital-dr-dump-restore-isolated-sg"
ISOLATED_SERVICE_SECURITY_GROUP_NAME = "hospital-dr-dump-restore-service-sg"
WEB_SECURITY_GROUP_NAME = "hospital-dr-web-sg"
DOC_SECURITY_GROUP_NAME = "hospital-dr-doc-sg"
APP_PORT_VARIABLES = {"web": "WEB_DB_PORT", "emr": "DOC_DB_PORT"}


class EndpointError(ValueError):
    """A safe, non-secret database endpoint validation failure."""


def _one_instance(response: dict) -> dict:
    if not isinstance(response, dict):
        raise EndpointError("ISOLATED_AWS_RESPONSE_INVALID")
    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    if len(instances) != 1:
        raise EndpointError("ISOLATED_INSTANCE_NOT_UNIQUE")
    return instances[0]


def _tags(resource: dict) -> dict[str, str]:
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in resource.get("Tags", [])}


def _aws_json(arguments: list[str], runner=subprocess.run) -> dict:
    try:
        result = runner(
            ["aws", *arguments, "--output", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise EndpointError("ISOLATED_AWS_READ_ONLY_VALIDATION_FAILED") from exc
    if result.returncode != 0:
        raise EndpointError("ISOLATED_AWS_READ_ONLY_VALIDATION_FAILED")
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise EndpointError("ISOLATED_AWS_RESPONSE_INVALID") from exc


def validate_isolated_aws_identity(
    *, instance_id: str, private_ip: str, region: str, runner=subprocess.run
) -> None:
    """Confirm the supplied endpoint is the running isolated host in the private DB subnet."""
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id) or instance_id == PRODUCTION_DB_INSTANCE_ID:
        raise EndpointError("ISOLATED_INSTANCE_ID_INVALID_OR_PROTECTED")
    if not re.fullmatch(r"[a-z0-9-]+", region):
        raise EndpointError("AWS_REGION_INVALID")
    try:
        address = ipaddress.ip_address(private_ip)
    except ValueError as exc:
        raise EndpointError("ISOLATED_PRIVATE_IP_INVALID") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or private_ip in PROTECTED_PRIVATE_IPS
        or address not in ipaddress.ip_network("IP_REDACTED/24")
        or private_ip == DEFAULT_DB_HOST
    ):
        raise EndpointError("ISOLATED_PRIVATE_IP_INVALID_OR_PROTECTED")

    instance = _one_instance(
        _aws_json(
            ["ec2", "describe-instances", "--region", region, "--instance-ids", instance_id],
            runner=runner,
        )
    )
    tags = _tags(instance)
    if (
        instance.get("InstanceId") != instance_id
        or instance.get("PrivateIpAddress") != private_ip
        or instance.get("State", {}).get("Name") != "running"
        or instance.get("PublicIpAddress")
        or tags.get("Name") != ISOLATED_INSTANCE_NAME
        or tags.get("Role") != ISOLATED_INSTANCE_ROLE
        or instance.get("IamInstanceProfile")
    ):
        raise EndpointError("ISOLATED_INSTANCE_IDENTITY_MISMATCH")

    security_groups = instance.get("SecurityGroups", [])
    if len(security_groups) != 2 or any(not group.get("GroupId") for group in security_groups):
        raise EndpointError("ISOLATED_SECURITY_GROUP_IDENTITY_MISMATCH")
    attached_group_ids = {str(group["GroupId"]) for group in security_groups}
    web_instances = [
        item
        for reservation in _aws_json(
            ["ec2", "describe-instances", "--region", region, "--filters", f"Name=tag:Name,Values={WEB_NAME}"],
            runner=runner,
        ).get("Reservations", [])
        for item in reservation.get("Instances", [])
    ]
    doc_instances = [
        item
        for reservation in _aws_json(
            ["ec2", "describe-instances", "--region", region, "--filters", f"Name=tag:Name,Values={DOC_NAME}"],
            runner=runner,
        ).get("Reservations", [])
        for item in reservation.get("Instances", [])
    ]
    if len(web_instances) != 1 or len(doc_instances) != 1:
        raise EndpointError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
    web, doc = web_instances[0], doc_instances[0]
    web_sgs = {str(group.get("GroupId", "")) for group in web.get("SecurityGroups", [])}
    doc_sgs = {str(group.get("GroupId", "")) for group in doc.get("SecurityGroups", [])}
    app_sgs = web_sgs | doc_sgs
    if (
        web.get("PrivateIpAddress") != WEB_PRIVATE_IP
        or doc.get("PrivateIpAddress") != DOC_PRIVATE_IP
        or web.get("VpcId") != instance.get("VpcId")
        or doc.get("VpcId") != instance.get("VpcId")
        or not web_sgs
        or not doc_sgs
    ):
        raise EndpointError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
    group_response = _aws_json(
        [
            "ec2", "describe-security-groups", "--region", region,
            "--group-ids", *sorted(attached_group_ids | app_sgs),
        ],
        runner=runner,
    ).get("SecurityGroups", [])
    groups_by_id = {str(group.get("GroupId", "")): group for group in group_response}
    base_groups = [group for group in group_response if group.get("GroupName") == ISOLATED_SECURITY_GROUP_NAME]
    service_groups = [group for group in group_response if group.get("GroupName") == ISOLATED_SERVICE_SECURITY_GROUP_NAME]
    if set(groups_by_id) != attached_group_ids | app_sgs or len(base_groups) != 1 or len(service_groups) != 1:
        raise EndpointError("ISOLATED_SERVICE_SECURITY_GROUP_REQUIRED")
    base_group, service_group = base_groups[0], service_groups[0]
    if {base_group.get("GroupId"), service_group.get("GroupId")} != attached_group_ids:
        raise EndpointError("ISOLATED_SECURITY_GROUP_SET_INVALID")
    if (
        base_group.get("VpcId") != instance.get("VpcId")
        or service_group.get("VpcId") != instance.get("VpcId")
        or not _sg_port_is_only_from_groups(base_group, "ingress", 22, web_sgs)
        or not _sg_port_is_only_from_groups(service_group, "ingress", ISOLATED_SERVICE_PORT, app_sgs)
        or not _sg_port_is_only_from_groups(service_group, "egress", ISOLATED_SERVICE_PORT, app_sgs)
    ):
        raise EndpointError("ISOLATED_SERVICE_SECURITY_GROUP_RULES_UNSAFE")
    for source_id in app_sgs:
        source_group = groups_by_id[source_id]
        expected_name = WEB_SECURITY_GROUP_NAME if source_id in web_sgs else DOC_SECURITY_GROUP_NAME
        if source_group.get("GroupName") != expected_name:
            raise EndpointError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")

    subnet_id = str(instance.get("SubnetId") or "")
    if not subnet_id:
        raise EndpointError("ISOLATED_SUBNET_IDENTITY_MISMATCH")
    subnets = _aws_json(
        ["ec2", "describe-subnets", "--region", region, "--subnet-ids", subnet_id],
        runner=runner,
    ).get("Subnets", [])
    if len(subnets) != 1:
        raise EndpointError("ISOLATED_SUBNET_IDENTITY_MISMATCH")
    subnet = subnets[0]
    try:
        in_subnet = address in ipaddress.ip_network(subnet["CidrBlock"])
    except (KeyError, ValueError) as exc:
        raise EndpointError("ISOLATED_SUBNET_CIDR_INVALID") from exc
    if (
        subnet.get("SubnetId") != subnet_id
        or subnet.get("VpcId") != instance.get("VpcId")
        or _tags(subnet).get("Name") != ISOLATED_SUBNET_NAME
        or subnet.get("MapPublicIpOnLaunch", False)
        or not in_subnet
    ):
        raise EndpointError("ISOLATED_SUBNET_IDENTITY_MISMATCH")


def _read_port(name: str, value: str | None, default: int | None) -> int:
    if value is None:
        if default is None:
            raise EndpointError(f"{name}_REQUIRED")
        return default
    if not value or not re.fullmatch(r"[0-9]+", value):
        raise EndpointError(f"{name}_INVALID")
    port = int(value)
    if not 1 <= port <= 65535:
        raise EndpointError(f"{name}_INVALID")
    return port


def resolve_endpoint(
    environment: Mapping[str, str], application: str, runner=subprocess.run
) -> dict[str, str | int]:
    if application not in APP_PORT_VARIABLES:
        raise EndpointError("APPLICATION_INVALID")

    mode = environment.get("DR_DB_SERVICE_MODE", "existing")
    if mode not in {"existing", "isolated"}:
        raise EndpointError("DB_SERVICE_MODE_INVALID")

    host_was_set = "DR_DB_SERVICE_HOST" in environment
    raw_host = environment.get("DR_DB_SERVICE_HOST")
    if host_was_set and (raw_host is None or not raw_host.strip()):
        if mode == "isolated":
            raise EndpointError("ISOLATED_DB_SERVICE_HOST_REQUIRED")
        raise EndpointError("DB_SERVICE_HOST_EMPTY")

    if mode == "existing":
        host = raw_host if host_was_set else DEFAULT_DB_HOST
        if host != DEFAULT_DB_HOST:
            raise EndpointError("EXISTING_DB_TARGET_MUST_USE_APPROVED_PRIVATE_IP")
        common_port = _read_port(
            "DR_DB_SERVICE_PORT", environment.get("DR_DB_SERVICE_PORT"), DEFAULT_DB_PORT
        )
        app_port_variable = APP_PORT_VARIABLES[application]
        app_port = _read_port(app_port_variable, environment.get(app_port_variable), common_port)
    else:
        if not host_was_set or raw_host is None or not raw_host.strip():
            raise EndpointError("ISOLATED_DB_SERVICE_HOST_REQUIRED")
        if "DR_DB_SERVICE_PORT" not in environment:
            raise EndpointError("ISOLATED_DB_SERVICE_PORT_REQUIRED")
        host = raw_host.strip()
        common_port = _read_port("DR_DB_SERVICE_PORT", environment.get("DR_DB_SERVICE_PORT"), None)
        app_port_variable = APP_PORT_VARIABLES[application]
        if app_port_variable in environment:
            app_port = _read_port(app_port_variable, environment.get(app_port_variable), None)
            if app_port != common_port:
                raise EndpointError("ISOLATED_DB_SERVICE_PORT_CONFLICT")
        else:
            app_port = common_port
        instance_id = environment.get("DR_DB_SERVICE_INSTANCE_ID", "")
        region = environment.get("AWS_REGION", "ap-northeast-2")
        validate_isolated_aws_identity(
            instance_id=instance_id,
            private_ip=host,
            region=region,
            runner=runner,
        )

    return {"host": host, "port": app_port}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application", choices=tuple(APP_PORT_VARIABLES), required=True)
    args = parser.parse_args(argv)
    try:
        result = resolve_endpoint(os.environ, args.application)
    except EndpointError as exc:
        print(f"DB_SERVICE_ENDPOINT=BLOCKED reason={exc}", file=sys.stderr)
        return 2
    print(result["host"])
    print(result["port"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
