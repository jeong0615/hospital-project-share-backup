#!/usr/bin/env python3
"""Prepare or run the explicitly approved, isolated AWS Web-only Canary.

Default mode is an offline contract check. ``--aws-read-only`` performs only
AWS Describe/List/Get calls. ``--run-canary`` is the sole full execution path:
it creates a temporary SG, adds only the SSM endpoint ingress reference,
replaces the exact Web ENI SG set, starts Web, waits for SSM, runs a sanitized
read-only guest inspection, then stops Web and restores the saved network
state. ``--restore`` is an independent recovery entry point. No NAT role,
route, DB, DNS, EMR, Trigger, or Action changes are implemented here.

This module is intentionally not invoked with a mutating option during
development or preflight work.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REGION = "ap-northeast-2"
ACCOUNT_ID = "AWS_ACCOUNT_ID_REDACTED"
VPC_ID = "AWS_RESOURCE_ID_REDACTED"
VPC_CIDR = "AWS_PUBLIC_IP_REDACTED/16"
WEB_ID = "AWS_RESOURCE_ID_REDACTED"
WEB_ENI = "AWS_RESOURCE_ID_REDACTED"
WEB_SUBNET = "AWS_RESOURCE_ID_REDACTED"
WEB_PRIVATE_IP = "IP_REDACTED"
WEB_EIP = "AWS_PUBLIC_IP_REDACTED"
WEB_ORIGINAL_SG = "AWS_RESOURCE_ID_REDACTED"
DB_SG = "AWS_RESOURCE_ID_REDACTED"
PRIVATE_ROUTE_TABLE_ID = "AWS_RESOURCE_ID_REDACTED"
SSM_SERVICES = {
    f"com.amazonaws.{REGION}.ssm",
    f"com.amazonaws.{REGION}.ssmmessages",
}
OPTIONAL_SSM_SERVICES = {f"com.amazonaws.{REGION}.ec2messages"}
SSM_POLICY_ARN = "AWS_ARN_REDACTED"
STATE_VERSION = 2
MAX_CANARY_SECONDS = 30 * 60
CLI_TIMEOUT_SECONDS = 20
START_TIMEOUT_SECONDS = 6 * 60
SSM_TIMEOUT_SECONDS = 10 * 60
COMMAND_TIMEOUT_SECONDS = 3 * 60
STOP_TIMEOUT_SECONDS = 5 * 60
POLL_SECONDS = 10


class CanaryError(RuntimeError):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _raise_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


class AwsCli:
    """Small AWS CLI adapter. It never prints command output or credentials."""

    def __init__(self, region: str = REGION, timeout: int = CLI_TIMEOUT_SECONDS):
        self.region = region
        self.timeout = timeout
        self.lock_fd: int | None = None
        self.event_callback: Callable[[str, dict[str, Any]], None] | None = None

    @staticmethod
    def _cli_operation(operation: str) -> str:
        return re.sub(r"(?<!^)([A-Z])", r"-\1", operation).lower()

    def call(self, service: str, operation: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        command = [
            "aws", service, self._cli_operation(operation), "--region", self.region,
            "--cli-connect-timeout", "5", "--cli-read-timeout", "12",
            "--output", "json", "--cli-input-json",
            json.dumps(payload or {}, separators=(",", ":")),
        ]
        started = time.monotonic()
        self._emit("AWS_API_START", service=service, operation=operation)
        try:
            kwargs: dict[str, Any] = {
                "capture_output": True, "text": True, "timeout": self.timeout, "check": False,
            }
            if self.lock_fd is not None:
                # Keep the flock alive while an AWS CLI child is still issuing an API call,
                # even if the controlling Python process is terminated unexpectedly.
                kwargs["pass_fds"] = (self.lock_fd,)
            result = subprocess.run(command, **kwargs)
        except subprocess.TimeoutExpired as exc:
            code = f"AWS_{service}_{operation}_TIMEOUT"
            self._emit("AWS_API_FAILED", service=service, operation=operation, reason=code)
            raise CanaryError(code, f"{service}.{operation} exceeded the {self.timeout}s process timeout") from exc
        except OSError as exc:
            code = f"AWS_{service}_{operation}_UNAVAILABLE"
            self._emit("AWS_API_FAILED", service=service, operation=operation, reason=code)
            raise CanaryError(code, f"{service}.{operation} could not be started") from exc
        if result.returncode:
            # Do not echo arbitrary CLI stderr: it can contain account or request metadata.
            match = re.search(r"An error occurred \(([^)]+)\) when calling", result.stderr or "")
            aws_code = re.sub(r"[^A-Za-z0-9]+", "_", match.group(1)).upper() if match else f"CLI_EXIT_{result.returncode}"
            code = f"AWS_{service}_{operation}_{aws_code}"
            self._emit("AWS_API_FAILED", service=service, operation=operation, reason=code)
            raise CanaryError(code, f"{service}.{operation} returned an AWS CLI error ({aws_code})")
        try:
            decoded = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            self._emit("AWS_API_FAILED", service=service, operation=operation, reason="AWS_RESPONSE_INVALID")
            raise CanaryError("AWS_RESPONSE_INVALID", f"{service}.{operation} returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            self._emit("AWS_API_FAILED", service=service, operation=operation, reason="AWS_RESPONSE_INVALID")
            raise CanaryError("AWS_RESPONSE_INVALID", f"{service}.{operation} response was not an object")
        self._emit("AWS_API_COMPLETE", service=service, operation=operation, elapsed_seconds=round(time.monotonic() - started, 2))
        return decoded

    def _emit(self, event: str, **fields: Any) -> None:
        if self.event_callback:
            self.event_callback(event, fields)


class EventLogger:
    """Flush-only progress log containing operation names and reason codes, never API payloads."""

    def __init__(self, path: Path | None = None, *, append: bool = False):
        self.path = path
        self.stream = None
        self.write_failed = False
        if path is not None:
            _secure_state_parent(path)
            flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_EXCL)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(path, flags, 0o600)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    os.close(fd)
                    raise CanaryError("LOG_FILE_PERMISSIONS", "Log file must be an operator-owned regular file with mode 0600")
                self.stream = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
            except CanaryError:
                raise
            except OSError as exc:
                raise CanaryError("LOG_FILE_UNAVAILABLE", "Could not create or open the private Canary log") from exc

    def emit(self, event: str, **fields: Any) -> None:
        record = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **fields}
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        try:
            print(line, flush=True)
        except OSError:
            self.write_failed = True
        if self.stream is not None:
            try:
                self.stream.write(line + "\n")
                self.stream.flush()
            except OSError:
                self.write_failed = True
                try:
                    self.stream.close()
                finally:
                    self.stream = None

    def close(self) -> None:
        if self.stream is not None:
            self.stream.close()
            self.stream = None


class ExecutionLock:
    """One host-wide mutation lock for run and recovery; AWS CLI children inherit it."""

    def __init__(self, path: Path | None = None):
        self.path = path or (Path.home() / ".local/state/hospital-dr-web-canary/.execution.lock")
        self.fd: int | None = None

    def __enter__(self) -> "ExecutionLock":
        _secure_state_parent(self.path)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self.fd = os.open(self.path, flags, 0o600)
            st = os.fstat(self.fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise CanaryError("CANARY_LOCK_PERMISSIONS", "Canary lock must be operator-owned and mode 0600")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CanaryError("CANARY_MUTATION_ALREADY_RUNNING", "Another Canary or recovery process holds the mutation lock") from exc
            os.ftruncate(self.fd, 0)
            os.write(self.fd, f"pid={os.getpid()} started_utc={datetime.now(timezone.utc).isoformat()}\n".encode())
            os.fsync(self.fd)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def _ip_permission(permission: dict[str, Any]) -> dict[str, Any]:
    """Convert DescribeSecurityGroups permission data to an API input shape."""
    result: dict[str, Any] = {"IpProtocol": permission["IpProtocol"]}
    for key in ("FromPort", "ToPort"):
        if key in permission:
            result[key] = permission[key]
    for key, identity in (
        ("IpRanges", "CidrIp"),
        ("Ipv6Ranges", "CidrIpv6"),
        ("PrefixListIds", "PrefixListId"),
        ("UserIdGroupPairs", "GroupId"),
    ):
        values = []
        for item in permission.get(key, []):
            if identity not in item:
                continue
            row = {identity: item[identity]}
            for extra in ("Description", "UserId", "VpcId", "VpcPeeringConnectionId"):
                if item.get(extra):
                    row[extra] = item[extra]
            values.append(row)
        if values:
            result[key] = values
    return result


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in sorted(value.items()) if key not in {"UserId", "VpcId", "GroupOwnerId", "PeeringStatus"}}
    if isinstance(value, list):
        return sorted((_canonical(item) for item in value), key=lambda row: json.dumps(row, sort_keys=True))
    return value


def _rule_is_group_443(permission: dict[str, Any], group_id: str) -> bool:
    return (
        permission.get("IpProtocol") == "tcp"
        and permission.get("FromPort") == 443
        and permission.get("ToPort") == 443
        and not permission.get("IpRanges")
        and not permission.get("Ipv6Ranges")
        and not permission.get("PrefixListIds")
        and group_id in {item.get("GroupId") for item in permission.get("UserIdGroupPairs", [])}
    )


def validate_isolation_group(group: dict[str, Any], endpoint_sg_ids: set[str]) -> list[str]:
    """Return contract errors for the attached Canary SG readback."""
    errors: list[str] = []
    if group.get("IpPermissions"):
        errors.append("CANARY_INGRESS_NOT_EMPTY")
    egress = group.get("IpPermissionsEgress", [])
    seen: set[str] = set()
    for rule in egress:
        peers = rule.get("UserIdGroupPairs", [])
        peer_ids = {item.get("GroupId", "") for item in peers}
        if (
            rule.get("IpProtocol") != "tcp" or rule.get("FromPort") != 443 or rule.get("ToPort") != 443
            or rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("PrefixListIds")
            or not peer_ids or not peer_ids.issubset(endpoint_sg_ids)
        ):
            errors.append("CANARY_EGRESS_NOT_EXACT_ENDPOINT_443")
            continue
        seen |= peer_ids
    if seen != endpoint_sg_ids:
        errors.append("CANARY_EGRESS_ENDPOINT_MISSING")
    return sorted(set(errors))


def validate_attached_group_set(actual_group_ids: list[str], canary_group_id: str) -> list[str]:
    actual = set(actual_group_ids)
    if actual == {canary_group_id}:
        return []
    errors = ["CANARY_SG_NOT_EXCLUSIVE"]
    if actual - {canary_group_id}:
        errors.append("ORIGINAL_OR_UNEXPECTED_SG_REMAINS_ATTACHED")
    return errors


def has_group_tcp443_rule(group: dict[str, Any], source_group_id: str) -> bool:
    return any(_rule_is_group_443(rule, source_group_id) for rule in group.get("IpPermissions", []))


def verify_exact_web_eni(eni: dict[str, Any]) -> bool:
    return (
        eni.get("NetworkInterfaceId") == WEB_ENI
        and eni.get("VpcId") == VPC_ID
        and eni.get("SubnetId") == WEB_SUBNET
        and eni.get("Attachment", {}).get("InstanceId") == WEB_ID
    )


def classify_nat_routes(route_table: dict[str, Any], web_eni_id: str = WEB_ENI) -> str:
    required = {"IP_REDACTED/0", "IP_REDACTED/24"}
    routes = {item.get("DestinationCidrBlock"): item for item in route_table.get("Routes", []) if item.get("DestinationCidrBlock") in required}
    if set(routes) != required or any(item.get("NetworkInterfaceId") != web_eni_id for item in routes.values()):
        return "wrong-target-or-missing"
    if any(item.get("State") != "active" for item in routes.values()):
        return "blackhole-or-not-active"
    return "active"


def _effective_acl_action(acl: dict[str, Any], *, egress: bool, peer_ip: str, protocol: int, port: int) -> str:
    address = ipaddress.ip_address(peer_ip)
    for rule in sorted(acl.get("Entries", []), key=lambda row: int(row.get("RuleNumber", 32767))):
        if bool(rule.get("Egress")) != egress:
            continue
        cidr_value = rule.get("CidrBlock") if address.version == 4 else rule.get("Ipv6CidrBlock")
        if not cidr_value:
            continue
        try:
            if address not in ipaddress.ip_network(cidr_value, strict=False):
                continue
        except ValueError:
            continue
        proto = str(rule.get("Protocol", "-1"))
        if proto not in {"-1", str(protocol)}:
            continue
        port_range = rule.get("PortRange")
        if proto != "-1" and port_range and not (int(port_range["From"]) <= port <= int(port_range["To"])):
            continue
        return str(rule.get("RuleAction", "deny")).lower()
    return "deny"


def _acl_for_subnet(acls: list[dict[str, Any]], subnet_id: str) -> dict[str, Any] | None:
    for acl in acls:
        if any(row.get("SubnetId") == subnet_id for row in acl.get("Associations", [])):
            return acl
    return None


def _acl_allows_port_range(acl: dict[str, Any], *, egress: bool, peer_ip: str, protocol: int, first: int, last: int) -> bool:
    """Check every effective NACL port interval without sampling gaps."""
    points = {first}
    address = ipaddress.ip_address(peer_ip)
    for rule in acl.get("Entries", []):
        if bool(rule.get("Egress")) != egress:
            continue
        cidr_value = rule.get("CidrBlock") if address.version == 4 else rule.get("Ipv6CidrBlock")
        if not cidr_value:
            continue
        try:
            if address not in ipaddress.ip_network(cidr_value, strict=False):
                continue
        except ValueError:
            continue
        proto = str(rule.get("Protocol", "-1"))
        if proto not in {"-1", str(protocol)}:
            continue
        port_range = rule.get("PortRange")
        if proto == "-1" or not port_range:
            continue
        start = max(first, int(port_range["From"]))
        end = min(last, int(port_range["To"]))
        if start <= end:
            points.add(start)
            if end < last:
                points.add(end + 1)
    return all(
        _effective_acl_action(acl, egress=egress, peer_ip=peer_ip, protocol=protocol, port=port) == "allow"
        for port in sorted(points)
        if port <= last
    )


def _check_nacl_path(acls: list[dict[str, Any]], web_subnet: str, endpoint_subnet: str, web_ip: str, endpoint_ip: str) -> bool:
    web_acl = _acl_for_subnet(acls, web_subnet)
    endpoint_acl = _acl_for_subnet(acls, endpoint_subnet)
    if not web_acl or not endpoint_acl:
        return False
    return all((
        _effective_acl_action(web_acl, egress=True, peer_ip=endpoint_ip, protocol=6, port=443) == "allow",
        _acl_allows_port_range(web_acl, egress=False, peer_ip=endpoint_ip, protocol=6, first=32768, last=65535),
        _effective_acl_action(endpoint_acl, egress=False, peer_ip=web_ip, protocol=6, port=443) == "allow",
        _acl_allows_port_range(endpoint_acl, egress=True, peer_ip=web_ip, protocol=6, first=32768, last=65535),
    ))


def _route_table_for_subnet(route_tables: list[dict[str, Any]], subnet_id: str) -> dict[str, Any] | None:
    for table in route_tables:
        if any(association.get("SubnetId") == subnet_id for association in table.get("Associations", [])):
            return table
    return next((table for table in route_tables if any(a.get("Main") for a in table.get("Associations", []))), None)


def _security_group(groups: list[dict[str, Any]], group_id: str) -> dict[str, Any] | None:
    return next((group for group in groups if group.get("GroupId") == group_id), None)


def _route_table_snapshot(table: dict[str, Any] | None) -> dict[str, Any]:
    if not table:
        return {}
    return {
        "route_table_id": table.get("RouteTableId", ""),
        "associations": table.get("Associations", []),
        "routes": table.get("Routes", []),
    }


def inspect_environment(aws: AwsCli) -> dict[str, Any]:
    """Read-only live snapshot and readiness findings; no mutation calls."""
    report: dict[str, Any] = {"region": aws.region, "checks": {}, "resources": {}}
    identity = aws.call("sts", "GetCallerIdentity")
    report["checks"]["account"] = "PASS" if identity.get("Account") == ACCOUNT_ID else "BLOCKED"
    if identity.get("Account") != ACCOUNT_ID:
        raise CanaryError("AWS_ACCOUNT_MISMATCH", "AWS caller account does not match the approved DR account")
    instances = aws.call("ec2", "DescribeInstances", {"InstanceIds": [WEB_ID]}).get("Reservations", [])
    rows = [row for reservation in instances for row in reservation.get("Instances", [])]
    if len(rows) != 1:
        raise CanaryError("WEB_INSTANCE_NOT_UNIQUE", "Expected exactly one Web instance")
    instance = rows[0]
    enis = instance.get("NetworkInterfaces", [])
    if len(enis) != 1 or enis[0].get("NetworkInterfaceId") != WEB_ENI:
        raise CanaryError("WEB_ENI_IDENTITY_MISMATCH", "Web instance ENI identity differs from the approved target")
    eni_id = enis[0]["NetworkInterfaceId"]
    network = aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
    if len(network) != 1:
        raise CanaryError("WEB_ENI_NOT_UNIQUE", "Expected exactly one Web ENI")
    eni = network[0]
    attached = sorted(row.get("GroupId", "") for row in eni.get("Groups", []))
    web_identity_ok = (
        instance.get("InstanceId") == WEB_ID
        and instance.get("VpcId") == VPC_ID
        and instance.get("SubnetId") == WEB_SUBNET
        and instance.get("PrivateIpAddress") == WEB_PRIVATE_IP
        and eni.get("VpcId") == VPC_ID
        and eni.get("SubnetId") == WEB_SUBNET
        and verify_exact_web_eni(eni)
        and eni.get("Association", {}).get("PublicIp") == WEB_EIP
    )
    if not web_identity_ok:
        raise CanaryError("WEB_IDENTITY_MISMATCH", "Web instance/ENI/VPC/subnet/EIP identity does not match the approved target")
    if instance.get("State", {}).get("Name") != "stopped":
        raise CanaryError("WEB_NOT_STOPPED", "Web must be stopped before isolation is prepared")
    if WEB_ORIGINAL_SG not in attached or not attached:
        raise CanaryError("WEB_SG_BASELINE_MISMATCH", "Expected existing Web security group is not attached to the Web ENI")
    report["checks"]["web_identity"] = "PASS"
    report["checks"]["web_stopped"] = "PASS"
    report["resources"].update({
        "web_instance_id": WEB_ID, "web_eni_id": WEB_ENI, "web_subnet_id": WEB_SUBNET,
        "original_web_security_group_ids": attached, "web_eip": WEB_EIP,
        "source_dest_check": bool(eni.get("SourceDestCheck")),
        "web_instance_state_before": instance.get("State", {}).get("Name", "unknown"),
    })

    vpc = aws.call("ec2", "DescribeVpcs", {"VpcIds": [VPC_ID]}).get("Vpcs", [])
    if len(vpc) != 1 or vpc[0].get("CidrBlock") != VPC_CIDR:
        raise CanaryError("VPC_IDENTITY_MISMATCH", "VPC identity or CIDR differs from the approved contract")
    dns_support = aws.call("ec2", "DescribeVpcAttribute", {"VpcId": VPC_ID, "Attribute": "enableDnsSupport"}).get("EnableDnsSupport", {}).get("Value")
    dns_hostnames = aws.call("ec2", "DescribeVpcAttribute", {"VpcId": VPC_ID, "Attribute": "enableDnsHostnames"}).get("EnableDnsHostnames", {}).get("Value")
    dhcp_id = vpc[0].get("DhcpOptionsId")
    dhcp = aws.call("ec2", "DescribeDhcpOptions", {"DhcpOptionsIds": [dhcp_id]}).get("DhcpOptions", []) if dhcp_id else []
    dns_servers = [
        value.get("Value")
        for item in (dhcp[0].get("DhcpConfigurations", []) if dhcp else [])
        if item.get("Key") == "domain-name-servers"
        for value in item.get("Values", [])
    ]
    dns_ok = dns_support is True and dns_hostnames is True and (not dns_servers or "AmazonProvidedDNS" in dns_servers)
    report["checks"]["vpc_dns"] = "PASS" if dns_ok else "BLOCKED"
    report["checks"]["dns_egress_filtering"] = "UNFILTERABLE_BY_SG_NACL"
    if not dns_ok:
        raise CanaryError("VPC_DNS_NOT_COMPATIBLE", "VPC DNS or DHCP DNS configuration is not compatible with endpoint Private DNS")

    endpoints = aws.call("ec2", "DescribeVpcEndpoints", {"Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}]}).get("VpcEndpoints", [])
    relevant = [ep for ep in endpoints if ep.get("ServiceName") in SSM_SERVICES | OPTIONAL_SSM_SERVICES]
    by_service: dict[str, list[dict[str, Any]]] = {}
    for endpoint in relevant:
        by_service.setdefault(endpoint.get("ServiceName", ""), []).append(endpoint)
    missing = SSM_SERVICES - set(by_service)
    if missing or any(len(by_service.get(service, [])) != 1 for service in SSM_SERVICES):
        raise CanaryError("SSM_ENDPOINT_SET_INCOMPLETE", "Exactly one SSM and ssmmessages endpoint is required")
    selected_services = SSM_SERVICES | (OPTIONAL_SSM_SERVICES & set(by_service))
    if any(len(by_service.get(service, [])) != 1 for service in selected_services):
        raise CanaryError("SSM_ENDPOINT_SET_AMBIGUOUS", "A required or configured optional SSM endpoint is not unique")
    endpoint_rows = []
    endpoint_sg_ids: set[str] = set()
    endpoint_eni_ids: set[str] = set()
    endpoint_subnets: set[str] = set()
    endpoint_ips: list[tuple[str, str]] = []
    for service in sorted(selected_services):
        ep = by_service[service][0]
        if ep.get("State") != "available" or ep.get("VpcId") != VPC_ID or ep.get("PrivateDnsEnabled") is not True:
            raise CanaryError("SSM_ENDPOINT_NOT_READY", "Required SSM endpoint is not available with Private DNS")
        group_ids = {item.get("GroupId", "") for item in ep.get("Groups", [])}
        eni_ids = set(ep.get("NetworkInterfaceIds", []))
        if not group_ids or not eni_ids:
            raise CanaryError("SSM_ENDPOINT_NETWORK_MISSING", "Required endpoint has no security group or ENI")
        eni_rows = aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": sorted(eni_ids)}).get("NetworkInterfaces", [])
        if {row.get("NetworkInterfaceId") for row in eni_rows} != eni_ids or any(row.get("Status") != "in-use" for row in eni_rows):
            raise CanaryError("SSM_ENDPOINT_ENI_NOT_READY", "SSM endpoint ENI is absent or not in use")
        for endpoint_eni in eni_rows:
            endpoint_subnets.add(endpoint_eni.get("SubnetId", ""))
            for address in endpoint_eni.get("PrivateIpAddresses", []):
                endpoint_ips.append((endpoint_eni.get("SubnetId", ""), address.get("PrivateIpAddress", "")))
        endpoint_sg_ids |= group_ids
        endpoint_eni_ids |= eni_ids
        endpoint_rows.append({
            "id": ep["VpcEndpointId"], "service": service, "state": ep["State"],
            "private_dns": ep["PrivateDnsEnabled"], "subnets": sorted(endpoint_subnets),
            "eni_ids": sorted(eni_ids), "security_group_ids": sorted(group_ids),
        })
    if not endpoint_ips or any(not subnet or not ip for subnet, ip in endpoint_ips):
        raise CanaryError("SSM_ENDPOINT_IP_MISSING", "Could not establish endpoint ENI private IPs")
    endpoint_eni_groups = aws.call("ec2", "DescribeNetworkInterfaces", {"Filters": [{"Name": "group-id", "Values": sorted(endpoint_sg_ids)}]}).get("NetworkInterfaces", [])
    allowed_endpoint_eni_ids = endpoint_eni_ids
    if {row.get("NetworkInterfaceId") for row in endpoint_eni_groups} != allowed_endpoint_eni_ids:
        raise CanaryError("SSM_ENDPOINT_SG_SHARED", "Endpoint security group is attached to an unapproved non-SSM ENI")
    endpoint_groups = aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": sorted(endpoint_sg_ids)}).get("SecurityGroups", [])
    if {row.get("GroupId") for row in endpoint_groups} != endpoint_sg_ids:
        raise CanaryError("SSM_ENDPOINT_SG_MISSING", "An endpoint security group could not be read")
    # Existing broad endpoint ingress is not modified or accepted as part of this plan.
    for group in endpoint_groups:
        for rule in group.get("IpPermissions", []):
            if rule.get("IpProtocol") == "-1" or (
                rule.get("IpProtocol") == "tcp" and int(rule.get("FromPort", -1)) <= 443 <= int(rule.get("ToPort", -1))
            ):
                if rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("PrefixListIds"):
                    raise CanaryError("SSM_ENDPOINT_SG_BROAD_INGRESS", "Endpoint SG has broad ingress that must be reviewed before Canary")
    report["checks"]["ssm_endpoints"] = "PASS"
    report["checks"]["ssm_private_dns"] = "PASS"
    report["checks"]["endpoint_security_group_update"] = "READY_FOR_APPROVED_CHANGE"
    report["checks"]["ec2messages_endpoint"] = "PRESENT" if OPTIONAL_SSM_SERVICES & set(by_service) else "NOT_PRESENT"
    report["checks"]["ssm_agent_compatibility"] = "PENDING_LIVE_TEST"
    report["resources"]["ssm_endpoints"] = endpoint_rows
    report["resources"]["endpoint_security_group_ids"] = sorted(endpoint_sg_ids)
    report["resources"]["endpoint_sg_ingress_sources"] = {
        group.get("GroupId", ""): [
            {
                "protocol": rule.get("IpProtocol"),
                "from_port": rule.get("FromPort"),
                "to_port": rule.get("ToPort"),
                "source_group_ids": sorted(pair.get("GroupId", "") for pair in rule.get("UserIdGroupPairs", [])),
                "ipv4_sources": sorted(item.get("CidrIp", "") for item in rule.get("IpRanges", [])),
                "ipv6_sources": sorted(item.get("CidrIpv6", "") for item in rule.get("Ipv6Ranges", [])),
            }
            for rule in group.get("IpPermissions", [])
        ]
        for group in endpoint_groups
    }

    web_sg = aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": attached}).get("SecurityGroups", [])
    if {row.get("GroupId") for row in web_sg} != set(attached):
        raise CanaryError("WEB_SECURITY_GROUP_UNREADABLE", "Could not read every security group attached to Web")
    report["resources"]["web_sg_egress_rule_count"] = sum(len(row.get("IpPermissionsEgress", [])) for row in web_sg)
    report["resources"]["web_sg_ingress_rule_count"] = sum(len(row.get("IpPermissions", [])) for row in web_sg)
    report["resources"]["web_sg_current_unrestricted_egress"] = any(
        rule.get("IpProtocol") == "-1" and any(item.get("CidrIp") == "IP_REDACTED/0" for item in rule.get("IpRanges", []))
        for group in web_sg for rule in group.get("IpPermissionsEgress", [])
    )
    report["resources"]["web_sg_rule_snapshot"] = [
        {"group_id": row.get("GroupId", ""), "ingress": row.get("IpPermissions", []), "egress": row.get("IpPermissionsEgress", [])}
        for row in web_sg
    ]
    report["checks"]["web_ingress_unchanged"] = "PASS"
    report["checks"]["isolation_model"] = "PREPARE_ONLY"

    route_tables = aws.call("ec2", "DescribeRouteTables", {"Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}]}).get("RouteTables", [])
    web_rt = _route_table_for_subnet(route_tables, WEB_SUBNET)
    local_route = next((route for route in (web_rt or {}).get("Routes", []) if route.get("DestinationCidrBlock") == VPC_CIDR and route.get("GatewayId") == "local" and route.get("State") == "active"), None)
    if not local_route:
        raise CanaryError("WEB_VPCE_LOCAL_ROUTE_MISSING", "Web subnet route table does not have the expected active VPC local route")
    endpoint_routes_ok = True
    acls = aws.call("ec2", "DescribeNetworkAcls", {"Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}]}).get("NetworkAcls", [])
    for endpoint_subnet, endpoint_ip in endpoint_ips:
        endpoint_rt = _route_table_for_subnet(route_tables, endpoint_subnet)
        endpoint_local = next((route for route in (endpoint_rt or {}).get("Routes", []) if route.get("DestinationCidrBlock") == VPC_CIDR and route.get("GatewayId") == "local" and route.get("State") == "active"), None)
        endpoint_routes_ok = endpoint_routes_ok and bool(endpoint_local)
        if not _check_nacl_path(acls, WEB_SUBNET, endpoint_subnet, WEB_PRIVATE_IP, endpoint_ip):
            endpoint_routes_ok = False
    report["checks"]["endpoint_route_nacl"] = "PASS" if endpoint_routes_ok else "BLOCKED"
    if not endpoint_routes_ok:
        raise CanaryError("SSM_ENDPOINT_NETWORK_ACL_OR_ROUTE_BLOCKED", "Web-to-endpoint route or stateless NACL response path is not verified")
    report["resources"]["web_route_table_id"] = (web_rt or {}).get("RouteTableId", "")
    report["resources"]["web_route_table_snapshot"] = _route_table_snapshot(web_rt)
    report["resources"]["endpoint_ips"] = [{"subnet_id": subnet, "private_ip": ip} for subnet, ip in endpoint_ips]
    private_table = next((item for item in route_tables if item.get("RouteTableId") == PRIVATE_ROUTE_TABLE_ID), None)
    private_route_state = classify_nat_routes(private_table or {})
    if private_route_state == "wrong-target-or-missing":
        raise CanaryError("WEB_NAT_ROUTE_TARGET_MISMATCH", "Private NAT routes are missing or do not target the expected Web ENI")
    report["checks"]["prestart_web_nat_routes"] = "PENDING_LIVE_TEST" if private_route_state != "active" else "PASS"
    report["resources"]["prestart_web_nat_route_state"] = private_route_state
    report["resources"]["private_nat_route_table_snapshot"] = _route_table_snapshot(private_table)

    profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
    profile_name = profile_arn.rsplit("/", 1)[-1] if profile_arn else ""
    if not profile_name:
        raise CanaryError("WEB_INSTANCE_PROFILE_MISSING", "Web has no instance profile")
    profile = aws.call("iam", "GetInstanceProfile", {"InstanceProfileName": profile_name}).get("InstanceProfile", {})
    role_names = [row.get("RoleName", "") for row in profile.get("Roles", [])]
    if len(role_names) != 1:
        raise CanaryError("WEB_INSTANCE_ROLE_UNVERIFIED", "Web instance profile does not resolve to exactly one IAM role")
    attached_policies = aws.call("iam", "ListAttachedRolePolicies", {"RoleName": role_names[0]}).get("AttachedPolicies", [])
    ssm_policy_present = any(row.get("PolicyArn") == SSM_POLICY_ARN for row in attached_policies)
    report["checks"]["web_ssm_instance_policy"] = "PASS" if ssm_policy_present else "BLOCKED"
    if not ssm_policy_present:
        raise CanaryError("WEB_SSM_IAM_POLICY_MISSING", "Web role lacks the expected SSM managed-node policy")
    report["resources"]["web_instance_profile"] = profile_name
    report["resources"]["web_role_name"] = role_names[0]
    report["checks"]["ssm_live_online"] = "PENDING_LIVE_TEST"
    report["checks"]["external_traffic_isolation"] = "GUARANTEED_AFTER_CANARY_SG_READBACK"
    report["checks"]["db_egress_isolation"] = "GUARANTEED_AFTER_CANARY_SG_READBACK"
    return report


def _secure_state_parent(path: Path) -> None:
    if not path.is_absolute():
        raise CanaryError("STATE_PATH_NOT_ABSOLUTE", "State file path must be absolute")
    try:
        if path.parent.is_symlink():
            raise CanaryError("STATE_DIRECTORY_SYMLINK", "State directory must not be a symlink")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        st = path.parent.stat()
    except CanaryError:
        raise
    except OSError as exc:
        raise CanaryError("STATE_DIRECTORY_UNAVAILABLE", "Could not prepare the private state directory") from exc
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise CanaryError("STATE_DIRECTORY_PERMISSIONS", "State directory must be owned by the operator and mode 0700")


def _write_state(path: Path, state: dict[str, Any]) -> None:
    _secure_state_parent(path)
    fd, temporary = tempfile.mkstemp(prefix=".canary-state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=True, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_state(path: Path) -> dict[str, Any]:
    _secure_state_parent(path)
    try:
        st = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise CanaryError("STATE_FILE_PERMISSIONS", "State file must be an operator-owned regular file with mode 0600")
        value = json.loads(path.read_text(encoding="utf-8"))
    except CanaryError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise CanaryError("STATE_FILE_UNREADABLE", "State file is absent or invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != STATE_VERSION
        or value.get("web_instance_id") != WEB_ID
        or value.get("web_eni_id") != WEB_ENI
        or value.get("account_id") != ACCOUNT_ID
        or value.get("region") != REGION
        or not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("run_id", "")))
        or not value.get("original_web_sg_ids")
        or any(not re.fullmatch(r"sg-[0-9a-f]+", str(group)) for group in value.get("original_web_sg_ids", []))
    ):
        raise CanaryError("STATE_FILE_CONTRACT_INVALID", "State file does not match the supported Web Canary contract")
    return value


class AwsWebCanary:
    def __init__(self, aws: Any, state_path: Path, *, logger: EventLogger | None = None, max_minutes: int = 30, sleep: Callable[[float], None] = time.sleep, monotonic: Callable[[], float] = time.monotonic):
        self.aws = aws
        self.state_path = state_path
        self.logger = logger or EventLogger()
        self.sleep = sleep
        self.monotonic = monotonic
        self.max_minutes = max_minutes
        self.cleanup_budget = min(STOP_TIMEOUT_SECONDS, max(5, max_minutes * 60 // 6))
        self.total_deadline = monotonic() + max(1, max_minutes * 60 - self.cleanup_budget - CLI_TIMEOUT_SECONDS)
        self.state: dict[str, Any] | None = None
        self._restoring = False
        if hasattr(self.aws, "event_callback"):
            self.aws.event_callback = self._aws_event

    def _event(self, event: str, **fields: Any) -> None:
        record = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **fields}
        if self.state is not None:
            history = self.state.setdefault("events", [])
            history.append(record)
            if len(history) > 500:
                del history[:-500]
            self.state["last_event"] = record
            self.state["updated_at"] = record["at"]
            try:
                self._save()
            except CanaryError as exc:
                if not self._restoring:
                    raise
                self.logger.emit("STATE_WRITE_FAILED_DURING_RECOVERY", reason=exc.reason)
        self.logger.emit(event, **fields)

    def _safe_event(self, event: str, **fields: Any) -> None:
        try:
            self._event(event, **fields)
        except Exception:
            self.logger.emit("PROGRESS_STATE_UPDATE_FAILED", event_name=event)

    def _aws_event(self, event: str, fields: dict[str, Any]) -> None:
        operation = {key: fields.get(key) for key in ("service", "operation") if fields.get(key)}
        if self.state is not None:
            if event == "AWS_API_START":
                self.state["inflight_api_operation"] = operation
                self.state["last_api_operation"] = {**operation, "status": "STARTED"}
            else:
                self.state["inflight_api_operation"] = None
                self.state["last_api_operation"] = {**operation, "status": "FAILED" if event == "AWS_API_FAILED" else "COMPLETE", **({"reason": fields["reason"]} if fields.get("reason") else {})}
        self._event(event, **fields)

    def _phase(self, phase: str, **fields: Any) -> None:
        if self.state is not None:
            self.state["phase"] = phase
        self._event("PHASE", phase=phase, **fields)

    def _save(self) -> None:
        if self.state is not None:
            try:
                _write_state(self.state_path, self.state)
            except CanaryError:
                raise
            except OSError as exc:
                raise CanaryError("STATE_WRITE_FAILED", "Could not persist the private Canary state file") from exc

    def prepare_isolation(self) -> dict[str, Any]:
        if self.state_path.exists() or self.state_path.is_symlink():
            raise CanaryError("STATE_FILE_EXISTS", "Refusing to overwrite an existing Canary snapshot")
        self._event("PREFLIGHT_START", stage="read_only_aws_contract")
        report = inspect_environment(self.aws)
        self._event("PREFLIGHT_COMPLETE", status="PASS")
        run_id = str(uuid.uuid4())
        endpoint_groups = report["resources"]["endpoint_security_group_ids"]
        endpoint_ingress: dict[str, list[dict[str, Any]]] = {}
        groups = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": endpoint_groups}).get("SecurityGroups", [])
        for group in groups:
            endpoint_ingress[group["GroupId"]] = group.get("IpPermissions", [])
        self.state = {
            "schema_version": STATE_VERSION,
            "run_id": run_id,
            "region": REGION,
            "account_id": ACCOUNT_ID,
            "web_instance_id": WEB_ID,
            "web_eni_id": WEB_ENI,
            "web_state_before": "stopped",
            "original_web_sg_ids": report["resources"]["original_web_security_group_ids"],
            "endpoint_sg_ids": endpoint_groups,
            "endpoint_ingress_before": endpoint_ingress,
            "endpoint_sg_rules_before": {
                group.get("GroupId", ""): {
                    "ingress": group.get("IpPermissions", []),
                    "egress": group.get("IpPermissionsEgress", []),
                }
                for group in groups
            },
            "endpoint_ingress_added": [],
            "canary_sg_id": "",
            "started_by_canary": False,
            "phase": "SNAPSHOT_SAVED",
            "events": [],
            "inflight_api_operation": None,
            "report": report,
        }
        self._event("SNAPSHOT_SAVED", state_file=str(self.state_path))  # Durable snapshot precedes the first AWS mutation.
        try:
            self._event("CANARY_SG_CREATE_START")
            created = self.aws.call("ec2", "CreateSecurityGroup", {
                "Description": f"Temporary isolated Web Canary {run_id}",
                "GroupName": f"hospital-dr-web-canary-{run_id[:8]}",
                "VpcId": VPC_ID,
                "TagSpecifications": [{"ResourceType": "security-group", "Tags": [
                    {"Key": "Name", "Value": f"hospital-dr-web-canary-{run_id[:8]}"},
                    {"Key": "Purpose", "Value": "HospitalDR-WebCanary-Isolation"},
                    {"Key": "HospitalDRCanaryRunId", "Value": run_id},
                ]}],
            })
            self.state["canary_sg_id"] = created.get("GroupId", "")
            if not self.state["canary_sg_id"]:
                raise CanaryError("CANARY_SG_CREATE_UNVERIFIED", "CreateSecurityGroup returned no group id")
            self._event("CANARY_SG_CREATED", canary_sg_id=self.state["canary_sg_id"])
            self._phase("CONFIGURE_CANARY_SG")
            self._configure_new_group()
            self._phase("AUTHORIZE_SSM_ENDPOINTS")
            self._authorize_endpoint_groups()
            self._phase("ENDPOINTS_AUTHORIZED")
            self._assert_web_sg_baseline()
            self._phase("REPLACE_WEB_ENI_SECURITY_GROUPS")
            self.aws.call("ec2", "ModifyNetworkInterfaceAttribute", {
                "NetworkInterfaceId": WEB_ENI, "Groups": [self.state["canary_sg_id"]],
            })
            self._phase("WEB_ENI_ISOLATED")
            self._verify_attached_isolation()
            self._phase("ISOLATION_VERIFIED")
            return report
        except BaseException:
            # Best effort restore. If it fails, the private state file remains the recovery source.
            try:
                self.restore()
            except BaseException:
                pass
            raise

    def _assert_web_sg_baseline(self) -> None:
        if self._instance_state() != "stopped":
            raise CanaryError("WEB_STATE_CHANGED_BEFORE_ISOLATION", "Web is no longer stopped before SG replacement")
        rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
        if len(rows) != 1 or not verify_exact_web_eni(rows[0]):
            raise CanaryError("WRONG_ENI_OR_ATTACHMENT", "Web ENI identity changed before SG replacement")
        actual = sorted(item.get("GroupId", "") for item in rows[0].get("Groups", []))
        expected = sorted(self.state["original_web_sg_ids"])
        if actual != expected:
            raise CanaryError("WEB_SG_BASELINE_CHANGED", "Web ENI SG attachments changed after the snapshot; no replacement was made")

    def _configure_new_group(self) -> None:
        group_id = self.state["canary_sg_id"]
        groups = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
        if len(groups) != 1:
            raise CanaryError("CANARY_SG_READBACK_FAILED", "New Canary SG could not be read back")
        group = groups[0]
        if group.get("VpcId") != VPC_ID or group.get("IpPermissions"):
            raise CanaryError("CANARY_SG_UNEXPECTED_INGRESS", "New Canary SG is not empty-ingress")
        for permission in group.get("IpPermissionsEgress", []):
            self.aws.call("ec2", "RevokeSecurityGroupEgress", {
                "GroupId": group_id, "IpPermissions": [_ip_permission(permission)],
            })
        readback = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
        if len(readback) != 1 or readback[0].get("IpPermissionsEgress"):
            raise CanaryError("CANARY_DEFAULT_EGRESS_REMAINS", "Default allow-all egress was not fully removed")
        for endpoint_group in self.state["endpoint_sg_ids"]:
            self.aws.call("ec2", "AuthorizeSecurityGroupEgress", {
                "GroupId": group_id,
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "UserIdGroupPairs": [{"GroupId": endpoint_group}],
                }],
            })
        group = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [None])[0]
        errors = validate_isolation_group(group or {}, set(self.state["endpoint_sg_ids"]))
        if errors:
            raise CanaryError(errors[0], "Canary SG failed the exact ingress/egress readback contract")

    def _authorize_endpoint_groups(self) -> None:
        canary_sg = self.state["canary_sg_id"]
        for endpoint_group in self.state["endpoint_sg_ids"]:
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_group]}).get("SecurityGroups", [])
            if len(current) != 1:
                raise CanaryError("ENDPOINT_SG_READBACK_FAILED", "Endpoint SG could not be read")
            saved = self.state["endpoint_sg_rules_before"].get(endpoint_group, {})
            if (
                _canonical(current[0].get("IpPermissions", [])) != _canonical(saved.get("ingress", []))
                or _canonical(current[0].get("IpPermissionsEgress", [])) != _canonical(saved.get("egress", []))
            ):
                raise CanaryError("ENDPOINT_SG_BASELINE_CHANGED", "Endpoint SG rules changed after the snapshot; no additional rule was applied")
            rules = current[0].get("IpPermissions", [])
            exists = any(_rule_is_group_443(rule, canary_sg) for rule in rules)
            if not exists:
                # Persist intent before mutation so restore can handle a process loss
                # between AuthorizeSecurityGroupIngress and its readback.
                if endpoint_group not in self.state["endpoint_ingress_added"]:
                    self.state["endpoint_ingress_added"].append(endpoint_group)
                    self._save()
                self.aws.call("ec2", "AuthorizeSecurityGroupIngress", {
                    "GroupId": endpoint_group,
                    "IpPermissions": [{
                        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "UserIdGroupPairs": [{"GroupId": canary_sg}],
                    }],
                })
        for endpoint_group in self.state["endpoint_sg_ids"]:
            rules = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_group]}).get("SecurityGroups", [])[0].get("IpPermissions", [])
            if not any(_rule_is_group_443(rule, canary_sg) for rule in rules):
                raise CanaryError("ENDPOINT_SG_INGRESS_NOT_VISIBLE", "Endpoint SG did not read back Canary TCP 443 ingress")

    def _verify_attached_isolation(self) -> None:
        eni = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
        if len(eni) != 1 or eni[0].get("Attachment", {}).get("InstanceId") != WEB_ID:
            raise CanaryError("WRONG_ENI_OR_ATTACHMENT", "Refusing to continue because Web ENI identity changed")
        attached = {item.get("GroupId") for item in eni[0].get("Groups", [])}
        attach_errors = validate_attached_group_set(list(attached), self.state["canary_sg_id"])
        if attach_errors:
            raise CanaryError(attach_errors[0], "Original Web SG remains attached or Canary SG is missing")
        groups = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [self.state["canary_sg_id"]]}).get("SecurityGroups", [])
        if len(groups) != 1:
            raise CanaryError("CANARY_SG_READBACK_FAILED", "Canary SG disappeared during attachment")
        errors = validate_isolation_group(groups[0], set(self.state["endpoint_sg_ids"]))
        if errors:
            raise CanaryError(errors[0], "Attached Canary SG does not meet the isolation contract")
        expected_endpoint_enis = {
            eni_id
            for endpoint in self.state["report"]["resources"].get("ssm_endpoints", [])
            for eni_id in endpoint.get("eni_ids", [])
        }
        current_endpoint_enis = self.aws.call("ec2", "DescribeNetworkInterfaces", {
            "Filters": [{"Name": "group-id", "Values": self.state["endpoint_sg_ids"]}],
        }).get("NetworkInterfaces", [])
        if {row.get("NetworkInterfaceId") for row in current_endpoint_enis} != expected_endpoint_enis:
            raise CanaryError("SSM_ENDPOINT_SG_MEMBERSHIP_CHANGED", "An unexpected ENI now uses the SSM endpoint SG; egress isolation is unverified")
        if any(row.get("Status") != "in-use" for row in current_endpoint_enis):
            raise CanaryError("SSM_ENDPOINT_ENI_NOT_READY", "An SSM endpoint ENI is no longer in use")

    def _instance_state(self) -> str:
        reservations = self.aws.call("ec2", "DescribeInstances", {"InstanceIds": [WEB_ID]}).get("Reservations", [])
        rows = [item for row in reservations for item in row.get("Instances", [])]
        if len(rows) != 1 or rows[0].get("InstanceId") != WEB_ID:
            raise CanaryError("WEB_INSTANCE_READBACK_FAILED", "Could not verify the exact Web instance state")
        return rows[0].get("State", {}).get("Name", "unknown")

    def _poll(self, predicate: Callable[[], bool], timeout: int, reason: str, message: str) -> None:
        wait_started = self.monotonic()
        deadline = min(wait_started + timeout, self.total_deadline)
        if deadline <= self.monotonic():
            raise CanaryError("CANARY_TOTAL_TIMEOUT", "The bounded Canary time budget is exhausted")
        self._event("WAIT_START", wait_for=reason, timeout_seconds=max(0, int(deadline - wait_started)))
        last_progress = wait_started
        while self.monotonic() < deadline:
            if predicate():
                self._event("WAIT_COMPLETE", wait_for=reason, elapsed_seconds=round(self.monotonic() - wait_started, 1))
                return
            now = self.monotonic()
            if now - last_progress >= 30:
                self._event("WAIT_PROGRESS", wait_for=reason, elapsed_seconds=round(now - wait_started, 1), remaining_seconds=max(0, int(deadline - now)))
                last_progress = now
            self.sleep(POLL_SECONDS)
        self._event("WAIT_TIMEOUT", wait_for=reason, elapsed_seconds=round(self.monotonic() - wait_started, 1))
        raise CanaryError(reason, message)

    def start_and_inspect(self) -> dict[str, Any]:
        if not self.state or self.state.get("phase") != "ISOLATION_VERIFIED":
            raise CanaryError("CANARY_ISOLATION_NOT_VERIFIED", "Web start is forbidden before isolated SG readback")
        self._verify_attached_isolation()
        if self._instance_state() != "stopped":
            raise CanaryError("WEB_NOT_STOPPED_BEFORE_START", "Web state changed before Canary start")
        self._phase("START_WEB_EC2")
        self.aws.call("ec2", "StartInstances", {"InstanceIds": [WEB_ID]})
        self.state["started_by_canary"] = True
        self._phase("WEB_START_REQUESTED")
        self._phase("WAIT_WEB_RUNNING")
        self._poll(lambda: self._instance_state() == "running", START_TIMEOUT_SECONDS, "WEB_START_TIMEOUT", "Web did not reach running state")
        self._phase("WAIT_EC2_STATUS_CHECKS")
        self._poll(self._instance_status_ok, START_TIMEOUT_SECONDS, "WEB_STATUS_CHECK_FAILED", "Web EC2 status checks did not become healthy")
        self._phase("WAIT_SSM_ONLINE")
        self._poll(self._ssm_online, SSM_TIMEOUT_SECONDS, "SSM_OFFLINE", "Web did not become SSM Online within the bounded wait")
        self._phase("SSM_ONLINE")
        self._phase("RUN_READ_ONLY_GUEST_AUDIT")
        guest = self._send_readonly_guest_audit()
        self._phase("VERIFY_NAT_ROUTE_READBACK")
        route_state = self._web_nat_route_state()
        if route_state != "active":
            raise CanaryError("WEB_NAT_ROUTE_NOT_ACTIVE", "Web NAT route remained blackhole or did not target the expected ENI")
        self.state["phase"] = "GUEST_AUDIT_COMPLETE"
        self.state["guest_audit"] = guest
        self.state["web_nat_route_state"] = route_state
        self._event("GUEST_AUDIT_COMPLETE", status="PASS", nat_route_state=route_state)
        return {"guest_audit": guest, "web_nat_route_state": route_state}

    def _instance_status_ok(self) -> bool:
        rows = self.aws.call("ec2", "DescribeInstanceStatus", {"InstanceIds": [WEB_ID], "IncludeAllInstances": True}).get("InstanceStatuses", [])
        return len(rows) == 1 and rows[0].get("InstanceStatus", {}).get("Status") == "ok" and rows[0].get("SystemStatus", {}).get("Status") == "ok"

    def _ssm_online(self) -> bool:
        rows = self.aws.call("ssm", "DescribeInstanceInformation", {"Filters": [{"Key": "InstanceIds", "Values": [WEB_ID]}]}).get("InstanceInformationList", [])
        return any(row.get("InstanceId") == WEB_ID and row.get("PingStatus") == "Online" for row in rows)

    @staticmethod
    def _guest_audit_command() -> str:
        return r'''set -eu
token=$(curl --fail --silent --show-error --max-time 3 -X PUT http://AWS_PUBLIC_IP_REDACTED/latest/api/token -H X-aws-ec2-metadata-token-ttl-seconds:60)
trap 'unset token' EXIT
iid=$(curl --fail --silent --show-error --max-time 3 -H "X-aws-ec2-metadata-token: $token" http://AWS_PUBLIC_IP_REDACTED/latest/meta-data/instance-id)
ip=$(curl --fail --silent --show-error --max-time 3 -H "X-aws-ec2-metadata-token: $token" http://AWS_PUBLIC_IP_REDACTED/latest/meta-data/local-ipv4)
test "$iid" = AWS_RESOURCE_ID_REDACTED && test "$ip" = AWS_PUBLIC_IP_REDACTED
printf 'CANARY_GUEST_AUDIT=PASS\nIMDS_INSTANCE_MATCH=PASS\n'
printf 'ACTIVE_RELEVANT_SERVICES='
systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -Ei 'cloudflared|wireguard|wg-quick|hospital-(dr|web|emr)|docker|nginx|node|apache' | paste -sd, - || true
printf 'ENABLED_RELEVANT_SERVICES='
systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -Ei 'cloudflared|wireguard|wg-quick|hospital-(dr|web|emr)|docker|nginx|node|apache' | paste -sd, - || true
printf 'ENABLED_TIMER_COUNT='
systemctl list-unit-files --type=timer --state=enabled --no-legend --no-pager 2>/dev/null | awk 'END {print NR+0}'
printf 'SCHEDULED_TIMER_COUNT='
systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk 'END {print NR+0}'
printf 'CRON_ACTIVE_JOB_COUNT='
while IFS=: read -r user _; do crontab -l -u "$user" 2>/dev/null || true; done < /etc/passwd | awk '!/^[[:space:]]*(#|$)/ {n++} END {print n+0}'
printf 'CRON_FILE_COUNT='
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f ! -name .placeholder 2>/dev/null | awk 'END {print NR+0}'
printf 'DOCKER_CONTAINER_COUNT='
docker ps -q 2>/dev/null | awk 'END {print NR+0}'
printf 'DOCKER_CONTAINER_STATES='
docker ps -aq 2>/dev/null | xargs -r docker inspect --format '{{.Name}}={{.State.Status}}|restart={{.HostConfig.RestartPolicy.Name}}' 2>/dev/null | paste -sd, - || true
if pgrep -x cloudflared >/dev/null 2>&1; then echo CLOUDFLARED_PROCESS=PRESENT; else echo CLOUDFLARED_PROCESS=ABSENT; fi
if pgrep -x wg-quick >/dev/null 2>&1 || ip link show type wireguard 2>/dev/null | grep -q wireguard; then echo WIREGUARD_RUNTIME=PRESENT; else echo WIREGUARD_RUNTIME=ABSENT; fi
printf 'ESTABLISHED_MYSQL_CONNECTION_COUNT='
ss -Htn state established '( dport = :3306 or sport = :3306 )' 2>/dev/null | awk 'END {print NR+0}'
printf 'IP_FORWARD='
sysctl -n net.ipv4.ip_forward 2>/dev/null || echo UNKNOWN
printf 'DR_NAT_CHAIN_RULE_COUNT='
(iptables-save -t nat 2>/dev/null || true) | awk '/HOSPITAL-DR-NAT/ {n++} END {print n+0}'
printf 'DR_NAT_CHAIN_SUMMARY='
(iptables-save -t nat 2>/dev/null || true) | awk '/^:HOSPITAL-DR-NAT/ {printf "%s ", $1} /^-A .*HOSPITAL-DR-NAT/ {n++} END {printf "rules=%d", n+0}'
'''

    def _send_readonly_guest_audit(self) -> dict[str, str]:
        if self.monotonic() >= self.total_deadline:
            raise CanaryError("CANARY_TOTAL_TIMEOUT", "The bounded Canary time budget is exhausted before guest inspection")
        self._event("SSM_GUEST_AUDIT_START", command_timeout_seconds=COMMAND_TIMEOUT_SECONDS)
        sent = self.aws.call("ssm", "SendCommand", {
            "InstanceIds": [WEB_ID],
            "DocumentName": "AWS-RunShellScript",
            "TimeoutSeconds": 180,
            "Parameters": {"commands": [self._guest_audit_command()]},
            "Comment": "Hospital DR isolated Web Canary read-only inspection",
        })
        command_id = sent.get("Command", {}).get("CommandId", "")
        if not command_id:
            raise CanaryError("SSM_COMMAND_NOT_ACCEPTED", "SSM did not return a command id")
        invocation: dict[str, Any] = {}
        command_started = self.monotonic()
        deadline = min(command_started + COMMAND_TIMEOUT_SECONDS, self.total_deadline)
        last_progress = command_started
        while self.monotonic() < deadline:
            try:
                invocation = self.aws.call("ssm", "GetCommandInvocation", {"CommandId": command_id, "InstanceId": WEB_ID})
            except CanaryError:
                invocation = {}
            status = invocation.get("Status")
            if status in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
                break
            now = self.monotonic()
            if now - last_progress >= 30:
                self._event("SSM_COMMAND_PROGRESS", elapsed_seconds=round(now - command_started, 1), remaining_seconds=max(0, int(deadline - now)), status="IN_PROGRESS")
                last_progress = now
            self.sleep(POLL_SECONDS)
        if invocation.get("Status") != "Success":
            self._event("SSM_GUEST_AUDIT_FAILED", reason="SSM_GUEST_AUDIT_FAILED", command_status=invocation.get("Status", "UNKNOWN"))
            raise CanaryError("SSM_GUEST_AUDIT_FAILED", "Read-only guest inspection did not complete successfully")
        stdout = invocation.get("StandardOutputContent", "")
        safe: dict[str, str] = {}
        allowed = {
            "CANARY_GUEST_AUDIT", "IMDS_INSTANCE_MATCH", "ACTIVE_RELEVANT_SERVICES",
            "ENABLED_RELEVANT_SERVICES",
            "ENABLED_TIMER_COUNT", "SCHEDULED_TIMER_COUNT", "CRON_ACTIVE_JOB_COUNT",
            "CRON_FILE_COUNT", "DOCKER_CONTAINER_COUNT", "DOCKER_CONTAINER_STATES",
            "CLOUDFLARED_PROCESS", "WIREGUARD_RUNTIME", "ESTABLISHED_MYSQL_CONNECTION_COUNT",
            "IP_FORWARD", "DR_NAT_CHAIN_RULE_COUNT", "DR_NAT_CHAIN_SUMMARY",
        }
        for line in stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in allowed and len(value) <= 1024 and "\n" not in value:
                safe[key] = value
        if safe.get("CANARY_GUEST_AUDIT") != "PASS" or safe.get("IMDS_INSTANCE_MATCH") != "PASS":
            raise CanaryError("GUEST_IDENTITY_OR_AUDIT_INVALID", "Read-only guest audit did not prove the expected Web identity")
        self._event("SSM_GUEST_AUDIT_COMPLETE", status="PASS")
        return safe

    def _web_nat_route_state(self) -> str:
        tables = self.aws.call("ec2", "DescribeRouteTables", {"Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}]}).get("RouteTables", [])
        # The route table is associated with EMR/DB subnets; require exact route targets.
        expected_table = "AWS_RESOURCE_ID_REDACTED"
        table = next((item for item in tables if item.get("RouteTableId") == expected_table), None)
        if not table:
            return "missing"
        return classify_nat_routes(table)

    def stop_web(self) -> None:
        state = self._instance_state()
        if state == "stopped":
            self._event("WEB_ALREADY_STOPPED")
            return
        if state in {"running", "pending"}:
            self._event("WEB_STOP_REQUEST_START", previous_state=state)
            self.aws.call("ec2", "StopInstances", {"InstanceIds": [WEB_ID]})
        elif state not in {"stopping"}:
            raise CanaryError("WEB_STOP_STATE_UNSUPPORTED", f"Web is in unexpected state {state}; isolation retained")
        # Cleanup has its own reserved portion of the 30-minute total budget.
        deadline = self.monotonic() + self.cleanup_budget
        wait_started = self.monotonic()
        last_progress = wait_started
        self._event("WAIT_WEB_STOPPED", timeout_seconds=self.cleanup_budget)
        while self.monotonic() < deadline:
            if self._instance_state() == "stopped":
                self._event("WEB_STOPPED", elapsed_seconds=round(self.monotonic() - wait_started, 1))
                return
            now = self.monotonic()
            if now - last_progress >= 30:
                self._event("WEB_STOP_PROGRESS", elapsed_seconds=round(now - wait_started, 1), remaining_seconds=max(0, int(deadline - now)))
                last_progress = now
            self.sleep(min(POLL_SECONDS, max(0, deadline - self.monotonic())))
        self._event("WEB_STOP_TIMEOUT", reason="WEB_STOP_TIMEOUT")
        raise CanaryError("WEB_STOP_TIMEOUT", "Web did not stop; Canary SG remains attached")

    def _verify_restored_baseline(self) -> list[str]:
        mismatches: list[str] = []
        reservations = self.aws.call("ec2", "DescribeInstances", {"InstanceIds": [WEB_ID]}).get("Reservations", [])
        instances = [item for reservation in reservations for item in reservation.get("Instances", [])]
        if len(instances) != 1 or instances[0].get("State", {}).get("Name") != "stopped":
            mismatches.append("WEB_NOT_STOPPED")
        elif (
            instances[0].get("VpcId") != VPC_ID
            or instances[0].get("SubnetId") != WEB_SUBNET
            or instances[0].get("PrivateIpAddress") != WEB_PRIVATE_IP
        ):
            mismatches.append("WEB_INSTANCE_IDENTITY_DRIFT")
        interfaces = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
        if len(interfaces) != 1 or not verify_exact_web_eni(interfaces[0]):
            mismatches.append("WEB_ENI_IDENTITY_DRIFT")
        elif (
            interfaces[0].get("Association", {}).get("PublicIp") != WEB_EIP
            or bool(interfaces[0].get("SourceDestCheck")) != bool(self.state["report"]["resources"].get("source_dest_check"))
            or sorted(item.get("GroupId", "") for item in interfaces[0].get("Groups", [])) != sorted(self.state["original_web_sg_ids"])
        ):
            mismatches.append("WEB_ENI_BASELINE_DRIFT")

        original_web_rules = self.state["report"]["resources"].get("web_sg_rule_snapshot", [])
        original_web_rule_ids = [row.get("group_id", "") for row in original_web_rules]
        if original_web_rule_ids:
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": original_web_rule_ids}).get("SecurityGroups", [])
            actual = [
                {"group_id": row.get("GroupId", ""), "ingress": row.get("IpPermissions", []), "egress": row.get("IpPermissionsEgress", [])}
                for row in current
            ]
            if _canonical(actual) != _canonical(original_web_rules):
                mismatches.append("ORIGINAL_WEB_SG_RULE_DRIFT")

        route_ids = {
            self.state["report"]["resources"].get("web_route_table_snapshot", {}).get("route_table_id", ""),
            self.state["report"]["resources"].get("private_nat_route_table_snapshot", {}).get("route_table_id", ""),
        } - {""}
        if route_ids:
            tables = self.aws.call("ec2", "DescribeRouteTables", {"RouteTableIds": sorted(route_ids)}).get("RouteTables", [])
            actual_routes = {row.get("RouteTableId"): _route_table_snapshot(row) for row in tables}
            for snapshot_key in ("web_route_table_snapshot", "private_nat_route_table_snapshot"):
                saved = self.state["report"]["resources"].get(snapshot_key, {})
                if saved and _canonical(actual_routes.get(saved.get("route_table_id"), {})) != _canonical(saved):
                    mismatches.append("ROUTE_TABLE_DRIFT")

        for group_id, saved_rules in self.state.get("endpoint_sg_rules_before", {}).items():
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
            if (
                len(current) != 1
                or _canonical(current[0].get("IpPermissions", [])) != _canonical(saved_rules.get("ingress", []))
                or _canonical(current[0].get("IpPermissionsEgress", [])) != _canonical(saved_rules.get("egress", []))
            ):
                mismatches.append("ENDPOINT_SG_INGRESS_DRIFT")
                break
        return sorted(set(mismatches))

    def restore(self) -> dict[str, Any]:
        self._restoring = True
        if self.state is None:
            self.state = _read_state(self.state_path)
        if self.state.get("phase") == "RESTORED":
            self._event("RESTORE_ALREADY_COMPLETE", status="RESTORED")
            return {"phase": "RESTORED", "web_security_groups": self.state.get("original_web_sg_ids", []), "canary_security_group_deleted": True}
        self._event("RESTORE_BEGIN", prior_phase=self.state.get("phase", "UNKNOWN"))
        identity = self.aws.call("sts", "GetCallerIdentity")
        if identity.get("Account") != ACCOUNT_ID:
            raise CanaryError("RESTORE_ACCOUNT_MISMATCH", "Refusing to restore against a different AWS account")
        canary_sg = self.state.get("canary_sg_id", "")
        if not canary_sg:
            # Recover the narrow crash window after CreateSecurityGroup succeeded
            # but before its response was persisted; the run-id tag is unique.
            tagged = self.aws.call("ec2", "DescribeSecurityGroups", {
                "Filters": [{"Name": "tag:HospitalDRCanaryRunId", "Values": [self.state.get("run_id", "")]}],
            }).get("SecurityGroups", []) if self.state.get("run_id") else []
            if len(tagged) == 1:
                canary_sg = tagged[0].get("GroupId", "")
                self.state["canary_sg_id"] = canary_sg
                self._save()
            elif len(tagged) > 1:
                raise CanaryError("RESTORE_CANARY_SG_AMBIGUOUS", "Multiple Canary SGs match the saved run id; manual review required")
            else:
                self.state["phase"] = "RESTORE_INCOMPLETE_NO_CANARY_SG_ID"
                self._save()
                raise CanaryError("RESTORE_CANARY_SG_ID_MISSING", "No Canary SG readback matched the saved run id; retry read-only discovery before declaring cleanup complete")
        if not re.fullmatch(r"sg-[0-9a-f]+", str(canary_sg)):
            raise CanaryError("RESTORE_CANARY_SG_ID_INVALID", "Saved Canary SG id is malformed")
        self._phase("RESTORE_STOP_WEB")
        self.stop_web()
        # Never overwrite a concurrent/unexpected SG attachment change.
        eni = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
        if len(eni) != 1 or not verify_exact_web_eni(eni[0]):
            self.state["phase"] = "RESTORE_WEB_ENI_IDENTITY_MISMATCH"
            self._save()
            raise CanaryError("RESTORE_WEB_ENI_IDENTITY_MISMATCH", "Web ENI identity changed; no SG replacement was made")
        actual_groups_before = sorted(row.get("GroupId", "") for row in eni[0].get("Groups", []))
        original_groups = sorted(self.state["original_web_sg_ids"])
        if actual_groups_before == [canary_sg]:
            self._phase("RESTORE_WEB_ENI_SECURITY_GROUPS")
            self.aws.call("ec2", "ModifyNetworkInterfaceAttribute", {
                "NetworkInterfaceId": WEB_ENI,
                "Groups": self.state["original_web_sg_ids"],
            })
        elif actual_groups_before != original_groups:
            self.state["phase"] = "RESTORE_WEB_SG_EXTERNAL_DRIFT"
            self.state["actual_web_sg_ids_at_restore"] = actual_groups_before
            self._save()
            raise CanaryError("RESTORE_WEB_SG_EXTERNAL_DRIFT", "Web ENI SG set changed unexpectedly; no further SG modifications were made")
        eni = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
        actual_groups = sorted(row.get("GroupId", "") for row in (eni[0].get("Groups", []) if len(eni) == 1 else []))
        if actual_groups != original_groups:
            self.state["phase"] = "RESTORE_WEB_SG_FAILED"
            self._save()
            raise CanaryError("RESTORE_WEB_SG_FAILED", "Original Web ENI SG attachment did not read back; Canary SG retained")
        canary_rules_remaining: list[str] = []
        self._phase("RESTORE_SSM_ENDPOINT_SECURITY_GROUP_RULES")
        for endpoint_group in self.state.get("endpoint_ingress_added", []):
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_group]}).get("SecurityGroups", [])
            if len(current) != 1:
                canary_rules_remaining.append(endpoint_group)
                continue
            for rule in current[0].get("IpPermissions", []):
                if _rule_is_group_443(rule, canary_sg):
                    self.aws.call("ec2", "RevokeSecurityGroupIngress", {
                        "GroupId": endpoint_group,
                        "IpPermissions": [{
                            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                            "UserIdGroupPairs": [{"GroupId": canary_sg}],
                        }],
                    })
            verify = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_group]}).get("SecurityGroups", [])
            original_ingress = self.state.get("endpoint_ingress_before", {}).get(endpoint_group, [])
            if (
                len(verify) != 1
                or has_group_tcp443_rule(verify[0], canary_sg)
                or _canonical(verify[0].get("IpPermissions", [])) != _canonical(original_ingress)
            ):
                canary_rules_remaining.append(endpoint_group)
        if canary_rules_remaining:
            self.state["phase"] = "RESTORE_ENDPOINT_SG_FAILED"
            self.state["endpoint_restore_failures"] = canary_rules_remaining
            self._save()
            raise CanaryError("RESTORE_ENDPOINT_SG_FAILED", "Canary source rule remains; state retained for retry")
        self._phase("VERIFY_RESTORED_BASELINE")
        mismatches = self._verify_restored_baseline()
        if mismatches:
            self.state["phase"] = "RESTORE_BASELINE_MISMATCH"
            self.state["restore_mismatches"] = mismatches
            self._save()
            raise CanaryError("RESTORE_BASELINE_MISMATCH", "Saved AWS readback differs from the pre-Canary snapshot; Canary SG retained")
        attached = self.aws.call("ec2", "DescribeNetworkInterfaces", {"Filters": [{"Name": "group-id", "Values": [canary_sg]}]}).get("NetworkInterfaces", [])
        if attached:
            self.state["phase"] = "RESTORE_CANARY_SG_STILL_ATTACHED"
            self._save()
            raise CanaryError("RESTORE_CANARY_SG_STILL_ATTACHED", "Canary SG remains attached to an ENI; it was not deleted")
        existing = self.aws.call("ec2", "DescribeSecurityGroups", {"Filters": [{"Name": "group-id", "Values": [canary_sg]}]}).get("SecurityGroups", [])
        if len(existing) > 1:
            raise CanaryError("RESTORE_CANARY_SG_AMBIGUOUS", "More than one SG matched the Canary group id")
        if existing:
            self._phase("DELETE_TEMPORARY_CANARY_SG")
            self.aws.call("ec2", "DeleteSecurityGroup", {"GroupId": canary_sg})
        self.state["phase"] = "RESTORED"
        self.state["restored_at_epoch"] = int(time.time())
        self._event("RESTORE_COMPLETE", status="RESTORED", web_state="stopped")
        return {"phase": "RESTORED", "web_security_groups": actual_groups, "canary_security_group_deleted": True}


def run_canary(canary: AwsWebCanary) -> dict[str, Any]:
    """Lifecycle controller; cleanup runs after start, SSM, audit, or route failures."""
    result: dict[str, Any] = {"status": "BLOCKED", "phase": "PREPARE"}
    interrupted = False
    canary._event("CANARY_RUN_BEGIN", max_minutes=getattr(canary, "max_minutes", "unknown"))
    try:
        canary.prepare_isolation()
        canary.start_and_inspect()
        result = {"status": "PASS", "phase": "GUEST_AUDIT_COMPLETE"}
        canary._event("CANARY_INSPECTION_COMPLETE", status="PASS")
    except KeyboardInterrupt:
        interrupted = True
        result = {"status": "BLOCKED", "phase": "INTERRUPTED", "interrupted": True}
        canary._safe_event("CANARY_INTERRUPTED", reason="OPERATOR_INTERRUPT")
    except CanaryError as exc:
        result = {"status": "BLOCKED", "phase": exc.reason}
        canary._safe_event("CANARY_FAILED", reason=exc.reason)
    except Exception as exc:
        result = {"status": "BLOCKED", "phase": "UNEXPECTED_ERROR"}
        canary._safe_event("CANARY_FAILED", reason="UNEXPECTED_ERROR", error_type=type(exc).__name__)
    finally:
        # If StartInstances was accepted but start_and_inspect failed early, inspect state and stop anyway.
        if canary.state:
            previous_handlers: dict[int, Any] = {}
            # Once cleanup starts, a second operator signal must not interrupt
            # the stop-and-restore sequence. The main lifecycle handler still
            # turns SIGTERM into KeyboardInterrupt before this point, so the
            # original failure remains visible.
            for signum in (signal.SIGINT, signal.SIGTERM):
                try:
                    previous_handlers[signum] = signal.signal(signum, signal.SIG_IGN)
                except Exception:
                    # run_canary can be invoked outside the main thread. Keep
                    # any earlier signal-handler changes so they are restored.
                    continue
            try:
                canary._safe_event("CLEANUP_BEGIN", prior_phase=canary.state.get("phase", "UNKNOWN"))
                restored = canary.restore()
                result["cleanup"] = restored["phase"]
                canary._safe_event("CLEANUP_COMPLETE", status=restored["phase"])
            except CanaryError as exc:
                result["cleanup"] = exc.reason
                result["status"] = "BLOCKED"
                canary._safe_event("CLEANUP_FAILED", reason=exc.reason)
            except Exception as exc:
                result["cleanup"] = "RESTORE_UNEXPECTED_ERROR"
                result["status"] = "BLOCKED"
                canary._safe_event("CLEANUP_FAILED", reason="RESTORE_UNEXPECTED_ERROR", error_type=type(exc).__name__)
            finally:
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
    if interrupted:
        result["interrupted"] = True
    canary._event("CANARY_RUN_COMPLETE", **result)
    return result


def _render_check(report: dict[str, Any]) -> str:
    rows = ["AWS_WEB_CANARY_PREFLIGHT=READ_ONLY"]
    for key, value in sorted(report.get("checks", {}).items()):
        rows.append(f"{key.upper()}={value}")
    rows.append("CURRENT_AWS_STATE_UNCHANGED=YES")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--aws-read-only", action="store_true", help="read AWS state and print Canary readiness only")
    mode.add_argument("--run-canary", action="store_true", help="MUTATING: create/attach isolation SG, start Web, inspect, stop and restore")
    mode.add_argument("--restore", action="store_true", help="MUTATING recovery: stop Web, restore saved SG attachments, remove only Canary rules/group")
    parser.add_argument("--state-file", type=Path, help="absolute path in a private mode-0700 directory; required for run/restore")
    parser.add_argument("--log-file", type=Path, help="private 0600 JSONL progress log; defaults beside --state-file in mutating modes")
    parser.add_argument("--confirm-web-id", default="", help="must equal the exact Web instance id for a mutating mode")
    parser.add_argument("--max-minutes", type=int, default=30, help="Canary execution limit (1..30 minutes)")
    args = parser.parse_args(argv)
    if not 1 <= args.max_minutes <= 30:
        parser.error("--max-minutes must be between 1 and 30")
    if args.run_canary or args.restore:
        if not args.state_file or not args.state_file.is_absolute():
            parser.error("mutating modes require an absolute --state-file")
        if args.confirm_web_id != WEB_ID:
            parser.error("mutating modes require --confirm-web-id to match the approved Web instance")
    try:
        if args.restore or args.run_canary:
            log_path = args.log_file or args.state_file.with_suffix(".log")
            with ExecutionLock() as execution_lock:
                logger = EventLogger(log_path, append=args.restore)
                aws = AwsCli()
                aws.lock_fd = execution_lock.fd
                canary = AwsWebCanary(aws, args.state_file, logger=logger, max_minutes=args.max_minutes)
                previous_sigterm = None
                try:
                    if args.restore:
                        logger.emit("RECOVERY_REQUESTED", state_file=str(args.state_file))
                        try:
                            result = canary.restore()
                        except CanaryError as exc:
                            logger.emit("RECOVERY_FAILED", reason=exc.reason)
                            raise
                        logger.emit("RECOVERY_COMPLETE", **result)
                        return 0
                    started_at = time.monotonic()
                    try:
                        previous_sigterm = signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
                    except ValueError:
                        previous_sigterm = None
                    result = run_canary(canary)
                    result["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
                    result["state_file"] = str(args.state_file)
                    result["log_file"] = str(log_path)
                    result["log_write_failed"] = logger.write_failed
                    exit_code = 130 if result.get("interrupted") else (0 if result.get("status") == "PASS" and result.get("cleanup") == "RESTORED" else 1)
                    logger.emit("CANARY_FINAL_RESULT", canary_exit=exit_code, **result)
                    print("CANARY_EXIT=" + str(exit_code), flush=True)
                    return exit_code
                finally:
                    if previous_sigterm is not None:
                        signal.signal(signal.SIGTERM, previous_sigterm)
                    logger.close()
        if args.aws_read_only:
            aws = AwsCli()
            print(json.dumps(inspect_environment(aws), ensure_ascii=True, indent=2, sort_keys=True))
            return 0
        print("OFFLINE_MODE=NO_AWS_REQUESTS")
        print("MUTATING_MODE=NOT_SELECTED")
        return 0
    except CanaryError as exc:
        print(f"AWS_WEB_CANARY=BLOCKED reason={exc.reason}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
