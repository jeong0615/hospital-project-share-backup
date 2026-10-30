#!/usr/bin/env python3
"""Isolated Web NAT + EMR egress Canary transaction.

The default mode is offline. --aws-read-only performs only Describe/List/Get
calls plus read-only SSM probes. Only --run-canary mutates temporary
security groups/ENI attachments and starts Web/EMR; it never changes routes,
the database, DNS, a production DR state, or a failover request. --restore
is an independent, state-bound recovery entry point.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import fcntl
import ipaddress
import io
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from operations.preflight.aws_web_canary_isolation import (  # noqa: E402
    ACCOUNT_ID,
    DB_SG,
    OPTIONAL_SSM_SERVICES,
    PRIVATE_ROUTE_TABLE_ID,
    REGION,
    SSM_POLICY_ARN,
    SSM_SERVICES,
    VPC_CIDR,
    VPC_ID,
    WEB_EIP,
    WEB_ENI,
    WEB_ID,
    WEB_PRIVATE_IP,
    WEB_SUBNET,
    AwsCli,
    CanaryError,
    EventLogger,
    ExecutionLock,
    _canonical,
    _acl_allows_port_range,
    _acl_for_subnet,
    _effective_acl_action,
    _ip_permission,
    _route_table_snapshot,
    _rule_is_group_443,
    _secure_state_parent,
    _write_state,
    classify_nat_routes,
    inspect_environment as inspect_web_environment,
)

EMR_ID = "AWS_RESOURCE_ID_REDACTED"
EMR_ENI = "AWS_RESOURCE_ID_REDACTED"
EMR_SUBNET = "AWS_RESOURCE_ID_REDACTED"
EMR_PRIVATE_IP = "IP_REDACTED"
EMR_HOST_CIDR = f"{EMR_PRIVATE_IP}/32"
EMR_ORIGINAL_SG = "AWS_RESOURCE_ID_REDACTED"
WEB_ORIGINAL_SG = "AWS_RESOURCE_ID_REDACTED"
DB_ID = "AWS_RESOURCE_ID_REDACTED"
DB_ENI = "AWS_RESOURCE_ID_REDACTED"
DB_SUBNET = "AWS_RESOURCE_ID_REDACTED"
DB_PRIVATE_IP = "IP_REDACTED"
DB_NAME_TAG = "Hospital-DR-DB-Server"
WEB_NAME_TAG = "Hospital-Real-Web-Server"
EMR_NAME_TAG = "Hospital-DR-Doc-Server"
DB_UUID = "a7988d84-5be8-11f1-bb28-0a4b1b977fad"
DB_SERVER_ID = 20
EXPECTED_WEB_EIP = "AWS_PUBLIC_IP_REDACTED"
PROBE_HOST = "checkip.amazonaws.com"
NAT_STATUS_SCRIPT = REPO_ROOT / "operations/nat_instance/web_nat_instance_status.sh"
NAT_APPLY_PLAYBOOK = REPO_ROOT / "automation/ansible/aws_web_nat_instance.yml"
NAT_RESTORE_PLAYBOOK = REPO_ROOT / "automation/ansible/aws_web_nat_instance_disable.yml"
ANSIBLE_CONFIG = REPO_ROOT / "automation/ansible/ansible.cfg"
STATE_VERSION = 1
CLI_TIMEOUT_SECONDS = 20
START_TIMEOUT_SECONDS = 360
SSM_TIMEOUT_SECONDS = 600
COMMAND_TIMEOUT_SECONDS = 180
STOP_TIMEOUT_SECONDS = 300
NAT_ROLE_TIMEOUT_SECONDS = 300
POLL_SECONDS = 10
MAX_MINUTES = 30
CLEANUP_RESERVE_SECONDS = 900
READ_ONLY_REQUIRED_CHECKS = (
    "web_identity", "emr_identity", "db_identity", "web_emr_stopped", "db_running",
    "db_read_only", "web_emr_original_sg", "web_eip_and_source_dest",
    "ssm_endpoints_and_profiles", "nacl_paths", "nat_route_target",
    "dns_firewall_walled_garden",
)
WEB_READ_ONLY_REQUIRED_CHECKS = (
    "account", "web_identity", "web_stopped", "vpc_dns", "ssm_endpoints",
    "ssm_private_dns", "web_ingress_unchanged", "endpoint_route_nacl",
    "web_ssm_instance_policy",
)
NAT_BASELINE_FILE = "/var/lib/hospital-dr-web-nat-instance/baseline.json"
NAT_BASELINE_DIR = "/var/lib/hospital-dr-web-nat-instance"
ALLOWED_DNS_NAMES = {
    f"ssm.{REGION}.amazonaws.com",
    f"ssmmessages.{REGION}.amazonaws.com",
    PROBE_HOST,
}
DNS_ISOLATION_STRICT = "strict"
DNS_ISOLATION_CONSTRAINED_EGRESS = "constrained-egress"
DNS_ISOLATION_MODES = {DNS_ISOLATION_STRICT, DNS_ISOLATION_CONSTRAINED_EGRESS}
CONSTRAINED_EGRESS_CONFIRMATION = "CONSTRAINED_EGRESS_REVIEWED"
RELEVANT_SERVICE_RE = re.compile(
    r"(cloudflared|wireguard|wg-quick|hospital-(web|emr|dr)|docker|nginx|apache|node|pm2|mysql|mariadb)",
    re.IGNORECASE,
)
SAFE_ACTIVE_SERVICES = {
    "docker.service", "nginx.service", "apache2.service", "ssh.service",
    "cron.service", "amazon-ssm-agent.service",
    "snap.amazon-ssm-agent.amazon-ssm-agent.service", "systemd-networkd.service",
    "systemd-resolved.service",
}


class NatEmrCanaryError(CanaryError):
    pass


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise NatEmrCanaryError(code, message)


def _target_instance(rows: list[dict[str, Any]], *, instance_id: str, name: str,
                     subnet_id: str, private_ip: str, eni_id: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get("InstanceId") == instance_id]
    _require(len(matches) == 1, "INSTANCE_IDENTITY_NOT_UNIQUE", f"Expected one exact instance {instance_id}")
    row = matches[0]
    tags = {item.get("Key"): item.get("Value") for item in row.get("Tags", [])}
    enis = row.get("NetworkInterfaces", [])
    _require(
        tags.get("Name") == name
        and row.get("VpcId") == VPC_ID
        and row.get("SubnetId") == subnet_id
        and row.get("PrivateIpAddress") == private_ip
        and len(enis) == 1
        and enis[0].get("NetworkInterfaceId") == eni_id,
        "INSTANCE_IDENTITY_MISMATCH",
        f"Instance identity does not match the pinned {name} contract",
    )
    return row


def _expected_service_groups(endpoints: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for endpoint in endpoints:
        by_name.setdefault(str(endpoint.get("ServiceName", "")), []).append(endpoint)
    required = SSM_SERVICES
    _require(required.issubset(by_name), "SSM_ENDPOINT_SET_INCOMPLETE", "Required SSM interface endpoints are absent")
    selected = required | (OPTIONAL_SSM_SERVICES & set(by_name))
    _require(all(len(by_name.get(service, [])) == 1 for service in selected),
             "SSM_ENDPOINT_SET_AMBIGUOUS", "An SSM endpoint is missing or duplicated")
    endpoint_sgs: set[str] = set()
    endpoint_enis: set[str] = set()
    for service in selected:
        endpoint = by_name[service][0]
        _require(endpoint.get("State") == "available" and endpoint.get("PrivateDnsEnabled") is True
                 and endpoint.get("VpcId") == VPC_ID,
                 "SSM_ENDPOINT_NOT_READY", "SSM endpoint is not available with private DNS")
        endpoint_sgs.update(group.get("GroupId", "") for group in endpoint.get("Groups", []))
        endpoint_enis.update(endpoint.get("NetworkInterfaceIds", []))
    _require(bool(endpoint_sgs) and bool(endpoint_enis), "SSM_ENDPOINT_NETWORK_MISSING",
             "SSM endpoint has no security group or ENI")
    return endpoint_sgs, endpoint_enis


def _paginate(aws: AwsCli, service: str, operation: str, key: str,
              payload: dict[str, Any] | None = None) -> list[Any]:
    items: list[Any] = []
    request = dict(payload or {})
    while True:
        response = aws.call(service, operation, request)
        items.extend(response.get(key, []))
        token = response.get("NextToken")
        if not token:
            return items
        request["NextToken"] = token


def validate_dns_firewall(associations: list[dict[str, Any]], rules: list[dict[str, Any]],
                          domains_by_list: dict[str, list[str]], firewall_configs: list[dict[str, Any]],
                          *, vpc_id: str = VPC_ID, required_domains: set[str] = ALLOWED_DNS_NAMES) -> list[str]:
    """Require a fail-closed DNS walled garden: only SSM and the one probe host."""
    errors: list[str] = []
    vpc_associations = [row for row in associations if row.get("VpcId") == vpc_id]
    if len(vpc_associations) != 1 or vpc_associations[0].get("Status") != "COMPLETE":
        errors.append("DNS_FIREWALL_ASSOCIATION_NOT_UNIQUE_COMPLETE")
        return errors
    configs = [row for row in firewall_configs if row.get("ResourceId") == vpc_id]
    if len(configs) != 1 or configs[0].get("FirewallFailOpen") != "DISABLED":
        errors.append("DNS_FIREWALL_FAIL_OPEN_OR_CONFIG_UNVERIFIED")
    if not vpc_associations[0].get("FirewallRuleGroupId") or not rules:
        errors.append("DNS_FIREWALL_RULES_UNVERIFIED")
        return errors
    allow_domains: set[str] = set()
    catchall_priorities: list[int] = []
    allow_priorities: list[int] = []
    for rule in rules:
        if rule.get("Status") not in (None, "COMPLETE"):
            errors.append("DNS_FIREWALL_RULE_NOT_COMPLETE")
            continue
        action = rule.get("Action")
        domain_list_id = rule.get("FirewallDomainListId")
        domain_list = {str(name).rstrip(".").lower() for name in domains_by_list.get(str(domain_list_id), [])}
        try:
            priority = int(rule.get("Priority"))
        except (TypeError, ValueError):
            errors.append("DNS_FIREWALL_PRIORITY_INVALID")
            continue
        if action == "ALLOW":
            allow_priorities.append(priority)
            allow_domains.update(domain_list)
            if not domain_list or any(name.startswith("*") for name in domain_list):
                errors.append("DNS_FIREWALL_ALLOW_RULE_TOO_BROAD")
        elif action == "BLOCK" and domain_list == {"*"}:
            catchall_priorities.append(priority)
        else:
            errors.append("DNS_FIREWALL_UNEXPECTED_RULE")
    if allow_domains != {name.lower() for name in required_domains}:
        errors.append("DNS_FIREWALL_ALLOWLIST_MISMATCH")
    if len(catchall_priorities) != 1 or not allow_priorities:
        errors.append("DNS_FIREWALL_CATCHALL_BLOCK_MISSING")
    elif max(allow_priorities) >= catchall_priorities[0]:
        errors.append("DNS_FIREWALL_RULE_ORDER_INVALID")
    return sorted(set(errors))


def _dns_isolation_assessment(mode: str, firewall_errors: list[str]) -> dict[str, Any]:
    """Describe DNS limits without treating SG/NACL egress rules as DNS filtering."""
    _require(mode in DNS_ISOLATION_MODES, "DNS_ISOLATION_MODE_INVALID",
             "DNS isolation mode is not supported")
    verified = not firewall_errors
    errors = list(firewall_errors)
    if mode == DNS_ISOLATION_CONSTRAINED_EGRESS and not verified:
        errors.insert(0, "DNS_ISOLATION_NOT_GUARANTEED")
    return {
        "selected_mode": mode,
        "status": "PASS" if verified else "BLOCKED",
        "dns_filtering": "VERIFIED" if verified else "NOT_GUARANTEED",
        "dns_filtering_guaranteed": verified,
        "amazon_provided_dns": {
            "used_by_vpc": True,
            "security_group_filtering": "BYPASSED",
            "network_acl_filtering": "BYPASSED",
            "resolver_firewall_policy": "VERIFIED" if verified else "NOT_VERIFIED",
            "unfiltered_dns_queries_possible": not verified,
        },
        "canary_egress_contract": {
            "status": "CONTRACT_ONLY_PENDING_EXCLUSIVE_SG_READBACK",
            "initial_allowlist": ["SSM_ENDPOINT_SECURITY_GROUPS_TCP_443"],
            "post_guest_audit_allowlist": [
                "SSM_ENDPOINT_SECURITY_GROUPS_TCP_443", "PINNED_PROBE_IPS_TCP_443",
            ],
            "probe_egress_enable_condition": "WEB_AND_EMR_GUEST_AUDITS_PASS",
            "db_tcp_3306": "DENIED_BY_EXCLUSIVE_CANARY_SG_EGRESS",
            "non_allowlisted_egress": "DENIED_BY_EXCLUSIVE_CANARY_SG_EGRESS",
            "dns_queries": "NOT_FILTERED_BY_SECURITY_GROUP_OR_NETWORK_ACL",
        },
        "reason_code": errors[0] if errors else None,
        "errors": errors,
        "firewall_validation_errors": list(firewall_errors),
    }


def validate_canary_security_group(group: dict[str, Any], *, role: str,
                                   endpoint_sgs: set[str], probe_ips: set[str],
                                   emr_host_cidr: str = EMR_HOST_CIDR) -> list[str]:
    errors: list[str] = []
    ingress = group.get("IpPermissions", [])
    if role == "emr" and ingress:
        errors.append("EMR_CANARY_INGRESS_NOT_EMPTY")
    if role == "web":
        if len(ingress) != 1:
            errors.append("WEB_CANARY_INGRESS_NOT_EMR_HTTPS_ONLY")
        else:
            rule = ingress[0]
            if (rule.get("IpProtocol") != "tcp" or rule.get("FromPort") != 443 or rule.get("ToPort") != 443
                    or {item.get("CidrIp") for item in rule.get("IpRanges", [])} != {emr_host_cidr}
                    or rule.get("Ipv6Ranges") or rule.get("UserIdGroupPairs") or rule.get("PrefixListIds")):
                errors.append("WEB_CANARY_INGRESS_NOT_EMR_HTTPS_ONLY")
    expected_group_egress = set(endpoint_sgs)
    expected_cidrs = {f"{ip}/32" for ip in probe_ips}
    egress_groups: set[str] = set()
    egress_cidrs: set[str] = set()
    for rule in group.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol") != "tcp" or rule.get("FromPort") != 443 or rule.get("ToPort") != 443:
            errors.append("CANARY_EGRESS_NOT_TCP443")
            continue
        if rule.get("UserIdGroupPairs"):
            if rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("PrefixListIds"):
                errors.append("CANARY_EGRESS_MIXED_TARGETS")
            egress_groups.update(row.get("GroupId", "") for row in rule.get("UserIdGroupPairs", []))
        else:
            egress_cidrs.update(row.get("CidrIp", "") for row in rule.get("IpRanges", []))
            if rule.get("Ipv6Ranges") or rule.get("PrefixListIds"):
                errors.append("CANARY_EGRESS_IPV6_OR_PREFIXLIST_FORBIDDEN")
    if egress_groups != expected_group_egress or egress_cidrs != expected_cidrs:
        errors.append("CANARY_EGRESS_ALLOWLIST_MISMATCH")
    return sorted(set(errors))


def resolve_probe_ips(host: str = PROBE_HOST, *, resolver: Callable[..., Any] = socket.getaddrinfo) -> list[str]:
    if host != PROBE_HOST:
        raise NatEmrCanaryError("PROBE_HOST_NOT_APPROVED", "Only the reviewed HTTPS egress probe hostname is accepted")
    try:
        rows = resolver(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        raise NatEmrCanaryError("PROBE_DNS_LOOKUP_FAILED", "Approved probe hostname did not resolve") from exc
    addresses = sorted({str(row[4][0]) for row in rows})
    if not addresses or len(addresses) > 8:
        raise NatEmrCanaryError("PROBE_ADDRESS_SET_INVALID", "Probe address set is empty or unexpectedly large")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4 or not parsed.is_global:
            raise NatEmrCanaryError("PROBE_ADDRESS_NOT_PUBLIC_IPV4", "Probe resolution returned a non-public IPv4 address")
    return addresses


def _egress_rule_group(group_id: str) -> dict[str, Any]:
    return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "UserIdGroupPairs": [{"GroupId": group_id}]}


def _egress_rule_cidr(cidr: str) -> dict[str, Any]:
    return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": cidr}]}


def _emr_ingress_rule() -> dict[str, Any]:
    return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": EMR_HOST_CIDR, "Description": "Isolated DR NAT Canary from approved EMR ENI"}]}


def _instance_rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    return [instance for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])]


def _only_line(stdout: str, key: str) -> str:
    values = [line.partition("=")[2] for line in stdout.splitlines()
              if line.partition("=")[0] == key and "=" in line]
    if len(values) != 1:
        raise NatEmrCanaryError("SSM_RESPONSE_CONTRACT_INVALID", f"SSM did not return one {key} result")
    return values[0].strip()


def _read_nat_state(path: Path) -> dict[str, Any]:
    _secure_state_parent(path)
    try:
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise NatEmrCanaryError("STATE_FILE_PERMISSIONS",
                                    "State must be an operator-owned regular file with mode 0600")
        value = json.loads(path.read_text(encoding="utf-8"))
    except NatEmrCanaryError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise NatEmrCanaryError("STATE_FILE_UNREADABLE", "Canary state is absent or invalid") from exc
    if not isinstance(value, dict):
        raise NatEmrCanaryError("STATE_FILE_CONTRACT_INVALID", "Canary state is not a JSON object")
    return value


class PidFile:
    """Private PID marker; flock remains the authoritative cross-run lock."""

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id
        self.fd: int | None = None
        self.identity: tuple[int, int] | None = None

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def __enter__(self) -> "PidFile":
        _secure_state_parent(self.path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self.fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            try:
                before = self.path.lstat()
                if (self.path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_uid != os.geteuid() or before.st_mode & 0o077):
                    raise NatEmrCanaryError("PID_FILE_PERMISSIONS", "Existing PID file is not private and regular")
                content = self.path.read_text(encoding="ascii")
                match = re.search(r"^pid=([0-9]+)$", content, re.MULTILINE)
                if match and self._alive(int(match.group(1))):
                    raise NatEmrCanaryError("CANARY_PID_ALREADY_RUNNING",
                                            "A prior Canary PID is still alive; refusing a second run")
                current = self.path.lstat()
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    raise NatEmrCanaryError("PID_FILE_CHANGED", "PID file changed during stale-marker check")
                self.path.unlink()
                self.fd = os.open(self.path, flags, 0o600)
            except NatEmrCanaryError:
                raise
            except (OSError, UnicodeError) as exc:
                raise NatEmrCanaryError("PID_FILE_UNREADABLE", "Could not safely reclaim a stale PID file") from exc
        except OSError as exc:
            raise NatEmrCanaryError("PID_FILE_UNAVAILABLE", "Could not create the private PID file") from exc
        info = os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            os.close(self.fd)
            self.fd = None
            raise NatEmrCanaryError("PID_FILE_PERMISSIONS", "PID file must be operator-owned mode 0600")
        self.identity = (info.st_dev, info.st_ino)
        content = f"pid={os.getpid()}\nrun_id={self.run_id}\n".encode("ascii")
        os.write(self.fd, content)
        os.fsync(self.fd)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        try:
            current = self.path.lstat()
            if self.identity == (current.st_dev, current.st_ino):
                self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


class DeadlineBoundAws:
    """Apply the transaction's remaining wall-clock budget to each AWS CLI process."""

    def __init__(self, client: AwsCli, deadline: Callable[[], float],
                 monotonic: Callable[[], float] = time.monotonic):
        self.client = client
        self.deadline = deadline
        self.monotonic = monotonic

    @property
    def region(self) -> str:
        """Preserve the AwsCli read-only inspection interface while bounding calls."""
        return self.client.region

    @property
    def event_callback(self):
        return getattr(self.client, "event_callback", None)

    @event_callback.setter
    def event_callback(self, callback):
        if hasattr(self.client, "event_callback"):
            self.client.event_callback = callback

    def call(self, service: str, operation: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        remaining = self.deadline() - self.monotonic()
        if remaining <= 0:
            raise NatEmrCanaryError("CANARY_TOTAL_TIMEOUT", "The bounded Canary wall-clock budget is exhausted")
        previous_timeout = getattr(self.client, "timeout", CLI_TIMEOUT_SECONDS)
        self.client.timeout = min(float(previous_timeout), max(0.1, remaining))
        try:
            return self.client.call(service, operation, payload)
        finally:
            self.client.timeout = previous_timeout


def _safe_exception_type(exc: BaseException) -> str:
    """Return only a bounded class name; exception text may contain sensitive data."""
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "UnexpectedError"


def _safe_reason_code(reason: Any) -> str:
    if not isinstance(reason, str):
        return "PREFLIGHT_CHECK_FAILED"
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", reason):
        return reason
    if re.fullmatch(r"AWS_[a-z0-9]+_[A-Za-z0-9]+_[A-Z0-9_]{1,48}", reason):
        return reason
    return "PREFLIGHT_CHECK_FAILED"


def _db_probe_command() -> str:
    return r"""set -eu
test -x /usr/bin/mysql
sudo timeout --foreground 15s mysql --defaults-file=/etc/mysql/debian.cnf \
  --protocol=socket --connect-timeout=5 --batch --raw --skip-column-names \
  -e "SELECT CONCAT(LOWER(@@server_uuid),'|',@@server_id,'|',@@port,'|',@@global.read_only,'|',@@global.super_read_only)"
"""


def _guest_audit_command(*, instance_id: str, private_ip: str, role: str) -> str:
    return f"""set -eu
token=$(curl --fail --silent --show-error --max-time 3 -X PUT http://AWS_PUBLIC_IP_REDACTED/latest/api/token -H X-aws-ec2-metadata-token-ttl-seconds:60)
trap 'unset token' EXIT
iid=$(curl --fail --silent --show-error --max-time 3 -H "X-aws-ec2-metadata-token: $token" http://AWS_PUBLIC_IP_REDACTED/latest/meta-data/instance-id)
ip=$(curl --fail --silent --show-error --max-time 3 -H "X-aws-ec2-metadata-token: $token" http://AWS_PUBLIC_IP_REDACTED/latest/meta-data/local-ipv4)
test "$iid" = {instance_id} && test "$ip" = {private_ip}
printf 'GUEST_IDENTITY=PASS\\n'
active=$(systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{{print $1}}' | grep -Ei 'cloudflared|wireguard|wg-quick|hospital-(web|emr|dr)|docker|nginx|apache|node|pm2|mysql|mariadb' || true)
enabled=$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{{print $1}}' | grep -Ei 'cloudflared|wireguard|wg-quick' || true)
interfaces=$(ip -brief link 2>/dev/null | awk '{{print $1}}' | grep -Ei '^(wg|wireguard)' || true)
if printf '%s\\n%s\\n%s\\n' "$active" "$enabled" "$interfaces" | grep -Eiq 'cloudflared|wireguard|wg-quick|^wg'; then
  printf 'TUNNEL_OR_WIREGUARD=RUNNING_OR_ENABLED\\n'
else
  printf 'TUNNEL_OR_WIREGUARD=ABSENT\\n'
fi
containers=0
if command -v docker >/dev/null 2>&1; then
  containers=$(sudo docker ps --quiet 2>/dev/null | wc -l | tr -d ' ')
fi
printf 'RUNNING_CONTAINER_COUNT=%s\\n' "$containers"
writer_processes=$(ps -eo comm= 2>/dev/null | grep -Eic '^(node|pm2|cloudflared|wg|wg-quick|wireguard|mysqld|mariadbd|mysql)$' || true)
printf 'WRITER_OR_TUNNEL_PROCESS_COUNT=%s\\n' "$writer_processes"
printf 'ACTIVE_RELEVANT_SERVICES='
printf '%s\\n' "$active" | paste -sd, -
printf 'RELEVANT_TIMER_COUNT='
systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{{print $NF}}' | grep -Eic 'hospital|web|emr|dr|backup|mysql|node|docker|wireguard|cloudflared' || true
printf 'RELEVANT_CRON_JOB_COUNT='
grep -RhsE '^[[:space:]]*[^#[:space:]].*(hospital|web|emr|dr|backup|mysql|node|docker|wireguard|cloudflared)' /etc/crontab /etc/cron.d /var/spool/cron/crontabs 2>/dev/null | wc -l | tr -d ' '
if [ -e {NAT_BASELINE_DIR} ]; then
  printf 'NAT_BASELINE=EXISTS\\n'
else
  printf 'NAT_BASELINE=ABSENT\\n'
fi
if [ '{role}' = 'web' ]; then
  printf 'IP_FORWARD='
  sysctl -n net.ipv4.ip_forward
else
  printf 'IP_FORWARD=NOT_APPLICABLE\\n'
fi
"""


def _emr_probe_command(host: str, ip: str) -> str:
    # --resolve pins the just-read A record while preserving TLS SNI and
    # certificate verification; the probe response is only one public IP.
    return (
        "set -eu; "
        f"out=$(curl --fail --silent --show-error --max-time 10 "
        f"--resolve {host}:443:{ip} https://{host}/); "
        "printf 'EGRESS_PUBLIC_IP=%s\\n' \"$(printf '%s' \"$out\" | tr -d '\\r\\n')\""
    )


def _parse_db_probe(stdout: str) -> dict[str, Any]:
    rows = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(rows) != 1:
        raise NatEmrCanaryError("DB_READ_ONLY_PROBE_INVALID", "DB probe did not return one identity row")
    fields = rows[0].split("|")
    if len(fields) != 5:
        raise NatEmrCanaryError("DB_READ_ONLY_PROBE_INVALID", "DB probe did not return the expected fields")
    server_uuid, server_id, port, read_only, super_read_only = fields
    if (server_uuid.lower() != DB_UUID or server_id != str(DB_SERVER_ID) or port != "3306"
            or read_only not in {"1", "ON"} or super_read_only not in {"1", "ON"}):
        raise NatEmrCanaryError("DB_NOT_READ_ONLY_STANDBY", "DB identity or read-only state failed the canary fence")
    return {
        "server_uuid": server_uuid.lower(), "server_id": int(server_id), "port": int(port),
        "read_only": True, "super_read_only": True,
    }


def _check_acl_tcp_path(acls: list[dict[str, Any]], source_subnet: str, dest_subnet: str,
                        source_ip: str, dest_ip: str, dest_port: int) -> bool:
    source_acl = _acl_for_subnet(acls, source_subnet)
    dest_acl = _acl_for_subnet(acls, dest_subnet)
    if not source_acl or not dest_acl:
        return False
    return all((
        _effective_acl_action(source_acl, egress=True, peer_ip=dest_ip, protocol=6, port=dest_port) == "allow",
        _acl_allows_port_range(source_acl, egress=False, peer_ip=dest_ip, protocol=6, first=32768, last=65535),
        _effective_acl_action(dest_acl, egress=False, peer_ip=source_ip, protocol=6, port=dest_port) == "allow",
        _acl_allows_port_range(dest_acl, egress=True, peer_ip=source_ip, protocol=6, first=32768, last=65535),
    ))


def _check_acl_public_egress(acls: list[dict[str, Any]], subnet_id: str,
                             public_ip: str) -> bool:
    acl = _acl_for_subnet(acls, subnet_id)
    if not acl:
        return False
    return (
        _effective_acl_action(acl, egress=True, peer_ip=public_ip, protocol=6, port=443) == "allow"
        and _acl_allows_port_range(acl, egress=False, peer_ip=public_ip, protocol=6, first=32768, last=65535)
    )


def _role_ssm_ready(aws: AwsCli, instance: dict[str, Any]) -> dict[str, str]:
    arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
    _require(bool(arn), "INSTANCE_PROFILE_MISSING", "Web/EMR has no IAM instance profile")
    profile_name = arn.rsplit("/", 1)[-1]
    profile = aws.call("iam", "GetInstanceProfile", {"InstanceProfileName": profile_name}).get("InstanceProfile", {})
    roles = [item.get("RoleName", "") for item in profile.get("Roles", [])]
    _require(len(roles) == 1 and roles[0], "INSTANCE_ROLE_UNVERIFIED", "Instance profile did not resolve to one IAM role")
    policies = aws.call("iam", "ListAttachedRolePolicies", {"RoleName": roles[0]}).get("AttachedPolicies", [])
    _require(any(row.get("PolicyArn") == SSM_POLICY_ARN for row in policies),
             "SSM_INSTANCE_POLICY_MISSING", "Instance role lacks the expected SSM managed-node policy")
    return {"profile_name": profile_name, "role_name": roles[0], "ssm_policy": "PRESENT"}


def _dns_firewall_snapshot(aws: AwsCli) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]], list[dict[str, Any]]]:
    associations = _paginate(aws, "route53resolver", "ListFirewallRuleGroupAssociations",
                             "FirewallRuleGroupAssociations", {"VpcId": VPC_ID, "MaxResults": 100})
    configs = _paginate(aws, "route53resolver", "ListFirewallConfigs",
                        "FirewallConfigs", {"MaxResults": 10})
    selected = [row for row in associations if row.get("VpcId") == VPC_ID]
    if len(selected) != 1:
        return associations, [], {}, configs
    group_id = selected[0].get("FirewallRuleGroupId", "")
    rules = _paginate(aws, "route53resolver", "ListFirewallRules", "FirewallRules",
                      {"FirewallRuleGroupId": group_id, "MaxResults": 100}) if group_id else []
    domains: dict[str, list[str]] = {}
    for rule in rules:
        list_id = rule.get("FirewallDomainListId")
        if list_id and list_id not in domains:
            domains[str(list_id)] = [
                str(value) for value in _paginate(
                    aws, "route53resolver", "ListFirewallDomains", "Domains",
                    {"FirewallDomainListId": list_id, "MaxResults": 100},
                )
            ]
    return associations, rules, domains, configs


def inspect_live(aws: AwsCli, *, probe_ips: list[str] | None = None,
                 run_db_probe: bool = True,
                 dns_isolation_mode: str = DNS_ISOLATION_STRICT) -> dict[str, Any]:
    """Read-only account, target, route, SG, SSM, DNS Firewall and DB snapshot."""
    _require(dns_isolation_mode in DNS_ISOLATION_MODES, "DNS_ISOLATION_MODE_INVALID",
             "DNS isolation mode is not supported")
    identity = aws.call("sts", "GetCallerIdentity")
    _require(identity.get("Account") == ACCOUNT_ID, "AWS_ACCOUNT_MISMATCH",
             "AWS caller account differs from the approved DR account")
    web_report = inspect_web_environment(aws)
    ids = [WEB_ID, EMR_ID, DB_ID]
    rows = _instance_rows(aws.call("ec2", "DescribeInstances", {"InstanceIds": ids}))
    _require(len(rows) == 3, "DR_INSTANCE_SET_INCOMPLETE", "Could not read all exact Web/EMR/DB instances")
    web = _target_instance(rows, instance_id=WEB_ID, name=WEB_NAME_TAG, subnet_id=WEB_SUBNET,
                           private_ip=WEB_PRIVATE_IP, eni_id=WEB_ENI)
    emr = _target_instance(rows, instance_id=EMR_ID, name=EMR_NAME_TAG, subnet_id=EMR_SUBNET,
                           private_ip=EMR_PRIVATE_IP, eni_id=EMR_ENI)
    db = _target_instance(rows, instance_id=DB_ID, name=DB_NAME_TAG, subnet_id=DB_SUBNET,
                          private_ip=DB_PRIVATE_IP, eni_id=DB_ENI)
    _require(web.get("State", {}).get("Name") == "stopped" and emr.get("State", {}).get("Name") == "stopped",
             "APPLICATION_INSTANCES_NOT_STOPPED", "Web and EMR must both be stopped before a Canary")
    _require(db.get("State", {}).get("Name") == "running", "DB_NOT_RUNNING", "Read-only DB fence check requires the expected DB running")

    web_eni_rows = aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [WEB_ENI]}).get("NetworkInterfaces", [])
    emr_eni_rows = aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [EMR_ENI]}).get("NetworkInterfaces", [])
    db_eni_rows = aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [DB_ENI]}).get("NetworkInterfaces", [])
    _require(len(web_eni_rows) == len(emr_eni_rows) == len(db_eni_rows) == 1,
             "TARGET_ENI_NOT_UNIQUE", "An expected instance ENI is missing or ambiguous")
    web_eni, emr_eni, db_eni = web_eni_rows[0], emr_eni_rows[0], db_eni_rows[0]
    web_sgs = sorted(group.get("GroupId", "") for group in web_eni.get("Groups", []))
    emr_sgs = sorted(group.get("GroupId", "") for group in emr_eni.get("Groups", []))
    db_sgs = sorted(group.get("GroupId", "") for group in db_eni.get("Groups", []))
    _require(web_sgs == [WEB_ORIGINAL_SG] and emr_sgs == [EMR_ORIGINAL_SG],
             "APPLICATION_SG_BASELINE_MISMATCH", "Web/EMR SG attachments differ from the pinned pre-Canary sets")
    _require(web_eni.get("SourceDestCheck") is False, "WEB_SOURCE_DEST_CHECK_ENABLED",
             "Web Source/Destination Check is not disabled")
    _require(web_eni.get("Association", {}).get("PublicIp") == EXPECTED_WEB_EIP,
             "WEB_EIP_ASSOCIATION_MISMATCH", "Web EIP is not associated with the exact Web ENI")

    all_sg_ids = sorted(set(web_sgs + emr_sgs + db_sgs + web_report["resources"]["endpoint_security_group_ids"]))
    groups = aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": all_sg_ids}).get("SecurityGroups", [])
    _require({item.get("GroupId") for item in groups} == set(all_sg_ids),
             "SECURITY_GROUP_SNAPSHOT_INCOMPLETE", "Could not read the complete original SG set")
    by_sg = {item["GroupId"]: item for item in groups}
    _require(DB_SG in {item.get("GroupId") for item in db_eni.get("Groups", [])},
             "DB_SECURITY_GROUP_IDENTITY_MISMATCH", "Expected DB security group is not attached")

    endpoint_rows = aws.call("ec2", "DescribeVpcEndpoints", {
        "Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}],
    }).get("VpcEndpoints", [])
    endpoint_sgs, endpoint_enis = _expected_service_groups(endpoint_rows)
    required_dns_names = set(ALLOWED_DNS_NAMES)
    if any(row.get("ServiceName") in OPTIONAL_SSM_SERVICES for row in endpoint_rows):
        required_dns_names.add(f"ec2messages.{REGION}.amazonaws.com")
    _require(endpoint_sgs == set(web_report["resources"]["endpoint_security_group_ids"]),
             "SSM_ENDPOINT_SG_DRIFT", "Endpoint SG membership differs from the Web Canary inspection")
    endpoint_eni_rows = aws.call("ec2", "DescribeNetworkInterfaces", {
        "Filters": [{"Name": "group-id", "Values": sorted(endpoint_sgs)}],
    }).get("NetworkInterfaces", [])
    _require({item.get("NetworkInterfaceId") for item in endpoint_eni_rows} == endpoint_enis,
             "SSM_ENDPOINT_SG_SHARED", "An SSM endpoint SG is also attached to an unapproved ENI")

    route_rows = aws.call("ec2", "DescribeRouteTables", {"RouteTableIds": [PRIVATE_ROUTE_TABLE_ID]}).get("RouteTables", [])
    _require(len(route_rows) == 1 and route_rows[0].get("VpcId") == VPC_ID,
             "NAT_ROUTE_TABLE_IDENTITY_MISMATCH", "Private route table identity is not exact")
    route_table = route_rows[0]
    route_by_cidr = {route.get("DestinationCidrBlock"): route for route in route_table.get("Routes", [])}
    for destination in ("AWS_PUBLIC_IP_REDACTED/0", "AWS_PUBLIC_IP_REDACTED/24"):
        route = route_by_cidr.get(destination)
        _require(route is not None and route.get("NetworkInterfaceId") == WEB_ENI
                 and route.get("State") in {"active", "blackhole"},
                 "NAT_ROUTE_TARGET_MISMATCH", f"Expected route target contract is missing for {destination}")

    all_instances = {row["InstanceId"]: row for row in (web, emr, db)}
    role_contracts = {
        role: _role_ssm_ready(aws, all_instances[instance_id])
        for role, instance_id in (("web", WEB_ID), ("emr", EMR_ID))
    }
    acls = aws.call("ec2", "DescribeNetworkAcls", {"Filters": [{"Name": "vpc-id", "Values": [VPC_ID]}]}).get("NetworkAcls", [])
    paths_ok = _check_acl_tcp_path(acls, EMR_SUBNET, WEB_SUBNET, EMR_PRIVATE_IP, WEB_PRIVATE_IP, 443)
    endpoint_ips = web_report["resources"].get("endpoint_ips", [])
    for endpoint in endpoint_ips:
        ep_ip = endpoint["private_ip"]
        paths_ok = paths_ok and _check_acl_tcp_path(
            acls, WEB_SUBNET, endpoint["subnet_id"], WEB_PRIVATE_IP, ep_ip, 443
        ) and _check_acl_tcp_path(
            acls, EMR_SUBNET, endpoint["subnet_id"], EMR_PRIVATE_IP, ep_ip, 443
        )
    resolved_probe_ips = probe_ips if probe_ips is not None else resolve_probe_ips()
    for probe_ip in resolved_probe_ips:
        paths_ok = paths_ok and _check_acl_public_egress(acls, WEB_SUBNET, probe_ip)
        paths_ok = paths_ok and _check_acl_public_egress(acls, EMR_SUBNET, probe_ip)
    _require(paths_ok, "CANARY_NACL_PATH_UNVERIFIED", "NACL does not prove endpoint/forward/probe and return paths")

    associations, dns_rules, domains, firewall_configs = _dns_firewall_snapshot(aws)
    firewall_errors = validate_dns_firewall(
        associations, dns_rules, domains, firewall_configs, required_domains=required_dns_names,
    )
    dns_isolation = _dns_isolation_assessment(dns_isolation_mode, firewall_errors)
    dns_errors = dns_isolation["errors"]

    db_probe: dict[str, Any] = {"status": "NOT_RUN"}
    if run_db_probe:
        result = _ssm_run_command(aws, DB_ID, _db_probe_command(), timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                                  deadline=time.monotonic() + COMMAND_TIMEOUT_SECONDS)
        db_probe = {"status": "PASS", **_parse_db_probe(result["stdout"])}

    report = {
        "status": "PASS" if dns_isolation["status"] == "PASS" else "BLOCKED",
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "checks": {
            "web_identity": "PASS",
            "emr_identity": "PASS",
            "db_identity": "PASS",
            "web_emr_stopped": "PASS",
            "db_running": "PASS",
            "db_read_only": db_probe["status"],
            "web_emr_original_sg": "PASS",
            "web_eip_and_source_dest": "PASS",
            "ssm_endpoints_and_profiles": "PASS",
            "nacl_paths": "PASS",
            "nat_route_target": "PASS",
            "nat_routes_active_before_start": "PENDING_LIVE_TEST" if any(
                route_by_cidr[item].get("State") != "active" for item in ("IP_REDACTED/0", "IP_REDACTED/24")
            ) else "PASS",
            "dns_firewall_walled_garden": dns_isolation["status"],
        },
        "resources": {
            "vpc_id": VPC_ID,
            "web": {"instance_id": WEB_ID, "eni_id": WEB_ENI, "subnet_id": WEB_SUBNET,
                    "private_ip": WEB_PRIVATE_IP, "state": web["State"]["Name"],
                    "original_sg_ids": web_sgs, "eip": EXPECTED_WEB_EIP,
                    "source_dest_check": False, "instance_profile": role_contracts["web"]},
            "emr": {"instance_id": EMR_ID, "eni_id": EMR_ENI, "subnet_id": EMR_SUBNET,
                    "private_ip": EMR_PRIVATE_IP, "state": emr["State"]["Name"],
                    "original_sg_ids": emr_sgs, "instance_profile": role_contracts["emr"]},
            "db": {"instance_id": DB_ID, "eni_id": DB_ENI, "subnet_id": DB_SUBNET,
                   "private_ip": DB_PRIVATE_IP, "state": db["State"]["Name"],
                   "security_group_ids": db_sgs,
                   "read_only_probe": db_probe},
            "endpoint_sg_ids": sorted(endpoint_sgs),
            "endpoint_eni_ids": sorted(endpoint_enis),
            "endpoint_ips": endpoint_ips,
            "web_sg_rules": by_sg[WEB_ORIGINAL_SG].get("IpPermissions", []),
            "emr_sg_rules": by_sg[EMR_ORIGINAL_SG].get("IpPermissions", []),
            "db_sg_rules": by_sg[DB_SG].get("IpPermissions", []),
            "endpoint_sg_rules": {sg: {"ingress": by_sg[sg].get("IpPermissions", []),
                                       "egress": by_sg[sg].get("IpPermissionsEgress", [])}
                                  for sg in sorted(endpoint_sgs)},
            "private_route_table": _route_table_snapshot(route_table),
            "probe_host": PROBE_HOST,
            "probe_ips": sorted(resolved_probe_ips),
            "nat_status_before_start": web_report["resources"].get("prestart_web_nat_route_state", "UNKNOWN"),
        },
        "dns_firewall": {
            "errors": dns_errors,
            "association_ids": [row.get("Id", "") for row in associations if row.get("VpcId") == VPC_ID],
            "rule_count": len(dns_rules),
            "allowed_domains_verified": sorted(required_dns_names) if not dns_errors else [],
        },
        "dns_isolation": dns_isolation,
        "side_effects": {
            "aws_resource_configuration": "UNCHANGED",
            "ssm_command_invocation": "CREATED_READ_ONLY_SELECT" if run_db_probe else "NOT_RUN",
        },
        "web_preflight": web_report,
    }
    return report


def _read_only_preflight_blocked(report: dict[str, Any], *,
                                expected_dns_isolation_mode: str = DNS_ISOLATION_STRICT) -> bool:
    """Fail closed on missing/failed required contracts; pre-start NAT may be pending."""
    if not isinstance(report, dict) or report.get("status") != "PASS":
        return True
    checks = report.get("checks")
    if not isinstance(checks, dict) or any(checks.get(name) != "PASS" for name in READ_ONLY_REQUIRED_CHECKS):
        return True
    dns_isolation = report.get("dns_isolation")
    if (not isinstance(dns_isolation, dict)
            or dns_isolation.get("selected_mode") != expected_dns_isolation_mode
            or dns_isolation.get("status") != "PASS"
            or dns_isolation.get("dns_filtering_guaranteed") is not True
            or dns_isolation.get("errors") != []
            or dns_isolation.get("firewall_validation_errors") != []
            or dns_isolation.get("reason_code") is not None):
        return True
    dns_firewall = report.get("dns_firewall")
    if not isinstance(dns_firewall, dict) or dns_firewall.get("errors") != []:
        return True
    amazon_dns = dns_isolation.get("amazon_provided_dns")
    if (not isinstance(amazon_dns, dict)
            or amazon_dns.get("security_group_filtering") != "BYPASSED"
            or amazon_dns.get("network_acl_filtering") != "BYPASSED"
            or amazon_dns.get("resolver_firewall_policy") != "VERIFIED"
            or amazon_dns.get("unfiltered_dns_queries_possible") is not False):
        return True
    if checks.get("nat_routes_active_before_start") not in {"PASS", "PENDING_LIVE_TEST"}:
        return True
    web_preflight = report.get("web_preflight")
    if not isinstance(web_preflight, dict):
        return True
    web_checks = web_preflight.get("checks")
    if not isinstance(web_checks, dict):
        return True
    if any(web_checks.get(name) != "PASS" for name in WEB_READ_ONLY_REQUIRED_CHECKS):
        return True
    if web_checks.get("prestart_web_nat_routes") not in {"PASS", "PENDING_LIVE_TEST"}:
        return True
    return any(value == "BLOCKED" for value in web_checks.values())


def _ssm_run_command(aws: AwsCli, instance_id: str, command: str, *,
                     timeout_seconds: int, deadline: float,
                     sleep: Callable[[float], None] = time.sleep,
                     monotonic: Callable[[], float] = time.monotonic) -> dict[str, str]:
    sent = aws.call("ssm", "SendCommand", {
        "InstanceIds": [instance_id],
        "DocumentName": "AWS-RunShellScript",
        "TimeoutSeconds": min(timeout_seconds, 300),
        "Parameters": {"commands": [command]},
        "Comment": "Hospital DR isolated Web NAT/EMR Canary read-only probe",
    })
    command_id = sent.get("Command", {}).get("CommandId", "")
    _require(bool(command_id), "SSM_COMMAND_NOT_ACCEPTED", "SSM did not return a command id")
    command_deadline = min(deadline, monotonic() + timeout_seconds)
    last_progress = monotonic()
    invocation: dict[str, Any] = {}
    while monotonic() < command_deadline:
        try:
            invocation = aws.call("ssm", "GetCommandInvocation", {
                "CommandId": command_id, "InstanceId": instance_id,
            })
        except CanaryError as exc:
            # SSM is eventually consistent immediately after SendCommand, but
            # authorization/network failures are real blockers and must not be
            # hidden behind a generic polling timeout.
            if not exc.reason.endswith("_INVOCATIONDOESNOTEXIST"):
                raise
            invocation = {}
        status = invocation.get("Status")
        if status in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
            break
        if monotonic() - last_progress >= 30:
            if hasattr(aws, "event_callback") and aws.event_callback:
                aws.event_callback("SSM_COMMAND_PROGRESS", {
                    "instance_id": instance_id, "remaining_seconds": max(0, int(command_deadline - monotonic())),
                })
            last_progress = monotonic()
        sleep(min(POLL_SECONDS, max(0.0, command_deadline - monotonic())))
    _require(invocation.get("Status") == "Success", "SSM_COMMAND_FAILED",
             f"Read-only SSM command failed with status {invocation.get('Status', 'UNKNOWN')}")
    return {
        "stdout": str(invocation.get("StandardOutputContent", "")),
        "status": str(invocation.get("Status", "")),
    }


class AwsNatEmrCanary:
    def __init__(self, aws: AwsCli, state_path: Path, *, logger: EventLogger | None = None,
                 max_minutes: int = MAX_MINUTES, sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic,
                 resolver: Callable[..., Any] = socket.getaddrinfo,
                 command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
                 run_id: str | None = None,
                 dns_isolation_mode: str = DNS_ISOLATION_STRICT):
        _require(dns_isolation_mode in DNS_ISOLATION_MODES, "DNS_ISOLATION_MODE_INVALID",
                 "DNS isolation mode is not supported")
        self.aws = aws
        self.state_path = state_path
        self.logger = logger or EventLogger()
        self.dns_isolation_mode = dns_isolation_mode
        self.max_minutes = max_minutes
        self.sleep = sleep
        self.monotonic = monotonic
        self.resolver = resolver
        self.command_runner = command_runner or subprocess.run
        self.cleanup_budget = min(CLEANUP_RESERVE_SECONDS, max(600, max_minutes * 30))
        self.total_deadline = monotonic() + max(1, max_minutes * 60 - self.cleanup_budget - CLI_TIMEOUT_SECONDS)
        self.cleanup_deadline = 0.0
        self.state: dict[str, Any] | None = None
        self._restoring = False
        self._lock_fd: int | None = None
        self.run_id = run_id or str(uuid.uuid4())
        self._raw_aws = aws
        self.aws = DeadlineBoundAws(aws, self._active_deadline, monotonic)
        if hasattr(self.aws, "event_callback"):
            self.aws.event_callback = self._aws_event

    def _active_deadline(self) -> float:
        if self._restoring and self.cleanup_deadline > 0:
            return self.cleanup_deadline
        return self.total_deadline

    def _event(self, event: str, **fields: Any) -> None:
        record = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **fields,
        }
        if self.state is not None:
            history = self.state.setdefault("events", [])
            history.append(record)
            if len(history) > 800:
                del history[:-800]
            self.state["last_event"] = record
            self.state["updated_at"] = record["at"]
            self._save()
        self.logger.emit(event, **fields)

    def _safe_event(self, event: str, **fields: Any) -> None:
        try:
            self._event(event, **fields)
        except Exception:
            self.logger.emit("PROGRESS_STATE_UPDATE_FAILED", event_name=event)

    def _aws_event(self, event: str, fields: dict[str, Any]) -> None:
        safe_fields = {key: fields.get(key) for key in ("service", "operation", "reason") if fields.get(key)}
        self._event(event, **safe_fields)

    def _save(self) -> None:
        if self.state is not None:
            _write_state(self.state_path, self.state)

    def _phase(self, phase: str, **fields: Any) -> None:
        if self.state is not None:
            self.state["phase"] = phase
        self._event("PHASE", phase=phase, **fields)

    def inspect(self) -> dict[str, Any]:
        probe_ips = resolve_probe_ips(resolver=self.resolver)
        report = inspect_live(
            self.aws, probe_ips=probe_ips, run_db_probe=True,
            dns_isolation_mode=self.dns_isolation_mode,
        )
        assessment = report.get("dns_isolation", {})
        _require(
            isinstance(assessment, dict)
            and assessment.get("selected_mode") == self.dns_isolation_mode
            and assessment.get("status") in {"PASS", "BLOCKED"}
            and isinstance(assessment.get("dns_filtering_guaranteed"), bool)
            and isinstance(assessment.get("errors"), list),
            "DNS_ISOLATION_ASSESSMENT_UNVERIFIED",
            "Read-only result omitted or mismatched the selected DNS isolation assessment",
        )
        self._event(
            "DNS_ISOLATION_ASSESSMENT",
            selected_mode=self.dns_isolation_mode,
            status=assessment.get("status", "UNVERIFIED"),
            dns_filtering=assessment.get("dns_filtering", "UNVERIFIED"),
            amazon_provided_dns_sg_nacl_filtering="BYPASSED",
            reason_code=assessment.get("reason_code") or (
                "NONE" if assessment.get("status") == "PASS" else "DNS_ISOLATION_ASSESSMENT_UNVERIFIED"
            ),
        )
        report["checks"]["dns_firewall_walled_garden"] = (
            "PASS" if not report["dns_firewall"]["errors"] else "BLOCKED"
        )
        if report["status"] != "PASS":
            raise NatEmrCanaryError(
                report["dns_firewall"]["errors"][0] if report["dns_firewall"]["errors"] else "PREFLIGHT_BLOCKED",
                "Read-only preflight found a blocking DNS-isolation or AWS contract condition",
            )
        if _read_only_preflight_blocked(
                report, expected_dns_isolation_mode=self.dns_isolation_mode):
            raise NatEmrCanaryError(
                "PREFLIGHT_REQUIRED_CHECK_FAILED",
                "Read-only preflight omitted or blocked a required AWS/DB safety check",
            )
        return report

    def prepare_snapshot(self) -> dict[str, Any]:
        if self.state_path.exists() or self.state_path.is_symlink():
            raise NatEmrCanaryError("STATE_FILE_EXISTS", "Refusing to overwrite an existing Canary recovery state")
        self._event("PREFLIGHT_START", mode="read_only_plus_db_ro_probe",
                    dns_isolation_mode=self.dns_isolation_mode)
        report = self.inspect()
        self._event("PREFLIGHT_COMPLETE", status="PASS")
        run_id = self.run_id
        probe_ips = report["resources"]["probe_ips"]
        endpoint_sg_rules = report["resources"]["endpoint_sg_rules"]
        self.state = {
            "schema_version": STATE_VERSION,
            "run_id": run_id,
            "region": REGION,
            "account_id": ACCOUNT_ID,
            "vpc_id": VPC_ID,
            "web_instance_id": WEB_ID,
            "web_eni_id": WEB_ENI,
            "emr_instance_id": EMR_ID,
            "emr_eni_id": EMR_ENI,
            "db_instance_id": DB_ID,
            "db_eni_id": DB_ENI,
            "web_state_before": "stopped",
            "emr_state_before": "stopped",
            "db_state_before": "running",
            "original_sg_ids": {
                WEB_ID: report["resources"]["web"]["original_sg_ids"],
                EMR_ID: report["resources"]["emr"]["original_sg_ids"],
            },
            "endpoint_sg_rules_before": endpoint_sg_rules,
            "endpoint_sg_ids": report["resources"]["endpoint_sg_ids"],
            "endpoint_ingress_added": [],
            "probe_host": PROBE_HOST,
            "probe_ips": probe_ips,
            "probe_egress_enable_requested": False,
            "dns_isolation_mode": self.dns_isolation_mode,
            "dns_isolation_assessment": report.get("dns_isolation", {}),
            "route_table_before": report["resources"]["private_route_table"],
            "report_before": report,
            "canary_sg_ids": {},
            "sg_create_requested": [],
            "eni_replacement_started": [],
            "start_requested": {WEB_ID: False, EMR_ID: False},
            "nat_apply_started": False,
            "nat_baseline_sha256": "",
            "nat_restore_required": False,
            "nat_role_outcome_uncertain": False,
            "events": [],
            "phase": "SNAPSHOT_SAVED",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cleanup_complete": False,
        }
        self._event("SNAPSHOT_SAVED", state_file=str(self.state_path), run_id=run_id)
        return report

    def _validate_loaded_state(self) -> None:
        if self.state is None:
            self.state = _read_nat_state(self.state_path)
        value = self.state
        _require(
            value.get("schema_version") == STATE_VERSION
            and value.get("account_id") == ACCOUNT_ID
            and value.get("region") == REGION
            and value.get("vpc_id") == VPC_ID
            and value.get("web_instance_id") == WEB_ID
            and value.get("web_eni_id") == WEB_ENI
            and value.get("emr_instance_id") == EMR_ID
            and value.get("emr_eni_id") == EMR_ENI
            and value.get("db_instance_id") == DB_ID
            and value.get("db_eni_id") == DB_ENI
            and value.get("probe_host") == PROBE_HOST
            and re.fullmatch(r"[0-9a-f-]{36}", str(value.get("run_id", ""))) is not None,
            "STATE_FILE_CONTRACT_INVALID",
            "State file is not the supported exact-target Web/EMR Canary transaction",
        )
        try:
            valid_probe_ips = bool(value.get("probe_ips")) and all(
                ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global
                for ip in value.get("probe_ips", [])
            )
        except (TypeError, ValueError):
            valid_probe_ips = False
        _require(valid_probe_ips,
            "STATE_PROBE_ADDRESS_INVALID", "Saved probe IP set is invalid",
        )
        _require(
            value.get("original_sg_ids") == {
                WEB_ID: [WEB_ORIGINAL_SG], EMR_ID: [EMR_ORIGINAL_SG],
            },
            "STATE_ORIGINAL_SG_CONTRACT_INVALID",
            "State original Web/EMR SG attachments differ from the reviewed restore targets",
        )
        endpoint_ids = value.get("endpoint_sg_ids")
        endpoint_rules = value.get("endpoint_sg_rules_before")
        report_resources = value.get("report_before", {}).get("resources", {})
        _require(
            isinstance(endpoint_ids, list) and endpoint_ids
            and all(re.fullmatch(r"sg-[0-9a-f]+", str(item)) for item in endpoint_ids)
            and set(endpoint_rules or {}) == set(endpoint_ids)
            and sorted(report_resources.get("endpoint_sg_ids", [])) == sorted(endpoint_ids),
            "STATE_ENDPOINT_SG_CONTRACT_INVALID",
            "Saved SSM endpoint SG set and ingress snapshot do not match",
        )
        groups = value.get("canary_sg_ids", {})
        _require(
            isinstance(groups, dict)
            and set(groups).issubset({"web", "emr"})
            and all(re.fullmatch(r"sg-[0-9a-f]+", str(item)) for item in groups.values())
            and isinstance(value.get("start_requested"), dict)
            and set(value["start_requested"]) == {WEB_ID, EMR_ID}
            and all(isinstance(item, bool) for item in value["start_requested"].values())
            and isinstance(value.get("endpoint_ingress_added"), list),
            "STATE_MUTATION_LEDGER_INVALID",
            "Saved mutation ledger is malformed; recovery will not guess",
        )
        for item in value.get("endpoint_ingress_added", []):
            _require(
                isinstance(item, dict)
                and item.get("endpoint_sg_id") in endpoint_ids
                and item.get("source_sg_id") in groups.values(),
                "STATE_ENDPOINT_MUTATION_INVALID",
                "Saved temporary SSM ingress does not match this Canary's SG inventory",
            )
        _require(
            set(value.get("sg_create_requested", [])) <= {"web", "emr"}
            and isinstance(value.get("nat_restore_required"), bool)
            and isinstance(value.get("nat_role_outcome_uncertain"), bool)
            and isinstance(value.get("cleanup_complete"), bool),
            "STATE_MUTATION_LEDGER_INVALID",
            "Saved lifecycle or NAT restore markers are malformed",
        )

    def _deadline(self, timeout: int, *, cleanup: bool = False) -> float:
        limit = self.cleanup_deadline if cleanup else self.total_deadline
        deadline = min(self.monotonic() + timeout, limit)
        if deadline <= self.monotonic():
            raise NatEmrCanaryError("CANARY_TOTAL_TIMEOUT", "The bounded Canary execution budget is exhausted")
        return deadline

    def _poll(self, predicate: Callable[[], bool], *, timeout: int, reason: str,
              message: str, cleanup: bool = False) -> None:
        started = self.monotonic()
        deadline = self._deadline(timeout, cleanup=cleanup)
        last_progress = started
        self._event("WAIT_START", wait_for=reason, timeout_seconds=max(0, int(deadline - started)))
        while self.monotonic() < deadline:
            if predicate():
                self._event("WAIT_COMPLETE", wait_for=reason,
                            elapsed_seconds=round(self.monotonic() - started, 1))
                return
            now = self.monotonic()
            if now - last_progress >= 30:
                self._event("WAIT_PROGRESS", wait_for=reason,
                            elapsed_seconds=round(now - started, 1),
                            remaining_seconds=max(0, int(deadline - now)))
                last_progress = now
            self.sleep(min(POLL_SECONDS, max(0.0, deadline - self.monotonic())))
        self._event("WAIT_TIMEOUT", wait_for=reason)
        raise NatEmrCanaryError(reason, message)

    def _describe_instance(self, instance_id: str) -> dict[str, Any]:
        rows = _instance_rows(self.aws.call("ec2", "DescribeInstances", {"InstanceIds": [instance_id]}))
        _require(len(rows) == 1 and rows[0].get("InstanceId") == instance_id,
                 "INSTANCE_STATE_READBACK_FAILED", "Could not read back one exact instance")
        expected = {
            WEB_ID: (WEB_NAME_TAG, WEB_SUBNET, WEB_PRIVATE_IP, WEB_ENI),
            EMR_ID: (EMR_NAME_TAG, EMR_SUBNET, EMR_PRIVATE_IP, EMR_ENI),
            DB_ID: (DB_NAME_TAG, DB_SUBNET, DB_PRIVATE_IP, DB_ENI),
        }[instance_id]
        return _target_instance(rows, instance_id=instance_id, name=expected[0],
                                subnet_id=expected[1], private_ip=expected[2], eni_id=expected[3])

    def _instance_state(self, instance_id: str) -> str:
        return str(self._describe_instance(instance_id).get("State", {}).get("Name", "unknown"))

    def _instance_status_ok(self, instance_id: str) -> bool:
        rows = self.aws.call("ec2", "DescribeInstanceStatus", {
            "InstanceIds": [instance_id], "IncludeAllInstances": True,
        }).get("InstanceStatuses", [])
        return (len(rows) == 1 and rows[0].get("InstanceId") == instance_id
                and rows[0].get("InstanceStatus", {}).get("Status") == "ok"
                and rows[0].get("SystemStatus", {}).get("Status") == "ok")

    def _ssm_online(self, instance_id: str) -> bool:
        rows = self.aws.call("ssm", "DescribeInstanceInformation", {
            "Filters": [{"Key": "InstanceIds", "Values": [instance_id]}],
        }).get("InstanceInformationList", [])
        matches = [row for row in rows if row.get("InstanceId") == instance_id]
        return len(matches) == 1 and matches[0].get("PingStatus") == "Online"

    def _wait_ready(self, instance_id: str, *, cleanup: bool = False) -> None:
        self._poll(lambda: self._instance_state(instance_id) == "running",
                   timeout=START_TIMEOUT_SECONDS, reason=f"{instance_id.upper()}_START_TIMEOUT",
                   message="EC2 did not reach running state", cleanup=cleanup)
        self._poll(lambda: self._instance_status_ok(instance_id),
                   timeout=START_TIMEOUT_SECONDS, reason=f"{instance_id.upper()}_STATUS_CHECK_TIMEOUT",
                   message="EC2 instance/system status checks did not pass", cleanup=cleanup)
        self._poll(lambda: self._ssm_online(instance_id),
                   timeout=SSM_TIMEOUT_SECONDS, reason=f"{instance_id.upper()}_SSM_OFFLINE",
                   message="SSM did not report the exact instance Online", cleanup=cleanup)

    def _ssm_command(self, instance_id: str, command: str, *, cleanup: bool = False) -> str:
        deadline = self._deadline(COMMAND_TIMEOUT_SECONDS, cleanup=cleanup)
        result = _ssm_run_command(self.aws, instance_id, command,
                                  timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                                  deadline=deadline, sleep=self.sleep, monotonic=self.monotonic)
        return result["stdout"]

    def _audit_guest(self, role: str) -> dict[str, Any]:
        instance_id, private_ip = (WEB_ID, WEB_PRIVATE_IP) if role == "web" else (EMR_ID, EMR_PRIVATE_IP)
        output = self._ssm_command(
            instance_id, _guest_audit_command(instance_id=instance_id, private_ip=private_ip, role=role)
        )
        result = {
            "identity": _only_line(output, "GUEST_IDENTITY"),
            "tunnel_or_wireguard": _only_line(output, "TUNNEL_OR_WIREGUARD"),
            "running_container_count": int(_only_line(output, "RUNNING_CONTAINER_COUNT")),
            "writer_or_tunnel_process_count": int(_only_line(output, "WRITER_OR_TUNNEL_PROCESS_COUNT")),
            "active_relevant_services": _only_line(output, "ACTIVE_RELEVANT_SERVICES").split(",") if
                _only_line(output, "ACTIVE_RELEVANT_SERVICES") else [],
            "nat_baseline": _only_line(output, "NAT_BASELINE"),
            "ip_forward": _only_line(output, "IP_FORWARD"),
            "relevant_timer_count": int(_only_line(output, "RELEVANT_TIMER_COUNT")),
            "relevant_cron_job_count": int(_only_line(output, "RELEVANT_CRON_JOB_COUNT")),
        }
        _require(result["identity"] == "PASS", "GUEST_IDENTITY_MISMATCH",
                 f"{role.upper()} guest IMDS identity did not match the pinned target")
        _require(result["tunnel_or_wireguard"] == "ABSENT", "GUEST_TUNNEL_OR_WIREGUARD_ACTIVE",
                 f"{role.upper()} has an active/enabled WireGuard or Cloudflare Tunnel path")
        _require(result["running_container_count"] == 0, "GUEST_AUTOSTART_CONTAINER_ACTIVE",
                 f"{role.upper()} started an application container during the isolated Canary")
        _require(result["writer_or_tunnel_process_count"] == 0,
                 "GUEST_WRITER_OR_TUNNEL_PROCESS_ACTIVE",
                 f"{role.upper()} has an active application writer, database, or tunnel process")
        _require(result["relevant_timer_count"] == 0 and result["relevant_cron_job_count"] == 0,
                 "GUEST_AUTOMATED_JOB_PRESENT",
                 f"{role.upper()} has an unreviewed DR/application timer or cron job")
        services = [name for name in result["active_relevant_services"] if name]
        unknown = [name for name in services if name not in SAFE_ACTIVE_SERVICES]
        _require(not unknown, "GUEST_UNEXPECTED_SERVICE_ACTIVE",
                 f"{role.upper()} started an unapproved relevant service")
        if role == "web":
            _require(result["nat_baseline"] == "ABSENT", "NAT_ROLE_BASELINE_ALREADY_EXISTS",
                     "A previous NAT role baseline exists; this run cannot safely claim or restore it")
            _require(result["ip_forward"] in {"0", "1"}, "GUEST_IP_FORWARD_UNREADABLE",
                     "Web runtime IPv4 forwarding could not be read")
        return result

    def _fresh_identity_and_state(self) -> None:
        identity = self.aws.call("sts", "GetCallerIdentity")
        _require(identity.get("Account") == ACCOUNT_ID, "AWS_ACCOUNT_MISMATCH",
                 "AWS caller account changed before Canary mutation")
        for instance_id, required_state in ((WEB_ID, "stopped"), (EMR_ID, "stopped"), (DB_ID, "running")):
            _require(self._instance_state(instance_id) == required_state,
                     "INSTANCE_STATE_CHANGED_BEFORE_CANARY",
                     f"{instance_id} lifecycle changed after the preflight snapshot")
        self._fresh_db_read_only()
        self._assert_original_eni_sgs(WEB_ID)
        self._assert_original_eni_sgs(EMR_ID)
        self._assert_endpoint_baseline()
        self._assert_routes_unchanged()

    def _fresh_db_read_only(self) -> None:
        output = self._ssm_command(DB_ID, _db_probe_command())
        parsed = _parse_db_probe(output)
        self.state["db_read_only_recheck"] = parsed
        self._save()
        self._event("DB_READ_ONLY_RECHECK", status="PASS")

    def _assert_original_eni_sgs(self, instance_id: str) -> None:
        eni_id = WEB_ENI if instance_id == WEB_ID else EMR_ENI
        actual = self.aws.call("ec2", "DescribeNetworkInterfaces", {
            "NetworkInterfaceIds": [eni_id],
        }).get("NetworkInterfaces", [])
        _require(len(actual) == 1 and actual[0].get("Attachment", {}).get("InstanceId") == instance_id,
                 "TARGET_ENI_IDENTITY_CHANGED", "Target ENI no longer belongs to the approved EC2")
        got = sorted(group.get("GroupId", "") for group in actual[0].get("Groups", []))
        expected = sorted(self.state["original_sg_ids"][instance_id])
        _require(got == expected, "TARGET_SG_CHANGED_BEFORE_CANARY",
                 "Target ENI security-group set changed after preflight")

    def _assert_endpoint_baseline(self) -> None:
        for group_id, before in self.state["endpoint_sg_rules_before"].items():
            rows = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
            _require(len(rows) == 1
                     and _canonical(rows[0].get("IpPermissions", [])) == _canonical(before["ingress"])
                     and _canonical(rows[0].get("IpPermissionsEgress", [])) == _canonical(before["egress"]),
                     "ENDPOINT_SG_BASELINE_CHANGED", "SSM endpoint SG changed after preflight")

    def _assert_routes_unchanged(self) -> None:
        rows = self.aws.call("ec2", "DescribeRouteTables", {"RouteTableIds": [PRIVATE_ROUTE_TABLE_ID]}).get("RouteTables", [])
        _require(len(rows) == 1 and _canonical(_route_table_snapshot(rows[0])) ==
                 _canonical(self.state["route_table_before"]),
                 "NAT_ROUTE_TABLE_CHANGED_BEFORE_CANARY", "NAT route table changed after preflight")

    def _create_security_group(self, role: str) -> str:
        run_id = self.state["run_id"]
        name = f"hospital-dr-nat-emr-canary-{role}-{run_id[:8]}"
        self.state["sg_create_requested"].append(role)
        self._save()
        response = self.aws.call("ec2", "CreateSecurityGroup", {
            "Description": f"Temporary isolated Hospital DR NAT/EMR Canary {run_id} {role}",
            "GroupName": name,
            "VpcId": VPC_ID,
            "TagSpecifications": [{
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "Purpose", "Value": "HospitalDR-NAT-EMR-Canary"},
                    {"Key": "HospitalDRCanaryRunId", "Value": run_id},
                    {"Key": "HospitalDRCanaryRole", "Value": role},
                ],
            }],
        })
        group_id = str(response.get("GroupId", ""))
        _require(re.fullmatch(r"sg-[0-9a-f]+", group_id) is not None,
                 "CANARY_SG_CREATE_UNVERIFIED", "Temporary SG creation returned no valid group id")
        self.state["canary_sg_ids"][role] = group_id
        self._save()
        self._event("CANARY_SG_CREATED", role=role, group_id=group_id)
        return group_id

    def _verify_canary_sg_ownership(self, role: str, group_id: str) -> dict[str, Any]:
        rows = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
        _require(len(rows) == 1 and rows[0].get("GroupId") == group_id and rows[0].get("VpcId") == VPC_ID,
                 "CANARY_SG_IDENTITY_UNVERIFIED", "Temporary SG identity or VPC differs from this transaction")
        tags = {item.get("Key"): item.get("Value") for item in rows[0].get("Tags", [])}
        expected_name = f"hospital-dr-nat-emr-canary-{role}-{self.state['run_id'][:8]}"
        _require(
            tags.get("Name") == expected_name
            and tags.get("Purpose") == "HospitalDR-NAT-EMR-Canary"
            and tags.get("HospitalDRCanaryRunId") == self.state["run_id"]
            and tags.get("HospitalDRCanaryRole") == role,
            "CANARY_SG_OWNERSHIP_UNVERIFIED",
            "Temporary SG ownership tags do not match this exact run and role",
        )
        return rows[0]

    def _configure_security_group(self, role: str, group_id: str) -> None:
        group_before = self._verify_canary_sg_ownership(role, group_id)
        _require(group_before.get("IpPermissions") == [],
                 "CANARY_SG_UNEXPECTED_INGRESS", "New SG is not exact-target and empty-ingress")
        for permission in group_before.get("IpPermissionsEgress", []):
            self.aws.call("ec2", "RevokeSecurityGroupEgress", {
                "GroupId": group_id, "IpPermissions": [_ip_permission(permission)],
            })
        readback = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
        _require(len(readback) == 1 and not readback[0].get("IpPermissionsEgress"),
                 "CANARY_DEFAULT_EGRESS_REMAINS", "Default allow-all egress remains on the temporary SG")
        for endpoint_sg in self.state["endpoint_sg_ids"]:
            self.aws.call("ec2", "AuthorizeSecurityGroupEgress", {
                "GroupId": group_id, "IpPermissions": [_egress_rule_group(endpoint_sg)],
            })
        if role == "web":
            self.aws.call("ec2", "AuthorizeSecurityGroupIngress", {
                "GroupId": group_id, "IpPermissions": [_emr_ingress_rule()],
            })
        groups = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [group_id]}).get("SecurityGroups", [])
        _require(len(groups) == 1, "CANARY_SG_READBACK_FAILED", "Temporary SG readback failed")
        errors = validate_canary_security_group(
            groups[0], role=role, endpoint_sgs=set(self.state["endpoint_sg_ids"]),
            probe_ips=set(),
        )
        _require(not errors, errors[0] if errors else "CANARY_SG_CONTRACT_FAILED",
                 "Temporary SG does not match the exact isolation rule contract")
        self._event("CANARY_SG_CONFIGURED", role=role, egress_rules=len(groups[0].get("IpPermissionsEgress", [])))

    def _authorize_probe_egress(self) -> None:
        _require(not self.state.get("probe_egress_enable_requested"),
                 "PROBE_EGRESS_ALREADY_REQUESTED", "Pinned public probe egress may only be enabled once")
        # Persist intent before the first AWS call. If the process stops partway
        # through, the existing state-bound restore deletes the temporary SGs.
        self.state["probe_egress_enable_requested"] = True
        self._save()
        for role in ("web", "emr"):
            group_id = self.state["canary_sg_ids"][role]
            group = self._verify_canary_sg_ownership(role, group_id)
            errors = validate_canary_security_group(
                group, role=role, endpoint_sgs=set(self.state["endpoint_sg_ids"]), probe_ips=set(),
            )
            _require(not errors, errors[0] if errors else "PROBE_EGRESS_BASELINE_INVALID",
                     "Probe egress cannot be enabled until the SSM-only SG contract is verified")
            for ip in self.state["probe_ips"]:
                self.aws.call("ec2", "AuthorizeSecurityGroupEgress", {
                    "GroupId": group_id, "IpPermissions": [_egress_rule_cidr(f"{ip}/32")],
                })
            readback = self._verify_canary_sg_ownership(role, group_id)
            errors = validate_canary_security_group(
                readback, role=role, endpoint_sgs=set(self.state["endpoint_sg_ids"]),
                probe_ips=set(self.state["probe_ips"]),
            )
            _require(not errors, errors[0] if errors else "PROBE_EGRESS_READBACK_FAILED",
                     "Pinned probe egress did not read back as the exact SG allowlist")
            self._event("PINNED_PROBE_EGRESS_ENABLED", role=role, probe_ip_count=len(self.state["probe_ips"]))
        self._verify_isolation_readback()

    def _authorize_endpoint_sgs(self) -> None:
        for endpoint_id in self.state["endpoint_sg_ids"]:
            before = self.state["endpoint_sg_rules_before"][endpoint_id]
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_id]}).get("SecurityGroups", [])
            _require(len(current) == 1
                     and _canonical(current[0].get("IpPermissions", [])) == _canonical(before["ingress"])
                     and _canonical(current[0].get("IpPermissionsEgress", [])) == _canonical(before["egress"]),
                     "ENDPOINT_SG_BASELINE_CHANGED", "SSM endpoint SG drifted before temporary ingress")
            for role in ("web", "emr"):
                source_sg = self.state["canary_sg_ids"][role]
                # Persist intent before adding the rule, so --restore handles a crash
                # between authorization and readback.
                item = {"endpoint_sg_id": endpoint_id, "source_sg_id": source_sg}
                if item not in self.state["endpoint_ingress_added"]:
                    self.state["endpoint_ingress_added"].append(item)
                    self._save()
                self.aws.call("ec2", "AuthorizeSecurityGroupIngress", {
                    "GroupId": endpoint_id,
                    "IpPermissions": [{
                        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "UserIdGroupPairs": [{"GroupId": source_sg}],
                    }],
                })
        for endpoint_id in self.state["endpoint_sg_ids"]:
            current = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_id]}).get("SecurityGroups", [])
            _require(len(current) == 1, "ENDPOINT_SG_READBACK_FAILED", "Endpoint SG readback failed")
            for role in ("web", "emr"):
                _require(any(_rule_is_group_443(rule, self.state["canary_sg_ids"][role])
                             for rule in current[0].get("IpPermissions", [])),
                         "ENDPOINT_SG_INGRESS_NOT_VISIBLE", "Temporary SSM 443 ingress did not read back")

    def _replace_eni_sg(self, role: str) -> None:
        instance_id = WEB_ID if role == "web" else EMR_ID
        eni_id = WEB_ENI if role == "web" else EMR_ENI
        self._assert_original_eni_sgs(instance_id)
        group_id = self.state["canary_sg_ids"][role]
        self.state["eni_replacement_started"].append(role)
        self._save()
        self.aws.call("ec2", "ModifyNetworkInterfaceAttribute", {
            "NetworkInterfaceId": eni_id, "Groups": [group_id],
        })
        rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
        attached = sorted(item.get("GroupId", "") for item in rows[0].get("Groups", [])) if len(rows) == 1 else []
        _require(attached == [group_id], "CANARY_SG_REPLACEMENT_READBACK_FAILED",
                 f"{role.upper()} ENI did not contain only its isolated Canary SG")
        self._event("ENI_ISOLATED", role=role, eni_id=eni_id, canary_sg_id=group_id)

    def _verify_endpoint_membership(self) -> None:
        expected = set(self.state["report_before"]["resources"]["endpoint_eni_ids"])
        rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {
            "Filters": [{"Name": "group-id", "Values": self.state["endpoint_sg_ids"]}],
        }).get("NetworkInterfaces", [])
        _require({row.get("NetworkInterfaceId") for row in rows} == expected
                 and all(row.get("Status") == "in-use" for row in rows),
                 "SSM_ENDPOINT_SG_MEMBERSHIP_CHANGED", "Endpoint SG attached to unexpected or inactive ENIs")

    def prepare_isolation(self) -> None:
        self._fresh_identity_and_state()
        self._phase("CREATE_TEMPORARY_SECURITY_GROUPS")
        web_sg = self._create_security_group("web")
        emr_sg = self._create_security_group("emr")
        self._phase("CONFIGURE_TEMPORARY_SECURITY_GROUPS")
        self._configure_security_group("web", web_sg)
        self._configure_security_group("emr", emr_sg)
        self._phase("AUTHORIZE_TEMPORARY_SSM_ENDPOINT_INGRESS")
        self._authorize_endpoint_sgs()
        self._phase("REPLACE_WEB_ENI_SECURITY_GROUP")
        self._replace_eni_sg("web")
        self._phase("REPLACE_EMR_ENI_SECURITY_GROUP")
        self._replace_eni_sg("emr")
        self._verify_endpoint_membership()
        self._verify_isolation_readback()
        self._phase("ISOLATION_VERIFIED")

    def _verify_isolation_readback(self) -> None:
        for role, eni_id in (("web", WEB_ENI), ("emr", EMR_ENI)):
            rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
            _require(len(rows) == 1, "ISOLATED_ENI_READBACK_FAILED", "Target ENI could not be read back")
            actual = sorted(item.get("GroupId", "") for item in rows[0].get("Groups", []))
            _require(actual == [self.state["canary_sg_ids"][role]],
                     "ORIGINAL_SG_REMAINS_ATTACHED", f"Original {role.upper()} SG remains attached")
            group = self._verify_canary_sg_ownership(role, self.state["canary_sg_ids"][role])
            errors = validate_canary_security_group(
                group, role=role,
                endpoint_sgs=set(self.state["endpoint_sg_ids"]),
                probe_ips=(set(self.state["probe_ips"])
                           if self.state.get("probe_egress_enable_requested") else set()),
            )
            _require(not errors, errors[0] if errors else "ISOLATION_READBACK_FAILED",
                     f"{role.upper()} SG isolation readback failed")
        self._verify_endpoint_membership()

    def _start(self, instance_id: str) -> None:
        _require(self._instance_state(instance_id) == "stopped",
                 "INSTANCE_NOT_STOPPED_BEFORE_START", f"{instance_id} is not stopped before start")
        self.state["start_requested"][instance_id] = True
        self._save()
        self._phase("START_EC2", instance_id=instance_id)
        self.aws.call("ec2", "StartInstances", {"InstanceIds": [instance_id]})
        self._wait_ready(instance_id)
        self._event("EC2_AND_SSM_READY", instance_id=instance_id)

    def _setup_ansible_transport(self, *, cleanup: bool = False) -> dict[str, str]:
        state_dir = self.state_path.parent
        ssh_config = state_dir / f"{self.state['run_id']}.ssh_config"
        inventory = state_dir / f"{self.state['run_id']}.inventory.ini"
        known_hosts = Path(os.environ.get("DR_SSH_KNOWN_HOSTS_FILE", "/var/lib/hospital-dr/ssh/known_hosts"))
        secret_file = os.environ.get("DR_SECRET_FILE", "/home/cloud/hospital-dr-secrets/dr.env")
        _require(known_hosts.is_file() and not known_hosts.is_symlink()
                 and os.access(known_hosts, os.R_OK),
                 "SSH_KNOWN_HOSTS_UNAVAILABLE", "Existing persistent SSH known_hosts is required; no new trust path is created")
        shell_script = r"""set -euo pipefail
umask 077
source "$1"
source "$DR_SSM_SSH_HELPER"
dr_load_secret_file
dr_resolve_ssh_key_config
dr_validate_ssh_key_files
dr_ssm_write_ssh_config "$2" "$3" "$SSH_KEY" "$4" "$5" "$6" "$7"
dr_ssm_write_ansible_inventory "$8" "$SSH_KEY" "$9"
"""
        args = [
            "bash", "-c", shell_script, "canary-transport",
            str(REPO_ROOT / "operations/runtime_paths.sh"), REGION, WEB_ID,
            str(known_hosts), str(EMR_PRIVATE_IP), str(DB_PRIVATE_IP), DB_ID,
            str(inventory), str(ssh_config),
        ]
        env = dict(os.environ)
        env.update({
            "DR_REPO_ROOT": str(REPO_ROOT),
            "DR_ANSIBLE_DIR": str(REPO_ROOT / "automation/ansible"),
            "DR_SECRET_FILE": secret_file,
            "DR_SSH_CONFIG_FILE": str(ssh_config),
            "DR_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
        })
        transport_deadline = self._deadline(20, cleanup=cleanup)
        transport_timeout = max(0.1, transport_deadline - self.monotonic())
        try:
            result = self.command_runner(args, env=env, capture_output=True, text=True,
                                         timeout=transport_timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise NatEmrCanaryError("ANSIBLE_TRANSPORT_PREP_TIMEOUT",
                                    "Existing SSM/SSH transport setup exceeded its timeout") from exc
        except OSError as exc:
            raise NatEmrCanaryError("ANSIBLE_TRANSPORT_UNAVAILABLE",
                                    "Could not prepare the existing SSM/SSH Ansible transport") from exc
        _require(result.returncode == 0 and inventory.is_file() and ssh_config.is_file(),
                 "ANSIBLE_TRANSPORT_PREP_FAILED",
                 "Existing SSH key/known_hosts/SSM transport did not produce the private Ansible files")
        for path in (inventory, ssh_config):
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(path, flags)
                try:
                    info = os.fstat(fd)
                    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                             and info.st_uid == os.geteuid(),
                             "ANSIBLE_TRANSPORT_FILE_UNSAFE",
                             "Generated SSM transport file is not an operator-owned regular file")
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise NatEmrCanaryError("ANSIBLE_TRANSPORT_FILE_UNSAFE",
                                        "Could not secure the generated SSM transport file") from exc
        self.state["ansible_inventory"] = str(inventory)
        self.state["ansible_ssh_config"] = str(ssh_config)
        self._save()
        return {"inventory": str(inventory), "ssh_config": str(ssh_config)}

    def _run_nat_role(self, *, restore: bool) -> None:
        _require(NAT_APPLY_PLAYBOOK.is_file() and not NAT_APPLY_PLAYBOOK.is_symlink()
                 and NAT_RESTORE_PLAYBOOK.is_file() and not NAT_RESTORE_PLAYBOOK.is_symlink()
                 and ANSIBLE_CONFIG.is_file() and not ANSIBLE_CONFIG.is_symlink(),
                 "NAT_ROLE_CANONICAL_FILES_MISSING", "Reviewed canonical NAT playbooks/config are unavailable")
        paths = self._setup_ansible_transport(cleanup=restore)
        playbook = NAT_RESTORE_PLAYBOOK if restore else NAT_APPLY_PLAYBOOK
        action = "remove" if restore else "apply"
        environment = dict(os.environ)
        environment.update({
            "AWS_WEB_NAT_INSTANCE_ENABLED": "true",
            "AWS_REGION": REGION,
            "ANSIBLE_CONFIG": str(ANSIBLE_CONFIG),
        })
        command = [
            "ansible-playbook", "-i", paths["inventory"], str(playbook), "--limit", "web_servers",
            "-e", "aws_web_nat_instance_enabled=true",
            "-e", f"aws_web_nat_instance_action={action}",
            "-e", f"aws_web_nat_instance_expected_instance_id={WEB_ID}",
            "-e", f"aws_web_nat_instance_expected_private_ip={WEB_PRIVATE_IP}",
            "-e", f"aws_web_nat_instance_expected_vpc_id={VPC_ID}",
            "-e", f"aws_web_nat_instance_expected_subnet_id={WEB_SUBNET}",
            "-e", f"aws_web_nat_instance_expected_eni={WEB_ENI}",
        ]
        role_deadline = self._deadline(NAT_ROLE_TIMEOUT_SECONDS, cleanup=restore)
        role_timeout = max(0.1, role_deadline - self.monotonic())
        self._event("NAT_ROLE_EXECUTION_START", action=action,
                    timeout_seconds=round(role_timeout, 1))
        self.state["nat_role_outcome_uncertain"] = True
        self._save()
        try:
            process = subprocess.Popen(
                command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                close_fds=True, pass_fds=(self._lock_fd,) if self._lock_fd is not None else (),
                start_new_session=True,
            )
        except OSError as exc:
            self.state["nat_role_outcome_uncertain"] = False
            self._save()
            raise NatEmrCanaryError("NAT_ROLE_EXECUTOR_UNAVAILABLE",
                                    "Could not start the reviewed Ansible NAT role") from exc

        def terminate_process_group() -> None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    for pipe in (process.stdout, process.stderr):
                        if pipe is not None:
                            pipe.close()

        try:
            _stdout, _stderr = process.communicate(timeout=role_timeout)
        except subprocess.TimeoutExpired as exc:
            terminate_process_group()
            self.state["phase"] = "NAT_ROLE_REMOTE_OUTCOME_UNCERTAIN"
            try:
                self._save()
            except CanaryError:
                pass
            self._safe_event("NAT_ROLE_EXECUTION_TIMEOUT", action=action)
            raise NatEmrCanaryError("NAT_ROLE_TIMEOUT", "NAT role exceeded its bounded execution time") from exc
        except KeyboardInterrupt:
            terminate_process_group()
            self.state["phase"] = "NAT_ROLE_REMOTE_OUTCOME_UNCERTAIN"
            try:
                self._save()
            except CanaryError:
                pass
            self._safe_event("NAT_ROLE_EXECUTION_INTERRUPTED", action=action)
            raise
        self.state["nat_role_outcome_uncertain"] = False
        self._save()
        _require(process.returncode == 0, "NAT_ROLE_RESTORE_FAILED" if restore else "NAT_ROLE_APPLY_FAILED",
                 "NAT role returned a nonzero result; raw Ansible output was suppressed")
        self._event("NAT_ROLE_EXECUTION_COMPLETE", action=action, status="PASS")

    def _nat_baseline_fingerprint(self) -> str:
        output = self._ssm_command(WEB_ID, f"""set -eu
sudo test -f {NAT_BASELINE_FILE}
sudo test ! -L {NAT_BASELINE_FILE}
mode=$(sudo stat -c '%a' {NAT_BASELINE_FILE})
owner=$(sudo stat -c '%u' {NAT_BASELINE_FILE})
test "$mode" = 600 && test "$owner" = 0
hash=$(sudo sha256sum {NAT_BASELINE_FILE} | awk '{{print $1}}')
printf 'NAT_BASELINE_SHA256=%s\\n' "$hash"
""", cleanup=True)
        digest = _only_line(output, "NAT_BASELINE_SHA256")
        _require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                 "NAT_BASELINE_HASH_INVALID", "Guest NAT baseline fingerprint is invalid")
        return digest

    def _verify_guest_nat(self) -> dict[str, str]:
        output = self._ssm_command(WEB_ID, "sudo /usr/local/sbin/hospital-dr-web-nat-instance verify")
        status = _only_line(output, "NAT_GUEST_STATUS")
        _require(status == "READY", "NAT_GUEST_NOT_READY",
                 "Guest NAT role did not report exact persistent forwarding/rules readiness")
        return {"guest_status": status}

    def _verify_nat_routes_active(self) -> dict[str, Any]:
        result = self.aws.call("ec2", "DescribeRouteTables", {"RouteTableIds": [PRIVATE_ROUTE_TABLE_ID]})
        rows = result.get("RouteTables", [])
        _require(len(rows) == 1 and rows[0].get("VpcId") == VPC_ID,
                 "NAT_ROUTE_TABLE_READBACK_FAILED", "Could not read the exact private NAT route table")
        classification = classify_nat_routes(rows[0], WEB_ENI)
        _require(classification == "active", "NAT_ROUTE_NOT_ACTIVE",
                 "Both private routes must be active and target the Web ENI")
        return _route_table_snapshot(rows[0])

    def _verify_nat_status_candidate(self) -> dict[str, str]:
        status_deadline = self._deadline(65)
        status_timeout = max(1, int(status_deadline - self.monotonic()))
        try:
            result = self.command_runner(
                ["timeout", "--foreground", "--signal=TERM", "--kill-after=5s",
                 f"{max(1, status_timeout - 5)}s",
                 "env", f"AWS_REGION={REGION}", str(NAT_STATUS_SCRIPT)],
                capture_output=True, text=True, timeout=status_timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NatEmrCanaryError("NAT_STATUS_CHECK_TIMEOUT",
                                    "Canonical read-only NAT status command did not finish") from exc
        if result.returncode != 2:
            raise NatEmrCanaryError("NAT_STATUS_CONTRACT_UNEXPECTED",
                                    "Read-only status must remain PENDING_LIVE_TEST before EMR egress evidence")
        fields: dict[str, list[str]] = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields.setdefault(key, []).append(value.strip())
        expected = {
            "NAT_INSTANCE_STATUS": "PENDING_LIVE_TEST",
            "CURRENT_EGRESS_MODE": "WEB_NAT_INSTANCE_CANDIDATE",
            "WEB_INSTANCE_STATE": "running",
            "WEB_ENI": WEB_ENI,
            "WEB_EIP_PUBLIC_IP": EXPECTED_WEB_EIP,
            "SOURCE_DEST_CHECK": "False",
            "PRIVATE_DEFAULT_ROUTE_STATE": "active",
            "PRIVATE_DEFAULT_ROUTE_TARGET": WEB_ENI,
        }
        for key, value in expected.items():
            _require(fields.get(key) == [value], "NAT_STATUS_IDENTITY_OR_ROUTE_MISMATCH",
                     f"Canonical NAT status checker did not return exact {key} candidate value")
        return {key: values[0] for key, values in fields.items() if len(values) == 1 and key in expected}

    def _probe_emr_egress(self) -> str:
        ips = self.state["probe_ips"]
        observed: set[str] = set()
        for ip in ips:
            output = self._ssm_command(EMR_ID, _emr_probe_command(PROBE_HOST, ip))
            value = _only_line(output, "EGRESS_PUBLIC_IP")
            parsed = ipaddress.ip_address(value)
            _require(parsed.version == 4 and parsed.is_global, "EMR_EGRESS_RESPONSE_INVALID",
                     "EMR egress probe did not return one public IPv4 address")
            observed.add(value)
        _require(observed == {EXPECTED_WEB_EIP}, "EMR_EGRESS_IP_MISMATCH",
                 "EMR HTTPS egress did not use the pinned Web EIP")
        return next(iter(observed))

    def run_steps(self) -> dict[str, Any]:
        self._require_run_state()
        self._event("CANARY_RUN_BEGIN", run_id=self.state["run_id"], max_minutes=self.max_minutes)
        self.prepare_isolation()

        self._start(WEB_ID)
        self._phase("AUDIT_WEB_GUEST")
        self.state["web_guest_audit"] = self._audit_guest("web")
        self._event("WEB_GUEST_AUDIT", status="PASS")

        self._phase("VERIFY_PRE_NAT_BASELINE_ABSENT")
        # A role-owned baseline from an earlier operation cannot be claimed by
        # this transaction. The audit above proves it was absent after boot.
        self.state["nat_apply_started"] = True
        self.state["nat_restore_required"] = True
        self._save()
        self._phase("APPLY_NAT_ANSIBLE_ROLE")
        self._run_nat_role(restore=False)
        self.state["nat_baseline_sha256"] = self._nat_baseline_fingerprint()
        self._save()
        self._verify_guest_nat()
        self._phase("VERIFY_NAT_ROUTE_ACTIVE")
        self.state["route_active_after_web"] = self._verify_nat_routes_active()
        self._state_event("NAT_BOOTSTRAP_READY", status="PENDING_LIVE_TEST")
        self._verify_nat_status_candidate()

        self._start(EMR_ID)
        self._phase("AUDIT_EMR_GUEST")
        self.state["emr_guest_audit"] = self._audit_guest("emr")
        self._event("EMR_GUEST_AUDIT", status="PASS")
        self._phase("ENABLE_PINNED_PROBE_EGRESS")
        self._authorize_probe_egress()
        self._phase("VERIFY_EMR_EXTERNAL_EGRESS")
        self.state["observed_egress_ip"] = self._probe_emr_egress()
        self._event("EMR_EGRESS_VERIFIED", egress_ip=self.state["observed_egress_ip"])
        self._phase("VERIFY_FINAL_NAT_CONTRACT")
        self._verify_nat_routes_active()
        self._verify_guest_nat()
        self._verify_nat_status_candidate()
        _require(self.state.get("observed_egress_ip") == EXPECTED_WEB_EIP,
                 "FINAL_NAT_EGRESS_CONTRACT_FAILED", "Final egress evidence does not match Web EIP")
        self.state["canary_nat_contract"] = "PASS"
        self.state["production_nat_status"] = "NOT_CHANGED"
        self._phase("CANARY_NAT_CONTRACT_VERIFIED")
        return {"status": "PASS", "canary_nat_contract": "PASS",
                "observed_egress_ip": self.state["observed_egress_ip"]}

    def _require_run_state(self) -> None:
        _require(self.state is not None and self.state.get("phase") == "SNAPSHOT_SAVED",
                 "CANARY_STATE_NOT_PREPARED", "Canary snapshot must be durable before mutations")

    def _state_event(self, event: str, **fields: Any) -> None:
        self._event(event, **fields)

    def _stop_instance(self, instance_id: str, *, cleanup: bool = False) -> None:
        state = self._instance_state(instance_id)
        if state == "stopped":
            self._event("EC2_ALREADY_STOPPED", instance_id=instance_id)
            return
        if state in {"running", "pending"}:
            _require(self.state.get("start_requested", {}).get(instance_id) is True,
                     "INSTANCE_STARTED_OUTSIDE_CANARY",
                     f"{instance_id} became active without a recorded Canary start request; refusing to stop it")
            self._event("STOP_EC2_START", instance_id=instance_id, prior_state=state)
            self.aws.call("ec2", "StopInstances", {"InstanceIds": [instance_id]})
        elif state != "stopping":
            raise NatEmrCanaryError("EC2_STOP_STATE_UNSUPPORTED",
                                    f"{instance_id} has an unsupported state; isolation remains attached")
        started = self.monotonic()
        deadline = self._deadline(STOP_TIMEOUT_SECONDS, cleanup=cleanup)
        while self.monotonic() < deadline:
            if self._instance_state(instance_id) == "stopped":
                self._event("EC2_STOPPED", instance_id=instance_id,
                            elapsed_seconds=round(self.monotonic() - started, 1))
                return
            self.sleep(min(POLL_SECONDS, max(0.0, deadline - self.monotonic())))
        raise NatEmrCanaryError("EC2_STOP_TIMEOUT", f"{instance_id} did not stop before the cleanup timeout")

    def _ensure_web_ssm_for_restore(self) -> None:
        self._verify_isolation_readback()
        state = self._instance_state(WEB_ID)
        if state == "stopped":
            self._phase("RESTART_ISOLATED_WEB_FOR_NAT_RESTORE")
            self.state["start_requested"][WEB_ID] = True
            self._save()
            self.aws.call("ec2", "StartInstances", {"InstanceIds": [WEB_ID]})
            self._wait_ready(WEB_ID, cleanup=True)
        elif state in {"pending", "running"}:
            if state == "pending":
                self._wait_ready(WEB_ID, cleanup=True)
            _require(self._ssm_online(WEB_ID), "WEB_SSM_OFFLINE_DURING_NAT_RESTORE",
                     "Web is not SSM Online for NAT role restoration")
        else:
            raise NatEmrCanaryError("WEB_STATE_UNSAFE_FOR_NAT_RESTORE",
                                    "Web cannot be safely reached for NAT baseline restoration")

    def _restore_nat_role(self) -> None:
        if not self.state.get("nat_restore_required"):
            return
        # The role writes its durable baseline before changing sysctl/files/
        # firewall. If it never got that far, an absent baseline proves the
        # role itself performed its own no-change failure path.
        self._ensure_web_ssm_for_restore()
        if not self.state.get("nat_baseline_sha256"):
            try:
                self.state["nat_baseline_sha256"] = self._nat_baseline_fingerprint()
                self._save()
            except CanaryError:
                absent = self._ssm_command(WEB_ID, f"sudo test ! -e {NAT_BASELINE_FILE} && sudo test ! -d {NAT_BASELINE_DIR}/baseline && echo NAT_BASELINE=ABSENT", cleanup=True)
                _require(_only_line(absent, "NAT_BASELINE") == "ABSENT",
                         "NAT_BASELINE_UNVERIFIED", "Cannot prove whether the interrupted NAT role changed guest state")
                self.state["nat_restore_required"] = False
                self.state["nat_role_outcome_uncertain"] = False
                self._save()
                return
        current_hash = self._nat_baseline_fingerprint()
        _require(current_hash == self.state["nat_baseline_sha256"],
                 "NAT_BASELINE_SHA256_CHANGED", "NAT role baseline changed; refusing destructive rollback")
        self._run_nat_role(restore=True)
        # The Ansible role removes its transaction state only after verifying
        # baseline file hashes, sysctl runtime, service state and firewall.
        absent = self._ssm_command(WEB_ID, f"sudo test ! -e {NAT_BASELINE_FILE} && sudo test ! -d {NAT_BASELINE_DIR} && echo NAT_RESTORE=PASS", cleanup=True)
        _require(_only_line(absent, "NAT_RESTORE") == "PASS",
                 "NAT_BASELINE_REMAINS_AFTER_RESTORE", "NAT role baseline directory remains after restore")
        self.state["nat_restore_required"] = False
        self.state["nat_role_outcome_uncertain"] = False
        self.state["nat_baseline_sha256"] = ""
        self._save()
        self._event("NAT_GUEST_BASELINE_RESTORED", status="PASS")

    def _restore_eni_sg(self, role: str) -> None:
        instance_id = WEB_ID if role == "web" else EMR_ID
        eni_id = WEB_ENI if role == "web" else EMR_ENI
        canary_sg = self.state.get("canary_sg_ids", {}).get(role, "")
        original = sorted(self.state.get("original_sg_ids", {}).get(instance_id, []))
        if not original:
            raise NatEmrCanaryError("ORIGINAL_SG_SNAPSHOT_MISSING", f"Original {role.upper()} SG set is missing")
        rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
        _require(len(rows) == 1 and rows[0].get("Attachment", {}).get("InstanceId") == instance_id,
                 "RESTORE_ENI_IDENTITY_MISMATCH", f"{role.upper()} ENI identity changed")
        actual = sorted(row.get("GroupId", "") for row in rows[0].get("Groups", []))
        if actual == original:
            return
        if not canary_sg or actual != [canary_sg]:
            raise NatEmrCanaryError("RESTORE_SG_EXTERNAL_DRIFT",
                                    f"{role.upper()} ENI SG set is unexpected; no overwrite was made")
        self._verify_canary_sg_ownership(role, canary_sg)
        self._phase("RESTORE_ENI_SECURITY_GROUPS", role=role)
        self.aws.call("ec2", "ModifyNetworkInterfaceAttribute", {
            "NetworkInterfaceId": eni_id, "Groups": original,
        })
        verify = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
        got = sorted(item.get("GroupId", "") for item in verify[0].get("Groups", [])) if len(verify) == 1 else []
        _require(got == original, "RESTORE_SG_READBACK_FAILED",
                 f"Original {role.upper()} SG attachments did not read back")

    def _restore_endpoint_rules(self) -> None:
        failures = []
        added_by_endpoint: dict[str, set[str]] = {}
        for item in self.state.get("endpoint_ingress_added", []):
            added_by_endpoint.setdefault(item.get("endpoint_sg_id", ""), set()).add(item.get("source_sg_id", ""))
        for endpoint_sg, source_groups in added_by_endpoint.items():
            original = self.state.get("endpoint_sg_rules_before", {}).get(endpoint_sg, {})
            rows = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_sg]}).get("SecurityGroups", [])
            if len(rows) != 1:
                failures.append(endpoint_sg)
                continue
            before = _canonical(original.get("ingress", []))
            current_rules = rows[0].get("IpPermissions", [])
            stripped = copy.deepcopy(current_rules)
            present_sources: set[str] = set()
            for rule in stripped:
                pairs = rule.get("UserIdGroupPairs", [])
                present_sources.update(
                    pair.get("GroupId", "") for pair in pairs
                    if pair.get("GroupId", "") in source_groups
                    and _rule_is_group_443(rule, pair.get("GroupId", ""))
                )
                rule["UserIdGroupPairs"] = [
                    pair for pair in pairs
                    if not (pair.get("GroupId", "") in source_groups
                            and _rule_is_group_443(rule, pair.get("GroupId", "")))
                ]
            stripped = [
                rule for rule in stripped
                if rule.get("IpProtocol") != "tcp"
                or rule.get("FromPort") != 443
                or rule.get("ToPort") != 443
                or rule.get("UserIdGroupPairs")
                or rule.get("IpRanges")
                or rule.get("Ipv6Ranges")
                or rule.get("PrefixListIds")
            ]
            if _canonical(stripped) != before:
                failures.append(endpoint_sg)
                continue
            for source_sg in sorted(present_sources):
                self.aws.call("ec2", "RevokeSecurityGroupIngress", {
                    "GroupId": endpoint_sg,
                    "IpPermissions": [{
                        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "UserIdGroupPairs": [{"GroupId": source_sg}],
                    }],
                })
            verify = self.aws.call("ec2", "DescribeSecurityGroups", {"GroupIds": [endpoint_sg]}).get("SecurityGroups", [])
            if len(verify) != 1 or _canonical(verify[0].get("IpPermissions", [])) != before:
                failures.append(endpoint_sg)
        if failures:
            self.state["phase"] = "RESTORE_ENDPOINT_SG_FAILED"
            self.state["endpoint_restore_failures"] = sorted(set(failures))
            self._save()
            raise NatEmrCanaryError("RESTORE_ENDPOINT_SG_FAILED",
                                    "Endpoint SG changed unexpectedly or temporary ingress did not restore")

    def _discover_created_sg(self, role: str) -> str:
        known = self.state.get("canary_sg_ids", {}).get(role, "")
        if known:
            return known
        tagged = self.aws.call("ec2", "DescribeSecurityGroups", {
            "Filters": [
                {"Name": "tag:HospitalDRCanaryRunId", "Values": [self.state["run_id"]]},
                {"Name": "tag:HospitalDRCanaryRole", "Values": [role]},
            ],
        }).get("SecurityGroups", [])
        if len(tagged) > 1:
            raise NatEmrCanaryError("RESTORE_CANARY_SG_AMBIGUOUS", "Multiple temporary SGs match the saved run")
        if tagged:
            self.state.setdefault("canary_sg_ids", {})[role] = tagged[0].get("GroupId", "")
            self._save()
            return tagged[0].get("GroupId", "")
        return ""

    def _delete_unattached_sg(self, role: str) -> None:
        group_id = self._discover_created_sg(role)
        if not group_id:
            return
        rows = self.aws.call("ec2", "DescribeSecurityGroups", {
            "Filters": [{"Name": "group-id", "Values": [group_id]}],
        }).get("SecurityGroups", [])
        if not rows:
            return
        tags = {item.get("Key"): item.get("Value") for item in rows[0].get("Tags", [])}
        _require(tags.get("HospitalDRCanaryRunId") == self.state["run_id"]
                 and tags.get("HospitalDRCanaryRole") == role,
                 "RESTORE_SG_OWNERSHIP_UNVERIFIED", "Temporary SG ownership tag does not match this state")
        attached = self.aws.call("ec2", "DescribeNetworkInterfaces", {
            "Filters": [{"Name": "group-id", "Values": [group_id]}],
        }).get("NetworkInterfaces", [])
        _require(not attached, "RESTORE_CANARY_SG_STILL_ATTACHED",
                 "Temporary SG is still attached and will not be deleted")
        self._phase("DELETE_TEMPORARY_SG", role=role, group_id=group_id)
        self.aws.call("ec2", "DeleteSecurityGroup", {"GroupId": group_id})
        verify = self.aws.call("ec2", "DescribeSecurityGroups", {
            "Filters": [{"Name": "group-id", "Values": [group_id]}],
        }).get("SecurityGroups", [])
        _require(not verify, "RESTORE_CANARY_SG_DELETE_UNVERIFIED", "Temporary SG still exists after delete")

    def _verify_restored_network(self) -> None:
        for instance_id, eni_id, original_groups in (
            (WEB_ID, WEB_ENI, self.state["original_sg_ids"][WEB_ID]),
            (EMR_ID, EMR_ENI, self.state["original_sg_ids"][EMR_ID]),
        ):
            _require(self._instance_state(instance_id) == "stopped", "RESTORE_INSTANCE_NOT_STOPPED",
                     f"{instance_id} must be stopped before normal SG is restored")
            rows = self.aws.call("ec2", "DescribeNetworkInterfaces", {"NetworkInterfaceIds": [eni_id]}).get("NetworkInterfaces", [])
            actual = sorted(item.get("GroupId", "") for item in rows[0].get("Groups", [])) if len(rows) == 1 else []
            _require(actual == sorted(original_groups), "RESTORE_ORIGINAL_SG_MISMATCH",
                     f"{instance_id} SG set differs from the snapshot")
        self._assert_endpoint_baseline()
        self._assert_routes_unchanged()
        self._verify_db_still_read_only()

    def _remove_private_transport_files(self) -> None:
        expected = {
            "ansible_inventory": self.state_path.parent / f"{self.state['run_id']}.inventory.ini",
            "ansible_ssh_config": self.state_path.parent / f"{self.state['run_id']}.ssh_config",
        }
        for key, expected_path in expected.items():
            recorded = self.state.get(key)
            if not recorded:
                continue
            path = Path(recorded)
            _require(path.absolute() == expected_path.absolute(), "TRANSPORT_FILE_PATH_MISMATCH",
                     "Saved transport file path is outside this run's private state directory")
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            _require(not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and info.st_uid == os.geteuid() and not (info.st_mode & 0o077),
                     "TRANSPORT_FILE_PERMISSIONS", "Transport file is not private and regular; refusing cleanup")
            path.unlink()

    def _verify_db_still_read_only(self) -> None:
        result = _ssm_run_command(
            self.aws, DB_ID, _db_probe_command(), timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            deadline=self._deadline(COMMAND_TIMEOUT_SECONDS, cleanup=True),
            sleep=self.sleep, monotonic=self.monotonic,
        )
        _parse_db_probe(result["stdout"])

    def restore(self, *, confirm_nat_role_idle: bool = False) -> dict[str, Any]:
        self._restoring = True
        self._validate_loaded_state()
        if self.state.get("cleanup_complete") is True:
            self._event("RESTORE_ALREADY_COMPLETE", status="RESTORED")
            return {"phase": "RESTORED"}
        if self.state.get("nat_role_outcome_uncertain") and not confirm_nat_role_idle:
            self.state["phase"] = "RESTORE_BLOCKED_NAT_ROLE_OUTCOME_UNCERTAIN"
            self._save()
            raise NatEmrCanaryError(
                "NAT_ROLE_OUTCOME_UNCERTAIN",
                "The timed-out guest role may still be active; verify it is idle over SSM before --restore",
            )
        identity = self.aws.call("sts", "GetCallerIdentity")
        _require(identity.get("Account") == ACCOUNT_ID, "RESTORE_ACCOUNT_MISMATCH",
                 "Refusing recovery in a different AWS account")
        self.cleanup_deadline = self.monotonic() + self.cleanup_budget
        self._event("RESTORE_BEGIN", prior_phase=self.state.get("phase", "UNKNOWN"))
        failures: list[str] = []
        try:
            # Required reverse order: stop EMR, restore the guest NAT while Web
            # is SSM reachable, then stop Web before any network unisolation.
            self._stop_instance(EMR_ID, cleanup=True)
        except CanaryError as exc:
            failures.append(exc.reason)
        if not failures:
            try:
                if self.state.get("nat_restore_required"):
                    self._restore_nat_role()
            except CanaryError as exc:
                failures.append(exc.reason)
        if not failures:
            try:
                self._stop_instance(WEB_ID, cleanup=True)
            except CanaryError as exc:
                failures.append(exc.reason)
        # If a guest restore or stop is uncertain, retain all remaining
        # network isolation and temporary resources for an independent retry.
        if failures:
            self.state["phase"] = "RESTORE_BLOCKED"
            self.state["restore_failures"] = failures
            self._save()
            raise NatEmrCanaryError(failures[0], "Canary remains isolated; retry --restore after resolving the recorded condition")

        try:
            self._phase("RESTORE_WEB_ENI_SECURITY_GROUP")
            self._restore_eni_sg("web")
            self._phase("RESTORE_EMR_ENI_SECURITY_GROUP")
            self._restore_eni_sg("emr")
            self._phase("RESTORE_SSM_ENDPOINT_RULES")
            self._restore_endpoint_rules()
            self._verify_restored_network()
            for role in ("emr", "web"):
                self._delete_unattached_sg(role)
            self._remove_private_transport_files()
        except CanaryError as exc:
            self.state["phase"] = "RESTORE_BLOCKED"
            self.state["restore_failures"] = [exc.reason]
            self._save()
            raise
        self.state["phase"] = "RESTORED"
        self.state["cleanup_complete"] = True
        self.state["restored_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._event("RESTORE_COMPLETE", status="RESTORED",
                    web_state="stopped", emr_state="stopped", db_state="running")
        return {"phase": "RESTORED"}


def run_canary(canary: AwsNatEmrCanary) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "BLOCKED", "phase": "PREPARE"}
    interrupted = False
    canary._event(
        "CANARY_RUN_BEGIN", max_minutes=canary.max_minutes,
        dns_isolation_mode=canary.dns_isolation_mode,
        amazon_provided_dns_sg_nacl_filtering="BYPASSED",
    )
    try:
        canary.prepare_snapshot()
        completed = canary.run_steps()
        result.update(completed)
        result["phase"] = canary.state.get("phase", "UNKNOWN") if canary.state else "UNKNOWN"
    except KeyboardInterrupt:
        interrupted = True
        result.update(status="BLOCKED", phase="INTERRUPTED", reason="OPERATOR_INTERRUPT")
        canary._safe_event("CANARY_INTERRUPTED", reason="OPERATOR_INTERRUPT")
    except CanaryError as exc:
        result.update(status="BLOCKED", phase=exc.reason, reason=exc.reason)
        canary._safe_event("CANARY_FAILED", reason=exc.reason)
    except Exception as exc:
        result.update(status="BLOCKED", phase="UNEXPECTED_ERROR", reason="UNEXPECTED_ERROR")
        canary._safe_event("CANARY_FAILED", reason="UNEXPECTED_ERROR", error_type=type(exc).__name__)
    finally:
        if canary.state is not None and not canary.state.get("cleanup_complete"):
            previous_handlers: dict[int, Any] = {}
            for signum in (signal.SIGINT, signal.SIGTERM):
                try:
                    previous_handlers[signum] = signal.signal(signum, signal.SIG_IGN)
                except Exception:
                    pass
            try:
                canary.cleanup_deadline = canary.monotonic() + canary.cleanup_budget
                canary._safe_event("CLEANUP_BEGIN", prior_phase=canary.state.get("phase", "UNKNOWN"))
                restored = canary.restore()
                result["cleanup"] = restored["phase"]
            except CanaryError as exc:
                result["cleanup"] = exc.reason
                result["status"] = "BLOCKED"
                canary._safe_event("CLEANUP_FAILED", reason=exc.reason)
            except Exception as exc:
                result["cleanup"] = "RESTORE_UNEXPECTED_ERROR"
                result["status"] = "BLOCKED"
                canary._safe_event("CLEANUP_FAILED", reason="RESTORE_UNEXPECTED_ERROR",
                                   error_type=type(exc).__name__)
            finally:
                for signum, handler in previous_handlers.items():
                    try:
                        signal.signal(signum, handler)
                    except Exception:
                        pass
    if interrupted:
        result["interrupted"] = True
    if result.get("status") == "PASS" and result.get("cleanup") != "RESTORED":
        result["status"] = "BLOCKED"
    canary._safe_event("CANARY_RUN_COMPLETE", **result)
    return result


def _raise_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


@contextmanager
def _defer_cleanup_signals():
    """Do not interrupt a stateful recovery transaction halfway through."""
    previous: dict[int, Any] = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, signal.SIG_IGN)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _require_mutation_confirmations(args: argparse.Namespace, *, parser: argparse.ArgumentParser,
                                    require_probe: bool) -> None:
    required = {
        "confirm_account": ACCOUNT_ID,
        "confirm_vpc_id": VPC_ID,
        "confirm_web_id": WEB_ID,
        "confirm_web_eni": WEB_ENI,
        "confirm_emr_id": EMR_ID,
        "confirm_emr_eni": EMR_ENI,
        "confirm_db_id": DB_ID,
        "confirm_route_table_id": PRIVATE_ROUTE_TABLE_ID,
    }
    if require_probe:
        required["confirm_probe_host"] = PROBE_HOST
    mismatched = [name for name, value in required.items() if getattr(args, name) != value]
    if mismatched:
        parser.error("mutating mode requires exact reviewed target confirmations: "
                     + ", ".join(f"--{name.replace('_', '-')}" for name in mismatched))


def _validate_mutation_paths(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[Path, Path, Path]:
    if not args.state_file or not args.state_file.is_absolute():
        parser.error("mutating modes require an absolute --state-file in a private mode-0700 directory")
    state_path = args.state_file
    log_path = args.log_file or state_path.with_suffix(".log")
    pid_path = args.pid_file or state_path.with_suffix(".pid")
    paths = [state_path.absolute(), log_path.absolute(), pid_path.absolute()]
    if len(set(paths)) != len(paths):
        parser.error("state, log, and PID files must be distinct paths")
    if any(path.parent != state_path.parent for path in paths):
        parser.error("state, log, and PID files must share one private state directory")
    return state_path, log_path, pid_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--aws-read-only", action="store_true",
                       help="read AWS resources and run a read-only DB identity/fence probe")
    modes.add_argument("--run-canary", action="store_true",
                       help="MUTATING: execute the isolated Web/NAT/EMR Canary transaction")
    modes.add_argument("--restore", action="store_true",
                       help="MUTATING: restore only the exact state recorded by a prior Canary")
    parser.add_argument("--state-file", type=Path, help="private mode-0600 state path; required for run/restore")
    parser.add_argument("--log-file", type=Path, help="private mode-0600 JSONL log; defaults beside state")
    parser.add_argument("--pid-file", type=Path, help="private PID file; defaults beside state")
    parser.add_argument("--max-minutes", type=int, default=30, help="bounded transaction limit (20..30 minutes)")
    parser.add_argument(
        "--dns-isolation-mode", choices=sorted(DNS_ISOLATION_MODES), default=DNS_ISOLATION_STRICT,
        help="strict requires the VPC DNS Firewall walled garden; constrained-egress records its DNS limitation and remains fail-closed",
    )
    parser.add_argument(
        "--confirm-dns-isolation-mode", default="",
        help=f"required for mutating constrained-egress selection: {CONSTRAINED_EGRESS_CONFIRMATION}",
    )
    parser.add_argument("--confirm-account", default="")
    parser.add_argument("--confirm-vpc-id", default="")
    parser.add_argument("--confirm-web-id", default="")
    parser.add_argument("--confirm-web-eni", default="")
    parser.add_argument("--confirm-emr-id", default="")
    parser.add_argument("--confirm-emr-eni", default="")
    parser.add_argument("--confirm-db-id", default="")
    parser.add_argument("--confirm-route-table-id", default="")
    parser.add_argument("--confirm-probe-host", default="")
    parser.add_argument("--confirm-run-id", default="", help="required for state-bound --restore")
    parser.add_argument("--confirm-nat-role-idle", action="store_true",
                        help="acknowledge a separate SSM check that a timed-out NAT Ansible operation is no longer active")
    parser.add_argument("--confirm-isolated-canary-scope", default="",
                        help="must be ISOLATED_WEB_NAT_EMR_CANARY_ONLY for --run-canary")
    args = parser.parse_args(argv)

    if not 20 <= args.max_minutes <= MAX_MINUTES:
        parser.error("--max-minutes must be between 20 and 30")
    if not (args.aws_read_only or args.run_canary or args.restore):
        print("OFFLINE_MODE=NO_AWS_REQUESTS")
        print("MUTATING_MODE=NOT_SELECTED")
        return 0

    try:
        if args.aws_read_only:
            try:
                preflight_deadline = time.monotonic() + MAX_MINUTES * 60
                bounded_aws = DeadlineBoundAws(AwsCli(), lambda: preflight_deadline)
                # The CLI contract is one JSON document on stdout. Discard any
                # incidental helper diagnostics; AWS CLI subprocess output is
                # separately captured by AwsCli.call().
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    report = inspect_live(
                        bounded_aws, run_db_probe=True,
                        dns_isolation_mode=args.dns_isolation_mode,
                    )
            except KeyboardInterrupt:
                report = {
                    "status": "BLOCKED",
                    "phase": "READ_ONLY_PREFLIGHT",
                    "reason_code": "PREFLIGHT_INTERRUPTED",
                    "error_type": "KeyboardInterrupt",
                }
            except CanaryError as exc:
                report = {
                    "status": "BLOCKED",
                    "phase": "READ_ONLY_PREFLIGHT",
                    "reason_code": _safe_reason_code(exc.reason),
                    "error_type": _safe_exception_type(exc),
                }
            except Exception as exc:
                # Never print exception text/tracebacks here: lower-level errors
                # can contain command output or other sensitive runtime data.
                report = {
                    "status": "BLOCKED",
                    "phase": "READ_ONLY_PREFLIGHT",
                    "reason_code": "PREFLIGHT_INTERNAL_ERROR",
                    "error_type": _safe_exception_type(exc),
                }
            if not isinstance(report, dict):
                report = {
                    "status": "BLOCKED",
                    "phase": "READ_ONLY_PREFLIGHT",
                    "reason_code": "PREFLIGHT_REPORT_INVALID",
                    "error_type": "InvalidPreflightReport",
                }
            if report.get("status") == "BLOCKED" and "dns_isolation" not in report:
                report["dns_isolation"] = _dns_isolation_assessment(
                    args.dns_isolation_mode, ["DNS_FIREWALL_STATE_UNVERIFIED"],
                )
            if _read_only_preflight_blocked(
                    report, expected_dns_isolation_mode=args.dns_isolation_mode):
                if report.get("status") == "PASS":
                    report["reason_code"] = "PREFLIGHT_REQUIRED_CHECK_FAILED"
                elif not report.get("reason_code"):
                    dns_firewall = report.get("dns_firewall")
                    dns_errors = dns_firewall.get("errors", []) if isinstance(dns_firewall, dict) else []
                    reason = dns_errors[0] if isinstance(dns_errors, list) and dns_errors else None
                    report["reason_code"] = _safe_reason_code(reason or "PREFLIGHT_BLOCKED")
                report["status"] = "BLOCKED"
            side_effects = report.get("side_effects")
            if not isinstance(side_effects, dict):
                side_effects = {}
                report["side_effects"] = side_effects
            side_effects.setdefault("aws_resource_configuration", "UNCHANGED")
            ssm_audit = (side_effects.get("ssm_command_invocation")
                         if isinstance(side_effects, dict) else None)
            audit_status = (
                "CREATED" if ssm_audit == "CREATED_READ_ONLY_SELECT" else
                "NOT_CREATED" if ssm_audit == "NOT_RUN" else
                "UNKNOWN"
            )
            side_effects["ssm_command_audit_record"] = audit_status
            print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True), flush=True)
            return 0 if report.get("status") == "PASS" else 1

        if (args.run_canary
                and args.dns_isolation_mode == DNS_ISOLATION_CONSTRAINED_EGRESS
                and args.confirm_dns_isolation_mode != CONSTRAINED_EGRESS_CONFIRMATION):
            parser.error(
                "--run-canary with constrained-egress requires --confirm-dns-isolation-mode "
                f"{CONSTRAINED_EGRESS_CONFIRMATION}; this acknowledgment does not bypass DNS safety checks"
            )
        state_path, log_path, pid_path = _validate_mutation_paths(args, parser)
        _require_mutation_confirmations(args, parser=parser, require_probe=args.run_canary)
        if args.run_canary and args.confirm_isolated_canary_scope != "ISOLATED_WEB_NAT_EMR_CANARY_ONLY":
            parser.error("--run-canary requires --confirm-isolated-canary-scope ISOLATED_WEB_NAT_EMR_CANARY_ONLY")

        saved_state: dict[str, Any] | None = None
        if args.restore:
            saved_state = _read_nat_state(state_path)
            run_id = str(saved_state.get("run_id", ""))
            if not run_id or args.confirm_run_id != run_id:
                parser.error("--restore requires --confirm-run-id to exactly match the saved run_id")
            if saved_state.get("nat_role_outcome_uncertain") and not args.confirm_nat_role_idle:
                parser.error("timed-out NAT role requires an independent SSM idle check and --confirm-nat-role-idle")

        run_id = str(uuid.uuid4()) if saved_state is None else str(saved_state["run_id"])
        started = time.monotonic()
        with ExecutionLock() as execution_lock:
            with PidFile(pid_path, run_id):
                logger = EventLogger(log_path, append=args.restore)
                aws = AwsCli()
                aws.lock_fd = execution_lock.fd
                canary = AwsNatEmrCanary(
                    aws, state_path, logger=logger, max_minutes=args.max_minutes, run_id=run_id,
                    dns_isolation_mode=args.dns_isolation_mode,
                )
                canary._lock_fd = execution_lock.fd
                try:
                    if args.restore:
                        with _defer_cleanup_signals():
                            result = canary.restore(confirm_nat_role_idle=args.confirm_nat_role_idle)
                        logger.emit("RECOVERY_COMPLETE", status="RESTORED", phase=result["phase"], run_id=run_id)
                        print("CANARY_RESTORE=RESTORED")
                        return 0
                    old_handlers: dict[int, Any] = {}
                    for signum in (signal.SIGINT, signal.SIGTERM):
                        old_handlers[signum] = signal.signal(signum, _raise_keyboard_interrupt)
                    try:
                        result = run_canary(canary)
                    finally:
                        for signum, handler in old_handlers.items():
                            signal.signal(signum, handler)
                    elapsed = round(time.monotonic() - started, 1)
                    exit_code = 130 if result.get("interrupted") else (
                        0 if result.get("status") == "PASS" and result.get("cleanup") == "RESTORED" else 1
                    )
                    logger.emit("CANARY_FINAL_RESULT", canary_exit=exit_code, elapsed_seconds=elapsed,
                                run_id=run_id, result=result,
                                state_file=str(state_path), log_file=str(log_path))
                    print("CANARY_RESULT=" + json.dumps({
                        "status": result.get("status"), "phase": result.get("phase"),
                        "reason": result.get("reason"), "cleanup": result.get("cleanup"),
                        "canary_nat_contract": result.get("canary_nat_contract", "NOT_VERIFIED"),
                        "production_nat_status": "NOT_CHANGED", "run_id": run_id,
                        "state_file": str(state_path), "log_file": str(log_path),
                        "elapsed_seconds": elapsed,
                    }, sort_keys=True), flush=True)
                    print(f"CANARY_EXIT={exit_code}", flush=True)
                    return exit_code
                finally:
                    logger.close()
    except CanaryError as exc:
        print(f"AWS_NAT_EMR_CANARY=BLOCKED reason={exc.reason}", flush=True)
        return 1
    except KeyboardInterrupt:
        print("AWS_NAT_EMR_CANARY=BLOCKED reason=OPERATOR_INTERRUPT_OUTSIDE_TRANSACTION", flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
