#!/usr/bin/env python3
"""Read-only inspection and cross-stack contract checks for the isolated HTTPS Probe."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
PROBE_TF_DIR = ROOT / "infra" / "terraform" / "synthetic_nat_probe"
CANARY_TF_DIR = ROOT / "infra" / "terraform" / "synthetic_nat_canary"
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,31}$")
API_TIMEOUT = 20
APPROVED_AMI_ID = "AWS_RESOURCE_ID_REDACTED"
AMAZON_LINUX_OWNER_ID = "137112412989"
APPROVED_PROBE_DOMAIN = "nat-probe.hospital-web.pp.ua"
PROBE_FIREWALL_ASSOCIATION_PRIORITY = 200
AWS_AUTODEFINED_INTERNET_RESOLVER_RULE_ID = "rslvr-autodefined-rr-internet-resolver"


class ProbeError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _value(raw: dict[str, Any], key: str) -> Any:
    value = raw.get(key)
    return value.get("value") if isinstance(value, dict) and "value" in value else value


def _run_id(value: str) -> str:
    if not RUN_ID_RE.fullmatch(value or ""):
        raise ProbeError("RUN_ID_INVALID")
    return value


def _terraform_workspace(value: str) -> str:
    """Validate an explicit Terraform workspace without selecting or moving state."""
    if value == "default":
        return value
    return _run_id(value)


def normalize_probe_outputs(raw: dict[str, Any], requested_run_id: str | None = None) -> dict[str, Any]:
    result = {key: _value(raw, key) for key in raw}
    required = {
        "account_id", "region", "run_id", "vpc_id", "vpc_cidr", "subnet_id", "subnet_cidr",
        "probe_instance_id", "probe_eni_id", "probe_private_ip", "probe_eip", "probe_eip_allocation_id",
        "probe_sg_id", "default_sg_id", "ssm_endpoint_sg_id", "ssm_endpoint_ids", "ssm_endpoint_eni_ids",
        "internet_gateway_id", "route_table_id", "default_route_table_id", "network_acl_id", "default_network_acl_id", "probe_domain",
        "allowed_web_eip_ipv4", "allowed_source_parameter_name", "certificate_parameter_name",
        "private_key_parameter_name", "kms_key_arn", "synthetic_ami_id", "synthetic_ami_owner_id",
        "root_volume_size_gib", "probe_sg_ingress_enabled", "probe_role_name",
        "probe_instance_profile_name", "probe_firewall_rule_group_id",
        "probe_firewall_allow_domain_list_id", "probe_firewall_block_domain_list_id",
        "probe_firewall_association_id",
    }
    if required - result.keys() or any(result.get(k) in (None, "", {}) for k in required):
        raise ProbeError("TERRAFORM_OUTPUT_MISSING")
    run_id = _run_id(str(result["run_id"]))
    if requested_run_id and run_id != requested_run_id:
        raise ProbeError("RUN_ID_OUTPUT_MISMATCH")
    if result["region"] != "ap-northeast-2" or not re.fullmatch(r"[0-9]{12}", str(result["account_id"])):
        raise ProbeError("AWS_IDENTITY_OUTPUT_INVALID")
    for key, prefix in (("vpc_id", "vpc-"), ("subnet_id", "subnet-"), ("probe_instance_id", "i-"),
                        ("probe_eni_id", "eni-"), ("probe_sg_id", "sg-"), ("default_sg_id", "sg-"),
                        ("ssm_endpoint_sg_id", "sg-"), ("internet_gateway_id", "igw-"),
                        ("route_table_id", "rtb-"), ("default_route_table_id", "rtb-"),
                        ("network_acl_id", "acl-"), ("default_network_acl_id", "acl-"),
                        ("probe_eip_allocation_id", "eipalloc-"),
                        ("probe_firewall_rule_group_id", "rslvr-frg-"),
                        ("probe_firewall_allow_domain_list_id", "rslvr-fdl-"),
                        ("probe_firewall_block_domain_list_id", "rslvr-fdl-"),
                        ("probe_firewall_association_id", "rslvr-frgassoc-")):
        if not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9-]{8,20}", str(result[key])):
            raise ProbeError("AWS_RESOURCE_OUTPUT_INVALID")
    try:
        vpc = ipaddress.ip_network(result["vpc_cidr"], strict=True)
        subnet = ipaddress.ip_network(result["subnet_cidr"], strict=True)
        private_ip = ipaddress.ip_address(result["probe_private_ip"])
        probe_ip = ipaddress.ip_address(result["probe_eip"])
    except (ValueError, TypeError):
        raise ProbeError("CIDR_OR_IP_OUTPUT_INVALID") from None
    if vpc.version != 4 or subnet.version != 4 or private_ip.version != 4 or probe_ip.version != 4:
        raise ProbeError("IPV6_NOT_ALLOWED")
    if not subnet.subnet_of(vpc) or private_ip not in subnet or not probe_ip.is_global:
        raise ProbeError("ADDRESS_CONTRACT_INVALID")
    domain = str(result["probe_domain"])
    if domain.lower() != APPROVED_PROBE_DOMAIN:
        raise ProbeError("PROBE_DOMAIN_INVALID")
    if result["allowed_web_eip_ipv4"] == "DISABLED":
        if result["probe_sg_ingress_enabled"]:
            raise ProbeError("INGRESS_DISABLED_CONTRACT_MISMATCH")
    else:
        try:
            source = ipaddress.ip_network(result["allowed_web_eip_ipv4"], strict=True)
        except (ValueError, TypeError):
            raise ProbeError("ALLOWED_SOURCE_INVALID") from None
        if source.version != 4 or source.prefixlen != 32 or not source.network_address.is_global:
            raise ProbeError("ALLOWED_SOURCE_INVALID")
        if not result["probe_sg_ingress_enabled"]:
            raise ProbeError("INGRESS_ENABLED_CONTRACT_MISMATCH")
    if result["run_id"] not in result["certificate_parameter_name"] or result["run_id"] not in result["private_key_parameter_name"]:
        raise ProbeError("TLS_PARAMETER_RUN_ID_MISMATCH")
    expected_prefix = f"/hospital-dr/synthetic-nat-probe/{run_id}/"
    if result["certificate_parameter_name"] != expected_prefix + "fullchain" or result["private_key_parameter_name"] != expected_prefix + "privkey":
        raise ProbeError("TLS_PARAMETER_RUN_ID_MISMATCH")
    if result["allowed_source_parameter_name"] != expected_prefix + "allowed-web-eip":
        raise ProbeError("SOURCE_PARAMETER_RUN_ID_MISMATCH")
    expected_kms = rf"^arn:aws:kms:{re.escape(str(result['region']))}:{re.escape(str(result['account_id']))}:key/[0-9a-fA-F-]{{36}}$"
    if not re.fullmatch(expected_kms, str(result["kms_key_arn"])):
        raise ProbeError("KMS_KEY_ACCOUNT_OR_REGION_MISMATCH")
    if result["synthetic_ami_id"] != APPROVED_AMI_ID:
        raise ProbeError("AMI_ID_NOT_APPROVED")
    if result["synthetic_ami_owner_id"] != AMAZON_LINUX_OWNER_ID:
        raise ProbeError("AMI_OWNER_NOT_APPROVED")
    if result["probe_role_name"] != f"dr-synthetic-probe-{run_id}" or result["probe_instance_profile_name"] != f"dr-synthetic-probe-{run_id}":
        raise ProbeError("PROBE_IAM_NAME_CONTRACT_INVALID")
    if result["root_volume_size_gib"] != 8:
        raise ProbeError("ROOT_VOLUME_SIZE_INVALID")
    if not isinstance(result["ssm_endpoint_ids"], dict) or set(result["ssm_endpoint_ids"]) != {"ssm", "ssmmessages"}:
        raise ProbeError("SSM_ENDPOINT_OUTPUT_INVALID")
    if not isinstance(result["ssm_endpoint_eni_ids"], dict) or set(result["ssm_endpoint_eni_ids"]) != {"ssm", "ssmmessages"}:
        raise ProbeError("SSM_ENDPOINT_ENI_OUTPUT_INVALID")
    return result


def validate_stack_link(probe: dict[str, Any], canary: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not probe.get("run_id") or not canary.get("run_id") or probe.get("run_id") == canary.get("run_id"):
        reasons.append("STACK_RUN_IDS_NOT_DISTINCT")
    if probe.get("account_id") != canary.get("account_id"):
        reasons.append("AWS_ACCOUNT_MISMATCH")
    if probe.get("region") != canary.get("region") or probe.get("region") != "ap-northeast-2":
        reasons.append("AWS_REGION_MISMATCH")
    if probe.get("synthetic_ami_id") != APPROVED_AMI_ID or canary.get("synthetic_ami_id") != APPROVED_AMI_ID:
        reasons.append("AMI_ID_NOT_APPROVED")
    if probe.get("synthetic_ami_id") != canary.get("synthetic_ami_id"):
        reasons.append("STACK_AMI_ID_MISMATCH")
    if probe.get("synthetic_ami_owner_id") != AMAZON_LINUX_OWNER_ID or canary.get("synthetic_ami_owner_id") != AMAZON_LINUX_OWNER_ID:
        reasons.append("AMI_OWNER_NOT_APPROVED")
    if probe.get("probe_eip") != canary.get("probe_ipv4"):
        reasons.append("PROBE_IPV4_MISMATCH")
    if str(probe.get("probe_domain", "")).lower() != str(canary.get("probe_domain", "")).lower():
        reasons.append("PROBE_DOMAIN_MISMATCH")
    if str(probe.get("probe_domain", "")).lower() != APPROVED_PROBE_DOMAIN or str(canary.get("probe_domain", "")).lower() != APPROVED_PROBE_DOMAIN:
        reasons.append("PROBE_DOMAIN_NOT_APPROVED")
    expected_source = f"{canary.get('web_eip')}/32"
    if probe.get("allowed_web_eip_ipv4") != expected_source:
        reasons.append("WEB_EIP_NOT_BOUND_TO_PROBE")
    try:
        web_eip = ipaddress.ip_address(canary["web_eip"])
        if web_eip.version != 4 or not web_eip.is_global:
            reasons.append("WEB_EIP_INVALID")
    except (KeyError, ValueError, TypeError):
        reasons.append("WEB_EIP_INVALID")
    if not probe.get("probe_sg_ingress_enabled"):
        reasons.append("PROBE_INGRESS_NOT_ENABLED_FOR_CANARY_EIP")
    return sorted(set(reasons))


def _terraform_outputs(directory: Path, run_id: str, workspace: str | None = None) -> dict[str, Any]:
    run_id = _run_id(run_id)
    env = _terraform_environment(_terraform_workspace(workspace or run_id))
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"], cwd=directory, env=env,
            text=True, capture_output=True, timeout=30, check=False,
        )
    except subprocess.TimeoutExpired:
        raise ProbeError("TERRAFORM_OUTPUT_TIMEOUT") from None
    except OSError:
        raise ProbeError("TERRAFORM_EXEC_FAILED") from None
    if result.returncode:
        raise ProbeError("TERRAFORM_OUTPUT_FAILED")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ProbeError("TERRAFORM_OUTPUT_INVALID_JSON") from None
    if not isinstance(payload, dict):
        raise ProbeError("TERRAFORM_OUTPUT_INVALID")
    if _value(payload, "run_id") != run_id:
        raise ProbeError("RUN_ID_OUTPUT_MISMATCH")
    return payload


def _terraform_environment(workspace: str) -> dict[str, str]:
    env = os.environ.copy()
    if any(
        name in {"TF_DATA_DIR", "TF_CLI_CONFIG_FILE"}
        or name.startswith("TF_CLI_ARGS")
        or name.startswith("TF_VAR_")
        for name, value in env.items() if value.strip()
    ):
        raise ProbeError("TERRAFORM_ENVIRONMENT_OVERRIDE_PRESENT")
    for name in ("TF_DATA_DIR", "TF_CLI_CONFIG_FILE", "TF_WORKSPACE"):
        env.pop(name, None)
    for name in tuple(env):
        if name.startswith("TF_CLI_ARGS") or name.startswith("TF_VAR_"):
            env.pop(name, None)
    env["TF_WORKSPACE"] = _terraform_workspace(workspace)
    return env


def _decode_policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(unquote(value))
        except (json.JSONDecodeError, TypeError):
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _as_sorted_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return sorted(value)
    return []


def _canonical_statements(document: dict[str, Any]) -> list[str]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    canonical = []
    for statement in statements:
        if not isinstance(statement, dict):
            return []
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            return []
        normalized_condition = {
            operator: {
                key: sorted(value) if isinstance(value, list) else value
                for key, value in sorted(entries.items())
            }
            for operator, entries in sorted(condition.items())
            if isinstance(entries, dict)
        }
        if len(normalized_condition) != len(condition):
            return []
        canonical.append(json.dumps({
            "Effect": statement.get("Effect"),
            "Action": _as_sorted_strings(statement.get("Action")),
            "Resource": _as_sorted_strings(statement.get("Resource")),
            "Condition": normalized_condition,
        }, sort_keys=True, separators=(",", ":")))
    return sorted(canonical)


def expected_probe_role_policy(outputs: dict[str, Any]) -> dict[str, Any]:
    account = outputs["account_id"]
    region = outputs["region"]
    prefix = f"/hospital-dr/synthetic-nat-probe/{outputs['run_id']}"
    parameter_arns = [
        f"arn:aws:ssm:{region}:{account}:parameter{prefix}/fullchain",
        f"arn:aws:ssm:{region}:{account}:parameter{prefix}/privkey",
        f"arn:aws:ssm:{region}:{account}:parameter{prefix}/allowed-web-eip",
    ]
    tls_arns = parameter_arns[:2]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["ssm:UpdateInstanceInformation"],
             "Resource": f"arn:aws:ec2:{region}:{account}:instance/*",
             "Condition": {"StringEquals": {"aws:ResourceTag/ProbeRunId": outputs["run_id"]}}},
            {"Effect": "Allow", "Action": [
                "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
            ], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ssm:GetParameter"], "Resource": parameter_arns},
            {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": outputs["kms_key_arn"],
             "Condition": {
                 "StringEquals": {"kms:ViaService": f"ssm.{region}.amazonaws.com"},
                 "StringLike": {"kms:EncryptionContext:PARAMETER_ARN": tls_arns},
             }},
        ],
    }


def validate_probe_iam_contract(
    outputs: dict[str, Any],
    instance: dict[str, Any],
    profile_response: dict[str, Any],
    role_response: dict[str, Any],
    inline_names_response: dict[str, Any],
    attached_response: dict[str, Any],
    policy_response: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    role_name = outputs["probe_role_name"]
    profile_name = outputs["probe_instance_profile_name"]
    profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
    if profile_arn.rsplit("/", 1)[-1] != profile_name:
        reasons.append("PROBE_INSTANCE_PROFILE_ATTACHMENT_MISMATCH")

    # GetInstanceProfile (the operation used by inspect()) returns the singular
    # `InstanceProfile` object. Accept the list form as well for callers/tests
    # that use ListInstanceProfiles, while refusing ambiguous dual responses.
    singular_profile = profile_response.get("InstanceProfile")
    plural_profiles = profile_response.get("InstanceProfiles")
    if isinstance(singular_profile, dict):
        profiles = [singular_profile] if plural_profiles is None else []
    else:
        profiles = plural_profiles if isinstance(plural_profiles, list) else []
    if len(profiles) != 1:
        reasons.append("PROBE_INSTANCE_PROFILE_READBACK_INVALID")
        profile = {}
    else:
        profile = profiles[0]
    if profile.get("InstanceProfileName") != profile_name or _tag_map(profile).get("ProbeRunId") != outputs["run_id"]:
        reasons.append("PROBE_INSTANCE_PROFILE_IDENTITY_MISMATCH")
    if [role.get("RoleName") for role in profile.get("Roles", [])] != [role_name]:
        reasons.append("PROBE_INSTANCE_PROFILE_ROLE_MISMATCH")

    role = role_response.get("Role", {})
    expected_role_arn = f"arn:aws:iam::{outputs['account_id']}:role/{role_name}"
    if role.get("RoleName") != role_name or role.get("Arn") != expected_role_arn or _tag_map(role).get("ProbeRunId") != outputs["run_id"]:
        reasons.append("PROBE_IAM_ROLE_IDENTITY_MISMATCH")
    trust = _decode_policy_document(role.get("AssumeRolePolicyDocument"))
    trust_statements = trust.get("Statement", [])
    if isinstance(trust_statements, dict):
        trust_statements = [trust_statements]
    trust_valid = False
    if trust.get("Version") == "2012-10-17" and len(trust_statements) == 1 and isinstance(trust_statements[0], dict):
        statement = trust_statements[0]
        principal = statement.get("Principal", {})
        service_principal = principal.get("Service") if isinstance(principal, dict) else None
        trust_valid = (
            statement.get("Effect") == "Allow"
            and _as_sorted_strings(statement.get("Action")) == ["sts:AssumeRole"]
            and isinstance(principal, dict)
            and set(principal) == {"Service"}
            and _as_sorted_strings(service_principal) == ["ec2.amazonaws.com"]
            and set(statement) <= {"Sid", "Effect", "Action", "Principal"}
        )
    if not trust_valid:
        reasons.append("PROBE_IAM_TRUST_POLICY_MISMATCH")

    expected_policy_name = role_name
    if sorted(inline_names_response.get("PolicyNames", [])) != [expected_policy_name]:
        reasons.append("PROBE_IAM_INLINE_POLICY_SET_MISMATCH")
    if attached_response.get("AttachedPolicies", []):
        reasons.append("PROBE_IAM_MANAGED_POLICY_ATTACHED")
    actual_document = _decode_policy_document(policy_response.get("PolicyDocument"))
    expected_document = expected_probe_role_policy(outputs)
    if (
        actual_document.get("Version") != expected_document["Version"]
        or _canonical_statements(actual_document) != _canonical_statements(expected_document)
    ):
        reasons.append("PROBE_IAM_INLINE_POLICY_DRIFT")
    return sorted(set(reasons))


def validate_probe_kms_metadata(outputs: dict[str, Any], response: dict[str, Any]) -> list[str]:
    key = response.get("KeyMetadata", {})
    if (
        key.get("Arn") != outputs["kms_key_arn"]
        or key.get("AWSAccountId") != outputs["account_id"]
        or key.get("KeyState") != "Enabled"
        or key.get("KeyManager") != "CUSTOMER"
        or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or key.get("KeySpec") != "SYMMETRIC_DEFAULT"
    ):
        return ["TLS_KMS_KEY_NOT_USABLE"]
    return []


def validate_probe_dns_firewall(
    outputs: dict[str, Any],
    config: dict[str, Any],
    associations: list[dict[str, Any]],
    firewall_rules: list[dict[str, Any]],
    domains_by_list: dict[str, list[str]],
    resolver_rule_association_count: int,
) -> list[str]:
    reasons: list[str] = []
    if config.get("ResourceId") != outputs["vpc_id"] or config.get("FirewallFailOpen", config.get("FirewallFailOpenStatus")) != "DISABLED":
        reasons.append("PROBE_DNS_FIREWALL_NOT_FAIL_CLOSED")
    vpc_associations = [item for item in associations if item.get("VpcId") == outputs["vpc_id"]]
    expected_association = [item for item in vpc_associations if item.get("Id") == outputs["probe_firewall_association_id"]]
    if (
        len(vpc_associations) != 1 or len(expected_association) != 1
        or expected_association[0].get("FirewallRuleGroupId") != outputs["probe_firewall_rule_group_id"]
        or expected_association[0].get("Status") != "COMPLETE"
        or expected_association[0].get("Priority") != PROBE_FIREWALL_ASSOCIATION_PRIORITY
        or expected_association[0].get("MutationProtection") != "DISABLED"
    ):
        reasons.append("PROBE_DNS_FIREWALL_ASSOCIATION_INVALID")
    if any(item.get("FirewallRuleGroupId") == outputs["probe_firewall_rule_group_id"] and item.get("VpcId") != outputs["vpc_id"] for item in associations):
        reasons.append("PROBE_DNS_FIREWALL_GROUP_ATTACHED_ELSEWHERE")

    allow_domains = {f"ssm.{outputs['region']}.amazonaws.com", f"ssmmessages.{outputs['region']}.amazonaws.com"}
    allow_rules = [item for item in firewall_rules if item.get("Action") == "ALLOW" and item.get("Priority") == 10]
    block_rules = [item for item in firewall_rules if item.get("Action") == "BLOCK" and item.get("Priority") == 100]
    if len(firewall_rules) != 2 or len(allow_rules) != 1 or len(block_rules) != 1:
        reasons.append("PROBE_DNS_FIREWALL_RULE_SET_INVALID")
    else:
        allow_rule, block_rule = allow_rules[0], block_rules[0]
        if allow_rule.get("FirewallDomainListId") != outputs["probe_firewall_allow_domain_list_id"] or _canonical_firewall_domains(domains_by_list.get(allow_rule.get("FirewallDomainListId"), [])) != allow_domains:
            reasons.append("PROBE_DNS_FIREWALL_SSM_ALLOWLIST_INVALID")
        if block_rule.get("FirewallDomainListId") != outputs["probe_firewall_block_domain_list_id"] or _canonical_firewall_domains(domains_by_list.get(block_rule.get("FirewallDomainListId"), [])) != {"*"} or block_rule.get("BlockResponse") != "NXDOMAIN":
            reasons.append("PROBE_DNS_FIREWALL_CATCH_ALL_BLOCK_INVALID")
    if resolver_rule_association_count:
        reasons.append("PROBE_CUSTOM_DNS_FORWARDING_RULE_PRESENT")
    return sorted(set(reasons))


def probe_dns_query_test_script(endpoint_ips: dict[str, str]) -> str:
    required = {"ssm", "ssmmessages"}
    try:
        valid_ips = all(ipaddress.ip_address(value).version == 4 for value in endpoint_ips.values())
    except (ValueError, TypeError):
        valid_ips = False
    if set(endpoint_ips) != required or not valid_ips:
        raise ProbeError("SSM_ENDPOINT_DNS_TEST_INPUT_INVALID")
    lines = []
    for service in ("ssm", "ssmmessages"):
        domain = f"{service}.ap-northeast-2.amazonaws.com"
        ip = endpoint_ips[service]
        lines.append(f"getent ahostsv4 {domain} | awk '{{print $1}}' | grep -Fx {ip} >/dev/null 2>&1")
    lines.append("if timeout 8 getent ahostsv4 example.com >/dev/null 2>&1; then exit 41; fi")
    return "; ".join(lines)


def build_guest_readonly_command(outputs: dict[str, Any], endpoint_ips: dict[str, str]) -> str:
    dns_test = probe_dns_query_test_script(endpoint_ips)
    expected_source = (
        str(ipaddress.ip_network(outputs["allowed_web_eip_ipv4"], strict=True).network_address)
        if outputs["allowed_web_eip_ipv4"] != "DISABLED" else "DISABLED"
    )
    return (
        "set -eu; " + dns_test + "; "
        f"aws ssm get-parameter --region {outputs['region']} --name {outputs['certificate_parameter_name']} --with-decryption --query Parameter.Value --output text >/dev/null 2>&1; "
        f"aws ssm get-parameter --region {outputs['region']} --name {outputs['private_key_parameter_name']} --with-decryption --query Parameter.Value --output text >/dev/null 2>&1; "
        "systemctl is-active --quiet hospital-dr-synthetic-probe.service; "
        "test \"$(ss -H -lnt 'sport = :443' | wc -l)\" -eq 1; "
        "exec /usr/bin/python3 /opt/hospital-dr-synthetic-probe/probe_server.py --self-check "
        f"--domain {outputs['probe_domain']} --allowed-source-file /etc/hospital-dr-synthetic-probe/allowed-source.txt "
        "--certificate /etc/hospital-dr-synthetic-probe/fullchain.pem --private-key /etc/hospital-dr-synthetic-probe/privkey.pem "
        f"--expected-source {expected_source}"
    )


def _aws_json(service: str, operation: str, *args: str, timeout: int = API_TIMEOUT) -> dict[str, Any]:
    environment = os.environ.copy()
    # AWS CLI v1 (including the MSP's 1.22.x) does not accept
    # --no-cli-pager. AWS_PAGER is ignored by v1 and disables the v2 pager.
    environment["AWS_PAGER"] = ""
    try:
        result = subprocess.run(
            ["aws", service, operation, "--region", "ap-northeast-2", "--output", "json", *args],
            text=True, capture_output=True, timeout=timeout, check=False, env=environment,
        )
    except subprocess.TimeoutExpired:
        raise ProbeError(f"AWS_{service}_{operation}_TIMEOUT") from None
    except OSError:
        raise ProbeError("AWS_CLI_UNAVAILABLE") from None
    if result.returncode:
        stderr = result.stderr or ""
        match = re.search(r"An error occurred \(([^()]{1,64})\) when calling the [A-Za-z0-9]+ operation", stderr)
        if match:
            code = re.sub(r"[^A-Za-z0-9_-]", "", match.group(1))
        elif re.search(r"unknown options?|unrecognized arguments?|error parsing parameter", stderr, re.IGNORECASE):
            code = "CLI_ARGUMENT_ERROR"
        elif re.search(r"unable to locate credentials|no credential providers", stderr, re.IGNORECASE):
            code = "CREDENTIALS_UNAVAILABLE"
        else:
            code = "CLI_OR_API_ERROR"
        raise ProbeError(f"AWS_{service}_{operation}_{code or 'ERROR'}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ProbeError(f"AWS_{service}_{operation}_INVALID_JSON") from None
    if not isinstance(payload, dict):
        raise ProbeError(f"AWS_{service}_{operation}_INVALID_RESPONSE")
    return payload


def _sg_rules(permissions: list[dict[str, Any]]) -> set[tuple[str, int | None, int | None, str]]:
    result: set[tuple[str, int | None, int | None, str]] = set()
    for permission in permissions or []:
        proto = str(permission.get("IpProtocol", "-1"))
        low, high = permission.get("FromPort"), permission.get("ToPort")
        for item in permission.get("IpRanges", []):
            result.add((proto, low, high, f"cidr:{item.get('CidrIp', '')}"))
        for item in permission.get("Ipv6Ranges", []):
            result.add((proto, low, high, f"ipv6:{item.get('CidrIpv6', '')}"))
        for item in permission.get("UserIdGroupPairs", []):
            result.add((proto, low, high, f"sg:{item.get('GroupId', '')}"))
        for item in permission.get("PrefixListIds", []):
            result.add((proto, low, high, f"prefix:{item.get('PrefixListId', '')}"))
    return result


def _tag_map(resource: dict[str, Any]) -> dict[str, str]:
    tags = resource.get("Tags", resource.get("TagSet", [])) or []
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if tag.get("Key") is not None}


def _canonical_firewall_domains(domains: Any) -> set[str]:
    if not isinstance(domains, list):
        return {"\x00invalid-domain-list"}
    normalized: set[str] = set()
    for domain in domains:
        if not isinstance(domain, str) or not domain or any(character.isspace() for character in domain):
            normalized.add("\x00invalid-domain")
            continue
        name = domain.lower().rstrip(".")
        normalized.add("*" if name == "*" else name)
    return normalized


def _custom_resolver_associations(associations: Any) -> list[dict[str, Any]]:
    if not isinstance(associations, list):
        raise ProbeError("RESOLVER_RULE_ASSOCIATIONS_INVALID")
    return [
        item for item in associations
        if not isinstance(item, dict)
        or item.get("ResolverRuleId") != AWS_AUTODEFINED_INTERNET_RESOLVER_RULE_ID
    ]


def _owned_by_run(resource: dict[str, Any], run_id: str) -> bool:
    return _tag_map(resource).get("ProbeRunId") == run_id


def _resource_arns(response: dict[str, Any]) -> list[str]:
    mappings = response.get("ResourceTagMappingList")
    if not isinstance(mappings, list):
        raise ProbeError("AWS_resourcegroupstaggingapi_get-resources_INVALID_RESPONSE")
    arns: list[str] = []
    for item in mappings:
        if not isinstance(item, dict) or not isinstance(item.get("ResourceARN"), str) or not item["ResourceARN"].strip():
            raise ProbeError("AWS_resourcegroupstaggingapi_get-resources_INVALID_RESPONSE")
        arns.append(item["ResourceARN"])
    return sorted(arns)


def inventory(run_id: str) -> dict[str, Any]:
    response = _aws_json("resourcegroupstaggingapi", "get-resources", "--tag-filters", f"Key=ProbeRunId,Values={_run_id(run_id)}")
    arns = _resource_arns(response)
    return {"status": "READ_ONLY", "phase": "RUN_ID_INVENTORY", "probe_only": True, "run_id": run_id, "resource_count": len(arns), "resource_arns": arns}


def read_only_preflight(outputs: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    identity = _aws_json("sts", "get-caller-identity")
    if identity.get("Account") != outputs["account_id"]:
        reasons.append("AWS_ACCOUNT_MISMATCH")
    instances = _aws_json("ec2", "describe-instances", "--instance-ids", outputs["probe_instance_id"]).get("Reservations", [])
    instance_list = [item for reservation in instances for item in reservation.get("Instances", [])]
    if len(instance_list) != 1:
        reasons.append("PROBE_INSTANCE_NOT_UNIQUE")
        instance = {}
    else:
        instance = instance_list[0]
        tags = _tag_map(instance)
        if instance.get("VpcId") != outputs["vpc_id"] or instance.get("SubnetId") != outputs["subnet_id"]:
            reasons.append("PROBE_INSTANCE_NETWORK_MISMATCH")
        if instance.get("ImageId") != outputs["synthetic_ami_id"]:
            reasons.append("PROBE_AMI_MISMATCH")
        if instance.get("PrivateIpAddress") != outputs["probe_private_ip"]:
            reasons.append("PROBE_PRIVATE_IP_MISMATCH")
        if tags.get("ProbeRunId") != outputs["run_id"]:
            reasons.append("PROBE_RUN_TAG_MISMATCH")
        if [group.get("GroupId") for group in instance.get("SecurityGroups", [])] != [outputs["probe_sg_id"]]:
            reasons.append("PROBE_INSTANCE_SG_MISMATCH")
        if instance.get("State", {}).get("Name") != "running":
            reasons.append("PROBE_INSTANCE_NOT_RUNNING")
    images = _aws_json("ec2", "describe-images", "--image-ids", outputs["synthetic_ami_id"]).get("Images", [])
    if (
        len(images) != 1 or images[0].get("OwnerId") != "137112412989"
        or images[0].get("ImageId") != APPROVED_AMI_ID
        or images[0].get("State") != "available" or images[0].get("Architecture") != "x86_64"
        or images[0].get("VirtualizationType") != "hvm" or images[0].get("RootDeviceType") != "ebs"
        or not re.fullmatch(r"al2023-ami-.+-x86_64", str(images[0].get("Name", "")))
    ):
        reasons.append("PROBE_AMI_PROVENANCE_MISMATCH")
    addresses = _aws_json("ec2", "describe-addresses", "--allocation-ids", outputs["probe_eip_allocation_id"]).get("Addresses", [])
    if len(addresses) != 1 or addresses[0].get("PublicIp") != outputs["probe_eip"] or addresses[0].get("InstanceId") != outputs["probe_instance_id"] or addresses[0].get("NetworkInterfaceId") != outputs["probe_eni_id"] or not _owned_by_run(addresses[0], outputs["run_id"]):
        reasons.append("PROBE_EIP_ASSOCIATION_MISMATCH")
    groups = _aws_json("ec2", "describe-security-groups", "--group-ids", outputs["probe_sg_id"], outputs["ssm_endpoint_sg_id"], outputs["default_sg_id"]).get("SecurityGroups", [])
    by_id = {group.get("GroupId"): group for group in groups}
    probe_sg = by_id.get(outputs["probe_sg_id"], {})
    endpoint_sg = by_id.get(outputs["ssm_endpoint_sg_id"], {})
    default_sg = by_id.get(outputs["default_sg_id"], {})
    if (
        probe_sg.get("VpcId") != outputs["vpc_id"]
        or endpoint_sg.get("VpcId") != outputs["vpc_id"]
        or default_sg.get("VpcId") != outputs["vpc_id"]
        or any(not _owned_by_run(group, outputs["run_id"]) for group in (probe_sg, endpoint_sg, default_sg))
    ):
        reasons.append("SECURITY_GROUP_VPC_MISMATCH")
    actual_ingress = _sg_rules(probe_sg.get("IpPermissions", []))
    expected_source = outputs["allowed_web_eip_ipv4"]
    if expected_source == "DISABLED":
        if actual_ingress:
            reasons.append("UNEXPECTED_PROBE_INGRESS")
    elif actual_ingress != {("tcp", 443, 443, f"cidr:{expected_source}")}:
        reasons.append("PROBE_INGRESS_RULE_MISMATCH")
    expected_probe_egress = {("tcp", 443, 443, f"sg:{outputs['ssm_endpoint_sg_id']}")}
    if _sg_rules(probe_sg.get("IpPermissionsEgress", [])) != expected_probe_egress:
        reasons.append("PROBE_EGRESS_RULE_MISMATCH")
    if _sg_rules(endpoint_sg.get("IpPermissions", [])) != {("tcp", 443, 443, f"sg:{outputs['probe_sg_id']}")} or _sg_rules(endpoint_sg.get("IpPermissionsEgress", [])):
        reasons.append("ENDPOINT_SG_RULE_MISMATCH")
    if _sg_rules(default_sg.get("IpPermissions", [])) or _sg_rules(default_sg.get("IpPermissionsEgress", [])):
        reasons.append("DEFAULT_SECURITY_GROUP_NOT_EMPTY")
    endpoints = _aws_json("ec2", "describe-vpc-endpoints", "--vpc-endpoint-ids", *outputs["ssm_endpoint_ids"].values()).get("VpcEndpoints", [])
    expected_services = {"com.amazonaws.ap-northeast-2.ssm", "com.amazonaws.ap-northeast-2.ssmmessages"}
    if len(endpoints) != 2 or {endpoint.get("ServiceName") for endpoint in endpoints} != expected_services:
        reasons.append("SSM_ENDPOINT_SET_MISMATCH")
    elif any(endpoint.get("VpcId") != outputs["vpc_id"] or endpoint.get("State") != "available" or not endpoint.get("PrivateDnsEnabled") or outputs["subnet_id"] not in endpoint.get("SubnetIds", []) or [group.get("GroupId") for group in endpoint.get("Groups", [])] != [outputs["ssm_endpoint_sg_id"]] or not _owned_by_run(endpoint, outputs["run_id"]) for endpoint in endpoints):
        reasons.append("SSM_ENDPOINT_NOT_READY")

    profile_response = _aws_json("iam", "get-instance-profile", "--instance-profile-name", outputs["probe_instance_profile_name"])
    role_response = _aws_json("iam", "get-role", "--role-name", outputs["probe_role_name"])
    inline_names = _aws_json("iam", "list-role-policies", "--role-name", outputs["probe_role_name"])
    attached_policies = _aws_json("iam", "list-attached-role-policies", "--role-name", outputs["probe_role_name"])
    inline_policy = _aws_json(
        "iam", "get-role-policy", "--role-name", outputs["probe_role_name"],
        "--policy-name", outputs["probe_role_name"],
    )
    reasons.extend(validate_probe_iam_contract(
        outputs, instance, profile_response, role_response, inline_names,
        attached_policies, inline_policy,
    ))

    key_response = _aws_json("kms", "describe-key", "--key-id", outputs["kms_key_arn"])
    reasons.extend(validate_probe_kms_metadata(outputs, key_response))

    firewall_config = _aws_json(
        "route53resolver", "get-firewall-config", "--resource-id", outputs["vpc_id"],
    ).get("FirewallConfig", {})
    firewall_associations = _aws_json(
        "route53resolver", "list-firewall-rule-group-associations",
    ).get("FirewallRuleGroupAssociations", [])
    firewall_rules = _aws_json(
        "route53resolver", "list-firewall-rules", "--firewall-rule-group-id",
        outputs["probe_firewall_rule_group_id"],
    ).get("FirewallRules", [])
    domains_by_list: dict[str, list[str]] = {}
    for firewall_rule in firewall_rules:
        domain_list_id = firewall_rule.get("FirewallDomainListId")
        if domain_list_id:
            domain_response = _aws_json(
                "route53resolver", "list-firewall-domains",
                "--firewall-domain-list-id", domain_list_id,
            )
            domains_by_list[domain_list_id] = sorted(
                item if isinstance(item, str) else item.get("Name", "")
                for item in domain_response.get("Domains", [])
            )
    resolver_associations = _aws_json(
        "route53resolver", "list-resolver-rule-associations",
        "--filters", f"Name=VPC_ID,Values={outputs['vpc_id']}",
    ).get("ResolverRuleAssociations", [])
    custom_resolver_associations = _custom_resolver_associations(resolver_associations)
    reasons.extend(validate_probe_dns_firewall(
        outputs, firewall_config, firewall_associations, firewall_rules,
        domains_by_list, len(custom_resolver_associations),
    ))
    for parameter_name, expected_type in (
        (outputs["certificate_parameter_name"], "SecureString"),
        (outputs["private_key_parameter_name"], "SecureString"),
        (outputs["allowed_source_parameter_name"], "String"),
    ):
        metadata = _aws_json(
            "ssm", "describe-parameters", "--parameter-filters",
            f"Key=Name,Option=Equals,Values={parameter_name}",
        ).get("Parameters", [])
        if len(metadata) != 1 or metadata[0].get("Name") != parameter_name or metadata[0].get("Type") != expected_type:
            reasons.append("SSM_PARAMETER_METADATA_MISMATCH")
        elif expected_type == "SecureString" and (
            metadata[0].get("Tier") != "Advanced"
            or str(outputs["kms_key_arn"]).split("/")[-1] not in str(metadata[0].get("KeyId", ""))
        ):
            reasons.append("TLS_PARAMETER_KMS_METADATA_MISMATCH")
    source_parameter = _aws_json("ssm", "get-parameter", "--name", outputs["allowed_source_parameter_name"]).get("Parameter", {})
    expected_source_ip = "DISABLED" if expected_source == "DISABLED" else str(ipaddress.ip_network(expected_source, strict=True).network_address)
    if source_parameter.get("Name") != outputs["allowed_source_parameter_name"] or source_parameter.get("Value") != expected_source_ip:
        reasons.append("SOURCE_PARAMETER_VALUE_MISMATCH")
    source_tags = _aws_json(
        "ssm", "list-tags-for-resource", "--resource-type", "Parameter",
        "--resource-id", outputs["allowed_source_parameter_name"],
    ).get("TagList", [])
    if {tag.get("Key"): tag.get("Value") for tag in source_tags}.get("ProbeRunId") != outputs["run_id"]:
        reasons.append("SOURCE_PARAMETER_RUN_TAG_MISMATCH")
    route_tables = _aws_json("ec2", "describe-route-tables", "--route-table-ids", outputs["route_table_id"]).get("RouteTables", [])
    routes = route_tables[0].get("Routes", []) if len(route_tables) == 1 else []
    if len(route_tables) != 1 or route_tables[0].get("VpcId") != outputs["vpc_id"] or not _owned_by_run(route_tables[0], outputs["run_id"]):
        reasons.append("PROBE_ROUTE_TABLE_IDENTITY_MISMATCH")
    route_contract = {
        (outputs["vpc_cidr"], "local", "active"),
        ("IP_REDACTED/0", outputs["internet_gateway_id"], "active"),
    }
    observed_routes = {
        (route.get("DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", "")),
         route.get("GatewayId", route.get("VpcPeeringConnectionId", route.get("TransitGatewayId", route.get("NatGatewayId", "")))),
         route.get("State", ""))
        for route in routes
    }
    if observed_routes != route_contract:
        reasons.append("PROBE_IGW_ROUTE_NOT_ACTIVE")
    if len(route_tables) == 1 and outputs["subnet_id"] not in [association.get("SubnetId") for association in route_tables[0].get("Associations", [])]:
        reasons.append("PROBE_ROUTE_TABLE_SUBNET_MISMATCH")
    internet_gateways = _aws_json("ec2", "describe-internet-gateways", "--internet-gateway-ids", outputs["internet_gateway_id"]).get("InternetGateways", [])
    if (
        len(internet_gateways) != 1
        or not _owned_by_run(internet_gateways[0], outputs["run_id"])
        or [attachment.get("VpcId") for attachment in internet_gateways[0].get("Attachments", []) if attachment.get("State") == "available"] != [outputs["vpc_id"]]
    ):
        reasons.append("PROBE_IGW_NOT_ATTACHED_TO_EXPECTED_VPC")
    vpcs = _aws_json("ec2", "describe-vpcs", "--vpc-ids", outputs["vpc_id"]).get("Vpcs", [])
    if len(vpcs) != 1 or vpcs[0].get("CidrBlock") != outputs["vpc_cidr"] or vpcs[0].get("IsDefault") or not _owned_by_run(vpcs[0], outputs["run_id"]):
        reasons.append("PROBE_VPC_IDENTITY_MISMATCH")
    elif vpcs[0].get("Ipv6CidrBlockAssociationSet"):
        reasons.append("PROBE_VPC_IPV6_PRESENT")
    dns_support = _aws_json("ec2", "describe-vpc-attribute", "--vpc-id", outputs["vpc_id"], "--attribute", "enableDnsSupport")
    dns_hostnames = _aws_json("ec2", "describe-vpc-attribute", "--vpc-id", outputs["vpc_id"], "--attribute", "enableDnsHostnames")
    if not dns_support.get("EnableDnsSupport", {}).get("Value") or not dns_hostnames.get("EnableDnsHostnames", {}).get("Value"):
        reasons.append("PROBE_VPC_DNS_ATTRIBUTES_MISMATCH")
    subnets = _aws_json("ec2", "describe-subnets", "--subnet-ids", outputs["subnet_id"]).get("Subnets", [])
    if len(subnets) != 1 or subnets[0].get("VpcId") != outputs["vpc_id"] or subnets[0].get("CidrBlock") != outputs["subnet_cidr"] or subnets[0].get("MapPublicIpOnLaunch") or subnets[0].get("AssignIpv6AddressOnCreation") or not _owned_by_run(subnets[0], outputs["run_id"]):
        reasons.append("PROBE_SUBNET_IDENTITY_MISMATCH")
    elif subnets[0].get("Ipv6CidrBlockAssociationSet"):
        reasons.append("PROBE_SUBNET_IPV6_PRESENT")
    nacls = _aws_json("ec2", "describe-network-acls", "--network-acl-ids", outputs["network_acl_id"]).get("NetworkAcls", [])
    expected_nacl_allows: set[tuple[bool, str, int, int, str]] = {
        (False, "6", 1024, 65535, outputs["subnet_cidr"]),
        (True, "6", 443, 443, outputs["subnet_cidr"]),
    }
    if expected_source != "DISABLED":
        expected_nacl_allows.update({
            (False, "6", 443, 443, expected_source),
            (True, "6", 1024, 65535, expected_source),
        })
    observed_nacl_allows: set[tuple[bool, str, int, int, str]] = set()
    if len(nacls) == 1:
        nacl = nacls[0]
        if nacl.get("VpcId") != outputs["vpc_id"] or [item.get("SubnetId") for item in nacl.get("Associations", [])] != [outputs["subnet_id"]] or not _owned_by_run(nacl, outputs["run_id"]):
            reasons.append("PROBE_NACL_ASSOCIATION_MISMATCH")
        for entry in nacl.get("Entries", []):
            if entry.get("RuleAction") == "allow":
                ports = entry.get("PortRange", {})
                observed_nacl_allows.add((bool(entry.get("Egress")), str(entry.get("Protocol")), ports.get("From"), ports.get("To"), entry.get("CidrBlock", "")))
        if observed_nacl_allows != expected_nacl_allows:
            reasons.append("PROBE_NACL_ALLOWLIST_MISMATCH")
    else:
        reasons.append("PROBE_NACL_MISSING")
    all_nacls = _aws_json("ec2", "describe-network-acls", "--filters", f"Name=vpc-id,Values={outputs['vpc_id']}").get("NetworkAcls", [])
    if {item.get("NetworkAclId") for item in all_nacls} != {outputs["network_acl_id"], outputs["default_network_acl_id"]} or any(not _owned_by_run(item, outputs["run_id"]) for item in all_nacls):
        reasons.append("UNEXPECTED_NETWORK_ACL_IN_PROBE_VPC")
    default_nacl = next((item for item in all_nacls if item.get("NetworkAclId") == outputs["default_network_acl_id"]), {})
    if any(entry.get("RuleAction") == "allow" for entry in default_nacl.get("Entries", [])):
        reasons.append("DEFAULT_NETWORK_ACL_NOT_LOCKED")
    all_routes = _aws_json("ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={outputs['vpc_id']}").get("RouteTables", [])
    if {item.get("RouteTableId") for item in all_routes} != {outputs["route_table_id"], outputs["default_route_table_id"]} or any(not _owned_by_run(item, outputs["run_id"]) for item in all_routes):
        reasons.append("UNEXPECTED_ROUTE_TABLE_IN_PROBE_VPC")
    default_routes = next((item for item in all_routes if item.get("RouteTableId") == outputs["default_route_table_id"]), {}).get("Routes", [])
    if any(route.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0" or route.get("DestinationIpv6CidrBlock") == "::/0" for route in default_routes):
        reasons.append("DEFAULT_ROUTE_TABLE_HAS_INTERNET_ROUTE")
    eni_ids = [outputs["probe_eni_id"], *outputs["ssm_endpoint_eni_ids"].values()]
    interfaces = _aws_json("ec2", "describe-network-interfaces", "--network-interface-ids", *eni_ids).get("NetworkInterfaces", [])
    by_eni = {eni.get("NetworkInterfaceId"): eni for eni in interfaces}
    if set(by_eni) != set(eni_ids):
        reasons.append("PROBE_ENI_SET_MISMATCH")
    else:
        for eni_id, eni in by_eni.items():
            tags = _tag_map(eni)
            if eni.get("VpcId") != outputs["vpc_id"] or eni.get("SubnetId") != outputs["subnet_id"] or tags.get("ProbeRunId") != outputs["run_id"]:
                reasons.append("PROBE_ENI_IDENTITY_OR_TAG_MISMATCH")
        probe_eni = by_eni[outputs["probe_eni_id"]]
        if probe_eni.get("PrivateIpAddress") != outputs["probe_private_ip"] or [group.get("GroupId") for group in probe_eni.get("Groups", [])] != [outputs["probe_sg_id"]]:
            reasons.append("PROBE_ENI_NETWORK_OR_SG_MISMATCH")
    endpoint_private_ips = {
        service: by_eni.get(eni_id, {}).get("PrivateIpAddress", "")
        for service, eni_id in outputs["ssm_endpoint_eni_ids"].items()
    }
    try:
        endpoint_ips_valid = all(
            isinstance(value, str) and bool(value) and ipaddress.ip_address(value).version == 4
            for value in endpoint_private_ips.values()
        )
    except (ValueError, TypeError):
        endpoint_ips_valid = False
    if set(endpoint_private_ips) != {"ssm", "ssmmessages"} or not endpoint_ips_valid:
        reasons.append("SSM_ENDPOINT_PRIVATE_IP_INVALID")
    if len(instance_list) == 1:
        mapping = next((item for item in instance.get("BlockDeviceMappings", []) if item.get("DeviceName") == instance.get("RootDeviceName")), {})
        volume_id = mapping.get("Ebs", {}).get("VolumeId")
        volumes = _aws_json("ec2", "describe-volumes", "--volume-ids", volume_id).get("Volumes", []) if volume_id else []
        volume = volumes[0] if len(volumes) == 1 else {}
        volume_tags = {tag.get("Key"): tag.get("Value") for tag in volume.get("Tags", [])}
        if not mapping.get("Ebs", {}).get("DeleteOnTermination") or not volume.get("Encrypted") or volume.get("VolumeType") != "gp3" or volume.get("Size") != 8 or volume_tags.get("ProbeRunId") != outputs["run_id"]:
            reasons.append("ROOT_VOLUME_PROTECTION_MISMATCH")
    managed = _aws_json("ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={outputs['probe_instance_id']}").get("InstanceInformationList", [])
    ssm_online = len(managed) == 1 and managed[0].get("PingStatus") == "Online"
    if not ssm_online:
        reasons.append("PROBE_SSM_NOT_ONLINE")
    guest = "NOT_CHECKED"
    dns_inputs_valid = (
        set(endpoint_private_ips) == {"ssm", "ssmmessages"}
        and endpoint_ips_valid
    )
    if ssm_online and dns_inputs_valid:
        command = build_guest_readonly_command(outputs, endpoint_private_ips)
        parameters = json.dumps({"commands": [command]}, separators=(",", ":"))
        sent = _aws_json("ssm", "send-command", "--instance-ids", outputs["probe_instance_id"], "--document-name", "AWS-RunShellScript", "--timeout-seconds", "30", "--parameters", parameters)
        command_id = sent.get("Command", {}).get("CommandId")
        if not command_id:
            reasons.append("GUEST_READ_ONLY_CHECK_NOT_ACCEPTED")
        else:
            deadline = time.monotonic() + 90
            invocation: dict[str, Any] = {}
            while time.monotonic() < deadline:
                try:
                    invocation = _aws_json("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", outputs["probe_instance_id"])
                    if invocation.get("Status") in {"Success", "Failed", "TimedOut", "Cancelled"}:
                        break
                except ProbeError as exc:
                    if not exc.reason_code.endswith("InvocationDoesNotExist"):
                        raise
                time.sleep(3)
            try:
                guest = json.loads(invocation.get("StandardOutputContent", "{}"))
            except json.JSONDecodeError:
                guest = "INVALID"
            if invocation.get("Status") != "Success" or not isinstance(guest, dict) or not all(guest.values()):
                reasons.append("GUEST_TLS_SERVICE_OR_ALLOWLIST_CHECK_FAILED")
    return {
        "status": "BLOCKED" if reasons else "PASS",
        "phase": "READ_ONLY_PREFLIGHT",
        "probe_only": True,
        "checks": sorted(set(reasons)),
        "live_instance_state": instance.get("State", {}).get("Name"),
        "ssm_online": ssm_online,
        "guest_self_check": guest,
        "firewall_basis": "PROBE_VPC_DNS_FIREWALL_SSM_ALLOWLIST_AND_CATCH_ALL_BLOCK_PLUS_EXACT_SECURITY_GROUP",
        "dns_firewall": "FAIL_CLOSED_SSM_ONLY_ALLOWLIST_VERIFIED",
    }


def run_cli(args: argparse.Namespace) -> dict[str, Any]:
    if not any((args.aws_read_only, args.verify_link, args.inventory_run_id)):
        return {"status": "NO_CHANGE", "phase": "DEFAULT", "probe_only": True}
    if args.inventory_run_id:
        return inventory(_run_id(args.run_id or ""))
    if args.verify_link:
        probe_id = _run_id(args.run_id or "")
        canary_id = _run_id(args.canary_run_id or "")
        probe_workspace = _terraform_workspace(args.probe_workspace or probe_id)
        probe = normalize_probe_outputs(_terraform_outputs(PROBE_TF_DIR, probe_id, probe_workspace), probe_id)
        canary = _terraform_outputs(CANARY_TF_DIR, canary_id)
        # The Canary stack emits scalar outputs with Terraform's {value,type} envelope.
        canary_values = {key: _value(canary, key) for key in canary}
        reasons = validate_stack_link(probe, canary_values)
        return {"status": "BLOCKED" if reasons else "PASS", "phase": "STACK_LINK", "probe_run_id": probe_id, "canary_run_id": canary_id, "checks": reasons, "probe_ipv4": probe["probe_eip"], "probe_domain": probe["probe_domain"], "web_eip_bound": probe["allowed_web_eip_ipv4"]}
    probe_id = _run_id(args.run_id or "")
    probe_workspace = _terraform_workspace(args.probe_workspace or probe_id)
    outputs = normalize_probe_outputs(_terraform_outputs(PROBE_TF_DIR, probe_id, probe_workspace), probe_id)
    return read_only_preflight(outputs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id")
    parser.add_argument("--canary-run-id")
    parser.add_argument(
        "--probe-workspace",
        help="Explicit Probe Terraform workspace (default is the Probe Run ID; use 'default' only when that is where its state lives).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--aws-read-only", action="store_true")
    group.add_argument("--verify-link", action="store_true")
    group.add_argument("--inventory-run-id", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_cli(args)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] in {"PASS", "NO_CHANGE", "READ_ONLY"} else 1
    except ProbeError as exc:
        print(json.dumps({"status": "BLOCKED", "phase": "PREFLIGHT", "probe_only": True, "reason_code": exc.reason_code}, sort_keys=True))
        return 1
    except Exception as exc:  # Do not expose CLI stderr, IAM details, or secret material.
        print(json.dumps({"status": "BLOCKED", "phase": "UNEXPECTED", "probe_only": True, "error_type": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
