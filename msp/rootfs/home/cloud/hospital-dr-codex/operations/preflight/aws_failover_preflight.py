#!/usr/bin/env python3
"""Read-only preflight for the existing Hospital DR AWS Failover path.

Default execution is offline: it checks repository contracts and timer
configuration only. ``--aws-read-only`` opts in to AWS describe/list calls;
IAM simulation additionally requires ``--policy-source-arn`` and is bounded,
or can be omitted with ``--skip-iam-simulation``. The tool never starts/stops
instances, sends SSM commands, changes routes, downloads backup payloads, or
modifies DNS. ``--cloudflare-read-only`` adds
Cloudflare GET requests after fetching the configured token from SSM in
memory.  Secret values and API response bodies are never printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from operations.runtime.ec2_start_plan import EXPECTED_INSTANCES, plan_instances  # noqa: E402
from operations.db.backup_manifest import (  # noqa: E402
    ManifestError,
    parse_manifest_text,
    validate_manifest_sidecar_content,
    verify_manifest_files,
)

REGION_DEFAULT = "ap-northeast-2"
AWS_CLI_TIMEOUT_SECONDS = 15
IAM_SIMULATION_TIMEOUT_SECONDS = 5
S3_LIST_TIMEOUT_SECONDS = 40
S3_OBJECT_TIMEOUT_SECONDS = 20
S3_SIDECAR_MAX_BYTES = 16_384
EXPECTED_VPC_ID = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_ENI = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_PRIVATE_ROUTE_TABLE = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_GATEWAY = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP_ALLOCATION = "AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP = "AWS_PUBLIC_IP_REDACTED"
EXPECTED_WEB_EIP = "AWS_PUBLIC_IP_REDACTED"
CF_TOKEN_PARAMETER_DEFAULT = "/hospital-dr/cloudflare/api-token"
CF_WEB_RECORD_DEFAULT = "4c35b40ec154fb21c92fc3795ce9d5ea"
CF_EMR_RECORD_DEFAULT = "4a4432c4e6290bcbd3dda5113ff8d560"
WEB_DNS_NAME = "hospital-web.pp.ua"
EMR_DNS_NAME = "emr.hospital-web.pp.ua"
ONPREM_TUNNEL = "e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com"
ONPREM_EMR_IP = "IP_REDACTED"
RPO_TARGET_SECONDS = 900
MONITORING_EVIDENCE_MAX_AGE_SECONDS = 120

SAFE_CONFIG_KEYS = {
    "AWS_REGION",
    "AWS_PROFILE",
    "S3_BACKUP_AWS_PROFILE",
    "TF_VAR_cloudflare_ipv4_cidrs",
    "S3_BACKUP_BUCKET",
    "S3_BACKUP_PREFIX",
    "S3_BACKUP_SOURCE_DIR",
    "DB_NR_ENABLED",
    "DB_REPL_MODE",
    "DB_SOURCE_HOST",
    "DB_SOURCE_PORT",
    "DB_SOURCE_LOG_FILE",
    "DB_SOURCE_LOG_POS",
    "DR_FAILOVER_DUMP_BACKUP_ID",
    "DR_FAILOVER_DUMP_SHA256",
    "DR_FAILOVER_DUMP_SIDECAR_SHA256",
    "DR_FAILOVER_DUMP_MANIFEST_SHA256",
    "DR_RPO_EVIDENCE_FILE",
    "DR_FAILOVER_RPO_EVIDENCE_FILE",
    "CF_ZONE_ID",
    "CF_RECORD_ID_EXPECTED",
    "CF_RECORD_ID",
    "CF_EMR_RECORD_ID_EXPECTED",
    "CF_EMR_RECORD_ID",
    "DR_CF_WEB_RECORD_ID_EXPECTED",
    "DR_CF_EMR_RECORD_ID_EXPECTED",
    "CF_TOKEN_PARAM_NAME",
    "CF_TOKEN_AWS_REGION",
    "DR_DOMAIN",
    "EMR_DOMAIN",
    "ONPREM_TUNNEL_HOST",
    "ONPREM_EMR_DNS_IP_EXPECTED",
}

STATUSES = {"PASS", "BLOCKED", "UNVERIFIED", "PENDING_LIVE_TEST", "DISABLED", "RPO_NOT_GUARANTEED"}


def _check(name: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"invalid status for {name}")
    return {"name": name, "status": status, "detail": detail, **extra}


def failover_executor_order_ok(full_failover: str, lifecycle: str) -> bool:
    """Check the real lifecycle function's ordered gates, not helper definitions."""
    start_marker = "start_environment() {"
    stop_marker = "\nstop_environment() {"
    start_at = lifecycle.find(start_marker)
    stop_at = lifecycle.find(stop_marker, start_at + len(start_marker)) if start_at >= 0 else -1
    if start_at < 0 or stop_at < 0:
        return False
    start_body = lifecycle[start_at:stop_at]

    db_start = start_body.find('dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-DR-DB-Server"')
    db_promote = start_body.find("    dr_promote_dr_database\n")
    web_start = start_body.find('dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-Real-Web-Server"')
    emr_start = start_body.find('dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-DR-Doc-Server"')
    # The executor's final readiness gate is the observed private-subnet egress
    # probe. The status formatter runs only after this gate succeeds.
    nat_gate = start_body.find("if ! dr_verify_private_nat_egress; then")
    dns_apply = start_body.find('if ! apply_dr_dns "$web_ip"')
    lifecycle_active = start_body.find("dr_state_write DR_ACTIVE", dns_apply)
    lifecycle_call = full_failover.find('"${FINOPS_DIR}/dr_environment_control.sh" start')
    outer_active = full_failover.find("dr_state_write DR_ACTIVE")
    positions = (db_start, db_promote, web_start, emr_start, nat_gate, dns_apply, lifecycle_active)
    return (
        lifecycle_call >= 0
        and min(positions) >= 0
        and db_start < db_promote < web_start < emr_start < nat_gate < dns_apply < lifecycle_active
        and outer_active > lifecycle_call
        and "SKIP_DNS=true" in full_failover
    )


def parse_safe_env(path: Path | None) -> dict[str, str]:
    """Read allowlisted dotenv values without shell evaluation."""
    if path is None:
        return {}
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in SAFE_CONFIG_KEYS:
            continue
        try:
            parsed = shlex.split(value.strip(), comments=True, posix=True)
        except ValueError:
            continue
        values[key] = parsed[0] if parsed else ""
    return values


def safe_config(env_file: Path | None, environ: dict[str, str] | None = None) -> dict[str, str]:
    values = parse_safe_env(env_file)
    runtime = os.environ if environ is None else environ
    values.update({key: runtime[key] for key in SAFE_CONFIG_KEYS if key in runtime})
    return values


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    raw = str(value).strip()
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        if raw.endswith(" KST"):
            try:
                parsed = datetime.strptime(raw, "%a %Y-%m-%d %H:%M:%S KST").replace(tzinfo=timezone(timedelta(hours=9)))
            except ValueError:
                parsed = None
        else:
            parsed = None
        for fmt in ("%Y%m%d_%H%M%S", "%Y%m%dT%H%M%SZ", "%a %Y-%m-%d %H:%M:%S UTC") if parsed is None else ():
            try:
                parsed = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def terraform_default_cidrs(root: Path, variable_name: str) -> set[str]:
    """Read an HCL list(string) variable's literal default CIDRs without evaluating Terraform."""
    source = _text(root, "infra/terraform/main.tf")
    variable = re.search(
        rf'(?ms)^variable\s+"{re.escape(variable_name)}"\s*\{{(?P<body>.*?)^\}}',
        source,
    )
    if not variable:
        return set()
    default = re.search(r"(?ms)^\s*default\s*=\s*\[(?P<body>.*?)\]", variable.group("body"))
    if not default:
        return set()
    return set(re.findall(r'"((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})"', default.group("body")))


def configured_cloudflare_cidrs(root: Path, values: dict[str, str]) -> set[str]:
    configured = set(re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d)", values.get("TF_VAR_cloudflare_ipv4_cidrs", "")))
    return configured or terraform_default_cidrs(root, "cloudflare_ipv4_cidrs")


def _dump_identity_from_key(dump_key: str) -> tuple[str, str | None]:
    name = Path(dump_key).name
    if not name.endswith(".sql.gz.enc"):
        return "", None
    backup_id = name[:-len(".sql.gz.enc")]
    match = re.search(r"_(\d{8}_\d{6})$", backup_id)
    return backup_id, match.group(1) if match else None


def parse_master_status_sidecar(content: str, dump_key: str) -> dict[str, Any]:
    """Parse supported sidecar formats without returning or logging source text."""
    if len(content.encode("utf-8", errors="replace")) > S3_SIDECAR_MAX_BYTES:
        return {"status": "InvalidFormat", "format": "OVERSIZED"}

    backup_id, dump_stamp = _dump_identity_from_key(dump_key)
    raw = content.lstrip("\ufeff \t\r\n")
    metadata: dict[str, Any] = {}
    sidecar_format = ""
    if raw.startswith(("{", "[")):
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"status": "InvalidFormat", "format": "JSON"}
        if not isinstance(document, dict):
            return {"status": "SchemaMismatch", "format": "JSON"}
        aliases = {
            "backup_id": ("backupid",),
            "backup_timestamp": ("backuptimestamp", "timestamp"),
            "binlog_file": ("binlogfile", "file"),
            "binlog_position": ("binlogposition", "position"),
            "data_reference_time": ("datareferencetime", "datareferenceat", "cutofftime"),
        }
        normalized: dict[str, Any] = {}
        for key, value in document.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized_key in normalized:
                return {"status": "SchemaMismatch", "format": "JSON"}
            normalized[normalized_key] = value
        recognized_json_fields = {alias for names in aliases.values() for alias in names}
        if not recognized_json_fields.intersection(normalized):
            return {"status": "SchemaMismatch", "format": "JSON"}
        for field, names in aliases.items():
            value = next((normalized[name] for name in names if name in normalized), None)
            if value is not None:
                metadata[field] = value
        sidecar_format = "JSON"
    else:
        sidecar_format = "MASTER_STATUS_TEXT"
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            match = re.match(r"^\s*([A-Za-z][A-Za-z0-9 _-]*)\s*:\s*(.*?)\s*$", line)
            if match:
                key = re.sub(r"[^a-z0-9]", "", match.group(1).lower())
                if key in fields:
                    return {"status": "SchemaMismatch", "format": sidecar_format}
                fields[key] = match.group(2)
        aliases = {
            "backup_timestamp": ("backuptimestamp", "timestamp"),
            "binlog_file": ("binlogfile", "file"),
            "binlog_position": ("binlogposition", "position"),
            "backup_id": ("backupid",),
            "data_reference_time": ("datareferencetime", "datareferenceat", "cutofftime"),
        }
        recognized_text_fields = {alias for names in aliases.values() for alias in names} | {"source"}
        has_change_statement = bool(re.search(r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b", raw, re.IGNORECASE))
        if not recognized_text_fields.intersection(fields) and not has_change_statement:
            return {"status": "InvalidFormat", "format": sidecar_format}
        for field, names in aliases.items():
            value = next((fields[name] for name in names if name in fields), None)
            if value is not None:
                metadata[field] = value
        if "binlog_file" not in metadata or "binlog_position" not in metadata:
            statement = re.search(
                r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b(?P<body>.*?)(?:;|$)",
                raw,
                re.IGNORECASE | re.DOTALL,
            )
            if statement:
                body = statement.group("body")
                file_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", body, re.IGNORECASE)
                pos_match = re.search(r"\b(?:MASTER|SOURCE)_LOG_POS\s*=\s*(\d+)", body, re.IGNORECASE)
                if file_match and pos_match:
                    metadata.setdefault("binlog_file", file_match.group(1))
                    metadata.setdefault("binlog_position", pos_match.group(1))
                    sidecar_format = "MYSQL_CHANGE_STATEMENT"

    file_name = metadata.get("binlog_file")
    position = metadata.get("binlog_position")
    if file_name in (None, "") or position in (None, ""):
        return {"status": "MissingBinlogCoordinates", "format": sidecar_format, "binlog_coordinate_status": "MissingBinlogCoordinates", "data_reference_evidence_present": "UNVERIFIED"}
    if not isinstance(file_name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", file_name):
        return {"status": "InvalidFormat", "format": sidecar_format, "binlog_coordinate_status": "InvalidFormat", "data_reference_evidence_present": False}
    try:
        parsed_position = int(position)
    except (TypeError, ValueError, OverflowError):
        return {"status": "InvalidFormat", "format": sidecar_format, "binlog_coordinate_status": "InvalidFormat", "data_reference_evidence_present": False}
    if parsed_position <= 0:
        return {"status": "InvalidFormat", "format": sidecar_format, "binlog_coordinate_status": "InvalidFormat", "data_reference_evidence_present": False}

    timestamp = metadata.get("backup_timestamp")
    declared_data_reference = parse_timestamp(metadata.get("data_reference_time"))
    parsed_timestamp = parse_timestamp(timestamp)
    if not timestamp or not parsed_timestamp or not dump_stamp:
        timestamp_status = "MISSING" if not timestamp else "InvalidFormat" if not parsed_timestamp else "UNVERIFIED"
        return {
            "status": "SchemaMismatch" if timestamp and parsed_timestamp else "InvalidFormat" if timestamp else "SchemaMismatch",
            "format": sidecar_format,
            "backup_identity_status": "UNVERIFIED",
            "sidecar_timestamp_match_status": timestamp_status,
            "binlog_coordinate_status": "PASS",
            "binlog_file": file_name,
            "binlog_position": parsed_position,
            "data_reference_evidence_present": declared_data_reference is not None,
        }
    if metadata.get("backup_id") not in (None, backup_id, Path(dump_key).name):
        return {"status": "SchemaMismatch", "format": sidecar_format, "backup_identity_status": "SchemaMismatch", "sidecar_timestamp_match_status": "PASS", "binlog_coordinate_status": "PASS", "binlog_file": file_name, "binlog_position": parsed_position, "data_reference_evidence_present": declared_data_reference is not None}
    if parsed_timestamp.strftime("%Y%m%d_%H%M%S") != dump_stamp:
        return {"status": "SchemaMismatch", "format": sidecar_format, "backup_identity_status": "SchemaMismatch", "sidecar_timestamp_match_status": "SchemaMismatch", "binlog_coordinate_status": "PASS", "binlog_file": file_name, "binlog_position": parsed_position, "data_reference_evidence_present": declared_data_reference is not None}
    return {
        "status": "PASS",
        "format": sidecar_format,
        "backup_timestamp": parsed_timestamp.isoformat().replace("+00:00", "Z"),
        "backup_identity_status": "PASS",
        "sidecar_timestamp_match_status": "PASS",
        "binlog_coordinate_status": "PASS",
        "binlog_file": file_name,
        "binlog_position": parsed_position,
        # BackupTimestamp is the dump job's start marker, not a proven data cutoff.
        "data_reference_time_status": "UNVERIFIED",
        "data_reference_evidence_present": declared_data_reference is not None,
    }


def classify_aws_cli_failure(return_code: int, stderr: str) -> str:
    """Map AWS CLI failures to safe, non-secret diagnostic categories."""
    if return_code == 0:
        return "PASS"
    if return_code == 124 or "timed out" in stderr.lower():
        return "Timeout"
    if return_code == 127:
        return "CommandUnavailable"
    if return_code == 403:
        return "AccessDenied"
    if return_code == 404:
        return "ObjectMissing"
    match = re.search(r"An error occurred \(([^)]+)\)", stderr, re.IGNORECASE)
    error_code = match.group(1).lower() if match else ""
    if error_code in {"accessdenied", "accessdeniedexception", "unauthorizedoperation", "forbidden", "forbiddenexception", "403"}:
        return "AccessDenied"
    if error_code in {"nosuchkey", "notfound", "404", "nosuchbucket"}:
        return "ObjectMissing"
    if "access denied" in stderr.lower() or "not authorized" in stderr.lower():
        return "AccessDenied"
    return "UNVERIFIED"


def _parse_dump_interval(timer_text: str) -> int | None:
    match = re.search(r"(?m)^OnCalendar=.*\*:(\d{2}(?:,\d{2})*):00\s*$", timer_text)
    if not match:
        return None
    minutes = sorted({int(part) for part in match.group(1).split(",")})
    if not minutes or any(minute > 59 for minute in minutes):
        return None
    gaps = [b - a for a, b in zip(minutes, minutes[1:])]
    gaps.append(60 - minutes[-1] + minutes[0])
    return max(gaps) if gaps else None


def _parse_upload_offset(backup_timer: str, upload_timer: str) -> int | None:
    def marks(text: str) -> list[int] | None:
        match = re.search(r"(?m)^OnCalendar=.*\*:(\d{2}(?:,\d{2})*):00\s*$", text)
        if not match:
            return None
        result = sorted({int(part) for part in match.group(1).split(",")})
        return result if result and all(0 <= minute <= 59 for minute in result) else None

    backups, uploads = marks(backup_timer), marks(upload_timer)
    if not backups or not uploads:
        return None
    offsets = [min((upload - backup) % 60 or 60 for upload in uploads) for backup in backups]
    return max(offsets) if offsets else None


def _text(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def static_contract_checks(root: Path, values: dict[str, str]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    terraform = _text(root, "infra/terraform/main.tf")
    nat_script = _text(root, "operations/nat_instance/web_nat_instance_status.sh")
    lifecycle = _text(root, "operations/finops/dr_environment_control.sh")
    dns = _text(root, "operations/failover/dns_transaction.sh")
    ssm = _text(root, "operations/runtime/ssm_ssh.sh")
    full_failover = _text(root, "operations/failover/full_failover.sh")
    ansible_site = _text(root, "automation/ansible/site.yml")
    ansible_db = _text(root, "automation/ansible/roles/db_recovery/tasks/main.yml")
    ansible_web = _text(root, "automation/ansible/roles/web_deploy/tasks/main.yml")
    ansible_emr = _text(root, "automation/ansible/roles/doc_deploy/tasks/main.yml")

    planner_consistent = EXPECTED_INSTANCES == {
        "Hospital-Real-Web-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
        "Hospital-DR-Doc-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
        "Hospital-DR-DB-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
    }
    instance_contract_present = planner_consistent and all(
        fragment in terraform
        for fragment in (
            'private_ip                  = "IP_REDACTED"',
            'private_ip                  = "IP_REDACTED"',
            'private_ip                  = "IP_REDACTED"',
            'source_dest_check           = false',
            'tags                        = { Name = "Hospital-Real-Web-Server" }',
            'tags                        = { Name = "Hospital-DR-Doc-Server" }',
            'tags                        = { Name = "Hospital-DR-DB-Server" }',
        )
    )
    checks.append(_check(
        "terraform_instance_contract",
        "PASS" if instance_contract_present else "BLOCKED",
        "Terraform and the existing EC2 identity planner contain the approved three-role identity contract" if instance_contract_present else "Terraform and EC2 identity planner do not agree with the approved role contract",
    ))

    network_contract = all(
        fragment in terraform
        for fragment in (
            'private_ip                  = "IP_REDACTED"',
            'private_ip                  = "IP_REDACTED"',
            'private_ip                  = "IP_REDACTED"',
            'aws_security_group.db_sg',
            'aws_security_group.doc_sg',
            'aws_security_group.web_sg',
            'aws_route_table.private_rt',
        )
    )
    checks.append(_check(
        "terraform_network_contract",
        "PASS" if network_contract else "BLOCKED",
        "Terraform defines the DR subnets, service security groups, and private route-table path" if network_contract else "required Terraform network references are missing",
    ))

    nat_contract = all(
        fragment in nat_script
        for fragment in (
            EXPECTED_VPC_ID,
            EXPECTED_WEB_ENI,
            EXPECTED_PRIVATE_ROUTE_TABLE,
            EXPECTED_NAT_GATEWAY,
            EXPECTED_NAT_EIP_ALLOCATION,
            'current_status=READY',
            'current_mode=WEB_NAT_INSTANCE',
            'current_status=READY_FOR_BLACKHOLE_RECOVERY',
        )
    ) and 'NAT_INSTANCE_STATUS' in lifecycle and 'CURRENT_EGRESS_MODE' in lifecycle and 'WEB_NAT_INSTANCE' in lifecycle
    checks.append(_check(
        "nat_ready_contract",
        "PASS" if nat_contract else "BLOCKED",
        "Failover requires READY plus WEB_NAT_INSTANCE; blackhole recovery readiness is not treated as service readiness" if nat_contract else "NAT status contract is missing or does not gate Failover on READY/WEB_NAT_INSTANCE",
    ))

    web_health = _text(root, "services/web/app.js")
    emr_health = _text(root, "services/emr/server.js")
    web_contract = all(fragment in web_health for fragment in ("/__hospital_dr/health", "SELECT 1", ".status(204)", ".status(503)"))
    emr_contract = all(fragment in emr_health for fragment in ("/__hospital_dr/health", "SELECT 1", ".status(204)", ".status(503)"))
    health_paths_wired = lifecycle.count("/__hospital_dr/health") >= 2 and "curl --fail" in lifecycle
    checks.append(_check(
        "application_health_contract",
        "PASS" if web_contract and emr_contract and health_paths_wired else "BLOCKED",
        "Web and EMR health endpoints perform SELECT 1 and return HTTP 204 on success; live health still requires started services" if web_contract and emr_contract and health_paths_wired else "Web/EMR health endpoint or deployment wiring is incomplete",
        live_status="PENDING_LIVE_TEST",
        emr_expected_http=204,
    ))

    executor_order_ok = failover_executor_order_ok(full_failover, lifecycle)
    checks.append(_check(
        "failover_executor_order",
        "PASS" if executor_order_ok else "BLOCKED",
        "existing executor orders DB start/promotion before Web/EMR, requires NAT readiness before DNS, and records DR_ACTIVE only after the lifecycle command returns" if executor_order_ok else "existing Failover executor call/order or final-state guard differs from the reviewed sequence",
        live_status="PENDING_LIVE_TEST",
    ))

    ansible_order_ok = (
        ansible_site.find("- db_recovery") >= 0
        and ansible_site.find("- doc_deploy") > ansible_site.find("- db_recovery")
        and ansible_site.find("- web_deploy") > ansible_site.find("- doc_deploy")
        and "DB_BACKUP_FILE and its matching .master_status" in ansible_db
        and "DR_DB_SERVICE_VALIDATOR" in ansible_web
        and "DR_DB_SERVICE_VALIDATOR" in ansible_emr
        and "DR_IMAGE_TAG" in ansible_web
        and "DR_IMAGE_TAG" in ansible_emr
    )
    checks.append(_check(
        "ansible_deployment_contract",
        "PASS" if ansible_order_ok else "BLOCKED",
        "Ansible source orders DB recovery then EMR then Web, requires a paired DB backup input, and validates immutable app image/DB endpoint contracts; this source is not proof that current instances match it",
        live_status="PENDING_LIVE_TEST",
    ))

    dns_ids = _dns_ids(values)
    dns_ids_configured = bool(
        (values.get("DR_CF_WEB_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID"))
        and (values.get("DR_CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID"))
    )
    dns_ids_match = dns_ids == {"web": CF_WEB_RECORD_DEFAULT, "emr": CF_EMR_RECORD_DEFAULT}
    zone_configured = bool(re.fullmatch(r"[0-9a-fA-F]{32}", values.get("CF_ZONE_ID", "")))
    dns_contract = all(fragment in dns for fragment in (
        "dr_dns_snapshot_record()", "dr_dns_update_record()", "dr_dns_verify_record_payload()", "dr_dns_rollback_snapshots()",
        "dr_dns_validate_snapshot_pair", "dr_dns_snapshot_pairs_equal_ids",
        "Snapshot record set restored and verified.",
        'echo "[DNS ROLLBACK ERROR] Could not restore ${label}."',
        'echo "[DNS ROLLBACK ERROR] On-Prem record pair restoration failed."',
    )) and "dr_dns_failover_transaction()" in dns and 'return 2' in dns
    dns_ordered = "prepare_dns_snapshot" in lifecycle and "apply_dr_dns" in lifecycle and "dr_dns_failover_transaction" in lifecycle
    checks.append(_check(
        "dns_transaction_contract",
        "PASS" if dns_contract and dns_ordered and dns_ids_match else "BLOCKED",
        "existing code snapshots both records, verifies readback, and rolls back partial/update-health failures; rollback failure is a distinct partial-failure result; current runtime IDs still need live readback" if dns_contract and dns_ordered and dns_ids_match else "DNS snapshot/readback/rollback wiring or expected record IDs are incomplete",
        web_record_id_configured=bool(values.get("DR_CF_WEB_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID")),
        emr_record_id_configured=bool(values.get("DR_CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID")),
        record_ids_explicitly_configured=dns_ids_configured,
        record_ids_match_canonical=dns_ids_match,
        zone_id_configured=zone_configured,
        live_status="UNVERIFIED",
    ))

    cloudflare_parameter = values.get("CF_TOKEN_PARAM_NAME", CF_TOKEN_PARAMETER_DEFAULT)
    cloudflare_region = values.get("CF_TOKEN_AWS_REGION", REGION_DEFAULT)
    checks.append(_check(
        "cloudflare_ssm_contract",
        "PASS" if "ssm get-parameter" in _text(root, "operations/cloudflare_ssm_auth.sh") else "BLOCKED",
        "existing token loader references SSM Parameter Store; token value is not read in offline mode",
        parameter_configured=bool(cloudflare_parameter),
        region_configured=bool(cloudflare_region),
        live_status="UNVERIFIED",
    ))
    checks.append(_check("cloudflare_zone_config", "PASS" if zone_configured else "UNVERIFIED", "Cloudflare zone ID has the expected non-secret format" if zone_configured else "CF_ZONE_ID was not supplied or does not match the expected format"))

    executor_text = lifecycle + ssm
    actions_present = all((
        "aws ec2 describe-instances" in executor_text,
        "aws ec2 start-instances" in _text(root, "operations/runtime/ec2_start_actions.sh"),
        '"ssm", "start-session"' in ssm,
    ))
    db_profile_absent = bool(re.search(r'resource\s+"aws_instance"\s+"db_server"\s*\{(?:(?!\n\}).)*\n\}', terraform, re.S)) and not bool(
        re.search(r'resource\s+"aws_instance"\s+"db_server"\s*\{(?:(?!\n\}).)*iam_instance_profile', terraform, re.S)
    )
    checks.append(_check(
        "executor_iam_contract",
        "PASS" if actions_present else "BLOCKED",
        "executor call sites use EC2 describe/start and SSM session/describe APIs; effective IAM is checked only in explicit AWS read-only mode" if actions_present else "executor API requirements could not be matched to the existing scripts",
        terraform_db_instance_profile="NOT_CONFIGURED_IN_CANONICAL_TERRAFORM" if db_profile_absent else "CONFIGURED_OR_UNVERIFIED",
        live_status="UNVERIFIED",
    ))
    checks.append(_check(
        "terraform_ssm_instance_profile",
        "UNVERIFIED" if db_profile_absent else "PASS",
        "Canonical Terraform has no instance profile on the DB host; Web/EMR use the ECR pull profile, so live SSM-managed status and attached role policy must be confirmed separately" if db_profile_absent else "Canonical Terraform declares instance profiles; live SSM role health still requires AWS read-only verification",
    ))

    backup_timer = _text(root, "operations/db/systemd/hospital-dr-db-backup.timer")
    upload_timer = _text(root, "operations/db/systemd/hospital-dr-s3-upload.timer")
    dump_interval = _parse_dump_interval(backup_timer)
    upload_interval = _parse_dump_interval(upload_timer)
    checks.append(_check(
        "backup_schedule_contract",
        "PASS" if dump_interval and upload_interval else "UNVERIFIED",
        "backup and uploader OnCalendar schedules parsed from existing systemd timer files" if dump_interval and upload_interval else "one or both systemd timer schedules could not be parsed",
        dump_interval_minutes=dump_interval,
        upload_schedule_interval_minutes=upload_interval,
        upload_timer_text="05,35 minute marks; upload runs shortly after the matching dump marks" if upload_interval == 30 else "see systemd timer contract",
        runtime_timer_status="UNVERIFIED",
    ))
    return checks


def _dns_ids(values: dict[str, str]) -> dict[str, str]:
    return {
        "web": values.get("DR_CF_WEB_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID_EXPECTED") or values.get("CF_RECORD_ID") or CF_WEB_RECORD_DEFAULT,
        "emr": values.get("DR_CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID_EXPECTED") or values.get("CF_EMR_RECORD_ID") or CF_EMR_RECORD_DEFAULT,
    }


def classify_nat_route(web: dict[str, Any], route_table: dict[str, Any], *, nat_gateway_id: str = EXPECTED_NAT_GATEWAY) -> dict[str, str]:
    """Mirror the existing NAT status contract, then keep stopped Web pending."""
    web_id = web.get("InstanceId")
    web_private = web.get("PrivateIpAddress")
    web_public = web.get("PublicIpAddress")
    source_dest = web.get("SourceDestCheck")
    state = (web.get("State") or {}).get("Name", "unknown")
    interfaces = web.get("NetworkInterfaces") or []
    primary = next((eni.get("NetworkInterfaceId") for eni in interfaces if eni.get("Attachment", {}).get("DeviceIndex") == 0), None)
    routes = route_table.get("Routes", [])
    default = next((item for item in routes if item.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0"), {})
    route_state = default.get("State", "missing")
    route_eni = default.get("NetworkInterfaceId")
    route_nat = default.get("NatGatewayId")
    identity_ok = web_id == "AWS_RESOURCE_ID_REDACTED" and web_private == "AWS_PUBLIC_IP_REDACTED" and web_public == EXPECTED_WEB_EIP and primary == EXPECTED_WEB_ENI and source_dest is False
    if identity_ok and route_table.get("RouteTableId") == EXPECTED_PRIVATE_ROUTE_TABLE and route_state == "active" and route_eni == EXPECTED_WEB_ENI:
        status = "READY" if state == "running" else "PENDING_LIVE_TEST"
        mode = "WEB_NAT_INSTANCE"
    elif route_state == "blackhole" and route_nat == nat_gateway_id:
        status, mode = "BLOCKED", "BLACKHOLE"
    elif route_state == "active" and route_nat == nat_gateway_id:
        status, mode = "BLOCKED", "NAT_GATEWAY_NOT_FAILOVER_MODE"
    elif route_state == "active" and route_eni and route_eni != EXPECTED_WEB_ENI:
        status, mode = "BLOCKED", "ENI_MISMATCH"
    else:
        status, mode = "BLOCKED", "NOT_READY"
    return {"status": status, "mode": mode, "route_state": route_state, "route_eni": route_eni or "", "web_state": state}


def preflight_nat_status(nat: dict[str, str]) -> str:
    """Translate executor NAT state into preflight status without weakening it."""
    if nat.get("status") == "READY":
        return "PASS" if nat.get("web_state") == "running" else "PENDING_LIVE_TEST"
    return nat.get("status", "UNVERIFIED")


def _read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def assess_rpo(
    nr_enabled: str | None,
    evidence: dict[str, Any] | None,
    *,
    now: datetime,
    dump_interval_minutes: int | None,
    nominal_upload_offset_minutes: int | None = None,
) -> list[dict[str, Any]]:
    nr_value = (nr_enabled or "").strip().lower()
    nr_state = "DISABLED" if nr_value in {"false", "0", "no", "off"} else "UNVERIFIED"
    measured_rpo: int | None = None
    evidence_reason = "NO_TRUSTED_RPO_EVIDENCE"
    source = evidence
    if evidence and isinstance(evidence.get("rpo"), dict):
        source = evidence["rpo"]
    cutoff = parse_timestamp(source.get("data_reference_at") or source.get("recovered_data_cutoff_at") or (evidence or {}).get("data_reference_at") or (evidence or {}).get("recovered_data_cutoff_at")) if source else None
    incident = parse_timestamp(source.get("incident_at") or (evidence or {}).get("incident_at")) if source else None
    reference_evidence = source.get("data_reference_evidence") if source else None
    reference_status = (
        (source.get("data_reference_evidence_status") if source else "")
        or (reference_evidence.get("status") if isinstance(reference_evidence, dict) else "")
    )
    reference_source = (
        (source.get("data_reference_evidence_source") if source else "")
        or (reference_evidence.get("source") if isinstance(reference_evidence, dict) else "")
    )
    try:
        raw_measurement = source.get("rpo_seconds") if source else None
        measured_rpo = int(raw_measurement) if raw_measurement is not None and not isinstance(raw_measurement, bool) else None
    except (TypeError, ValueError):
        measured_rpo = None
    measurement_is_real = bool(
        source
        and source.get("rpo_status") == "MEASURED"
        and source.get("rpo_value_status") == "MEASURED"
        and reference_status == "VERIFIED"
        and bool(str(reference_source or "").strip())
        and measured_rpo is not None
        and measured_rpo >= 0
        and cutoff is not None
        and incident is not None
        and cutoff <= now
        and incident <= now
        and cutoff <= incident
        and abs((incident - cutoff).total_seconds() - measured_rpo) <= 1
    )
    nr_last_replicated_at: datetime | None = None
    if nr_value in {"true", "1", "yes", "on"} and evidence and source:
        verified_at = parse_timestamp(source.get("verified_at") or source.get("captured_at") or evidence.get("generated_at"))
        nr_last_replicated_at = parse_timestamp(source.get("last_replicated_at"))
        io_ok = str(source.get("replica_io_running", "")).strip().lower() in {"yes", "true", "on", "1"}
        sql_ok = str(source.get("replica_sql_running", "")).strip().lower() in {"yes", "true", "on", "1"}
        lag = source.get("seconds_behind_source")
        try:
            lag_seconds = int(lag)
        except (TypeError, ValueError):
            lag_seconds = None
        fresh = verified_at is not None and 0 <= (now - verified_at).total_seconds() <= MONITORING_EVIDENCE_MAX_AGE_SECONDS
        replication_age = (now - nr_last_replicated_at).total_seconds() if nr_last_replicated_at else None
        replication_fresh = replication_age is not None and 0 <= replication_age <= RPO_TARGET_SECONDS
        lag_valid = lag_seconds is not None and 0 <= lag_seconds <= RPO_TARGET_SECONDS
        if fresh and replication_fresh and io_ok and sql_ok and lag_valid:
            nr_state = "PASS"
            evidence_reason = "FRESH_NR_READINESS_EVIDENCE"
        else:
            explicit_failure = (
                str(source.get("replica_io_running", "")).strip().lower() in {"no", "false", "off", "0"}
                or str(source.get("replica_sql_running", "")).strip().lower() in {"no", "false", "off", "0"}
                or (lag_seconds is not None and lag_seconds > RPO_TARGET_SECONDS)
                or (fresh and replication_age is not None and replication_age > RPO_TARGET_SECONDS)
            )
            nr_state = "BLOCKED" if fresh and explicit_failure else "UNVERIFIED"
            evidence_reason = "FRESH_NR_EVIDENCE_SHOWS_REPLICATION_NOT_READY" if nr_state == "BLOCKED" else "NR_EVIDENCE_STALE_OR_INCOMPLETE"
    else:
        if nr_value not in {"false", "0", "no", "off", "true", "1", "yes", "on"}:
            evidence_reason = "DB_NR_ENABLED_NOT_CONFIGURED"
        elif nr_state == "DISABLED":
            evidence_reason = "DB_NR_ENABLED_FALSE"

    dump_schedule = dump_interval_minutes is not None
    dump_alone_meets = bool(
        dump_schedule
        and nominal_upload_offset_minutes is not None
        and (dump_interval_minutes + nominal_upload_offset_minutes) * 60 <= RPO_TARGET_SECONDS
    )
    data_reference_status = "VERIFIED" if measurement_is_real and cutoff is not None else "UNVERIFIED"
    if measurement_is_real:
        rpo_status = "PASS" if measured_rpo <= RPO_TARGET_SECONDS else "RPO_NOT_GUARANTEED"
        rpo_detail = "measured RPO matches the verified incident-to-recovered-data-cutoff interval" if measured_rpo <= RPO_TARGET_SECONDS else "verified recovered-data cutoff exceeds the 15-minute RPO target"
    elif nr_state != "PASS" and not dump_alone_meets:
        rpo_status = "RPO_NOT_GUARANTEED"
        rpo_detail = "NR is not freshly verified and the configured dump interval exceeds the 15-minute target"
    else:
        rpo_status = "UNVERIFIED"
        rpo_detail = "no internally consistent incident time, measured RPO, and recovered-data cutoff is available; file/upload time is not a data timestamp"
    upload_delay = nominal_upload_offset_minutes
    return [
        _check(
            "nr_readiness",
            nr_state,
            evidence_reason,
            last_verified_replication_at=nr_last_replicated_at.isoformat().replace("+00:00", "Z") if nr_state == "PASS" and nr_last_replicated_at else None,
        ),
        _check(
            "dump_rpo_capability",
            "PENDING_LIVE_TEST" if dump_alone_meets else "UNVERIFIED" if dump_schedule and nr_state == "PASS" else "RPO_NOT_GUARANTEED" if dump_schedule else "UNVERIFIED",
            "nominal dump plus upload cadence is within target; actual data cutoff, upload success, and restore remain unverified" if dump_alone_meets else "dump-only fallback alone cannot guarantee 15-minute RPO; NR is currently verified as primary" if dump_schedule and nr_state == "PASS" else "dump plus upload cadence cannot guarantee 15-minute RPO" if dump_schedule else "dump cadence is not available",
            dump_interval_minutes=dump_interval_minutes,
            nominal_upload_offset_minutes=upload_delay,
            data_reference_time_status=data_reference_status,
            rpo_target_seconds=RPO_TARGET_SECONDS,
        ),
        _check("rpo_measurement", rpo_status, rpo_detail, rpo_seconds=measured_rpo if measurement_is_real else None, data_reference_at=cutoff.isoformat().replace("+00:00", "Z") if measurement_is_real and cutoff else None, reason=evidence_reason),
    ]


def validate_instance_inventory(instances: list[dict[str, Any]]) -> tuple[list[dict[str, str]] | None, str]:
    response = {"Reservations": [{"Instances": instances}]}
    try:
        plan = plan_instances(response)
    except (ValueError, TypeError, KeyError) as exc:
        # The planner's error messages are safe identity/status reasons.
        return None, str(exc)
    return plan, "approved instance IDs, role tags, private IPs, and lifecycle states match"


def validate_network_snapshot(
    inventory: list[dict[str, Any]],
    enis: list[dict[str, Any]],
    subnets: list[dict[str, Any]],
    security_groups: list[dict[str, Any]],
    route_tables: list[dict[str, Any]],
    *,
    cloudflare_cidrs: set[str] | None = None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    by_id = {item.get("InstanceId"): item for item in inventory}
    ids = {item[0]: item for item in EXPECTED_INSTANCES.values()}
    instance_vpcs_ok = len(by_id) == 3 and all(by_id.get(instance_id, {}).get("VpcId") == EXPECTED_VPC_ID for instance_id in ids)
    checks.append(_check(
        "instance_vpc",
        "PASS" if instance_vpcs_ok else "BLOCKED",
        "all three expected EC2s belong to the approved DR VPC" if instance_vpcs_ok else "one or more EC2s are missing or outside the approved VPC",
        expected_vpc_id=EXPECTED_VPC_ID,
        observed_vpc_ids=sorted({str(item.get("VpcId")) for item in inventory if item.get("VpcId")}),
    ))

    eni_by_id = {eni.get("NetworkInterfaceId"): eni for eni in enis}
    eni_ok = True
    sg_ids: set[str] = set()
    subnet_ids: set[str] = set()
    for instance_id, instance in by_id.items():
        subnet_ids.add(str(instance.get("SubnetId") or ""))
        sg_ids.update(group.get("GroupId") for group in instance.get("SecurityGroups", []) if group.get("GroupId"))
        attached = instance.get("NetworkInterfaces", [])
        if not attached:
            eni_ok = False
        for ref in attached:
            eni = eni_by_id.get(ref.get("NetworkInterfaceId"))
            attachment = (eni or {}).get("Attachment") or {}
            if not eni or attachment.get("InstanceId") != instance_id or eni.get("VpcId") != EXPECTED_VPC_ID:
                eni_ok = False
    web = by_id.get("AWS_RESOURCE_ID_REDACTED", {})
    web_primary = next((eni.get("NetworkInterfaceId") for eni in web.get("NetworkInterfaces", []) if eni.get("Attachment", {}).get("DeviceIndex") == 0), None)
    eni_ok = eni_ok and web_primary == EXPECTED_WEB_ENI
    checks.append(_check(
        "eni_attachment",
        "PASS" if eni_ok else "BLOCKED",
        "ENIs are attached to the expected instances and Web NAT ENI identity matches" if eni_ok else "ENI attachment or Web NAT target does not match the expected instance",
        expected_web_eni=EXPECTED_WEB_ENI,
        observed_eni_ids=sorted(eni_by_id),
    ))

    subnet_by_id = {item.get("SubnetId"): item for item in subnets}
    subnet_ok = bool(subnet_ids) and all(
        subnet_by_id.get(subnet_id, {}).get("VpcId") == EXPECTED_VPC_ID
        and subnet_by_id.get(subnet_id, {}).get("State") == "available"
        for subnet_id in subnet_ids
    )
    checks.append(_check(
        "subnets",
        "PASS" if subnet_ok else "BLOCKED",
        "all instance subnets exist, are available, and are in the approved VPC" if subnet_ok else "one or more instance subnet references are missing or mismatched",
        subnet_ids=sorted(subnet_ids),
    ))

    group_by_id = {group.get("GroupId"): group for group in security_groups}
    sg_ok = bool(sg_ids) and all(group_by_id.get(sg_id, {}).get("VpcId") == EXPECTED_VPC_ID for sg_id in sg_ids)
    checks.append(_check(
        "security_groups",
        "PASS" if sg_ok else "BLOCKED",
        "all attached security groups exist in the approved VPC" if sg_ok else "attached security group is missing or belongs to another VPC",
        group_count=len(sg_ids),
        group_ids=sorted(sg_ids),
    ))

    web_sgs = {group.get("GroupId") for group in by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SecurityGroups", [])}
    doc_sgs = {group.get("GroupId") for group in by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SecurityGroups", [])}
    db_sgs = {group.get("GroupId") for group in by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SecurityGroups", [])}

    def port_rules(group_ids: set[str], port: int) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for group_id in group_ids:
            for rule in group_by_id.get(group_id, {}).get("IpPermissions", []):
                protocol = str(rule.get("IpProtocol", ""))
                first, last = rule.get("FromPort", 0), rule.get("ToPort", 65535)
                if protocol not in {"tcp", "-1"}:
                    continue
                if protocol == "tcp" and not (isinstance(first, int) and isinstance(last, int) and first <= port <= last):
                    continue
                matches.append({"group_id": group_id, **rule})
        return matches

    def source_groups_for_port(group_ids: set[str], port: int) -> set[str]:
        return {
            peer.get("GroupId")
            for rule in port_rules(group_ids, port)
            for peer in rule.get("UserIdGroupPairs", [])
            if peer.get("GroupId")
        }

    def ipv4_sources_for_port(group_ids: set[str], port: int) -> set[str]:
        return {
            entry.get("CidrIp")
            for rule in port_rules(group_ids, port)
            for entry in rule.get("IpRanges", [])
            if entry.get("CidrIp")
        }

    required_rules: list[dict[str, Any]] = []

    def require_cidrs(role: str, group_ids: set[str], port: int, source_label: str, expected: set[str] | None) -> None:
        observed = ipv4_sources_for_port(group_ids, port)
        missing = sorted(expected - observed) if expected else []
        present = bool(observed) if expected is None else not missing
        required_rules.append({
            "target_role": role,
            "target_security_group_ids": sorted(group_ids),
            "protocol": "tcp",
            "port": port,
            "required_source": source_label,
            "status": "PASS" if present else "BLOCKED",
            "missing_sources": missing,
        })

    def require_peer(role: str, group_ids: set[str], port: int, peer_groups: set[str], source_label: str) -> None:
        observed = source_groups_for_port(group_ids, port)
        missing = sorted(peer_groups - observed)
        required_rules.append({
            "target_role": role,
            "target_security_group_ids": sorted(group_ids),
            "protocol": "tcp",
            "port": port,
            "required_source": source_label,
            "status": "PASS" if peer_groups and not missing else "BLOCKED",
            "missing_sources": missing,
        })

    require_cidrs("Web", web_sgs, 80, "Terraform cloudflare_ipv4_cidrs", cloudflare_cidrs)
    require_cidrs("Web", web_sgs, 443, "Terraform cloudflare_ipv4_cidrs", cloudflare_cidrs)
    require_peer("EMR/Doc", doc_sgs, 80, web_sgs, "Web Security Group (reverse proxy)")
    require_peer("EMR/Doc", doc_sgs, 22, web_sgs, "Web Security Group (SSM-jump SSH for Ansible)")
    require_peer("DB", db_sgs, 3306, web_sgs, "Web Security Group (application DB writes)")
    require_peer("DB", db_sgs, 3306, doc_sgs, "EMR/Doc Security Group (application DB writes)")
    require_peer("DB", db_sgs, 22, web_sgs, "Web Security Group (SSM-jump SSH for Ansible)")
    missing_rules = [item for item in required_rules if item["status"] != "PASS"]
    checks.append(_check(
        "security_group_service_ports",
        "PASS" if not missing_rules else "BLOCKED",
        "required application and SSM/Ansible TCP ingress rules match the Terraform source contract" if not missing_rules else "one or more required application or SSM/Ansible TCP ingress rules are absent or have the wrong source",
        required_ingress_rules=required_rules,
        missing_required_rules=missing_rules,
        not_required_for_executor=[{
            "target_role": "Web",
            "protocol": "tcp",
            "port": 22,
            "reason": "executor reaches Web through AWS Systems Manager AWS-StartSSHSession; this is not inbound VPC TCP/22 and does not justify opening the Web Security Group",
            "terraform_optional_source": "management_ipv4_cidrs",
        }],
    ))

    def has_unrestricted_ingress(group_ids: set[str], port: int) -> bool:
        for group_id in group_ids:
            for rule in group_by_id.get(group_id, {}).get("IpPermissions", []):
                protocol = str(rule.get("IpProtocol", ""))
                if protocol not in {"tcp", "-1"}:
                    continue
                first, last = rule.get("FromPort", 0), rule.get("ToPort", 65535)
                if protocol == "tcp" and not (isinstance(first, int) and isinstance(last, int) and first <= port <= last):
                    continue
                cidrs = {entry.get("CidrIp") for entry in rule.get("IpRanges", [])}
                cidrs6 = {entry.get("CidrIpv6") for entry in rule.get("Ipv6Ranges", [])}
                if "IP_REDACTED/0" in cidrs or "::/0" in cidrs6:
                    return True
        return False

    public_ingress_scoped = all(
        not has_unrestricted_ingress(web_sgs, port)
        for port in (22, 80, 443)
    )
    checks.append(_check("security_group_public_scope", "PASS" if public_ingress_scoped else "BLOCKED", "Web management/HTTP/HTTPS ingress has no world-open source CIDR" if public_ingress_scoped else "Web security group exposes a checked ingress port to the entire IPv4/IPv6 Internet"))

    egress_by_group = {
        group_id: group_by_id.get(group_id, {}).get("IpPermissionsEgress", [])
        for group_id in sg_ids
    }
    every_group_has_unrestricted_egress = all(
        any(
            str(rule.get("IpProtocol")) == "-1"
            and bool(rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("PrefixListIds") or rule.get("UserIdGroupPairs"))
            for rule in rules
        )
        for rules in egress_by_group.values()
    )
    egress_rules_known = bool(sg_ids) and all("IpPermissionsEgress" in group_by_id.get(group_id, {}) for group_id in sg_ids)
    egress_status = "UNVERIFIED" if not egress_rules_known else "BLOCKED" if any(not rules for rules in egress_by_group.values()) else "PASS" if every_group_has_unrestricted_egress else "UNVERIFIED"
    checks.append(_check(
        "security_group_egress",
        egress_status,
        "attached groups expose the configured all-protocol egress path" if egress_status == "PASS" else "one or more attached groups have no egress rules" if egress_status == "BLOCKED" else "restricted/missing egress evidence needs comparison with the live service dependency ports",
    ))

    route_table = next((table for table in route_tables if table.get("RouteTableId") == EXPECTED_PRIVATE_ROUTE_TABLE), None)
    if route_table is None or route_table.get("VpcId") != EXPECTED_VPC_ID:
        nat = {"status": "BLOCKED", "mode": "ROUTE_TABLE_MISSING", "route_state": "missing", "route_eni": "", "web_state": web.get("State", {}).get("Name", "unknown")}
    else:
        nat = classify_nat_route(web, route_table)
    nat_status = preflight_nat_status(nat)
    checks.append(_check(
        "web_nat_route",
        nat_status,
        f"executor_nat_state={nat['status']}, mode={nat['mode']}, default_route={nat['route_state']}, target={nat['route_eni'] or 'none'}, web_state={nat['web_state']}",
        nat_state=nat["status"],
        mode=nat["mode"],
        route_state=nat["route_state"],
        route_eni=nat["route_eni"],
        web_state=nat["web_state"],
    ))

    private_associated = {
        association.get("SubnetId")
        for association in (route_table or {}).get("Associations", [])
        if association.get("SubnetId")
    }
    emr_subnet = by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SubnetId")
    db_subnet = by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SubnetId")
    emr_db_routes_ok = bool(emr_subnet and db_subnet and {emr_subnet, db_subnet}.issubset(private_associated))
    web_subnet = by_id.get("AWS_RESOURCE_ID_REDACTED", {}).get("SubnetId")
    public_table = next((table for table in route_tables if any(item.get("SubnetId") == web_subnet for item in table.get("Associations", []))), None)
    public_default = next((item for item in (public_table or {}).get("Routes", []) if item.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0"), {})
    web_route_ok = bool(web_subnet and public_table and public_table.get("VpcId") == EXPECTED_VPC_ID and public_default.get("State") == "active" and str(public_default.get("GatewayId", "")).startswith("igw-"))
    checks.append(_check(
        "subnet_route_associations",
        "PASS" if emr_db_routes_ok and web_route_ok else "BLOCKED",
        "EMR/DB subnets use the private route table and Web subnet has the public IGW route" if emr_db_routes_ok and web_route_ok else "Web/EMR/DB route-table association contract is incomplete or mismatched",
        private_route_table_id=EXPECTED_PRIVATE_ROUTE_TABLE,
        private_associated_subnet_ids=sorted(private_associated),
        public_web_route_table_id=(public_table or {}).get("RouteTableId"),
    ))
    return checks


def simulated_permission_status(result: dict[str, Any] | None) -> str:
    if result is None:
        return "UNVERIFIED"
    return "PASS" if result.get("allowed") is True else "BLOCKED"


class AwsReadOnly:
    ALLOWED = {
        ("sts", "get-caller-identity"),
        ("ec2", "describe-instances"),
        ("ec2", "describe-instance-status"),
        ("ec2", "describe-network-interfaces"),
        ("ec2", "describe-subnets"),
        ("ec2", "describe-security-groups"),
        ("ec2", "describe-route-tables"),
        ("ec2", "describe-nat-gateways"),
        ("ec2", "describe-addresses"),
        ("ec2", "describe-vpc-attribute"),
        ("ssm", "describe-instance-information"),
        ("ssm", "describe-parameters"),
        ("ssm", "get-parameter"),
        ("iam", "simulate-principal-policy"),
        ("iam", "get-role"),
        ("iam", "get-instance-profile"),
        ("kms", "describe-key"),
        ("s3api", "list-objects-v2"),
        ("s3api", "head-object"),
        ("s3", "cp"),
    }

    def __init__(self, region: str, runner: Callable[..., tuple[int, str]] | None = None, profile: str = "") -> None:
        if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region):
            raise ValueError("AWS region format is invalid")
        self.region = region
        self.profile = profile
        self.runner = runner or command_result

    def call(self, service: str, action: str, *args: str, timeout: int = AWS_CLI_TIMEOUT_SECONDS) -> tuple[int, str]:
        command = self._command(service, action, args)
        return self.runner(command, timeout=timeout)

    def _command(self, service: str, action: str, args: tuple[str, ...]) -> list[str]:
        if (service, action) not in self.ALLOWED:
            raise ValueError("non-read-only AWS operation was rejected")
        if service == "s3" and action == "cp":
            if len(args) < 2 or not str(args[0]).startswith("s3://") or args[1] != "-" or any(arg.startswith("--") and arg not in {"--only-show-errors"} for arg in args[2:]):
                raise ValueError("only streaming a read-only S3 object to stdout is allowed")
        command = ["aws", "--region", self.region]
        if self.profile:
            command.extend(["--profile", self.profile])
        command.extend([service, action, *args])
        return command

    def diagnostic_call(
        self,
        service: str,
        action: str,
        *args: str,
        timeout: int = AWS_CLI_TIMEOUT_SECONDS,
    ) -> tuple[int, str, str]:
        """Run an allowlisted read and return only a sanitized error category."""
        command = self._command(service, action, args)
        if self.runner is command_result:
            return command_result_diagnostic(command, timeout=timeout)
        rc, output = self.runner(command, timeout=timeout)
        return rc, output, classify_aws_cli_failure(rc, "")

    def diagnostic_json_call(
        self,
        service: str,
        action: str,
        *args: str,
        timeout: int = AWS_CLI_TIMEOUT_SECONDS,
    ) -> tuple[str, dict[str, Any] | None]:
        rc, output, status = self.diagnostic_call(service, action, *args, "--output", "json", timeout=timeout)
        if rc != 0:
            return status, None
        try:
            decoded = json.loads(output)
        except (ValueError, TypeError, json.JSONDecodeError):
            return "InvalidFormat", None
        return ("PASS", decoded) if isinstance(decoded, dict) else ("InvalidFormat", None)

    def json_call(self, service: str, action: str, *args: str, timeout: int = AWS_CLI_TIMEOUT_SECONDS) -> dict[str, Any] | None:
        rc, output = self.call(service, action, *args, "--output", "json", timeout=timeout)
        if rc != 0:
            return None
        try:
            decoded = json.loads(output)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None
        return decoded if isinstance(decoded, dict) else None


def command_result_diagnostic(command: list[str], *, timeout: int = 20) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"
    except (OSError, subprocess.SubprocessError):
        return 127, "", "CommandUnavailable"
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace")
    return result.returncode, stdout, classify_aws_cli_failure(result.returncode, stderr)


def command_result(command: list[str], *, timeout: int = 20) -> tuple[int, str]:
    rc, output, _ = command_result_diagnostic(command, timeout=timeout)
    return rc, output


def _properties(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def local_readonly_checks(
    values: dict[str, str],
    *,
    runner: Callable[..., tuple[int, str]] | None = None,
) -> list[dict[str, Any]]:
    """Read local systemd state and staging metadata without invoking units."""
    run = runner or command_result
    checks: list[dict[str, Any]] = []
    timer_units = (
        "hospital-dr-db-backup.timer",
        "hospital-dr-s3-upload.timer",
    )
    for unit in timer_units:
        rc, output = run(["systemctl", "show", unit, "--property=LoadState", "--property=ActiveState", "--property=LastTriggerUSec", "--property=NextElapseUSecRealtime"], timeout=8)
        props = _properties(output) if rc == 0 else {}
        loaded = props.get("LoadState") == "loaded"
        active = props.get("ActiveState") == "active"
        name = "dump_timer_runtime" if "db-backup" in unit else "s3_upload_timer_runtime"
        checks.append(_check(
            name,
            "UNVERIFIED" if not loaded else "PASS" if active else "BLOCKED",
            "systemd timer is loaded and active" if loaded and active else "systemd timer is missing/unreadable" if not loaded else "systemd timer is not active",
            last_trigger_reported=bool(props.get("LastTriggerUSec")),
            next_trigger_reported=bool(props.get("NextElapseUSecRealtime")),
        ))
    rc, output = run([
        "systemctl", "show", "hospital-dr-s3-upload.service",
        "--property=LoadState", "--property=Result", "--property=ExecMainStatus", "--property=ExecMainExitTimestamp",
    ], timeout=8)
    props = _properties(output) if rc == 0 else {}
    upload_time = parse_timestamp(props.get("ExecMainExitTimestamp"))
    upload_ok = props.get("LoadState") == "loaded" and props.get("Result") == "success" and props.get("ExecMainStatus") == "0" and upload_time is not None
    checks.append(_check(
        "last_s3_upload_service_result",
        "PASS" if upload_ok else "UNVERIFIED" if props.get("LoadState") != "loaded" or not upload_time else "BLOCKED",
        "last uploader service invocation completed successfully" if upload_ok else "last uploader success could not be established from systemd service state",
        last_service_exit_at=upload_time.isoformat().replace("+00:00", "Z") if upload_ok and upload_time else None,
    ))

    directory = Path(values.get("S3_BACKUP_SOURCE_DIR", "/home/cloud/db_backups"))
    try:
        encrypted = sorted(directory.glob("db_backup_*.sql.gz.enc"))
        pairs = []
        for dump_path in encrypted:
            sidecar = dump_path.with_name(dump_path.name.removesuffix(".sql.gz.enc") + ".master_status")
            if dump_path.is_file() and dump_path.stat().st_size > 0 and sidecar.is_file() and sidecar.stat().st_size > 0:
                manifest = dump_path.with_name(dump_path.name.removesuffix(".sql.gz.enc") + ".manifest.json")
                pairs.append((dump_path, sidecar, manifest))
        requested_backup_id = Path(values.get("DR_FAILOVER_DUMP_BACKUP_ID", "").strip()).name
        if requested_backup_id.endswith(".sql.gz.enc"):
            requested_backup_id = requested_backup_id[:-len(".sql.gz.enc")]
        selected = next((pair for pair in pairs if _dump_identity_from_key(pair[0].name)[0] == requested_backup_id), None) if requested_backup_id else (pairs[-1] if pairs else None)
        sidecar_result: dict[str, Any] = {"status": "UNVERIFIED", "format": "UNVERIFIED"}
        sidecar_sha256_status = "UNVERIFIED"
        manifest_status = "LEGACY"
        manifest_result: dict[str, Any] = {}
        ciphertext_sha256_status = "UNVERIFIED"
        if selected:
            dump_path, sidecar, manifest = selected
            if sidecar.stat().st_size > S3_SIDECAR_MAX_BYTES:
                sidecar_result = {"status": "InvalidFormat", "format": "OVERSIZED"}
            else:
                sidecar_text = sidecar.read_text(encoding="utf-8", errors="replace")
                sidecar_result = parse_master_status_sidecar(sidecar_text, dump_path.name)
                expected_sidecar_sha256 = values.get("DR_FAILOVER_DUMP_SIDECAR_SHA256", "").strip().lower()
                sidecar_actual_sha256 = hashlib.sha256(sidecar_text.encode("utf-8", errors="replace")).hexdigest()
                sidecar_sha256_status = (
                    "PASS" if sidecar_actual_sha256 == expected_sidecar_sha256 else "MISMATCH"
                ) if re.fullmatch(r"[0-9a-f]{64}", expected_sidecar_sha256) else "EXPECTED_SHA256_NOT_CONFIGURED"
                if manifest.is_symlink() or dump_path.is_symlink() or sidecar.is_symlink():
                    manifest_status = "InvalidFormat"
                elif manifest.is_file():
                    try:
                        prefix = values.get("S3_BACKUP_PREFIX", "mysql/hospital_db").strip("/")
                        validated = verify_manifest_files(
                            dump_path, sidecar, manifest,
                            expected_sha256=values.get("DR_FAILOVER_DUMP_SHA256", "").strip().lower(),
                            expected_sidecar_sha256=expected_sidecar_sha256,
                            expected_manifest_sha256=values.get("DR_FAILOVER_DUMP_MANIFEST_SHA256", "").strip().lower(),
                            expected_object_prefix=prefix,
                        )
                        manifest_status = "PASS"
                        manifest_result = validated
                        ciphertext_sha256_status = "PASS" if values.get("DR_FAILOVER_DUMP_SHA256") else "MANIFEST_MATCH_UNPINNED"
                    except ManifestError as exc:
                        manifest_status = exc.code
                        ciphertext_sha256_status = exc.code if exc.code in {"CHECKSUM_MISMATCH", "MANIFEST_CHECKSUM_MISMATCH"} else "UNVERIFIED"
                elif manifest.exists():
                    manifest_status = "InvalidFormat"
        if not selected:
            local_pair_status = "BLOCKED" if requested_backup_id and pairs else "UNVERIFIED"
        elif manifest_status != "PASS":
            local_pair_status = "BLOCKED"
        else:
            local_pair_status = "BLOCKED" if sidecar_result["status"] != "PASS" or sidecar_sha256_status == "MISMATCH" else "PASS"
        checks.append(_check(
            "local_backup_pair",
            local_pair_status,
            "selected local dump and sidecar identifiers, timestamp, and coordinates match" if local_pair_status == "PASS" else "selected local backup pair is absent or sidecar metadata/checksum is invalid" if local_pair_status == "BLOCKED" else "no complete local backup pair was confirmed",
            backup_name=selected[0].name if selected else None,
            sidecar_name=selected[1].name if selected else None,
            manifest_name=selected[2].name if selected else None,
            manifest_status=manifest_status,
            sidecar_status=sidecar_result.get("status", "UNVERIFIED"),
            sidecar_format_status=sidecar_result.get("format", "UNVERIFIED"),
            sidecar_sha256_status=sidecar_sha256_status,
            object_pair_identity_status="PASS" if selected else "UNVERIFIED",
            backup_identity_status=sidecar_result.get("backup_identity_status", "UNVERIFIED"),
            sidecar_timestamp_match_status=sidecar_result.get("sidecar_timestamp_match_status", "UNVERIFIED"),
            binlog_coordinate_status=sidecar_result.get("binlog_coordinate_status", "UNVERIFIED"),
            source_binlog_coordinate_status="UNVERIFIED",
            ciphertext_sha256_status=ciphertext_sha256_status,
            manifest_sha256_status="PASS" if manifest_result else "UNVERIFIED",
            data_reference_time_status=manifest_result.get("data_reference_time_status", "UNVERIFIED"),
            data_reference_evidence_present=sidecar_result.get("data_reference_evidence_present", "UNVERIFIED"),
        ))
        if selected and local_pair_status == "PASS":
            checks.append(_check("local_dump_restoreability", "PENDING_LIVE_TEST", "local pair presence does not prove ciphertext checksum, decryption, or successful restore"))
    except OSError:
        checks.append(_check("local_backup_pair", "UNVERIFIED", "local backup directory or sidecar could not be read"))
    return checks


def _instances_from_response(response: dict[str, Any]) -> list[dict[str, Any]]:
    return [instance for reservation in response.get("Reservations", []) for instance in reservation.get("Instances", [])]


def _simulate(
    client: AwsReadOnly,
    principal_arn: str,
    account: str,
    action: str,
    resources: list[str],
    *,
    timeout: int = IAM_SIMULATION_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    response = client.json_call(
        "iam", "simulate-principal-policy",
        "--policy-source-arn", principal_arn,
        "--action-names", action,
        "--resource-arns", *resources,
        timeout=timeout,
    )
    if response is None:
        return None
    results = response.get("EvaluationResults", [])
    if not results:
        return None
    decisions = [str(item.get("EvalDecision", "")).lower() for item in results]
    return {"action": action, "allowed": len(decisions) == len(resources) and all(decision == "allowed" for decision in decisions), "resource_count": len(resources), "decisions": decisions}


def _principal_arn(client: AwsReadOnly, identity: dict[str, Any], supplied: str = "") -> str:
    if supplied:
        if not re.fullmatch(r"arn:aws:iam::\d{12}:(?:role|user)/[A-Za-z0-9+=,.@_/-]+", supplied):
            return ""
        return supplied
    arn = str(identity.get("Arn") or "")
    if arn.startswith("arn:aws:iam::") and re.fullmatch(r"arn:aws:iam::\d{12}:(?:role|user)/[A-Za-z0-9+=,.@_/-]+", arn):
        return arn
    assumed = re.fullmatch(r"arn:aws:sts::(\d{12}):assumed-role/([^/]+)/[^/]+", arn)
    if assumed:
        response = client.json_call("iam", "get-role", "--role-name", assumed.group(2))
        role = response.get("Role", {}) if response else {}
        candidate = str(role.get("Arn") or "")
        if candidate.startswith(f"arn:aws:iam::{assumed.group(1)}:role/"):
            return candidate
    return ""


def _dns_content_class(content: str) -> str:
    if content == ONPREM_TUNNEL:
        return "ONPREM_TUNNEL"
    if content == ONPREM_EMR_IP:
        return "ONPREM_IP"
    if content == EXPECTED_WEB_EIP:
        return "DR_WEB_EIP"
    return "OTHER"


def _cloudflare_readonly(client: AwsReadOnly, values: dict[str, str], web_id: str, emr_id: str) -> list[dict[str, Any]]:
    region = values.get("CF_TOKEN_AWS_REGION", REGION_DEFAULT)
    parameter = values.get("CF_TOKEN_PARAM_NAME", CF_TOKEN_PARAMETER_DEFAULT)
    zone = values.get("CF_ZONE_ID", "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", zone):
        return [_check("cloudflare_dns_live", "UNVERIFIED", "CF_ZONE_ID is missing or invalid; DNS GET was not attempted")]
    if parameter != CF_TOKEN_PARAMETER_DEFAULT:
        return [_check("cloudflare_dns_live", "BLOCKED", "Cloudflare token parameter differs from the approved SSM parameter; DNS GET was not attempted")]
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region):
        return [_check("cloudflare_dns_live", "BLOCKED", "Cloudflare token AWS region is invalid; DNS GET was not attempted")]
    if any(not re.fullmatch(r"[0-9a-fA-F]{32}", record_id) for record_id in (web_id, emr_id)):
        return [_check("cloudflare_dns_live", "BLOCKED", "configured DNS record ID format is invalid; DNS GET was not attempted")]
    secret_response = client.json_call("ssm", "get-parameter", "--name", parameter, "--with-decryption")
    token = ((secret_response or {}).get("Parameter") or {}).get("Value")
    if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(char) < 0x20 or ord(char) == 0x7f for char in token):
        token = ""
        return [_check("cloudflare_dns_live", "BLOCKED", "Cloudflare token could not be loaded from the configured SSM parameter; DNS GET was not attempted")]
    del secret_response
    records: list[dict[str, Any]] = []
    for label, record_id, expected_name in (("web", web_id, values.get("DR_DOMAIN", WEB_DNS_NAME)), ("emr", emr_id, values.get("EMR_DOMAIN", EMR_DNS_NAME))):
        try:
            request = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/zones/{urllib.parse.quote(zone, safe='')}/dns_records/{urllib.parse.quote(record_id, safe='')}",
                method="GET",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read(128 * 1024).decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, UnicodeError, json.JSONDecodeError):
            records.append(_check(f"cloudflare_{label}_record", "UNVERIFIED", "Cloudflare read-only GET failed; response body suppressed"))
            continue
        record = payload.get("result") if isinstance(payload, dict) else None
        valid_identity = (
            isinstance(payload, dict)
            and payload.get("success") is True
            and isinstance(record, dict)
            and record.get("id") == record_id
            and record.get("name") == expected_name
            and record.get("type") in {"A", "CNAME"}
            and isinstance(record.get("content"), str)
            and isinstance(record.get("proxied"), bool)
        )
        content_class = _dns_content_class(str(record.get("content", ""))) if isinstance(record, dict) else "UNKNOWN"
        origin_content_ok = (
            label == "web" and record.get("type") == "CNAME" and content_class == "ONPREM_TUNNEL"
            or label == "emr" and record.get("type") == "A" and content_class == "ONPREM_IP"
        ) if isinstance(record, dict) else False
        valid = bool(valid_identity and origin_content_ok and record.get("proxied") is True)
        records.append(_check(
            f"cloudflare_{label}_record",
            "PASS" if valid else "BLOCKED",
            "record identity and current On-Prem origin content match the approved pre-failover pair" if valid else "record identity, type, proxy, or current On-Prem origin content differs from the approved pre-failover pair",
            record_id_match=bool(valid_identity),
            record_id=record.get("id") if valid_identity else None,
            record_type=record.get("type") if valid_identity else None,
            content_class=content_class,
            proxied=record.get("proxied") if isinstance(record, dict) and valid else None,
        ))
    token = ""
    return records


def live_aws_checks(
    values: dict[str, str],
    *,
    region: str,
    policy_source_arn: str = "",
    skip_iam_simulation: bool = False,
    rpo_evidence: dict[str, Any] | None = None,
    cloudflare_read_only: bool = False,
    runner: Callable[..., tuple[int, str]] | None = None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    client = AwsReadOnly(region, runner=runner, profile=values.get("AWS_PROFILE", ""))
    identity = client.json_call("sts", "get-caller-identity")
    if not identity or not identity.get("Account") or not identity.get("Arn"):
        checks.append(_check("aws_identity", "BLOCKED", "AWS caller identity could not be verified"))
        checks.extend((
            _check("aws_resources", "UNVERIFIED", "AWS resource queries were skipped because caller identity was unavailable"),
            _check("application_health_live", "PENDING_LIVE_TEST", "service health requires an approved live start and non-identifying HTTP checks"),
            _check("cloudflare_dns_live", "UNVERIFIED", "Cloudflare GET was not attempted because AWS identity/SSM access is unavailable"),
            _check("s3_backup_pair", "UNVERIFIED", "S3 inventory was not queried because AWS identity was unavailable"),
        ))
        dump_timer = _text(ROOT, "operations/db/systemd/hospital-dr-db-backup.timer")
        upload_timer = _text(ROOT, "operations/db/systemd/hospital-dr-s3-upload.timer")
        checks.extend(assess_rpo(
            values.get("DB_NR_ENABLED"), rpo_evidence, now=datetime.now(timezone.utc),
            dump_interval_minutes=_parse_dump_interval(dump_timer),
            nominal_upload_offset_minutes=_parse_upload_offset(dump_timer, upload_timer),
        ))
        return checks
    account = str(identity["Account"])
    if not re.fullmatch(r"\d{12}", account):
        checks.append(_check("aws_identity", "BLOCKED", "AWS identity response did not contain a valid account identifier"))
        checks.extend((
            _check("aws_resources", "UNVERIFIED", "AWS resource queries were skipped because account identity was invalid"),
            _check("application_health_live", "PENDING_LIVE_TEST", "service health requires an approved live start and non-identifying HTTP checks"),
            _check("cloudflare_dns_live", "UNVERIFIED", "Cloudflare GET was not attempted because AWS account identity was invalid"),
            _check("s3_backup_pair", "UNVERIFIED", "S3 inventory was not queried because AWS account identity was invalid"),
        ))
        return checks
    checks.append(_check("aws_identity", "PASS", "AWS identity API succeeded; principal value suppressed", account_id_valid=True, region=region))
    # IAM simulations can issue many AWS CLI calls. Treat them as explicit
    # opt-in work: the caller must supply the runtime policy ARN, and the
    # skip flag always overrides it. Never simulate discovered EC2 profiles
    # implicitly when --policy-source-arn was omitted.
    principal = _principal_arn(client, identity, policy_source_arn) if policy_source_arn and not skip_iam_simulation else ""
    iam_simulation_enabled = bool(principal)

    inventory: list[dict[str, Any]] = []
    missing: list[str] = []
    query_unverified: list[str] = []
    for _, (instance_id, _) in EXPECTED_INSTANCES.items():
        response = client.json_call("ec2", "describe-instances", "--instance-ids", instance_id)
        if response is None:
            query_unverified.append(instance_id)
            continue
        found = _instances_from_response(response or {})
        if len(found) != 1:
            missing.append(instance_id)
        else:
            inventory.extend(found)
    plan, reason = validate_instance_inventory(inventory)
    if plan is None:
        checks.append(_check(
            "ec2_identity",
            "UNVERIFIED" if query_unverified else "BLOCKED",
            "one or more EC2 identity queries failed; absence was not inferred" if query_unverified else "expected EC2 resources are missing or do not match the approved identity contract",
            missing_count=len(missing),
            query_failure_count=len(query_unverified),
            reason=reason,
        ))
        checks.append(_check("ec2_network", "UNVERIFIED", "network checks require all three approved EC2 identities and readable describe responses"))
    else:
        summaries = []
        for instance in inventory:
            tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", [])}
            summaries.append({
                "role": tags.get("Name"),
                "instance_id": instance.get("InstanceId"),
                "state": (instance.get("State") or {}).get("Name"),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
                "vpc_id": instance.get("VpcId"),
                "subnet_id": instance.get("SubnetId"),
                "security_group_ids": sorted(group.get("GroupId") for group in instance.get("SecurityGroups", []) if group.get("GroupId")),
                "eni_ids": sorted(eni.get("NetworkInterfaceId") for eni in instance.get("NetworkInterfaces", []) if eni.get("NetworkInterfaceId")),
                "instance_profile_present": bool((instance.get("IamInstanceProfile") or {}).get("Arn")),
            })
        checks.append(_check("ec2_identity", "PASS", reason, instance_count=len(plan), instances=summaries))
        states = {row["instance_id"]: row["state"] for row in plan}
        planned_actions = {row["instance_id"]: row["action"] for row in plan}
        all_stopped = all(state == "stopped" for state in states.values())
        checks.append(_check(
            "ec2_lifecycle",
            "PENDING_LIVE_TEST" if all_stopped or any(state != "running" for state in states.values()) else "PASS",
            "instance states are readable; stopped instances are start candidates only and no start was attempted" if all_stopped else "one or more instances are not running; start readiness is not inferred from EC2 state alone" if any(state != "running" for state in states.values()) else "all approved instances currently report running; application readiness remains separate",
            states=states,
            planned_actions=planned_actions,
            start_action_not_attempted=True,
        ))

        profile_statuses: list[dict[str, Any]] = []
        instance_role_actions = (
            "ssm:UpdateInstanceInformation",
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
        )
        profile_role_cache: dict[str, str | None] = {}
        role_decision_cache: dict[str, list[str]] = {}
        for instance in inventory:
            instance_id = str(instance.get("InstanceId") or "")
            profile_arn = str((instance.get("IamInstanceProfile") or {}).get("Arn") or "")
            profile_name = profile_arn.rsplit("/", 1)[-1] if profile_arn else ""
            if not profile_name:
                profile_statuses.append({"instance_id": instance_id, "status": "BLOCKED", "reason": "instance_profile_missing"})
                continue
            if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,128}", profile_name):
                profile_statuses.append({"instance_id": instance_id, "status": "UNVERIFIED", "reason": "profile_name_invalid"})
                continue
            if not iam_simulation_enabled:
                reason_code = "iam_simulation_skipped" if skip_iam_simulation else "policy_source_arn_missing_or_unresolved"
                profile_statuses.append({"instance_id": instance_id, "status": "UNVERIFIED", "reason": reason_code})
                continue
            if profile_arn not in profile_role_cache:
                profile_response = client.json_call("iam", "get-instance-profile", "--instance-profile-name", profile_name)
                roles = ((profile_response or {}).get("InstanceProfile") or {}).get("Roles", [])
                role = roles[0] if len(roles) == 1 else {}
                role_arn = str(role.get("Arn") or "")
                profile_role_cache[profile_arn] = role_arn or None
            role_arn = profile_role_cache[profile_arn]
            if not role_arn:
                profile_statuses.append({"instance_id": instance_id, "status": "UNVERIFIED", "reason": "profile_role_unreadable"})
                continue
            if role_arn not in role_decision_cache:
                role_decision_cache[role_arn] = [
                    simulated_permission_status(_simulate(client, role_arn, account, action, ["*"]))
                    for action in instance_role_actions
                ]
            role_decisions = role_decision_cache[role_arn]
            profile_statuses.append({
                "instance_id": instance_id,
                "status": "PASS" if all(item == "PASS" for item in role_decisions) else "BLOCKED" if any(item == "BLOCKED" for item in role_decisions) else "UNVERIFIED",
                "ssm_agent_actions": role_decisions,
            })
        profile_rollup = "PASS" if len(profile_statuses) == 3 and all(item["status"] == "PASS" for item in profile_statuses) else "BLOCKED" if any(item["status"] == "BLOCKED" for item in profile_statuses) else "UNVERIFIED"
        profile_detail = "IAM simulations were explicitly skipped; SSM Online status remains independently checked" if skip_iam_simulation else "IAM simulation was not opted into with a resolvable --policy-source-arn; SSM Online status remains independently checked" if not iam_simulation_enabled else "EC2 instance-profile presence and SSM Agent channel permissions were checked read-only; SSM Online status remains separately checked"
        checks.append(_check("instance_profile_ssm_iam", profile_rollup, profile_detail, roles=profile_statuses))

        eni_ids = sorted({eni.get("NetworkInterfaceId") for instance in inventory for eni in instance.get("NetworkInterfaces", []) if eni.get("NetworkInterfaceId")})
        subnet_ids = sorted({instance.get("SubnetId") for instance in inventory if instance.get("SubnetId")})
        sg_ids = sorted({group.get("GroupId") for instance in inventory for group in instance.get("SecurityGroups", []) if group.get("GroupId")})
        eni_resp = client.json_call("ec2", "describe-network-interfaces", "--network-interface-ids", *eni_ids) if eni_ids else None
        subnet_resp = client.json_call("ec2", "describe-subnets", "--subnet-ids", *subnet_ids) if subnet_ids else None
        sg_resp = client.json_call("ec2", "describe-security-groups", "--group-ids", *sg_ids) if sg_ids else None
        route_resp = client.json_call("ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={EXPECTED_VPC_ID}")
        if not all((eni_resp, subnet_resp, sg_resp, route_resp)):
            checks.append(_check("ec2_network", "UNVERIFIED", "one or more read-only ENI/subnet/security-group/route-table queries failed"))
        else:
            checks.extend(validate_network_snapshot(
                inventory,
                eni_resp.get("NetworkInterfaces", []),
                subnet_resp.get("Subnets", []),
                sg_resp.get("SecurityGroups", []),
                route_resp.get("RouteTables", []),
                cloudflare_cidrs=configured_cloudflare_cidrs(ROOT, values),
            ))
        running_ids = sorted(instance_id for instance_id, state in states.items() if state == "running")
        status_resp = client.json_call(
            "ssm", "describe-instance-information",
            "--filters", f"Key=InstanceIds,Values={','.join(running_ids)}",
        ) if running_ids else {}
        if not running_ids:
            checks.append(_check("ssm_managed_instances", "PENDING_LIVE_TEST", "all approved instances are stopped; SSM Online is not required until an approved start"))
        elif status_resp is None:
            checks.append(_check("ssm_managed_instances", "UNVERIFIED", "SSM managed-instance status could not be read"))
        else:
            ssm_online = {item.get("InstanceId") for item in status_resp.get("InstanceInformationList", []) if item.get("PingStatus") == "Online"}
            running_online = set(running_ids).issubset(ssm_online)
            stopped_pending = len(running_ids) != len(states)
            status = "BLOCKED" if not running_online else "PENDING_LIVE_TEST" if stopped_pending else "PASS"
            detail = "one or more running instances are not SSM Online" if not running_online else "running instances are SSM Online; stopped instances still require post-start validation" if stopped_pending else "all approved running instances are SSM Online"
            checks.append(_check("ssm_managed_instances", status, detail, running_instance_count=len(running_ids), stopped_instance_count=len(states) - len(running_ids)))

        running_inventory = sorted(instance_id for instance_id, state in states.items() if state == "running")
        if not running_inventory:
            checks.append(_check("ec2_status_checks", "PENDING_LIVE_TEST", "stopped instances have no current EC2 instance status checks"))
        else:
            health_response = client.json_call(
                "ec2", "describe-instance-status",
                "--instance-ids", *running_inventory,
                "--include-all-instances",
            )
            rows = (health_response or {}).get("InstanceStatuses", [])
            healthy = {
                item.get("InstanceId") for item in rows
                if item.get("InstanceStatus", {}).get("Status") == "ok"
                and item.get("SystemStatus", {}).get("Status") == "ok"
            }
            if health_response is None:
                status, detail = "UNVERIFIED", "read-only EC2 instance status query failed"
            elif not set(running_inventory).issubset(healthy):
                status, detail = "BLOCKED", "one or more running instances lack both EC2 status checks"
            elif len(running_inventory) != len(states):
                status, detail = "PENDING_LIVE_TEST", "running instances pass EC2 checks; stopped instances remain untested"
            else:
                status, detail = "PASS", "all approved running instances pass both EC2 status checks"
            checks.append(_check("ec2_status_checks", status, detail, checked_running_instance_count=len(running_inventory)))
        checks.append(_check("application_health_live", "PENDING_LIVE_TEST", "service HTTP checks are not inferred from EC2/SSM state; run the approved non-identifying checks after service start"))

        route_tables = (route_resp or {}).get("RouteTables", [])
        route = next((item for item in route_tables if item.get("RouteTableId") == EXPECTED_PRIVATE_ROUTE_TABLE), None)
        web = next((item for item in inventory if item.get("InstanceId") == "AWS_RESOURCE_ID_REDACTED"), {})
        nat = classify_nat_route(web, route or {}) if route else {"status": "BLOCKED", "mode": "ROUTE_TABLE_MISSING", "route_state": "missing", "route_eni": "", "web_state": (web.get("State") or {}).get("Name", "unknown")}
        checks.append(_check(
            "nat_readiness",
            preflight_nat_status(nat),
            f"executor_nat_state={nat['status']}; mode={nat['mode']}; route={nat['route_state']}; Web={nat['web_state']}; no route or ENI changes were made",
            nat_state=nat["status"],
            mode=nat["mode"],
            route_state=nat["route_state"],
            route_eni=nat["route_eni"],
            web_state=nat["web_state"],
        ))

        web_eip_response = client.json_call("ec2", "describe-addresses", "--public-ips", EXPECTED_WEB_EIP)
        nat_eip_response = client.json_call("ec2", "describe-addresses", "--allocation-ids", EXPECTED_NAT_EIP_ALLOCATION)
        web_addresses = (web_eip_response or {}).get("Addresses", [])
        nat_addresses = (nat_eip_response or {}).get("Addresses", [])
        web_addr = web_addresses[0] if len(web_addresses) == 1 else {}
        nat_addr = nat_addresses[0] if len(nat_addresses) == 1 else {}
        expected_web_eni_ids = {eni.get("NetworkInterfaceId") for eni in web.get("NetworkInterfaces", [])}
        web_eip_ok = bool(
            web_addr.get("PublicIp") == EXPECTED_WEB_EIP
            and web_addr.get("InstanceId") == "AWS_RESOURCE_ID_REDACTED"
            and web_addr.get("NetworkInterfaceId") in expected_web_eni_ids
            and web_addr.get("AssociationId")
        )
        checks.append(_check("web_eip_association", "UNVERIFIED" if web_eip_response is None else "PASS" if web_eip_ok else "BLOCKED", "approved Web EIP is associated with the approved Web instance/ENI" if web_eip_ok else "approved Web EIP association is missing or mismatched"))
        nat_tag_map = {tag.get("Key"): tag.get("Value") for tag in nat_addr.get("Tags", [])}
        nat_eip_ok = bool(
            nat_addr.get("AllocationId") == EXPECTED_NAT_EIP_ALLOCATION
            and nat_addr.get("PublicIp") == EXPECTED_NAT_EIP
            and nat_tag_map.get("Purpose") == "MySQL-NR-Egress"
            and str(nat_tag_map.get("Preserve", "")).lower() == "true"
            and not nat_addr.get("AssociationId")
            and not nat_addr.get("InstanceId")
        )
        checks.append(_check("preserved_nr_nat_eip", "UNVERIFIED" if nat_eip_response is None else "PASS" if nat_eip_ok else "BLOCKED", "reserved MySQL-NR EIP identity and Preserve=true tag match; no EIP mutation was performed" if nat_eip_ok else "preserved MySQL-NR EIP is missing, associated, or does not match the preservation contract"))

        nat_gateway_response = client.json_call("ec2", "describe-nat-gateways", "--nat-gateway-ids", EXPECTED_NAT_GATEWAY)
        nat_gateways = (nat_gateway_response or {}).get("NatGateways", [])
        nat_gateway = nat_gateways[0] if len(nat_gateways) == 1 else {}
        route_default = next((item for item in (route or {}).get("Routes", []) if item.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0"), {})
        nat_gateway_not_used = route_default.get("NetworkInterfaceId") == EXPECTED_WEB_ENI
        nat_gateway_status = "UNVERIFIED" if nat_gateway_response is None else "DISABLED" if nat_gateway_not_used and not nat_gateway else "PASS" if nat_gateway.get("NatGatewayId") == EXPECTED_NAT_GATEWAY else "BLOCKED"
        nat_gateway_detail = "Web NAT Instance is the active route target; a separate NAT Gateway is not required" if nat_gateway_not_used and not nat_gateway else "expected NAT Gateway is present as an inventory reference; active Failover still requires Web NAT Instance mode" if nat_gateway.get("NatGatewayId") == EXPECTED_NAT_GATEWAY else "NAT Gateway query failed or an unexpected reference is present"
        checks.append(_check("nat_gateway_reference", nat_gateway_status, nat_gateway_detail))

        dns_support = client.json_call("ec2", "describe-vpc-attribute", "--vpc-id", EXPECTED_VPC_ID, "--attribute", "enableDnsSupport")
        dns_hostnames = client.json_call("ec2", "describe-vpc-attribute", "--vpc-id", EXPECTED_VPC_ID, "--attribute", "enableDnsHostnames")
        dns_vpc_ok = bool((dns_support or {}).get("EnableDnsSupport", {}).get("Value") is True and (dns_hostnames or {}).get("EnableDnsHostnames", {}).get("Value") is True)
        checks.append(_check("vpc_dns", "UNVERIFIED" if dns_support is None or dns_hostnames is None else "PASS" if dns_vpc_ok else "BLOCKED", "VPC DNS support and hostnames are enabled" if dns_vpc_ok else "VPC DNS attributes are disabled or unreadable"))

    # Read-only executor policy evaluation. IAM simulation failures are
    # UNVERIFIED; they never grant permissions or change policy.
    # The operator's current AWS principal is not necessarily the service role
    # used by the Failover executor. Never substitute caller permissions.
    if skip_iam_simulation:
        checks.append(_check("executor_iam", "UNVERIFIED", "IAM simulations were explicitly skipped; executor permissions are not treated as verified"))
    elif not principal:
        principal_reason = "--policy-source-arn is missing or could not be resolved; operator permissions are not treated as executor permissions"
        checks.append(_check("executor_iam", "UNVERIFIED", principal_reason))
    else:
        instance_arns = [f"arn:aws:ec2:{region}:{account}:instance/{instance_id}" for instance_id, _ in EXPECTED_INSTANCES.values()]
        required = [
            ("ec2:DescribeInstances", ["*"]),
            ("ec2:DescribeInstanceStatus", ["*"]),
            ("ec2:DescribeNetworkInterfaces", ["*"]),
            ("ec2:DescribeSubnets", ["*"]),
            ("ec2:DescribeSecurityGroups", ["*"]),
            ("ec2:DescribeRouteTables", ["*"]),
            ("ec2:DescribeAddresses", ["*"]),
            ("ec2:DescribeNatGateways", ["*"]),
            ("ec2:DescribeVpcAttribute", ["*"]),
            ("ec2:StartInstances", instance_arns),
            ("sts:GetCallerIdentity", ["*"]),
            ("ssm:DescribeInstanceInformation", ["*"]),
            ("ssm:StartSession", instance_arns),
        ]
        required.append(("ssm:StartSession", [f"arn:aws:ssm:{region}::document/AWS-StartSSHSession"]))
        bucket_for_policy = values.get("S3_BACKUP_BUCKET", "")
        if bucket_for_policy:
            prefix_for_policy = values.get("S3_BACKUP_PREFIX", "mysql/hospital_db").strip("/")
            required.extend((
                ("s3:ListBucket", [f"arn:aws:s3:::{bucket_for_policy}"]),
                ("s3:GetObject", [f"arn:aws:s3:::{bucket_for_policy}/{prefix_for_policy}/*"]),
            ))
        permissions: list[dict[str, Any]] = []
        for action, resources in required:
            result = _simulate(client, principal, account, action, resources)
            if result is None:
                permissions.append({"action": action, "status": "UNVERIFIED"})
            else:
                permissions.append({"action": action, "status": simulated_permission_status(result), "resource_count": result["resource_count"]})
        checks.append(_check("executor_iam", "PASS" if all(item["status"] == "PASS" for item in permissions) else "BLOCKED" if any(item["status"] == "BLOCKED" for item in permissions) else "UNVERIFIED", "IAM policy simulation results are advisory and do not prove service/runtime health", permissions=permissions))

    parameter_name = values.get("CF_TOKEN_PARAM_NAME", CF_TOKEN_PARAMETER_DEFAULT)
    parameter_region = values.get("CF_TOKEN_AWS_REGION", REGION_DEFAULT)
    parameter_client: AwsReadOnly | None = None
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", parameter_region):
        checks.append(_check("cloudflare_ssm_parameter", "BLOCKED", "Cloudflare token AWS region is invalid; SSM metadata query was not attempted"))
        checks.append(_check("cloudflare_ssm_permission", "UNVERIFIED", "SSM permission could not be simulated because the parameter region is invalid"))
    else:
        parameter_client = AwsReadOnly(parameter_region, runner=runner, profile=values.get("AWS_PROFILE", ""))
        parameter_response = parameter_client.json_call("ssm", "describe-parameters", "--parameter-filters", f"Key=Name,Option=Equals,Values={parameter_name}")
        metadata = (parameter_response or {}).get("Parameters", [])
        parameter = next((item for item in metadata if item.get("Name") == parameter_name), None)
        if parameter is None:
            checks.append(_check("cloudflare_ssm_parameter", "UNVERIFIED" if parameter_response is None else "BLOCKED", "configured Cloudflare SSM parameter metadata is unavailable or absent; no parameter value was read"))
        else:
            checks.append(_check("cloudflare_ssm_parameter", "PASS", "configured SSM parameter exists; value was not read", parameter_type=parameter.get("Type", "UNKNOWN"), key_managed=bool(parameter.get("KeyId"))))
            if skip_iam_simulation:
                checks.append(_check("cloudflare_ssm_permission", "UNVERIFIED", "IAM simulation was explicitly skipped; GetParameter permission is not treated as verified"))
                if parameter.get("Type") == "SecureString" or parameter.get("KeyId"):
                    checks.append(_check("cloudflare_kms_permission", "UNVERIFIED", "IAM simulation was explicitly skipped; KMS decrypt permission is not treated as verified"))
            elif principal:
                parameter_arn = str(parameter.get("ARN") or f"arn:aws:ssm:{parameter_region}:{account}:parameter{parameter_name}")
                result = _simulate(client, principal, account, "ssm:GetParameter", [parameter_arn])
                checks.append(_check("cloudflare_ssm_permission", simulated_permission_status(result), "GetParameter permission was simulated without retrieving the value"))
                key_id = str(parameter.get("KeyId") or "")
                if key_id:
                    key_response = client.json_call("kms", "describe-key", "--key-id", key_id)
                    key_arn = str(((key_response or {}).get("KeyMetadata") or {}).get("Arn") or (key_id if key_id.startswith("arn:") else ""))
                    decrypt = _simulate(client, principal, account, "kms:Decrypt", [key_arn]) if key_arn and principal else None
                    checks.append(_check("cloudflare_kms_permission", simulated_permission_status(decrypt), "KMS decrypt permission was simulated against the parameter key; no decrypt operation was called"))
                elif parameter.get("Type") == "SecureString":
                    checks.append(_check("cloudflare_kms_permission", "UNVERIFIED", "SecureString parameter metadata did not identify its KMS key; decryption permission was not inferred"))
            else:
                checks.append(_check("cloudflare_ssm_permission", "UNVERIFIED", "runtime IAM principal was not resolved for simulation; operator access is not substituted"))
                if parameter.get("Type") == "SecureString":
                    checks.append(_check("cloudflare_kms_permission", "UNVERIFIED", "SecureString decryption permission for the actual runtime principal was not simulated"))
    if cloudflare_read_only and parameter_client is not None:
        web_id, emr_id = _dns_ids(values)["web"], _dns_ids(values)["emr"]
        checks.extend(_cloudflare_readonly(parameter_client, values, web_id, emr_id))
    elif cloudflare_read_only:
        checks.append(_check("cloudflare_dns_live", "BLOCKED", "Cloudflare token AWS region is invalid; DNS GET was not attempted"))
    else:
        checks.append(_check("cloudflare_dns_live", "UNVERIFIED", "Cloudflare DNS GET was not requested; existing snapshot/readback/rollback code contract was checked offline"))

    # Read-only S3 inspection: only a small .master_status object is streamed
    # in memory. The encrypted database payload is never downloaded here.
    bucket = values.get("S3_BACKUP_BUCKET", "")
    if not bucket:
        checks.append(_check(
            "s3_backup_pair", "UNVERIFIED", "S3_BACKUP_BUCKET is not configured in the supplied safe config",
            s3_list_status="UNVERIFIED", dump_head_status="NOT_CHECKED", sidecar_head_status="NOT_CHECKED",
            sidecar_get_status="NOT_CHECKED", sidecar_format_status="UNVERIFIED",
            source_binlog_coordinate_status="UNVERIFIED", ciphertext_sha256_status="UNVERIFIED",
            data_reference_time_status="UNVERIFIED",
        ))
    else:
        s3_profile = values.get("S3_BACKUP_AWS_PROFILE") or values.get("AWS_PROFILE", "")
        s3_client = AwsReadOnly(region, runner=runner, profile=s3_profile)
        prefix = values.get("S3_BACKUP_PREFIX", "mysql/hospital_db").strip("/")
        s3_list_status, s3_response = s3_client.diagnostic_json_call(
            "s3api", "list-objects-v2", "--bucket", bucket, "--prefix", f"{prefix}/",
            timeout=S3_LIST_TIMEOUT_SECONDS,
        )
        if s3_response is None:
            outer_status = "BLOCKED" if s3_list_status in {"AccessDenied", "ObjectMissing"} else "UNVERIFIED"
            checks.append(_check(
                "s3_backup_pair", outer_status,
                "S3 ListBucket was denied" if s3_list_status == "AccessDenied" else "configured bucket/prefix is absent" if s3_list_status == "ObjectMissing" else "S3 read-only listing could not be verified",
                s3_list_status=s3_list_status, dump_head_status="NOT_CHECKED", sidecar_head_status="NOT_CHECKED",
                sidecar_get_status="NOT_CHECKED", sidecar_exists_status="UNVERIFIED",
                sidecar_format_status="UNVERIFIED", backup_identity_status="UNVERIFIED",
                binlog_coordinate_status="UNVERIFIED", source_binlog_coordinate_status="UNVERIFIED",
                ciphertext_sha256_status="UNVERIFIED", data_reference_time_status="UNVERIFIED",
            ))
        else:
            objects = s3_response.get("Contents", [])
            if not isinstance(objects, list) or any(not isinstance(item, dict) for item in objects):
                s3_list_status = "InvalidFormat"
                objects = []
            by_key = {str(item.get("Key")): item for item in objects if item.get("Key")}
            pairs = []
            for item in objects:
                key = str(item.get("Key", ""))
                suffix = ".sql.gz.enc"
                if not key.endswith(suffix):
                    continue
                sidecar = key[:-len(suffix)] + ".master_status"
                if sidecar in by_key and int(item.get("Size", 0) or 0) > 0 and int(by_key[sidecar].get("Size", 0) or 0) > 0:
                    manifest = key[:-len(suffix)] + ".manifest.json"
                    times = [parse_timestamp(item.get("LastModified")), parse_timestamp(by_key[sidecar].get("LastModified"))]
                    if manifest in by_key:
                        times.append(parse_timestamp(by_key[manifest].get("LastModified")))
                    valid_times = [stamp for stamp in times if stamp]
                    pairs.append((max(valid_times) if valid_times else None, key, sidecar, manifest if manifest in by_key else ""))
            pairs.sort(key=lambda row: row[0] or datetime.min.replace(tzinfo=timezone.utc))
            requested_backup_id = Path(values.get("DR_FAILOVER_DUMP_BACKUP_ID", "").strip()).name
            if requested_backup_id.endswith(".sql.gz.enc"):
                requested_backup_id = requested_backup_id[:-len(".sql.gz.enc")]
            if requested_backup_id:
                selected = next((row for row in pairs if _dump_identity_from_key(row[1])[0] == requested_backup_id), None)
                selection_missing = selected is None
                selected = selected or (None, "", "", "")
            else:
                selection_missing = not pairs
                selected = pairs[-1] if pairs else (None, "", "", "")
            latest_upload, latest_key, latest_sidecar, latest_manifest = selected
            latest_objects = by_key if latest_key else {}
            dump_list_obj = latest_objects.get(latest_key, {})
            sidecar_list_obj = latest_objects.get(latest_sidecar, {})
            manifest_list_obj = latest_objects.get(latest_manifest, {}) if latest_manifest else {}
            dump_head_status = sidecar_head_status = manifest_head_status = "NOT_CHECKED"
            sidecar_get_status = manifest_get_status = "NOT_CHECKED"
            dump_head: dict[str, Any] | None = None
            sidecar_head: dict[str, Any] | None = None
            manifest_head: dict[str, Any] | None = None
            parsed_sidecar: dict[str, Any] = {"status": "UNVERIFIED", "format": "UNKNOWN"}
            parsed_manifest: dict[str, Any] | None = None
            manifest_validation_status = "LEGACY" if latest_key and not latest_manifest else "UNVERIFIED"
            sidecar_rc = manifest_rc = -1
            sidecar_text = ""
            manifest_text = ""
            if latest_sidecar:
                # The executor profile is deliberately used here: a separate
                # uploader's ListBucket access must not imply restore GetObject access.
                dump_head_status, dump_head = client.diagnostic_json_call(
                    "s3api", "head-object", "--bucket", bucket, "--key", latest_key,
                )
                sidecar_head_status, sidecar_head = client.diagnostic_json_call(
                    "s3api", "head-object", "--bucket", bucket, "--key", latest_sidecar,
                )
                if latest_manifest:
                    manifest_head_status, manifest_head = client.diagnostic_json_call(
                        "s3api", "head-object", "--bucket", bucket, "--key", latest_manifest,
                    )
                if int(sidecar_list_obj.get("Size", 0) or 0) > S3_SIDECAR_MAX_BYTES:
                    sidecar_get_status = "InvalidFormat"
                    parsed_sidecar = {"status": "InvalidFormat", "format": "OVERSIZED"}
                elif sidecar_head and int(sidecar_head.get("ContentLength", -1)) != int(sidecar_list_obj.get("Size", -2)):
                    sidecar_get_status = "SchemaMismatch"
                    parsed_sidecar = {"status": "SchemaMismatch", "format": "OBJECT_SIZE_CHANGED"}
                else:
                    sidecar_rc, sidecar_text, sidecar_get_status = client.diagnostic_call(
                        "s3", "cp", f"s3://{bucket}/{latest_sidecar}", "-", "--only-show-errors",
                        timeout=S3_OBJECT_TIMEOUT_SECONDS,
                    )
                    if sidecar_rc == 0:
                        parsed_sidecar = parse_master_status_sidecar(sidecar_text, latest_key)
                        if parsed_sidecar["status"] == "PASS" and len(sidecar_text.encode("utf-8", errors="replace")) != int(sidecar_list_obj.get("Size", -1)):
                            parsed_sidecar = {"status": "SchemaMismatch", "format": parsed_sidecar.get("format", "UNKNOWN")}
                if latest_manifest:
                    manifest_size = int(manifest_list_obj.get("Size", 0) or 0)
                    if manifest_size <= 0 or manifest_size > 64 * 1024:
                        manifest_get_status = "InvalidFormat"
                    elif manifest_head and int(manifest_head.get("ContentLength", -1)) != manifest_size:
                        manifest_get_status = "SchemaMismatch"
                    else:
                        manifest_rc, manifest_text, manifest_get_status = client.diagnostic_call(
                            "s3", "cp", f"s3://{bucket}/{latest_manifest}", "-", "--only-show-errors",
                            timeout=S3_OBJECT_TIMEOUT_SECONDS,
                        )
                        if manifest_rc == 0 and len(manifest_text.encode("utf-8", errors="replace")) != manifest_size:
                            manifest_get_status = "SchemaMismatch"
                        elif manifest_rc == 0:
                            try:
                                manifest_doc = parse_manifest_text(manifest_text)
                                parsed_manifest = manifest_doc
                                prefix_for_key = prefix
                                validated_manifest = validate_manifest_sidecar_content(
                                    manifest_doc,
                                    backup_id=Path(latest_key).name,
                                    dump_key=latest_key,
                                    sidecar_key=latest_sidecar,
                                    manifest_key=latest_manifest,
                                    sidecar_content=sidecar_text,
                                    dump_size=int(dump_list_obj.get("Size", 0) or 0),
                                    sidecar_size=int(sidecar_list_obj.get("Size", 0) or 0),
                                    expected_sha256=values.get("DR_FAILOVER_DUMP_SHA256", "").strip().lower(),
                                    expected_sidecar_sha256=values.get("DR_FAILOVER_DUMP_SIDECAR_SHA256", "").strip().lower(),
                                )
                                if any(str(Path(key).parent) != prefix_for_key for key in (latest_key, latest_sidecar, latest_manifest)):
                                    raise ManifestError("MANIFEST_OBJECT_PREFIX_MISMATCH")
                                parsed_manifest = {**validated_manifest, "format": "JSON"}
                                manifest_validation_status = "PASS"
                            except (ValueError, TypeError, ManifestError):
                                manifest_validation_status = "SchemaMismatch"
                                manifest_get_status = "InvalidFormat" if not parsed_manifest else "SchemaMismatch"
            sidecar_status = parsed_sidecar.get("status", "UNVERIFIED") if sidecar_get_status == "PASS" else sidecar_get_status
            if sidecar_get_status == "PASS" and sidecar_status not in {"PASS", "MissingBinlogCoordinates", "InvalidFormat", "SchemaMismatch"}:
                sidecar_status = "UNVERIFIED"
            if selection_missing or not latest_key:
                pair_status = "BLOCKED"
                sidecar_status = "InvalidFormat" if s3_list_status == "InvalidFormat" else "ObjectMissing"
            elif not latest_manifest:
                pair_status = "BLOCKED"
                manifest_validation_status = "LEGACY"
            elif sidecar_status in {"AccessDenied", "ObjectMissing", "InvalidFormat", "SchemaMismatch", "MissingBinlogCoordinates"}:
                pair_status = "BLOCKED"
            elif manifest_validation_status in {"InvalidFormat", "SchemaMismatch", "MANIFEST_OBJECT_PREFIX_MISMATCH"} or manifest_get_status in {"AccessDenied", "ObjectMissing", "InvalidFormat", "SchemaMismatch"} or manifest_head_status in {"AccessDenied", "ObjectMissing"}:
                pair_status = "BLOCKED"
                manifest_validation_status = manifest_get_status if manifest_get_status != "PASS" else manifest_head_status
            elif dump_head_status in {"AccessDenied", "ObjectMissing"} or sidecar_head_status in {"AccessDenied", "ObjectMissing"}:
                pair_status = "BLOCKED"
                if sidecar_get_status != "PASS":
                    sidecar_status = sidecar_get_status
            elif dump_head_status != "PASS" or sidecar_head_status != "PASS" or manifest_head_status != "PASS" or sidecar_status != "PASS" or manifest_validation_status != "PASS":
                pair_status = "UNVERIFIED"
            else:
                # This read-only inventory does not fetch dump payload bytes;
                # a manifest hash claim is not substituted for recomputation.
                pair_status = "UNVERIFIED"
            expected_sha256 = values.get("DR_FAILOVER_DUMP_SHA256", "").strip().lower()
            valid_expected_sha256 = bool(re.fullmatch(r"[0-9a-f]{64}", expected_sha256))
            s3_checksum = str((dump_head or {}).get("ChecksumSHA256") or "")
            # HeadObject's ETag is not a SHA-256 digest. No payload is fetched
            # to calculate one; the executor must verify the configured digest.
            ciphertext_sha256_status = "UNVERIFIED"
            if dump_head_status == "AccessDenied":
                ciphertext_sha256_status = "AccessDenied"
            elif dump_head_status == "ObjectMissing":
                ciphertext_sha256_status = "ObjectMissing"
            elif not valid_expected_sha256:
                ciphertext_sha256_status = "EXPECTED_SHA256_NOT_CONFIGURED"
            elif s3_checksum:
                try:
                    checksum_hex = base64.b64decode(s3_checksum, validate=True).hex()
                except (ValueError, TypeError):
                    checksum_hex = ""
                ciphertext_sha256_status = "PASS" if checksum_hex == expected_sha256 else "MISMATCH" if checksum_hex else "UNVERIFIED"
            elif dump_head_status == "PASS":
                ciphertext_sha256_status = "S3_CHECKSUM_NOT_EXPOSED_BY_HEAD_OBJECT"
            sidecar_expected_sha256 = values.get("DR_FAILOVER_DUMP_SIDECAR_SHA256", "").strip().lower()
            if sidecar_rc == 0:
                sidecar_actual_sha256 = hashlib.sha256(sidecar_text.encode("utf-8", errors="replace")).hexdigest()
                if parsed_manifest and sidecar_actual_sha256 == parsed_manifest.get("sidecar_sha256"):
                    sidecar_sha256_status = "PASS"
                elif parsed_manifest:
                    sidecar_sha256_status = "MISMATCH"
                else:
                    sidecar_sha256_status = (
                        "PASS" if sidecar_actual_sha256 == sidecar_expected_sha256 else "MISMATCH"
                    ) if re.fullmatch(r"[0-9a-f]{64}", sidecar_expected_sha256) else "EXPECTED_SHA256_NOT_CONFIGURED"
            else:
                sidecar_sha256_status = sidecar_get_status
            manifest_sha256_status = "UNVERIFIED"
            if manifest_rc == 0:
                manifest_expected_sha = values.get("DR_FAILOVER_DUMP_MANIFEST_SHA256", "").strip().lower()
                manifest_sha = hashlib.sha256(manifest_text.encode("utf-8", errors="replace")).hexdigest()
                manifest_sha256_status = (
                    "PASS" if manifest_sha == manifest_expected_sha else "MISMATCH"
                ) if re.fullmatch(r"[0-9a-f]{64}", manifest_expected_sha) else "EXPECTED_SHA256_NOT_CONFIGURED"
            if ciphertext_sha256_status == "MISMATCH" or sidecar_sha256_status == "MISMATCH":
                pair_status = "BLOCKED"
            if sidecar_status in {"AccessDenied", "ObjectMissing", "InvalidFormat", "SchemaMismatch", "MissingBinlogCoordinates"}:
                pair_status = "BLOCKED"
            sidecar_timestamp = parsed_sidecar.get("backup_timestamp")
            checks.append(_check(
                "s3_backup_pair",
                pair_status,
                "selected encrypted dump and matching sidecar are listed, readable, and sidecar identity/coordinates match" if pair_status == "PASS" else "S3 ListObjects response has an invalid structure" if s3_list_status == "InvalidFormat" else "configured backup ID has no complete S3 dump/sidecar pair" if selection_missing else "S3 pair exists but restore-role read, sidecar schema, identity, or coordinates are blocked/unverified",
                s3_list_status=s3_list_status,
                dump_head_status=dump_head_status,
                sidecar_head_status=sidecar_head_status,
                sidecar_get_status=sidecar_get_status,
                manifest_head_status=manifest_head_status,
                manifest_get_status=manifest_get_status,
                manifest_status=manifest_validation_status,
                manifest_sha256_status=manifest_sha256_status,
                sidecar_exists_status="PASS" if latest_sidecar else "ObjectMissing",
                latest_pair_name=Path(latest_key).name if latest_key else None,
                latest_sidecar_name=Path(latest_sidecar).name if latest_sidecar else None,
                s3_last_modified_upload_time=latest_upload.isoformat().replace("+00:00", "Z") if latest_upload else None,
                sidecar_status=sidecar_status,
                recorded_backup_start_timestamp=sidecar_timestamp,
                sidecar_format_status=parsed_sidecar.get("format", "UNVERIFIED") if sidecar_get_status == "PASS" else "UNVERIFIED",
                backup_identity_status=parsed_sidecar.get("backup_identity_status", "UNVERIFIED"),
                object_pair_identity_status="PASS" if latest_sidecar else "UNVERIFIED",
                sidecar_timestamp_match_status=parsed_sidecar.get("sidecar_timestamp_match_status", "UNVERIFIED"),
                binlog_coordinate_status=parsed_sidecar.get("binlog_coordinate_status", "UNVERIFIED"),
                sidecar_binlog_coordinate_present=parsed_sidecar.get("binlog_coordinate_status") == "PASS",
                source_binlog_coordinate_status="UNVERIFIED",
                ciphertext_sha256_status=ciphertext_sha256_status,
                sidecar_sha256_status=sidecar_sha256_status,
                expected_ciphertext_sha256_configured=valid_expected_sha256,
                s3_checksum_metadata_available=bool(s3_checksum),
                decryptability_status="PENDING_LIVE_TEST" if pair_status == "PASS" else "UNVERIFIED",
                dump_object_size=int(dump_list_obj.get("Size", 0) or 0) if latest_key else None,
                sidecar_object_size=int(sidecar_list_obj.get("Size", 0) or 0) if latest_sidecar else None,
                manifest_object_size=int(manifest_list_obj.get("Size", 0) or 0) if latest_manifest else None,
                manifest_ciphertext_sha256_match_status=(
                    "PASS" if valid_expected_sha256 and parsed_manifest and parsed_manifest.get("ciphertext_sha256") == expected_sha256 else "MISMATCH" if valid_expected_sha256 and parsed_manifest else "EXPECTED_SHA256_NOT_CONFIGURED"
                ),
                expected_sidecar_sha256_match_status=(
                    "PASS" if re.fullmatch(r"[0-9a-f]{64}", sidecar_expected_sha256) and parsed_manifest and parsed_manifest.get("sidecar_sha256") == sidecar_expected_sha256 else "MISMATCH" if re.fullmatch(r"[0-9a-f]{64}", sidecar_expected_sha256) and parsed_manifest else "EXPECTED_SHA256_NOT_CONFIGURED"
                ),
                data_reference_time_status=(parsed_manifest or {}).get("data_reference_time_status", "UNVERIFIED"),
                data_reference_evidence_present=parsed_sidecar.get("data_reference_evidence_present", "UNVERIFIED"),
                warning="S3 List/LastModified and BackupTimestamp describe object/job timing, not independently proven transaction cutoff; source binlog retention and encrypted payload SHA-256 require a separate read-only/live restore-path verification",
            ))
            if manifest_validation_status == "LEGACY":
                checks.append(_check("s3_dump_restoreability", "BLOCKED", "legacy Sidecar-only backup has no Manifest and is not treated as integrity-verified"))
            elif manifest_validation_status == "PASS":
                checks.append(_check("s3_dump_restoreability", "PENDING_LIVE_TEST", "Manifest and Sidecar metadata match; encrypted payload SHA-256 must be recomputed from the selected object before restore; decryption and restore remain untested"))
    now = datetime.now(timezone.utc)
    rpo_path_raw = values.get("DR_RPO_EVIDENCE_FILE") or values.get("DR_FAILOVER_RPO_EVIDENCE_FILE")
    evidence_path = Path(rpo_path_raw) if rpo_path_raw else None
    evidence = rpo_evidence if rpo_evidence is not None else _read_json(evidence_path)
    dump_timer = _text(ROOT, "operations/db/systemd/hospital-dr-db-backup.timer")
    upload_timer = _text(ROOT, "operations/db/systemd/hospital-dr-s3-upload.timer")
    interval = _parse_dump_interval(dump_timer)
    checks.extend(assess_rpo(
        values.get("DB_NR_ENABLED"), evidence, now=now,
        dump_interval_minutes=interval,
        nominal_upload_offset_minutes=_parse_upload_offset(dump_timer, upload_timer),
    ))
    return checks


def overall_status(checks: list[dict[str, Any]]) -> str:
    if any(item["status"] in {"BLOCKED", "RPO_NOT_GUARANTEED"} for item in checks):
        return "BLOCKED"
    if any(item["status"] in {"UNVERIFIED", "PENDING_LIVE_TEST"} for item in checks):
        return "NOT_READY"
    return "READY"


def build_report(
    *,
    root: Path,
    values: dict[str, str],
    aws_read_only: bool,
    policy_source_arn: str = "",
    skip_iam_simulation: bool = False,
    rpo_evidence: dict[str, Any] | None = None,
    cloudflare_read_only: bool = False,
    local_read_only: bool = False,
    runner: Callable[..., tuple[int, str]] | None = None,
) -> dict[str, Any]:
    checks = static_contract_checks(root, values)
    mode = "OFFLINE"
    if aws_read_only:
        mode = "AWS_READ_ONLY"
        checks.extend(live_aws_checks(
            values,
            region=values.get("AWS_REGION", REGION_DEFAULT),
            policy_source_arn=policy_source_arn,
            skip_iam_simulation=skip_iam_simulation,
            rpo_evidence=rpo_evidence,
            cloudflare_read_only=cloudflare_read_only,
            runner=runner,
        ))
    if not aws_read_only:
        checks.extend([
            _check("aws_resources", "UNVERIFIED", "AWS API was not called; use --aws-read-only for explicit describe/simulate queries"),
            _check("application_health_live", "PENDING_LIVE_TEST", "stopped/unstarted service Health cannot be verified from repository configuration"),
            _check("s3_backup_pair", "UNVERIFIED", "S3 object presence/upload timestamps were not queried"),
            _check("cloudflare_dns_live", "UNVERIFIED", "Cloudflare DNS API was not called"),
        ])
        dump_timer = _text(root, "operations/db/systemd/hospital-dr-db-backup.timer")
        upload_timer = _text(root, "operations/db/systemd/hospital-dr-s3-upload.timer")
        checks.extend(assess_rpo(
            values.get("DB_NR_ENABLED"), rpo_evidence,
            now=datetime.now(timezone.utc),
            dump_interval_minutes=_parse_dump_interval(dump_timer),
            nominal_upload_offset_minutes=_parse_upload_offset(dump_timer, upload_timer),
        ))
    if skip_iam_simulation:
        checks.append(_check("iam_simulation", "UNVERIFIED", "IAM simulations were explicitly skipped; no unverified permission is treated as allowed"))
        iam_simulation_status = "NOT_VERIFIED"
    elif not aws_read_only:
        iam_simulation_status = "NOT_REQUESTED"
    else:
        iam_checks = [
            item for item in checks
            if item.get("name") in {"instance_profile_ssm_iam", "executor_iam", "cloudflare_ssm_permission", "cloudflare_kms_permission"}
        ]
        if any(item.get("status") == "BLOCKED" for item in iam_checks):
            iam_simulation_status = "BLOCKED"
        elif iam_checks and all(item.get("status") == "PASS" for item in iam_checks):
            iam_simulation_status = "PASS"
        else:
            iam_simulation_status = "NOT_VERIFIED"
    if local_read_only:
        checks.extend(local_readonly_checks(values, runner=runner))
        if not aws_read_only:
            mode = "LOCAL_READ_ONLY"
        else:
            mode = "AWS_AND_LOCAL_READ_ONLY"
    return {
        "schema_version": 1,
        "mode": mode,
        "read_only": True,
        "mutations_performed": False,
        "iam_simulation": iam_simulation_status,
        "overall": overall_status(checks),
        "checks": checks,
        "forbidden_operations_called": [],
    }


def render_text(report: dict[str, Any]) -> str:
    lines = ["AWS FAILOVER READ-ONLY PREFLIGHT", f"MODE={report['mode']}", f"OVERALL={report['overall']}", f"IAM_SIMULATION={report['iam_simulation']}", "MUTATIONS_PERFORMED=false"]
    for item in report["checks"]:
        extra = []
        for key in (
            "dump_interval_minutes", "nominal_upload_offset_minutes", "live_status",
            "data_reference_time_status", "latest_pair_name", "s3_last_modified_upload_time",
            "recorded_backup_start_timestamp", "last_service_exit_at", "last_verified_replication_at",
            "s3_list_status", "dump_head_status", "sidecar_head_status", "sidecar_get_status",
            "sidecar_exists_status", "sidecar_format_status", "sidecar_status", "backup_identity_status",
            "object_pair_identity_status", "sidecar_timestamp_match_status", "binlog_coordinate_status",
            "source_binlog_coordinate_status", "ciphertext_sha256_status",
            "sidecar_sha256_status", "s3_checksum_metadata_available", "expected_ciphertext_sha256_configured",
                "data_reference_evidence_present",
            "rpo_seconds", "data_reference_at", "region", "record_id", "record_type",
            "instances", "states", "planned_actions", "observed_vpc_ids", "observed_eni_ids",
            "subnet_ids", "group_ids", "private_route_table_id", "private_associated_subnet_ids",
            "public_web_route_table_id", "permissions", "roles", "required_ingress_rules",
            "missing_required_rules", "not_required_for_executor",
        ):
            value = item.get(key)
            if value is not None:
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
                extra.append(f"{key.upper()}={value}")
        detail = item["detail"].replace("\n", " ")
        suffix = f" {' '.join(extra)}" if extra else ""
        lines.append(f"{item['name']}={item['status']} {detail}{suffix}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aws-read-only", action="store_true", help="explicitly run AWS read-only describe/list calls; IAM simulation also requires --policy-source-arn")
    parser.add_argument("--local-read-only", action="store_true", help="read systemd timer/service state and backup sidecar metadata; does not invoke units")
    parser.add_argument("--cloudflare-read-only", action="store_true", help="also fetch the Cloudflare token from SSM in memory and issue DNS GET requests only")
    parser.add_argument("--env-file", type=Path, help="optional dotenv file; only non-secret allowlisted settings are parsed, never executed")
    parser.add_argument("--rpo-evidence", type=Path, help="optional existing read-only RPO/replication evidence JSON")
    parser.add_argument("--policy-source-arn", default="", help="explicitly opt in to bounded IAM policy simulation for this role/user and discovered EC2 profiles")
    parser.add_argument("--skip-iam-simulation", action="store_true", help="skip every IAM simulate-principal-policy call; IAM permissions remain NOT_VERIFIED")
    parser.add_argument("--region", default="", help="AWS region override (only used with --aws-read-only)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    if args.cloudflare_read_only and not args.aws_read_only:
        parser.error("--cloudflare-read-only requires --aws-read-only")
    if args.env_file and (not args.env_file.is_file() or not os.access(args.env_file, os.R_OK)):
        parser.error("--env-file is not a readable regular file")
    values = safe_config(args.env_file)
    if args.region:
        values["AWS_REGION"] = args.region
    if args.aws_read_only and not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", values.get("AWS_REGION", REGION_DEFAULT)):
        parser.error("AWS region format is invalid")
    rpo_path = args.rpo_evidence
    if rpo_path is None:
        configured = values.get("DR_RPO_EVIDENCE_FILE") or values.get("DR_FAILOVER_RPO_EVIDENCE_FILE")
        rpo_path = Path(configured) if configured else None
    report = build_report(
        root=ROOT,
        values=values,
        aws_read_only=args.aws_read_only,
        policy_source_arn=args.policy_source_arn,
        skip_iam_simulation=args.skip_iam_simulation,
        rpo_evidence=_read_json(rpo_path),
        cloudflare_read_only=args.cloudflare_read_only,
        local_read_only=args.local_read_only,
    )
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) if args.format == "json" else render_text(report))
    return 0 if report["overall"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
