#!/usr/bin/env bash
set -euo pipefail

# Final DR readiness gate. This file is read-only by design: it never starts
# services or EC2, changes NAT/routes/EIPs/DNS, mutates Terraform state, or
# sends Slack/Zabbix callbacks.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

usage() {
    cat <<'USAGE'
Usage: final_dr_preflight.sh

Run final DR Failover/Failback readiness checks without executing either
workflow. Set DR_TERRAFORM_PLAN_JSON to an existing terraform show -json plan
to include the read-only Terraform drift classifier.
USAGE
}

case "${1:-}" in
    "") ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

SECRET_FILE="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"
secret_loaded=false
if [[ -r "$SECRET_FILE" ]]; then
    set +u
    # shellcheck disable=SC1090
    if source "$SECRET_FILE" >/dev/null 2>&1; then
        secret_loaded=true
    fi
    set -u
fi

# These files only define functions and read values when their functions are
# called. No state preparation/write function is invoked by this checker.
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

AWS_REGION="${AWS_REGION:-ap-northeast-2}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
ONPREM_TUNNEL_HOST="${ONPREM_TUNNEL_HOST:-e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com}"
EXPECTED_RECORD_ID="4c35b40ec154fb21c92fc3795ce9d5ea"
EXPECTED_WEB_PUBLIC_IP="AWS_PUBLIC_IP_REDACTED"
EXPECTED_NAT_EIP="AWS_PUBLIC_IP_REDACTED"

BLOCKERS=()
WARNINGS=()
RTO_MEASUREMENT_READY=BLOCKED
RPO_MEASUREMENT_READY=BLOCKED

ready_check() {
    printf 'READY: %s\n' "$1"
}

warn_check() {
    WARNINGS+=("$1")
    printf 'WARN: %s\n' "$1"
}

blocked_check() {
    BLOCKERS+=("$1")
    printf 'BLOCKED: %s\n' "$1"
}

has_value() {
    local name="$1"
    [[ -n "${!name:-}" ]]
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

join_codes() {
    local IFS=,
    printf '%s' "$*"
}

check_service_active() {
    local label="$1" unit="$2" code="$3"
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        ready_check "$label"
    else
        blocked_check "$code"
    fi
}

check_service_or_process() {
    local label="$1" unit="$2" pattern="$3" code="$4"
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        ready_check "$label (systemd)"
    elif command_available pgrep && pgrep -f -- "$pattern" >/dev/null 2>&1; then
        ready_check "$label (process)"
    else
        blocked_check "$code"
    fi
}

check_lock_free() {
    local label="$1" path="$2" code="$3"
    if [[ ! -e "$path" ]]; then
        ready_check "$label (absent)"
    elif [[ ! -f "$path" ]]; then
        blocked_check "$code"
    elif flock -n "$path" -c true 2>/dev/null; then
        ready_check "$label (free)"
    else
        blocked_check "$code"
    fi
}

printf '%s\n' FINAL_DR_PREFLIGHT_BEGIN

if [[ "$secret_loaded" == true ]]; then
    ready_check SECRET_SOURCE
else
    blocked_check SECRET_SOURCE_UNREADABLE
fi

git_head=""
if ! command_available git; then
    blocked_check GIT_UNAVAILABLE
else
    if [[ "$(git branch --show-current 2>/dev/null || true)" == main ]]; then
        ready_check GIT_BRANCH_MAIN
    else
        blocked_check GIT_BRANCH_NOT_MAIN
    fi
    if [[ -z "$(git status --porcelain 2>/dev/null)" ]]; then
        ready_check GIT_WORKTREE_CLEAN
    else
        blocked_check GIT_WORKTREE_DIRTY
    fi
    git_head="$(git rev-parse HEAD 2>/dev/null || true)"
    origin_head="$(git rev-parse origin/main 2>/dev/null || true)"
    if [[ -n "$git_head" && "$git_head" == "$origin_head" ]]; then
        ready_check GIT_HEAD_MATCHES_ORIGIN_MAIN
    else
        blocked_check GIT_HEAD_ORIGIN_MISMATCH
    fi
fi

github_repository=""
origin_url="$(git config --get remote.origin.url 2>/dev/null || true)"
origin_url="${origin_url%.git}"
case "$origin_url" in
    git@github.com:*) github_repository="${origin_url#git@github.com:}" ;;
    https://github.com/*) github_repository="${origin_url#https://github.com/}" ;;
    ssh://git@github.com/*) github_repository="${origin_url#ssh://git@github.com/}" ;;
esac

if [[ -z "$github_repository" || "$github_repository" != */* ]]; then
    blocked_check GITHUB_REPOSITORY_UNRESOLVED
elif ! command_available gh; then
    blocked_check GITHUB_CLI_UNAVAILABLE
else
    ci_record="$(gh run list --repo "$github_repository" --limit 50 \
        --json databaseId,status,conclusion,headSha,createdAt \
        --jq 'map(select(.headSha == "'"$git_head"'")) | sort_by(.createdAt) | reverse | .[0] | if . == null then "" else [.databaseId, .status, (.conclusion // ""), .headSha] | join(" ") end' \
        2>/dev/null || true)"
    ci_id="" ci_status="" ci_conclusion="" ci_sha=""
    read -r ci_id ci_status ci_conclusion ci_sha <<< "$ci_record" || true
    if [[ "$ci_status" == completed && "$ci_conclusion" == success && "$ci_sha" == "$git_head" ]]; then
        ready_check "GITHUB_ACTIONS_GREEN_RUN_$ci_id"
    else
        blocked_check GITHUB_ACTIONS_NOT_GREEN
    fi
fi

DR_IMAGE_TAG="${DR_IMAGE_TAG:-$git_head}"
if [[ "$DR_IMAGE_TAG" =~ ^[0-9a-fA-F]{40}$ && "$DR_IMAGE_TAG" == "$git_head" ]]; then
    ready_check IMMUTABLE_IMAGE_TAG_IS_CURRENT_HEAD
else
    blocked_check IMAGE_TAG_NOT_CURRENT_HEAD
fi

aws_ready=false
if ! command_available aws; then
    blocked_check AWS_CLI_UNAVAILABLE
elif aws sts get-caller-identity --query Arn --output text >/dev/null 2>&1; then
    aws_ready=true
    ready_check AWS_READ_ONLY_CREDENTIALS
else
    blocked_check AWS_READ_ONLY_CREDENTIALS_UNAVAILABLE
fi

if [[ "$aws_ready" == true && "$DR_IMAGE_TAG" == "$git_head" ]]; then
    for image_repository in "${ECR_WEB_REPOSITORY:-hospital-dr-web}" "${ECR_EMR_REPOSITORY:-hospital-dr-emr}"; do
        image_digest="$(aws ecr describe-images --region "$AWS_REGION" \
            --repository-name "$image_repository" --image-ids "imageTag=$DR_IMAGE_TAG" \
            --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
        if [[ "$image_digest" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
            ready_check "ECR_${image_repository}_IMMUTABLE_IMAGE"
        else
            blocked_check "ECR_IMAGE_MISSING_${image_repository}"
        fi
    done
fi

check_service_active CHATOPS_SERVICE hospital-dr-chatops.service CHATOPS_SERVICE_INACTIVE
check_service_or_process GUNICORN hospital-dr-chatops.service '[g]unicorn.*wsgi:app' GUNICORN_INACTIVE
check_service_active ZABBIX_PROXY_SERVICE hospital-dr-zabbix-proxy.service ZABBIX_PROXY_INACTIVE
check_service_active NGROK_SERVICE hospital-dr-chatops-ngrok.service NGROK_INACTIVE
check_service_or_process DOCKER docker.service '[d]ockerd|docker.service' DOCKER_INACTIVE
check_service_or_process ZABBIX_SERVER zabbix-server.service '[z]abbix_server' ZABBIX_SERVER_INACTIVE
check_service_or_process GRAFANA grafana-server.service '[g]rafana server' GRAFANA_INACTIVE
check_service_or_process WAZUH_MANAGER wazuh-manager.service '[w]azuh-(analysisd|remoted|authd|db)' WAZUH_MANAGER_INACTIVE
check_service_or_process WAZUH_INDEXER wazuh-indexer.service '[o]pensearch' WAZUH_INDEXER_INACTIVE
check_service_or_process WAZUH_DASHBOARD wazuh-dashboard.service '[w]azuh-dashboard|[o]pensearch-dashboards' WAZUH_DASHBOARD_INACTIVE

if [[ -d "$DR_STATE_DIR" && -r "$DR_STATE_DIR" && -w "$DR_STATE_DIR" ]]; then
    ready_check PERSISTENT_STATE_DIRECTORY
else
    blocked_check PERSISTENT_STATE_DIRECTORY_UNAVAILABLE
fi
if [[ -r "$DR_STATE_FILE" ]]; then
    current_state="$(dr_state_read 2>/dev/null || true)"
    if [[ "$current_state" == IDLE ]]; then ready_check PERSISTENT_DR_STATE_IDLE; else blocked_check PERSISTENT_DR_STATE_NOT_IDLE; fi
else
    blocked_check PERSISTENT_DR_STATE_MISSING
fi

CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-$DR_STATE_DIR/chatops_state.sqlite3}"
CHATOPS_AUDIT_FILE="${CHATOPS_AUDIT_FILE:-$DR_STATE_DIR/audit/chatops_audit.jsonl}"
if [[ -r "$CHATOPS_STATE_DB" ]]; then ready_check CHATOPS_STATE_DATABASE; else blocked_check CHATOPS_STATE_DATABASE_UNREADABLE; fi
if [[ -r "$CHATOPS_AUDIT_FILE" ]]; then ready_check CHATOPS_AUDIT_FILE; else blocked_check CHATOPS_AUDIT_FILE_UNREADABLE; fi

check_lock_free WORKFLOW_LOCK "${DR_WORKFLOW_LOCK_FILE:-$DR_STATE_DIR/workflow.lock}" ACTIVE_WORKFLOW_LOCK
check_lock_free FAILOVER_LOCK "${DR_FAILOVER_LOCK_FILE:-$DR_STATE_DIR/failover.lock}" ACTIVE_FAILOVER_LOCK
check_lock_free FAILBACK_LOCK "${DR_FAILBACK_LOCK_FILE:-$DR_STATE_DIR/failback.lock}" ACTIVE_FAILBACK_LOCK
check_lock_free ENVIRONMENT_LOCK "${DR_ENVIRONMENT_LOCK_FILE:-$DR_STATE_DIR/environment.lock}" ACTIVE_ENVIRONMENT_LOCK
check_lock_free TERRAFORM_LOCK "${DR_TERRAFORM_LOCK_FILE:-$DR_STATE_DIR/terraform.lock}" ACTIVE_TERRAFORM_LOCK
check_lock_free PROJECT_RESUME_LOCK "${DR_PROJECT_RESUME_LOCK_FILE:-$DR_STATE_DIR/project-resume.lock}" ACTIVE_PROJECT_RESUME_LOCK

for slack_value in SLACK_CHANNEL_ID SLACK_ALERT_CHANNEL_ID \
    SLACK_FAILOVER_BOT_TOKEN SLACK_FAILBACK_BOT_TOKEN SLACK_ALERT_BOT_TOKEN \
    SLACK_FAILOVER_SIGNING_SECRET SLACK_FAILBACK_SIGNING_SECRET; do
    if has_value "$slack_value"; then ready_check "${slack_value}_SET"; else blocked_check "${slack_value}_MISSING"; fi
done
if has_value SLACK_CHANNEL_ID && has_value SLACK_ALERT_CHANNEL_ID \
    && [[ "$SLACK_CHANNEL_ID" == "$SLACK_ALERT_CHANNEL_ID" ]]; then
    blocked_check SLACK_CHANNELS_NOT_SEPARATED
fi
approver_count="$(SLACK_ADMIN_USER_IDS="${SLACK_ADMIN_USER_IDS:-}" python3 -c 'import os; print(len({item.strip() for item in os.environ.get("SLACK_ADMIN_USER_IDS", "").split(",") if item.strip()}))')"
printf 'SLACK_APPROVER_COUNT=%s\n' "$approver_count"
if [[ "$approver_count" =~ ^[0-9]+$ && "$approver_count" -ge 2 ]]; then
    ready_check SLACK_DISTINCT_APPROVERS_GE_2
else
    blocked_check INSUFFICIENT_APPROVERS
fi

failback_probe_missing=()
for failback_probe in ONPREM_WEB_HEALTH_URL ONPREM_DOC_HEALTH_URL ONPREM_DB_HOST; do
    if ! has_value "$failback_probe"; then
        failback_probe_missing+=("$failback_probe")
    fi
done
if [[ "${#failback_probe_missing[@]}" -eq 0 ]]; then
    ready_check FAILBACK_STABILITY_PROBE_CONFIGURATION
else
    printf 'FAILBACK_STABILITY_PROBES_MISSING=%s\n' "${failback_probe_missing[*]}"
    blocked_check FAILBACK_STABILITY_PROBE_CONFIGURATION_MISSING
fi

CF_RECORD_ID="${CF_RECORD_ID:-$EXPECTED_RECORD_ID}"
if [[ ! "${CF_ZONE_ID:-}" =~ ^[0-9a-fA-F]{32}$ ]]; then
    blocked_check CLOUDFLARE_ZONE_ID_MISSING_OR_INVALID
elif [[ "$CF_RECORD_ID" != "$EXPECTED_RECORD_ID" ]]; then
    blocked_check CLOUDFLARE_RECORD_ID_MISMATCH
elif ! load_cloudflare_ssm_token >/dev/null 2>&1; then
    blocked_check CLOUDFLARE_TOKEN_UNAVAILABLE
else
    cloudflare_record_json="$(curl -fsS --connect-timeout 5 --max-time 15 \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${CF_RECORD_ID}" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H 'Content-Type: application/json' 2>/dev/null || true)"
    if [[ -z "$cloudflare_record_json" ]]; then
        blocked_check CLOUDFLARE_RECORD_UNREADABLE
    elif printf '%s' "$cloudflare_record_json" | \
        CF_EXPECTED_ID="$EXPECTED_RECORD_ID" CF_EXPECTED_NAME="$DR_DOMAIN" \
        CF_EXPECTED_CONTENT="$ONPREM_TUNNEL_HOST" \
        python3 -c '
import json
import os
import sys

try:
    response = json.load(sys.stdin)
    record = response.get("result") if isinstance(response, dict) else None
    expected = {
        "id": os.environ["CF_EXPECTED_ID"],
        "name": os.environ["CF_EXPECTED_NAME"],
        "type": "CNAME",
        "content": os.environ["CF_EXPECTED_CONTENT"],
        "proxied": True,
        "ttl": 1,
    }
    ok = response.get("success") is True and isinstance(record, dict)
    ok = ok and all(record.get(key) == value for key, value in expected.items())
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    ok = False
print("OK" if ok else "MISMATCH")
' | grep -Fxq OK; then
        ready_check CLOUDFLARE_ONPREM_CNAME_BASELINE
    else
        blocked_check CLOUDFLARE_BASELINE_MISMATCH
    fi
fi

tls_cert="${DR_TLS_CERT_FILE:-/home/cloud/hospital-dr-secrets/tls/hospital-web.crt}"
tls_key="${DR_TLS_KEY_FILE:-/home/cloud/hospital-dr-secrets/tls/hospital-web.key}"
if [[ ! -r "$tls_cert" ]]; then
    blocked_check TLS_CERT_SOURCE_UNREADABLE
elif [[ ! -r "$tls_key" ]]; then
    blocked_check TLS_KEY_SOURCE_UNREADABLE
else
    cert_mode="$(stat -c '%a' "$tls_cert" 2>/dev/null || true)"
    key_mode="$(stat -c '%a' "$tls_key" 2>/dev/null || true)"
    if [[ "$cert_mode" == 644 ]]; then ready_check TLS_CERT_PERMISSION; else blocked_check TLS_CERT_PERMISSION; fi
    if [[ "$key_mode" == 600 || "$key_mode" == 400 ]]; then ready_check TLS_KEY_PERMISSION; else blocked_check TLS_KEY_PERMISSION; fi

    tls_valid=false
    san_data=""
    issuer_data=""
    subject_data=""
    if command_available openssl \
        && openssl x509 -in "$tls_cert" -noout >/dev/null 2>&1 \
        && openssl x509 -in "$tls_cert" -checkend 0 -noout >/dev/null 2>&1; then
        san_data="$(openssl x509 -in "$tls_cert" -noout -ext subjectAltName 2>/dev/null || true)"
        issuer_data="$(openssl x509 -in "$tls_cert" -noout -issuer 2>/dev/null || true)"
        subject_data="$(openssl x509 -in "$tls_cert" -noout -subject 2>/dev/null || true)"
        if [[ "$san_data" == *DNS:hospital-web.pp.ua* ]]; then tls_valid=true; ready_check TLS_CERT_SAN_AND_EXPIRY; else blocked_check TLS_CERT_SAN_MISMATCH; fi
    else
        blocked_check TLS_CERT_INVALID_OR_EXPIRED
    fi
    if [[ "$issuer_data $subject_data" != *[Cc]loud[Ff]lare*Origin* ]]; then warn_check TLS_ISSUER_REVIEW_REQUIRED; fi
    cert_public_hash=""
    key_public_hash=""
    if [[ "$tls_valid" == true ]] && command_available openssl && command_available sha256sum; then
        cert_public_hash="$(openssl x509 -in "$tls_cert" -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || cert_public_hash=""
        key_public_hash="$(openssl pkey -in "$tls_key" -pubout 2>/dev/null \
            | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || key_public_hash=""
        if [[ -n "$cert_public_hash" && "$cert_public_hash" == "$key_public_hash" ]]; then ready_check TLS_CERT_KEY_MATCH; else blocked_check TLS_CERT_KEY_MISMATCH; fi
    else
        blocked_check TLS_CERT_KEY_UNVERIFIED
    fi
fi

if [[ "$aws_ready" == true ]]; then
    instance_json="$(aws ec2 describe-instances --region "$AWS_REGION" \
        --filters \
            Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server \
            Name=instance-state-name,Values=pending,running,stopping,stopped \
        --query 'Reservations[].Instances[]' --output json 2>/dev/null || true)"
    if printf '%s' "$instance_json" | python3 -c '
import json
import sys

expected = {
    "Hospital-Real-Web-Server": ("IP_REDACTED", "IP_REDACTED"),
    "Hospital-DR-Doc-Server": ("IP_REDACTED", None),
    "Hospital-DR-DB-Server": ("IP_REDACTED", None),
}
try:
    items = json.load(sys.stdin)
    by_name = {}
    for item in items:
        tags = {tag.get("Key"): tag.get("Value") for tag in item.get("Tags", [])}
        by_name.setdefault(tags.get("Name"), []).append(item)
    ok = set(by_name) == set(expected)
    for name, (private_ip, public_ip) in expected.items():
        matches = by_name.get(name, [])
        ok = ok and len(matches) == 1
        if len(matches) != 1:
            continue
        item = matches[0]
        ok = ok and item.get("State", {}).get("Name") == "stopped"
        ok = ok and item.get("PrivateIpAddress") == private_ip
        ok = ok and item.get("PublicIpAddress") == public_ip
        ok = ok and bool(item.get("InstanceId"))
except (TypeError, ValueError, json.JSONDecodeError):
    ok = False
raise SystemExit(0 if ok else 1)
' >/dev/null 2>&1; then
        ready_check AWS_THREE_DR_EC2_STOPPED_AND_ADDRESS_STABLE
    else
        blocked_check AWS_DR_EC2_SUSPENDED_STATE_MISMATCH
    fi

    eip_json="$(aws ec2 describe-addresses --region "$AWS_REGION" \
        --public-ips "$EXPECTED_NAT_EIP" "$EXPECTED_WEB_PUBLIC_IP" --output json 2>/dev/null || true)"
    if printf '%s' "$eip_json" | python3 -c '
import json
import sys
try:
    response = json.load(sys.stdin)
    addresses = response.get("Addresses", [])
    ips = {item.get("PublicIp") for item in addresses if isinstance(item, dict)}
    ok = {"IP_REDACTED", "IP_REDACTED"}.issubset(ips)
except (TypeError, ValueError, json.JSONDecodeError):
    ok = False
raise SystemExit(0 if ok else 1)
' >/dev/null 2>&1; then ready_check FIXED_NAT_AND_WEB_EIP_PRESERVED; else blocked_check PRESERVED_EIP_MISSING; fi

    nat_json="$(aws ec2 describe-nat-gateways --region "$AWS_REGION" \
        --filter Name=state,Values=pending,available,active,deleting --output json 2>/dev/null || true)"
    if printf '%s' "$nat_json" | python3 -c '
import json
import sys
try:
    data = json.load(sys.stdin)
    ok = not bool((data or {}).get("NatGateways"))
except (TypeError, ValueError, json.JSONDecodeError):
    ok = False
raise SystemExit(0 if ok else 1)
' >/dev/null 2>&1; then ready_check NAT_GATEWAY_ABSENT; else blocked_check NAT_GATEWAY_PRESENT_OR_DELETING; fi

    vpc_id="$(aws ec2 describe-vpcs --region "$AWS_REGION" --filters Name=cidr-block,Values=AWS_PUBLIC_IP_REDACTED/16 \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)"
    if [[ -z "$vpc_id" || "$vpc_id" == None ]]; then
        blocked_check DR_VPC_NOT_FOUND
    else
        nat_routes="$(aws ec2 describe-route-tables --region "$AWS_REGION" \
            --filters "Name=vpc-id,Values=$vpc_id" \
            --query 'RouteTables[].Routes[?NatGatewayId!=null].NatGatewayId' --output text 2>/dev/null || true)"
        if [[ -z "$nat_routes" || "$nat_routes" == None ]]; then ready_check PRIVATE_NAT_ROUTE_ABSENT; else blocked_check PRIVATE_NAT_ROUTE_PRESENT; fi
    fi
fi

terraform_plan_json="${DR_TERRAFORM_PLAN_JSON:-}"
terraform_runtime_dir="${DR_TERRAFORM_RUNTIME_DIR:-/home/cloud/hospital-dr-terraform}"
if [[ -n "$terraform_plan_json" && -r "$terraform_plan_json" && -x "$SCRIPT_DIR/terraform_drift_check.sh" ]]; then
    terraform_drift_report=""
    terraform_drift_rc=0
    terraform_drift_report="$("$SCRIPT_DIR/terraform_drift_check.sh" --plan-json "$terraform_plan_json" 2>/dev/null)" || terraform_drift_rc=$?
    if [[ "$terraform_drift_rc" -eq 0 ]]; then
        ready_check TERRAFORM_READ_ONLY_PLAN_NO_DRIFT
    else
        grep -Fq 'OIDC_STATE_DRIFT=true' <<< "$terraform_drift_report" && warn_check OIDC_STATE_DRIFT_OPERATOR_RECONCILE || true
        grep -Fq 'KEY_PAIR_MISMATCH=true' <<< "$terraform_drift_report" && warn_check KEY_PAIR_INPUT_REQUIRED || true
        grep -Fq 'MANAGEMENT_CIDR_NEEDS_INPUT=true' <<< "$terraform_drift_report" && warn_check MANAGEMENT_CIDR_INPUT_REQUIRED || true
        grep -Eq 'DESTRUCTIVE_CHANGE_COUNT=[1-9]' <<< "$terraform_drift_report" && warn_check TERRAFORM_DESTRUCTIVE_PLAN_REVIEW_REQUIRED || true
    fi
else
    warn_check TERRAFORM_READ_ONLY_PLAN_NOT_SUPPLIED
fi
if [[ -d "$terraform_runtime_dir" && -r "$terraform_runtime_dir/terraform.tfstate" ]] && command_available terraform; then
    terraform_state_output=""
    if terraform_state_output="$(terraform -chdir="$terraform_runtime_dir" state list 2>/dev/null)"; then
        terraform_state_count="$(printf '%s\n' "$terraform_state_output" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
        if [[ "$terraform_state_count" =~ ^[0-9]+$ && "$terraform_state_count" -gt 0 ]]; then
            ready_check TERRAFORM_OPERATIONAL_STATE_READABLE
        else
            blocked_check TERRAFORM_OPERATIONAL_STATE_UNREADABLE
        fi
    else
        blocked_check TERRAFORM_OPERATIONAL_STATE_UNREADABLE
    fi
else
    blocked_check TERRAFORM_OPERATIONAL_STATE_UNAVAILABLE
fi
if [[ -x "$SCRIPT_DIR/sync_terraform_runtime.sh" ]] \
    && DR_REPO_ROOT="$DR_REPO_ROOT" DR_CANONICAL_TERRAFORM_DIR="$DR_TERRAFORM_DIR" \
       DR_TERRAFORM_RUNTIME_DIR="$terraform_runtime_dir" "$SCRIPT_DIR/sync_terraform_runtime.sh" --check >/dev/null 2>&1; then
    ready_check TERRAFORM_SOURCE_RUNTIME_MATCH
else
    warn_check TERRAFORM_SOURCE_RUNTIME_DRIFT_REQUIRES_REVIEW
fi

local_backup_result="$(BACKUP_SEARCH_PATHS="${DR_BACKUP_SEARCH_PATHS:-/home/cloud/db_backups:/var/lib/hospital-dr/db_backups}" \
    python3 - <<'PY'
import os
import re
from pathlib import Path

pattern = re.compile(r"^db_backup_(\d{8}_\d{6})\.sql\.gz\.enc$")
line_file = re.compile(r"(?im)^\s*(?:File|BinlogFile)\s*:\s*\S+\s*$")
line_pos = re.compile(r"(?im)^\s*(?:Position|BinlogPosition)\s*:\s*[0-9]+\s*$")
statement = re.compile(
    r"(?is)CHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO.*?"
    r"(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'[^']+'.*?"
    r"(?:MASTER|SOURCE)_LOG_POS\s*=\s*[0-9]+",
)
pairs = []
for root_name in os.environ.get("BACKUP_SEARCH_PATHS", "").split(os.pathsep):
    if not root_name:
        continue
    root = Path(root_name)
    if not root.is_dir():
        continue
    for encrypted in root.glob("db_backup_*.sql.gz.enc"):
        match = pattern.fullmatch(encrypted.name)
        if not match or not encrypted.is_file() or encrypted.stat().st_size <= 0:
            continue
        status = encrypted.with_name(encrypted.name.removesuffix(".sql.gz.enc") + ".master_status")
        if not status.is_file() or status.stat().st_size <= 0:
            continue
        try:
            text = status.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if (line_file.search(text) and line_pos.search(text)) or statement.search(text):
            pairs.append(match.group(1))
print(f"{len(pairs)} {max(pairs) if pairs else '-'}")
PY
)" || local_backup_result="0 -"
local_pair_count="${local_backup_result%% *}"
local_pair_latest="${local_backup_result#* }"

s3_pair_count=0
s3_pair_latest=-
S3_BACKUP_BUCKET="${S3_BACKUP_BUCKET:-}"
S3_BACKUP_PREFIX="${S3_BACKUP_PREFIX:-mysql/hospital_db}"
if [[ -n "$S3_BACKUP_BUCKET" && "$aws_ready" == true ]]; then
    s3_args=(--region "$AWS_REGION")
    [[ -n "${S3_BACKUP_AWS_PROFILE:-}" ]] && s3_args+=(--profile "$S3_BACKUP_AWS_PROFILE")
    s3_json="$(aws "${s3_args[@]}" s3api list-objects-v2 --bucket "$S3_BACKUP_BUCKET" \
        --prefix "${S3_BACKUP_PREFIX%/}/" --query 'Contents[].{Key:Key,Size:Size}' \
        --output json 2>/dev/null || true)"
    s3_pair_result="$(printf '%s' "$s3_json" | python3 -c '
import json
import re
import sys

pattern = re.compile(r"(?:^|/)db_backup_(\d{8}_\d{6})\.sql\.gz\.enc$")
try:
    objects = json.load(sys.stdin) or []
    names = {
        item.get("Key") for item in objects
        if isinstance(item, dict) and item.get("Key") and int(item.get("Size") or 0) > 0
    }
    pairs = []
    for name in names:
        match = pattern.search(name or "")
        if not match:
            continue
        if name.removesuffix(".sql.gz.enc") + ".master_status" in names:
            pairs.append(match.group(1))
    latest = max(pairs) if pairs else "-"
    print(f"{len(pairs)} {latest}")
except (TypeError, ValueError, json.JSONDecodeError):
    print("0 -")
')"
    s3_pair_count="${s3_pair_result%% *}"
    s3_pair_latest="${s3_pair_result#* }"
elif [[ -z "$S3_BACKUP_BUCKET" ]]; then
    warn_check S3_BACKUP_BUCKET_NOT_CONFIGURED
fi

if [[ "$local_pair_count" =~ ^[0-9]+$ && "$local_pair_count" -gt 0 ]] \
    || [[ "$s3_pair_count" =~ ^[0-9]+$ && "$s3_pair_count" -gt 0 ]]; then
    ready_check COMPLETE_BACKUP_MASTER_STATUS_PAIR
    printf 'BACKUP_PAIR_LATEST_LOCAL=%s\n' "$local_pair_latest"
    printf 'BACKUP_PAIR_LATEST_S3=%s\n' "$s3_pair_latest"
else
    blocked_check DB_BACKUP_PAIR_NOT_FOUND
fi
if has_value DB_BACKUP_ENCRYPTION_KEY; then ready_check DB_BACKUP_ENCRYPTION_KEY_PRESENT; else blocked_check DB_BACKUP_ENCRYPTION_KEY_MISSING; fi

direct_nr_ready=true
direct_nr_missing=()
[[ "${DB_NR_ENABLED:-}" == true ]] || direct_nr_ready=false
[[ "${DB_REPL_MODE:-}" == position ]] || direct_nr_ready=false
[[ "${DB_SOURCE_HOST:-}" == IP_REDACTED ]] || direct_nr_ready=false
[[ "${DB_SOURCE_PORT:-}" == 3306 ]] || direct_nr_ready=false
[[ "${DB_REPL_USER:-}" == repl1 ]] || direct_nr_ready=false
for direct_nr_secret in DB_REPL_PASSWORD DB_SOURCE_LOG_FILE DB_SOURCE_LOG_POS; do
    if ! has_value "$direct_nr_secret"; then direct_nr_missing+=("$direct_nr_secret"); fi
done
if [[ "${#direct_nr_missing[@]}" -gt 0 ]]; then
    direct_nr_ready=false
    printf 'DIRECT_NR_INPUTS_MISSING=%s\n' "${direct_nr_missing[*]}"
fi
[[ "${DR_DIRECT_NR_NAT_WHITELIST_CONFIRMED:-}" == true ]] || direct_nr_ready=false
[[ "${DR_DIRECT_NR_NETWORK_EVIDENCE:-}" == PASS ]] || direct_nr_ready=false
if [[ "$direct_nr_ready" == true ]]; then ready_check DIRECT_NR_POSITION_INPUT_AND_EVIDENCE; else blocked_check DIRECT_NR_NOT_READY; fi

wazuh_required=(WAZUH_API_URL WAZUH_API_USER WAZUH_API_PASSWORD WAZUH_INDEXER_URL WAZUH_INDEXER_USER WAZUH_INDEXER_PASSWORD WAZUH_FAILBACK_REQUIRED_AGENTS)
wazuh_missing=()
for wazuh_value in "${wazuh_required[@]}"; do
    if ! has_value "$wazuh_value"; then wazuh_missing+=("$wazuh_value"); fi
done
if [[ "${#wazuh_missing[@]}" -gt 0 ]]; then
    printf 'WAZUH_INPUTS_MISSING=%s\n' "${wazuh_missing[*]}"
    blocked_check WAZUH_AGENT_NOT_READY
elif [[ -n "${WAZUH_CA_CERT:-}" && ! -r "$WAZUH_CA_CERT" ]]; then
    blocked_check WAZUH_CA_CERT_UNREADABLE
elif command_available python3; then
    wazuh_status="$(PYTHONPATH="$DR_REPO_ROOT/operations/chatops${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PY'
import os
try:
    from wazuh_live_provider import build_wazuh_provider
    from wazuh_failback_gate import evaluate_failback_security
    values = dict(os.environ)
    provider = build_wazuh_provider(values)
    if provider is None:
        print("UNKNOWN")
    else:
        required = tuple(item.strip() for item in values["WAZUH_FAILBACK_REQUIRED_AGENTS"].split(",") if item.strip())
        print(evaluate_failback_security(provider.snapshot(), required_agents=required).get("status", "UNKNOWN"))
except Exception:
    print("UNKNOWN")
PY
)"
    case "$wazuh_status" in
        READY) ready_check WAZUH_FAILBACK_SECURITY_PROVIDER_READY ;;
        BLOCKED) blocked_check WAZUH_SECURITY_BLOCKED ;;
        *) blocked_check WAZUH_AGENT_NOT_READY ;;
    esac
else
    blocked_check WAZUH_PROVIDER_RUNTIME_UNAVAILABLE
fi

if [[ -n "${SNMP_TARGETS_FILE:-}" && -r "$SNMP_TARGETS_FILE" ]]; then
    warn_check SNMP_TARGET_FILE_PRESENT_REACHABILITY_UNVERIFIED
fi
blocked_check SNMP_NOT_READY

runbook_contract_ready=true
for runbook_file in "$DR_FAILOVER_DIR/full_failover.sh" "$DR_FAILOVER_DIR/full_failback.sh" \
    "$DR_FAILOVER_DIR/failback.sh" "$DR_DNS_HELPER" "$DR_REPO_ROOT/infra/terraform/run_demo.sh" \
    "$DR_FINOPS_DIR/dr_environment_control.sh" "$DR_NAT_DIR/nat_enable.sh" \
    "$DR_NAT_DIR/nat_disable.sh" "$DR_NAT_DIR/nat_status.sh"; do
    [[ -r "$runbook_file" ]] || runbook_contract_ready=false
done
for pattern in web_nat_instance_status.sh dr_environment_control.sh 'dr_state_write DR_ACTIVE'; do
    grep -Fq "$pattern" "$DR_FAILOVER_DIR/full_failover.sh" 2>/dev/null || runbook_contract_ready=false
done
if grep -Fq 'nat_enable.sh' "$DR_FAILOVER_DIR/full_failover.sh" "$DR_FAILOVER_DIR/full_failback.sh" "$DR_REPO_ROOT/operations/db/db_failback_to_onprem.sh" 2>/dev/null; then
    runbook_contract_ready=false
fi
for pattern in dr_dns_snapshot_record dr_dns_preserve_origin_pair \
    dr_dns_validate_aws_web_eip dr_dns_failover_transaction 'dr_state_write DR_ACTIVE'; do
    grep -Fq "$pattern" "$DR_REPO_ROOT/infra/terraform/run_demo.sh" 2>/dev/null || runbook_contract_ready=false
done
if grep -Fq 'is_dr_mode=true' "$DR_REPO_ROOT/infra/terraform/run_demo.sh" 2>/dev/null; then
    runbook_contract_ready=false
fi
for pattern in prepare_dns_snapshot apply_dr_dns dr_dns_preserve_origin_pair \
    dr_dns_validate_aws_web_eip dr_dns_failover_transaction \
    dr_dns_failback_transaction check_public_health; do
    grep -Fq "$pattern" "$DR_FINOPS_DIR/dr_environment_control.sh" 2>/dev/null || runbook_contract_ready=false
done
if grep -Eq 'terraform_dns_mode|terraform[[:space:]]+apply|apply_dns_mode' "$DR_FINOPS_DIR/dr_environment_control.sh" 2>/dev/null; then
    runbook_contract_ready=false
fi
for pattern in RUN_DB_FAILBACK RUN_DOC_FAILBACK failback.sh 'Automatic NAT cleanup is disabled' STOP_DR_EC2_AFTER_FAILBACK 'dr_state_write IDLE'; do
    grep -Fq "$pattern" "$DR_FAILOVER_DIR/full_failback.sh" 2>/dev/null || runbook_contract_ready=false
done
for pattern in prepare_dns_snapshot dr_dns_apply_origin_pair dr_dns_validate_origin_pair \
    dr_dns_failback_transaction dr_dns_check_public_health \
    dr_dns_rollback_snapshots dr_dns_archive_origin_pair '"ttl"' '"proxied"'; do
    if ! grep -Fq "$pattern" "$DR_FAILOVER_DIR/failback.sh" "$DR_DNS_HELPER" 2>/dev/null; then
        runbook_contract_ready=false
    fi
done
if [[ "$runbook_contract_ready" == true ]]; then ready_check FAILOVER_FAILBACK_RUNBOOK_CONTRACT; else blocked_check FAILOVER_FAILBACK_RUNBOOK_CONTRACT_MISMATCH; fi

if grep -Fq 'dr.rto.seconds' "$DR_REPO_ROOT/infra/terraform/run_demo.sh" "$DR_FAILOVER_DIR/full_failback.sh" "$DR_TIMING_SCRIPT" 2>/dev/null; then
    RTO_MEASUREMENT_READY=READY
    ready_check RTO_METRIC_CONTRACT
    warn_check RTO_LIVE_VALUE_REQUIRES_ACTUAL_TEST
else
    warn_check RTO_METRIC_CONTRACT_MISSING
fi
if grep -REq 'SHOW (REPLICA|SLAVE) STATUS|DB_REPL_MODE|DB_SOURCE_LOG_POS' "$DR_REPO_ROOT/operations" 2>/dev/null; then
    warn_check RPO_LIVE_VALUE_REQUIRES_DIRECT_NR_EVIDENCE
else
    warn_check RPO_METRIC_CONTRACT_UNAVAILABLE
fi

if [[ "${#BLOCKERS[@]}" -eq 0 ]]; then final_ready=true; else final_ready=false; fi
printf 'RTO_MEASUREMENT_READY=%s\n' "$RTO_MEASUREMENT_READY"
printf 'RPO_MEASUREMENT_READY=%s\n' "$RPO_MEASUREMENT_READY"
printf 'FINAL_DR_READY=%s\n' "$final_ready"
if [[ "${#BLOCKERS[@]}" -gt 0 ]]; then
    printf 'FINAL_DR_BLOCKERS=%s\n' "$(join_codes "${BLOCKERS[@]}")"
else
    printf 'FINAL_DR_BLOCKERS=NONE\n'
fi
if [[ "${#WARNINGS[@]}" -gt 0 ]]; then
    printf 'FINAL_DR_WARNINGS=%s\n' "$(join_codes "${WARNINGS[@]}")"
else
    printf 'FINAL_DR_WARNINGS=NONE\n'
fi
printf '%s\n' FINAL_DR_PREFLIGHT_END
[[ "$final_ready" == true ]]
