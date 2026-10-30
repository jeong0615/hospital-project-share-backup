#!/usr/bin/env bash
set -uo pipefail

# Read-only readiness gate for the existing Web/EMR Failover path. This does
# not start/stop EC2, change DNS, invoke Terraform, or run Ansible roles.
# Ansible's ping module creates only its normal transient remote module files.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"
# shellcheck disable=SC1091
source "$DR_SSM_SSH_HELPER"
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

SECRET_FILE="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"
SECRET_CONFIG_READY=true
if ! dr_load_secret_file; then
  SECRET_CONFIG_READY=false
fi

AWS_REGION="${AWS_REGION:-ap-northeast-2}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
ONPREM_TUNNEL_HOST="${ONPREM_TUNNEL_HOST:-e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com}"
ONPREM_EMR_DNS_IP_EXPECTED="${ONPREM_EMR_DNS_IP_EXPECTED:-IP_REDACTED}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
CF_RECORD_ID_EXPECTED="${DR_CF_WEB_RECORD_ID_EXPECTED:-${CF_RECORD_ID:-4c35b40ec154fb21c92fc3795ce9d5ea}}"
CF_EMR_RECORD_ID_EXPECTED="${DR_CF_EMR_RECORD_ID_EXPECTED:-${CF_EMR_RECORD_ID:-4a4432c4e6290bcbd3dda5113ff8d560}}"
CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-$DR_STATE_DIR/chatops_state.sqlite3}"
CHATOPS_AUDIT_FILE="${CHATOPS_AUDIT_FILE:-$DR_STATE_DIR/audit/chatops_audit.jsonl}"
CHATOPS_LOCK="${CHATOPS_EXECUTION_LOCK_FILE:-$DR_STATE_DIR/chatops.pipeline.lock}"
WORKFLOW_LOCK="${DR_WORKFLOW_LOCK_FILE:-$DR_STATE_DIR/workflow.lock}"
FAILOVER_LOCK="${DR_FAILOVER_LOCK_FILE:-$DR_STATE_DIR/failover.lock}"
FAILBACK_LOCK="${DR_FAILBACK_LOCK_FILE:-$DR_STATE_DIR/failback.lock}"
ENVIRONMENT_LOCK="${DR_ENVIRONMENT_LOCK_FILE:-$DR_STATE_DIR/environment.lock}"
SSH_KEY="${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}"
INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
NAT_INSTANCE_STATUS_SCRIPT="${NAT_INSTANCE_STATUS_SCRIPT:-$DR_REPO_ROOT/operations/nat_instance/web_nat_instance_status.sh}"
ORIGIN_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-$DR_STATE_DIR/dns/origin}"
BLOCKERS=()
WARNINGS=()
instance_ids=()
TMP_DIR="$(mktemp -d)" || exit 2
trap 'rm -rf -- "$TMP_DIR"' EXIT

pass() { printf 'READY: %s\n' "$1"; }
warn() { WARNINGS+=("$1"); printf 'WARN: %s\n' "$1"; }
block() { BLOCKERS+=("$1"); printf 'BLOCKED: %s\n' "$1"; }
command_available() { command -v "$1" >/dev/null 2>&1; }

if [[ "$SECRET_CONFIG_READY" != "true" ]]; then
  block DR_SECRET_FILE_MISSING_OR_UNREADABLE
elif ! dr_resolve_ssh_key_config; then
  block SSH_KEY_MISSING_FROM_DR_SECRET_FILE
elif ! dr_validate_ssh_key_files; then
  block SSH_KEY_FILES_MISSING_OR_UNREADABLE
else
  pass SSH_KEY_AND_TERRAFORM_PUBLIC_KEY_READABLE
fi

lock_free() {
  local label="$1" path="$2"
  if [[ ! -e "$path" ]]; then
    pass "$label (no lock file)"
  elif [[ -f "$path" ]] && flock -n "$path" -c true 2>/dev/null; then
    pass "$label (unlocked)"
  else
    block "${label}_ACTIVE"
  fi
}

printf '%s\n' WEB_FAILOVER_PREFLIGHT_BEGIN

if systemctl is-active --quiet hospital-dr-chatops.service 2>/dev/null; then
  pass CHATOPS_SERVICE_ACTIVE
else
  block CHATOPS_SERVICE_INACTIVE
fi

approval_required="${DR_APPROVAL_REQUIRED:-2}"
admin_count="$(SLACK_ADMIN_USER_IDS="${SLACK_ADMIN_USER_IDS:-}" python3 -c 'import os; print(len({item.strip() for item in os.environ.get("SLACK_ADMIN_USER_IDS", "").split(",") if item.strip()}))')"
printf 'APPROVAL_REQUIRED=%s\n' "$approval_required"
printf 'ALLOWLIST_ADMIN_COUNT=%s\n' "$admin_count"
if [[ "$approval_required" == 1 ]]; then
  block PRODUCTION_TWO_ADMIN_POLICY_REQUIRED_SINGLE_ADMIN_IS_SYNTHETIC_DEMO_ONLY
elif [[ "$approval_required" == 2 && "$admin_count" -ge 2 ]]; then
  pass TWO_PERSON_APPROVAL_POLICY_AND_ALLOWLIST
else
  block APPROVAL_POLICY_OR_ADMIN_ALLOWLIST_INVALID
fi

if [[ -r "$DR_STATE_FILE" ]]; then
  dr_state="$(dr_state_read 2>/dev/null || true)"
  printf 'DR_STATE=%s\n' "${dr_state:-UNKNOWN}"
  case "$dr_state" in
    IDLE|FAILED) pass DR_STATE_RETRYABLE_OR_IDLE ;;
    *) block DR_STATE_NOT_RETRYABLE ;;
  esac
else
  block DR_STATE_FILE_MISSING
fi

lock_free CHATOPS_EXECUTION_LOCK "$CHATOPS_LOCK"
lock_free WORKFLOW_LOCK "$WORKFLOW_LOCK"
lock_free FAILOVER_LOCK "$FAILOVER_LOCK"
lock_free FAILBACK_LOCK "$FAILBACK_LOCK"
lock_free ENVIRONMENT_LOCK "$ENVIRONMENT_LOCK"

pending_count="$(python3 - "$CHATOPS_STATE_DB" <<'PY'
import sqlite3
import sys

try:
    connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=2)
    row = connection.execute(
        "SELECT COUNT(*) FROM approval_requests WHERE status IN ('PENDING','PARTIALLY_APPROVED','EXECUTING')"
    ).fetchone()
    connection.close()
    print(int(row[0]))
except (OSError, sqlite3.Error, TypeError, ValueError):
    print("UNKNOWN")
PY
  )"
printf 'ACTIVE_APPROVAL_REQUESTS=%s\n' "$pending_count"
if [[ "$pending_count" == 0 ]]; then pass NO_ACTIVE_APPROVAL_REQUESTS; else block ACTIVE_APPROVAL_REQUESTS_PRESENT; fi

if ! command_available aws || ! aws sts get-caller-identity >/dev/null 2>&1; then
  block AWS_READ_ONLY_CREDENTIALS_UNAVAILABLE
else
  pass AWS_READ_ONLY_CREDENTIALS
  instances_json="$(aws ec2 describe-instances --region "$AWS_REGION" \
    --filters 'Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server' \
    --output json 2>/dev/null || true)"
  if plan="$(printf '%s\n' "$instances_json" | python3 "$SCRIPT_DIR/ec2_start_plan.py" --require-running 2>/dev/null)"; then
    pass APPROVED_EC2_IDENTITY_PRIVATE_IPS_RUNNING
    printf 'EC2_ROLE_STATES=%s\n' "$(awk -F '\t' '{printf "%s=%s ", $1, $3}' <<< "$plan" | sed 's/[[:space:]]*$//')"
    mapfile -t instance_ids < <(awk -F '\t' '{print $2}' <<< "$plan")
    web_id="${instance_ids[0]}"
    doc_id="${instance_ids[1]}"
    aws_status="$(aws ec2 describe-instance-status --region "$AWS_REGION" \
      --include-all-instances --instance-ids "${instance_ids[@]}" --output json 2>/dev/null || true)"
    if printf '%s' "$aws_status" | python3 -c '
import json,sys
try:
    items=json.load(sys.stdin).get("InstanceStatuses",[])
    ok=len(items)==3 and all(i.get("SystemStatus",{}).get("Status")=="ok" and i.get("InstanceStatus",{}).get("Status")=="ok" for i in items)
except (TypeError,ValueError): ok=False
raise SystemExit(0 if ok else 1)
'; then pass AWS_SYSTEM_AND_INSTANCE_STATUS_OK; else block AWS_INSTANCE_STATUS_NOT_OK; fi

    ssm_status="$(aws ssm describe-instance-information --region "$AWS_REGION" \
      --filters "Key=InstanceIds,Values=${web_id}" --output json 2>/dev/null || true)"
    if printf '%s' "$ssm_status" | WEB_ID="$web_id" python3 -c '
import json,os,sys
try:
    items=json.load(sys.stdin).get("InstanceInformationList",[])
    online={i.get("InstanceId") for i in items if i.get("PingStatus")=="Online"}
    ok=os.environ["WEB_ID"] in online
except (TypeError,ValueError): ok=False
raise SystemExit(0 if ok else 1)
'; then
      pass SSM_WEB_ONLINE
      pass DOC_SSH_JUMP_VIA_WEB_TRANSPORT
    else
      block SSM_WEB_NOT_ONLINE
    fi
  else
    block APPROVED_EC2_IDENTITY_OR_RUNNING_STATE_MISMATCH
    instance_ids=()
  fi
fi

if [[ "${#instance_ids[@]}" -eq 0 ]]; then
  web_id="AWS_RESOURCE_ID_REDACTED"
  doc_id="AWS_RESOURCE_ID_REDACTED"
fi

if dr_dns_validate_aws_web_eip_association "$DR_WEB_EIP_EXPECTED" "$DR_WEB_EIP_EXPECTED" "$AWS_REGION"; then
  pass APPROVED_WEB_EIP_ASSOCIATION
else
  block APPROVED_WEB_EIP_ASSOCIATION_INVALID
fi

if [[ -n "$SSH_KEY" && -r "$SSH_KEY" && -r "$DR_SSH_CONFIG_FILE" && -r "$DR_SSH_KNOWN_HOSTS_FILE" ]] \
  && dr_ssm_require_tools >/dev/null 2>&1; then
  pass SSM_SSH_LOCAL_PREREQUISITES
  web_container="$(ssh -F "$DR_SSH_CONFIG_FILE" -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$DR_SSH_KNOWN_HOSTS_FILE" dr-web \
    'sudo docker inspect --format "{{.State.Running}} {{.State.Health.Status}}" hospital-dr-web' 2>/dev/null || true)"
  if [[ "$web_container" == "true healthy" ]]; then pass WEB_CONTAINER_HEALTHY; else block WEB_CONTAINER_NOT_HEALTHY; fi
  doc_container="$(ssh -F "$DR_SSH_CONFIG_FILE" -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$DR_SSH_KNOWN_HOSTS_FILE" dr-doc \
    'sudo docker inspect --format "{{.State.Running}} {{.State.Health.Status}}" hospital-dr-emr' 2>/dev/null || true)"
  if [[ "$doc_container" == "true healthy" ]]; then pass EMR_CONTAINER_HEALTHY; else block EMR_CONTAINER_NOT_HEALTHY; fi
else
  block SSM_SSH_CONFIG_OR_KEY_UNAVAILABLE
fi

if command_available ansible && [[ -r "$INVENTORY" ]]; then
  ansible_output="$(mktemp "$TMP_DIR/ansible.XXXXXX")"
  if ansible -i "$INVENTORY" 'web_servers:doc_servers' -m ansible.builtin.ping -o >"$ansible_output" 2>&1; then
    pass ANSIBLE_WEB_EMR_PING
  else
    block ANSIBLE_WEB_EMR_CONNECTION_FAILED
  fi
else
  block ANSIBLE_OR_INVENTORY_UNAVAILABLE
fi

# The live full_failover runner invokes this read-only gate. Include it here
# so the Web preflight catches a failure before the DNS transaction begins.
nat_status_rc=0
nat_status_output=""
nat_bootstrap_status=""
nat_bootstrap_candidate_verified=false
if [[ -x "$NAT_INSTANCE_STATUS_SCRIPT" ]]; then
  nat_status_output="$(AWS_REGION="$AWS_REGION" bash "$NAT_INSTANCE_STATUS_SCRIPT" 2>&1)"
  nat_status_rc=$?
  nat_bootstrap_status="$(awk -F= '$1 == "NAT_BOOTSTRAP_STATUS" { count++; value=$2 } END { if (count == 1) print value }' <<< "$nat_status_output")"
  if [[ "$nat_status_rc" -le 2 \
    && "$nat_bootstrap_status" == READY_FOR_GUEST_CONFIGURATION \
    && "$(awk -F= '$1 == "NAT_INSTANCE_STATUS" { count++; value=$2 } END { if (count == 1) print value }' <<< "$nat_status_output")" == PENDING_LIVE_TEST \
    && "$(awk -F= '$1 == "CURRENT_EGRESS_MODE" { count++; value=$2 } END { if (count == 1) print value }' <<< "$nat_status_output")" == WEB_NAT_INSTANCE_CANDIDATE ]]; then
    pass WEB_NAT_BOOTSTRAP_AWS_CANDIDATE
    nat_bootstrap_candidate_verified=true
  else
    block WEB_NAT_BOOTSTRAP_NOT_READY
  fi
  grep -E '^(CURRENT_EGRESS_MODE|NAT_INSTANCE_STATUS|NAT_BOOTSTRAP_STATUS|WEB_EIP_(PUBLIC_IP|ASSOCIATION|INSTANCE_ID|ENI|PRIVATE_IP)|PRIVATE_DEFAULT_ROUTE_STATE|PRIVATE_DEFAULT_ROUTE_TARGET|SOURCE_DEST_CHECK)=' \
    <<< "$nat_status_output" || true
else
  block WEB_NAT_INSTANCE_STATUS_SCRIPT_MISSING
fi

# An AWS-only result is bootstrap readiness, never final NAT READY. The Web
# guest and a private-subnet data-plane probe must both pass before the legacy
# final executor contract is emitted.
if [[ "$nat_bootstrap_candidate_verified" == true ]]; then
  nat_guest_output="$(ssh -F "$DR_SSH_CONFIG_FILE" -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$DR_SSH_KNOWN_HOSTS_FILE" dr-web \
    'sudo /usr/local/sbin/hospital-dr-web-nat-instance verify' 2>/dev/null || true)"
  nat_guest_status="$(awk -F= '$1 == "NAT_GUEST_STATUS" { count++; value=$2; gsub(/\r/, "", value) } END { if (count == 1) print value }' <<< "$nat_guest_output")"
  nat_final_ready=true
  if [[ "$nat_guest_status" == READY ]]; then
    pass WEB_NAT_GUEST_CONFIGURATION
  else
    block WEB_NAT_GUEST_CONFIGURATION_UNVERIFIED
    nat_final_ready=false
  fi

  if [[ "$nat_final_ready" == true ]]; then
    private_egress_ip="$(ssh -F "$DR_SSH_CONFIG_FILE" -o BatchMode=yes -o StrictHostKeyChecking=yes \
      -o "UserKnownHostsFile=$DR_SSH_KNOWN_HOSTS_FILE" dr-doc \
      'curl --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com/' 2>/dev/null \
      | tr -d '\r\n' || true)"
    if [[ "$private_egress_ip" == "$DR_WEB_EIP_EXPECTED" ]]; then
      pass PRIVATE_SUBNET_EGRESS_VIA_WEB_EIP
    else
      block PRIVATE_SUBNET_EGRESS_NOT_VERIFIED
      nat_final_ready=false
    fi
  fi
  if [[ "$nat_final_ready" == true ]]; then
    printf 'CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE\nNAT_INSTANCE_STATUS=READY\n'
    pass WEB_NAT_INSTANCE_RUNNER_GATE
  else
    block WEB_NAT_INSTANCE_RUNNER_GATE_NOT_READY
  fi
else
  warn NAT_FINAL_READY_PENDING_BOOTSTRAP
fi

CF_ZONE_ID="${CF_ZONE_ID:-}"
if [[ ! "$CF_ZONE_ID" =~ ^[0-9a-fA-F]{32}$ ]]; then
  block CLOUDFLARE_ZONE_ID_MISSING_OR_INVALID
elif load_cloudflare_ssm_token >/dev/null 2>&1; then
  verify_file="$TMP_DIR/token-verify.json"
  if curl -fsS --connect-timeout 5 --max-time 15 \
      'https://api.cloudflare.com/client/v4/user/tokens/verify' \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H 'Content-Type: application/json' >"$verify_file" 2>/dev/null \
      && python3 - "$verify_file" <<'PY'
import json,sys
try:
    data=json.load(open(sys.argv[1],encoding="utf-8"))
    valid=data.get("success") is True and data.get("result",{}).get("status")=="active"
except (OSError,TypeError,ValueError): valid=False
raise SystemExit(0 if valid else 1)
PY
  then
    pass CLOUDFLARE_TOKEN_ACTIVE_READ_ONLY
  else
    block CLOUDFLARE_TOKEN_VERIFY_FAILED
  fi

  if dr_dns_snapshot_record "$DR_DOMAIN" "$TMP_DIR/web.json" "$CF_RECORD_ID_EXPECTED" >/dev/null \
      && dr_dns_snapshot_record "$EMR_DOMAIN" "$TMP_DIR/emr.json" "$CF_EMR_RECORD_ID_EXPECTED" >/dev/null \
      && dr_dns_validate_snapshot_pair "$TMP_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
      && dr_dns_validate_origin_pair "$TMP_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
        "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED"; then
    pass CLOUDFLARE_APPROVED_ONPREM_DNS_PAIR_READBACK
  else
    block CLOUDFLARE_ORIGIN_PAIR_OR_RECORD_ID_MISMATCH
  fi

  if [[ -d "$ORIGIN_DIR" ]]; then
    if dr_dns_validate_origin_pair "$ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
        "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED" \
      && dr_dns_snapshot_pairs_equal "$TMP_DIR" "$ORIGIN_DIR"; then
      pass PERSISTENT_DNS_ROLLBACK_SNAPSHOT_MATCHES_LIVE_ORIGIN
    else
      block PERSISTENT_DNS_ROLLBACK_SNAPSHOT_CONFLICT
    fi
  else
    snapshot_parent="$(dirname -- "$ORIGIN_DIR")"
    if python3 - "$snapshot_parent" <<'PY'
import os,sys
path=os.path.abspath(sys.argv[1])
while not os.path.exists(path):
    parent=os.path.dirname(path)
    if parent==path: break
    path=parent
ok=os.path.isdir(path) and os.access(path,os.W_OK|os.X_OK)
raise SystemExit(0 if ok else 1)
PY
    then
      pass DNS_ORIGIN_SNAPSHOT_CAN_BE_CREATED_LOCAL_PERMISSION_CHECK
    else
      block DNS_ORIGIN_SNAPSHOT_DIRECTORY_NOT_WRITABLE
    fi
  fi
  if declare -F dr_dns_rollback_snapshots >/dev/null; then
    pass DNS_ROLLBACK_CODE_AND_READBACK_AVAILABLE
  else
    block DNS_ROLLBACK_HELPER_MISSING
  fi
  dns_test_window="$(python3 "$SCRIPT_DIR/validate_live_dns_test_window.py" \
    "${DR_CLOUDFLARE_LIVE_DNS_TEST_MODE:-false}" \
    "${DR_CLOUDFLARE_LIVE_DNS_TEST_EXPIRES_AT:-}" 2>/dev/null || true)"
  printf '%s\n' 'CLOUDFLARE_DNS_WRITE_PERMISSION=UNVERIFIED_NO_PUT'
  case "$dns_test_window" in
    ACTIVE)
      printf '%s\n' 'CLOUDFLARE_LIVE_DNS_TEST_MODE=ACTIVE'
      warn CLOUDFLARE_DNS_EDIT_UNVERIFIED_LIVE_TEST_WINDOW_ACTIVE_NO_PUT
      ;;
    INACTIVE)
      printf '%s\n' 'CLOUDFLARE_LIVE_DNS_TEST_MODE=INACTIVE'
      block CLOUDFLARE_DNS_WRITE_SCOPE_UNVERIFIED_NO_PUT_PERFORMED
      ;;
    *)
      printf '%s\n' 'CLOUDFLARE_LIVE_DNS_TEST_MODE=INVALID_OR_EXPIRED'
      block CLOUDFLARE_LIVE_DNS_TEST_WINDOW_INVALID_OR_EXPIRED
      ;;
  esac
else
  block CLOUDFLARE_TOKEN_UNAVAILABLE
fi

# These are deliberately not gates for this Web/EMR-only cutover objective.
printf '%s\n' 'ECR_REDEPLOY=NOT_REQUIRED_IF_EXISTING_WEB_EMR_CONTAINERS_HEALTHY' \
  'DB_NR=OUT_OF_SCOPE_FOR_WEB_EMR_DNS_CUTOVER' \
  'WAZUH=OUT_OF_SCOPE_FOR_WEB_EMR_DNS_CUTOVER' \
  'SNMP=OUT_OF_SCOPE_FOR_WEB_EMR_DNS_CUTOVER' \
  'ONPREM_PUBLIC_HTTP_HEALTH=NOT_USED_AS_PRE_CUTOVER_GATE'

if ((${#BLOCKERS[@]} == 0)); then
  printf 'WEB_FAILOVER_PREFLIGHT_READY=true\n'
else
  printf 'WEB_FAILOVER_PREFLIGHT_READY=false\n'
fi
if ((${#BLOCKERS[@]})); then
  printf 'WEB_FAILOVER_PREFLIGHT_BLOCKERS=%s\n' "$(IFS=,; echo "${BLOCKERS[*]}")"
else
  printf 'WEB_FAILOVER_PREFLIGHT_BLOCKERS=NONE\n'
fi
if ((${#WARNINGS[@]})); then
  printf 'WEB_FAILOVER_PREFLIGHT_WARNINGS=%s\n' "$(IFS=,; echo "${WARNINGS[*]}")"
else
  printf 'WEB_FAILOVER_PREFLIGHT_WARNINGS=NONE\n'
fi
unset CLOUDFLARE_API_TOKEN CF_API_TOKEN
printf '%s\n' WEB_FAILOVER_PREFLIGHT_END
(( ${#BLOCKERS[@]} == 0 ))
