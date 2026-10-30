#!/usr/bin/env bash
set -euo pipefail
umask 027

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
source "$DR_RUNTIME_DIR/ec2_start_actions.sh"
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

REGION="${AWS_REGION:-ap-northeast-2}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
DR_WEB_PRIVATE_IP_EXPECTED="${DR_WEB_PRIVATE_IP_EXPECTED:-IP_REDACTED}"
ONPREM_TUNNEL_HOST="${ONPREM_TUNNEL_HOST:-e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com}"
ONPREM_EMR_DNS_IP_EXPECTED="${ONPREM_EMR_DNS_IP_EXPECTED:-IP_REDACTED}"
DR_CF_WEB_RECORD_ID_EXPECTED="${DR_CF_WEB_RECORD_ID_EXPECTED:-${CF_RECORD_ID:-4c35b40ec154fb21c92fc3795ce9d5ea}}"
DR_CF_EMR_RECORD_ID_EXPECTED="${DR_CF_EMR_RECORD_ID_EXPECTED:-${CF_EMR_RECORD_ID:-4a4432c4e6290bcbd3dda5113ff8d560}}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
INVENTORY="${INVENTORY:-${DR_STATE_DIR}/ssh/active-recovery-inventory.ini}"
SSH_KEY="${SSH_KEY:-${DR_SSH_PRIVATE_KEY:-${DR_SSH_KEY:-}}}"
ENV_LOCK="${DR_ENVIRONMENT_LOCK_FILE:-${DR_STATE_DIR}/environment.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
LOG_DIR="${DR_RECOVERY_LOG_DIR:-${DR_STATE_DIR}/logs}"
LOG_FILE="${DR_ACTIVE_RECOVERY_LOG:-${LOG_DIR}/recover_active_dr_after_cost_shutdown.log}"
DNS_TX_DIR="${DR_ACTIVE_RECOVERY_DNS_TX_DIR:-${DR_STATE_DIR}/dns/active-recovery-$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}}"
DNS_ORIGIN_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
SHUTDOWN_RULE="hospital-dr-daily-safety-shutdown"
DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
DR_STATE_TRANSITION_STARTED=0

fail() {
  echo "[ACTIVE DR RECOVERY BLOCKED] $*" >&2
  return 1
}

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "Required configuration is missing: ${name}."
  fi
}

if [ "$#" -ne 0 ]; then
  echo "Usage: $0" >&2
  exit 2
fi

if [ ! -f "$DR_SECRET_FILE" ] || [ ! -r "$DR_SECRET_FILE" ]; then
  fail "DR_SECRET_FILE is missing or unreadable."
  exit 1
fi
dr_load_secret_file
dr_resolve_ssh_key_config
dr_validate_ssh_key_files
SSH_KEY="${SSH_KEY:-$DR_SSH_PRIVATE_KEY}"
require_config SSH_KEY
require_config CF_ZONE_ID

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  fail "AWS credentials are missing, expired, or invalid."
  exit 1
fi
if ! dr_ssm_require_tools; then
  fail "SSM SSH tools are unavailable; direct SSH fallback is disabled."
  exit 1
fi

if [ ! -r "$DR_STATE_FILE" ]; then
  fail "Persistent DR state is missing or unreadable; refusing to initialize it implicitly."
  exit 1
fi
mkdir -p "$LOG_DIR" "$(dirname -- "$DNS_TX_DIR")"
chmod 0750 "$LOG_DIR" "$(dirname -- "$DNS_TX_DIR")"
dr_state_prepare
dr_workflow_lock_prepare
exec 7>>"$WORKFLOW_LOCK_FILE"
if ! flock -n 7; then
  fail "Another DR workflow holds the global execution lock."
  exit 1
fi
exec 8>>"$ENV_LOCK"
if ! flock -n 8; then
  fail "Another environment lifecycle operation is running."
  exit 1
fi
exec > >(tee -a "$LOG_FILE") 2>&1

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$DR_STATE_TRANSITION_STARTED" = "1" ]; then
    dr_state_mark_failure "$DR_STATE_FAILURE_STATUS" >/dev/null 2>&1 || true
    echo "[ACTIVE DR RECOVERY] Failed after transition; state recorded as ${DR_STATE_FAILURE_STATUS}."
  fi
  exit "$rc"
}
trap on_exit EXIT

current_state="$(dr_state_read)"
if [ "$current_state" != "DR_ACTIVE" ]; then
  fail "This recovery is only for the verified cost-shutdown state (expected DR_ACTIVE, found ${current_state})."
  exit 1
fi

shutdown_rule_state="$(aws events describe-rule --region "$REGION" \
  --name "$SHUTDOWN_RULE" --query State --output text 2>/dev/null || true)"
if [ "$shutdown_rule_state" != "DISABLED" ]; then
  fail "The daily shutdown rule is not disabled; refusing to restart into another scheduled stop."
  exit 1
fi

require_config CF_ZONE_ID
load_cloudflare_ssm_token
mkdir -p "$DNS_TX_DIR"
chmod 0750 "$DNS_TX_DIR"
CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-$DR_CF_WEB_RECORD_ID_EXPECTED}")"
CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-$DR_CF_EMR_RECORD_ID_EXPECTED}")"
dr_dns_validate_snapshot_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
  || { fail "Current Cloudflare record snapshot is invalid."; exit 1; }
if [ "$(dr_dns_snapshot_id "$DNS_TX_DIR/web.json")" != "$DR_CF_WEB_RECORD_ID_EXPECTED" ] \
  || [ "$(dr_dns_snapshot_id "$DNS_TX_DIR/emr.json")" != "$DR_CF_EMR_RECORD_ID_EXPECTED" ]; then
  fail "Cloudflare record IDs do not match the approved Web/EMR pair."
  exit 1
fi
if ! dr_dns_validate_origin_pair "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
    "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED"; then
  fail "The preserved On-Prem DNS snapshot is invalid; it will not be replaced."
  exit 1
fi
if ! dr_dns_snapshot_pairs_equal_ids "$DNS_TX_DIR" "$DNS_ORIGIN_DIR"; then
  fail "Cloudflare record IDs differ from the preserved origin snapshot."
  exit 1
fi

# Accept the fully restored On-Prem pair written by the updated scheduled
# shutdown, plus the exact legacy split written by the previously deployed
# Lambda (Web On-Prem, EMR still at the approved DR EIP).
if ! python3 - "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
    "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED" <<'PY'
import json
import os
import sys

directory, web_name, emr_name, tunnel_host, dr_ip, onprem_emr_ip = sys.argv[1:]
try:
    with open(os.path.join(directory, "web.json"), encoding="utf-8") as stream:
        web = json.load(stream)["payload"]
    with open(os.path.join(directory, "emr.json"), encoding="utf-8") as stream:
        emr = json.load(stream)["payload"]
    valid_web = (
        web.get("name") == web_name
        and web.get("type") == "CNAME"
        and str(web.get("content", "")).rstrip(".").lower()
        == tunnel_host.rstrip(".").lower()
        and web.get("proxied") is True
    )
    emr_onprem = (
        emr.get("name") == emr_name
        and emr.get("type") == "A"
        and emr.get("content") == onprem_emr_ip
        and emr.get("proxied") is True
    )
    emr_legacy_split = (
        emr.get("name") == emr_name
        and emr.get("type") == "A"
        and emr.get("content") == dr_ip
        and emr.get("proxied") is True
    )
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    valid_web = emr_onprem = emr_legacy_split = False
if not (valid_web and (emr_onprem or emr_legacy_split)):
    raise SystemExit(1)
PY
then
  fail "Current DNS is not a recognized post-shutdown On-Prem pair; no AWS or DNS changes made."
  exit 1
fi

if ! dr_dns_validate_aws_web_eip_association "$DR_WEB_EIP_EXPECTED" \
    "$DR_WEB_EIP_EXPECTED" "$REGION"; then
  fail "The approved Web EIP is not associated with the expected Web instance."
  exit 1
fi

if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
    --output json)"; then
  fail "Could not read the tagged DR instance inventory."
  exit 1
fi
plan_script="$DR_RUNTIME_DIR/ec2_start_plan.py"
if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")"; then
  fail "DR instance identity/state validation failed."
  exit 1
fi
if ! printf '%s\n' "$plan" | awk -F '\t' 'NF != 4 || $3 != "stopped" { bad=1 } END { exit (bad || NR != 3) }'; then
  fail "Expected exactly the three approved DR instances, all stopped by the shutdown action."
  exit 1
fi
mapfile -t INSTANCE_IDS < <(awk -F '\t' '{print $2}' <<< "$plan")

if ! dr_prepare_ssh_known_hosts; then
  fail "Could not prepare the persistent SSH known_hosts path."
  exit 1
fi

echo "[ACTIVE DR RECOVERY] Preconditions passed; beginning audited recovery of the existing DR environment."
dr_state_write FAILOVER_EXECUTING
DR_STATE_TRANSITION_STARTED=1
dr_state_flag_clear

dr_ec2_start_instances_safely "$REGION" "$inventory_json"
aws ec2 wait instance-running --region "$REGION" --instance-ids "${INSTANCE_IDS[@]}"
aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "${INSTANCE_IDS[@]}"

inventory_json="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
  --output json)"
plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script" --require-running)"
mapfile -t INSTANCE_IDS < <(awk -F '\t' '{print $2}' <<< "$plan")
web_instance_id="$(dr_ssm_discover_web_instance_id "$REGION" "$DR_WEB_PRIVATE_IP_EXPECTED")"
dr_ssm_write_ssh_config "$REGION" "$web_instance_id" "$SSH_KEY" \
  "$DR_SSH_KNOWN_HOSTS_FILE" "${DR_DOC_PRIVATE_IP:-IP_REDACTED}" \
  "${DR_DB_PRIVATE_IP:-IP_REDACTED}"
dr_ssm_write_ansible_inventory "$INVENTORY" "$SSH_KEY" "$DR_SSH_CONFIG_FILE"

dr_ssm_wait_for_ssh "DR Web instance ${web_instance_id}" dr-web 18 5
dr_ssm_wait_for_ssh "DR Doc ${DR_DOC_PRIVATE_IP:-IP_REDACTED} through DR Web" dr-doc 18 5
dr_ssm_wait_for_ssh "DR DB ${DR_DB_PRIVATE_IP:-IP_REDACTED} through DR Web" dr-db 18 5

dr_ssm_ssh dr-web 'set -eu
sudo systemctl start docker nginx
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-web 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-web >/dev/null; fi
health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-web 2>/dev/null || true)"
[ "$health" = "healthy" ]' >/dev/null
dr_ssm_ssh dr-doc 'set -eu
sudo systemctl start docker apache2
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-emr 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-emr >/dev/null; fi
health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-emr 2>/dev/null || true)"
[ "$health" = "healthy" ]' >/dev/null
dr_ssm_ssh dr-db 'set -eu; sudo systemctl is-active --quiet mysql' >/dev/null

if ! dr_dns_validate_aws_web_eip "$DR_WEB_EIP_EXPECTED" "$DR_WEB_EIP_EXPECTED" "$REGION"; then
  fail "Running DR Web identity/EIP/source-destination validation failed."
  exit 1
fi

web_id="$(dr_dns_snapshot_id "$DNS_TX_DIR/web.json")"
emr_id="$(dr_dns_snapshot_id "$DNS_TX_DIR/emr.json")"
web_payload="$(dr_dns_payload A "$DR_DOMAIN" "$DR_WEB_EIP_EXPECTED")"
emr_payload="$(dr_dns_payload A "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED")"
echo "[ACTIVE DR RECOVERY] Updating the approved Web and EMR records to the verified DR EIP."
if ! dr_dns_apply_records "$DNS_TX_DIR" \
    "$web_id" "$web_payload" "recovery:$DR_DOMAIN" \
    "$emr_id" "$emr_payload" "recovery:$EMR_DOMAIN"; then
  fail "Cloudflare update/read-back failed; transaction helper attempted to restore the pre-recovery pair."
  exit 1
fi

if ! dr_dns_check_public_health "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/" \
    "$EMR_HEALTH_CHECK_HEADER" "${PUBLIC_HEALTH_ATTEMPTS:-30}" \
    "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}" "Public DR"; then
  echo "[ACTIVE DR RECOVERY] Public health failed; restoring the exact pre-recovery DNS pair."
  if dr_dns_rollback_snapshots "$DNS_TX_DIR"; then
    echo "[ACTIVE DR RECOVERY] Pre-recovery DNS pair restored and read-back verified."
  else
    echo "[ACTIVE DR RECOVERY ERROR] DNS rollback failed; inspect the transaction snapshots immediately." >&2
  fi
  fail "Public Web/EMR health did not pass. EC2 remains running for diagnosis; it will not be auto-stopped."
  exit 1
fi

dr_state_write DR_ACTIVE
DR_STATE_TRANSITION_STARTED=0
echo "[ACTIVE DR RECOVERY COMPLETE] Web, EMR, DB service checks and public Web/EMR health passed."
echo "DR_STATE=DR_ACTIVE"
echo "WEB_URL=https://$DR_DOMAIN/"
echo "EMR_URL=https://$EMR_DOMAIN/"
echo "AWS_MUTATION=STARTED_ONLY_APPROVED_STOPPED_DR_INSTANCES"
echo "DNS_MUTATION=WEB_AND_EMR_TO_APPROVED_DR_EIP"
echo "NAT_DB_DATA_WIREGUARD=UNCHANGED"
