#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$BASH_SOURCE")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

LOCK_FILE="${DR_FAILBACK_DNS_LOCK_FILE:-${DR_STATE_DIR}/failback-dns.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/failback.log}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
ONPREM_WEB_IP="${ONPREM_WEB_IP:-}"
ONPREM_WEB_PORT="${ONPREM_WEB_PORT:-80}"
ONPREM_HEALTH_URL="${ONPREM_HEALTH_URL:-}"
ONPREM_EMR_HEALTH_URL="${ONPREM_EMR_HEALTH_URL:-}"
ONPREM_TUNNEL_HOST="${ONPREM_TUNNEL_HOST:-e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
DNS_TX_DIR="${DR_DNS_TX_DIR:-${DR_STATE_DIR}/dns/failback-${BASHPID}}"
DNS_ORIGIN_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DNS_ARCHIVE_DIR="${DR_DNS_ORIGIN_ARCHIVE_DIR:-${DR_STATE_DIR}/dns/origin-archive}"
mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
    echo "[FAILBACK] Another DR workflow is already in progress."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[FAILBACK] Another DNS failback workflow is already in progress."
  exit 1
fi

if [ -r "$DR_TIMING_SCRIPT" ]; then
  # shellcheck disable=SC1091
  source "$DR_TIMING_SCRIPT"
else
  dr_timing_start() { printf '0\n'; }
  dr_timing_end() { :; }
fi

DR_STATE_FAILURE_STATUS=FAILED
initial_failback_state="$(dr_state_read 2>/dev/null || true)"
if [ "$initial_failback_state" = "DR_ACTIVE" ] \
    || { [ "${DR_FAILBACK_CONTROLLER:-0}" = "1" ] && [ "$initial_failback_state" = "FAILBACK_EXECUTING" ]; }; then
  DR_STATE_FAILURE_STATUS=DR_ACTIVE
fi
trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; exit "$rc"' ERR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: $name."
    return 1
  fi
}

SECRET_FILE="$DR_SECRET_FILE"
load_failback_secrets() {
  local controller_was_set="${DR_FAILBACK_CONTROLLER+x}"
  local controller_from_caller="${DR_FAILBACK_CONTROLLER-}"
  dr_load_secret_file || return 1
  # The full workflow owns the final archive and state transition. A dr.env
  # value must not disable that handoff when the caller set the marker.
  if [ "$controller_was_set" = "x" ]; then
    DR_FAILBACK_CONTROLLER="$controller_from_caller"
  else
    unset DR_FAILBACK_CONTROLLER
  fi
}
load_failback_secrets
unset -f load_failback_secrets

ONPREM_HEALTH_URL="${ONPREM_HEALTH_URL:-${ONPREM_WEB_HEALTH_URL:-}}"
ONPREM_EMR_HEALTH_URL="${ONPREM_EMR_HEALTH_URL:-${ONPREM_DOC_HEALTH_URL:-}}"
if [ -z "$ONPREM_HEALTH_URL" ] && [ -n "${ONPREM_WEB_IP:-}" ]; then
  ONPREM_HEALTH_URL="http://${ONPREM_WEB_IP}:${ONPREM_WEB_PORT}/"
fi
if [ -z "$ONPREM_EMR_HEALTH_URL" ] && [ -n "${ONPREM_WEB_IP:-}" ]; then
  ONPREM_EMR_HEALTH_URL="http://${ONPREM_WEB_IP}:${ONPREM_WEB_PORT}/emr/"
fi
CF_ZONE_ID="${CF_ZONE_ID:-}"
require_config "CF_ZONE_ID"
require_config "ONPREM_HEALTH_URL"
require_config "ONPREM_EMR_HEALTH_URL"

load_cloudflare_ssm_token

prepare_dns_snapshot() {
  mkdir -p "$DNS_TX_DIR"
  chmod 0750 "$DNS_TX_DIR"
  CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-}")"
  CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-}")"
  dr_dns_validate_snapshot_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN"
}

check_public_health() {
  local attempts="${1:-12}"
  dr_dns_check_public_health "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/" \
    "$EMR_HEALTH_CHECK_HEADER" "$attempts" \
    "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}" "Public failback"
}

preflight_failback_only() {
  local state
  state="$(dr_state_read 2>/dev/null || true)"
  if [ "${DR_FAILBACK_CONTROLLER:-0}" = "1" ] && [ "$state" != "FAILBACK_EXECUTING" ]; then
    echo "[DNS PREFLIGHT BLOCKED] The parent Failback workflow state changed unexpectedly."
    return 1
  fi

  echo "[DNS PREFLIGHT] Checking On-Prem Web and EMR Health without changing DNS."
  if ! curl -fsS --connect-timeout 5 --max-time 15 "$ONPREM_HEALTH_URL" >/dev/null \
      || ! curl -fsS --connect-timeout 5 --max-time 15 \
        -H "X-Hospital-DR-Check: $EMR_HEALTH_CHECK_HEADER" "$ONPREM_EMR_HEALTH_URL" >/dev/null; then
    echo "[DNS PREFLIGHT BLOCKED] On-Prem Web or EMR Health did not pass."
    mark_state_from_current_dns
    return 1
  fi

  prepare_dns_snapshot
  if ! dr_dns_validate_origin_pair \
      "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
      "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED"; then
    echo "[DNS PREFLIGHT BLOCKED] The preserved On-Prem DNS snapshot is missing or invalid."
    mark_state_from_current_dns
    return 1
  fi
  if ! dr_dns_validate_dr_pair \
      "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
    echo "[DNS PREFLIGHT BLOCKED] Current DNS is not the verified AWS DR Web/EMR pair."
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    return 1
  fi
  echo "[DNS PREFLIGHT] On-Prem Health, current DR DNS, and preserved origin snapshot passed; no DNS records changed."
}

mark_state_from_current_dns() {
  if prepare_dns_snapshot \
      && dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
    DR_STATE_FAILURE_STATUS=DR_ACTIVE
    dr_state_write DR_ACTIVE 2>/dev/null || true
  else
    # Without a verified DR pair, DR_ACTIVE would misrepresent DNS state.
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
}

echo "=================================================="
if [ "${1:-}" = "--preflight-only" ]; then
  preflight_failback_only
  exit $?
fi

echo "[$(date)] Web traffic failback workflow started."
echo "=================================================="
dr_state_write FAILBACK_EXECUTING

echo "[VALIDATION] Checking on-premise Web and EMR health before DNS failback."
health_timing_start="$(dr_timing_start failback_health)"
for attempt in $(seq 1 "${ONPREM_HEALTH_ATTEMPTS:-12}"); do
  if curl -fsS --connect-timeout 5 --max-time 15 "$ONPREM_HEALTH_URL" >/dev/null \
     && curl -fsS --connect-timeout 5 --max-time 15 \
       -H "X-Hospital-DR-Check: $EMR_HEALTH_CHECK_HEADER" "$ONPREM_EMR_HEALTH_URL" >/dev/null; then
    echo "[VALIDATION] On-premise Web and EMR health checks passed."
    break
  fi
  if [ "$attempt" -eq "${ONPREM_HEALTH_ATTEMPTS:-12}" ]; then
    echo "[VALIDATION ERROR] On-premise web service is not healthy. DNS failback aborted."
    mark_state_from_current_dns
    exit 1
  fi
  echo "[VALIDATION] Waiting for on-premise web response ($attempt/${ONPREM_HEALTH_ATTEMPTS:-12})."
  sleep 5
done
dr_timing_end failback_health "$health_timing_start"

echo "[DNS] On-premise origin health passed; snapshotting records before failback."
dns_timing_start="$(dr_timing_start dns_restore_internal)"
prepare_dns_snapshot
if ! dr_dns_validate_origin_pair \
    "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
    "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED"; then
  echo "[DNS ERROR] A verified pre-failover On-Prem snapshot is required; failback stopped."
  if dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
    DR_STATE_FAILURE_STATUS=DR_ACTIVE
    dr_state_write DR_ACTIVE 2>/dev/null || true
  else
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
  exit 1
fi

if dr_dns_snapshot_pairs_equal "$DNS_TX_DIR" "$DNS_ORIGIN_DIR"; then
  echo "[DNS] Cloudflare already matches the preserved On-Prem snapshot."
  if ! check_public_health "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
    echo "[VALIDATION ERROR] Public health failed while DNS already matches the On-Prem snapshot."
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    exit 1
  fi
else
  if ! dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
    echo "[DNS ERROR] Current records are neither the preserved On-Prem origin nor the approved DR pair."
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    exit 1
  fi
  if dr_dns_failback_transaction \
      "$DNS_TX_DIR" "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
      "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" check_public_health \
      "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
    echo "[DNS] Restored exact pre-failover Web and EMR records."
  else
    dns_rc=$?
    if [ "$dns_rc" -eq 2 ]; then
      DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
      dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    else
      DR_STATE_FAILURE_STATUS=DR_ACTIVE
      dr_state_write DR_ACTIVE 2>/dev/null || true
    fi
    exit 1
  fi
fi

dr_timing_end dns_restore_internal "$dns_timing_start"
if [ "${DR_FAILBACK_CONTROLLER:-0}" != "1" ]; then
  if ! dr_dns_archive_origin_pair "$DNS_ORIGIN_DIR" "$DNS_ARCHIVE_DIR"; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    exit 1
  fi
  dr_state_write IDLE
fi
echo "[DNS] Cloudflare DNS failback completed successfully: $DR_DOMAIN and $EMR_DOMAIN"
echo "=================================================="
