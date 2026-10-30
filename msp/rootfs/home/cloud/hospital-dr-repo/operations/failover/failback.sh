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
FAILBACK_TARGET_MODE="${FAILBACK_TARGET_MODE:-tunnel}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
DNS_TX_DIR="${DR_DNS_TX_DIR:-${DR_STATE_DIR}/dns/failback-${BASHPID}}"
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
trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; exit "$rc"' ERR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: $name."
    return 1
  fi
}

SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi

ONPREM_HEALTH_URL="${ONPREM_HEALTH_URL:-http://${ONPREM_WEB_IP}:${ONPREM_WEB_PORT}/}"
ONPREM_EMR_HEALTH_URL="${ONPREM_EMR_HEALTH_URL:-http://${ONPREM_WEB_IP}:${ONPREM_WEB_PORT}/emr/}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
require_config "CF_ZONE_ID"
require_config "ONPREM_WEB_IP"

load_cloudflare_ssm_token

prepare_dns_snapshot() {
  mkdir -p "$DNS_TX_DIR"
  chmod 0750 "$DNS_TX_DIR"
  CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-}")"
  CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-}")"
}

rollback_dns() {
  if dr_dns_rollback_snapshots "$DNS_TX_DIR"; then
    DR_STATE_FAILURE_STATUS=FAILED
    dr_state_write FAILED 2>/dev/null || true
  else
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
}

check_public_health() {
  local attempts="${1:-12}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if curl -fsS --connect-timeout 5 --max-time 15 "https://$DR_DOMAIN/" >/dev/null \
       && curl -fsS --connect-timeout 5 --max-time 15 \
         -H "X-Hospital-DR-Check: $EMR_HEALTH_CHECK_HEADER" "https://$EMR_DOMAIN/emr/" >/dev/null; then
      return 0
    fi
    echo "[VALIDATION] Waiting for public failback health ($attempt/$attempts)."
    sleep "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}"
  done
  return 1
}

echo "=================================================="
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
    exit 1
  fi
  echo "[VALIDATION] Waiting for on-premise web response ($attempt/${ONPREM_HEALTH_ATTEMPTS:-12})."
  sleep 5
done
dr_timing_end failback_health "$health_timing_start"

echo "[DNS] On-premise origin health passed; snapshotting records before failback."
dns_timing_start="$(dr_timing_start dns_restore_internal)"
prepare_dns_snapshot
if [ "$FAILBACK_TARGET_MODE" = "direct" ]; then
  CF_PAYLOAD="{\"type\":\"A\",\"name\":\"$DR_DOMAIN\",\"content\":\"$ONPREM_WEB_IP\",\"ttl\":1,\"proxied\":true}"
  echo "[DNS] Failback target mode: direct public IP with Cloudflare proxy."
elif [ "$FAILBACK_TARGET_MODE" = "tunnel" ]; then
  CF_PAYLOAD="{\"type\":\"CNAME\",\"name\":\"$DR_DOMAIN\",\"content\":\"$ONPREM_TUNNEL_HOST\",\"ttl\":1,\"proxied\":true}"
  echo "[DNS] Failback target mode: Cloudflare Tunnel CNAME."
else
  echo "[CONFIG ERROR] FAILBACK_TARGET_MODE must be direct or tunnel."
  exit 2
fi
CF_EMR_PAYLOAD="{\"type\":\"A\",\"name\":\"$EMR_DOMAIN\",\"content\":\"$ONPREM_WEB_IP\",\"ttl\":1,\"proxied\":true}"

if dr_dns_apply_records "$DNS_TX_DIR" \
  "$CF_RECORD_ID" "$CF_PAYLOAD" "failback:$DR_DOMAIN" \
  "$CF_EMR_RECORD_ID" "$CF_EMR_PAYLOAD" "failback:$EMR_DOMAIN"; then
  :
else
  dns_rc=$?
  if [ "$dns_rc" -eq 2 ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  else
    dr_state_write FAILED 2>/dev/null || true
  fi
  exit 1
fi

echo "[DNS] Cloudflare DNS failback records updated. Checking public health."
if ! check_public_health "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
  echo "[VALIDATION ERROR] Public health failed after DNS failback; attempting rollback."
  rollback_dns
  exit 1
fi

dr_timing_end dns_restore_internal "$dns_timing_start"
if [ "${DR_FAILBACK_CONTROLLER:-0}" != "1" ]; then
  dr_state_write IDLE
fi
echo "[DNS] Cloudflare DNS failback completed successfully: $DR_DOMAIN and $EMR_DOMAIN"
echo "=================================================="
