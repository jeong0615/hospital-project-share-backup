#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/zabbix_failback_guard.log}"
SEND_FAILBACK="${SEND_FAILBACK:-$DR_OPERATIONS_DIR/chatops/send_failback.sh}"
mkdir -p "$(dirname -- "$LOG_FILE")"
DOMAIN="${DOMAIN:-hospital-web.pp.ua}"
ONPREM_WEB_HEALTH_URL="${ONPREM_WEB_HEALTH_URL:-http://IP_REDACTED/}"
ONPREM_DOC_HEALTH_URL="${ONPREM_DOC_HEALTH_URL:-http://IP_REDACTED/emr/}"
ONPREM_DB_HOST="${ONPREM_DB_HOST:-IP_REDACTED}"
ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
REQUIRED_OK_COUNT="${REQUIRED_OK_COUNT:-2}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-2}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-3}"
CURL_MAX_TIME="${CURL_MAX_TIME:-5}"
NC_TIMEOUT_SECONDS="${NC_TIMEOUT_SECONDS:-3}"

exec >> "$LOG_FILE" 2>&1

dr_state_prepare

echo "=================================================="
echo "[$(date)] Zabbix failback recovery guard started."

if dr_state_flag_is_set; then
  echo "[FAILBACK ALERT SKIPPED] Failback approval was already requested."
  exit 0
fi

if [ "$(dr_state_read)" != "DR_ACTIVE" ]; then
  echo "[FAILBACK ALERT SKIPPED] Persistent DR state is not DR_ACTIVE."
  exit 0
fi

ok_count=0
for attempt in $(seq 1 "$REQUIRED_OK_COUNT"); do
  echo "[RECOVERY CHECK] Attempt ${attempt}/${REQUIRED_OK_COUNT}: validating on-premise Web, Doc, and DB."

  if curl -fsS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "$ONPREM_WEB_HEALTH_URL" >/dev/null \
     && curl -fsS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "$ONPREM_DOC_HEALTH_URL" >/dev/null \
     && nc -vz -w "$NC_TIMEOUT_SECONDS" "$ONPREM_DB_HOST" "$ONPREM_DB_PORT" >/dev/null 2>&1; then
    ok_count=$((ok_count + 1))
  else
    echo "[RECOVERY CHECK] On-premise service is not stable yet."
    exit 1
  fi

  sleep "$CHECK_INTERVAL_SECONDS"
done

if curl -fsSI --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "https://${DOMAIN}/emr/" | grep -q " 403"; then
  echo "[RECOVERY CHECK] Public EMR access restriction is active."
fi

echo "[FAILBACK ALERT] On-premise recovery is stable. Sending Slack failback approval request."
if ! bash "$SEND_FAILBACK"; then
  echo "[FAILBACK ALERT ERROR] Slack failback approval request failed; retry remains possible."
  exit 1
fi
dr_state_flag_write sent
echo "[FAILBACK ALERT] Failback approval request recorded after successful delivery."
