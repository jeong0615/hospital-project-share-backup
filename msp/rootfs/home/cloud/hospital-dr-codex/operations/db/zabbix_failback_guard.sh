#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_PATHS="${DR_RUNTIME_PATHS:-$SCRIPT_DIR/../runtime_paths.sh}"
if [ ! -r "$RUNTIME_PATHS" ] && [ -r "/home/cloud/hospital-dr-codex/operations/runtime_paths.sh" ]; then
  RUNTIME_PATHS="/home/cloud/hospital-dr-codex/operations/runtime_paths.sh"
fi
if [ ! -r "$RUNTIME_PATHS" ]; then
  echo "[FAILBACK ALERT ERROR] runtime_paths.sh is not available." >&2
  exit 2
fi
# shellcheck disable=SC1091
source "$RUNTIME_PATHS"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/failback_stability.sh"

LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/zabbix_failback_guard.log}"
SEND_FAILBACK="${SEND_FAILBACK:-$DR_OPERATIONS_DIR/chatops/send_failback.sh}"
ORIGINAL_ARGS=("$@")
mkdir -p "$(dirname -- "$LOG_FILE")"
DOMAIN="${DOMAIN:-hospital-web.pp.ua}"
ONPREM_WEB_HEALTH_URL="${ONPREM_WEB_HEALTH_URL:-}"
ONPREM_DOC_HEALTH_URL="${ONPREM_DOC_HEALTH_URL:-}"
ONPREM_DB_HOST="${ONPREM_DB_HOST:-}"
ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
FAILBACK_STABILITY_SECONDS="${FAILBACK_STABILITY_SECONDS:-300}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-${FAILBACK_STABILITY_CHECK_INTERVAL_SECONDS:-2}}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-3}"
CURL_MAX_TIME="${CURL_MAX_TIME:-5}"
NC_TIMEOUT_SECONDS="${NC_TIMEOUT_SECONDS:-3}"
NETWORK_DR_HEALTH_URL="${NETWORK_DR_HEALTH_URL:-http://IP_REDACTED:5001/chatops/network-health}"
FAILBACK_GUARD_TEST_MODE="${FAILBACK_GUARD_TEST_MODE:-false}"

exec >> "$LOG_FILE" 2>&1

probe_http() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "$url" >/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -t 1 -T "$CURL_MAX_TIME" -O /dev/null "$url"
  else
    echo "[RECOVERY CHECK] No HTTP probe client (curl or wget) is available."
    return 1
  fi
}

probe_tcp() {
  local host="$1"
  local port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -vz -w "$NC_TIMEOUT_SECONDS" "$host" "$port" >/dev/null 2>&1
  elif command -v timeout >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then
    timeout "$NC_TIMEOUT_SECONDS" bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" >/dev/null 2>&1
  else
    echo "[RECOVERY CHECK] No TCP probe client (nc or Bash /dev/tcp) is available."
    return 1
  fi
}

probe_network_health() {
  local response
  if command -v curl >/dev/null 2>&1; then
    response="$(curl -fsS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "$NETWORK_DR_HEALTH_URL")" || return 1
  elif command -v wget >/dev/null 2>&1; then
    response="$(wget -q -t 1 -T "$CURL_MAX_TIME" -O - "$NETWORK_DR_HEALTH_URL")" || return 1
  else
    echo "[RECOVERY CHECK] No HTTP probe client for the Zabbix network health endpoint."
    return 1
  fi
  if printf '%s' "$response" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"READY"'; then
    echo "[RECOVERY CHECK] Network/SNMP DR health is READY."
    return 0
  fi
  echo "[RECOVERY CHECK] Network/SNMP DR health is not READY."
  return 1
}

dr_state_prepare

echo "=================================================="
echo "[$(date)] Zabbix failback recovery guard started."

if dr_state_flag_is_set; then
  echo "[FAILBACK ALERT SKIPPED] Failback approval was already requested."
  exit 0
fi

if [ "$FAILBACK_GUARD_TEST_MODE" != "true" ] && [ "$(dr_state_read)" != "DR_ACTIVE" ]; then
  echo "[FAILBACK ALERT SKIPPED] Persistent DR state is not DR_ACTIVE."
  exit 0
fi

if ! failback_stability_validate_config "$FAILBACK_STABILITY_SECONDS" "$CHECK_INTERVAL_SECONDS"; then
  echo "[FAILBACK ALERT ERROR] FAILBACK_STABILITY_SECONDS must be a non-negative integer."
  exit 2
fi

missing_probe_config=()
for probe_variable in ONPREM_WEB_HEALTH_URL ONPREM_DOC_HEALTH_URL ONPREM_DB_HOST; do
  if [ -z "${!probe_variable:-}" ]; then
    missing_probe_config+=("$probe_variable")
  fi
done
if [ "${#missing_probe_config[@]}" -gt 0 ]; then
  echo "[FAILBACK ALERT SKIPPED] Recovery probe configuration is missing: ${missing_probe_config[*]}"
  exit 1
fi

recovery_started_at=""
attempt=0
while :; do
  attempt=$((attempt + 1))
  echo "[RECOVERY CHECK] Stability probe ${attempt}: validating on-premise Web, Doc, DB, and Network/SNMP."

  if probe_http "$ONPREM_WEB_HEALTH_URL" \
     && probe_http "$ONPREM_DOC_HEALTH_URL" \
     && probe_tcp "$ONPREM_DB_HOST" "$ONPREM_DB_PORT" \
     && probe_network_health; then
    now="$(date +%s)"
    if [ -z "$recovery_started_at" ]; then
      recovery_started_at="$now"
      echo "[RECOVERY CHECK] Full recovery stability window started."
    fi
  else
    if [ -z "$recovery_started_at" ]; then
      echo "[RECOVERY CHECK] Recovery is not ready; no Failback approval will be sent."
      exit 1
    fi
    echo "[RECOVERY CHECK] Recovery or Network/SNMP health regressed; stability timer reset."
    recovery_started_at=""
    sleep "$CHECK_INTERVAL_SECONDS"
    continue
  fi

  if failback_stability_is_satisfied "$recovery_started_at" "$now" "$FAILBACK_STABILITY_SECONDS"; then
    break
  fi
  remaining="$(failback_stability_remaining "$recovery_started_at" "$now" "$FAILBACK_STABILITY_SECONDS")"
  sleep_for="$CHECK_INTERVAL_SECONDS"
  if [ "$remaining" -lt "$sleep_for" ]; then
    sleep_for="$remaining"
  fi
  [ "$sleep_for" -gt 0 ] && sleep "$sleep_for"
done

if command -v curl >/dev/null 2>&1 \
   && curl -fsSI --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "https://${DOMAIN}/emr/" | grep -q " 403"; then
  echo "[RECOVERY CHECK] Public EMR access restriction is active."
fi

echo "[FAILBACK ALERT] On-premise recovery is stable. Sending Slack failback approval request."
if ! FAILBACK_GUARD_BYPASS=true FAILBACK_STABILITY_VERIFIED=true bash "$SEND_FAILBACK" "${ORIGINAL_ARGS[@]}"; then
  echo "[FAILBACK ALERT ERROR] Slack failback approval request failed; retry remains possible."
  exit 1
fi
dr_state_flag_write sent
echo "[FAILBACK ALERT] Failback approval request recorded after successful delivery."
