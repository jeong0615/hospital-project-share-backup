#!/bin/bash
set -euo pipefail

CHATOPS_REQUEST_URL="${CHATOPS_REQUEST_URL:-http://IP_REDACTED:5000/chatops/request}"

if [ "${1:-}" = "__zabbix__" ]; then
  ALERT_SUBJECT="${2:-Zabbix failover alert}"
  ALERT_MESSAGE="${3:-}"
  if command -v sha256sum >/dev/null 2>&1; then
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | sha256sum | awk '{print $1}')"
  else
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | cksum | awk '{print $1}')"
  fi
  INCIDENT_ID="${ZABBIX_EVENT_ID:-zabbix-${INCIDENT_DIGEST}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-$ALERT_SUBJECT}"
else
  INCIDENT_ID="${ZABBIX_EVENT_ID:-${1:-failover-$(date +%s)}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-${2:-On-premise service failure detected}}"
fi

json_escape() {
  sed ':a;N;$!ba;s/\\/\\\\/g;s/"/\\"/g;s/\r/\\r/g;s/\t/\\t/g;s/\n/\\n/g'
}

INCIDENT_ID_JSON="$(printf '%s' "$INCIDENT_ID" | json_escape)"
INCIDENT_SUMMARY_JSON="$(printf '%s' "$INCIDENT_SUMMARY" | json_escape)"
PAYLOAD="{\"action\":\"failover\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\"}"

if command -v curl >/dev/null 2>&1; then
  curl -fsS -X POST "$CHATOPS_REQUEST_URL" \
    -H "Content-Type: application/json" \
    --data "$PAYLOAD"
elif command -v wget >/dev/null 2>&1; then
  wget -qO- --timeout=10 \
    --header="Content-Type: application/json" \
    --post-data="$PAYLOAD" "$CHATOPS_REQUEST_URL"
else
  echo "No HTTP client available for ChatOps request." >&2
  exit 1
fi
echo
