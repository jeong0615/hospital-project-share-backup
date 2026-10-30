#!/bin/bash
set -euo pipefail

CHATOPS_REQUEST_URL="${CHATOPS_REQUEST_URL:-http://IP_REDACTED:5000/chatops/request}"
# Compatibility fields are retained in the payload, but Demo Freeze no
# longer waits for a sustained Recovery window before creating Failback.
STABILITY_SECONDS="0"
STABILITY_VERIFIED=true
TEST_MODE=false
REQUEST_SOURCE=""
EVENT_AGE_SECONDS=""
INCIDENT_HOST=""
INCIDENT_TIME=""

is_unexpanded_macro() {
  case "${1:-}" in
    \{*\}) return 0 ;;
    *) return 1 ;;
  esac
}

message_field() {
  printf '%s\n' "$ALERT_MESSAGE" | sed -n "s/^$1:[[:space:]]*//p" | head -n 1
}

if [ "${1:-}" = "__zabbix_test__" ]; then
  TEST_MODE=true
  REQUEST_SOURCE="zabbix"
  ALERT_SUBJECT="${2:-Zabbix test failback alert}"
  ALERT_MESSAGE="${3:-}"
  INCIDENT_HOST="${4:-}"
  INCIDENT_ID="${5:-${ZABBIX_EVENT_ID:-}}"
  EVENT_AGE_SECONDS="${6:-}"
  INCIDENT_TIME="${7:-}"
  # See send_slack.sh: use the structured alert body when Zabbix leaves
  # non-ALERT macros literal in custom script parameters.
  if [ -z "$INCIDENT_HOST" ] || is_unexpanded_macro "$INCIDENT_HOST"; then
    INCIDENT_HOST="$(message_field 'Host')"
  fi
  if [ -z "$INCIDENT_ID" ] || is_unexpanded_macro "$INCIDENT_ID"; then
    INCIDENT_ID="$(message_field 'Event ID')"
  fi
  if [ -z "$EVENT_AGE_SECONDS" ] || is_unexpanded_macro "$EVENT_AGE_SECONDS"; then
    EVENT_AGE_SECONDS="$(message_field 'Event age')"
  fi
  if [ -z "$INCIDENT_TIME" ] || is_unexpanded_macro "$INCIDENT_TIME"; then
    INCIDENT_TIME="$(message_field 'Time')"
  fi
  if [ -z "$INCIDENT_ID" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | sha256sum | awk '{print $1}')"
    else
      INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | cksum | awk '{print $1}')"
    fi
    INCIDENT_ID="zabbix-${INCIDENT_DIGEST}"
  fi
  INCIDENT_SUMMARY="[DR TEST MODE] ${ZABBIX_EVENT_NAME:-$ALERT_SUBJECT}"
elif [ "${1:-}" = "__zabbix__" ]; then
  REQUEST_SOURCE="zabbix"
  ALERT_SUBJECT="${2:-Zabbix failback alert}"
  ALERT_MESSAGE="${3:-}"
  INCIDENT_HOST="$(message_field 'Host')"
  INCIDENT_ID="$(message_field 'Event ID')"
  EVENT_AGE_SECONDS="$(message_field 'Event age')"
  INCIDENT_TIME="$(message_field 'Time')"
  if is_unexpanded_macro "$INCIDENT_HOST"; then INCIDENT_HOST=""; fi
  if is_unexpanded_macro "$INCIDENT_ID"; then INCIDENT_ID=""; fi
  if is_unexpanded_macro "$EVENT_AGE_SECONDS"; then EVENT_AGE_SECONDS=""; fi
  if is_unexpanded_macro "$INCIDENT_TIME"; then INCIDENT_TIME=""; fi
  if command -v sha256sum >/dev/null 2>&1; then
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | sha256sum | awk '{print $1}')"
  else
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | cksum | awk '{print $1}')"
  fi
  INCIDENT_ID="${ZABBIX_EVENT_ID:-zabbix-${INCIDENT_DIGEST}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-$ALERT_SUBJECT}"
else
  INCIDENT_ID="${ZABBIX_EVENT_ID:-${1:-failback-$(date +%s)}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-${2:-On-premise service recovery detected}}"
fi

json_escape() {
  sed ':a;N;$!ba;s/\\/\\\\/g;s/"/\\"/g;s/\r/\\r/g;s/\t/\\t/g;s/\n/\\n/g'
}

INCIDENT_ID_JSON="$(printf '%s' "$INCIDENT_ID" | json_escape)"
INCIDENT_SUMMARY_JSON="$(printf '%s' "$INCIDENT_SUMMARY" | json_escape)"
INCIDENT_HOST_JSON="$(printf '%s' "$INCIDENT_HOST" | json_escape)"
EVENT_AGE_JSON="$(printf '%s' "$EVENT_AGE_SECONDS" | json_escape)"
INCIDENT_TIME_JSON="$(printf '%s' "$INCIDENT_TIME" | json_escape)"
if [ "$REQUEST_SOURCE" = "zabbix" ]; then
  PAYLOAD="{\"source\":\"zabbix\",\"action\":\"failback\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\",\"host\":\"${INCIDENT_HOST_JSON}\",\"incident_at\":\"${INCIDENT_TIME_JSON}\",\"test_mode\":${TEST_MODE},\"event_age_seconds\":\"${EVENT_AGE_JSON}\",\"stability_verified\":${STABILITY_VERIFIED},\"stability_seconds\":\"${STABILITY_SECONDS}\",\"stability_required_seconds\":\"${STABILITY_SECONDS}\"}"
else
  PAYLOAD="{\"action\":\"failback\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\",\"host\":\"${INCIDENT_HOST_JSON}\",\"incident_at\":\"${INCIDENT_TIME_JSON}\",\"test_mode\":${TEST_MODE},\"event_age_seconds\":\"${EVENT_AGE_JSON}\",\"stability_verified\":${STABILITY_VERIFIED},\"stability_seconds\":\"${STABILITY_SECONDS}\",\"stability_required_seconds\":\"${STABILITY_SECONDS}\"}"
fi

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
