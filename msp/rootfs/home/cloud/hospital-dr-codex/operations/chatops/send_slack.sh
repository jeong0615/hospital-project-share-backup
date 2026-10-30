#!/bin/bash
set -euo pipefail

CHATOPS_REQUEST_URL="${CHATOPS_REQUEST_URL:-http://IP_REDACTED:5000/chatops/request}"
TEST_MODE=false
REQUEST_SOURCE=""
EVENT_AGE_SECONDS=""
INCIDENT_HOST=""
INCIDENT_TIME=""
EVENT_STATUS=""
EVENT_SOURCE=""
ACTION_NAME=""
TRIGGER_ID=""
EVENT_TAGS_JSON=""
EVENT_VALUE=""
SENDER_ARGC=$#

is_unexpanded_macro() {
  [[ "${1:-}" =~ \{[A-Za-z][A-Za-z0-9_.]*\} ]]
}

message_field() {
  local field="$1"
  printf '%s' "$ALERT_MESSAGE" | awk -v key="$field" '
    {
      line = $0
      sub(/\r$/, "", line)
      prefix = key ":"
      if (index(line, prefix) == 1) {
        value = substr(line, length(prefix) + 1)
        sub(/^[ \t]+/, "", value)
        sub(/[ \t]+$/, "", value)
        matches++
        selected = value
      }
    }
    END {
      if (matches == 1) printf "%s", selected
    }
  '
}

valid_event_age() {
  local compact="${EVENT_AGE_SECONDS//[[:space:]]/}"
  [[ -n "$compact" ]] || return 1
  [[ "$compact" =~ ^[0-9]+([.][0-9]+)?$ \
    || "$compact" =~ ^([0-9]+([.][0-9]+)?[smhdw])+$ ]]
}

valid_event_tags_json() {
  printf '%s' "$EVENT_TAGS_JSON" | python3 -c '
import json, sys
try:
    value = json.load(sys.stdin)
except (ValueError, TypeError):
    raise SystemExit(1)
valid = isinstance(value, list) and all(
    isinstance(item, dict)
    and isinstance(item.get("tag"), str)
    and isinstance(item.get("value"), str)
    for item in value
)
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1
}

test_field_check() {
  local name="$1"
  shift
  if "$@"; then
    printf 'ZABBIX_TEST_FIELD_%s=PASS\n' "$name" >&2
  else
    printf 'ZABBIX_TEST_FIELD_%s=FAIL\n' "$name" >&2
    TEST_FIELDS_OK=false
  fi
}

check_test_arg_count() { [[ "$SENDER_ARGC" -eq 3 ]]; }
check_test_arg1() { [[ "${1:-}" == "__zabbix_test__" ]]; }
check_test_arg2() { [[ "$SENDER_ARGC" -ge 2 && -n "${1:-}" ]] && ! is_unexpanded_macro "${1:-}"; }
check_test_arg3() { [[ "$SENDER_ARGC" -ge 3 && -n "${1:-}" ]]; }
check_test_action_name() { [[ "$ACTION_NAME" == "Cloud_Slack_DR_Broad_Test_Mode" ]] && ! is_unexpanded_macro "$ACTION_NAME"; }
check_test_event_id() { [[ "$INCIDENT_ID" =~ ^[1-9][0-9]*$ ]] && ! is_unexpanded_macro "$INCIDENT_ID"; }
check_test_trigger_id() { [[ "$TRIGGER_ID" =~ ^[1-9][0-9]*$ ]] && ! is_unexpanded_macro "$TRIGGER_ID"; }
check_test_event_source() { [[ "$EVENT_SOURCE" == "0" ]] && ! is_unexpanded_macro "$EVENT_SOURCE"; }
check_test_host() { [[ -n "$INCIDENT_HOST" ]] && ! is_unexpanded_macro "$INCIDENT_HOST"; }
check_test_status() { [[ "$EVENT_STATUS" == "PROBLEM" ]] && ! is_unexpanded_macro "$EVENT_STATUS"; }
check_test_event_age() { valid_event_age && ! is_unexpanded_macro "$EVENT_AGE_SECONDS"; }
check_test_event_tags() { valid_event_tags_json; }
check_test_time() { [[ -n "$INCIDENT_TIME" ]] && ! is_unexpanded_macro "$INCIDENT_TIME"; }

report_test_contract() {
  TEST_FIELDS_OK=true
  printf 'ZABBIX_TEST_DIAGNOSTIC=1\n' >&2
  test_field_check ARG_COUNT check_test_arg_count
  test_field_check ARG1_MODE check_test_arg1 "${1:-}"
  test_field_check ARG2_SUBJECT check_test_arg2 "${2:-}"
  test_field_check ARG3_MESSAGE check_test_arg3 "${3:-}"
  test_field_check ACTION_NAME check_test_action_name
  test_field_check EVENT_ID check_test_event_id
  test_field_check TRIGGER_ID check_test_trigger_id
  test_field_check EVENT_SOURCE check_test_event_source
  test_field_check HOST check_test_host
  test_field_check STATUS check_test_status
  test_field_check EVENT_AGE check_test_event_age
  test_field_check EVENT_TAGS_JSON check_test_event_tags
  test_field_check TIME check_test_time
  [[ "$TEST_FIELDS_OK" == true ]]
}

if [ "${1:-}" = "__zabbix_test__" ]; then
  TEST_MODE=true
  REQUEST_SOURCE="zabbix_test_action"
  ALERT_SUBJECT="${2:-Zabbix test failover alert}"
  ALERT_MESSAGE="${3:-}"
  ACTION_NAME="$(message_field 'Action name')"
  INCIDENT_ID="$(message_field 'Event ID')"
  TRIGGER_ID="$(message_field 'Trigger ID')"
  EVENT_SOURCE="$(message_field 'Event source')"
  INCIDENT_HOST="$(message_field 'Host')"
  EVENT_STATUS="$(message_field 'Status' | tr '[:lower:]' '[:upper:]')"
  EVENT_VALUE="$(message_field 'Value')"
  EVENT_AGE_SECONDS="$(message_field 'Event age')"
  EVENT_TAGS_JSON="$(message_field 'Event tags JSON')"
  INCIDENT_TIME="$(message_field 'Time')"
  for field_name in ACTION_NAME INCIDENT_ID TRIGGER_ID EVENT_SOURCE INCIDENT_HOST EVENT_STATUS EVENT_AGE_SECONDS EVENT_TAGS_JSON INCIDENT_TIME; do
    if is_unexpanded_macro "${!field_name:-}"; then
      printf -v "$field_name" ''
    fi
  done
  if ! report_test_contract "$@"; then
    echo "Zabbix test Action event contract is incomplete; request was not sent." >&2
    exit 1
  fi
  INCIDENT_SUMMARY="[DR TEST MODE] ${ZABBIX_EVENT_NAME:-$ALERT_SUBJECT}"
elif [ "${1:-}" = "__zabbix__" ]; then
  REQUEST_SOURCE="zabbix_production_action"
  ALERT_SUBJECT="${2:-Zabbix failover alert}"
  ALERT_MESSAGE="${3:-}"
  ACTION_NAME="$(message_field 'Action name')"
  INCIDENT_HOST="$(message_field 'Host')"
  INCIDENT_ID="$(message_field 'Event ID')"
  TRIGGER_ID="$(message_field 'Trigger ID')"
  EVENT_SOURCE="$(message_field 'Event source')"
  EVENT_STATUS="$(message_field 'Status')"
  EVENT_TAGS_JSON="$(message_field 'Event tags JSON')"
  EVENT_AGE_SECONDS="$(message_field 'Event age')"
  INCIDENT_TIME="$(message_field 'Time')"
  if is_unexpanded_macro "$ACTION_NAME"; then ACTION_NAME=""; fi
  if is_unexpanded_macro "$INCIDENT_HOST"; then INCIDENT_HOST=""; fi
  if is_unexpanded_macro "$INCIDENT_ID"; then INCIDENT_ID=""; fi
  if is_unexpanded_macro "$TRIGGER_ID"; then TRIGGER_ID=""; fi
  if is_unexpanded_macro "$EVENT_SOURCE"; then EVENT_SOURCE=""; fi
  if is_unexpanded_macro "$EVENT_STATUS"; then EVENT_STATUS=""; fi
  if is_unexpanded_macro "$EVENT_TAGS_JSON"; then EVENT_TAGS_JSON=""; fi
  if is_unexpanded_macro "$EVENT_AGE_SECONDS"; then EVENT_AGE_SECONDS=""; fi
  if is_unexpanded_macro "$INCIDENT_TIME"; then INCIDENT_TIME=""; fi
  EVENT_STATUS="$(printf '%s' "$EVENT_STATUS" | tr '[:lower:]' '[:upper:]')"
  if [[ "$ACTION_NAME" != "Cloud_Slack_DR_Trigger" || ! "$INCIDENT_ID" =~ ^[1-9][0-9]*$ || ! "$TRIGGER_ID" =~ ^[1-9][0-9]*$ || "$EVENT_SOURCE" != "0" || "$EVENT_STATUS" != "PROBLEM" || "$INCIDENT_HOST" != "Zabbix server" || -z "$EVENT_TAGS_JSON" ]]; then
    echo "Production Zabbix Action event contract is incomplete; approval request was not sent." >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | sha256sum | awk '{print $1}')"
  else
    INCIDENT_DIGEST="$(printf '%s\n%s' "$ALERT_SUBJECT" "$ALERT_MESSAGE" | cksum | awk '{print $1}')"
  fi
  INCIDENT_ID="${ZABBIX_EVENT_ID:-${INCIDENT_ID:-zabbix-${INCIDENT_DIGEST}}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-$ALERT_SUBJECT}"
else
  INCIDENT_ID="${ZABBIX_EVENT_ID:-${1:-failover-$(date +%s)}}"
  INCIDENT_SUMMARY="${ZABBIX_EVENT_NAME:-${2:-On-premise service failure detected}}"
fi

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.stdin.read(), ensure_ascii=True)[1:-1])'
}

INCIDENT_ID_JSON="$(printf '%s' "$INCIDENT_ID" | json_escape)"
INCIDENT_SUMMARY_JSON="$(printf '%s' "$INCIDENT_SUMMARY" | json_escape)"
INCIDENT_HOST_JSON="$(printf '%s' "$INCIDENT_HOST" | json_escape)"
EVENT_AGE_JSON="$(printf '%s' "$EVENT_AGE_SECONDS" | json_escape)"
INCIDENT_TIME_JSON="$(printf '%s' "$INCIDENT_TIME" | json_escape)"
ACTION_NAME_JSON="$(printf '%s' "$ACTION_NAME" | json_escape)"
TRIGGER_ID_JSON="$(printf '%s' "$TRIGGER_ID" | json_escape)"
EVENT_SOURCE_JSON="$(printf '%s' "$EVENT_SOURCE" | json_escape)"
EVENT_STATUS_JSON="$(printf '%s' "$EVENT_STATUS" | json_escape)"
EVENT_TAGS_JSON_ESCAPED="$(printf '%s' "$EVENT_TAGS_JSON" | json_escape)"
EVENT_VALUE_JSON="$(printf '%s' "$EVENT_VALUE" | json_escape)"
if [ "$REQUEST_SOURCE" = "zabbix_production_action" ]; then
  PAYLOAD="{\"source\":\"zabbix_production_action\",\"action_name\":\"${ACTION_NAME_JSON}\",\"action\":\"failover\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"event_id\":\"${INCIDENT_ID_JSON}\",\"trigger_id\":\"${TRIGGER_ID_JSON}\",\"event_source\":\"${EVENT_SOURCE_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\",\"host\":\"${INCIDENT_HOST_JSON}\",\"status\":\"${EVENT_STATUS_JSON}\",\"event_tags_json\":\"${EVENT_TAGS_JSON_ESCAPED}\",\"incident_at\":\"${INCIDENT_TIME_JSON}\",\"test_mode\":false,\"event_age_seconds\":\"${EVENT_AGE_JSON}\"}"
elif [ "$REQUEST_SOURCE" = "zabbix_test_action" ]; then
  PAYLOAD="{\"source\":\"zabbix_test_action\",\"action_name\":\"${ACTION_NAME_JSON}\",\"action\":\"failover\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"event_id\":\"${INCIDENT_ID_JSON}\",\"trigger_id\":\"${TRIGGER_ID_JSON}\",\"event_source\":\"${EVENT_SOURCE_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\",\"host\":\"${INCIDENT_HOST_JSON}\",\"status\":\"${EVENT_STATUS_JSON}\",\"value\":\"${EVENT_VALUE_JSON}\",\"event_tags_json\":\"${EVENT_TAGS_JSON_ESCAPED}\",\"incident_at\":\"${INCIDENT_TIME_JSON}\",\"test_mode\":true,\"event_age_seconds\":\"${EVENT_AGE_JSON}\"}"
else
  PAYLOAD="{\"action\":\"failover\",\"incident_id\":\"${INCIDENT_ID_JSON}\",\"summary\":\"${INCIDENT_SUMMARY_JSON}\",\"host\":\"${INCIDENT_HOST_JSON}\",\"incident_at\":\"${INCIDENT_TIME_JSON}\",\"test_mode\":${TEST_MODE},\"event_age_seconds\":\"${EVENT_AGE_JSON}\"}"
fi

HTTP_HEADERS=(-H "Content-Type: application/json")
if [ "$REQUEST_SOURCE" = "zabbix_production_action" ] || [ "$REQUEST_SOURCE" = "zabbix_test_action" ]; then
  if [ "${ZABBIX_PRODUCTION_ACTION_HMAC_KEY:-}" = "" ]; then
    echo "Signed Zabbix Action signing is not configured; request was not sent." >&2
    exit 1
  fi
  SIGNATURE_TIMESTAMP="$(date +%s)"
  if ! SIGNATURE="$(printf '%s' "$PAYLOAD" | ZABBIX_ACTION_SIGNATURE_TIMESTAMP="$SIGNATURE_TIMESTAMP" python3 -c 'import hashlib, hmac, os, sys; key=os.environ.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY", "").encode("utf-8"); timestamp=os.environ["ZABBIX_ACTION_SIGNATURE_TIMESTAMP"].encode("ascii"); body=sys.stdin.buffer.read(); sys.exit(2) if len(key) < 32 else None; print(hmac.new(key, timestamp + b"." + body, hashlib.sha256).hexdigest())')"; then
    echo "Signed Zabbix Action signing failed; approval request was not sent." >&2
    exit 1
  fi
  HTTP_HEADERS+=(
    -H "X-ChatOps-Zabbix-Timestamp: ${SIGNATURE_TIMESTAMP}"
    -H "X-ChatOps-Zabbix-Signature: v1=${SIGNATURE}"
  )
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsS -X POST "$CHATOPS_REQUEST_URL" \
    "${HTTP_HEADERS[@]}" \
    --data-binary "$PAYLOAD"
elif command -v wget >/dev/null 2>&1; then
  WGET_HEADERS=(--header="Content-Type: application/json")
  if [ "$REQUEST_SOURCE" = "zabbix_production_action" ] || [ "$REQUEST_SOURCE" = "zabbix_test_action" ]; then
    WGET_HEADERS+=(
      --header="X-ChatOps-Zabbix-Timestamp: ${SIGNATURE_TIMESTAMP}"
      --header="X-ChatOps-Zabbix-Signature: v1=${SIGNATURE}"
    )
  fi
  wget -qO- --timeout=10 "${WGET_HEADERS[@]}" \
    --post-data="$PAYLOAD" "$CHATOPS_REQUEST_URL"
else
  echo "No HTTP client available for ChatOps request." >&2
  exit 1
fi
echo
