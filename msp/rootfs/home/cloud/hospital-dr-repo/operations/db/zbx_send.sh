#!/bin/bash

# Common non-blocking Zabbix sender helper for DR automation metrics.
# Source this file from DR scripts, then call: zbx_send "item.key" "value"

ZBX_SENDER_BIN="${ZBX_SENDER_BIN:-/usr/bin/zabbix_sender}"
ZBX_SERVER="${ZBX_SERVER:-IP_REDACTED}"
ZBX_SERVER_PORT="${ZBX_SERVER_PORT:-10051}"
ZBX_DR_HOST="${ZBX_DR_HOST:-Hospital_DR_Automation}"

zbx_send() {
  local key="${1:-}"
  local value="${2:-}"

  if [ -z "$key" ] || [ -z "$value" ]; then
    return 0
  fi

  if [ ! -x "$ZBX_SENDER_BIN" ]; then
    return 0
  fi

  "$ZBX_SENDER_BIN" \
    -z "$ZBX_SERVER" \
    -p "$ZBX_SERVER_PORT" \
    -s "$ZBX_DR_HOST" \
    -k "$key" \
    -o "$value" >/dev/null 2>&1 || true
}

zbx_send_now() {
  local key="${1:-}"
  zbx_send "$key" "$(date +%s)"
}
