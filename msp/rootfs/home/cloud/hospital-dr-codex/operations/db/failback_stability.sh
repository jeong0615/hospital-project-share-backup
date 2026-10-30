#!/usr/bin/env bash

# Shared, side-effect-free stability-window policy.  The Zabbix recovery
# guard and the local DR dry-run both use these functions so the test does not
# model a different policy from the production recovery path.
failback_stability_validate_config() {
  local duration="${1:-${FAILBACK_STABILITY_SECONDS:-300}}"
  local interval="${2:-${CHECK_INTERVAL_SECONDS:-2}}"
  [[ "$duration" =~ ^[0-9]+$ ]] || return 1
  [[ "$interval" =~ ^[1-9][0-9]*$ ]] || return 1
}

failback_stability_is_satisfied() {
  local started_at="${1:-0}"
  local now="${2:-0}"
  local required_seconds="${3:-${FAILBACK_STABILITY_SECONDS:-300}}"
  [[ "$started_at" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ && "$required_seconds" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -ge "$started_at" ] && [ "$((now - started_at))" -ge "$required_seconds" ]
}

failback_stability_remaining() {
  local started_at="${1:-0}"
  local now="${2:-0}"
  local required_seconds="${3:-${FAILBACK_STABILITY_SECONDS:-300}}"
  if ! [[ "$started_at" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ && "$required_seconds" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  local elapsed=$((now - started_at))
  [ "$elapsed" -lt 0 ] && elapsed=0
  local remaining=$((required_seconds - elapsed))
  [ "$remaining" -lt 0 ] && remaining=0
  printf '%s\n' "$remaining"
}
