#!/usr/bin/env bash

# Best-effort workflow timing helper. It never changes the caller's exit status.
dr_timing_now_ns() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(time.monotonic_ns())' 2>/dev/null && return 0
  fi
  date +%s%N
}

dr_timing_safe_name() {
  printf '%s' "${1:-phase}" | tr -c '[:alnum:]_.' '_'
}

dr_timing_emit() {
  local phase event value
  phase="$(dr_timing_safe_name "${1:-phase}")"
  event="$(dr_timing_safe_name "${2:-event}")"
  value="${3:-0}"

  printf '[METRIC] %s_%s=%s\n' "$phase" "$event" "$value" >&2
  if [ -n "${DR_TIMING_FILE:-}" ]; then
    printf '{"phase":"%s","event":"%s","value":%s}\n' \
      "$phase" "$event" "$value" >> "$DR_TIMING_FILE" 2>/dev/null || true
  fi
}

dr_timing_send_now() {
  if declare -F zbx_send_now >/dev/null 2>&1; then
    zbx_send_now "${1:-}" 2>/dev/null || true
  fi
}

dr_timing_send() {
  if declare -F zbx_send >/dev/null 2>&1; then
    zbx_send "${1:-}" "${2:-0}" 2>/dev/null || true
  fi
}

dr_timing_start() {
  local phase now
  phase="$(dr_timing_safe_name "${1:-phase}")"
  now="$(dr_timing_now_ns)"
  dr_timing_emit "$phase" started_at "$(date +%s)"
  dr_timing_send_now "dr.${phase}.started_at"
  printf '%s\n' "$now"
}

dr_timing_end() {
  local phase start end duration_ns duration_ms duration_sec
  phase="$(dr_timing_safe_name "${1:-phase}")"
  start="${2:-}"
  end="$(dr_timing_now_ns)"
  if [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$end" -ge "$start" ]]; then
    duration_ns=$((end - start))
    duration_ms=$((duration_ns / 1000000))
    duration_sec=$((duration_ns / 1000000000))
    dr_timing_emit "$phase" finished_at "$(date +%s)"
    dr_timing_emit "$phase" duration_ms "$duration_ms"
    dr_timing_emit "$phase" duration_sec "$duration_sec"
    dr_timing_send_now "dr.${phase}.finished_at"
    dr_timing_send "dr.${phase}.duration_sec" "$duration_sec"
  else
    dr_timing_emit "$phase" duration_unavailable 1
  fi
}
