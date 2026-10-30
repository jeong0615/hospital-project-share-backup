#!/usr/bin/env bash
# Persistent DR runtime state helper.
# Directory mode: 0750. State, lock, and flag files: 0640.
# The default owner is cloud:cloud; deployments may override DR_STATE_OWNER.

DR_STATE_DIR="${DR_STATE_DIR:-/var/lib/hospital-dr}"
DR_STATE_FILE="${DR_STATE_FILE:-${DR_STATE_DIR}/dr_state}"
DR_STATE_LOCK_FILE="${DR_STATE_LOCK_FILE:-${DR_STATE_DIR}/dr_state.lock}"
DR_STATE_OWNER="${DR_STATE_OWNER:-cloud:cloud}"
DR_STATE_DIR_MODE="${DR_STATE_DIR_MODE:-0750}"
DR_STATE_FILE_MODE="${DR_STATE_FILE_MODE:-0640}"
DR_FAILBACK_ALERT_STATE_FILE="${DR_FAILBACK_ALERT_STATE_FILE:-${DR_STATE_DIR}/failback-alert.sent}"
DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"

DR_STATES="IDLE FAILOVER_EXECUTING DR_ACTIVE FAILBACK_EXECUTING FAILED PARTIAL_FAILURE"

dr_state_is_valid() {
  case "${1:-}" in
    IDLE|FAILOVER_EXECUTING|DR_ACTIVE|FAILBACK_EXECUTING|FAILED|PARTIAL_FAILURE)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

dr_state_apply_owner() {
  local path="$1"
  local owner_user="${DR_STATE_OWNER%%:*}"
  local owner_group="${DR_STATE_OWNER#*:}"
  if [ "$(id -u)" -eq 0 ] && command -v getent >/dev/null 2>&1 \
      && getent passwd "$owner_user" >/dev/null 2>&1 \
      && getent group "$owner_group" >/dev/null 2>&1; then
    chown "$DR_STATE_OWNER" "$path"
  fi
}

dr_state_apply_mode() {
  local mode="$1"
  local path="$2"
  # Shared state can be used by a non-root Zabbix alert process.  Preserve
  # the owner-managed permissions while allowing the owner of newly-created
  # files to apply the configured mode.
  if [ "$(id -u)" -eq 0 ] || [ -O "$path" ]; then
    chmod "$mode" "$path"
  fi
}

dr_state_prepare_dir() {
  mkdir -p "$DR_STATE_DIR"
  dr_state_apply_mode "$DR_STATE_DIR_MODE" "$DR_STATE_DIR"
  dr_state_apply_owner "$DR_STATE_DIR"
}

dr_state_prepare_lock() {
  dr_state_prepare_dir
  if [ ! -e "$DR_STATE_LOCK_FILE" ]; then
    : > "$DR_STATE_LOCK_FILE"
  fi
  dr_state_apply_mode "$DR_STATE_FILE_MODE" "$DR_STATE_LOCK_FILE"
  dr_state_apply_owner "$DR_STATE_LOCK_FILE"
}

dr_workflow_lock_prepare() {
  local lock_dir
  lock_dir="$(dirname -- "$DR_WORKFLOW_LOCK_FILE")"
  mkdir -p "$lock_dir"
  if [ ! -e "$DR_WORKFLOW_LOCK_FILE" ]; then
    : > "$DR_WORKFLOW_LOCK_FILE"
  fi
  dr_state_apply_mode "$DR_STATE_FILE_MODE" "$DR_WORKFLOW_LOCK_FILE"
  dr_state_apply_owner "$DR_WORKFLOW_LOCK_FILE"
}

dr_state_prepare() {
  dr_state_prepare_dir
  dr_state_prepare_lock
  if [ ! -f "$DR_STATE_FILE" ]; then
    dr_state_write IDLE
  fi
}

dr_state_write() {
  local new_state="${1:-}"
  local temporary=""
  dr_state_is_valid "$new_state" || {
    echo "[DR STATE ERROR] Invalid state: $new_state" >&2
    return 2
  }
  dr_state_prepare_lock
  (
    set -e
    trap 'if [ -n "${temporary:-}" ]; then rm -f -- "$temporary"; fi' EXIT
    flock -x 9
    temporary="$(mktemp "$DR_STATE_DIR/.dr_state.XXXXXX")"
    umask 027
    printf '%s\n' "$new_state" > "$temporary"
    dr_state_apply_mode "$DR_STATE_FILE_MODE" "$temporary"
    dr_state_apply_owner "$temporary"
    mv -f -- "$temporary" "$DR_STATE_FILE"
    temporary=""
    dr_state_apply_mode "$DR_STATE_FILE_MODE" "$DR_STATE_FILE"
    dr_state_apply_owner "$DR_STATE_FILE"
  ) 9>"$DR_STATE_LOCK_FILE"
}

dr_state_read() {
  local current_state
  if [ ! -r "$DR_STATE_FILE" ]; then
    printf '%s\n' IDLE
    return 0
  fi
  IFS= read -r current_state < "$DR_STATE_FILE" || current_state=""
  if ! dr_state_is_valid "$current_state"; then
    echo "[DR STATE ERROR] Invalid persisted state." >&2
    return 2
  fi
  printf '%s\n' "$current_state"
}

dr_state_is() {
  [ "$(dr_state_read)" = "$1" ]
}

dr_state_mark_failure() {
  local fallback="${1:-FAILED}"
  local current_state=""
  current_state="$(dr_state_read 2>/dev/null || true)"
  if [ "$fallback" = "PARTIAL_FAILURE" ] || [ "$current_state" = "PARTIAL_FAILURE" ]; then
    dr_state_write PARTIAL_FAILURE
  else
    dr_state_write "$fallback"
  fi
}

dr_state_flag_write() {
  local value="${1:-set}"
  local temporary=""
  dr_state_prepare_lock
  (
    set -e
    trap 'if [ -n "${temporary:-}" ]; then rm -f -- "$temporary"; fi' EXIT
    flock -x 9
    temporary="$(mktemp "$DR_STATE_DIR/.dr_flag.XXXXXX")"
    umask 027
    printf '%s\n' "$value" > "$temporary"
    dr_state_apply_mode "$DR_STATE_FILE_MODE" "$temporary"
    dr_state_apply_owner "$temporary"
    mv -f -- "$temporary" "$DR_FAILBACK_ALERT_STATE_FILE"
    temporary=""
    dr_state_apply_mode "$DR_STATE_FILE_MODE" "$DR_FAILBACK_ALERT_STATE_FILE"
    dr_state_apply_owner "$DR_FAILBACK_ALERT_STATE_FILE"
  ) 9>"$DR_STATE_LOCK_FILE"
}

dr_state_flag_is_set() {
  [ -s "$DR_FAILBACK_ALERT_STATE_FILE" ]
}

dr_state_flag_clear() {
  rm -f -- "$DR_FAILBACK_ALERT_STATE_FILE"
}
