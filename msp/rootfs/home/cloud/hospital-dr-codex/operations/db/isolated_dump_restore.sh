#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MODE="${1:-}"
_dr_wrapper_cutover_opt_in="${DUMP_DB_SERVICE_CUTOVER_ENABLED:-false}"
[[ -n "$MODE" ]] || {
  echo "Usage: $0 preflight|restore|service-preflight|prepare-service|service-cutover|service-promote [isolated arguments...]" >&2
  exit 2
}
shift

if [[ "$MODE" == "preflight" ]]; then
  if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
    if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
      echo "ISOLATED_DUMP_PREFLIGHT=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
      exit 1
    fi
    export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
    export DUMP_RESTORE_EXEC_ENABLED=false
    unset DUMP_RESTORE_EXECUTOR
  else
    unset DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
  fi
  exec python3 "$SCRIPT_DIR/isolated_dump_restore.py" preflight "$@"
fi
[[ "$MODE" == "restore" || "$MODE" == "service-preflight" || "$MODE" == "prepare-service" || "$MODE" == "service-cutover" || "$MODE" == "service-promote" ]] || {
  echo "Unsupported isolated dump operation." >&2
  exit 2
}

# Secret values remain shell-local and are copied only into short-lived tmpfs
# files. The Python controller receives file paths, never credential values.
# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"
if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  exit 1
fi
if [[ "$MODE" == "service-cutover" && "${_dr_wrapper_cutover_opt_in,,}" == "true" ]]; then
  DUMP_DB_SERVICE_CUTOVER_ENABLED=true
fi
if [[ "$MODE" == "service-promote" && "${DUMP_DB_SERVICE_PROMOTION_ENABLED:-false}" != "true" ]]; then
  echo "DB_SERVICE_PROMOTION=BLOCKED reason=DB_SERVICE_WRITE_PROMOTION_DISABLED" >&2
  exit 1
fi
if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
  if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
    echo "ISOLATED_DUMP_OPERATION=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
    exit 1
  fi
  export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
  DUMP_RESTORE_EXEC_ENABLED=false
  unset DUMP_RESTORE_EXECUTOR
else
  unset DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
  if [[ "${DUMP_RESTORE_EXEC_ENABLED:-false}" != "false" || -n "${DUMP_RESTORE_EXECUTOR:-}" ]]; then
    echo "ISOLATED_DUMP_PREFLIGHT=BLOCKED reason=CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_DISABLED_AND_UNSET" >&2
    exit 1
  fi
fi

export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export AWS_REGION="${AWS_REGION:-ap-northeast-2}"
export DUMP_RESTORE_EXEC_ENABLED=false
export ISOLATED_DUMP_RESTORE_WRAPPER=1
unset DUMP_RESTORE_EXECUTOR

if [[ "$MODE" == "service-preflight" ]]; then
  python3 "$SCRIPT_DIR/isolated_dump_restore.py" service-preflight \
    --ssh-key "$SSH_KEY" \
    --ssh-config "$DR_SSH_CONFIG_FILE" \
    --known-hosts "$DR_SSH_KNOWN_HOSTS_FILE" \
    "$@"
  exit $?
fi

if [[ ( "$MODE" == "service-cutover" || "$MODE" == "service-promote" ) \
   && "${DR_DUMP_EXECUTOR_CHILD:-0}" != "1" ]]; then
  # Serialize against normal Failover/Failback/environment workflows. This
  # standalone operation is not yet called from a parent runner, so it must
  # acquire both canonical locks itself before app configuration can change.
  if [[ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]]; then
    exec 7>"${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
    if ! flock -n 7; then
      echo "DB_SERVICE_OPERATION=BLOCKED reason=ACTIVE_DR_WORKFLOW" >&2
      exit 1
    fi
    export DR_WORKFLOW_LOCK_HELD=1
  fi
  if [[ "${DR_FAILOVER_LOCK_HELD:-0}" != "1" ]]; then
    exec 8>"${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
    if ! flock -n 8; then
      echo "DB_SERVICE_OPERATION=BLOCKED reason=ACTIVE_FAILOVER_WORKFLOW" >&2
      exit 1
    fi
    export DR_FAILOVER_LOCK_HELD=1
  fi
fi

umask 077
if [[ ! -d /dev/shm ]] || [[ "$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)" != "tmpfs" ]]; then
  echo "ISOLATED_OPERATION=BLOCKED reason=SECRET_TMPFS_UNAVAILABLE" >&2
  exit 1
fi

secret_file=""
cleanup() {
  [[ -z "$secret_file" ]] || rm -f -- "$secret_file"
}
trap cleanup EXIT INT TERM

if [[ "$MODE" == "restore" ]]; then
  if [[ -z "${DB_BACKUP_ENCRYPTION_KEY:-}" ]]; then
    echo "ISOLATED_DUMP_PREFLIGHT=BLOCKED reason=ENCRYPTION_KEY_MISSING" >&2
    exit 1
  fi
  secret_file="$(mktemp /dev/shm/hospital-dr-dump-key.XXXXXX)"
  printf '%s' "$DB_BACKUP_ENCRYPTION_KEY" >"$secret_file"
  unset DB_BACKUP_ENCRYPTION_KEY
  python3 "$SCRIPT_DIR/isolated_dump_restore.py" restore \
    --key-file "$secret_file" \
    --ssh-key "$SSH_KEY" \
    --ssh-config "$DR_SSH_CONFIG_FILE" \
    --known-hosts "$DR_SSH_KNOWN_HOSTS_FILE" \
    "$@"
  exit $?
fi

if [[ "$MODE" == "service-cutover" ]]; then
  if [[ "${DUMP_DB_SERVICE_CUTOVER_ENABLED:-false}" != "true" ]]; then
    echo "DB_SERVICE_CUTOVER=BLOCKED reason=DB_SERVICE_CUTOVER_DISABLED" >&2
    exit 1
  fi
  if [[ -z "${DUMP_RESTORE_SERVICE_DB_PASSWORD:-}" ]]; then
    echo "DB_SERVICE_CUTOVER=BLOCKED reason=SERVICE_DB_PASSWORD_MISSING" >&2
    exit 1
  fi
  secret_file="$(mktemp /dev/shm/hospital-dr-db-cutover.XXXXXX)"
  chmod 0600 "$secret_file"
  printf '%s' "$DUMP_RESTORE_SERVICE_DB_PASSWORD" >"$secret_file"
  unset DUMP_RESTORE_SERVICE_DB_PASSWORD
  export DUMP_DB_SERVICE_CUTOVER_ENABLED=true
  python3 "$SCRIPT_DIR/dump_db_service_cutover.py" \
    --service-password-file "$secret_file" \
    --ssh-key "$SSH_KEY" \
    --ssh-config "$DR_SSH_CONFIG_FILE" \
    --known-hosts "$DR_SSH_KNOWN_HOSTS_FILE" \
    --inventory "${INVENTORY:-${DR_ANSIBLE_DIR}/inventory.ini}" \
    "$@"
  exit $?
fi

if [[ "$MODE" == "service-promote" ]]; then
  export DUMP_DB_SERVICE_PROMOTION_ENABLED=true
  python3 "$SCRIPT_DIR/dump_db_service_promotion.py" \
    --ssh-key "$SSH_KEY" \
    --ssh-config "$DR_SSH_CONFIG_FILE" \
    --known-hosts "$DR_SSH_KNOWN_HOSTS_FILE" \
    --inventory "${INVENTORY:-${DR_ANSIBLE_DIR}/inventory.ini}" \
    "$@"
  exit $?
fi

if [[ -z "${DUMP_RESTORE_SERVICE_DB_PASSWORD:-}" ]]; then
  echo "ISOLATED_DB_SERVICE=BLOCKED reason=SERVICE_DB_PASSWORD_MISSING" >&2
  exit 1
fi
secret_file="$(mktemp /dev/shm/hospital-dr-db-service.XXXXXX)"
printf '%s' "$DUMP_RESTORE_SERVICE_DB_PASSWORD" >"$secret_file"
unset DUMP_RESTORE_SERVICE_DB_PASSWORD
python3 "$SCRIPT_DIR/isolated_dump_restore.py" prepare-service \
  --service-password-file "$secret_file" \
  --ssh-key "$SSH_KEY" \
  --ssh-config "$DR_SSH_CONFIG_FILE" \
  --known-hosts "$DR_SSH_KNOWN_HOSTS_FILE" \
  "$@"
