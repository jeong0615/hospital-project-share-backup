#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
readonly_optin="${DUMP_DB_READONLY_HEALTH_ENABLED:-false}"
dns_preflight_optin="${DUMP_DB_DNS_PREFLIGHT_ENABLED:-false}"

# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"
if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  echo "DUMP_READONLY_HEALTH=BLOCKED reason=DR_SECRET_OR_SSH_CONFIG_UNAVAILABLE" >&2
  exit 1
fi

if [[ "${readonly_optin,,}" != "true" || "${dns_preflight_optin,,}" != "true" ]]; then
  echo "DUMP_READONLY_HEALTH=BLOCKED reason=EXPLICIT_OPTIN_REQUIRED" >&2
  exit 1
fi
if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
  if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
    echo "DUMP_READONLY_HEALTH=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
    exit 1
  fi
  export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
  DUMP_RESTORE_EXEC_ENABLED=false
  unset DUMP_RESTORE_EXECUTOR
else
  unset DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
  if [[ "${DUMP_RESTORE_EXEC_ENABLED:-false}" != "false" || -n "${DUMP_RESTORE_EXECUTOR:-}" ]]; then
    echo "DUMP_READONLY_HEALTH=BLOCKED reason=DUMP_EXECUTOR_MUST_REMAIN_DISABLED" >&2
    exit 1
  fi
  exec 7>"${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
  if ! flock -n 7; then
    echo "DUMP_READONLY_HEALTH=BLOCKED reason=ACTIVE_DR_WORKFLOW" >&2
    exit 1
  fi
  exec 8>"${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
  if ! flock -n 8; then
    echo "DUMP_READONLY_HEALTH=BLOCKED reason=ACTIVE_FAILOVER_WORKFLOW" >&2
    exit 1
  fi
fi

export DUMP_DB_READONLY_HEALTH_ENABLED=true
export DUMP_DB_DNS_PREFLIGHT_ENABLED=true
export DUMP_RESTORE_EXEC_ENABLED=false
unset DUMP_RESTORE_EXECUTOR
export ISOLATED_DUMP_RESTORE_WRAPPER=1
export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
export DR_DUMP_EXECUTOR_CHILD="${DR_DUMP_EXECUTOR_CHILD:-0}"
export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export AWS_REGION="${AWS_REGION:-ap-northeast-2}"

# The preceding DNS gate uses the same SSM-backed, read-only Cloudflare token
# loader. Its token remains in this controller process and is never put in argv.
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"
if ! load_cloudflare_ssm_token >/dev/null; then
  echo "DUMP_READONLY_HEALTH=BLOCKED reason=CLOUDFLARE_READ_CREDENTIAL_UNAVAILABLE" >&2
  exit 1
fi

exec python3 "$SCRIPT_DIR/dump_db_readonly_health.py" "$@"
