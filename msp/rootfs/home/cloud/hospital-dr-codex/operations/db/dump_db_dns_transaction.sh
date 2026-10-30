#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"

# This is a one-invocation operator opt-in. A value stored in dr.env cannot
# silently authorize a DNS write.
explicit_transaction_optin="${DUMP_DB_DNS_TRANSACTION_ENABLED:-false}"
if [[ "${explicit_transaction_optin,,}" != "true" ]]; then
  echo "DUMP_DNS_TRANSACTION=BLOCKED reason=EXPLICIT_OPERATOR_OPTIN_REQUIRED" >&2
  exit 1
fi

if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  echo "DUMP_DNS_TRANSACTION=BLOCKED reason=DR_SECRET_OR_SSH_CONFIG_UNAVAILABLE" >&2
  exit 1
fi

for setting in DUMP_DB_PUBLIC_READINESS_ENABLED DUMP_DB_READONLY_HEALTH_ENABLED DUMP_DB_DNS_PREFLIGHT_ENABLED; do
  value="${!setting:-false}"
  if [[ "${value,,}" != "true" ]]; then
    echo "DUMP_DNS_TRANSACTION=BLOCKED reason=PREPARATION_OPTINS_REQUIRED" >&2
    exit 1
  fi
done
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
DR_STATE_FILE="${DR_STATE_FILE:-${DR_STATE_DIR}/dr_state}"
DR_DNS_ORIGIN_SNAPSHOT_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
DUMP_DB_DNS_TRANSACTION_STATE_DIR="${DUMP_DB_DNS_TRANSACTION_STATE_DIR:-/var/lib/hospital-dr/dump-dns-transactions}"
DUMP_DB_DNS_TRANSACTION_LOCK_FILE="${DUMP_DB_DNS_TRANSACTION_LOCK_FILE:-${DUMP_DB_DNS_TRANSACTION_STATE_DIR}/.lock}"
CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-${DR_STATE_DIR}/chatops_state.sqlite3}"

DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
DR_FAILOVER_LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
  if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
    echo "DUMP_DNS_TRANSACTION=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
    exit 1
  fi
  DUMP_RESTORE_EXEC_ENABLED=false
  unset DUMP_RESTORE_EXECUTOR
else
  dump_executor_enabled="${DUMP_RESTORE_EXEC_ENABLED:-false}"
  if [[ "${dump_executor_enabled,,}" != "false" || -n "${DUMP_RESTORE_EXECUTOR:-}" ]]; then
    echo "DUMP_DNS_TRANSACTION=BLOCKED reason=DUMP_EXECUTOR_MUST_REMAIN_DISABLED" >&2
    exit 1
  fi
  # Standalone invocations acquire the canonical locks themselves; the
  # integrated executor passes verified descriptors 7/8 to avoid self-deadlock.
  unset DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
  exec 7>"$DR_WORKFLOW_LOCK_FILE"
  if ! flock -n 7; then
    echo "DUMP_DNS_TRANSACTION=BLOCKED reason=ACTIVE_DR_WORKFLOW" >&2
    exit 1
  fi
  exec 8>"$DR_FAILOVER_LOCK_FILE"
  if ! flock -n 8; then
    echo "DUMP_DNS_TRANSACTION=BLOCKED reason=ACTIVE_FAILOVER_WORKFLOW" >&2
    exit 1
  fi
fi

# Load the short-lived API credential from the existing SSM-backed provider.
# It is inherited by Python, never placed on argv or printed.
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"
if ! load_cloudflare_ssm_token >/dev/null; then
  echo "DUMP_DNS_TRANSACTION=BLOCKED reason=CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE" >&2
  exit 1
fi

export ISOLATED_DUMP_RESTORE_WRAPPER=1
export DR_WORKFLOW_LOCK_FILE DR_FAILOVER_LOCK_FILE
export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
export DR_DUMP_EXECUTOR_CHILD="${DR_DUMP_EXECUTOR_CHILD:-0}"
export DUMP_DB_DNS_TRANSACTION_ENABLED=true
export DUMP_DB_PUBLIC_READINESS_ENABLED DUMP_DB_READONLY_HEALTH_ENABLED DUMP_DB_DNS_PREFLIGHT_ENABLED
export DUMP_RESTORE_EXEC_ENABLED=false
unset DUMP_RESTORE_EXECUTOR
export AWS_REGION DR_STATE_FILE DR_DNS_ORIGIN_SNAPSHOT_DIR DR_DOMAIN EMR_DOMAIN DR_WEB_EIP_EXPECTED
export DUMP_DB_DNS_TRANSACTION_STATE_DIR DUMP_DB_DNS_TRANSACTION_LOCK_FILE
export CHATOPS_STATE_DB
export DR_WORKFLOW_LOCK_FILE DR_FAILOVER_LOCK_FILE
export CF_ZONE_ID CF_RECORD_ID_EXPECTED CF_EMR_RECORD_ID_EXPECTED
export ONPREM_TUNNEL_HOST ONPREM_EMR_DNS_IP_EXPECTED
export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE CLOUDFLARE_API_TOKEN
DUMP_DB_DNS_HEALTH_ATTEMPTS="${DUMP_DB_DNS_HEALTH_ATTEMPTS:-4}"
DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS="${DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS:-5}"
export DUMP_DB_DNS_HEALTH_ATTEMPTS DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS

exec python3 "$SCRIPT_DIR/dump_db_dns_transaction.py" "$@"
