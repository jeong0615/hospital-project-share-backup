#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"

if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  echo "DUMP_PUBLIC_READINESS=BLOCKED reason=DR_SECRET_OR_SSH_CONFIG_UNAVAILABLE" >&2
  exit 1
fi

public_optin="${DUMP_DB_PUBLIC_READINESS_ENABLED:-false}"
readonly_optin="${DUMP_DB_READONLY_HEALTH_ENABLED:-false}"
preflight_optin="${DUMP_DB_DNS_PREFLIGHT_ENABLED:-false}"
if [[ "${public_optin,,}" != "true" \
   || "${readonly_optin,,}" != "true" \
   || "${preflight_optin,,}" != "true" ]]; then
  echo "DUMP_PUBLIC_READINESS=BLOCKED reason=EXPLICIT_OPTIN_REQUIRED" >&2
  exit 1
fi
dump_executor_enabled="${DUMP_RESTORE_EXEC_ENABLED:-false}"
if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
  if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
    echo "DUMP_PUBLIC_READINESS=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
    exit 1
  fi
  export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
  DUMP_RESTORE_EXEC_ENABLED=false
  unset DUMP_RESTORE_EXECUTOR
else
  if [[ "${dump_executor_enabled,,}" != "false" || -n "${DUMP_RESTORE_EXECUTOR:-}" ]]; then
    echo "DUMP_PUBLIC_READINESS=BLOCKED reason=DUMP_EXECUTOR_MUST_REMAIN_DISABLED" >&2
    exit 1
  fi
  unset DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
  exec 7>"${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
  if ! flock -n 7; then
    echo "DUMP_PUBLIC_READINESS=BLOCKED reason=ACTIVE_DR_WORKFLOW" >&2
    exit 1
  fi
  exec 8>"${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
  if ! flock -n 8; then
    echo "DUMP_PUBLIC_READINESS=BLOCKED reason=ACTIVE_FAILOVER_WORKFLOW" >&2
    exit 1
  fi
fi

source "$DR_CLOUDFLARE_AUTH_SCRIPT"
if ! load_cloudflare_ssm_token >/dev/null; then
  echo "DUMP_PUBLIC_READINESS=BLOCKED reason=CLOUDFLARE_READ_CREDENTIAL_UNAVAILABLE" >&2
  exit 1
fi

DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
export ISOLATED_DUMP_RESTORE_WRAPPER=1
export DUMP_DB_PUBLIC_READINESS_ENABLED=true
export DUMP_DB_READONLY_HEALTH_ENABLED=true
export DUMP_DB_DNS_PREFLIGHT_ENABLED=true
export DUMP_RESTORE_EXEC_ENABLED=false
unset DUMP_RESTORE_EXECUTOR
export DR_DUMP_EXECUTOR_CHILD="${DR_DUMP_EXECUTOR_CHILD:-0}"
export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export AWS_REGION="${AWS_REGION:-ap-northeast-2}"
export CF_ZONE_ID CF_RECORD_ID_EXPECTED CF_EMR_RECORD_ID_EXPECTED
export DR_DOMAIN EMR_DOMAIN ONPREM_TUNNEL_HOST ONPREM_EMR_DNS_IP_EXPECTED
export DR_WEB_EIP_EXPECTED DR_DNS_ORIGIN_SNAPSHOT_DIR DR_STATE_FILE
export CLOUDFLARE_API_TOKEN

exec python3 "$SCRIPT_DIR/dump_db_public_readiness.py" "$@"
