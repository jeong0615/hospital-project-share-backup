#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../runtime_paths.sh"

explicit_preflight_optin="${DUMP_DB_DNS_PREFLIGHT_ENABLED:-false}"

if ! dr_load_secret_file; then
  echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=DR_SECRET_FILE_UNAVAILABLE" >&2
  exit 1
fi
if [[ "$explicit_preflight_optin" == "true" ]]; then
  DUMP_DB_DNS_PREFLIGHT_ENABLED=true
fi
if [[ "${DUMP_DB_DNS_PREFLIGHT_ENABLED:-false}" != "true" ]]; then
  echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=DUMP_DNS_PREFLIGHT_NOT_EXPLICITLY_ENABLED" >&2
  exit 1
fi
if ! dr_resolve_ssh_key_config; then
  echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=SSH_KEY_UNAVAILABLE" >&2
  exit 1
fi

DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
DR_FAILOVER_LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" == "1" ]]; then
  if ! python3 "$(dirname -- "${BASH_SOURCE[0]}")/dump_execution_contract.py" --verify-inherited >/dev/null; then
    echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
    exit 1
  fi
  export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
  DUMP_RESTORE_EXEC_ENABLED=false
  unset DUMP_RESTORE_EXECUTOR
else
  if [[ "${DUMP_RESTORE_EXEC_ENABLED:-false}" != "false" || -n "${DUMP_RESTORE_EXECUTOR:-}" ]]; then
    echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=DUMP_EXECUTOR_MUST_REMAIN_DISABLED" >&2
    exit 1
  fi
fi

AWS_REGION="${AWS_REGION:-ap-northeast-2}"
DR_STATE_FILE="${DR_STATE_FILE:-${DR_STATE_DIR}/dr_state}"
DR_DNS_ORIGIN_SNAPSHOT_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"

# Use the existing SSM-backed Cloudflare token path. The token is inherited only
# by the preflight process and is never written to command arguments or output.
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"
if ! load_cloudflare_ssm_token >/dev/null; then
  echo "DUMP_DNS_PREFLIGHT=BLOCKED reason=CLOUDFLARE_READ_CREDENTIAL_UNAVAILABLE" >&2
  exit 1
fi

export ISOLATED_DUMP_RESTORE_WRAPPER=1
export DR_DUMP_EXECUTOR_CHILD="${DR_DUMP_EXECUTOR_CHILD:-0}"
export DR_WORKFLOW_LOCK_FILE DR_FAILOVER_LOCK_FILE
export DR_WORKFLOW_LOCK_HELD DR_FAILOVER_LOCK_HELD
export DUMP_DB_DNS_PREFLIGHT_ENABLED DUMP_RESTORE_EXEC_ENABLED DUMP_RESTORE_EXECUTOR
export AWS_REGION CF_ZONE_ID CF_RECORD_ID_EXPECTED CF_EMR_RECORD_ID_EXPECTED
export DR_DOMAIN EMR_DOMAIN ONPREM_TUNNEL_HOST ONPREM_EMR_DNS_IP_EXPECTED
export DR_WEB_EIP_EXPECTED DR_DNS_ORIGIN_SNAPSHOT_DIR DR_STATE_DIR DR_STATE_FILE
export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export CLOUDFLARE_API_TOKEN

exec python3 "${SCRIPT_DIR}/dump_db_dns_preflight.py" "$@"
