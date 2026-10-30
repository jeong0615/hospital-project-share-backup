#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"

if [[ "${DR_DUMP_EXECUTOR_CHILD:-0}" != "1" ]]; then
  echo "DUMP_SERVICE_OPEN=BLOCKED reason=INTEGRATED_EXECUTOR_REQUIRED" >&2
  exit 1
fi
if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  echo "DUMP_SERVICE_OPEN=BLOCKED reason=DR_SECRET_OR_SSH_CONFIG_UNAVAILABLE" >&2
  exit 1
fi
if ! python3 "$SCRIPT_DIR/dump_execution_contract.py" --verify-inherited >/dev/null; then
  echo "DUMP_SERVICE_OPEN=BLOCKED reason=SHARED_DR_EXECUTION_LOCK_REQUIRED" >&2
  exit 1
fi
service_open_optin="${DUMP_DB_SERVICE_OPEN_ENABLED:-false}"
if [[ "${service_open_optin,,}" != "true" ]]; then
  echo "DUMP_SERVICE_OPEN=BLOCKED reason=DUMP_SERVICE_OPEN_NOT_EXPLICITLY_ENABLED" >&2
  exit 1
fi

export DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
export DR_FAILOVER_LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
export DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1
export ISOLATED_DUMP_RESTORE_WRAPPER=1
export DUMP_RESTORE_EXEC_ENABLED=false
unset DUMP_RESTORE_EXECUTOR
export AWS_REGION="${AWS_REGION:-ap-northeast-2}"
export SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export DR_DUMP_EXECUTOR_CHILD=1

# The Cloudflare credential is loaded only for this short-lived controller.
# It is never added to argv, the request log, or a receipt.
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"
if ! load_cloudflare_ssm_token >/dev/null; then
  echo "DUMP_SERVICE_OPEN=BLOCKED reason=CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE" >&2
  exit 1
fi

export INVENTORY="${INVENTORY:-${DR_ANSIBLE_DIR}/inventory.ini}"
export CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-${DR_STATE_DIR}/chatops_state.sqlite3}"
export DR_STATE_FILE="${DR_STATE_FILE:-${DR_STATE_DIR}/dr_state}"
export DR_DNS_ORIGIN_SNAPSHOT_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
export DUMP_DB_DNS_TRANSACTION_STATE_DIR="${DUMP_DB_DNS_TRANSACTION_STATE_DIR:-${DR_STATE_DIR}/dump-dns-transactions}"
export DUMP_DB_PUBLIC_READINESS_STATE_DIR="${DUMP_DB_PUBLIC_READINESS_STATE_DIR:-${DR_STATE_DIR}/dump-public-readiness}"
export DUMP_DB_SERVICE_OPEN_STATE_DIR="${DUMP_DB_SERVICE_OPEN_STATE_DIR:-${DR_STATE_DIR}/dump-service-open}"
export DUMP_DB_SERVICE_OPEN_LOCK_FILE="${DUMP_DB_SERVICE_OPEN_LOCK_FILE:-${DUMP_DB_SERVICE_OPEN_STATE_DIR}/.lock}"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
export DUMP_DB_SERVICE_OPEN_ENABLED=true
export DUMP_DB_SERVICE_CUTOVER_ENABLED DUMP_DB_SERVICE_PROMOTION_ENABLED
export DUMP_DB_DNS_TRANSACTION_ENABLED DUMP_DB_PUBLIC_READINESS_ENABLED
export DUMP_DB_READONLY_HEALTH_ENABLED DUMP_DB_DNS_PREFLIGHT_ENABLED
export CF_ZONE_ID CF_RECORD_ID_EXPECTED CF_EMR_RECORD_ID_EXPECTED
export DR_DOMAIN EMR_DOMAIN DR_WEB_EIP_EXPECTED ONPREM_TUNNEL_HOST ONPREM_EMR_DNS_IP_EXPECTED
export TF_VAR_cloudflare_ipv4_cidrs TF_VAR_management_ipv4_cidrs
export DUMP_DB_DNS_HEALTH_ATTEMPTS DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS
export CLOUDFLARE_API_TOKEN

exec python3 "$SCRIPT_DIR/dump_db_service_open.py" "$@"
