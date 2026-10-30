#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"

fail_closed() {
  local reason="$1"
  printf 'DUMP_FAILOVER_EXECUTOR=BLOCKED reason=%s\n' "$reason" >&2
  exit 1
}

dr_load_secret_file || fail_closed DR_SECRET_FILE_UNAVAILABLE
dr_resolve_ssh_key_config || fail_closed SSH_KEY_UNAVAILABLE
dr_validate_ssh_key_files || fail_closed SSH_KEY_UNAVAILABLE

expected_executor="$SCRIPT_DIR/dump_failover_executor.sh"
configured_executor="${DUMP_RESTORE_EXECUTOR:-}"
dump_executor_enabled="${DUMP_RESTORE_EXEC_ENABLED:-false}"
[[ "${dump_executor_enabled,,}" == "true" ]] || fail_closed DUMP_RESTORE_EXECUTOR_DISABLED
[[ "$configured_executor" == /* && ! -L "$configured_executor" && -f "$configured_executor" ]] \
  || fail_closed DUMP_RESTORE_EXECUTOR_PATH_INVALID
[[ "$(realpath -e -- "$configured_executor" 2>/dev/null || true)" == "$(realpath -e -- "$expected_executor")" ]] \
  || fail_closed DUMP_RESTORE_EXECUTOR_PATH_MISMATCH

for setting in \
  DUMP_DB_SERVICE_CUTOVER_ENABLED \
  DUMP_DB_SERVICE_PROMOTION_ENABLED \
  DUMP_DB_DNS_PREFLIGHT_ENABLED \
  DUMP_DB_READONLY_HEALTH_ENABLED \
  DUMP_DB_PUBLIC_READINESS_ENABLED \
  DUMP_DB_DNS_TRANSACTION_ENABLED \
  DUMP_DB_SERVICE_OPEN_ENABLED; do
  value="${!setting:-false}"
  [[ "${value,,}" == "true" ]] || fail_closed "${setting}_NOT_EXPLICITLY_ENABLED"
done

[[ -n "${DUMP_FAILOVER_MAX_RUNTIME_SECONDS:-}" ]] || fail_closed DUMP_FAILOVER_MAX_RUNTIME_SECONDS_REQUIRED
[[ -n "${DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS:-}" ]] || fail_closed DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS_REQUIRED

DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
DR_FAILOVER_LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
DR_STATE_FILE="${DR_STATE_FILE:-${DR_STATE_DIR}/dr_state}"
DR_DNS_ORIGIN_SNAPSHOT_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DUMP_BACKUP_DIR="${DUMP_BACKUP_DIR:-/home/cloud/db_backups}"
CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-${DR_STATE_DIR}/chatops_state.sqlite3}"
INVENTORY="${INVENTORY:-${DR_ANSIBLE_DIR}/inventory.ini}"
DUMP_DB_PUBLIC_READINESS_STATE_DIR="${DUMP_DB_PUBLIC_READINESS_STATE_DIR:-${DR_STATE_DIR}/dump-public-readiness}"
DUMP_DB_DNS_TRANSACTION_STATE_DIR="${DUMP_DB_DNS_TRANSACTION_STATE_DIR:-${DR_STATE_DIR}/dump-dns-transactions}"
DUMP_DB_SERVICE_OPEN_STATE_DIR="${DUMP_DB_SERVICE_OPEN_STATE_DIR:-${DR_STATE_DIR}/dump-service-open}"
DUMP_DB_SERVICE_OPEN_LOCK_FILE="${DUMP_DB_SERVICE_OPEN_LOCK_FILE:-${DUMP_DB_SERVICE_OPEN_STATE_DIR}/.lock}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"

export DR_REPO_ROOT DR_TERRAFORM_DIR DR_ANSIBLE_DIR DR_STATE_DIR DR_STATE_FILE
export DR_SECRET_FILE DR_WORKFLOW_LOCK_FILE DR_FAILOVER_LOCK_FILE
export DR_SSH_PRIVATE_KEY SSH_KEY DR_SSH_KEY DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE
export DUMP_BACKUP_DIR CHATOPS_STATE_DB INVENTORY AWS_REGION
export DUMP_DB_PUBLIC_READINESS_STATE_DIR DUMP_DB_DNS_TRANSACTION_STATE_DIR
export DUMP_DB_SERVICE_OPEN_STATE_DIR DUMP_DB_SERVICE_OPEN_LOCK_FILE
export DR_DNS_ORIGIN_SNAPSHOT_DIR
export DUMP_RESTORE_EXEC_ENABLED=true DUMP_RESTORE_EXECUTOR="$expected_executor"
export DR_DUMP_EXECUTOR_CHILD=1
export DUMP_FAILOVER_MAX_RUNTIME_SECONDS DUMP_FAILOVER_SHUTDOWN_MARGIN_SECONDS
export DUMP_DB_SERVICE_CUTOVER_ENABLED DUMP_DB_SERVICE_PROMOTION_ENABLED
export DUMP_DB_DNS_PREFLIGHT_ENABLED DUMP_DB_READONLY_HEALTH_ENABLED
export DUMP_DB_PUBLIC_READINESS_ENABLED DUMP_DB_DNS_TRANSACTION_ENABLED DUMP_DB_SERVICE_OPEN_ENABLED

for setting in \
  SLACK_ADMIN_USER_IDS CF_ZONE_ID CF_RECORD_ID_EXPECTED CF_EMR_RECORD_ID_EXPECTED \
  DR_DOMAIN EMR_DOMAIN DR_WEB_EIP_EXPECTED ONPREM_TUNNEL_HOST ONPREM_EMR_DNS_IP_EXPECTED \
  TF_VAR_cloudflare_ipv4_cidrs TF_VAR_management_ipv4_cidrs \
  TF_VAR_zabbix_agent_source_ipv4_cidrs TF_VAR_aws_dr_wg_peer_ingress_ipv4_cidrs \
  TF_VAR_aws_dr_wg_enabled DUMP_DB_PUBLIC_READINESS_TTL_SECONDS \
  DUMP_DB_DNS_HEALTH_ATTEMPTS DUMP_DB_DNS_HEALTH_INTERVAL_SECONDS; do
  if [[ -n "${!setting:-}" ]]; then
    export "$setting"
  else
    unset "$setting"
  fi
done

# Credentials are reloaded by the narrowly scoped stage wrappers. Do not carry
# database, Slack, or Cloudflare credentials through the orchestration process.
unset DB_BACKUP_ENCRYPTION_KEY DUMP_RESTORE_SERVICE_DB_PASSWORD MYSQL_ROOT_PASS
unset ONPREM_DB_ROOT_PASS ONPREM_DOC_DB_PASSWORD DOC_DB_PASSWORD
unset CLOUDFLARE_API_TOKEN SLACK_FAILOVER_BOT_TOKEN SLACK_FAILBACK_BOT_TOKEN
unset SLACK_EMERGENCY_BOT_TOKEN SLACK_FAILOVER_SIGNING_SECRET
unset SLACK_FAILBACK_SIGNING_SECRET SLACK_EMERGENCY_SIGNING_SECRET

# Python namespace packages can merge directories from multiple repositories.
# Pin this invocation to the repository containing this wrapper, and reject a
# package search path that resolves outside that release before loading code.
export PYTHONPATH="$REPO_ROOT"
if ! (
  cd -- "$SCRIPT_DIR"
  python3 - "$REPO_ROOT" <<'PY'
import importlib.util
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for name, expected in (
    ("operations", root / "operations"),
    ("operations.db", root / "operations" / "db"),
):
    spec = importlib.util.find_spec(name)
    locations = [Path(item).resolve() for item in (spec.submodule_search_locations or ())] if spec else []
    if spec is None or locations != [expected.resolve()]:
        raise SystemExit(1)
    if spec.origin not in (None, "namespace") and Path(spec.origin).resolve().parent != expected.resolve():
        raise SystemExit(1)
PY
); then
  fail_closed PYTHON_IMPORT_ROOT_MISMATCH
fi

umask 077
exec python3 "$SCRIPT_DIR/dump_failover_executor.py" "$@"
