#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec python3 "$SCRIPT_DIR/demo_dump_finalize_existing_dr.py" --help
fi

# Preserve request-scoped authority supplied by this invocation. The shared
# dr.env is for credentials/configuration and must not silently authorize a
# different finalization request.
DR_REPO_ROOT="$REPO_ROOT"
export DR_REPO_ROOT
DR_CLOUDFLARE_AUTH_SCRIPT="$REPO_ROOT/operations/cloudflare_ssm_auth.sh"
export DR_CLOUDFLARE_AUTH_SCRIPT
approved_enabled="${DEMO_DUMP_FINALIZE_ENABLED:-false}"
approved_request="${DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID:-}"
approved_backup="${DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID:-}"
approved_sha="${DEMO_DUMP_FINALIZE_APPROVED_SHA256:-}"
source "$REPO_ROOT/operations/runtime_paths.sh"
fail_closed() {
  printf 'DEMO_DUMP_FINALIZE=BLOCKED code=%s\n' "$1" >&2
  exit 1
}

dr_load_secret_file || fail_closed DR_SECRET_FILE_UNAVAILABLE
# This final stage never decrypts a backup; don't retain or forward its key.
unset DB_BACKUP_ENCRYPTION_KEY
# A dr.env assignment must not redirect this runner to another source tree
# or another token-loader script after runtime_paths.sh computed the local paths.
DR_REPO_ROOT="$REPO_ROOT"
DR_CLOUDFLARE_AUTH_SCRIPT="$REPO_ROOT/operations/cloudflare_ssm_auth.sh"
export DR_REPO_ROOT DR_CLOUDFLARE_AUTH_SCRIPT
dr_resolve_ssh_key_config || fail_closed SSH_KEY_UNAVAILABLE
dr_validate_ssh_key_files || fail_closed SSH_KEY_UNAVAILABLE
[[ "${approved_enabled,,}" == true ]] || fail_closed DUMP_FINALIZE_DISABLED
[[ -n "$approved_request" && -n "$approved_backup" && -n "$approved_sha" ]] || fail_closed REQUEST_SCOPED_FINALIZATION_AUTHORIZATION_REQUIRED
DEMO_DUMP_FINALIZE_ENABLED="$approved_enabled"
DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID="$approved_request"
DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID="$approved_backup"
DEMO_DUMP_FINALIZE_APPROVED_SHA256="$approved_sha"
export DEMO_DUMP_FINALIZE_ENABLED DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID
export DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID DEMO_DUMP_FINALIZE_APPROVED_SHA256

dump_exec_enabled="${DUMP_RESTORE_EXEC_ENABLED:-false}"
[[ "${dump_exec_enabled,,}" == false ]] || fail_closed DUMP_EXECUTOR_MUST_REMAIN_DISABLED
[[ -z "${DUMP_RESTORE_EXECUTOR:-}" ]] || fail_closed DUMP_EXECUTOR_MUST_REMAIN_UNSET
[[ -n "${MYSQL_ROOT_PASS:-}" ]] || fail_closed MYSQL_ROOT_SECRET_UNAVAILABLE
[[ -n "${SLACK_FAILOVER_BOT_TOKEN:-}" ]] || fail_closed SLACK_FINAL_RESULT_CREDENTIAL_UNAVAILABLE
[[ -n "${SLACK_ADMIN_USER_IDS:-}" ]] || fail_closed SLACK_ADMIN_ALLOWLIST_UNAVAILABLE

tmpfs_type="$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)"
[[ "$tmpfs_type" == tmpfs ]] || fail_closed SECRET_TMPFS_UNAVAILABLE
umask 077
secret_dir="$(mktemp -d /dev/shm/hospital-dr-demo-finalize.XXXXXX)" || fail_closed SECRET_TMPFS_UNAVAILABLE
chmod 0700 "$secret_dir"
cleanup_finalize_secret() {
  rm -f -- "$secret_dir/mysql_root_pass"
  rmdir -- "$secret_dir" 2>/dev/null || true
}
trap cleanup_finalize_secret EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s' "$MYSQL_ROOT_PASS" > "$secret_dir/mysql_root_pass"
chmod 0600 "$secret_dir/mysql_root_pass"
unset MYSQL_ROOT_PASS

source "$DR_CLOUDFLARE_AUTH_SCRIPT"
load_cloudflare_ssm_token >/dev/null || fail_closed CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE

DR_STATE_DIR="${DR_STATE_DIR:-/var/lib/hospital-dr}"
DR_STATE_FILE="${DR_STATE_FILE:-$DR_STATE_DIR/dr_state}"
DR_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-$DR_STATE_DIR/workflow.lock}"
DR_FAILOVER_LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-$DR_STATE_DIR/failover.lock}"
CHATOPS_STATE_DB="${CHATOPS_STATE_DB:-$DR_STATE_DIR/chatops_state.sqlite3}"
CHATOPS_EXECUTION_LOG_DIR="${CHATOPS_EXECUTION_LOG_DIR:-$DR_STATE_DIR/execution-logs}"
DEMO_DUMP_RESTORE_STATE_DIR="${DEMO_DUMP_RESTORE_STATE_DIR:-$DR_STATE_DIR/demo-dump-restores}"
export DR_STATE_DIR DR_STATE_FILE DR_WORKFLOW_LOCK_FILE DR_FAILOVER_LOCK_FILE
export CHATOPS_STATE_DB CHATOPS_EXECUTION_LOG_DIR DEMO_DUMP_RESTORE_STATE_DIR
export DEMO_DUMP_FINALIZE_MYSQL_SECRET_FILE="$secret_dir/mysql_root_pass"
export DR_REPO_ROOT="$REPO_ROOT" PYTHONPATH="$REPO_ROOT"

python_env=(
  env -i
  "PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
  "HOME=${HOME:-/home/cloud}"
  "USER=${USER:-cloud}"
  "LOGNAME=${LOGNAME:-${USER:-cloud}}"
  "PYTHONPATH=$REPO_ROOT"
  "DR_REPO_ROOT=$REPO_ROOT"
  "DR_SECRET_FILE=$DR_SECRET_FILE"
  "DR_STATE_DIR=$DR_STATE_DIR"
  "DR_STATE_FILE=$DR_STATE_FILE"
  "DR_WORKFLOW_LOCK_FILE=$DR_WORKFLOW_LOCK_FILE"
  "DR_FAILOVER_LOCK_FILE=$DR_FAILOVER_LOCK_FILE"
  "DR_SSH_CONFIG_FILE=$DR_SSH_CONFIG_FILE"
  "DR_SSH_KNOWN_HOSTS_FILE=$DR_SSH_KNOWN_HOSTS_FILE"
  "SSH_KEY=$SSH_KEY"
  "DR_SSH_PRIVATE_KEY=$SSH_KEY"
  "CHATOPS_STATE_DB=$CHATOPS_STATE_DB"
  "CHATOPS_EXECUTION_LOG_DIR=$CHATOPS_EXECUTION_LOG_DIR"
  "DEMO_DUMP_RESTORE_STATE_DIR=$DEMO_DUMP_RESTORE_STATE_DIR"
  "DUMP_BACKUP_DIR=${DUMP_BACKUP_DIR:-}"
  "SLACK_ADMIN_USER_IDS=$SLACK_ADMIN_USER_IDS"
  "SLACK_FAILOVER_BOT_TOKEN=$SLACK_FAILOVER_BOT_TOKEN"
  "CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN"
  "CF_ZONE_ID=${CF_ZONE_ID:-}"
  "CF_RECORD_ID=${CF_RECORD_ID:-}"
  "DR_CF_WEB_RECORD_ID_EXPECTED=${DR_CF_WEB_RECORD_ID_EXPECTED:-${CF_RECORD_ID_EXPECTED:-${CF_RECORD_ID:-}}}"
  "DR_CF_EMR_RECORD_ID_EXPECTED=${DR_CF_EMR_RECORD_ID_EXPECTED:-${CF_EMR_RECORD_ID_EXPECTED:-${CF_EMR_RECORD_ID:-}}}"
  "CF_RECORD_ID_EXPECTED=${CF_RECORD_ID_EXPECTED:-}"
  "CF_EMR_RECORD_ID_EXPECTED=${CF_EMR_RECORD_ID_EXPECTED:-}"
  "ONPREM_TUNNEL_HOST=${ONPREM_TUNNEL_HOST:-}"
  "ONPREM_EMR_DNS_IP_EXPECTED=${ONPREM_EMR_DNS_IP_EXPECTED:-}"
  "ONPREM_DB_SERVER_UUID_EXPECTED=${ONPREM_DB_SERVER_UUID_EXPECTED:-}"
  "DEMO_DUMP_FINALIZE_ENABLED=$DEMO_DUMP_FINALIZE_ENABLED"
  "DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID=$DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID"
  "DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID=$DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID"
  "DEMO_DUMP_FINALIZE_APPROVED_SHA256=$DEMO_DUMP_FINALIZE_APPROVED_SHA256"
  "DEMO_DUMP_FINALIZE_MYSQL_SECRET_FILE=$DEMO_DUMP_FINALIZE_MYSQL_SECRET_FILE"
  "DUMP_RESTORE_EXEC_ENABLED=${DUMP_RESTORE_EXEC_ENABLED:-false}"
  "DUMP_RESTORE_EXECUTOR=${DUMP_RESTORE_EXECUTOR:-}"
  "AWS_REGION=${AWS_REGION:-ap-northeast-2}"
  "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-${AWS_REGION:-ap-northeast-2}}"
  "DR_DUMP_EXECUTOR_CHILD=0"
)
for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE SSH_AUTH_SOCK; do
  if [[ -n "${!name:-}" ]]; then
    python_env+=("$name=${!name}")
  fi
done
set +e
"${python_env[@]}" python3 "$SCRIPT_DIR/demo_dump_finalize_existing_dr.py" "$@"
status=$?
set -e
exit "$status"
