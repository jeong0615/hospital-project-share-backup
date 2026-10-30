#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec python3 "$SCRIPT_DIR/demo_dump_restore_existing_dr_apps.py" --help
fi

DR_REPO_ROOT="$REPO_ROOT"
export DR_REPO_ROOT
source "$REPO_ROOT/operations/runtime_paths.sh"
fail_closed() {
  printf 'DEMO_DUMP_APPS=BLOCKED code=%s\n' "$1" >&2
  exit 1
}

dr_load_secret_file || fail_closed DR_SECRET_FILE_UNAVAILABLE
dr_resolve_ssh_key_config || fail_closed SSH_KEY_UNAVAILABLE
[[ -n "${SSH_KEY:-}" && -r "$SSH_KEY" ]] || fail_closed SSH_KEY_UNAVAILABLE

DR_REPO_ROOT="$REPO_ROOT"
DR_STATE_DIR="${DR_STATE_DIR:-/var/lib/hospital-dr}"
DR_SSH_CONFIG_FILE="${DR_SSH_CONFIG_FILE:-$DR_STATE_DIR/ssh/config}"
DR_SSH_KNOWN_HOSTS_FILE="${DR_SSH_KNOWN_HOSTS_FILE:-$DR_STATE_DIR/ssh/known_hosts}"
DEMO_DUMP_RESTORE_STATE_DIR="${DEMO_DUMP_RESTORE_STATE_DIR:-$DR_STATE_DIR/demo-dump-restores}"
DEMO_DUMP_APPS_START_ENABLED="${DEMO_DUMP_APPS_START_ENABLED:-false}"
DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID="${DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID:-}"

# Pass only connection/runtime settings to Python. MySQL and backup secrets
# are intentionally not inherited by this read-only app-start follow-up.
python_env=(
  env -i
  "PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
  "HOME=${HOME:-/home/cloud}"
  "USER=${USER:-cloud}"
  "LOGNAME=${LOGNAME:-${USER:-cloud}}"
  "DR_REPO_ROOT=$DR_REPO_ROOT"
  "DR_SECRET_FILE=$DR_SECRET_FILE"
  "DR_STATE_DIR=$DR_STATE_DIR"
  "DR_SSH_CONFIG_FILE=$DR_SSH_CONFIG_FILE"
  "DR_SSH_KNOWN_HOSTS_FILE=$DR_SSH_KNOWN_HOSTS_FILE"
  "DR_WORKFLOW_LOCK_FILE=${DR_WORKFLOW_LOCK_FILE:-$DR_STATE_DIR/workflow.lock}"
  "DR_FAILOVER_LOCK_FILE=${DR_FAILOVER_LOCK_FILE:-$DR_STATE_DIR/failover.lock}"
  "DEMO_DUMP_RESTORE_STATE_DIR=$DEMO_DUMP_RESTORE_STATE_DIR"
  "DEMO_DUMP_APPS_START_ENABLED=$DEMO_DUMP_APPS_START_ENABLED"
  "DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID=$DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID"
  "SSH_KEY=$SSH_KEY"
  "DR_SSH_PRIVATE_KEY=$SSH_KEY"
  "DR_SSH_KEY=$SSH_KEY"
)
for name in AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE SSH_AUTH_SOCK; do
  if [[ -n "${!name:-}" ]]; then
    python_env+=("$name=${!name}")
  fi
done
while IFS= read -r name; do
  [[ "$name" == AWS_* ]] || continue
  python_env+=("$name=${!name}")
done < <(compgen -A variable)

exec "${python_env[@]}" python3 "$SCRIPT_DIR/demo_dump_restore_existing_dr_apps.py" "$@"
