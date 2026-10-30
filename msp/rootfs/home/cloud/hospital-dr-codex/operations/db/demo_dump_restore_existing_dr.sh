#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec python3 "$SCRIPT_DIR/demo_dump_restore_existing_dr.py" --help
fi

# Parse and validate the three-argument contract before reading secrets or
# touching AWS. This mode performs no external calls or state changes.
python3 "$SCRIPT_DIR/demo_dump_restore_existing_dr.py" --validate-cli-only "$@"

# shellcheck disable=SC1091
source "$REPO_ROOT/operations/runtime_paths.sh"
fail_closed() {
  printf 'DEMO_DUMP_RESTORE=BLOCKED reason=%s\n' "$1" >&2
  exit 1
}

dr_load_secret_file || fail_closed DR_SECRET_FILE_UNAVAILABLE
dr_resolve_ssh_key_config || fail_closed SSH_KEY_UNAVAILABLE
dr_validate_ssh_key_files || fail_closed SSH_KEY_UNAVAILABLE

[[ "${DUMP_RESTORE_EXEC_ENABLED:-false}" == "true" ]] || fail_closed DUMP_RESTORE_EXECUTOR_DISABLED
[[ -n "${MYSQL_ROOT_PASS:-}" && -n "${DB_BACKUP_ENCRYPTION_KEY:-}" ]] || fail_closed DATABASE_SECRET_UNAVAILABLE

secret_tmpfs="$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)"
[[ "$secret_tmpfs" == "tmpfs" ]] || fail_closed SECRET_TMPFS_UNAVAILABLE
umask 077
secret_dir="$(mktemp -d /dev/shm/hospital-dr-demo-runner.XXXXXX)" || fail_closed SECRET_TMPFS_UNAVAILABLE
chmod 0700 "$secret_dir"
cleanup_demo_runner() {
  rm -f -- "$secret_dir/mysql_root_pass" "$secret_dir/backup_key"
  rmdir -- "$secret_dir" 2>/dev/null || true
}
trap cleanup_demo_runner EXIT INT TERM
printf '%s' "$MYSQL_ROOT_PASS" >"$secret_dir/mysql_root_pass"
printf '%s' "$DB_BACKUP_ENCRYPTION_KEY" >"$secret_dir/backup_key"
chmod 0600 "$secret_dir/mysql_root_pass" "$secret_dir/backup_key"
unset MYSQL_ROOT_PASS DB_BACKUP_ENCRYPTION_KEY

# These are global executor gates only. The request-specific overwrite grant
# is read and verified from the protected ChatOps SQLite approval record.
export DUMP_RESTORE_EXEC_ENABLED DUMP_RESTORE_EXECUTOR
export DR_STATE_DIR DR_SECRET_FILE SSH_KEY DR_SSH_PRIVATE_KEY DR_SSH_KEY
export DR_SSH_CONFIG_FILE DR_SSH_KNOWN_HOSTS_FILE AWS_REGION AWS_DEFAULT_REGION
export CHATOPS_STATE_DB SLACK_ADMIN_USER_IDS DUMP_BACKUP_DIR
export DEMO_DUMP_RESTORE_STATE_DIR
export DEMO_DUMP_SECRET_DIR="$secret_dir"
export PYTHONPATH="$REPO_ROOT"

set +e
python3 "$SCRIPT_DIR/demo_dump_restore_existing_dr.py" "$@"
status=$?
set -e
exit "$status"
