#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

FAILOVER_DIR="${FAILOVER_DIR:-$DR_FAILOVER_DIR}"
SECRET_FILE="$DR_SECRET_FILE"
CHATOPS_DB_FAILBACK_CONFIRM="${DB_FAILBACK_CONFIRM-}"
CHATOPS_DB_FAILBACK_CONFIRM_SET="${DB_FAILBACK_CONFIRM+x}"
CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID="${DB_FAILBACK_CONFIRM_REQUEST_ID-}"
CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID_SET="${DB_FAILBACK_CONFIRM_REQUEST_ID+x}"
if ! dr_load_secret_file || ! dr_resolve_ssh_key_config || ! dr_validate_ssh_key_files; then
  exit 1
fi
if [ "$CHATOPS_DB_FAILBACK_CONFIRM_SET" = "x" ]; then
  DB_FAILBACK_CONFIRM="$CHATOPS_DB_FAILBACK_CONFIRM"
else
  unset DB_FAILBACK_CONFIRM
fi
if [ "$CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID_SET" = "x" ]; then
  DB_FAILBACK_CONFIRM_REQUEST_ID="$CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID"
else
  unset DB_FAILBACK_CONFIRM_REQUEST_ID
fi

require_secret() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required secret: ${name}. Set it in ${SECRET_FILE}."
    exit 1
  fi
}

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: ${name}."
    exit 1
  fi
}

require_secret "MYSQL_ROOT_PASS"
export MYSQL_ROOT_PASS

export RUN_DB_FAILBACK=true
DB_FAILBACK_CONFIRM="${DB_FAILBACK_CONFIRM:-}"
DB_FAILBACK_CONFIRM_REQUEST_ID="${DB_FAILBACK_CONFIRM_REQUEST_ID:-}"
export DB_FAILBACK_CONFIRM DB_FAILBACK_CONFIRM_REQUEST_ID
export ONPREM_DB_HOST="${ONPREM_DB_HOST:-}"
export ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
require_config "ONPREM_DB_HOST"
export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$DR_ANSIBLE_DIR/ansible.cfg}"
export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/ansible-local}"
export ANSIBLE_REMOTE_TEMP="${ANSIBLE_REMOTE_TEMP:-/tmp/ansible-remote}"
export ANSIBLE_SSH_CONTROL_PATH_DIR="${ANSIBLE_SSH_CONTROL_PATH_DIR:-/tmp/ansible-cp}"
export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"
export ANSIBLE_DEPRECATION_WARNINGS="${ANSIBLE_DEPRECATION_WARNINGS:-False}"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore}"
export CLEANUP_NAT_AFTER_FAILBACK="${CLEANUP_NAT_AFTER_FAILBACK:-false}"
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

echo "[DB FAILBACK] The existing AWS DR hospital_db will be copied to the existing On-Prem DB."
echo "[FAILBACK] On-Prem Web/EMR Health and DNS verification remain required; AWS DR EC2 stay running."

"${FAILOVER_DIR}/full_failback.sh"
