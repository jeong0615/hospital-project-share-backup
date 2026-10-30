#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

FAILOVER_DIR="${FAILOVER_DIR:-$DR_FAILOVER_DIR}"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
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

ONPREM_DB_ROOT_PASS="${ONPREM_DB_ROOT_PASS:-}"
ONPREM_DOC_DB_PASSWORD="${ONPREM_DOC_DB_PASSWORD:-${DOC_DB_PASSWORD:-}}"
require_secret "MYSQL_ROOT_PASS"
require_secret "ONPREM_DB_ROOT_PASS"
require_secret "ONPREM_DOC_DB_PASSWORD"
export MYSQL_ROOT_PASS ONPREM_DB_ROOT_PASS ONPREM_DOC_DB_PASSWORD

export RUN_DB_FAILBACK=true
export RUN_DOC_FAILBACK=true
export DB_FAILBACK_CONFIRM=OVERWRITE_ONPREM_DB
export DOC_FAILBACK_CONFIRM="${DOC_FAILBACK_CONFIRM:-SYNC_DOC_TO_ONPREM}"
export ONPREM_DB_HOST="${ONPREM_DB_HOST:-}"
export ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
export ONPREM_DB_ROOT_USER="${ONPREM_DB_ROOT_USER:-restore}"
export ONPREM_DB_ROOT_PASS
export ONPREM_DOC_SSH="${ONPREM_DOC_SSH:-}"
export ONPREM_DOC_PATH="${ONPREM_DOC_PATH:-}"
export ONPREM_DOC_PORT="${ONPREM_DOC_PORT:-5000}"
export ONPREM_DOC_DB_HOST="${ONPREM_DOC_DB_HOST:-}"
export ONPREM_DOC_DB_PORT="${ONPREM_DOC_DB_PORT:-3306}"
export ONPREM_DOC_DB_USER="${ONPREM_DOC_DB_USER:-admin}"
export ONPREM_DOC_DB_PASSWORD
export ONPREM_DOC_DB_NAME="${ONPREM_DOC_DB_NAME:-hospital_db}"
require_config "ONPREM_DB_HOST"
require_config "ONPREM_DOC_SSH"
require_config "ONPREM_DOC_PATH"
require_config "ONPREM_DOC_DB_HOST"
export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$DR_ANSIBLE_DIR/ansible.cfg}"
export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/ansible-local}"
export ANSIBLE_REMOTE_TEMP="${ANSIBLE_REMOTE_TEMP:-/tmp/ansible-remote}"
export ANSIBLE_SSH_CONTROL_PATH_DIR="${ANSIBLE_SSH_CONTROL_PATH_DIR:-/tmp/ansible-cp}"
export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"
export ANSIBLE_DEPRECATION_WARNINGS="${ANSIBLE_DEPRECATION_WARNINGS:-False}"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore}"
export CLEANUP_NAT_AFTER_FAILBACK="${CLEANUP_NAT_AFTER_FAILBACK:-true}"
export STOP_DR_EC2_AFTER_FAILBACK="${STOP_DR_EC2_AFTER_FAILBACK:-false}"
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

echo "[WEB+DOC+DB FAILBACK] DR Web/Doc write data will be copied back to on-premises services."

"${FAILOVER_DIR}/full_failback.sh"
