#!/usr/bin/env bash
set -euo pipefail

export DR_REPO_ROOT="${DR_REPO_ROOT:-/home/cloud/hospital-dr-codex}"
export DR_TERRAFORM_DIR="${DR_TERRAFORM_DIR:-/home/cloud/hospital-dr-terraform}"
export DR_ANSIBLE_DIR="${DR_ANSIBLE_DIR:-/home/cloud/hospital-dr-ansible}"
export DR_OPERATIONS_DIR="${DR_OPERATIONS_DIR:-/home/cloud/hospital-dr-codex/operations}"
export DR_LOG_DIR="${DR_LOG_DIR:-/home/cloud/scripts}"
export LOG_FILE="${LOG_FILE:-/home/cloud/scripts/zabbix_failback_guard.log}"
export SEND_FAILBACK="${SEND_FAILBACK:-/home/cloud/send_failback.sh}"
export ONPREM_WEB_HEALTH_URL="${ONPREM_WEB_HEALTH_URL:-http://IP_REDACTED/}"
export ONPREM_DOC_HEALTH_URL="${ONPREM_DOC_HEALTH_URL:-http://IP_REDACTED/emr/}"
export ONPREM_DB_HOST="${ONPREM_DB_HOST:-IP_REDACTED}"
export ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"

exec bash "$DR_OPERATIONS_DIR/db/zabbix_failback_guard.sh" "$@"
