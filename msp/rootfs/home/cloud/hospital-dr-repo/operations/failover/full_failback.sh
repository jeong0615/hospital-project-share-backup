#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

DB_DIR="${DB_DIR:-$DR_DB_DIR}"
FINOPS_DIR="${FINOPS_DIR:-$DR_FINOPS_DIR}"
FAILOVER_DIR="${FAILOVER_DIR:-$DR_FAILOVER_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/full_failback.log}"
LOCK_FILE="${DR_FAILBACK_LOCK_FILE:-${DR_STATE_DIR}/failback.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
    echo "[DR FAILBACK ERROR] Another DR workflow is already running."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[DR FAILBACK ERROR] Another failback workflow is already running."
  exit 1
fi

if [ -r "$DR_ZBX_SCRIPT" ]; then
  # Metrics are best-effort; Zabbix must never block DR execution.
  # shellcheck disable=SC1091
  source "$DR_ZBX_SCRIPT"
else
  zbx_send() { :; }
  zbx_send_now() { :; }
fi
if [ -r "$DR_TIMING_SCRIPT" ]; then
  # shellcheck disable=SC1091
  source "$DR_TIMING_SCRIPT"
else
  dr_timing_start() { printf '0\n'; }
  dr_timing_end() { :; }
fi

failback_started_at="$(date +%s)"
zbx_send dr.failback.status 1 2>/dev/null || true
failback_metric_failed() {
  zbx_send dr.failback.status 3 2>/dev/null || true
}

DR_STATE_FAILURE_STATUS=FAILED
cleanup_failed=0
stop_failed=0
trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; failback_metric_failed; exit "$rc"' ERR

export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$DR_ANSIBLE_DIR/ansible.cfg}"
export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"
export ANSIBLE_DEPRECATION_WARNINGS="${ANSIBLE_DEPRECATION_WARNINGS:-False}"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore}"

exec > >(tee -a "$LOG_FILE") 2>&1
failback_timing_start="$(dr_timing_start failback)"

echo "=================================================="
echo "[$(date)] Full DR failback started."
echo "=================================================="
dr_state_write FAILBACK_EXECUTING
dr_state_flag_clear

if [ "${RUN_DB_FAILBACK:-false}" = "true" ]; then
  echo "[FAILBACK] Running DB failback workflow."
  db_failback_timing_start="$(dr_timing_start db_failback)"
  "${DB_DIR}/db_failback_to_onprem.sh"
  dr_timing_end db_failback "$db_failback_timing_start"
else
  echo "[FAILBACK] DB failback skipped. Set RUN_DB_FAILBACK=true to enable it."
fi

if [ "${RUN_DOC_FAILBACK:-false}" = "true" ]; then
  echo "[FAILBACK] Running Doc failback workflow."
  doc_sync_timing_start="$(dr_timing_start doc_sync)"
  "${DB_DIR}/doc_failback_sync.sh"
  dr_timing_end doc_sync "$doc_sync_timing_start"
else
  echo "[FAILBACK] Doc failback skipped. Set RUN_DOC_FAILBACK=true to enable it."
fi

echo "[FAILBACK] Returning public web traffic to on-premises."
export DR_FAILBACK_CONTROLLER=1
dns_restore_timing_start="$(dr_timing_start dns_restore)"
"${FAILOVER_DIR}/failback.sh"
dr_timing_end dns_restore "$dns_restore_timing_start"
zbx_send_now dr.dns.cutover_at

if [ "${CLEANUP_NAT_AFTER_FAILBACK:-true}" = "true" ]; then
  echo "[COST CONTROL] Cleaning temporary NAT resources after successful failback. DR EC2 instances are kept unchanged."
  if ! "${FINOPS_DIR}/nat_gateway_control.sh" cleanup; then
    echo "[COST CONTROL ERROR] NAT cleanup failed; failback result is PARTIAL_FAILURE."
    cleanup_failed=1
  fi
else
  echo "[COST CONTROL] NAT cleanup skipped. Set CLEANUP_NAT_AFTER_FAILBACK=true to enable automatic NAT cleanup."
fi

if [ "${STOP_DR_EC2_AFTER_FAILBACK:-false}" = "true" ]; then
  echo "[COST CONTROL] Stopping DR EC2 instances by explicit request."
  if ! "${FINOPS_DIR}/dr_environment_control.sh" stop; then
    echo "[COST CONTROL ERROR] DR EC2 stop failed; failback result is PARTIAL_FAILURE."
    stop_failed=1
  fi
else
  echo "[COST CONTROL] DR EC2 instances were not stopped automatically."
fi

if [ "$cleanup_failed" -ne 0 ] || [ "$stop_failed" -ne 0 ]; then
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  echo "=================================================="
  echo "[DR FAILBACK PARTIAL_FAILURE] Failback completed with cleanup errors; retry or manual cleanup is required."
  echo "=================================================="
  exit 1
fi

echo "=================================================="
zbx_send_now dr.health.passed_at
zbx_send dr.rto.seconds "$(( $(date +%s) - failback_started_at ))"
zbx_send dr.failback.status 2
dr_timing_end failback "$failback_timing_start"
echo "[$(date)] Full DR failback completed."
echo "=================================================="
dr_state_write IDLE
dr_state_flag_clear
