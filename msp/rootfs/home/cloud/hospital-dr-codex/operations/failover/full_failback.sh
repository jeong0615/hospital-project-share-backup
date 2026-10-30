#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"

DB_DIR="${DB_DIR:-$DR_DB_DIR}"
FINOPS_DIR="${FINOPS_DIR:-$DR_FINOPS_DIR}"
FAILOVER_DIR="${FAILOVER_DIR:-$DR_FAILOVER_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/full_failback.log}"
LOCK_FILE="${DR_FAILBACK_LOCK_FILE:-${DR_STATE_DIR}/failback.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
DNS_ORIGIN_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DNS_ARCHIVE_DIR="${DR_DNS_ORIGIN_ARCHIVE_DIR:-${DR_STATE_DIR}/dns/origin-archive}"
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
current_dr_state="$(dr_state_read 2>/dev/null || true)"
if [ "$current_dr_state" != "DR_ACTIVE" ]; then
  echo "[DR FAILBACK BLOCKED] Expected DR_ACTIVE before failback; found ${current_dr_state:-UNKNOWN}."
  exit 1
fi
DR_STATE_FAILURE_STATUS=DR_ACTIVE
if [ "${RUN_DB_FAILBACK:-false}" != "true" ]; then
  echo "[DR FAILBACK BLOCKED] The approved Failback path must include the existing DR-to-On-Prem DB restore."
  exit 1
fi

dr_state_write FAILBACK_EXECUTING
dr_state_flag_clear

export DR_FAILBACK_CONTROLLER=1
echo "[FAILBACK PREFLIGHT] Verifying On-Prem Web/EMR Health and preserved DNS before changing either database."
if ! "${FAILOVER_DIR}/failback.sh" --preflight-only; then
  echo "[DR FAILBACK BLOCKED] On-Prem Health or DNS preflight failed before database changes."
  exit 1
fi

echo "[FAILBACK] Copying the current DR hospital_db to On-Prem; NR status is not a prerequisite."
db_failback_timing_start="$(dr_timing_start db_failback)"
"${DB_DIR}/db_failback_to_onprem.sh"
dr_timing_end db_failback "$db_failback_timing_start"

echo "[FAILBACK] Returning public web traffic to on-premises."
dns_restore_timing_start="$(dr_timing_start dns_restore)"
if ! "${FAILOVER_DIR}/failback.sh"; then
  current_after_dns="$(dr_state_read 2>/dev/null || true)"
  if [ "$current_after_dns" = "DR_ACTIVE" ]; then
    DR_STATE_FAILURE_STATUS=DR_ACTIVE
    echo "[FAILBACK RECOVERY] DNS remains on DR; the DR DB stays read-only until an operator verifies a single-writer recovery plan."
    "${DB_DIR}/db_failback_to_onprem.sh" --restore-dr-primary || {
      DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
      dr_state_write PARTIAL_FAILURE 2>/dev/null || true
      echo "[DR FAILBACK PARTIAL_FAILURE] DNS stayed on DR; DB writer roles require operator review."
    }
  else
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  fi
  exit 1
fi
dr_timing_end dns_restore "$dns_restore_timing_start"
zbx_send_now dr.dns.cutover_at

if [ "${CLEANUP_NAT_AFTER_FAILBACK:-false}" = "true" ]; then
  echo "[COST CONTROL] Automatic NAT cleanup is disabled for the Web NAT Instance architecture."
  echo "[COST CONTROL] Review egress state first, then invoke the dedicated operations/nat command manually if required."
else
  echo "[COST CONTROL] NAT cleanup skipped."
fi

echo "[EC2 LIFECYCLE] DR Web/EMR/DB EC2 states are operator-managed and were not changed by Failback."

if [ "$cleanup_failed" -ne 0 ]; then
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  echo "=================================================="
  echo "[DR FAILBACK PARTIAL_FAILURE] Failback completed with cleanup errors; retry or manual cleanup is required."
  echo "=================================================="
  exit 1
fi

if [ -d "$DNS_ORIGIN_DIR" ]; then
  if ! dr_dns_archive_origin_pair "$DNS_ORIGIN_DIR" "$DNS_ARCHIVE_DIR"; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    echo "[DR FAILBACK PARTIAL_FAILURE] DNS is restored, but the origin snapshot could not be archived."
    exit 1
  fi
fi

echo "=================================================="
zbx_send_now dr.health.passed_at
zbx_send dr.failback.status 2
dr_timing_end failback "$failback_timing_start"
echo "[$(date)] Full DR failback completed."
echo "=================================================="
dr_state_write IDLE
dr_state_flag_clear
