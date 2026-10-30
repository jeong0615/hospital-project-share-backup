#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

if ! dr_load_secret_file || ! dr_resolve_ssh_key_config; then
  exit 1
fi

# Re-read ChatOps's authoritative SQLite request before metrics, locks, or AWS.
dr_verify_chatops_failover_launch || exit 1

FINOPS_DIR="${FINOPS_DIR:-$DR_FINOPS_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/full_failover.log}"
REGION="${AWS_REGION:-ap-northeast-2}"
LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
mkdir -p "$(dirname -- "$LOG_FILE")"

if [ -r "$DR_ZBX_SCRIPT" ]; then
  # Metrics are best-effort; Zabbix must never block DR execution.
  # shellcheck disable=SC1091
  source "$DR_ZBX_SCRIPT"
else
  zbx_send() { :; }
fi
if [ -r "$DR_TIMING_SCRIPT" ]; then
  # shellcheck disable=SC1091
  source "$DR_TIMING_SCRIPT"
else
  dr_timing_start() { printf '0\n'; }
  dr_timing_end() { :; }
  dr_rto_record() { :; }
fi

failover_started_at="${DR_FAILOVER_START_TS:-$(date +%s)}"
failover_metrics_owner=1
if [ "${DR_FAILOVER_METRICS_STARTED:-0}" != "1" ]; then
  export DR_FAILOVER_METRICS_STARTED=1
  export DR_FAILOVER_START_TS="$failover_started_at"
  zbx_send dr.failover.status 1 2>/dev/null || true
else
  failover_metrics_owner=0
fi

failover_metric_failed() {
  zbx_send dr.failover.status 3 2>/dev/null || true
}

dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 7>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 7; then
    echo "[DR FAILOVER ERROR] Another DR workflow is already running."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[DR FAILOVER ERROR] Another failover workflow is already running."
  exit 1
fi
export DR_FAILOVER_LOCK_HELD=1

current_dr_state="$(dr_state_read)"
case "$current_dr_state" in
  IDLE|FAILED) ;;
  *)
    echo "[DR FAILOVER BLOCKED] Cannot start from persistent state ${current_dr_state}."
    exit 1
    ;;
esac

DR_STATE_FAILURE_STATUS=FAILED
trap 'rc=$?; current="$(dr_state_read 2>/dev/null || true)"; case "$current" in FAILOVER_EXECUTING|DR_ACTIVE|PARTIAL_FAILURE) dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true ;; esac; failover_metric_failed; exit "$rc"' ERR

exec > >(tee -a "$LOG_FILE") 2>&1

failover_timing_start="$(dr_timing_start failover_controller)"

echo "=================================================="
echo "[$(date)] Full DR failover started."
echo "=================================================="

echo "[FAILOVER] Scope: existing DR EC2 lifecycle, Web/EMR health, and Cloudflare DNS transaction."

validate_environment_start_config() {
  dr_validate_ssh_key_files
}

existing_dr_instance_count() {
  if ! command -v aws >/dev/null 2>&1 || ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo 0
    return
  fi

  aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'length(Reservations[].Instances[])' \
    --output text
}

validate_environment_start_config
if [ "${SKIP_DNS:-false}" = "true" ]; then
  echo "[FAILOVER BLOCKED] SKIP_DNS=true is preparation-only and cannot be reported as a completed Failover."
  exit 1
fi
dr_count="$(existing_dr_instance_count)"
if [ "$dr_count" = "3" ]; then
  echo "[FAILOVER] Existing approved DR EC2 instances found; only stopped instances will be started."
  dr_rto_record failover_started_at
  dr_rto_record automation_started_at
  "${FINOPS_DIR}/dr_environment_control.sh" start
else
  echo "[FAILOVER BLOCKED] Existing DR EC2 set is incomplete (${dr_count}/3)."
  echo "[FAILOVER BLOCKED] Automatic full provisioning is disabled in the live workflow; complete the reviewed Web NAT Instance provisioning path separately."
  exit 1
fi

if [ "$failover_metrics_owner" = "1" ]; then
  zbx_send dr.failover.status 2 2>/dev/null || true
fi
dr_state_write DR_ACTIVE
echo "[DR STATE] DR_ACTIVE persisted after full failover verification."
dr_rto_record service_recovered_at
if [ "${SKIP_DNS:-false}" != "true" ]; then
  dr_rto_record dns_traffic_recovered_at
fi
dr_timing_end failover_controller "$failover_timing_start"

echo "=================================================="
echo "[$(date)] Full DR failover completed."
echo "=================================================="
dr_rto_record failover_completed_at
