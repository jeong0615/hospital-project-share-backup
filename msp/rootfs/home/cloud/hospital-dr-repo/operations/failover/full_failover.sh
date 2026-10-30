#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
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
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
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
DR_STATE_FAILURE_STATUS=FAILED
trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; failover_metric_failed; exit "$rc"' ERR

exec > >(tee -a "$LOG_FILE") 2>&1

failover_timing_start="$(dr_timing_start failover_controller)"

echo "=================================================="
echo "[$(date)] Full DR failover started."
echo "=================================================="
dr_state_write FAILOVER_EXECUTING
dr_state_flag_clear

export ANSIBLE_LIMIT="${ANSIBLE_LIMIT:-all}"
export DB_PROMOTE_ON_FAILOVER="${DB_PROMOTE_ON_FAILOVER:-true}"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi
export MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"

if { [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "db_servers" ]; } && [ -z "$MYSQL_ROOT_PASS" ]; then
  echo "[CONFIG ERROR] Missing required secret: "<SET_IN_SECRET_STORE>" Set it in ${SECRET_FILE}."
  exit 1
fi

echo "[FAILOVER] Target scope: ${ANSIBLE_LIMIT}"
echo "[FAILOVER] DR DB promotion on failover: ${DB_PROMOTE_ON_FAILOVER}"

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

dr_count="$(existing_dr_instance_count)"
if [ "$dr_count" = "3" ]; then
  echo "[FAILOVER] Existing DR EC2 instances found. Starting stopped DR environment and enabling NAT."
  "${FINOPS_DIR}/nat_gateway_control.sh" enable
  "${FINOPS_DIR}/dr_environment_control.sh" start
else
  echo "[FAILOVER] Existing DR EC2 set is incomplete (${dr_count}/3). Running full Terraform provisioning."
  DR_WORKFLOW_LOCK_HELD=1 DR_FAILOVER_LOCK_HELD=1 "${TF_DIR}/run_demo.sh"
fi

if [ "$failover_metrics_owner" = "1" ]; then
  zbx_send dr.failover.status 2 2>/dev/null || true
fi
dr_state_write DR_ACTIVE
dr_timing_end failover_controller "$failover_timing_start"

echo "=================================================="
echo "[$(date)] Full DR failover completed."
echo "=================================================="
