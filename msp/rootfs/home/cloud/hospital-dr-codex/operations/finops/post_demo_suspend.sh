#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/post_demo_suspend.log}"
LOCK_FILE="${DR_POST_DEMO_LOCK_FILE:-${DR_STATE_DIR}/post-demo-suspend.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
FAILBACK_SCRIPT="${FAILBACK_SCRIPT:-$TF_DIR/failback.sh}"
STATUS_SCRIPT="${STATUS_SCRIPT:-$TF_DIR/dr_environment_control.sh}"
SKIP_DNS="${SKIP_DNS:-false}"
DR_STATE_FAILURE_STATUS=FAILED
partial_failure=0

mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
    echo "[SUSPEND ERROR] Another DR workflow is already running."
    echo "[중단 오류] 다른 DR 워크플로가 이미 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[SUSPEND ERROR] Another post-demo suspend workflow is already running."
  echo "[중단 오류] 다른 시연 후 중단 워크플로가 이미 실행 중입니다."
  exit 1
fi

trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; exit "$rc"' ERR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT

exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================="
echo "[$(date)] Post-demo cost suspend started."
echo "[$(date)] 시연 후 비용 중단 작업 시작."
echo "=================================================="
dr_state_write FAILBACK_EXECUTING
dr_state_flag_clear

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "[AWS AUTH ERROR] AWS credentials are missing, expired, or invalid."
  echo "[AWS 인증 오류] AWS 자격 증명이 없거나 만료되었거나 유효하지 않습니다."
  exit 1
fi

if [ "$SKIP_DNS" = "true" ]; then
  echo "[SUSPEND] Cloudflare DNS transition skipped because SKIP_DNS=true."
  echo "[중단] SKIP_DNS=true이므로 Cloudflare DNS 전환을 건너뜁니다."
else
  echo "[SUSPEND] Returning Cloudflare traffic to the on-premises endpoint."
  echo "[중단] Cloudflare 트래픽을 온프레미스 엔드포인트로 원복합니다."
  export DR_FAILBACK_CONTROLLER=1
  if ! "$FAILBACK_SCRIPT"; then
    echo "[SUSPEND ERROR] DNS failback failed; the final result is PARTIAL_FAILURE."
    echo "[중단 오류] DNS 페일백에 실패했으며 최종 결과는 PARTIAL_FAILURE입니다."
    partial_failure=1
  fi
fi

echo "[SUSPEND] FinOps does not change NAT. Run operations/nat/nat_disable.sh separately after checking the DR state."
echo "[중단] FinOps는 NAT를 변경하지 않습니다. DR 상태 확인 후 operations/nat/nat_disable.sh를 별도로 실행하십시오."

echo "[SUSPEND] Current DR resource status."
echo "[중단] 현재 DR 리소스 상태."
if ! "$STATUS_SCRIPT" status; then
  echo "[SUSPEND ERROR] DR resource status check failed; the final result is PARTIAL_FAILURE."
  echo "[중단 오류] DR 리소스 상태 확인에 실패했으며 최종 결과는 PARTIAL_FAILURE입니다."
  partial_failure=1
fi

if [ "$partial_failure" -ne 0 ]; then
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  dr_state_write PARTIAL_FAILURE
  echo "=================================================="
  echo "[SUSPEND PARTIAL_FAILURE] One or more failback or cleanup steps failed; retry is required."
  echo "[중단 부분 실패] 페일백 또는 정리 단계 일부가 실패했으며 재시도가 필요합니다."
  echo "=================================================="
  exit 1
fi

dr_state_write IDLE
dr_state_flag_clear
echo "=================================================="
echo "[SUSPEND COMPLETE] NAT resources are cleaned up. Stop DR EC2 instances manually in the AWS console if the demo is finished."
echo "[중단 완료] NAT 리소스를 정리했습니다. 시연이 끝났다면 AWS 콘솔에서 DR EC2 인스턴스를 수동 중지하십시오."
echo "=================================================="
