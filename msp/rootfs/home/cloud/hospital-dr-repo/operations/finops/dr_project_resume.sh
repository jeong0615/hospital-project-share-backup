#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/dr_project_resume.log}"
LOCK_FILE="${DR_PROJECT_RESUME_LOCK_FILE:-${DR_STATE_DIR}/project-resume.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
NAT_SCRIPT="${NAT_SCRIPT:-$TF_DIR/nat_gateway_control.sh}"
ENV_SCRIPT="${ENV_SCRIPT:-$TF_DIR/dr_environment_control.sh}"
ENABLE_NAT_ON_RESUME="${ENABLE_NAT_ON_RESUME:-false}"
SKIP_DNS="${SKIP_DNS:-false}"
DR_STATE_FAILURE_STATUS=FAILED

mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
    echo "[RESUME ERROR] Another DR workflow is already running."
    echo "[재개 오류] 다른 DR 워크플로가 이미 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[RESUME ERROR] Another DR resume workflow is already running."
  echo "[재개 오류] 다른 DR 재개 워크플로가 이미 실행 중입니다."
  exit 1
fi

trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; exit "$rc"' ERR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT

exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================="
echo "[$(date)] DR project resume started."
echo "[$(date)] DR 프로젝트 재개 작업 시작."
echo "=================================================="
dr_state_write FAILOVER_EXECUTING
dr_state_flag_clear

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "[AWS AUTH ERROR] AWS credentials are missing, expired, or invalid."
  echo "[AWS 인증 오류] AWS 자격 증명이 없거나 만료되었거나 유효하지 않습니다."
  exit 1
fi

if [ "$ENABLE_NAT_ON_RESUME" = "true" ]; then
  echo "[RESUME] Creating NAT Gateway resources for private subnet outbound access."
  echo "[재개] 프라이빗 서브넷 외부 통신을 위해 NAT Gateway 리소스를 생성합니다."
  if ! "$NAT_SCRIPT" enable; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE
    echo "[RESUME PARTIAL_FAILURE] NAT enable failed; DR environment start was not attempted."
    echo "[재개 부분 실패] NAT 활성화에 실패하여 DR 환경 시작을 진행하지 않았습니다."
    exit 1
  fi
else
  echo "[RESUME] NAT creation skipped. Set ENABLE_NAT_ON_RESUME=true only when Doc/DB private outbound access is required."
  echo "[재개] NAT 생성을 생략합니다. Doc/DB 프라이빗 외부 통신이 필요할 때만 ENABLE_NAT_ON_RESUME=true를 사용하십시오."
fi

if [ "$SKIP_DNS" = "true" ]; then
  echo "[RESUME] Starting existing DR EC2 instances without changing Cloudflare DNS (SKIP_DNS=true)."
  echo "[재개] SKIP_DNS=true이므로 Cloudflare DNS를 변경하지 않고 기존 DR EC2를 시작합니다."
else
  echo "[RESUME] Starting existing DR EC2 instances and switching Cloudflare to DR."
  echo "[재개] 기존 DR EC2 인스턴스를 시작하고 Cloudflare를 DR로 전환합니다."
fi
"$ENV_SCRIPT" start

echo "[RESUME] Current DR resource status."
echo "[재개] 현재 DR 리소스 상태."
if ! "$ENV_SCRIPT" status; then
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  dr_state_write PARTIAL_FAILURE
  echo "[RESUME PARTIAL_FAILURE] DR resource status check failed after start."
  echo "[재개 부분 실패] 시작 후 DR 리소스 상태 확인에 실패했습니다."
  exit 1
fi

if [ "$SKIP_DNS" = "true" ]; then
  # Without a DNS transition this is an infrastructure warm-up, not an active DR cutover.
  dr_state_write IDLE
else
  dr_state_write DR_ACTIVE
fi
dr_state_flag_clear
echo "=================================================="
if [ "$SKIP_DNS" = "true" ]; then
  echo "[RESUME COMPLETE] Existing DR resources are active; Cloudflare DNS was unchanged and runtime state remains IDLE."
  echo "[재개 완료] 기존 DR 리소스가 활성화되었으며 Cloudflare DNS는 유지했고 runtime state는 IDLE입니다."
else
  echo "[RESUME COMPLETE] Existing DR resources are active again."
  echo "[재개 완료] 기존 DR 리소스가 다시 활성화되었습니다."
fi
echo "=================================================="
