#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
LOCK_FILE="${DR_TERRAFORM_LOCK_FILE:-${DR_STATE_DIR}/terraform.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/nat_gateway.log}"
ACTION="${1:-status}"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi
CF_ZONE_ID="${CF_ZONE_ID:-}"
DR_SSH_PRIVATE_KEY="${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}"
if [ -n "$DR_SSH_PRIVATE_KEY" ] && [ -z "${TF_VAR_ssh_public_key_path:-}" ]; then
  export TF_VAR_ssh_public_key_path="${DR_SSH_PRIVATE_KEY}.pub"
fi
mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 7>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 7; then
    echo "[NAT ERROR] Another DR workflow is already in progress."
    echo "[NAT 오류] 다른 DR 워크플로가 이미 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1

if [ "${DR_TERRAFORM_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$LOCK_FILE"
  if ! flock -n 8; then
    echo "[NAT ERROR] Another Terraform operation is already in progress."
    echo "[NAT 오류] 다른 Terraform 작업이 이미 실행 중입니다."
    exit 1
  fi
fi

DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-PARTIAL_FAILURE}" 2>/dev/null || true; fi; exit "$rc"' ERR

exec > >(tee -a "$LOG_FILE") 2>&1
cd "$TF_DIR"

nat_in_state() {
  local state_output
  if ! state_output="$(terraform state list 2>/dev/null)"; then
    return 2
  fi
  printf '%s\n' "$state_output" | grep -Eq '^aws_nat_gateway\.nat_gw(\[0\])?$'
}

release_detached_nat_eips() {
  local allocation_ids allocation_id
  allocation_ids=$(aws ec2 describe-addresses \
    --region "${AWS_REGION:-ap-northeast-2}" \
    --filters "Name=tag:Name,Values=Hospital-DR-NAT-EIP" \
    --query "Addresses[?AssociationId==null && NetworkInterfaceId==null && !contains(Tags[?Key=='Preserve'].Value, 'true')].AllocationId" \
    --output text)

  for allocation_id in $allocation_ids; do
    echo "[NAT CLEANUP] Releasing detached NAT Elastic IP: ${allocation_id}"
    echo "[NAT 정리] 미연결 NAT Elastic IP 해제: ${allocation_id}"
    aws ec2 release-address --region "${AWS_REGION:-ap-northeast-2}" --allocation-id "$allocation_id"
  done
}

require_nat_ssh_key() {
  if [ -z "$DR_SSH_PRIVATE_KEY" ] || [ ! -r "$DR_SSH_PRIVATE_KEY" ]; then
    echo "[NAT CONFIG ERROR] DR_SSH_PRIVATE_KEY must point to a readable private key before Terraform is invoked."
    return 1
  fi
  if [ ! -r "${TF_VAR_ssh_public_key_path:-${DR_SSH_PRIVATE_KEY}.pub}" ]; then
    echo "[NAT CONFIG ERROR] The SSH public key paired with DR_SSH_PRIVATE_KEY is not readable."
    return 1
  fi
}

case "$ACTION" in
  enable)
    if ! require_nat_ssh_key; then
      dr_state_mark_failure PARTIAL_FAILURE 2>/dev/null || true
      exit 1
    fi
    echo "[NAT ENABLE] Creating the NAT gateway with the preserved Elastic IP and private default route."
    echo "[NAT 활성화] 보존형 Elastic IP로 NAT Gateway와 프라이빗 기본 경로를 생성합니다."
    terraform apply -input=false -auto-approve \
      -var="is_dr_mode=false" \
      -var="enable_nat_gateway=true" \
      -var="cloudflare_zone_id=$CF_ZONE_ID" \
      -target='aws_eip.nat_eip' \
      -target='aws_nat_gateway.nat_gw' \
      -target='aws_route.private_internet'
    echo "[NAT ENABLED] Private Doc/DB subnets can access external networks."
    echo "[NAT 활성화 완료] 프라이빗 Doc/DB 서브넷의 외부 통신이 가능합니다."
    ;;
  disable)
    if ! require_nat_ssh_key; then
      dr_state_mark_failure PARTIAL_FAILURE 2>/dev/null || true
      exit 1
    fi
    echo "[NAT DISABLE] Removing the private default route and NAT gateway. The NAT Elastic IP is preserved."
    echo "[NAT 비활성화] 프라이빗 기본 경로와 NAT Gateway만 제거합니다. NAT Elastic IP는 보존합니다."
    terraform apply -input=false -auto-approve \
      -var="is_dr_mode=false" \
      -var="enable_nat_gateway=false" \
      -var="cloudflare_zone_id=$CF_ZONE_ID" \
      -target='aws_route.private_internet' \
      -target='aws_nat_gateway.nat_gw'
    release_detached_nat_eips
    echo "[NAT DISABLED] Hourly NAT gateway billing has stopped."
    echo "[NAT 비활성화 완료] NAT Gateway 시간당 과금이 중지되었습니다."
    ;;
  cleanup)
    echo "[NAT CLEANUP] Removing NAT gateway resources without touching DR EC2 instances."
    echo "[NAT 정리] DR EC2 인스턴스는 유지하고 NAT Gateway 리소스만 제거합니다."
    DR_WORKFLOW_LOCK_HELD=1 DR_TERRAFORM_LOCK_HELD=1 "$0" disable
    ;;
  status)
    if nat_in_state; then
      echo "[NAT STATUS] ENABLED"
      echo "[NAT 상태] 활성화됨"
    else
      nat_status_rc=$?
      if [ "$nat_status_rc" -eq 2 ]; then
        echo "[NAT STATUS ERROR] Terraform state could not be read." >&2
        echo "[NAT 상태 오류] Terraform state를 읽지 못했습니다." >&2
        dr_state_mark_failure PARTIAL_FAILURE 2>/dev/null || true
        exit 1
      fi
      echo "[NAT STATUS] DISABLED"
      echo "[NAT 상태] 비활성화됨"
    fi
    ;;
  *)
    echo "Usage: $0 {enable|disable|cleanup|status}" >&2
    exit 2
    ;;
esac
