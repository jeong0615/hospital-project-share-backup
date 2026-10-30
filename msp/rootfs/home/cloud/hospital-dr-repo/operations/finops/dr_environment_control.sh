#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
FINOPS_DIR="${FINOPS_DIR:-$DR_FINOPS_DIR}"
INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
SSH_KEY="${SSH_KEY:-${DR_SSH_PRIVATE_KEY:-${DR_SSH_KEY:-}}}"
REGION="${AWS_REGION:-ap-northeast-2}"
ENV_LOCK="${DR_ENVIRONMENT_LOCK_FILE:-${DR_STATE_DIR}/environment.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
TF_LOCK="${DR_TERRAFORM_LOCK_FILE:-${DR_STATE_DIR}/terraform.lock}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/dr_environment.log}"
ACTION="${1:-status}"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
SKIP_DNS="${SKIP_DNS:-false}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi
SSH_KEY="${SSH_KEY:-${DR_SSH_PRIVATE_KEY:-${DR_SSH_KEY:-}}}"
if [ -n "$SSH_KEY" ] && [ -z "${TF_VAR_ssh_public_key_path:-}" ]; then
  export TF_VAR_ssh_public_key_path="${SSH_KEY}.pub"
fi

DR_STATE_FAILURE_STATUS=FAILED
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
ONPREM_WEB_HEALTH_URL="${ONPREM_WEB_HEALTH_URL:-http://IP_REDACTED/}"
ONPREM_EMR_HEALTH_URL="${ONPREM_EMR_HEALTH_URL:-http://IP_REDACTED/emr/}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
DNS_TX_DIR="${DR_DNS_TX_DIR:-${DR_STATE_DIR}/dns/environment-${ACTION}-${BASHPID}}"
mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 7>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 7; then
    echo "[DR ENVIRONMENT ERROR] Another DR workflow is already running."
    echo "[DR 환경 오류] 다른 DR 워크플로가 이미 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1

stateful_action() {
  case "$ACTION" in
    start|stop|provision) return 0 ;;
    *) return 1 ;;
  esac
}

if stateful_action; then
  trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; exit "$rc"' ERR
  trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT
fi

if [ "$ACTION" = "start" ] && [ -n "${INVOCATION_ID:-}" ] && [ "${DR_ENVIRONMENT_SYSTEMD_START_ALLOWED:-false}" != "true" ]; then
  echo "[DR ENVIRONMENT] systemd auto-start was ignored to prevent unintended failover."
  echo "[DR 환경] 의도하지 않은 페일오버 방지를 위해 systemd 자동 시작을 건너뜁니다."
  echo "[DR ENVIRONMENT] Use this script directly for manual DR start: $0 start"
  echo "[DR 환경] 수동 DR 시작은 스크립트를 직접 실행하십시오: $0 start"
  exit 0
fi

if [ "${DR_ENVIRONMENT_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$ENV_LOCK"
  if ! flock -n 8; then
    echo "[DR ENVIRONMENT ERROR] Another environment lifecycle operation is already running."
    echo "[DR 환경 오류] 다른 환경 수명주기 작업이 이미 실행 중입니다."
    exit 1
  fi
fi

exec > >(tee -a "$LOG_FILE") 2>&1

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: $name."
    return 1
  fi
}

aws_check() {
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[AWS AUTH ERROR] AWS credentials are missing, expired, or invalid."
    echo "[AWS 인증 오류] AWS 자격 증명이 없거나 만료되었거나 유효하지 않습니다."
    return 1
  fi
}

instance_ids() {
  aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text | tr '\t' '\n' | sed '/^$/d'
}

web_public_ip() {
  local tf_ip aws_ip
  tf_ip=$(terraform -chdir="$TF_DIR" output -raw web_server_public_ip 2>/dev/null || true)
  if [ -n "${tf_ip:-}" ] && [ "$tf_ip" != "None" ]; then
    printf '%s\n' "$tf_ip"
    return 0
  fi

  aws_ip=$(aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=tag:Name,Values=Hospital-Real-Web-Server" \
      "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)
  printf '%s\n' "$aws_ip"
}

wait_for_ssh_target() {
  local label="$1"
  local host="$2"
  shift 2
  local attempt

  echo "[CONNECTIVITY] Waiting for SSH readiness: ${label}"
  echo "[접속 확인] SSH 접속 가능 상태 대기: ${label}"
  for attempt in $(seq 1 18); do
    if ssh -i "$SSH_KEY" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o GlobalKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o ConnectTimeout=8 \
      "$@" "$host" "true" >/dev/null 2>&1; then
      echo "[CONNECTIVITY] SSH readiness confirmed: ${label}"
      echo "[접속 확인] SSH 접속 가능 확인: ${label}"
      return 0
    fi
    echo "[CONNECTIVITY] SSH not ready yet (${attempt}/18): ${label}"
    echo "[접속 대기] SSH 아직 준비되지 않음 (${attempt}/18): ${label}"
    sleep 5
  done

  echo "[CONNECTIVITY ERROR] SSH readiness check failed: ${label}"
  echo "[접속 오류] SSH 준비 상태 확인 실패: ${label}"
  return 1
}

update_inventory() {
  local web_ip="$1"
  local temporary ssh_common ssh_jump_common proxy_command
  temporary=$(mktemp)
  ssh_common="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR"
  proxy_command="ssh -i ${SSH_KEY} ${ssh_common} -W %h:%p ubuntu@${web_ip}"
  ssh_jump_common="${ssh_common} -o ProxyCommand=\"${proxy_command}\""
  {
    echo "[web_servers]"
    echo "${web_ip} ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_common}'"
    echo
    echo "[doc_servers]"
    echo "IP_REDACTED ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_jump_common}'"
    echo
    echo "[db_servers]"
    echo "IP_REDACTED ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_jump_common}'"
  } > "$temporary"
  install -m 0644 "$temporary" "$INVENTORY"
  rm -f "$temporary"
}

terraform_dns_mode() {
  local dr_mode="$1"
  if ! flock -n "$TF_LOCK" terraform -chdir="$TF_DIR" apply \
    -input=false \
    -auto-approve \
    -var="is_dr_mode=${dr_mode}" \
    -var="enable_nat_gateway=false" \
    -var="cloudflare_zone_id=${CF_ZONE_ID}" \
    -target=cloudflare_record.hospital_web \
    -target=cloudflare_record.hospital_emr; then
    echo "[DNS ERROR] Terraform could not update the Cloudflare traffic target."
    echo "[DNS 오류] Terraform이 Cloudflare 트래픽 대상을 갱신하지 못했습니다."
    return 1
  fi
}

release_detached_nat_eips() {
  local allocation_ids allocation_id
  if ! allocation_ids=$(aws ec2 describe-addresses \
    --region "$REGION" \
    --filters "Name=tag:Name,Values=Hospital-DR-NAT-EIP" \
    --query "Addresses[?AssociationId==null && NetworkInterfaceId==null && !contains(Tags[?Key=='Preserve'].Value, 'true')].AllocationId" \
    --output text); then
    echo "[COST CONTROL ERROR] Could not list detached NAT Elastic IPs."
    return 1
  fi

  for allocation_id in $allocation_ids; do
    echo "[COST CONTROL] Releasing detached NAT Elastic IP: ${allocation_id}."
    echo "[비용 제어] 미연결 NAT Elastic IP 해제: ${allocation_id}."
    if ! aws ec2 release-address --region "$REGION" --allocation-id "$allocation_id"; then
      echo "[COST CONTROL ERROR] Failed to release detached NAT Elastic IP: ${allocation_id}."
      return 1
    fi
  done
}

prepare_dns_snapshot() {
  require_config "CF_ZONE_ID"
  mkdir -p "$DNS_TX_DIR"
  chmod 0750 "$DNS_TX_DIR"
  load_cloudflare_ssm_token
  CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-}")"
  CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-}")"
}

rollback_dns() {
  if dr_dns_rollback_snapshots "$DNS_TX_DIR"; then
    DR_STATE_FAILURE_STATUS=FAILED
    dr_state_write FAILED 2>/dev/null || true
  else
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
}

apply_dns_mode() {
  local mode="$1"
  if terraform_dns_mode "$mode"; then
    return 0
  fi
  echo "[DNS] Terraform DNS update failed; restoring the pre-change records."
  rollback_dns
  return 1
}

check_public_health() {
  local web_url="$1"
  local emr_url="$2"
  local attempts="$3"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if curl -fsS --connect-timeout 5 --max-time 15 "$web_url" >/dev/null \
       && curl -fsS --connect-timeout 5 --max-time 15 \
         -H "X-Hospital-DR-Check: $EMR_HEALTH_CHECK_HEADER" "$emr_url" >/dev/null; then
      return 0
    fi
    echo "[VALIDATION] Waiting for public service health ($attempt/$attempts)."
    sleep "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}"
  done
  return 1
}

start_environment() {
  local ids web_ip proxy_command ids_count instance_list
  dr_state_write FAILOVER_EXECUTING
  if ! instance_list="$(instance_ids)"; then
    echo "[START ERROR] Failed to list DR EC2 instances."
    echo "[시작 오류] DR EC2 인스턴스 목록을 조회하지 못했습니다."
    return 1
  fi
  mapfile -t ids <<< "$instance_list"
  ids_count=$(printf '%s\n' "${ids[@]}" | sed '/^$/d' | wc -l)
  if [ "$ids_count" -ne 3 ]; then
    echo "[START ERROR] Expected three DR instances but found $ids_count. Run '$0 provision' first."
    echo "[시작 오류] DR 인스턴스 3대가 필요하지만 $ids_count대만 확인됐습니다. 먼저 '$0 provision'을 실행하십시오."
    return 1
  fi

  echo "[DR START] Starting Web, Doc, and DB instances."
  echo "[DR 시작] Web, Doc, DB 인스턴스를 시작합니다."
  aws ec2 start-instances --region "$REGION" --instance-ids "${ids[@]}" >/dev/null
  aws ec2 wait instance-running --region "$REGION" --instance-ids "${ids[@]}"
  aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "${ids[@]}"

  web_ip=$(web_public_ip)
  if [ -z "$web_ip" ] || [ "$web_ip" = "None" ]; then
    echo "[START ERROR] The DR Web instance has no public IPv4 address."
    echo "[시작 오류] DR Web 인스턴스에 공인 IPv4 주소가 없습니다."
    return 1
  fi

  require_config "SSH_KEY"
  if [ ! -r "$SSH_KEY" ]; then
    echo "[CONFIG ERROR] SSH private key is not readable: $SSH_KEY."
    echo "[설정 오류] SSH 개인 키를 읽을 수 없습니다: $SSH_KEY."
    return 1
  fi
  if [ ! -r "${TF_VAR_ssh_public_key_path:-${SSH_KEY}.pub}" ]; then
    echo "[CONFIG ERROR] SSH public key is not readable: ${TF_VAR_ssh_public_key_path:-${SSH_KEY}.pub}."
    echo "[설정 오류] SSH 공개 키를 읽을 수 없습니다: ${TF_VAR_ssh_public_key_path:-${SSH_KEY}.pub}."
    return 1
  fi

  update_inventory "$web_ip"
  proxy_command="ssh -i $SSH_KEY -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -W %h:%p ubuntu@$web_ip"
  wait_for_ssh_target "DR Web $web_ip" "ubuntu@$web_ip"
  wait_for_ssh_target "DR Doc IP_REDACTED via DR Web $web_ip" "ubuntu@IP_REDACTED" -o "ProxyCommand=$proxy_command"

  ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "ubuntu@$web_ip" 'set -eu
sudo systemctl start docker nginx
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-web 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-web >/dev/null; fi
health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-web 2>/dev/null || true)"
[ "$health" = "healthy" ]' >/dev/null
  ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o "ProxyCommand=$proxy_command" \
    ubuntu@IP_REDACTED 'set -eu
sudo systemctl start docker apache2
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-emr 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-emr >/dev/null; fi
health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-emr 2>/dev/null || true)"
[ "$health" = "healthy" ]' >/dev/null

  echo "[VALIDATION] Checking DR origin Web and EMR health before DNS cutover."
  if ! curl -kfsS --connect-timeout 5 --max-time 15 "https://$web_ip/" >/dev/null \
     || ! curl -kfsS --connect-timeout 5 --max-time 15 \
       -H "X-Hospital-DR-Check: $EMR_HEALTH_CHECK_HEADER" "https://$web_ip/emr/" >/dev/null; then
    echo "[VALIDATION ERROR] DR origin health failed; DNS was not changed."
    return 1
  fi

  if [ "$SKIP_DNS" = "true" ]; then
    echo "[DNS] Cloudflare transition skipped because SKIP_DNS=true; origin health passed."
    echo "[DNS] SKIP_DNS=true이므로 Cloudflare 전환을 건너뛰었습니다. Origin health는 통과했습니다."
    dr_state_write IDLE
    return 0
  fi

  prepare_dns_snapshot
  echo "[DNS] Switching Cloudflare to DR Web only after origin health passed: $web_ip"
  if ! apply_dns_mode true; then
    return 1
  fi
  if ! check_public_health "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/emr/" "${PUBLIC_HEALTH_ATTEMPTS:-30}"; then
    echo "[VALIDATION ERROR] Public DR health failed; attempting DNS rollback."
    rollback_dns
    return 1
  fi

  dr_state_write DR_ACTIVE
  echo "[DR STARTED] Web and EMR HTTPS health checks passed. NAT remains disabled."
  echo "[DR 시작 완료] Web 및 EMR HTTPS 상태 점검을 통과했습니다. NAT는 비활성 상태를 유지합니다."
}
stop_environment() {
  local ids stop_failed cleanup_failed ids_count instance_list
  dr_state_write FAILBACK_EXECUTING
  stop_failed=0
  cleanup_failed=0
  if ! instance_list="$(instance_ids)"; then
    echo "[DR STOP ERROR] Failed to list DR EC2 instances."
    echo "[DR 중지 오류] DR EC2 인스턴스 목록을 조회하지 못했습니다."
    return 1
  fi
  mapfile -t ids <<< "$instance_list"
  ids_count=$(printf '%s\n' "${ids[@]}" | sed '/^$/d' | wc -l)

  if [ "$SKIP_DNS" = "true" ]; then
    echo "[DNS] Cloudflare transition skipped because SKIP_DNS=true; keeping current DNS records."
    echo "[DNS] SKIP_DNS=true이므로 현재 Cloudflare DNS record를 유지합니다."
  else
    echo "[VALIDATION] Checking on-premise Web and EMR health before DNS failback."
    if ! check_public_health "$ONPREM_WEB_HEALTH_URL" "$ONPREM_EMR_HEALTH_URL" "${ONPREM_HEALTH_ATTEMPTS:-12}"; then
      echo "[VALIDATION ERROR] On-premise health failed; DNS remains on the DR endpoint."
      return 1
    fi

    prepare_dns_snapshot
    echo "[DNS] Switching Cloudflare back to the on-premises tunnel."
    if ! apply_dns_mode false; then
      return 1
    fi
    if ! check_public_health "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/emr/" "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
      echo "[VALIDATION ERROR] Public on-premise health failed after DNS failback; attempting rollback."
      rollback_dns
      return 1
    fi
  fi

  if [ "$ids_count" -gt 0 ]; then
    echo "[DR STOP] Stopping $ids_count DR EC2 instances."
    echo "[DR 중지] EC2 인스턴스 $ids_count대를 중지합니다."
    if ! aws ec2 stop-instances --region "$REGION" --instance-ids "${ids[@]}" >/dev/null; then
      echo "[DR STOP ERROR] Failed to request EC2 stop."
      stop_failed=1
    fi
  fi

  if ! "$FINOPS_DIR/nat_gateway_control.sh" disable; then
    echo "[COST CONTROL ERROR] NAT cleanup failed."
    cleanup_failed=1
  fi
  if ! release_detached_nat_eips; then
    echo "[COST CONTROL ERROR] Detached NAT EIP cleanup failed."
    cleanup_failed=1
  fi

  if [ "$ids_count" -gt 0 ]; then
    if ! aws ec2 wait instance-stopped --region "$REGION" --instance-ids "${ids[@]}"; then
      echo "[DR STOP ERROR] EC2 stop wait failed."
      stop_failed=1
    fi
  fi

  if [ "$stop_failed" -ne 0 ] || [ "$cleanup_failed" -ne 0 ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    echo "[DR STOP PARTIAL_FAILURE] One or more DR stop or cleanup steps failed."
    return 1
  fi

  dr_state_write IDLE
  echo "[DR STOPPED] EC2 compute is stopped and the temporary NAT gateway is removed. The NAT EIP is preserved."
  echo "[DR 중지 완료] EC2 컴퓨팅과 임시 NAT Gateway가 정리되었습니다. NAT EIP는 보존합니다."
}
show_status() {
  echo "[DR STATE] $(dr_state_read)"
  echo "[EC2 STATUS]"
  aws ec2 describe-instances \
    --region "$REGION" \
    --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
    --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,ID:InstanceId,State:State.Name,PublicIP:PublicIpAddress}' \
    --output table

  echo "[NAT STATUS]"
  aws ec2 describe-nat-gateways \
    --region "$REGION" \
    --filter "Name=tag:Name,Values=Hospital-DR-NAT-GW" "Name=state,Values=pending,available,deleting" \
    --query 'NatGateways[].{ID:NatGatewayId,State:State,PublicIP:NatGatewayAddresses[0].PublicIp}' \
    --output table

  echo "[DETACHED NAT EIP STATUS]"
  aws ec2 describe-addresses \
    --region "$REGION" \
    --filters "Name=tag:Name,Values=Hospital-DR-NAT-EIP" \
    --query 'Addresses[].{AllocationID:AllocationId,PublicIP:PublicIp,AssociationID:AssociationId}' \
    --output table
}

aws_check
case "$ACTION" in
  start)
    start_environment
    ;;
  stop)
    stop_environment
    ;;
  status)
    show_status
    ;;
  provision)
    dr_state_write FAILOVER_EXECUTING
    DR_PROVISION_ONLY=true "$TF_DIR/run_demo.sh"
    cleanup_failed=0
    if [ "${KEEP_NAT_AFTER_PROVISION:-false}" != "true" ]; then
      if ! "$FINOPS_DIR/nat_gateway_control.sh" disable; then
        echo "[COST CONTROL ERROR] NAT cleanup after provision failed."
        cleanup_failed=1
      fi
      if ! release_detached_nat_eips; then
        echo "[COST CONTROL ERROR] Detached NAT EIP cleanup after provision failed."
        cleanup_failed=1
      fi
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
      DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
      dr_state_write PARTIAL_FAILURE 2>/dev/null || true
      exit 1
    fi
    dr_state_write DR_ACTIVE
    ;;
  *)
    echo "Usage: $0 {start|stop|status|provision}" >&2
    exit 2
    ;;
esac
