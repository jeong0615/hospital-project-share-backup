#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../operations/runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

LOCK_FILE="${DR_FAILOVER_LOCK_FILE:-${DR_STATE_DIR}/failover.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
TF_LOCK_FILE="${DR_TERRAFORM_LOCK_FILE:-${DR_STATE_DIR}/terraform.lock}"
TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
ANSIBLE_DIR="${ANSIBLE_DIR:-$DR_ANSIBLE_DIR}"
INVENTORY="${INVENTORY:-$ANSIBLE_DIR/inventory.ini}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/failover.log}"
mkdir -p "$(dirname -- "$LOG_FILE")"

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

FAILOVER_START_TS="${DR_FAILOVER_START_TS:-$(date +%s)}"
if [ "${DR_FAILOVER_METRICS_STARTED:-0}" != "1" ]; then
  export DR_FAILOVER_METRICS_STARTED=1
  export DR_FAILOVER_START_TS="$FAILOVER_START_TS"
  zbx_send dr.failover.status 1 2>/dev/null || true
fi

failover_metric_failed() {
  zbx_send dr.failover.status 3 2>/dev/null || true
}

dr_state_prepare
dr_workflow_lock_prepare
DR_STATE_FAILURE_STATUS=FAILED
trap 'rc=$?; dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; failover_metric_failed; exit "$rc"' ERR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT

# Hold the shared workflow and Terraform locks in this process so failures
# from the workflow do not pass through a parent wrapper that could overwrite
# the persistent result state.
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 8; then
    echo "[DR FAILOVER] Another DR workflow is already in progress."
    echo "[DR 페일오버] 이미 다른 DR 워크플로가 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1

if [ "${DR_FAILOVER_LOCK_HELD:-0}" != "1" ]; then
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "[DR FAILOVER] Another failover workflow is already in progress."
    echo "[DR 페일오버] 이미 다른 페일오버 워크플로가 실행 중입니다."
    exit 1
  fi
fi

if [ "${DR_TERRAFORM_LOCK_HELD:-0}" != "1" ]; then
  exec 7>"$TF_LOCK_FILE"
  if ! flock -n 7; then
    echo "[PROVISIONING ERROR] Another Terraform operation is already in progress."
    echo "[프로비저닝 오류] 다른 Terraform 작업이 이미 실행 중입니다."
    exit 1
  fi
fi

exec > >(tee -a "$LOG_FILE") 2>&1
workflow_timing_start="$(dr_timing_start failover)"
echo "=================================================="
echo "[$(date)] DR failover workflow started."
echo "[$(date)] DR 페일오버 워크플로 시작."
echo "=================================================="
dr_state_write FAILOVER_EXECUTING
dr_state_flag_clear

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Required environment variable is missing: $name"
    echo "[설정 오류] 필수 환경변수가 없습니다: $name"
    exit 1
  fi
}

load_secret_env() {
  local secret_file="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
  if [ -f "$secret_file" ]; then
    # shellcheck disable=SC1090
    source "$secret_file"
  fi
}

wait_for_ssh() {
  local host="$1"
  local user="$2"
  local key="$3"
  local args="${4:-}"
  local max_attempts="${5:-30}"

  echo "[CONNECTIVITY] Waiting for SSH readiness: ${user}@${host}"
  echo "[접속 확인] SSH 접속 가능 상태 대기: ${user}@${host}"
  for attempt in $(seq 1 "$max_attempts"); do
    if ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR $args "${user}@${host}" "true" >/dev/null 2>&1; then
      echo "[CONNECTIVITY] SSH readiness confirmed: ${host}"
      echo "[접속 확인] SSH 접속 가능 확인: ${host}"
      return 0
    fi
    echo "[CONNECTIVITY] SSH not ready yet (${attempt}/${max_attempts}): ${host}"
    echo "[접속 대기] SSH 아직 준비되지 않음 (${attempt}/${max_attempts}): ${host}"
    sleep 10
  done

  echo "[CONNECTIVITY ERROR] SSH readiness check failed: ${host}"
  echo "[접속 오류] SSH 준비 상태 확인 실패: ${host}"
  return 1
}

wait_for_ssh_via_web() {
  local host="$1"
  local user="$2"
  local key="$3"
  local web_ip="$4"
  local max_attempts="${5:-30}"
  local attempt proxy_command

  proxy_command="ssh -i ${key} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -W %h:%p ubuntu@${web_ip}"

  echo "[CONNECTIVITY] Waiting for SSH readiness through DR Web bastion: ${user}@${host}"
  echo "[접속 확인] DR Web bastion 경유 SSH 접속 가능 상태 대기: ${user}@${host}"
  for attempt in $(seq 1 "$max_attempts"); do
    if ssh -i "$key" \
      -o BatchMode=yes \
      -o ConnectTimeout=5 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o GlobalKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o "ProxyCommand=${proxy_command}" \
      "${user}@${host}" "true" >/dev/null 2>&1; then
      echo "[CONNECTIVITY] SSH readiness confirmed: ${host}"
      echo "[접속 확인] SSH 접속 가능 확인: ${host}"
      return 0
    fi
    echo "[CONNECTIVITY] SSH not ready yet (${attempt}/${max_attempts}): ${host}"
    echo "[접속 대기] SSH 아직 준비되지 않음 (${attempt}/${max_attempts}): ${host}"
    sleep 10
  done

  echo "[CONNECTIVITY ERROR] SSH readiness check failed: ${host}"
  echo "[접속 오류] SSH 준비 상태 확인 실패: ${host}"
  return 1
}

patch_cloudflare_zone_setting() {
  local setting_name="$1"
  local setting_value="$2"
  local response_file
  response_file=$(mktemp)

  if ! curl -fsS -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/${setting_name}" \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"value\":\"${setting_value}\"}" > "$response_file"; then
    echo "[DNS ERROR] Cloudflare setting update failed for ${setting_name}."
    echo "[DNS 오류] Cloudflare 설정 ${setting_name} 업데이트에 실패했습니다."
    rm -f "$response_file"
    return 1
  fi

  if ! dr_dns_response_success "$response_file"; then
    echo "[DNS ERROR] Cloudflare setting update returned a non-success response for ${setting_name}."
    echo "[DNS 오류] Cloudflare 설정 ${setting_name}이 성공 응답을 반환하지 않았습니다."
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"
}

load_secret_env
load_cloudflare_ssm_token
export MYSQL_ROOT_PASS DB_REPL_PASSWORD DB_BACKUP_ENCRYPTION_KEY WEB_DB_PASSWORD DOC_DB_PASSWORD SESSION_SECRET
CF_ZONE_ID="${CF_ZONE_ID:-}"
DNS_TX_DIR="${DR_DNS_TX_DIR:-${DR_STATE_DIR}/dns/failover-${FAILOVER_START_TS}-${BASHPID}}"
mkdir -p "$DNS_TX_DIR"
chmod 0750 "$DNS_TX_DIR"
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
SSH_KEY="${SSH_KEY:-${DR_SSH_KEY:-}}"
DR_DOC_PRIVATE_IP="${DR_DOC_PRIVATE_IP:-IP_REDACTED}"
DR_DB_PRIVATE_IP="${DR_DB_PRIVATE_IP:-IP_REDACTED}"
ANSIBLE_LIMIT="${ANSIBLE_LIMIT:-all}"
DB_PROMOTE_ON_FAILOVER="${DB_PROMOTE_ON_FAILOVER:-true}"
require_env "CF_ZONE_ID"
require_env "SSH_KEY"
export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$ANSIBLE_DIR/ansible.cfg}"
export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"
export ANSIBLE_DEPRECATION_WARNINGS="${ANSIBLE_DEPRECATION_WARNINGS:-False}"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore}"
if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "db_servers" ]; then
  require_env "MYSQL_ROOT_PASS"
  require_env "WEB_DB_PASSWORD"
  require_env "DOC_DB_PASSWORD"
  if [ "${DB_NR_ENABLED:-false}" = "true" ]; then
    require_env "DB_SOURCE_HOST"
    require_env "DB_REPL_PASSWORD"
  fi
  if [ -z "${DB_BACKUP_ENCRYPTION_KEY:-}" ] && [ "${DB_NR_ENABLED:-false}" != "true" ] && [ "${DB_PROMOTE_ON_FAILOVER:-false}" != "true" ]; then
    echo "[CONFIG ERROR] DB recovery requires DB_BACKUP_ENCRYPTION_KEY, DB_NR_ENABLED=true, or DB_PROMOTE_ON_FAILOVER=true."
    echo "[설정 오류] DB 복구에는 DB_BACKUP_ENCRYPTION_KEY, DB_NR_ENABLED=true, 또는 DB_PROMOTE_ON_FAILOVER=true가 필요합니다."
    exit 1
  fi
fi

if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "web_servers" ]; then
  require_env "WEB_DB_PASSWORD"
  require_env "SESSION_SECRET"
fi

if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "doc_servers" ]; then
  require_env "DOC_DB_PASSWORD"
fi

cd "$TF_DIR"

echo "[PROVISIONING] Applying Terraform plan for DR infrastructure..."
echo "[프로비저닝] DR 인프라 Terraform 적용 시작..."
terraform_timing_start="$(dr_timing_start terraform)"
terraform apply -var="is_dr_mode=true" -var="enable_nat_gateway=true" -auto-approve
dr_timing_end terraform "$terraform_timing_start"
echo "[PROVISIONING] Terraform apply completed successfully."
echo "[프로비저닝] Terraform 적용 완료."

echo "[CONFIGURATION] Generating Ansible inventory for DR hosts..."
echo "[구성 관리] DR 대상 호스트 Ansible inventory 생성..."
WEB_PUB_IP=$(terraform output -raw web_server_public_ip)

SSH_COMMON="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR"
SSH_PROXY_COMMAND="ssh -i ${SSH_KEY} ${SSH_COMMON} -W %h:%p ubuntu@${WEB_PUB_IP}"
SSH_JUMP_COMMON="${SSH_COMMON} -o ProxyCommand=\"${SSH_PROXY_COMMAND}\""

cat <<EOF > "$INVENTORY"
[web_servers]
$WEB_PUB_IP ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='${SSH_COMMON}'

[doc_servers]
$DR_DOC_PRIVATE_IP ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='${SSH_JUMP_COMMON}'

[db_servers]
$DR_DB_PRIVATE_IP ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='${SSH_JUMP_COMMON}'
EOF
echo "[CONFIGURATION] Ansible inventory generation completed."
echo "[구성 관리] Ansible inventory 생성 완료."

wait_for_ssh "$WEB_PUB_IP" "ubuntu" "$SSH_KEY"
if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "doc_servers" ]; then
  wait_for_ssh_via_web "$DR_DOC_PRIVATE_IP" "ubuntu" "$SSH_KEY" "$WEB_PUB_IP"
fi
if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "db_servers" ]; then
  wait_for_ssh_via_web "$DR_DB_PRIVATE_IP" "ubuntu" "$SSH_KEY" "$WEB_PUB_IP"
fi

echo "[CONFIGURATION] Running Ansible recovery playbook with limit: ${ANSIBLE_LIMIT}"
echo "[구성 관리] Ansible 복구 playbook 실행 범위: ${ANSIBLE_LIMIT}"
ansible_timing_start="$(dr_timing_start ansible)"
cd "$ANSIBLE_DIR"
ansible-playbook -i "$INVENTORY" site.yml --limit "$ANSIBLE_LIMIT"
dr_timing_end ansible "$ansible_timing_start"
echo "[CONFIGURATION] Ansible recovery playbook completed successfully."
echo "[구성 관리] Ansible 복구 playbook 완료."

echo "[VALIDATION] Starting DR web service health check..."
echo "[검증] DR Web 서비스 health check 시작..."
health_timing_start="$(dr_timing_start health)"
for attempt in $(seq 1 30); do
  if curl -kfsS "https://${WEB_PUB_IP}/" >/dev/null; then
    echo "[VALIDATION] DR web origin HTTPS health check passed: https://${WEB_PUB_IP}/"
    echo "[검증] DR Web 원본 HTTPS 정상 응답 확인: https://${WEB_PUB_IP}/"
    break
  fi

  if [ "$attempt" -eq 30 ]; then
    echo "[VALIDATION ERROR] DR web origin HTTPS health check failed: https://${WEB_PUB_IP}/"
    echo "[검증 오류] DR Web 원본 HTTPS health check 실패: https://${WEB_PUB_IP}/"
    exit 1
  fi

  echo "[VALIDATION] Waiting for DR web service response (${attempt}/30)."
  echo "[검증 대기] DR Web 서비스 응답 대기 (${attempt}/30)."
  sleep 5
done

if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "doc_servers" ]; then
  echo "[VALIDATION] Starting DR EMR service health check..."
  echo "[검증] DR EMR 서비스 health check 시작..."
  for attempt in $(seq 1 30); do
    if curl -kfsS -H "X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}" "https://${WEB_PUB_IP}/emr/" >/dev/null; then
      echo "[VALIDATION] DR EMR origin HTTPS health check passed: https://${WEB_PUB_IP}/emr/"
      echo "[검증] DR EMR 원본 HTTPS 정상 응답 확인: https://${WEB_PUB_IP}/emr/"
      break
    fi

    if [ "$attempt" -eq 30 ]; then
      echo "[VALIDATION ERROR] DR EMR origin HTTPS health check failed: https://${WEB_PUB_IP}/emr/"
      echo "[검증 오류] DR EMR 원본 HTTPS health check 실패: https://${WEB_PUB_IP}/emr/"
      exit 1
    fi

    echo "[VALIDATION] Waiting for DR EMR service response (${attempt}/30)."
    echo "[검증 대기] DR EMR 서비스 응답 대기 (${attempt}/30)."
    sleep 5
  done

  for attempt in $(seq 1 30); do
    if curl -kfsS -H "Host: ${EMR_DOMAIN}" -H "X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}" "https://${WEB_PUB_IP}/" >/dev/null; then
      echo "[VALIDATION] DR EMR subdomain HTTPS health check passed: https://${EMR_DOMAIN}/"
      echo "[검증] DR EMR 서브도메인 HTTPS 정상 응답 확인: https://${EMR_DOMAIN}/"
      break
    fi

    if [ "$attempt" -eq 30 ]; then
      echo "[VALIDATION ERROR] DR EMR subdomain HTTPS health check failed: https://${EMR_DOMAIN}/"
      echo "[검증 오류] DR EMR 서브도메인 HTTPS health check 실패: https://${EMR_DOMAIN}/"
      exit 1
    fi

    echo "[VALIDATION] Waiting for DR EMR subdomain response (${attempt}/30)."
    echo "[검증 대기] DR EMR 서브도메인 응답 대기 (${attempt}/30)."
    sleep 5
  done
fi

if [ "$ANSIBLE_LIMIT" = "all" ] || [ "$ANSIBLE_LIMIT" = "db_servers" ]; then
  echo "[VALIDATION] Checking DR DB service readiness through Ansible."
  echo "[검증] Ansible을 통해 DR DB 서비스 준비 상태 확인."
  ansible -i "$INVENTORY" db_servers \
    -m shell \
    -a "
mysql_defaults_file=\$(mktemp)
cleanup_mysql_defaults() { rm -f \"\$mysql_defaults_file\"; }
trap cleanup_mysql_defaults EXIT
chmod 600 \"\$mysql_defaults_file\"
{
  printf '[client]\\n'
  printf 'user=root\\n'
  printf 'password=%s\\n' '${MYSQL_ROOT_PASS}'
} > \"\$mysql_defaults_file\"
mysqladmin --defaults-extra-file=\"\$mysql_defaults_file\" ping --silent
mysql --defaults-extra-file=\"\$mysql_defaults_file\" -e \"SELECT @@read_only AS read_only, @@super_read_only AS super_read_only;\"
"
fi

echo "[DNS] Origin health checks passed; snapshotting current Cloudflare records before cutover."
echo "[DNS] 원본 health check 통과 후 DNS 전환 전 현재 Cloudflare record를 snapshot합니다."
dns_timing_start="$(dr_timing_start dns.cutover)"
CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-}")"
CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-}")"

patch_cloudflare_zone_setting "ssl" "full"
patch_cloudflare_zone_setting "always_use_https" "on"

CF_PAYLOAD="{\"type\":\"A\",\"name\":\"${DR_DOMAIN}\",\"content\":\"${WEB_PUB_IP}\",\"ttl\":1,\"proxied\":true}"
CF_EMR_PAYLOAD="{\"type\":\"A\",\"name\":\"${EMR_DOMAIN}\",\"content\":\"${WEB_PUB_IP}\",\"ttl\":1,\"proxied\":true}"
if dr_dns_apply_records "$DNS_TX_DIR" \
  "$CF_RECORD_ID" "$CF_PAYLOAD" "failover:${DR_DOMAIN}" \
  "$CF_EMR_RECORD_ID" "$CF_EMR_PAYLOAD" "failover:${EMR_DOMAIN}"; then
  :
else
  dns_rc=$?
  if [ "$dns_rc" -eq 2 ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  fi
  dr_state_write "$DR_STATE_FAILURE_STATUS" 2>/dev/null || true
  exit "$dns_rc"
fi

echo "[DNS] Cloudflare proxied DNS records switched to the AWS DR web endpoint."
echo "[DNS] Cloudflare proxied DNS record를 AWS DR Web endpoint로 전환했습니다."

public_health_passed=0
public_health_attempts="${PUBLIC_HEALTH_ATTEMPTS:-30}"
for attempt in $(seq 1 "$public_health_attempts"); do
  if curl -fsS --connect-timeout 5 --max-time 15 "https://${DR_DOMAIN}/" >/dev/null \
     && curl -fsS --connect-timeout 5 --max-time 15 \
       -H "X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}" "https://${EMR_DOMAIN}/emr/" >/dev/null; then
    public_health_passed=1
    echo "[VALIDATION] Public Web and EMR health checks passed after DNS cutover."
    break
  fi
  echo "[VALIDATION] Waiting for public DNS health (${attempt}/${public_health_attempts})."
  sleep "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}"
done
if [ "$public_health_passed" -ne 1 ]; then
  echo "[VALIDATION ERROR] Public health failed after DNS cutover; attempting DNS rollback."
  if dr_dns_rollback_snapshots "$DNS_TX_DIR"; then
    DR_STATE_FAILURE_STATUS=FAILED
    dr_state_write FAILED 2>/dev/null || true
  else
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
  exit 1
fi
dr_timing_end dns.cutover "$dns_timing_start"
dr_state_write DR_ACTIVE

echo "--------------------------------------------------"
dr_timing_end health "$health_timing_start"
zbx_send_now dr.dns.cutover_at
zbx_send_now dr.health.passed_at
zbx_send dr.rto.seconds "$(( $(date +%s) - FAILOVER_START_TS ))"
zbx_send dr.failover.status 2
dr_timing_end failover "$workflow_timing_start"
echo "[DR FAILOVER] Service provisioning and validation completed successfully."
echo "[DR 페일오버] 서비스 프로비저닝 및 검증 완료."
