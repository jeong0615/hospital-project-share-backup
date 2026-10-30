#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
REGION="${AWS_REGION:-ap-northeast-2}"
DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi

CF_ZONE_ID="${CF_ZONE_ID:-}"
require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: ${name}."
    return 1
  fi
}

require_config "CF_ZONE_ID"
load_cloudflare_ssm_token

echo "[STATUS] AWS DR instances"
echo "[상태] AWS DR 인스턴스"
aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
  --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,State:State.Name,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress}' \
  --output table

echo "[STATUS] Cloudflare DNS record"
echo "[상태] Cloudflare DNS record"
curl -fsS -G "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
  --data-urlencode "name=${DOMAIN}" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json" || true
echo

echo "[STATUS] Public Web health"
echo "[상태] 공개 Web health"
curl -kfsS --connect-timeout 5 --max-time 15 "https://${DOMAIN}/health" || true
echo

echo "[STATUS] Public EMR health"
echo "[상태] 공개 EMR health"
curl -kfsS --connect-timeout 5 --max-time 15 -H "X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}" "https://${DOMAIN}/emr/" >/dev/null && echo "EMR_OK" || echo "EMR_FAIL"

echo "[STATUS] DR DB replication or writability"
echo "[상태] DR DB replication 또는 쓰기 가능 상태"
if [ -z "${MYSQL_ROOT_PASS:-}" ]; then
  echo "[CONFIG ERROR] Missing required secret: "<SET_IN_SECRET_STORE>" Set it in ${SECRET_FILE}."
  echo "[설정 오류] 필수 secret 누락: MYSQL_ROOT_PASS. ${SECRET_FILE}에 설정하십시오."
  exit 1
fi
ansible -i "$INVENTORY" db_servers -m shell -a "
mysql_defaults_file=\$(mktemp)
cleanup_mysql_defaults() { rm -f \"\$mysql_defaults_file\"; }
trap cleanup_mysql_defaults EXIT
chmod 600 \"\$mysql_defaults_file\"
{
  printf '[client]\\n'
  printf 'user=root\\n'
  printf 'password=%s\\n' '${MYSQL_ROOT_PASS}'
} > \"\$mysql_defaults_file\"
mysql --defaults-extra-file=\"\$mysql_defaults_file\" -e 'SELECT @@read_only AS read_only, @@super_read_only AS super_read_only;'
(mysql --defaults-extra-file=\"\$mysql_defaults_file\" -e 'SHOW REPLICA STATUS\\G' 2>/dev/null || mysql --defaults-extra-file=\"\$mysql_defaults_file\" -e 'SHOW SLAVE STATUS\\G' 2>/dev/null || true)
"
