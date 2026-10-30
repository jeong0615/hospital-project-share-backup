#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="$SCRIPT_DIR/rootfs"
TARGET="${EMR_SSH_TARGET:-hoseo@IP_REDACTED}"
MODE="${1:---dry-run}"

if [[ "$MODE" != "--dry-run" && "$MODE" != "--apply" ]]; then
  printf 'Usage: EMR_SSH_TARGET=user@host %s [--dry-run|--apply]\n' "$0" >&2
  exit 2
fi

if ! command -v rsync >/dev/null 2>&1; then
  printf 'rsync is required.\n' >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$STAGE/home/hoseo" "$STAGE/etc/apache2/sites-available" "$STAGE/etc/apache2/sites-enabled" "$STAGE/etc/nginx" "$STAGE/var/www" "$STAGE/etc/openvpn" "$STAGE/etc/zabbix"

EXCLUDES=(
  --exclude='.env'
  --exclude='.env.*'
  --exclude='.git/'
  --exclude='.ssh/'
  --exclude='.aws/'
  --exclude='.docker/'
  --exclude='.terraform/'
  --exclude='node_modules/'
  --exclude='__pycache__/'
  --exclude='nohup.out'
  --exclude='*.log'
  --exclude='*.pem'
  --exclude='*.key'
  --exclude='*.secret'
  --exclude='*.sql'
  --exclude='*.dump'
  --exclude='*.enc'
  --exclude='*.zip'
  --exclude='*.tar'
  --exclude='*.tar.gz'
  --exclude='backend/db (orginal).js'
  --exclude='app (1try).py'
  --exclude='*.pyc'
)

rsync -a "${EXCLUDES[@]}" "$TARGET:/home/hoseo/hospital_emr/" "$STAGE/home/hoseo/hospital_emr/"
rsync -a "${EXCLUDES[@]}" "$TARGET:/home/hoseo/doctor_web/" "$STAGE/home/hoseo/doctor_web/"
CONFIG_EXCLUDES=(
  --exclude='.git/'
  --exclude='*.pem'
  --exclude='*.key'
  --exclude='*.secret'
)

rsync -a "${CONFIG_EXCLUDES[@]}" "$TARGET:/etc/nginx/" "$STAGE/etc/nginx/"
rsync -a "$TARGET:/etc/apache2/sites-available/000-default.conf" "$STAGE/etc/apache2/sites-available/"
rsync -a "$TARGET:/etc/apache2/sites-enabled/000-default.conf" "$STAGE/etc/apache2/sites-enabled/"
rsync -a "$TARGET:/etc/apache2/ports.conf" "$STAGE/etc/apache2/"
rsync -a "$TARGET:/etc/openvpn/update-resolv-conf" "$STAGE/etc/openvpn/"
rsync -a "$TARGET:/etc/vsftpd.conf" "$STAGE/etc/"
rsync -a "$TARGET:/etc/zabbix/zabbix_agentd.conf" "$STAGE/etc/zabbix/"
rsync -a "$TARGET:/var/www/html/" "$STAGE/var/www/html/"

# Keep the repository copy reproducible without copying inline credentials from
# the live source. Values are supplied through the external environment on restore.
if [[ -f "$STAGE/home/hoseo/hospital_emr/backend/db.js" ]]; then
  sed -E -i 's/(password:[[:space:]]*process\.env\.DB_PASSWORD)[[:space:]]*\|\|[[:space:]]*[^,]+/\1/g' \
    "$STAGE/home/hoseo/hospital_emr/backend/db.js"
fi

if [[ -f "$STAGE/home/hoseo/hospital_emr/backend/auth.js" ]]; then
  sed -E -i 's#^[[:space:]]*// 비밀번호가 .*#    // 환경변수 기반 테스트 계정일 때 임시 계정으로 로그인 처리#' \
    "$STAGE/home/hoseo/hospital_emr/backend/auth.js"
  sed -E -i "s/(password[[:space:]]*===[[:space:]]*)('[^']*'|\"[^\"]*\")/\1process.env.EMR_TEST_ACCOUNT_PASSWORD/g" \
    "$STAGE/home/hoseo/hospital_emr/backend/auth.js"
  sed -E -i "s/if \(testUsers\[login_id\] && password === process\.env\.EMR_TEST_ACCOUNT_PASSWORD\)/if (testUsers[login_id] \&\& process.env.EMR_TEST_ACCOUNT_PASSWORD \&\& password === process.env.EMR_TEST_ACCOUNT_PASSWORD)/" \
    "$STAGE/home/hoseo/hospital_emr/backend/auth.js"
fi

if [[ -f "$STAGE/home/hoseo/doctor_web/app.py" ]] && \
   grep -qE "['\"]password['\"][[:space:]]*:[[:space:]]*['\"]" "$STAGE/home/hoseo/doctor_web/app.py"; then
  grep -qE '^import os$' "$STAGE/home/hoseo/doctor_web/app.py" || \
    sed -i '1a import os' "$STAGE/home/hoseo/doctor_web/app.py"
  sed -E -i "s/(['\"]password['\"][[:space:]]*:[[:space:]]*)['\"][^'\"]*['\"]/\1os.getenv('DB_PASSWORD')/" \
    "$STAGE/home/hoseo/doctor_web/app.py"
fi

# Normalize text copied from the remote host so git diff --check remains useful.
while IFS= read -r -d '' file; do
  sed -i -e 's/\r$//' -e 's/[[:space:]]\+$//' -e 's/^[ ]*\t/\t/' "$file"
  perl -0777 -pi -e 's/\n+\z/\n/' "$file"
done < <(find "$STAGE" -type f -print0)

if [[ "$MODE" == "--dry-run" ]]; then
  rsync -a --dry-run "$STAGE/" "$BACKUP_ROOT/"
  printf 'Dry-run complete. No local backup files were changed.\n'
  exit 0
fi

mkdir -p "$BACKUP_ROOT"
rsync -a "$STAGE/" "$BACKUP_ROOT/"
printf 'EMR source/config synchronization complete. Review git diff before staging.\n'
printf 'This script does not run git add, commit, push, sudo, or remote services.\n'
