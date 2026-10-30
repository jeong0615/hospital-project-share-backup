#!/bin/bash
set -euo pipefail

MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"

if [ -z "$MYSQL_ROOT_PASS" ]; then
  echo "[DB PROMOTION ERROR] Required variable is missing: MYSQL_ROOT_PASS"
  echo "[DB 승격 오류] 필수 변수가 없습니다: MYSQL_ROOT_PASS"
  exit 1
fi

MYSQL_DEFAULTS_FILE=$(mktemp)
cleanup_mysql_defaults() {
  rm -f "$MYSQL_DEFAULTS_FILE"
}
trap cleanup_mysql_defaults EXIT
chmod 600 "$MYSQL_DEFAULTS_FILE"
{
  printf '[client]\n'
  printf 'user=root\n'
  printf 'password=%s\n' "$MYSQL_ROOT_PASS"
} > "$MYSQL_DEFAULTS_FILE"

echo "[DB PROMOTION] Promoting DR database to writable primary mode."
echo "[DB 승격] DR 데이터베이스를 쓰기 가능한 primary 모드로 승격합니다."

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP REPLICA;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP SLAVE;" 2>/dev/null || true
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SET GLOBAL super_read_only=OFF;" 2>/dev/null || true
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SET GLOBAL read_only=OFF;"

rm -f /etc/mysql/mysql.conf.d/99-hospital-dr-promotion.cnf /etc/mysql/mysql.conf.d/100-hospital-dr-promotion.cnf
cat >/etc/mysql/mysql.conf.d/zz-hospital-dr-promotion.cnf <<EOF
[mysqld]
read_only=OFF
super_read_only=OFF
EOF

systemctl restart mysql

echo "[DB PROMOTION] DR database is writable."
echo "[DB 승격] DR 데이터베이스 쓰기 가능 상태 확인 완료."
