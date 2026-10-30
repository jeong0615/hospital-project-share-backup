#!/bin/bash
set -euo pipefail

MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
TARGET_DB="${TARGET_DB:-hospital_db}"

SOURCE_HOST="${DB_SOURCE_HOST:-}"
SOURCE_PORT="${DB_SOURCE_PORT:-3306}"
REPL_USER="${DB_REPL_USER:-repl}"
REPL_PASSWORD="${DB_REPL_PASSWORD:-}"
REPL_SERVER_ID="${DB_REPL_SERVER_ID:-20}"
REPL_MODE="${DB_REPL_MODE:-position}"
SOURCE_LOG_FILE="${DB_SOURCE_LOG_FILE:-}"
SOURCE_LOG_POS="${DB_SOURCE_LOG_POS:-}"
BACKUP_DIR="${BACKUP_DIR:-/home/ubuntu/db_backups}"

for required_secret in MYSQL_ROOT_PASS DB_SOURCE_HOST DB_REPL_PASSWORD; do
  if [ -z "${!required_secret:-}" ]; then
    echo "[NR CONFIG ERROR] Required variable is missing: ${required_secret}"
    echo "[NR 설정 오류] 필수 변수가 없습니다: ${required_secret}"
    exit 1
  fi
done

case "$REPL_MODE" in
  position|gtid) ;;
  *)
    echo "[NR CONFIG ERROR] Unsupported DB_REPL_MODE: ${REPL_MODE}. Use position or gtid."
    echo "[NR 설정 오류] 지원하지 않는 DB_REPL_MODE입니다: ${REPL_MODE}. position 또는 gtid을 사용하십시오."
    exit 1
    ;;
esac

echo "[NR CONFIG] Configuring DR database as a MySQL replica."
echo "[NR 설정] DR 데이터베이스를 MySQL replica로 구성합니다."

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

cat >/etc/mysql/mysql.conf.d/99-hospital-dr-replica.cnf <<EOF
[mysqld]
server-id=${REPL_SERVER_ID}
relay_log=dr-relay-bin
read_only=ON
super_read_only=ON
log_bin=dr-mysql-bin
binlog_format=ROW
replicate_do_db=${TARGET_DB}
EOF

systemctl restart mysql

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP REPLICA;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP SLAVE;" 2>/dev/null || true
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "RESET REPLICA ALL;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "RESET SLAVE ALL;" 2>/dev/null || true

if [ "$REPL_MODE" = "position" ]; then
  if [ -z "$SOURCE_LOG_FILE" ] || [ -z "$SOURCE_LOG_POS" ]; then
    LATEST_STATUS=$(find "$BACKUP_DIR" -maxdepth 1 -type f \( -name '*.master_status' -o -name 'recovery.master_status' \) -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {print $2}')
    if [ -n "${LATEST_STATUS:-}" ]; then
      SOURCE_LOG_FILE=$(awk '/File:/ {print $2; exit} /MASTER_LOG_FILE|SOURCE_LOG_FILE/ {match($0, /(MASTER_LOG_FILE|SOURCE_LOG_FILE)='\''[^'\'']+'\''/); if (RSTART) {value=substr($0, RSTART, RLENGTH); sub(/.*='\''/, "", value); sub(/'\''$/, "", value); print value; exit}}' "$LATEST_STATUS")
      SOURCE_LOG_POS=$(awk '/Position:/ {print $2; exit} /MASTER_LOG_POS|SOURCE_LOG_POS/ {match($0, /(MASTER_LOG_POS|SOURCE_LOG_POS)=[0-9]+/); if (RSTART) {value=substr($0, RSTART, RLENGTH); sub(/.*=/, "", value); print value; exit}}' "$LATEST_STATUS")
      echo "[NR CONFIG] Loaded replication coordinates from ${LATEST_STATUS}: ${SOURCE_LOG_FILE}/${SOURCE_LOG_POS}"
      echo "[NR 설정] ${LATEST_STATUS}에서 replication 좌표를 불러왔습니다: ${SOURCE_LOG_FILE}/${SOURCE_LOG_POS}"
    fi
  fi

  if [ -z "$SOURCE_LOG_FILE" ] || [ -z "$SOURCE_LOG_POS" ]; then
    echo "[NR CONFIG ERROR] Position mode requires DB_SOURCE_LOG_FILE and DB_SOURCE_LOG_POS."
    echo "[NR 설정 오류] position 모드는 DB_SOURCE_LOG_FILE, DB_SOURCE_LOG_POS가 필요합니다."
    exit 1
  fi

  CHANGE_SQL="CHANGE REPLICATION SOURCE TO SOURCE_HOST='${SOURCE_HOST}', SOURCE_PORT=${SOURCE_PORT}, SOURCE_USER='${REPL_USER}', SOURCE_PASSWORD='${REPL_PASSWORD}', SOURCE_LOG_FILE='${SOURCE_LOG_FILE}', SOURCE_LOG_POS=${SOURCE_LOG_POS}, GET_SOURCE_PUBLIC_KEY=1;"
  LEGACY_CHANGE_SQL="CHANGE MASTER TO MASTER_HOST='${SOURCE_HOST}', MASTER_PORT=${SOURCE_PORT}, MASTER_USER='${REPL_USER}', MASTER_PASSWORD='${REPL_PASSWORD}', MASTER_LOG_FILE='${SOURCE_LOG_FILE}', MASTER_LOG_POS=${SOURCE_LOG_POS}, GET_MASTER_PUBLIC_KEY=1;"
else
  CHANGE_SQL="CHANGE REPLICATION SOURCE TO SOURCE_HOST='${SOURCE_HOST}', SOURCE_PORT=${SOURCE_PORT}, SOURCE_USER='${REPL_USER}', SOURCE_PASSWORD='${REPL_PASSWORD}', SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1;"
  LEGACY_CHANGE_SQL="CHANGE MASTER TO MASTER_HOST='${SOURCE_HOST}', MASTER_PORT=${SOURCE_PORT}, MASTER_USER='${REPL_USER}', MASTER_PASSWORD='${REPL_PASSWORD}', MASTER_AUTO_POSITION=1, GET_MASTER_PUBLIC_KEY=1;"
fi

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "$CHANGE_SQL" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "$LEGACY_CHANGE_SQL"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "START REPLICA;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "START SLAVE;"

echo "[NR CONFIG] Native Replication configuration completed."
echo "[NR 설정] Native Replication 구성이 완료되었습니다."
