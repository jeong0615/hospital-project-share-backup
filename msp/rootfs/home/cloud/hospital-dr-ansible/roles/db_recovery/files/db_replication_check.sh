#!/bin/bash
set -euo pipefail

MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
STATUS_FILE="/tmp/mysql_replication_status.txt"

if [ -r /home/cloud/scripts/zbx_send.sh ]; then
  # The helper is optional on the DR host and always fails open.
  # shellcheck disable=SC1091
  source /home/cloud/scripts/zbx_send.sh
else
  zbx_send() { :; }
fi

if [ -z "$MYSQL_ROOT_PASS" ]; then
  echo "[NR CHECK ERROR] Required variable is missing: MYSQL_ROOT_PASS"
  echo "[NR 점검 오류] 필수 변수가 없습니다: MYSQL_ROOT_PASS"
  exit 1
fi

MYSQL_DEFAULTS_FILE=$(mktemp)
cleanup_mysql_defaults() {
  rm -f "$MYSQL_DEFAULTS_FILE" "$STATUS_FILE"
}
trap cleanup_mysql_defaults EXIT
chmod 600 "$MYSQL_DEFAULTS_FILE"
{
  printf '[client]\n'
  printf 'user=root\n'
  printf 'password=%s\n' "$MYSQL_ROOT_PASS"
} > "$MYSQL_DEFAULTS_FILE"

echo "[NR CHECK] Checking MySQL Native Replication status."
echo "[NR 점검] MySQL Native Replication 상태를 확인합니다."

if mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SHOW REPLICA STATUS\\G" > "$STATUS_FILE" 2>/dev/null \
  && grep -Eq '^[[:space:]]*Replica_IO_Running:' "$STATUS_FILE"; then
  IO_LABEL="Replica_IO_Running"
  SQL_LABEL="Replica_SQL_Running"
else
  mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SHOW SLAVE STATUS\\G" > "$STATUS_FILE"
  IO_LABEL="Slave_IO_Running"
  SQL_LABEL="Slave_SQL_Running"
fi

cat "$STATUS_FILE"

IO_RUNNING=$(awk -F': ' -v key="$IO_LABEL" '$1 ~ key {print $2; exit}' "$STATUS_FILE")
SQL_RUNNING=$(awk -F': ' -v key="$SQL_LABEL" '$1 ~ key {print $2; exit}' "$STATUS_FILE")

seconds_behind=$(awk -F': ' '/^[[:space:]]*(Seconds_Behind_Source|Seconds_Behind_Master):/ {print $2; exit}' "$STATUS_FILE")
binlog_file=$(awk -F': ' '/^[[:space:]]*(Source_Log_File|Master_Log_File):/ {print $2; exit}' "$STATUS_FILE")
binlog_position=$(awk -F': ' '/^[[:space:]]*(Exec_Source_Log_Pos|Exec_Master_Log_Pos):/ {print $2; exit}' "$STATUS_FILE")

case "$IO_RUNNING" in
  Yes) zbx_send dr.nr.io_running 1 ;;
  No) zbx_send dr.nr.io_running 0 ;;
esac
case "$SQL_RUNNING" in
  Yes) zbx_send dr.nr.sql_running 1 ;;
  No) zbx_send dr.nr.sql_running 0 ;;
esac
case "$seconds_behind" in
  ''|NULL|[!0-9]*) ;;
  *) zbx_send dr.nr.seconds_behind "$seconds_behind" ;;
esac
[ -n "$binlog_file" ] && zbx_send dr.nr.binlog_file "$binlog_file"
case "$binlog_position" in
  ''|[!0-9]*) ;;
  *) zbx_send dr.nr.binlog_position "$binlog_position" ;;
esac

if [ "$IO_RUNNING" = "Yes" ] && [ "$SQL_RUNNING" = "Yes" ]; then
  echo "[NR CHECK] Replication is healthy. IO=${IO_RUNNING}, SQL=${SQL_RUNNING}"
  echo "[NR 점검] Replication 정상. IO=${IO_RUNNING}, SQL=${SQL_RUNNING}"
  exit 0
fi

echo "[NR CHECK ERROR] Replication is not healthy. IO=${IO_RUNNING:-unknown}, SQL=${SQL_RUNNING:-unknown}"
echo "[NR 점검 오류] Replication 비정상. IO=${IO_RUNNING:-unknown}, SQL=${SQL_RUNNING:-unknown}"
exit 1
