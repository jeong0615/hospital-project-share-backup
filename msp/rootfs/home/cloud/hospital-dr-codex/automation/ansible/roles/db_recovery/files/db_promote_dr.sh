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

replica_status=""
if ! replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW REPLICA STATUS\G' 2>/dev/null)"; then
  replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW SLAVE STATUS\G' 2>/dev/null)" \
    || { echo "[DB PROMOTION ERROR] Replication status could not be read; DR writes remain blocked."; exit 1; }
fi
if [[ "${DR_RECOVERY_SELECTED_MODE:-UNKNOWN}" == "NR" && -z "$replica_status" ]]; then
  echo "[DB PROMOTION ERROR] Verified NR recovery has no readable replica channel; DR writes remain blocked."
  exit 1
fi
if [[ -n "$replica_status" ]]; then
  mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" \
    -e 'SET PERSIST_ONLY skip_replica_start=ON' >/dev/null 2>&1 \
    || { echo "[DB PROMOTION ERROR] Replica auto-start could not be fenced; DR writes remain blocked."; exit 1; }
  persisted_skip="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" --batch --skip-column-names \
    -e "SELECT COALESCE(UPPER(variable_value),'MISSING') FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='skip_replica_start' LIMIT 1" 2>/dev/null)" \
    || { echo "[DB PROMOTION ERROR] Replica auto-start fence could not be read back; DR writes remain blocked."; exit 1; }
  [[ "$persisted_skip" == "ON" ]] \
    || { echo "[DB PROMOTION ERROR] Replica auto-start fence did not persist; DR writes remain blocked."; exit 1; }

  if ! mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'STOP REPLICA' >/dev/null 2>&1; then
    mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'STOP SLAVE' >/dev/null 2>&1 \
      || { echo "[DB PROMOTION ERROR] Replication could not be stopped; DR writes remain blocked."; exit 1; }
  fi
  if ! replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW REPLICA STATUS\G' 2>/dev/null)"; then
    replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW SLAVE STATUS\G' 2>/dev/null)" \
      || { echo "[DB PROMOTION ERROR] Replication stop could not be verified; DR writes remain blocked."; exit 1; }
  fi
  replica_fields="$(printf '%s\n' "$replica_status" | awk -F: '
    /^[[:space:]]*(Replica_IO_Running|Slave_IO_Running):/ { io=$2; gsub(/[[:space:]]/, "", io); io_count++ }
    /^[[:space:]]*(Replica_SQL_Running|Slave_SQL_Running):/ { sql=$2; gsub(/[[:space:]]/, "", sql); sql_count++ }
    END { if (io_count == 1 && sql_count == 1) print io "|" sql; else print "UNKNOWN" }
  ')"
  [[ "$replica_fields" == "No|No" ]] \
    || { echo "[DB PROMOTION ERROR] Replica IO/SQL threads are not verified stopped; DR writes remain blocked."; exit 1; }
fi

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SET GLOBAL super_read_only=OFF;"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SET GLOBAL read_only=OFF;"

rm -f /etc/mysql/mysql.conf.d/99-hospital-dr-promotion.cnf /etc/mysql/mysql.conf.d/100-hospital-dr-promotion.cnf
cat >/etc/mysql/mysql.conf.d/zz-hospital-dr-promotion.cnf <<EOF
[mysqld]
read_only=OFF
super_read_only=OFF
EOF

# A prior standby setup may have persisted read_only=ON and
# super_read_only=ON in mysqld-auto.cnf. Those persisted values take precedence
# over this promotion file after restart, so remove only these two overrides.
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" \
  -e "RESET PERSIST IF EXISTS read_only; RESET PERSIST IF EXISTS super_read_only;"

systemctl restart mysql

replica_status=""
if ! replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW REPLICA STATUS\G' 2>/dev/null)"; then
  replica_status="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e 'SHOW SLAVE STATUS\G' 2>/dev/null)" \
    || { echo "[DB PROMOTION ERROR] Post-restart replication state could not be read."; exit 1; }
fi
if [[ "${DR_RECOVERY_SELECTED_MODE:-UNKNOWN}" == "NR" && -z "$replica_status" ]]; then
  echo "[DB PROMOTION ERROR] NR channel disappeared after MySQL restart; promotion result is not trusted."; exit 1
fi
if [[ -n "$replica_status" ]]; then
  replica_fields="$(printf '%s\n' "$replica_status" | awk -F: '
    /^[[:space:]]*(Replica_IO_Running|Slave_IO_Running):/ { io=$2; gsub(/[[:space:]]/, "", io); io_count++ }
    /^[[:space:]]*(Replica_SQL_Running|Slave_SQL_Running):/ { sql=$2; gsub(/[[:space:]]/, "", sql); sql_count++ }
    END { if (io_count == 1 && sql_count == 1) print io "|" sql; else print "UNKNOWN" }
  ')"
  [[ "$replica_fields" == "No|No" ]] \
    || { echo "[DB PROMOTION ERROR] Replica IO/SQL threads restarted after promotion; result is not trusted."; exit 1; }
fi

echo "[DB PROMOTION] DR database is writable."
echo "[DB 승격] DR 데이터베이스 쓰기 가능 상태 확인 완료."
