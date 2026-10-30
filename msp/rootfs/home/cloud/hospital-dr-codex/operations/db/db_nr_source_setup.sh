#!/bin/bash
set -euo pipefail

SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi

MYSQL_ROOT_USER="${MYSQL_ROOT_USER:-root}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
TARGET_DB="${TARGET_DB:-hospital_db}"
REPL_USER="${DB_REPL_USER:-repl1}"
REPL_PASSWORD="${DB_REPL_PASSWORD:-}"
REPL_ALLOWED_HOST="${DB_REPL_ALLOWED_HOST:-IP_REDACTED}"
SOURCE_SERVER_ID="${DB_SOURCE_SERVER_ID:-1}"

for required_secret in MYSQL_ROOT_PASS DB_REPL_PASSWORD; do
  if [ -z "${!required_secret:-}" ]; then
    echo "[NR SOURCE CONFIG ERROR] Required variable is missing: ${required_secret}. Set it in ${SECRET_FILE}."
    exit 1
  fi
done

MYSQL_DEFAULTS_FILE=$(mktemp)
cleanup_mysql_defaults() {
  rm -f "$MYSQL_DEFAULTS_FILE"
}
trap cleanup_mysql_defaults EXIT
chmod 600 "$MYSQL_DEFAULTS_FILE"
{
  printf '[client]\n'
  printf 'user=%s\n' "$MYSQL_ROOT_USER"
  printf 'password=%s\n' "$MYSQL_ROOT_PASS"
} > "$MYSQL_DEFAULTS_FILE"

echo "[NR SOURCE CONFIG] Enabling MySQL binary log and replication account on source DB."

sudo tee /etc/mysql/mysql.conf.d/99-hospital-dr-source.cnf >/dev/null <<EOF
[mysqld]
server-id=${SOURCE_SERVER_ID}
log_bin=mysql-bin
binlog_format=ROW
binlog_do_db=${TARGET_DB}
bind-address=IP_REDACTED
EOF

sudo systemctl restart mysql

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "CREATE USER IF NOT EXISTS '$REPL_USER'@'$REPL_ALLOWED_HOST' IDENTIFIED BY '$REPL_PASSWORD';"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO '$REPL_USER'@'$REPL_ALLOWED_HOST';"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "FLUSH PRIVILEGES;"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SHOW MASTER STATUS\\G" || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "SHOW BINARY LOG STATUS\\G"

echo "[NR SOURCE CONFIG] Source DB is ready for Native Replication."
