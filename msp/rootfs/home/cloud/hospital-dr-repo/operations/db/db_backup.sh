#!/bin/bash
set -euo pipefail

if [ -r /opt/hospital-dr/operations/db/zbx_send.sh ]; then
    # Metrics are best-effort; backup behavior must remain unchanged.
    # shellcheck disable=SC1091
    source /opt/hospital-dr/operations/db/zbx_send.sh
else
    zbx_send() { :; }
    zbx_send_now() { :; }
fi

dump_metric_failed() {
    zbx_send dr.dump.status 0 2>/dev/null || true
}
trap dump_metric_failed ERR

SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
    # shellcheck disable=SC1090
    source "$SECRET_FILE"
fi

require_secret() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        echo "[CONFIG ERROR] Missing required secret: ${name}. Set it in ${SECRET_FILE}."
        exit 1
    fi
}

MYSQL_DEFAULTS_FILE=""
TMP_DUMP=""
TMP_GZ=""
TMP_ENC=""
TMP_STATUS=""

cleanup() {
    if [ -n "$MYSQL_DEFAULTS_FILE" ]; then
        rm -f "$MYSQL_DEFAULTS_FILE"
    fi
    rm -f "$TMP_DUMP" "$TMP_GZ" "$TMP_ENC" "$TMP_STATUS"
}
trap cleanup EXIT

create_mysql_defaults_file() {
    MYSQL_DEFAULTS_FILE=$(mktemp)
    chmod 600 "$MYSQL_DEFAULTS_FILE"
    {
        printf '[client]\n'
        printf 'user=%s\n' "$DB_USER"
        printf 'password=%s\n' "$DB_PASS"
    } > "$MYSQL_DEFAULTS_FILE"
}

# 1. 변수 설정
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-${MYSQL_ROOT_PASS:-}}"
DB_NAME="${DB_NAME:-hospital_db}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/db_backups}"
STAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_PREFIX="db_backup_${STAMP}"
FILENAME="${BACKUP_PREFIX}.sql"
STATUS_NAME="${BACKUP_PREFIX}.master_status"
ENC_NAME="${BACKUP_PREFIX}.sql.gz.enc"
ENCRYPTION_KEY="${DB_BACKUP_ENCRYPTION_KEY:-}"

# 2. 클라우드 서버 전송 정보
CLOUD_USER="${CLOUD_USER:-cloud}"
CLOUD_IP="${CLOUD_IP:-IP_REDACTED}"
CLOUD_DEST="${CLOUD_DEST:-/var/lib/hospital-dr/db_backups/}"

if [ -z "$ENCRYPTION_KEY" ]; then
    echo "[CONFIG ERROR] Required environment variable is missing: DB_BACKUP_ENCRYPTION_KEY"
    exit 1
fi
require_secret "DB_PASS"
create_mysql_defaults_file

# 3. 백업 디렉토리 확인 및 생성
mkdir -p "$BACKUP_DIR"
cd "$BACKUP_DIR"
LOCK_FILE="${BACKUP_LOCK_FILE:-$BACKUP_DIR/.db_backup.lock}"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "[$(date)] Another DB backup is already running; skipping this schedule."
    exit 0
fi
TMP_DUMP=$(mktemp "$BACKUP_DIR/.${BACKUP_PREFIX}.XXXXXX.sql")
TMP_GZ="${TMP_DUMP}.gz"
TMP_ENC="${TMP_GZ}.enc"
TMP_STATUS=$(mktemp "$BACKUP_DIR/.${STATUS_NAME}.XXXXXX")

if mysqldump --help 2>/dev/null | grep -q -- '--source-data'; then
    BINLOG_OPTION="--source-data=2"
elif mysqldump --help 2>/dev/null | grep -q -- '--master-data'; then
    BINLOG_OPTION="--master-data=2"
else
    echo "[CONFIG ERROR] mysqldump does not support Position metadata (--master-data/--source-data)."
    exit 1
fi

# 4. DB 덤프 (mysqldump)
echo "[$(date)] Starting MySQL logical backup export..."
mysqldump --defaults-extra-file="$MYSQL_DEFAULTS_FILE" --single-transaction "$BINLOG_OPTION" --routines --triggers "$DB_NAME" > "$TMP_DUMP"
test -s "$TMP_DUMP"

echo "[$(date)] Extracting the binlog coordinates embedded in the dump."
python3 - "$TMP_DUMP" "$TMP_STATUS" "$STAMP" <<'PY'
import re
import sys

dump_path, status_path, stamp = sys.argv[1:]
log_file = None
log_pos = None
with open(dump_path, "r", encoding="utf-8", errors="replace") as dump:
    for line in dump:
        if "CHANGE MASTER TO" not in line and "CHANGE REPLICATION SOURCE TO" not in line:
            continue
        file_match = re.search(r"(?:MASTER|SOURCE)_LOG_FILE='([^']+)'", line)
        pos_match = re.search(r"(?:MASTER|SOURCE)_LOG_POS=(\d+)", line)
        if file_match and pos_match:
            log_file = file_match.group(1)
            log_pos = pos_match.group(1)
            break

if not log_file or not log_pos:
    raise SystemExit("dump does not contain usable binlog coordinates")

with open(status_path, "w", encoding="ascii") as status:
    status.write(f"BackupTimestamp: {stamp}\n")
    status.write(f"BinlogFile: {log_file}\n")
    status.write(f"BinlogPosition: {log_pos}\n")
    status.write("Source: mysqldump embedded Position metadata\n")
PY
test -s "$TMP_STATUS"

# 5. 압축 (gzip)
echo "[$(date)] Compressing database backup artifact..."
gzip -c "$TMP_DUMP" > "$TMP_GZ"
gzip -t "$TMP_GZ"

# 6. 암호화 적용 (AES-256-CBC)
echo "[$(date)] Encrypting database backup artifact..."
printf '%s' "$ENCRYPTION_KEY" | openssl enc -aes-256-cbc -salt -pbkdf2 -in "$TMP_GZ" -out "$TMP_ENC" -pass stdin
test -s "$TMP_ENC"

echo "[$(date)] Verifying encrypted gzip integrity without writing plaintext."
printf '%s' "$ENCRYPTION_KEY" | openssl enc -d -aes-256-cbc -in "$TMP_ENC" -pass stdin | gzip -t
echo "[$(date)] Encrypted gzip integrity verification passed."

# 7. 클라우드 서버로 안전하게 전송 (scp)
echo "[$(date)] Transferring encrypted backup artifact to DR staging host..."
REMOTE_HOST="${CLOUD_USER}@${CLOUD_IP}"
REMOTE_DEST="${CLOUD_DEST%/}"
REMOTE_ENC_PART="${REMOTE_DEST}/.${ENC_NAME}.part"
REMOTE_STATUS_PART="${REMOTE_DEST}/.${STATUS_NAME}.part"
SSH_OPTS=(-o StrictHostKeyChecking=no)
scp "${SSH_OPTS[@]}" "$TMP_ENC" "$REMOTE_HOST:$REMOTE_ENC_PART"
scp "${SSH_OPTS[@]}" "$TMP_STATUS" "$REMOTE_HOST:$REMOTE_STATUS_PART"
ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" sh -s -- "$REMOTE_DEST" "$ENC_NAME" "$STATUS_NAME" <<'REMOTE'
set -eu
destination="$1"
encrypted_name="$2"
status_name="$3"
test -s "$destination/.$encrypted_name.part"
test -s "$destination/.$status_name.part"
mv -- "$destination/.$status_name.part" "$destination/$status_name"
mv -- "$destination/.$encrypted_name.part" "$destination/$encrypted_name"
test -s "$destination/$status_name"
test -s "$destination/$encrypted_name"
REMOTE

# 8. 로컬 임시 파일 삭제 (보안 및 용량 확보)
echo "[$(date)] Cleaning up local temporary backup artifacts..."
rm -f "$TMP_DUMP" "$TMP_GZ" "$TMP_ENC" "$TMP_STATUS"
TMP_DUMP=""
TMP_GZ=""
TMP_ENC=""
TMP_STATUS=""

echo "[$(date)] Database backup pair ${BACKUP_PREFIX}.sql.gz.enc + ${STATUS_NAME} completed successfully."
zbx_send_now dr.dump.last_created_at
zbx_send dr.dump.status 1
