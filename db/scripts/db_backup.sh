#!/bin/bash
set -euo pipefail
DB_USER="hoseo"
DB_NAME="hospital_db"
# Inject this value from an access-controlled Secret store or environment.
# Never commit the encryption key to this Repository.
ENCRYPTION_KEY="${DB_BACKUP_ENCRYPTION_KEY:?DB_BACKUP_ENCRYPTION_KEY is required}"
CLOUD_USER="cloud"
CLOUD_IP="IP_REDACTED"

CLOUD_DIR="/home/cloud/db_backups"
SSH_KEY="/home/hoseo/.ssh/hospital_dr_backup"

BACKUP_DIR="$HOME/db_backups"
TS=$(date +"%Y%m%d_%H%M%S")
BASE="db_backup_${TS}"

SQL_TMP="$BACKUP_DIR/${BASE}.sql.part"
GZ_TMP="$BACKUP_DIR/${BASE}.sql.gz.part"
ENC_TMP="$BACKUP_DIR/${BASE}.sql.gz.enc.part"
MASTER_TMP="$BACKUP_DIR/${BASE}.master_status.part"

ENC_FILE="$BACKUP_DIR/${BASE}.sql.gz.enc"
MASTER_FILE="$BACKUP_DIR/${BASE}.master_status"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# 중복 실행 방지
exec 9>"$BACKUP_DIR/.db_backup.lock"
if ! flock -n 9; then
    echo "ERROR: 이미 DB 백업이 실행 중입니다."
    exit 75
fi

cleanup() {
    rm -f "$SQL_TMP" "$GZ_TMP" "$ENC_TMP" "$MASTER_TMP"
}
trap cleanup EXIT

echo "[1/6] mysqldump 생성 중..."

mysqldump \
  -u "$DB_USER" \
  --single-transaction \
  --source-data=2 \
  --routines \
  --triggers \
  --events \
  --no-tablespaces \
  "$DB_NAME" > "$SQL_TMP"

echo "[2/6] Dump 시점 Binlog 좌표 추출 중..."

grep -m 1 -E "CHANGE MASTER TO|CHANGE REPLICATION SOURCE TO" \
  "$SQL_TMP" > "$MASTER_TMP" || {
    echo "ERROR: Dump 내부에서 Binlog File/Position을 찾지 못했습니다."
    exit 1
}

echo "[3/6] gzip 압축 중..."
gzip -c "$SQL_TMP" > "$GZ_TMP"

echo "[4/6] AES-256 암호화 중..."
printf '%s' "$ENCRYPTION_KEY" |
  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in "$GZ_TMP" \
    -out "$ENC_TMP" \
    -pass stdin

echo "[5/6] 암호화 Dump 무결성 검사 중..."

if ! printf '%s' "$ENCRYPTION_KEY" |
    openssl enc -d -aes-256-cbc -pbkdf2 \
    -in "$ENC_TMP" \
    -pass stdin 2>/dev/null |
    gzip -t
then
    echo "ERROR: 암호화 Dump 무결성 검증 실패"
    exit 1
fi

# 로컬에서도 완전한 pair가 된 뒤 최종 파일명으로 전환
mv "$MASTER_TMP" "$MASTER_FILE"
mv "$ENC_TMP" "$ENC_FILE"
chmod 600 "$MASTER_FILE" "$ENC_FILE"

echo "[6/6] MSP로 전송 중..."

REMOTE_ENC_PART="${CLOUD_DIR}/${BASE}.sql.gz.enc.part"
REMOTE_MASTER_PART="${CLOUD_DIR}/${BASE}.master_status.part"

scp \
  -i "$SSH_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  "$ENC_FILE" \
  "${CLOUD_USER}@${CLOUD_IP}:${REMOTE_ENC_PART}"

scp \
  -i "$SSH_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  "$MASTER_FILE" \
  "${CLOUD_USER}@${CLOUD_IP}:${REMOTE_MASTER_PART}"

# master_status를 먼저 rename하고 Dump를 마지막에 공개.
# MSP uploader가 완성되지 않은 pair를 정상 백업으로 보지 않도록 함.
ssh \
  -i "$SSH_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  "${CLOUD_USER}@${CLOUD_IP}" \
  "test -s '$REMOTE_ENC_PART' &&
   test -s '$REMOTE_MASTER_PART' &&
   mv '$REMOTE_MASTER_PART' '${CLOUD_DIR}/${BASE}.master_status' &&
   mv '$REMOTE_ENC_PART' '${CLOUD_DIR}/${BASE}.sql.gz.enc'"

echo
echo "===== DB BACKUP SUCCESS ====="
echo "Dump:          $ENC_FILE"
echo "Master Status: $MASTER_FILE"
echo
echo "Dump-consistent Binlog coordinate:"
cat "$MASTER_FILE"
