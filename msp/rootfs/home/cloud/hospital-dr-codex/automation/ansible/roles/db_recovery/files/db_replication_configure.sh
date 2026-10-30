#!/bin/bash
set -euo pipefail

MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
TARGET_DB="${TARGET_DB:-hospital_db}"

SOURCE_HOST="${DB_SOURCE_HOST:-}"
SOURCE_PORT="${DB_SOURCE_PORT:-3306}"
REPL_USER="${DB_REPL_USER:-repl1}"
REPL_PASSWORD="${DB_REPL_PASSWORD:-}"
REPL_SERVER_ID="${DB_REPL_SERVER_ID:-20}"
REPL_MODE="${DB_REPL_MODE:-position}"
SOURCE_LOG_FILE="${DB_SOURCE_LOG_FILE:-}"
SOURCE_LOG_POS="${DB_SOURCE_LOG_POS:-}"
BACKUP_DIR="${BACKUP_DIR:-/home/ubuntu/db_backups}"
BACKUP_ID="${DB_NR_BACKUP_ID:-}"
BACKUP_FILE="${DB_NR_BACKUP_FILE:-}"
STATUS_FILE="${DB_NR_STATUS_FILE:-}"
RESTORE_PROOF_BACKUP_ID="${DB_NR_RESTORE_PROOF_BACKUP_ID:-}"
RESTORE_PROOF_RC="${DB_NR_RESTORE_PROOF_RC:-}"
RESTORE_PROOF_LOG_FILE="${DB_NR_RESTORE_PROOF_LOG_FILE:-}"
RESTORE_PROOF_LOG_POS="${DB_NR_RESTORE_PROOF_LOG_POS:-}"
ALLOW_EXISTING_DATA="${DB_NR_ALLOW_EXISTING_DATA:-true}"
PREFLIGHT_ONLY=false

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--preflight-only" ]; }; then
  echo "Usage: $0 [--preflight-only]"
  exit 2
fi
if [ "$#" -eq 1 ]; then
  PREFLIGHT_ONLY=true
fi

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

if [[ ! "$SOURCE_PORT" =~ ^[0-9]{1,5}$ ]] || (( SOURCE_PORT < 1 || SOURCE_PORT > 65535 )); then
  echo "[NR CONFIG ERROR] DB_SOURCE_PORT is invalid."
  exit 1
fi

# This check is tied to the exact backup and the successful restore task
# registered by the current Ansible play. It never infers a seed from an
# existing DR database or from a caller-provided Boolean alone.
if COORDINATE_OUTPUT="$(python3 - "$BACKUP_DIR" "$BACKUP_ID" "$BACKUP_FILE" "$STATUS_FILE" \
  "$RESTORE_PROOF_BACKUP_ID" "$RESTORE_PROOF_RC" "$RESTORE_PROOF_LOG_FILE" "$RESTORE_PROOF_LOG_POS" "$ALLOW_EXISTING_DATA" \
  "$SOURCE_LOG_FILE" "$SOURCE_LOG_POS" 2>&1 <<'PY'
import datetime
import re
import sys
from pathlib import Path

(
    backup_dir_arg,
    backup_id,
    backup_file_arg,
    status_file_arg,
    restore_backup_id,
    restore_rc,
    restore_log_file,
    restore_log_position,
    allow_existing,
    explicit_file,
    explicit_position,
) = sys.argv[1:]


def fail(code):
    print(code, file=sys.stderr)
    raise SystemExit(1)


match = re.fullmatch(r"db_backup_(\d{8}_\d{4,6})\.sql\.gz\.enc", backup_id)
if not match:
    fail("NR_SEED_BACKUP_ID_INVALID")
if restore_backup_id != backup_id or restore_rc != "0":
    fail("NR_SEED_RESTORE_NOT_VERIFIED")
if allow_existing.strip().lower() == "true":
    fail("NR_SEED_EXISTING_DATA_NOT_ALLOWED")
if allow_existing.strip().lower() != "false":
    fail("NR_SEED_DATA_POLICY_INVALID")
if bool(explicit_file) != bool(explicit_position):
    fail("NR_EXPLICIT_COORDINATES_INCOMPLETE")

try:
    raw_root = Path(backup_dir_arg)
    if raw_root.is_symlink():
        fail("NR_BACKUP_DIRECTORY_INVALID")
    backup_root = raw_root.resolve(strict=True)
    backup_path = Path(backup_file_arg)
    status_path = Path(status_file_arg)
    if backup_path.is_symlink() or status_path.is_symlink():
        fail("NR_SELECTED_ARTIFACT_SYMLINK")
    backup_real = backup_path.resolve(strict=True)
    status_real = status_path.resolve(strict=True)
except OSError:
    fail("NR_SELECTED_ARTIFACT_MISSING")

expected_status_name = backup_id.removesuffix(".sql.gz.enc") + ".master_status"
if (
    not backup_root.is_dir()
    or backup_path.name != backup_id
    or backup_real.parent != backup_root
    or not backup_real.is_file()
    or backup_real.stat().st_size <= 0
):
    fail("NR_SELECTED_BACKUP_MISMATCH")
if (
    status_path.name != expected_status_name
    or status_real.parent != backup_root
    or not status_real.is_file()
    or status_real.stat().st_size <= 0
):
    fail("NR_SELECTED_SIDECAR_MISMATCH")

try:
    text = status_real.read_text(encoding="utf-8")
except (OSError, UnicodeError):
    fail("NR_SELECTED_SIDECAR_UNREADABLE")

stamps = re.findall(r"(?im)^\s*BackupTimestamp\s*:\s*(\S+)\s*$", text)
if len(set(stamps)) != 1:
    fail("NR_SIDECAR_BACKUP_TIMESTAMP_MISSING_OR_AMBIGUOUS")
expected_stamp = match.group(1)
actual_stamp = stamps[0]
if actual_stamp != expected_stamp:
    # Support equivalent ISO timestamp spelling, while comparing the complete
    # timestamp rather than only the date.
    try:
        expected_dt = datetime.datetime.strptime(expected_stamp, "%Y%m%d_%H%M%S")
        iso_text = actual_stamp[:-1] + "+00:00" if actual_stamp.endswith("Z") else actual_stamp
        actual_dt = datetime.datetime.fromisoformat(iso_text)
        if actual_dt.replace(tzinfo=None) != expected_dt:
            fail("NR_SIDECAR_BACKUP_TIMESTAMP_MISMATCH")
    except ValueError:
        fail("NR_SIDECAR_BACKUP_TIMESTAMP_MISMATCH")

files = re.findall(r"(?im)^\s*(?:File|BinlogFile)\s*:\s*(\S+)\s*$", text)
positions = re.findall(r"(?im)^\s*(?:Position|BinlogPosition)\s*:\s*(\d+)\s*$", text)
files += re.findall(r"(?i)(?:MASTER|SOURCE)_LOG_FILE\s*=\s*'([^']+)'", text)
positions += re.findall(r"(?i)(?:MASTER|SOURCE)_LOG_POS\s*=\s*(\d+)", text)
if len(set(files)) != 1 or len(set(positions)) != 1:
    fail("NR_SIDECAR_COORDINATES_MISSING_OR_AMBIGUOUS")
log_file = files[0]
log_position = positions[0]
if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", log_file) or not re.fullmatch(r"[1-9][0-9]{0,19}", log_position):
    fail("NR_SIDECAR_COORDINATES_INVALID")
if restore_log_file != log_file or restore_log_position != log_position:
    fail("NR_RESTORED_DUMP_COORDINATES_MISMATCH")

if explicit_file and (explicit_file != log_file or explicit_position != log_position):
    fail("NR_EXPLICIT_COORDINATES_MISMATCH")

print(f"{log_file}\t{log_position}")
PY
)"; then
  COORDINATES="$COORDINATE_OUTPUT"
else
  if [ "$COORDINATE_OUTPUT" = "NR_SIDECAR_COORDINATES_INVALID" ]; then
    echo "[NR CONFIG ERROR] Position metadata is not a valid binlog file/position pair." >&2
    echo "[NR 설정 오류] Position metadata가 유효한 binlog 파일/position 쌍이 아닙니다." >&2
  else
    echo "[NR CONFIG ERROR] Dump/sidecar/restore preflight failed (${COORDINATE_OUTPUT:-unknown}); replication state was not changed." >&2
    echo "[NR 설정 오류] Dump/sidecar/복원 사전 검증 실패; 복제 상태는 변경되지 않았습니다." >&2
  fi
  exit 1
fi

IFS=$'\t' read -r SIDECAR_LOG_FILE SIDECAR_LOG_POS <<< "$COORDINATES"
if [ "$REPL_MODE" = "position" ]; then
  SOURCE_LOG_FILE="$SIDECAR_LOG_FILE"
  SOURCE_LOG_POS="$SIDECAR_LOG_POS"
fi

if [ "$PREFLIGHT_ONLY" = true ]; then
  echo "NR_PREFLIGHT=PASS backup_id=${BACKUP_ID} binlog_file=${SIDECAR_LOG_FILE} binlog_position=${SIDECAR_LOG_POS} mode=${REPL_MODE}"
  exit 0
fi

echo "[NR CONFIG] Configuring DR database as a MySQL replica from the selected restored Dump."
echo "[NR 설정] 선택한 복원 Dump 기준으로 DR 데이터베이스를 MySQL replica로 구성합니다."

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
log_bin=mysql-bin
binlog_format=ROW
replicate_do_db=${TARGET_DB}
EOF

systemctl restart mysql

mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP REPLICA;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "STOP SLAVE;" 2>/dev/null || true
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "RESET REPLICA ALL;" 2>/dev/null || mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "RESET SLAVE ALL;" 2>/dev/null || true

if [ "$REPL_MODE" = "position" ]; then
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
