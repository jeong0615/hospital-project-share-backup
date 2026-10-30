#!/bin/bash
set -euo pipefail

# ==========================================
# 설정 변수 (백업 스크립트와 동일하게 설정)
# ==========================================
BACKUP_DIR="${BACKUP_DIR:-/home/ubuntu/db_backups}"
PASS_PHRASE="${DB_BACKUP_ENCRYPTION_KEY:-}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
TARGET_DB="${TARGET_DB:-hospital_db}"

# The demo existing-DR path is deliberately separate from the legacy restore
# workflow below. It is opt-in, request-bound, verifies both encrypted files,
# and streams SQL directly into MySQL without persisting plaintext SQL.
if [[ "${DEMO_DUMP_RESTORE_MODE:-false}" == "true" ]]; then
    fail_demo_restore() {
        printf 'DEMO_DB_RESTORE=BLOCKED reason=%s\n' "$1" >&2
        exit 1
    }

    [[ "${DUMP_RESTORE_EXEC_ENABLED:-false}" == "true" ]] || fail_demo_restore DUMP_RESTORE_EXECUTOR_DISABLED
    [[ "${TARGET_DB}" == "hospital_db" ]] || fail_demo_restore TARGET_DATABASE_NOT_ALLOWED

    request_id="${DEMO_DUMP_REQUEST_ID:-}"
    authorization_request_id="${DEMO_DUMP_CHATOPS_AUTHORIZATION_REQUEST_ID:-}"
    authorization_id="${DEMO_DUMP_CHATOPS_AUTHORIZATION_ID:-}"
    authorization_scope="${DEMO_DUMP_CHATOPS_AUTHORIZATION_SCOPE:-}"
    expected_sha="${DB_BACKUP_EXPECTED_SHA256:-}"
    expected_instance="${DEMO_DUMP_EXPECTED_DB_INSTANCE_ID:-}"
    expected_private_ip="${DEMO_DUMP_EXPECTED_DB_PRIVATE_IP:-}"
    [[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || fail_demo_restore REQUEST_ID_INVALID
    # These values are injected only by the ChatOps restore executor after it
    # re-reads the protected SQLite approval row and validates the two-admin,
    # request/backup/hash/target-bound authorization.
    [[ "$authorization_request_id" == "$request_id" ]] \
        || fail_demo_restore CHATOPS_AUTHORIZATION_REQUEST_MISMATCH
    [[ "$authorization_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || fail_demo_restore CHATOPS_OVERWRITE_AUTHORIZATION_MISSING
    [[ "$authorization_scope" == "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB" ]] \
        || fail_demo_restore CHATOPS_OVERWRITE_SCOPE_MISMATCH
    [[ "$expected_sha" =~ ^[0-9a-fA-F]{64}$ ]] || fail_demo_restore EXPECTED_CHECKSUM_INVALID
    [[ "$expected_instance" == "AWS_RESOURCE_ID_REDACTED" ]] \
        || fail_demo_restore DR_DATABASE_INSTANCE_ID_MISMATCH
    [[ "$expected_private_ip" == "IP_REDACTED" ]] \
        || fail_demo_restore DR_DATABASE_PRIVATE_IP_MISMATCH
    demo_key="$PASS_PHRASE"
    demo_root_secret="$MYSQL_ROOT_PASS"
    export -n demo_key demo_root_secret 2>/dev/null || true
    unset DB_BACKUP_ENCRYPTION_KEY MYSQL_ROOT_PASS
    [[ -n "$demo_key" && -n "$demo_root_secret" ]] || fail_demo_restore DATABASE_SECRET_UNAVAILABLE

    [[ -n "${DB_BACKUP_FILE:-}" && -f "$DB_BACKUP_FILE" && ! -L "$DB_BACKUP_FILE" ]] \
        || fail_demo_restore SELECTED_BACKUP_UNAVAILABLE
    [[ "$(basename -- "$DB_BACKUP_FILE")" =~ ^db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc$ ]] \
        || fail_demo_restore BACKUP_ID_INVALID
    [[ "$(basename -- "$DB_BACKUP_FILE")" == "${DB_BACKUP_ID:-}" ]] \
        || fail_demo_restore BACKUP_ID_MISMATCH
    [[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || fail_demo_restore BACKUP_DIRECTORY_INVALID

    status_file="${DB_BACKUP_FILE%.sql.gz.enc}.master_status"
    [[ -s "$status_file" && ! -L "$status_file" ]] || fail_demo_restore MASTER_STATUS_MISSING
    expected_status_sha="${DEMO_DUMP_MASTER_STATUS_EXPECTED_SHA256:-}"
    [[ "$expected_status_sha" =~ ^[0-9a-f]{64}$ ]] || fail_demo_restore MASTER_STATUS_CHECKSUM_INVALID
    actual_status_sha="$(sha256sum -- "$status_file" | awk '{print $1}')"
    [[ "$actual_status_sha" == "$expected_status_sha" ]] || fail_demo_restore MASTER_STATUS_CHECKSUM_MISMATCH
    expected_stamp="${DB_BACKUP_ID#db_backup_}"
    expected_stamp="${expected_stamp%.sql.gz.enc}"
    status_stamp="$(awk -F: '/^[[:space:]]*BackupTimestamp[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$status_file" || true)"
    [[ -z "$status_stamp" || "$status_stamp" == "$expected_stamp" ]] \
        || fail_demo_restore MASTER_STATUS_BACKUP_ID_MISMATCH
    status_name="$(awk -F: '/^[[:space:]]*(File|BinlogFile)[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$status_file" || true)"
    status_position="$(awk -F: '/^[[:space:]]*(Position|BinlogPosition)[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$status_file" || true)"
    if [[ -z "$status_name" || -z "$status_position" ]]; then
        status_name="$(grep -Eo "(MASTER_LOG_FILE|SOURCE_LOG_FILE)[[:space:]]*=[[:space:]]*'[^']+'" "$status_file" \
            | sed -E "s/^[^=]+='//; s/'$//" | head -n 1 || true)"
        status_position="$(grep -Eo "(MASTER_LOG_POS|SOURCE_LOG_POS)[[:space:]]*=[[:space:]]*[0-9]+" "$status_file" \
            | sed -E 's/^[^=]+=//' | head -n 1 || true)"
    fi
    [[ "$status_name" =~ ^[A-Za-z0-9._-]+$ && "$status_position" =~ ^[0-9]+$ && "$status_position" -gt 0 ]] \
        || fail_demo_restore MASTER_STATUS_INVALID

    actual_sha="$(sha256sum -- "$DB_BACKUP_FILE" | awk '{print $1}')"
    [[ "${actual_sha,,}" == "${expected_sha,,}" ]] || fail_demo_restore SELECTED_BACKUP_CHECKSUM_MISMATCH

    snapshot_file="${DEMO_DUMP_PRESNAPSHOT_FILE:-}"
    snapshot_sha="${DEMO_DUMP_PRESNAPSHOT_SHA256:-}"
    [[ "$snapshot_file" == "/home/ubuntu/db_backups/pre-restore/$request_id/hospital_db.sql.gz.enc" \
        && -s "$snapshot_file" && ! -L "$snapshot_file" ]] || fail_demo_restore PRESNAPSHOT_UNAVAILABLE
    [[ "$snapshot_sha" =~ ^[0-9a-f]{64}$ ]] || fail_demo_restore PRESNAPSHOT_CHECKSUM_INVALID
    snapshot_actual_sha="$(sha256sum -- "$snapshot_file" | awk '{print $1}')"
    [[ "$snapshot_actual_sha" == "$snapshot_sha" ]] || fail_demo_restore PRESNAPSHOT_CHECKSUM_MISMATCH

    python3 - "$expected_instance" "$expected_private_ip" <<'PY' || fail_demo_restore DR_DATABASE_RUNTIME_IDENTITY_MISMATCH
import sys
import urllib.request

expected_id, expected_ip = sys.argv[1:]
base = "http://IP_REDACTED/latest"
try:
    request = urllib.request.Request(
        f"{base}/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        token = response.read(512).decode("ascii").strip()
    def read(name):
        request = urllib.request.Request(
            f"{base}/meta-data/{name}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.read(512).decode("ascii").strip()
    if read("instance-id") != expected_id or read("local-ipv4") != expected_ip:
        raise ValueError("identity mismatch")
except Exception:
    raise SystemExit(1)
PY

    [[ "$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)" == "tmpfs" ]] \
        || fail_demo_restore SECRET_TMPFS_UNAVAILABLE
    secret_dir="$(mktemp -d /dev/shm/hospital-dr-demo-restore.XXXXXX)" \
        || fail_demo_restore SECRET_TMPFS_UNAVAILABLE
    chmod 0700 "$secret_dir"
    defaults_file="$secret_dir/mysql.cnf"
    key_file="$secret_dir/backup.key"
    work_dir=""
    restore_write_window_open=0
    demo_startup_config_read_only_standby() {
        local config_file=/etc/mysql/mysql.conf.d/zz-hospital-dr-promotion.cnf
        local config_state
        [[ -f "$config_file" && ! -L "$config_file" ]] || return 1
        config_state="$(awk -F= '
          /^[[:space:]]*read_only[[:space:]]*=/ {
            key=$1; value=$2; gsub(/[[:space:]]/, "", key); gsub(/[[:space:]]/, "", value)
            ro=toupper(value); ro_count++
          }
          /^[[:space:]]*super_read_only[[:space:]]*=/ {
            key=$1; value=$2; gsub(/[[:space:]]/, "", key); gsub(/[[:space:]]/, "", value)
            super_ro=toupper(value); super_ro_count++
          }
          END {
            if (ro_count == 1 && super_ro_count == 1) print ro "|" super_ro
            else print "INVALID"
          }' "$config_file")" || return 1
        [[ "$config_state" == "ON|ON" ]]
    }
    demo_assert_durable_read_only_standby() {
        local state
        state="$(mysql --defaults-extra-file="$defaults_file" --batch --skip-column-names -e \
            "SELECT CONCAT(@@global.read_only,'|',@@global.super_read_only,'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='read_only' LIMIT 1),'MISSING'),'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='super_read_only' LIMIT 1),'MISSING'))" 2>/dev/null)" || return 1
        [[ "$state" == "1|1|ON|ON" ]] && return 0
        [[ "$state" == "1|1|MISSING|MISSING" ]] || return 1
        # The controller preflight verifies the effective mysqld startup
        # options and running process. When persisted_variables has no rows,
        # accept that same durable startup-config mode instead of requiring
        # SET PERSIST solely for this executor gate.
        demo_startup_config_read_only_standby
    }
    demo_force_read_only_standby() {
        local state
        mysql --defaults-extra-file="$defaults_file" -e \
            'SET GLOBAL read_only=ON; SET GLOBAL super_read_only=ON' >/dev/null 2>&1 || return 1
        state="$(mysql --defaults-extra-file="$defaults_file" --batch --skip-column-names -e \
            'SELECT CONCAT(@@global.read_only,"|",@@global.super_read_only)' 2>/dev/null)" || return 1
        [[ "$state" == "1|1" ]] || return 1
        demo_assert_durable_read_only_standby || return 1
        restore_write_window_open=0
    }
    demo_stop_mysql_after_refence_failure() {
        local listeners
        command -v systemctl >/dev/null 2>&1 && command -v ss >/dev/null 2>&1 || return 1
        systemctl stop mysql.service >/dev/null 2>&1 \
            || systemctl stop mysqld.service >/dev/null 2>&1 || true
        if systemctl is-active --quiet mysql.service || systemctl is-active --quiet mysqld.service; then
            return 1
        fi
        listeners="$(ss -H -ltn '( sport = :3306 )')" || return 1
        [[ -z "$listeners" ]]
    }
    cleanup_demo_restore() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$restore_write_window_open" == "1" ]]; then
            if ! demo_force_read_only_standby; then
                printf 'DEMO_DB_RESTORE=BLOCKED reason=READ_ONLY_REFENCE_FAILED\n' >&2
                if demo_stop_mysql_after_refence_failure; then
                    printf 'DEMO_DB_RESTORE=DB_SERVICE_STOPPED_AFTER_REFENCE_FAILURE\n' >&2
                else
                    printf 'DEMO_DB_RESTORE=BLOCKED reason=DB_SERVICE_STOP_AFTER_REFENCE_FAILURE_FAILED\n' >&2
                fi
                result=1
            fi
        fi
        [[ -z "$work_dir" ]] || rm -rf -- "$work_dir" || result=1
        rm -f -- "$defaults_file" "$key_file" || result=1
        rmdir -- "$secret_dir" 2>/dev/null || true
        exit "$result"
    }
    trap cleanup_demo_restore EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    escaped_password="$(printf '%s' "$demo_root_secret" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    {
        printf '[client]\nuser=root\npassword="%s"\n' "$escaped_password"
    } > "$defaults_file"
    printf '%s' "$demo_key" > "$key_file"
    chmod 0600 "$defaults_file" "$key_file"
    unset PASS_PHRASE demo_key demo_root_secret

    work_dir="$(mktemp -d "$BACKUP_DIR/.demo-restore-${request_id}.XXXXXX")" \
        || fail_demo_restore RESTORE_TEMP_DIRECTORY_UNAVAILABLE
    chmod 0700 "$work_dir"

    if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$snapshot_file" -pass "file:$key_file" 2>/dev/null \
        | gzip -t >/dev/null 2>&1; then
        fail_demo_restore PRESNAPSHOT_INTEGRITY_CHECK_FAILED
    fi
    if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$DB_BACKUP_FILE" -pass "file:$key_file" 2>/dev/null \
        | gzip -t >/dev/null 2>&1; then
        fail_demo_restore SELECTED_BACKUP_INTEGRITY_CHECK_FAILED
    fi

    demo_assert_durable_read_only_standby || fail_demo_restore DATABASE_NOT_PERSISTENT_READ_ONLY_STANDBY
    # Dump and NR must never apply concurrently. If a channel exists, durably
    # suppress automatic replica-thread startup before opening the restore
    # write window, stop the channel, and read back both thread states.
    replica_status=""
    if ! replica_status="$(mysql --defaults-extra-file="$defaults_file" -e 'SHOW REPLICA STATUS\G' 2>/dev/null)"; then
        replica_status="$(mysql --defaults-extra-file="$defaults_file" -e 'SHOW SLAVE STATUS\G' 2>/dev/null)" \
            || fail_demo_restore REPLICA_STATUS_UNAVAILABLE
    fi
    if [[ -z "$replica_status" ]]; then
        printf 'REPLICA_FENCE|NONE|NONE\n'
    else
        replica_fields="$(printf '%s\n' "$replica_status" | awk -F: '
          /^[[:space:]]*(Replica_IO_Running|Slave_IO_Running):/ { io=$2; gsub(/[[:space:]]/, "", io); io_count++ }
          /^[[:space:]]*(Replica_SQL_Running|Slave_SQL_Running):/ { sql=$2; gsub(/[[:space:]]/, "", sql); sql_count++ }
          END { if (io_count == 1 && sql_count == 1) print io "|" sql; else print "UNKNOWN" }')"
        [[ "$replica_fields" != "UNKNOWN" ]] || fail_demo_restore REPLICA_THREAD_STATE_AMBIGUOUS
        mysql --defaults-extra-file="$defaults_file" -e 'SET PERSIST_ONLY skip_replica_start=ON' \
            >/dev/null 2>&1 || fail_demo_restore REPLICA_AUTOSTART_FENCE_FAILED
        persisted_skip="$(mysql --defaults-extra-file="$defaults_file" --batch --skip-column-names -e \
            "SELECT COALESCE(UPPER(variable_value),'MISSING') FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='skip_replica_start' LIMIT 1" 2>/dev/null)" \
            || fail_demo_restore REPLICA_AUTOSTART_READBACK_FAILED
        [[ "$persisted_skip" == "ON" ]] || fail_demo_restore REPLICA_AUTOSTART_READBACK_FAILED
        if [[ "$replica_fields" == *Yes* ]]; then
            mysql --defaults-extra-file="$defaults_file" -e 'STOP REPLICA' >/dev/null 2>&1 \
                || mysql --defaults-extra-file="$defaults_file" -e 'STOP SLAVE' >/dev/null 2>&1 \
                || fail_demo_restore REPLICA_STOP_FAILED
        fi
        replica_status="$(mysql --defaults-extra-file="$defaults_file" -e 'SHOW REPLICA STATUS\G' 2>/dev/null)" \
            || replica_status="$(mysql --defaults-extra-file="$defaults_file" -e 'SHOW SLAVE STATUS\G' 2>/dev/null)" \
            || fail_demo_restore REPLICA_STATUS_READBACK_FAILED
        replica_fields="$(printf '%s\n' "$replica_status" | awk -F: '
          /^[[:space:]]*(Replica_IO_Running|Slave_IO_Running):/ { io=$2; gsub(/[[:space:]]/, "", io); io_count++ }
          /^[[:space:]]*(Replica_SQL_Running|Slave_SQL_Running):/ { sql=$2; gsub(/[[:space:]]/, "", sql); sql_count++ }
          END { if (io_count == 1 && sql_count == 1) print io "|" sql; else print "UNKNOWN" }')"
        [[ "$replica_fields" == "No|No" ]] || fail_demo_restore REPLICA_THREADS_NOT_STOPPED
        printf 'REPLICA_FENCE|STOPPED|PERSISTED_SKIP_REPLICA_START\n'
    fi
    remote_sessions="$(mysql --defaults-extra-file="$defaults_file" --batch --skip-column-names -e \
        "SELECT COUNT(*) FROM information_schema.processlist WHERE HOST IS NOT NULL AND HOST NOT LIKE 'localhost%' AND HOST NOT LIKE 'IP_REDACTED%'" 2>/dev/null)" \
        || fail_demo_restore DATABASE_SESSION_CHECK_FAILED
    [[ "$remote_sessions" == "0" ]] || fail_demo_restore REMOTE_DATABASE_WRITER_SESSION_PRESENT
    restore_write_window_open=1
    mysql --defaults-extra-file="$defaults_file" -e \
        'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF' >/dev/null 2>&1 \
        || fail_demo_restore DATABASE_WRITE_WINDOW_OPEN_FAILED
    write_state="$(mysql --defaults-extra-file="$defaults_file" --batch --skip-column-names -e \
        'SELECT CONCAT(@@global.read_only,"|",@@global.super_read_only)' 2>/dev/null)" \
        || fail_demo_restore DATABASE_WRITE_WINDOW_STATE_UNVERIFIED
    [[ "$write_state" == "0|0" ]] || fail_demo_restore DATABASE_WRITE_WINDOW_STATE_UNVERIFIED
    mysql --defaults-extra-file="$defaults_file" -e \
        "CREATE DATABASE IF NOT EXISTS hospital_db DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" \
        >/dev/null 2>&1 || fail_demo_restore MYSQL_DATABASE_PREPARE_FAILED
    printf 'DEMO_DB_RESTORE=RESTORE_STARTED request_id=%s backup_id=%s\n' "$request_id" "$(basename -- "$DB_BACKUP_FILE")"
    if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$DB_BACKUP_FILE" -pass "file:$key_file" 2>/dev/null \
        | gzip -dc 2>/dev/null \
        | mysql --defaults-extra-file="$defaults_file" hospital_db >/dev/null 2>&1; then
        fail_demo_restore RESTORE_RESULT_UNCERTAIN
    fi
    demo_force_read_only_standby || fail_demo_restore READ_ONLY_REFENCE_FAILED
    printf 'DEMO_DB_RESTORE=RESTORE_COMMAND_SUCCEEDED request_id=%s\n' "$request_id"
    exit 0
fi

for required_secret in DB_BACKUP_ENCRYPTION_KEY MYSQL_ROOT_PASS; do
  if [ -z "${!required_secret:-}" ]; then
    echo "[CONFIG ERROR] Required environment variable is missing: ${required_secret}"
    echo "[설정 오류] 필수 환경변수가 없습니다: ${required_secret}"
    exit 1
  fi
done

echo "[DR DATABASE] Starting database restore workflow."
echo "[DR 데이터베이스] 데이터베이스 복구 워크플로 시작."

MYSQL_DEFAULTS_FILE=$(mktemp)
cleanup_restore_files() {
    rm -f "$MYSQL_DEFAULTS_FILE" "$BACKUP_DIR/recovery.sql"
}
trap cleanup_restore_files EXIT
chmod 600 "$MYSQL_DEFAULTS_FILE"
{
    printf '[client]\n'
    printf 'user=root\n'
    printf 'password=%s\n' "$MYSQL_ROOT_PASS"
} > "$MYSQL_DEFAULTS_FILE"

# 1. 복구 대상 암호화 백업 파일(.enc) 선택
if [ -n "${DB_BACKUP_FILE:-}" ]; then
    LATEST_BACKUP="$DB_BACKUP_FILE"
else
    LATEST_BACKUP=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.enc' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {print $2}')
fi

if [ -z "$LATEST_BACKUP" ]; then
    echo "[RESTORE ERROR] No encrypted backup artifact was found for recovery."
    echo "[복구 오류] 복구에 사용할 암호화 백업 파일을 찾지 못했습니다."
    exit 1
fi

BACKUP_BASENAME=$(basename -- "$LATEST_BACKUP")
BACKUP_PARENT=$(dirname -- "$LATEST_BACKUP")
case "$BACKUP_BASENAME" in
    *.sql.gz.enc) ;;
    *)
        echo "[RESTORE ERROR] Backup artifact must use the .sql.gz.enc naming contract."
        echo "[복구 오류] 백업 파일은 .sql.gz.enc 명명 규칙을 따라야 합니다."
        exit 1
        ;;
esac
BACKUP_STEM=$(printf '%s' "$BACKUP_BASENAME" | sed 's/\.sql\.gz\.enc$//')
MATCHING_STATUS="$BACKUP_PARENT/$BACKUP_STEM.master_status"
if [ ! -s "$MATCHING_STATUS" ]; then
    echo "[RESTORE ERROR] Matching master_status artifact is missing for the selected backup."
    echo "[복구 오류] 선택한 백업과 일치하는 master_status 파일이 없습니다."
    exit 1
fi

# Validate actual values, not only field-name markers. This keeps malformed
# metadata from reaching a later CHANGE REPLICATION SOURCE command.
status_file_name="$(grep -Eo "(MASTER_LOG_FILE|SOURCE_LOG_FILE)[[:space:]]*=[[:space:]]*'[^']+'" "$MATCHING_STATUS" \
    | sed -E "s/^[^=]+='//; s/'$//" | head -n 1 || true)"
if [ -z "$status_file_name" ]; then
    status_file_name="$(awk -F: '/^[[:space:]]*(File|BinlogFile)[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$MATCHING_STATUS" || true)"
fi
status_position="$(grep -Eo "(MASTER_LOG_POS|SOURCE_LOG_POS)[[:space:]]*=[[:space:]]*[0-9]+" "$MATCHING_STATUS" \
    | sed -E 's/^[^=]+=//' | head -n 1 || true)"
if [ -z "$status_position" ]; then
    status_position="$(awk -F: '/^[[:space:]]*(Position|BinlogPosition)[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$MATCHING_STATUS" || true)"
fi
if [[ ! "$status_file_name" =~ ^[A-Za-z0-9._-]+$ ]] \
    || [[ ! "$status_position" =~ ^[0-9]+$ ]]; then
    echo "[RESTORE ERROR] Matching master_status artifact has no usable file/position pair."
    echo "[복구 오류] 일치하는 master_status 파일에 사용할 수 있는 File/Position 쌍이 없습니다."
    exit 1
fi

echo "[DR DATABASE] Selected backup artifact: $LATEST_BACKUP"
echo "[DR 데이터베이스] 선택된 백업 파일: $LATEST_BACKUP"

# 2. 암호화 해제 (백업 시 사용한 -aes-256-cbc -salt -pbkdf2 방식 대응)
echo "[1/3] Decrypting backup artifact..."
echo "[1/3] 백업 파일 복호화 중."
openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$LATEST_BACKUP" -out "$BACKUP_DIR/recovery.sql.gz" -k "$PASS_PHRASE"
gzip -t "$BACKUP_DIR/recovery.sql.gz"

# 3. 압축 해제 (.gz -> .sql)
echo "[2/3] Decompressing backup payload..."
echo "[2/3] 백업 페이로드 압축 해제 중."
gunzip -f "$BACKUP_DIR/recovery.sql.gz"
test -s "$BACKUP_DIR/recovery.sql"

MASTER_DATA_LINE=$(grep -m1 -E "CHANGE MASTER TO|CHANGE REPLICATION SOURCE TO" "$BACKUP_DIR/recovery.sql" || true)
if [ -n "$MASTER_DATA_LINE" ]; then
    echo "[DR DATABASE] Capturing replication coordinates from dump metadata."
    echo "[DR 데이터베이스] dump 메타데이터에서 replication 좌표를 기록합니다."
    printf '%s\n' "$MASTER_DATA_LINE" > "$BACKUP_DIR/recovery.master_status"
fi

# 4. 데이터 입력 (MySQL)
echo "[3/3] Restoring database into the DR MySQL instance..."
echo "[3/3] DR MySQL 인스턴스로 데이터베이스 복구 중."
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}'; FLUSH PRIVILEGES;" 2>/dev/null || true
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -e "CREATE DATABASE IF NOT EXISTS $TARGET_DB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" "$TARGET_DB" < "$BACKUP_DIR/recovery.sql"

echo "[DR DATABASE] Database restore workflow completed successfully."
echo "[DR 데이터베이스] 데이터베이스 복구 워크플로 완료."
