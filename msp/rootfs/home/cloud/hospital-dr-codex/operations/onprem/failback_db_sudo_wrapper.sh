#!/usr/bin/env bash
set -euo pipefail

# Root-owned, narrowly scoped On-Prem MySQL helper for the approved Failback
# executor. This command is intended to be installed at
# /usr/local/sbin/hospital-dr-failback-db and invoked only through sudo.
#
# The database and server identity are pinned to the existing On-Prem target.
# No database name, SQL, executable, or filesystem path is accepted from the
# caller. The controller enforces the request-bound two-admin approval before
# invoking any mutating action.

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
export MYSQL_HISTFILE=/dev/null
umask 077

readonly EXPECTED_HOSTNAME="hoseo-VirtualBox"
readonly EXPECTED_SERVER_UUID="d4ea304e-269f-11f1-b866-08002794ce78"
readonly EXPECTED_PORT="3306"
readonly DATABASE="hospital_db"
readonly STAGE_ROOT="/home/hoseo/.cache/hospital-dr-failback"
readonly BACKUP_ROOT="/home/hoseo/db_backups"
readonly RUNTIME_ROOT="/run/hospital-dr-failback"
readonly LOCK_FILE="/run/lock/hospital-dr-failback-db.lock"

die() {
  printf 'FAILBACK_DB_WRAPPER=BLOCKED reason=%s\n' "$1" >&2
  exit 1
}

valid_request_id() {
  [[ "${1:-}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

mysql_query() {
  /usr/bin/mysql --no-defaults --protocol=socket --batch --raw --skip-column-names -e "$1"
}

mysql_identity() {
  mysql_query 'SELECT @@server_uuid,@@hostname,@@port,@@global.read_only,@@global.super_read_only,VERSION()'
}

validate_identity() {
  local identity uuid hostname port read_only super_read_only version
  identity="$(mysql_identity)" || die MYSQL_SOCKET_AUTH_FAILED
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  [[ "$uuid" == "$EXPECTED_SERVER_UUID" ]] || die MYSQL_SERVER_UUID_MISMATCH
  [[ "$hostname" == "$EXPECTED_HOSTNAME" ]] || die MYSQL_HOSTNAME_MISMATCH
  [[ "$port" == "$EXPECTED_PORT" ]] || die MYSQL_PORT_MISMATCH
  [[ "$version" == 8.* ]] || die MYSQL_VERSION_UNSUPPORTED
  [[ -n "$read_only" && -n "$super_read_only" ]] || die MYSQL_ROLE_READBACK_INVALID
  printf '%s\n' "$identity"
}

validate_request_and_identity() {
  valid_request_id "${1:-}" || die REQUEST_ID_INVALID
  validate_identity
}

table_counts() {
  local tables table escaped count
  tables="$(mysql_query "SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA='${DATABASE}' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")" \
    || die TABLE_LIST_QUERY_FAILED
  [[ -n "$tables" ]] || die HOSPITAL_DB_HAS_NO_TABLES
  while IFS= read -r table; do
    [[ -n "$table" ]] || continue
    escaped="${table//\`/\`\`}"
    count="$(mysql_query "SELECT COUNT(*) FROM \`${DATABASE}\`.\`${escaped}\`")" || die TABLE_COUNT_QUERY_FAILED
    [[ "$count" =~ ^[0-9]+$ ]] || die TABLE_COUNT_INVALID
    printf '%s\t%s\n' "$table" "$count"
  done <<< "$tables"
}

acquire_lock() {
  exec 9>"$LOCK_FILE"
  flock -n 9 || die FAILBACK_DB_OPERATION_ALREADY_RUNNING
}

check_only() {
  local identity uuid hostname port read_only super_read_only version
  for executable in /usr/bin/mysql /usr/bin/mysqldump /usr/bin/gzip /usr/bin/sha256sum /usr/bin/flock; do
    [[ -x "$executable" ]] || die REQUIRED_TOOL_MISSING
  done
  [[ "$(/usr/bin/hostname)" == "$EXPECTED_HOSTNAME" ]] || die SYSTEM_HOSTNAME_MISMATCH
  [[ -d "$BACKUP_ROOT" && ! -L "$BACKUP_ROOT" ]] || die EXISTING_BACKUP_DIRECTORY_MISSING
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  mysql_query "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${DATABASE}'" | grep -qx '1' \
    || die HOSPITAL_DB_MISSING
  printf 'FAILBACK_DB_WRAPPER_CHECK=PASS mysql=%s\n' "$version"
}

make_prebackup() {
  local request_id="$1" identity uuid hostname port read_only super_read_only version
  local destination temporary checksum
  valid_request_id "$request_id" || die REQUEST_ID_INVALID
  acquire_lock
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  [[ -d "$BACKUP_ROOT" && ! -L "$BACKUP_ROOT" ]] || die EXISTING_BACKUP_DIRECTORY_MISSING
  destination="${BACKUP_ROOT}/onprem-${DATABASE}-failback-${request_id}.sql.gz"
  [[ ! -e "$destination" && ! -L "$destination" ]] || die REQUEST_BACKUP_ALREADY_EXISTS
  temporary="$(/usr/bin/mktemp "${BACKUP_ROOT}/.hospital-db-failback-${request_id}.XXXXXX")" || die BACKUP_TEMP_CREATE_FAILED
  trap '/usr/bin/rm -f -- "${temporary:-}"' EXIT
  if ! /usr/bin/mysqldump --no-defaults --protocol=socket --single-transaction --routines --triggers --events \
      --hex-blob --quick --add-drop-table "$DATABASE" 2>/dev/null | /usr/bin/gzip -1 > "$temporary"; then
    die ONPREM_PREBACKUP_FAILED
  fi
  /usr/bin/gzip -t "$temporary" || die ONPREM_PREBACKUP_GZIP_INVALID
  [[ -s "$temporary" ]] || die ONPREM_PREBACKUP_EMPTY
  checksum="$(/usr/bin/sha256sum "$temporary" | /usr/bin/awk '{print $1}')"
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die ONPREM_PREBACKUP_HASH_INVALID
  /usr/bin/chmod 0600 "$temporary"
  /usr/bin/mv -- "$temporary" "$destination" || die ONPREM_PREBACKUP_PUBLISH_FAILED
  trap - EXIT
  printf 'ONPREM_PREBACKUP=PASS sha256=%s\n' "$checksum"
}

restore_dump() {
  local request_id="$1" expected_sha256="$2" confirmation="$3"
  local identity uuid hostname port read_only super_read_only version
  local stage_file safe_file actual_sha256 error_file flags
  valid_request_id "$request_id" || die REQUEST_ID_INVALID
  [[ "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || die DUMP_SHA256_INVALID
  [[ "$confirmation" == "OVERWRITE_ONPREM_DB" ]] || die REQUEST_SCOPED_OVERWRITE_CONFIRMATION_MISSING
  acquire_lock
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  stage_file="${STAGE_ROOT}/${request_id}/hospital_db.sql.gz"
  [[ -f "$stage_file" && ! -L "$stage_file" ]] || die REQUEST_DUMP_MISSING
  [[ "$(/usr/bin/stat -c '%U' "$stage_file")" == "hoseo" ]] || die REQUEST_DUMP_OWNER_INVALID
  [[ "$(/usr/bin/stat -c '%a' "$stage_file")" == "600" ]] || die REQUEST_DUMP_MODE_INVALID
  /usr/bin/install -d -o root -g root -m 0700 "$RUNTIME_ROOT" || die ROOT_STAGE_CREATE_FAILED
  safe_file="$(/usr/bin/mktemp "${RUNTIME_ROOT}/restore-${request_id}.XXXXXX.sql.gz")" || die ROOT_STAGE_CREATE_FAILED
  error_file="$(/usr/bin/mktemp "${RUNTIME_ROOT}/mysql-${request_id}.XXXXXX.err")" || die ROOT_STAGE_CREATE_FAILED
  trap '/usr/bin/rm -f -- "${safe_file:-}" "${error_file:-}"' EXIT
  /usr/bin/cp -- "$stage_file" "$safe_file" || die REQUEST_DUMP_STAGE_FAILED
  /usr/bin/chmod 0600 "$safe_file"
  actual_sha256="$(/usr/bin/sha256sum "$safe_file" | /usr/bin/awk '{print $1}')"
  [[ "${actual_sha256,,}" == "${expected_sha256,,}" ]] || die REQUEST_DUMP_SHA256_MISMATCH
  /usr/bin/gzip -t "$safe_file" || die REQUEST_DUMP_GZIP_INVALID
  trap 'mysql_query "SET PERSIST super_read_only=ON; SET PERSIST read_only=ON; SET GLOBAL super_read_only=ON; SET GLOBAL read_only=ON" >/dev/null 2>&1 || true; /usr/bin/rm -f -- "${safe_file:-}" "${error_file:-}"' EXIT
  # Keep ordinary application sessions read-only while the approved root
  # import runs. This makes the post-restore master position a stable NR
  # baseline; the source is opened only after the DR replica is attached.
  mysql_query 'SET PERSIST super_read_only=OFF; SET PERSIST read_only=ON; SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=ON' >/dev/null \
    || die ONPREM_DB_RESTORE_ACCESS_PREPARE_FAILED
  if ! /usr/bin/gzip -dc "$safe_file" | /usr/bin/mysql --no-defaults --protocol=socket --batch --raw "$DATABASE" >/dev/null 2>"$error_file"; then
    die MYSQL_RESTORE_FAILED
  fi
  mysql_query 'SET PERSIST super_read_only=ON; SET PERSIST read_only=ON; SET GLOBAL super_read_only=ON; SET GLOBAL read_only=ON' >/dev/null \
    || die ONPREM_DB_NR_BASELINE_READ_ONLY_FAILED
  flags="$(mysql_query 'SELECT @@global.read_only,@@global.super_read_only')" \
    || die ONPREM_DB_NR_BASELINE_READ_ONLY_READBACK_FAILED
  [[ "$flags" == $'1\t1' ]] || die ONPREM_DB_NR_BASELINE_READ_ONLY_READBACK_FAILED
  /usr/bin/rm -f -- "$stage_file"
  trap - EXIT
  printf 'ONPREM_DB_RESTORE=PASS sha256=%s\n' "${actual_sha256,,}"
}

nr_coordinate() {
  local request_id="$1" identity uuid hostname port read_only super_read_only version
  local status log_file log_position server_id
  valid_request_id "$request_id" || die REQUEST_ID_INVALID
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  [[ "$read_only" == "1" && "$super_read_only" == "1" ]] \
    || die ONPREM_DB_NOT_READ_ONLY_FOR_NR_BASELINE
  server_id="$(mysql_query 'SELECT @@global.server_id')" || die ONPREM_DB_SERVER_ID_QUERY_FAILED
  [[ "$server_id" =~ ^[1-9][0-9]*$ ]] || die ONPREM_DB_SERVER_ID_INVALID
  status="$(mysql_query 'SHOW MASTER STATUS')" || die ONPREM_DB_MASTER_STATUS_QUERY_FAILED
  IFS=$'\t' read -r log_file log_position _ <<< "$status"
  [[ "$log_file" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || die ONPREM_DB_BINLOG_FILE_INVALID
  [[ "$log_position" =~ ^[1-9][0-9]{0,19}$ ]] || die ONPREM_DB_BINLOG_POSITION_INVALID
  printf '%s\t%s\t%s\n' "$uuid" "$log_file" "$log_position"
}

nr_baseline_hold() {
  local request_id="$1" flags
  valid_request_id "$request_id" || die REQUEST_ID_INVALID
  acquire_lock
  validate_identity >/dev/null
  mysql_query 'SET PERSIST super_read_only=ON; SET PERSIST read_only=ON; SET GLOBAL super_read_only=ON; SET GLOBAL read_only=ON' \
    >/dev/null || die ONPREM_DB_NR_BASELINE_HOLD_FAILED
  flags="$(mysql_query 'SELECT @@global.read_only,@@global.super_read_only')" \
    || die ONPREM_DB_NR_BASELINE_HOLD_READBACK_FAILED
  [[ "$flags" == $'1\t1' ]] || die ONPREM_DB_NR_BASELINE_HOLD_READBACK_FAILED
  printf 'ONPREM_DB_NR_BASELINE_HOLD=PASS\n'
}

promote_after_verification() {
  local request_id="$1" expected_counts_sha256="$2"
  local identity uuid hostname port read_only super_read_only version counts actual_hash
  valid_request_id "$request_id" || die REQUEST_ID_INVALID
  [[ "$expected_counts_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || die EXPECTED_TABLE_COUNTS_HASH_INVALID
  acquire_lock
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  counts="$(table_counts)" || die POST_RESTORE_TABLE_COUNTS_FAILED
  actual_hash="$(printf '%s' "$counts" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
  [[ "${actual_hash,,}" == "${expected_counts_sha256,,}" ]] || die POST_RESTORE_TABLE_COUNTS_MISMATCH
  mysql_query 'SET PERSIST read_only=OFF; SET PERSIST super_read_only=OFF' >/dev/null || die ONPREM_DB_PROMOTION_FAILED
  identity="$(validate_identity)"
  IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
  [[ "$read_only" == "0" && "$super_read_only" == "0" ]] || die ONPREM_DB_PROMOTION_READBACK_FAILED
  printf 'ONPREM_DB_PROMOTION=PASS counts_sha256=%s\n' "${actual_hash,,}"
}

case "${1:-}" in
  --check)
    [[ "$#" -eq 1 ]] || die ARGUMENTS_INVALID
    check_only
    ;;
  --identity)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    validate_request_and_identity "$2"
    ;;
  --flags)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    valid_request_id "$2" || die REQUEST_ID_INVALID
    identity="$(validate_identity)"
    IFS=$'\t' read -r uuid hostname port read_only super_read_only version <<< "$identity"
    printf '%s\t%s\n' "$read_only" "$super_read_only"
    ;;
  --nr-coordinate)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    nr_coordinate "$2"
    ;;
  --nr-baseline-hold)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    nr_baseline_hold "$2"
    ;;
  --counts)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    validate_request_and_identity "$2" >/dev/null
    table_counts
    ;;
  --backup)
    [[ "$#" -eq 2 ]] || die ARGUMENTS_INVALID
    make_prebackup "$2"
    ;;
  --restore)
    [[ "$#" -eq 4 ]] || die ARGUMENTS_INVALID
    restore_dump "$2" "$3" "$4"
    ;;
  --promote)
    [[ "$#" -eq 3 ]] || die ARGUMENTS_INVALID
    promote_after_verification "$2" "$3"
    ;;
  *)
    die ACTION_NOT_ALLOWED
    ;;
esac
