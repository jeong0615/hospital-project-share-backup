#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/db_failback.log}"
mkdir -p "$(dirname -- "$LOG_FILE")"
SECRET_FILE="$DR_SECRET_FILE"
CHATOPS_DB_FAILBACK_CONFIRM="${DB_FAILBACK_CONFIRM-}"
CHATOPS_DB_FAILBACK_CONFIRM_SET="${DB_FAILBACK_CONFIRM+x}"
CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID="${DB_FAILBACK_CONFIRM_REQUEST_ID-}"
CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID_SET="${DB_FAILBACK_CONFIRM_REQUEST_ID+x}"
dr_load_secret_file || exit 1
if [ "$CHATOPS_DB_FAILBACK_CONFIRM_SET" = "x" ]; then
  DB_FAILBACK_CONFIRM="$CHATOPS_DB_FAILBACK_CONFIRM"
else
  unset DB_FAILBACK_CONFIRM
fi
if [ "$CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID_SET" = "x" ]; then
  DB_FAILBACK_CONFIRM_REQUEST_ID="$CHATOPS_DB_FAILBACK_CONFIRM_REQUEST_ID"
else
  unset DB_FAILBACK_CONFIRM_REQUEST_ID
fi
dr_resolve_ssh_key_config || exit 1

require_secret() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required secret: ${name}. Set it in ${SECRET_FILE}."
    exit 1
  fi
}

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: ${name}."
    exit 1
  fi
}

INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
DB_NAME="${DB_NAME:-hospital_db}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-}"
ONPREM_DB_HOST="${ONPREM_DB_HOST:-}"
# Keep the On-Prem SSH target (ONPREM_DB_HOST) separate from the MySQL path:
# the DR DB reaches MySQL through the existing WireGuard endpoint.
ONPREM_DB_TCP_HOST="IP_REDACTED"
ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
DB_REPL_USER="${DB_REPL_USER:-}"
DB_REPL_PASSWORD="${DB_REPL_PASSWORD:-}"
ONPREM_DB_SSH_USER="${ONPREM_DB_SSH_USER:-hoseo}"
ONPREM_SSH_KEY="${ONPREM_SSH_KEY:-}"
ONPREM_SSH_KNOWN_HOSTS_FILE="${ONPREM_SSH_KNOWN_HOSTS_FILE:-${HOME:-/home/cloud}/.ssh/known_hosts}"
ONPREM_FAILBACK_DB_WRAPPER="/usr/local/sbin/hospital-dr-failback-db"
ONPREM_DB_SERVER_UUID_EXPECTED="${ONPREM_DB_SERVER_UUID_EXPECTED:-}"
ONPREM_DB_HOSTNAME_EXPECTED="${ONPREM_DB_HOSTNAME_EXPECTED:-}"
CONFIRM="${DB_FAILBACK_CONFIRM:-}"
CONFIRM_REQUEST_ID="${DB_FAILBACK_CONFIRM_REQUEST_ID:-}"
SSH_KEY="${SSH_KEY:-${DR_SSH_PRIVATE_KEY:-${DR_SSH_KEY:-}}}"
DR_DB_HOST="${DR_DB_HOST:-IP_REDACTED}"
DR_FAILBACK_REQUEST_ID="${DB_FAILBACK_CONFIRM_REQUEST_ID:-${DR_FAILOVER_REQUEST_ID:-$(date -u +%Y%m%dT%H%M%SZ)}}"
DR_FAILBACK_REQUEST_ID="$(printf '%s' "$DR_FAILBACK_REQUEST_ID" | tr -cd 'A-Za-z0-9-')"
DR_DUMP_FILE="${DR_DUMP_FILE:-/tmp/${DB_NAME}_failback_${DR_FAILBACK_REQUEST_ID}.sql.gz}"
REGION="${AWS_REGION:-ap-northeast-2}"
ONPREM_DB_CONNECT_ATTEMPTS="${ONPREM_DB_CONNECT_ATTEMPTS:-12}"
ONPREM_DB_CONNECT_SLEEP="${ONPREM_DB_CONNECT_SLEEP:-5}"
DR_WEB_INSTANCE_ID="${DR_WEB_INSTANCE_ID:-AWS_RESOURCE_ID_REDACTED}"
DR_EMR_INSTANCE_ID="${DR_EMR_INSTANCE_ID:-AWS_RESOURCE_ID_REDACTED}"
DR_DB_INSTANCE_ID="${DR_DB_INSTANCE_ID:-AWS_RESOURCE_ID_REDACTED}"
DR_DB_WRITER_FENCED=0
FAILBACK_COMPLETED=0

export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$DR_ANSIBLE_DIR/ansible.cfg}"
export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/ansible-local}"
export ANSIBLE_REMOTE_TEMP="${ANSIBLE_REMOTE_TEMP:-/tmp/ansible-remote}"
export ANSIBLE_SSH_CONTROL_PATH_DIR="${ANSIBLE_SSH_CONTROL_PATH_DIR:-/tmp/ansible-cp}"
export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"
export ANSIBLE_DEPRECATION_WARNINGS="${ANSIBLE_DEPRECATION_WARNINGS:-False}"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore}"
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

if [ -r "$DR_TIMING_SCRIPT" ]; then
  # shellcheck disable=SC1091
  source "$DR_TIMING_SCRIPT"
else
  dr_timing_start() { printf '0\n'; }
  dr_timing_end() { :; }
fi

exec > >(tee -a "$LOG_FILE") 2>&1
db_failback_timing_start="$(dr_timing_start db_failback_internal)"

require_secret "MYSQL_ROOT_PASS"
require_secret "DB_REPL_PASSWORD"
require_config "ONPREM_DB_HOST"
require_config "DB_REPL_USER"
require_config "SSH_KEY"
require_config "ONPREM_SSH_KEY"
require_config "ONPREM_SSH_KNOWN_HOSTS_FILE"
if [[ ! "$ONPREM_DB_SSH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "[DB FAILBACK BLOCKED] On-Prem SSH user or fixed wrapper path is invalid."
  exit 1
fi
if [[ ! "$DB_REPL_USER" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]; then
  echo "[DB FAILBACK BLOCKED] Existing NR replication user contains unsupported characters."
  exit 1
fi
if (( ${#DB_REPL_PASSWORD} > 32 )); then
  echo "[DB FAILBACK BLOCKED] Existing MySQL replication password exceeds the server's 32-character limit."
  exit 1
fi
if [ ! -r "$ONPREM_SSH_KEY" ] || [ -L "$ONPREM_SSH_KEY" ] \
    || [ ! -r "$ONPREM_SSH_KNOWN_HOSTS_FILE" ] || [ -L "$ONPREM_SSH_KNOWN_HOSTS_FILE" ]; then
  echo "[DB FAILBACK BLOCKED] Existing On-Prem SSH key or known-hosts file is unavailable."
  exit 1
fi

aws_instance_state() {
  local instance_id="$1"
  aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text
}

aws_instance_name() {
  local instance_id="$1"
  aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].Tags[?Key==`Name`]|[0].Value' \
    --output text
}

refresh_inventory_for_failback() {
  local temporary ssh_common
  temporary=$(mktemp)
  ssh_common="-F ${DR_SSH_CONFIG_FILE}"
  {
    echo "[web_servers]"
    echo "dr-web ansible_connection=ssh ansible_host=dr-web ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_common}'"
    echo
    echo "[doc_servers]"
    echo "dr-doc ansible_connection=ssh ansible_host=dr-doc ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_common}'"
    echo
    echo "[db_servers]"
    echo "dr-db ansible_connection=ssh ansible_host=dr-db ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_common}'"
  } > "$temporary"
  install -m 0644 "$temporary" "$INVENTORY"
  rm -f "$temporary"
}

wait_for_dr_ssh() {
  local alias label attempt
  for alias in dr-web dr-db; do
    label="DR ${alias#dr-} SSM SSH"
    echo "[DB FAILBACK] Waiting for SSH readiness through the existing SSM target: ${label}"
    for attempt in $(seq 1 30); do
      if ssh -F "$DR_SSH_CONFIG_FILE" -o ConnectTimeout=10 "$alias" true >/dev/null 2>&1; then
        echo "[DB FAILBACK] SSH ready through SSM: ${label}"
        break
      fi
      if [ "$attempt" -eq 30 ]; then
        echo "[DB FAILBACK ERROR] Existing SSM SSH target is unavailable: ${label}"
        return 1
      fi
      echo "[DB FAILBACK] SSM SSH not ready yet (${attempt}/30): ${label}"
      sleep 10
    done
  done
}

ansible_db_shell() {
  ansible -i "$INVENTORY" db_servers -m shell -a "$1"
}

ensure_onprem_db_tcp_for_failback() {
  local attempt

  echo "[DB FAILBACK] Validating TCP connectivity from DR DB to the On-Prem WireGuard endpoint."

  for attempt in $(seq 1 "$ONPREM_DB_CONNECT_ATTEMPTS"); do
    if ansible_db_shell "nc -vz -w 5 ${ONPREM_DB_TCP_HOST} ${ONPREM_DB_PORT}" >/dev/null 2>&1; then
      echo "[DB FAILBACK] DR DB can reach on-premises DB: ${ONPREM_DB_TCP_HOST}:${ONPREM_DB_PORT}"
      return 0
    fi

    echo "[DB FAILBACK] Waiting for DR DB to on-premises DB TCP connectivity (${attempt}/${ONPREM_DB_CONNECT_ATTEMPTS})."
    sleep "$ONPREM_DB_CONNECT_SLEEP"
  done

  echo "[DB FAILBACK BLOCKED] DR DB cannot reach the on-premises DB over direct TCP."
  echo "[REQUIRED ACTION] Restore the existing DR DB route/firewall path to the configured On-Prem MySQL endpoint."
  ansible_db_shell "ip route get ${ONPREM_DB_TCP_HOST} || true; nc -vz -w 5 ${ONPREM_DB_TCP_HOST} ${ONPREM_DB_PORT} || true" || true
  exit 1
}

ensure_dr_compute_for_failback() {
  if ! command -v aws >/dev/null 2>&1 || ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[DB FAILBACK BLOCKED] AWS read-only identity/state checks are unavailable."
    exit 1
  fi

  local web_state emr_state db_state
  [ "$(aws_instance_name "$DR_WEB_INSTANCE_ID")" = "Hospital-Real-Web-Server" ] || {
    echo "[DB FAILBACK BLOCKED] The configured existing Web instance identity did not match."
    exit 1
  }
  [ "$(aws_instance_name "$DR_EMR_INSTANCE_ID")" = "Hospital-DR-Doc-Server" ] || {
    echo "[DB FAILBACK BLOCKED] The configured existing EMR instance identity did not match."
    exit 1
  }
  [ "$(aws_instance_name "$DR_DB_INSTANCE_ID")" = "Hospital-DR-DB-Server" ] || {
    echo "[DB FAILBACK BLOCKED] The configured existing DB instance identity did not match."
    exit 1
  }

  web_state=$(aws_instance_state "$DR_WEB_INSTANCE_ID")
  emr_state=$(aws_instance_state "$DR_EMR_INSTANCE_ID")
  db_state=$(aws_instance_state "$DR_DB_INSTANCE_ID")
  if [ "$web_state" != "running" ] || [ "$emr_state" != "running" ] || [ "$db_state" != "running" ]; then
    echo "[DB FAILBACK BLOCKED] All three existing DR EC2 instances must already be running; Failback never changes EC2 lifecycle."
    exit 1
  fi

  echo "[DB FAILBACK] Preparing existing SSM SSH targets for DR Web and DB."
  refresh_inventory_for_failback
  wait_for_dr_ssh
  ensure_onprem_db_tcp_for_failback
}

echo "=================================================="
echo "[$(date)] DB failback to on-premises started."
echo "=================================================="

if [[ "$DB_NAME" != "hospital_db" ]]; then
  echo "[DB FAILBACK BLOCKED] The restricted On-Prem wrapper only permits hospital_db."
  exit 1
fi
if [ -z "$DR_FAILBACK_REQUEST_ID" ]; then
  DR_FAILBACK_REQUEST_ID="$(date -u +%Y%m%dT%H%M%SZ)"
  DR_DUMP_FILE="/tmp/${DB_NAME}_failback_${DR_FAILBACK_REQUEST_ID}.sql.gz"
fi
if [[ ! "$ONPREM_DB_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] \
    || [[ ! "$ONPREM_DB_TCP_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] \
    || [[ ! "$ONPREM_DB_PORT" =~ ^[0-9]{1,5}$ ]] \
    || [ "$ONPREM_DB_PORT" -lt 1 ] || [ "$ONPREM_DB_PORT" -gt 65535 ]; then
  echo "[DB FAILBACK BLOCKED] On-Prem MySQL host/port is not a valid endpoint."
  exit 1
fi
if [[ ! "$DR_DUMP_FILE" =~ ^/tmp/[A-Za-z0-9_-]+\.sql\.gz$ ]]; then
  echo "[DB FAILBACK BLOCKED] The temporary DR dump path is invalid."
  exit 1
fi
if [[ ! "$ONPREM_DB_SERVER_UUID_EXPECTED" =~ ^[0-9A-Fa-f-]{36}$ ]]; then
  echo "[DB FAILBACK BLOCKED] The approved On-Prem MySQL server UUID pin is missing or invalid."
  exit 1
fi

connectivity_timing_start="$(dr_timing_start db_connectivity)"
ensure_dr_compute_for_failback
dr_timing_end db_connectivity "$connectivity_timing_start"

REMOTE_SSH=(
  ssh
  -F "$DR_SSH_CONFIG_FILE"
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=12
  -o ConnectTimeout=15
  dr-db
)

DR_MYSQL_DEFAULTS_FILE="/tmp/dr-db-root-defaults-${DR_FAILBACK_REQUEST_ID}"
DR_REPL_DEFAULTS_FILE="/tmp/dr-db-repl-defaults-${DR_FAILBACK_REQUEST_ID}"

mysql_option_value() {
  local value="$1"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "[DB FAILBACK BLOCKED] MySQL option values must be single-line."
    return 1
  fi
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

remote_bash() {
  local script="$1" quoted
  printf -v quoted '%q' "$script"
  "${REMOTE_SSH[@]}" "bash -c ${quoted}"
}

remote_mysql() {
  local defaults_file="$1" sql="$2" quoted
  printf -v quoted '%q' "$sql"
  "${REMOTE_SSH[@]}" "mysql --defaults-extra-file='${defaults_file}' --batch --raw --skip-column-names -e ${quoted}"
}

remote_mysql_vertical() {
  local defaults_file="$1" sql="$2" quoted
  printf -v quoted '%q' "$sql"
  "${REMOTE_SSH[@]}" "mysql --defaults-extra-file='${defaults_file}' --vertical --raw -e ${quoted}"
}

remote_mysql_stdin() {
  local defaults_file="$1"
  "${REMOTE_SSH[@]}" "mysql --defaults-extra-file='${defaults_file}' --batch --raw"
}

onprem_ssh() {
  local remote_command="$1"
  ssh -i "$ONPREM_SSH_KEY" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=${ONPREM_SSH_KNOWN_HOSTS_FILE}" \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=10 \
    -o ServerAliveCountMax=3 \
    "${ONPREM_DB_SSH_USER}@${ONPREM_DB_HOST}" "$remote_command"
}

onprem_wrapper() {
  local argument quoted remote_command
  remote_command="sudo -n ${ONPREM_FAILBACK_DB_WRAPPER}"
  for argument in "$@"; do
    printf -v quoted '%q' "$argument"
    remote_command+=" ${quoted}"
  done
  onprem_ssh "$remote_command"
}

onprem_table_counts() {
  onprem_wrapper --counts "$DR_FAILBACK_REQUEST_ID"
}

stage_dr_dump_onprem() {
  local request_id="$1" stage_dir remote_command quoted
  stage_dir="/home/${ONPREM_DB_SSH_USER}/.cache/hospital-dr-failback/${request_id}"
  printf -v quoted '%q' "$stage_dir"
  remote_command="set -euo pipefail; umask 077; mkdir -p -- ${quoted}; chmod 0700 -- ${quoted}; test ! -e ${quoted}/hospital_db.sql.gz; cat > ${quoted}/hospital_db.sql.gz.part; chmod 0600 -- ${quoted}/hospital_db.sql.gz.part; mv -- ${quoted}/hospital_db.sql.gz.part ${quoted}/hospital_db.sql.gz"
  echo "[DB FAILBACK] Streaming the verified DR export to the existing On-Prem host over SSH."
  remote_bash "cat '${DR_DUMP_FILE}'" | onprem_ssh "$remote_command"
}

cleanup_onprem_stage() {
  local request_id="$1" stage_dir quoted
  [[ "$request_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || return 0
  stage_dir="/home/${ONPREM_DB_SSH_USER}/.cache/hospital-dr-failback/${request_id}"
  printf -v quoted '%q' "$stage_dir"
  onprem_ssh "rm -f -- ${quoted}/hospital_db.sql.gz ${quoted}/hospital_db.sql.gz.part; rmdir -- ${quoted} 2>/dev/null || true" \
    >/dev/null 2>&1 || true
}

remote_table_counts() {
  local defaults_file="$1"
  "${REMOTE_SSH[@]}" "bash -s -- '${DB_NAME}' '${defaults_file}'" <<'REMOTE_COUNTS'
set -euo pipefail
database="$1"
defaults_file="$2"
tables="$(mysql --defaults-extra-file="$defaults_file" --batch --raw --skip-column-names \
  -e "SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA='${database}' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")"
[ -n "$tables" ] || exit 1
while IFS= read -r table; do
  escaped_table="${table//\`/\`\`}"
  count="$(mysql --defaults-extra-file="$defaults_file" --batch --raw --skip-column-names \
    "$database" -e "SELECT COUNT(*) FROM \`$escaped_table\`")"
  [[ "$count" =~ ^[0-9]+$ ]] || exit 1
  printf '%s\t%s\n' "$table" "$count"
done <<< "$tables"
REMOTE_COUNTS
}

write_remote_defaults() {
  local destination="$1" username="$2" password="$3" host="${4:-}" port="${5:-}"
  {
    printf '[client]\nuser=%s\npassword=%s\n' \
      "$(mysql_option_value "$username")" "$(mysql_option_value "$password")"
    if [ -n "$host" ]; then
      printf 'host=%s\nport=%s\nprotocol=TCP\n' \
        "$(mysql_option_value "$host")" "$(mysql_option_value "$port")"
    else
      printf 'protocol=socket\n'
    fi
  } | "${REMOTE_SSH[@]}" "umask 077; cat > '${destination}'; chmod 600 '${destination}'"
}

restore_dr_primary() {
  echo "[DB FAILBACK RECOVERY BLOCKED] Automatic DR writer restoration is disabled while On-Prem may remain writable; operator review is required."
  return 1
}

cleanup_failback() {
  local rc=$?
  trap - EXIT
  if [ "$RECOVERY_ONLY" != "1" ] && [ "$FAILBACK_COMPLETED" != "1" ] \
      && [ "$DR_DB_WRITER_FENCED" = "1" ]; then
      echo "[DB FAILBACK PARTIAL_FAILURE] DR remains read-only; On-Prem may remain writable. Operator review is required before changing either writer role."
  fi
  cleanup_onprem_stage "$DR_FAILBACK_REQUEST_ID"
  "${REMOTE_SSH[@]}" "rm -f '${DR_MYSQL_DEFAULTS_FILE}' '${DR_REPL_DEFAULTS_FILE}' '${DR_DUMP_FILE}'" \
    >/dev/null 2>&1 || true
  exit "$rc"
}

verify_onprem_nr_source() {
  local identity source_uuid source_server_id source_log_bin dr_server_id status source_file source_pos
  identity="$(remote_mysql "$DR_REPL_DEFAULTS_FILE" \
    'SELECT @@server_uuid,@@global.server_id,@@global.log_bin')" \
    || { echo "[NR FAILBACK BLOCKED] On-Prem replication account authentication failed."; return 1; }
  IFS=$'\t' read -r source_uuid source_server_id source_log_bin <<< "$identity"
  dr_server_id="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@global.server_id')" \
    || { echo "[NR FAILBACK BLOCKED] Existing DR server ID could not be read."; return 1; }
  if [ "${source_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ] \
      || [[ ! "$source_server_id" =~ ^[1-9][0-9]*$ ]] \
      || [[ ! "$dr_server_id" =~ ^[1-9][0-9]*$ ]] || [ "$source_server_id" = "$dr_server_id" ] \
      || [ "$source_log_bin" != "1" ]; then
    echo "[NR FAILBACK BLOCKED] On-Prem replication source identity/binlog settings are invalid."
    return 1
  fi
  status="$(remote_mysql "$DR_REPL_DEFAULTS_FILE" 'SHOW MASTER STATUS')" \
    || { echo "[NR FAILBACK BLOCKED] On-Prem master position is unavailable to the replication account."; return 1; }
  IFS=$'\t' read -r source_file source_pos _ <<< "$status"
  if [[ ! "$source_file" =~ ^[A-Za-z0-9._-]{1,128}$ ]] \
      || [[ ! "$source_pos" =~ ^[1-9][0-9]{0,19}$ ]]; then
    echo "[NR FAILBACK BLOCKED] On-Prem master position is invalid."
    return 1
  fi
  echo "[NR FAILBACK PREFLIGHT] Existing On-Prem source identity, binlog, and replication login are ready."
}

replica_status_fields() {
  awk -F: '
    function value_after_colon(line, colon) {
      colon = index(line, ":")
      if (!colon) return ""
      line = substr(line, colon + 1)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      return line
    }
    {
      key = $1
      gsub(/[[:space:]]/, "", key)
      value = value_after_colon($0)
      if (key == "Source_Host" || key == "Master_Host") host = value
      else if (key == "Source_User" || key == "Master_User") user = value
      else if (key == "Source_UUID" || key == "Master_UUID") uuid = value
      else if (key == "Source_Log_File" || key == "Master_Log_File") file = value
      else if (key == "Read_Source_Log_Pos" || key == "Read_Master_Log_Pos") read_pos = value
      else if (key == "Relay_Source_Log_File" || key == "Relay_Master_Log_File") exec_file = value
      else if (key == "Exec_Source_Log_Pos" || key == "Exec_Master_Log_Pos") exec_pos = value
      else if (key == "Seconds_Behind_Source" || key == "Seconds_Behind_Master") lag = value
      else if (key == "Replica_IO_Running" || key == "Slave_IO_Running") io = value
      else if (key == "Replica_SQL_Running" || key == "Slave_SQL_Running") sql = value
      else if (key == "Last_IO_Errno") io_error = value
      else if (key == "Last_SQL_Errno") sql_error = value
    }
    END {
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", \
        host, user, uuid, file, read_pos, exec_file, exec_pos, lag, io, sql, io_error, sql_error
    }
  '
}

read_dr_replica_status() {
  local status
  if status="$(remote_mysql_vertical "$DR_MYSQL_DEFAULTS_FILE" 'SHOW REPLICA STATUS' 2>/dev/null)" \
      && [ -n "$status" ]; then
    printf '%s\n' "$status"
    return 0
  fi
  status="$(remote_mysql_vertical "$DR_MYSQL_DEFAULTS_FILE" 'SHOW SLAVE STATUS' 2>/dev/null)" || return 1
  [ -n "$status" ] || return 1
  printf '%s\n' "$status"
}

verify_failback_nr() {
  local expected_uuid="$1" expected_file="$2" expected_pos="$3"
  local status fields host user uuid file read_pos exec_file exec_pos lag io sql io_error sql_error attempt
  echo "[NR FAILBACK] Verifying the existing DR database is following the restored On-Prem baseline."
  for attempt in $(seq 1 15); do
    status="$(read_dr_replica_status 2>/dev/null || true)"
    fields="$(printf '%s\n' "$status" | replica_status_fields)"
    IFS=$'\t' read -r host user uuid file read_pos exec_file exec_pos lag io sql io_error sql_error <<< "$fields"
    if [ "$host" = "$ONPREM_DB_TCP_HOST" ] && [ "$user" = "$DB_REPL_USER" ] \
        && [ "${uuid,,}" = "${expected_uuid,,}" ] && [ "$file" = "$expected_file" ] \
        && [[ "$read_pos" =~ ^[0-9]+$ ]] && (( read_pos >= expected_pos )) \
        && [ "$exec_file" = "$expected_file" ] \
        && [[ "$exec_pos" =~ ^[0-9]+$ ]] && (( exec_pos >= expected_pos )) \
        && [ "$lag" = "0" ] && [ "$io" = "Yes" ] && [ "$sql" = "Yes" ] \
        && [ "$io_error" = "0" ] && [ "$sql_error" = "0" ]; then
      echo "[NR FAILBACK] Replica IO/SQL are running; source identity and applied position are verified with zero lag."
      return 0
    fi
    if { [ -n "$io_error" ] && [ "$io_error" != "0" ]; } \
        || { [ -n "$sql_error" ] && [ "$sql_error" != "0" ]; }; then
      echo "[NR FAILBACK ERROR] Replica reported a nonzero IO/SQL error; DNS cutover is blocked."
      return 1
    fi
    if [ "$attempt" -lt 15 ]; then
      sleep 2
    fi
  done
  echo "[NR FAILBACK ERROR] Replica did not reach the verified On-Prem coordinate with IO/SQL healthy and zero lag."
  return 1
}

start_nr_from_failback_coordinate() {
  local identity source_uuid source_server_id source_log_bin source_status source_file source_pos
  local dr_server_id coordinate_uuid coordinate_file coordinate_pos password_sql change_sql legacy_change_sql
  local no_backslash_escapes_sql
  local persisted_skip_replica_start dr_flags

  IFS=$'\t' read -r coordinate_uuid coordinate_file coordinate_pos \
    <<< "$(onprem_wrapper --nr-coordinate "$DR_FAILBACK_REQUEST_ID")"
  if [ "${coordinate_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ] \
      || [[ ! "$coordinate_file" =~ ^[A-Za-z0-9._-]{1,128}$ ]] \
      || [[ ! "$coordinate_pos" =~ ^[1-9][0-9]{0,19}$ ]]; then
    echo "[NR FAILBACK ERROR] The post-restore On-Prem Binlog coordinate is invalid."
    return 1
  fi
  NR_FAILBACK_SOURCE_UUID="$coordinate_uuid"
  NR_FAILBACK_SOURCE_FILE="$coordinate_file"
  NR_FAILBACK_SOURCE_POS="$coordinate_pos"

  identity="$(remote_mysql "$DR_REPL_DEFAULTS_FILE" \
    'SELECT @@server_uuid,@@global.server_id,@@global.log_bin')" \
    || { echo "[NR FAILBACK ERROR] On-Prem replication source authentication failed after restore."; return 1; }
  IFS=$'\t' read -r source_uuid source_server_id source_log_bin <<< "$identity"
  dr_server_id="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@global.server_id')" \
    || { echo "[NR FAILBACK ERROR] Existing DR server ID could not be read."; return 1; }
  source_status="$(remote_mysql "$DR_REPL_DEFAULTS_FILE" 'SHOW MASTER STATUS')" \
    || { echo "[NR FAILBACK ERROR] On-Prem Binlog position could not be reread after restore."; return 1; }
  IFS=$'\t' read -r source_file source_pos _ <<< "$source_status"
  if [ "${source_uuid,,}" != "${coordinate_uuid,,}" ] \
      || [ "${source_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ] \
      || [[ ! "$source_server_id" =~ ^[1-9][0-9]*$ ]] \
      || [[ ! "$dr_server_id" =~ ^[1-9][0-9]*$ ]] || [ "$source_server_id" = "$dr_server_id" ] \
      || [ "$source_log_bin" != "1" ] \
      || [ "$source_file" != "$coordinate_file" ] || [ "$source_pos" != "$coordinate_pos" ]; then
    echo "[NR FAILBACK ERROR] On-Prem changed after the restore coordinate was captured; NR setup is blocked."
    return 1
  fi

  echo "[NR FAILBACK] Configuring the existing DR replica from the verified post-restore On-Prem coordinate."
  remote_mysql "$DR_MYSQL_DEFAULTS_FILE" \
    'SET PERSIST super_read_only=ON; SET PERSIST read_only=ON; SET GLOBAL super_read_only=ON; SET GLOBAL read_only=ON' \
    >/dev/null
  dr_flags="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@global.read_only,@@global.super_read_only')"
  [ "$dr_flags" = $'1\t1' ] || { echo "[NR FAILBACK ERROR] DR read-only standby state did not verify."; return 1; }

  if ! remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'STOP REPLICA' >/dev/null 2>&1; then
    remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'STOP SLAVE' >/dev/null 2>&1 \
      || { echo "[NR FAILBACK ERROR] Existing replica channel could not be stopped for repositioning."; return 1; }
  fi
  password_sql="$(printf '%s' "$DB_REPL_PASSWORD" | sed "s/'/''/g")"
  [[ -n "$password_sql" && "$DB_REPL_PASSWORD" != *$'\n'* && "$DB_REPL_PASSWORD" != *$'\r'* ]] \
    || { echo "[NR FAILBACK ERROR] Replication credential could not be encoded safely."; return 1; }
  # CHANGE REPLICATION SOURCE TO accepts a quoted text string for its password,
  # not a hexadecimal literal. Disable backslash escapes for this MySQL session
  # so doubling single quotes preserves arbitrary password characters safely.
  no_backslash_escapes_sql="SET SESSION sql_mode=IF(FIND_IN_SET('NO_BACKSLASH_ESCAPES',@@SESSION.sql_mode),@@SESSION.sql_mode,CONCAT_WS(',',NULLIF(@@SESSION.sql_mode,''),'NO_BACKSLASH_ESCAPES'));"
  change_sql="${no_backslash_escapes_sql} CHANGE REPLICATION SOURCE TO SOURCE_HOST='${ONPREM_DB_TCP_HOST}', SOURCE_PORT=${ONPREM_DB_PORT}, SOURCE_USER='${DB_REPL_USER}', SOURCE_PASSWORD='${password_sql}', SOURCE_LOG_FILE='${coordinate_file}', SOURCE_LOG_POS=${coordinate_pos}, GET_SOURCE_PUBLIC_KEY=1"
  legacy_change_sql="${no_backslash_escapes_sql} CHANGE MASTER TO MASTER_HOST='${ONPREM_DB_TCP_HOST}', MASTER_PORT=${ONPREM_DB_PORT}, MASTER_USER='${DB_REPL_USER}', MASTER_PASSWORD='${password_sql}', MASTER_LOG_FILE='${coordinate_file}', MASTER_LOG_POS=${coordinate_pos}, GET_MASTER_PUBLIC_KEY=1"
  if ! printf '%s;\n' "$change_sql" | remote_mysql_stdin "$DR_MYSQL_DEFAULTS_FILE" >/dev/null 2>&1; then
    if ! printf '%s;\n' "$legacy_change_sql" | remote_mysql_stdin "$DR_MYSQL_DEFAULTS_FILE" >/dev/null 2>&1; then
      echo "[NR FAILBACK ERROR] Existing DR replication channel could not be set to the verified coordinate."
      return 1
    fi
  fi
  # Failover persists this guard so a restarted promoted DB cannot auto-apply
  # source events. Clear it only after the existing channel points at the
  # verified failback coordinate; a restart before that must stay stopped.
  remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'RESET PERSIST IF EXISTS skip_replica_start' \
    >/dev/null || { echo "[NR FAILBACK ERROR] Replica auto-start guard could not be cleared."; return 1; }
  persisted_skip_replica_start="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" \
    "SELECT COUNT(*) FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='skip_replica_start'")"
  [ "$persisted_skip_replica_start" = "0" ] \
    || { echo "[NR FAILBACK ERROR] Replica auto-start guard remains persisted."; return 1; }
  if ! remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'START REPLICA' >/dev/null 2>&1; then
    remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'START SLAVE' >/dev/null 2>&1 \
      || { echo "[NR FAILBACK ERROR] Existing DR replication channel did not start."; return 1; }
  fi
  verify_failback_nr "$coordinate_uuid" "$coordinate_file" "$coordinate_pos"
}

RECOVERY_ONLY=0
trap cleanup_failback EXIT

echo "[DB FAILBACK] Staging DR MySQL options through SSH stdin; secret values are not command arguments or log output."
write_remote_defaults "$DR_MYSQL_DEFAULTS_FILE" root "$MYSQL_ROOT_PASS"
write_remote_defaults "$DR_REPL_DEFAULTS_FILE" "$DB_REPL_USER" "$DB_REPL_PASSWORD" \
  "$ONPREM_DB_TCP_HOST" "$ONPREM_DB_PORT"

echo "[DB FAILBACK] Checking DR MySQL and restricted On-Prem sudo wrapper."
"${REMOTE_SSH[@]}" "mysqladmin --defaults-extra-file='${DR_MYSQL_DEFAULTS_FILE}' ping --silent" >/dev/null
onprem_wrapper --check >/dev/null

if [ "${1:-}" = "--restore-dr-primary" ]; then
  RECOVERY_ONLY=1
  if [ "$(dr_state_read 2>/dev/null || true)" != "DR_ACTIVE" ]; then
    echo "[DB FAILBACK RECOVERY BLOCKED] DR_STATE is not DR_ACTIVE; refusing to open DR writes."
    exit 1
  fi
  recovery_target_uuid="$(onprem_wrapper --identity "$DR_FAILBACK_REQUEST_ID" | awk -F '\t' 'NR==1 {print $1}')"
  if [ "${recovery_target_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ]; then
    echo "[DB FAILBACK RECOVERY BLOCKED] On-Prem server identity did not match before recovery."
    exit 1
  fi
  restore_dr_primary
  exit 1
fi

if [ "$CONFIRM" != "OVERWRITE_ONPREM_DB" ] \
    || [ "$CONFIRM_REQUEST_ID" != "$DR_FAILBACK_REQUEST_ID" ] \
    || [[ ! "$CONFIRM_REQUEST_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "[DB FAILBACK BLOCKED] Request-scoped DB overwrite authorization is required before copying DR data to On-Prem."
  exit 2
fi

dr_identity="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@server_uuid,@@hostname,@@port,@@global.read_only,@@global.super_read_only,VERSION()')"
target_identity="$(onprem_wrapper --identity "$DR_FAILBACK_REQUEST_ID")"
IFS=$'\t' read -r dr_uuid dr_hostname dr_port dr_read_only dr_super_read_only dr_version <<< "$dr_identity"
IFS=$'\t' read -r target_uuid target_hostname target_port target_read_only target_super_read_only target_version <<< "$target_identity"
if [ -z "$dr_uuid" ] || [ -z "$target_uuid" ] || [ "$target_port" != "$ONPREM_DB_PORT" ]; then
  echo "[DB FAILBACK BLOCKED] MySQL identity response was incomplete or the On-Prem port did not match."
  exit 1
fi
if [ -z "$ONPREM_DB_SERVER_UUID_EXPECTED" ] \
    || [ "${target_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ]; then
  echo "[DB FAILBACK BLOCKED] On-Prem MySQL server UUID did not match the approved target identity."
  exit 1
fi
if [ -n "$ONPREM_DB_HOSTNAME_EXPECTED" ] && [ "$target_hostname" != "$ONPREM_DB_HOSTNAME_EXPECTED" ]; then
  echo "[DB FAILBACK BLOCKED] On-Prem MySQL hostname did not match the approved target identity."
  exit 1
fi
if [[ "$target_version" != 8.* ]]; then
  echo "[DB FAILBACK BLOCKED] On-Prem MySQL must support persistent primary/standby role settings (MySQL 8+)."
  exit 1
fi
if [ "$dr_read_only" != "0" ] || [ "$dr_super_read_only" != "0" ]; then
  echo "[DB FAILBACK BLOCKED] The active DR DB is not the current writable primary."
  exit 1
fi
verify_onprem_nr_source || exit 1
echo "[DB FAILBACK] Preserving the current On-Prem hospital_db before overwrite."
backup_receipt="$(onprem_wrapper --backup "$DR_FAILBACK_REQUEST_ID")"
backup_sha256="$(sed -n 's/^ONPREM_PREBACKUP=PASS sha256=\([0-9a-f]\{64\}\)$/\1/p' <<< "$backup_receipt")"
if [[ ! "$backup_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "[DB FAILBACK BLOCKED] The On-Prem pre-backup checksum could not be verified."
  exit 1
fi
echo "[DB BACKUP] On-Prem pre-overwrite backup verified; SHA-256=${backup_sha256}; artifact retained in the existing On-Prem DB backup directory."

echo "[DB FAILBACK] Fencing writes on the DR source; NR will be repositioned only after the restored On-Prem baseline is verified."
DR_DB_WRITER_FENCED=1
remote_mysql "$DR_MYSQL_DEFAULTS_FILE" \
  "SET PERSIST super_read_only=ON; SET PERSIST read_only=ON; SET GLOBAL super_read_only=ON; SET GLOBAL read_only=ON"
dr_flags="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@global.read_only,@@global.super_read_only')"
if [ "$dr_flags" != $'1\t1' ]; then
  echo "[DB FAILBACK BLOCKED] The DR source writer fence did not verify."
  exit 1
fi

source_counts="$(remote_table_counts "$DR_MYSQL_DEFAULTS_FILE")"
source_hash="$(printf '%s' "$source_counts" | sha256sum | awk '{print $1}')"
if [[ ! "$source_hash" =~ ^[0-9a-f]{64}$ ]]; then
  echo "[DB FAILBACK BLOCKED] DR source table row-count baseline could not be verified."
  exit 1
fi
echo "[DB FAILBACK] Exporting the fenced DR hospital_db snapshot."
db_export_timing_start="$(dr_timing_start db_export)"
export_command="set -euo pipefail; umask 077; mysqldump --defaults-extra-file='${DR_MYSQL_DEFAULTS_FILE}' --single-transaction --routines --triggers --events --hex-blob --quick --add-drop-table '${DB_NAME}' | gzip -1 > '${DR_DUMP_FILE}'; gzip -t '${DR_DUMP_FILE}'; test -s '${DR_DUMP_FILE}'; sha256sum '${DR_DUMP_FILE}'"
export_receipt="$(remote_bash "$export_command")"
dump_sha256="$(awk 'NR==1 {print $1}' <<< "$export_receipt")"
if [[ ! "$dump_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "[DB FAILBACK BLOCKED] The DR snapshot checksum could not be verified."
  exit 1
fi
dr_timing_end db_export "$db_export_timing_start"

echo "[DB FAILBACK] Restoring the approved DR snapshot after request-scoped overwrite approval and pre-backup verification."
echo "[DB FAILBACK] Restoring the approved DR snapshot to On-Prem hospital_db."
db_restore_timing_start="$(dr_timing_start db_restore)"
echo "[NR FAILBACK] Holding On-Prem application writes during the approved restore and baseline capture."
onprem_wrapper --nr-baseline-hold "$DR_FAILBACK_REQUEST_ID" >/dev/null
stage_dr_dump_onprem "$DR_FAILBACK_REQUEST_ID"
onprem_wrapper --restore "$DR_FAILBACK_REQUEST_ID" "$dump_sha256" "$CONFIRM"
dr_timing_end db_restore "$db_restore_timing_start"

echo "[DB FAILBACK] Comparing restored table names and row counts with the fenced DR snapshot."
target_counts="$(onprem_table_counts)"
if [ "$source_counts" != "$target_counts" ]; then
  echo "[DB FAILBACK ERROR] Restored On-Prem data does not match the DR table row-count baseline."
  exit 1
fi
target_counts_hash="$(printf '%s' "$target_counts" | sha256sum | awk '{print $1}')"
if [ "$source_hash" != "$target_counts_hash" ]; then
  echo "[DB FAILBACK ERROR] Restored On-Prem data hash does not match the DR table row-count baseline."
  exit 1
fi

start_nr_from_failback_coordinate || exit 1

echo "[DB FAILBACK] Promoting On-Prem as the sole writer after NR has reached the verified baseline."
onprem_wrapper --promote "$DR_FAILBACK_REQUEST_ID" "$source_hash"
target_flags="$(onprem_wrapper --flags "$DR_FAILBACK_REQUEST_ID")"
dr_flags="$(remote_mysql "$DR_MYSQL_DEFAULTS_FILE" 'SELECT @@global.read_only,@@global.super_read_only')"
if [ "$target_flags" != $'0\t0' ] || [ "$dr_flags" != $'1\t1' ]; then
  echo "[DB FAILBACK ERROR] Single-writer role readback failed after data verification."
  exit 1
fi
verify_failback_nr "$NR_FAILBACK_SOURCE_UUID" "$NR_FAILBACK_SOURCE_FILE" "$NR_FAILBACK_SOURCE_POS" || exit 1

FAILBACK_COMPLETED=1
echo "[DB FAILBACK] DB data restored; On-Prem is the sole writable DB and the existing DR NR replica is running from the verified restore coordinate."
dr_timing_end db_failback_internal "$db_failback_timing_start"
echo "=================================================="
echo "[$(date)] DB failback completed."
echo "=================================================="
