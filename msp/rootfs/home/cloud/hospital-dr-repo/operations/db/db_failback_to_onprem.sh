#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

FINOPS_DIR="${FINOPS_DIR:-$DR_FINOPS_DIR}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/db_failback.log}"
mkdir -p "$(dirname -- "$LOG_FILE")"
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
ONPREM_DB_PORT="${ONPREM_DB_PORT:-3306}"
ONPREM_DB_ROOT_USER="${ONPREM_DB_ROOT_USER:-restore}"
ONPREM_DB_ROOT_PASS="${ONPREM_DB_ROOT_PASS:-}"
CONFIRM="${DB_FAILBACK_CONFIRM:-}"
SSH_KEY="${SSH_KEY:-${DR_SSH_KEY:-}}"
DR_DB_HOST="${DR_DB_HOST:-IP_REDACTED}"
DR_DUMP_FILE="${DR_DUMP_FILE:-/tmp/${DB_NAME}_failback.sql}"
REGION="${AWS_REGION:-ap-northeast-2}"
ENABLE_NAT_FOR_DB_FAILBACK="${ENABLE_NAT_FOR_DB_FAILBACK:-true}"
ONPREM_DB_CONNECT_ATTEMPTS="${ONPREM_DB_CONNECT_ATTEMPTS:-12}"
ONPREM_DB_CONNECT_SLEEP="${ONPREM_DB_CONNECT_SLEEP:-5}"

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
require_secret "ONPREM_DB_ROOT_PASS"
require_config "ONPREM_DB_HOST"
require_config "SSH_KEY"

aws_instance_id_by_name() {
  local name="$1"
  aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=tag:Name,Values=${name}" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text
}

aws_instance_state() {
  local instance_id="$1"
  aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text
}

aws_instance_public_ip() {
  local instance_id="$1"
  aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text
}

refresh_inventory_for_failback() {
  local web_ip="$1"
  local temporary ssh_common ssh_jump_common proxy_command
  temporary=$(mktemp)
  ssh_common="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR"
  proxy_command="ssh -i ${SSH_KEY} ${ssh_common} -W %h:%p ubuntu@${web_ip}"
  ssh_jump_common="${ssh_common} -o ProxyCommand=\"${proxy_command}\""
  {
    echo "[web_servers]"
    echo "${web_ip} ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_common}'"
    echo
    echo "[doc_servers]"
    echo "IP_REDACTED ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_jump_common}'"
    echo
    echo "[db_servers]"
    echo "${DR_DB_HOST} ansible_connection=ssh ansible_user=ubuntu ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='${ssh_jump_common}'"
  } > "$temporary"
  install -m 0644 "$temporary" "$INVENTORY"
  rm -f "$temporary"
}

wait_for_ssh_target() {
  local label="$1"
  local host="$2"
  shift 2
  local attempt ssh_args

  ssh_args=(
    ssh
    -i "$SSH_KEY"
    -o BatchMode=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o GlobalKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=10
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=3
  )

  echo "[DB FAILBACK] Waiting for SSH readiness: ${label}"
  for attempt in $(seq 1 30); do
    if "${ssh_args[@]}" "$@" "$host" "true" >/dev/null 2>&1; then
      echo "[DB FAILBACK] SSH ready: ${label}"
      return 0
    fi

    echo "[DB FAILBACK] SSH not ready yet (${attempt}/30): ${label}"
    sleep 10
  done

  echo "[DB FAILBACK ERROR] SSH did not become ready: ${label}"
  return 1
}

wait_for_dr_ssh() {
  local web_ip="$1"
  local ssh_common proxy_command
  ssh_common="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
  proxy_command="ssh -i ${SSH_KEY} ${ssh_common} -W %h:%p ubuntu@${web_ip}"
  wait_for_ssh_target "DR Web bastion ${web_ip}" "ubuntu@${web_ip}"
  wait_for_ssh_target "DR DB ${DR_DB_HOST} through Web bastion" "ubuntu@${DR_DB_HOST}" -o "ProxyCommand=${proxy_command}"
}

ansible_web_shell() {
  ansible -i "$INVENTORY" web_servers -m shell -a "$1"
}

ansible_db_shell() {
  ansible -i "$INVENTORY" db_servers -m shell -a "$1"
}

ensure_onprem_db_tcp_for_failback() {
  local attempt

  echo "[DB FAILBACK] Validating direct TCP connectivity from DR DB to on-premises DB."

  for attempt in $(seq 1 "$ONPREM_DB_CONNECT_ATTEMPTS"); do
    if ansible_db_shell "nc -vz -w 5 ${ONPREM_DB_HOST} ${ONPREM_DB_PORT}" >/dev/null 2>&1; then
      echo "[DB FAILBACK] DR DB can reach on-premises DB: ${ONPREM_DB_HOST}:${ONPREM_DB_PORT}"
      return 0
    fi

    echo "[DB FAILBACK] Waiting for DR DB to on-premises DB TCP connectivity (${attempt}/${ONPREM_DB_CONNECT_ATTEMPTS})."
    sleep "$ONPREM_DB_CONNECT_SLEEP"
  done

  echo "[DB FAILBACK BLOCKED] DR DB cannot reach the on-premises DB over direct TCP."
  echo "[REQUIRED ACTION] Allow the AWS NAT egress IP to access on-premises MySQL ${ONPREM_DB_PORT}/tcp, or set ONPREM_DB_HOST to a reachable DB endpoint."
  ansible_db_shell "ip route get ${ONPREM_DB_HOST} || true; nc -vz -w 5 ${ONPREM_DB_HOST} ${ONPREM_DB_PORT} || true" || true
  exit 1
}

ensure_dr_compute_for_failback() {
  if ! command -v aws >/dev/null 2>&1 || ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[DB FAILBACK WARNING] AWS CLI is unavailable or not authenticated. Skipping EC2 preflight."
    return 0
  fi

  local web_id db_id web_state db_state web_ip
  web_id=$(aws_instance_id_by_name "Hospital-Real-Web-Server")
  db_id=$(aws_instance_id_by_name "Hospital-DR-DB-Server")

  if [ -z "$web_id" ] || [ "$web_id" = "None" ] || [ -z "$db_id" ] || [ "$db_id" = "None" ]; then
    echo "[DB FAILBACK WARNING] DR Web or DB EC2 instance could not be resolved. Continuing with current inventory."
    return 0
  fi

  web_state=$(aws_instance_state "$web_id")
  db_state=$(aws_instance_state "$db_id")
  if [ "$web_state" != "running" ] || [ "$db_state" != "running" ]; then
    echo "[DB FAILBACK] Starting DR Web/DB EC2 instances for data export only."
    aws ec2 start-instances --region "$REGION" --instance-ids "$web_id" "$db_id" >/dev/null
    aws ec2 wait instance-running --region "$REGION" --instance-ids "$web_id" "$db_id"
    aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$web_id" "$db_id"
  fi

  web_ip=$(aws_instance_public_ip "$web_id")
  if [ -z "$web_ip" ] || [ "$web_ip" = "None" ]; then
    echo "[DB FAILBACK ERROR] DR Web instance has no public IP after start."
    exit 1
  fi

  echo "[DB FAILBACK] Refreshing Ansible inventory for DR Web bastion: ${web_ip}"
  refresh_inventory_for_failback "$web_ip"
  wait_for_dr_ssh "$web_ip"
  if [ "$ENABLE_NAT_FOR_DB_FAILBACK" = "true" ]; then
    echo "[DB FAILBACK] Enabling NAT for private DR DB outbound access during failback."
    "${FINOPS_DIR}/nat_gateway_control.sh" enable
  fi
  ensure_onprem_db_tcp_for_failback
}

echo "=================================================="
echo "[$(date)] DB failback to on-premises started."
echo "=================================================="

if [ "$CONFIRM" != "OVERWRITE_ONPREM_DB" ]; then
  echo "[DB FAILBACK BLOCKED] Set DB_FAILBACK_CONFIRM=OVERWRITE_ONPREM_DB to overwrite on-premises ${DB_NAME}."
  exit 2
fi

connectivity_timing_start="$(dr_timing_start db_connectivity)"
ensure_dr_compute_for_failback
dr_timing_end db_connectivity "$connectivity_timing_start"

echo "[DB FAILBACK] Checking DR DB and on-prem DB connectivity."
ansible_db_shell "nc -vz -w 5 ${ONPREM_DB_HOST} ${ONPREM_DB_PORT}"

WEB_HOST=$(awk '/^\[web_servers\]/{getline; print $1; exit}' "$INVENTORY")
if [ -z "${WEB_HOST:-}" ]; then
  echo "[DB FAILBACK ERROR] Web bastion host could not be resolved from inventory."
  exit 1
fi
SSH_COMMON="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=15"
PROXY_COMMAND="ssh -i ${SSH_KEY} ${SSH_COMMON} -W %h:%p ubuntu@${WEB_HOST}"

REMOTE_SSH=(
  ssh
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o GlobalKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=12
  -o ConnectTimeout=15
  -o "ProxyCommand=${PROXY_COMMAND}"
  "ubuntu@${DR_DB_HOST}"
)

DR_MYSQL_DEFAULTS_FILE="/tmp/dr-db-root-defaults.$$"
ONPREM_MYSQL_DEFAULTS_FILE="/tmp/onprem-db-restore-defaults.$$"

cleanup_remote_defaults() {
  "${REMOTE_SSH[@]}" "rm -f '${DR_MYSQL_DEFAULTS_FILE}' '${ONPREM_MYSQL_DEFAULTS_FILE}'" >/dev/null 2>&1 || true
}
trap cleanup_remote_defaults EXIT

echo "[DB FAILBACK] Staging temporary MySQL client credential files on DR DB."
"${REMOTE_SSH[@]}" "umask 077; {
printf '[client]\n';
printf 'user=root\n';
printf 'password=%s\n' '${MYSQL_ROOT_PASS}';
} > '${DR_MYSQL_DEFAULTS_FILE}';
chmod 600 '${DR_MYSQL_DEFAULTS_FILE}';
{
printf '[client]\n';
printf 'user=%s\n' '${ONPREM_DB_ROOT_USER}';
printf 'password=%s\n' '${ONPREM_DB_ROOT_PASS}';
printf 'host=%s\n' '${ONPREM_DB_HOST}';
printf 'port=%s\n' '${ONPREM_DB_PORT}';
} > '${ONPREM_MYSQL_DEFAULTS_FILE}';
chmod 600 '${ONPREM_MYSQL_DEFAULTS_FILE}'"

echo "[DB FAILBACK] Checking DR MySQL authentication."
"${REMOTE_SSH[@]}" "mysqladmin --defaults-extra-file='${DR_MYSQL_DEFAULTS_FILE}' ping --silent"

echo "[DB FAILBACK] Exporting DR database to a staged dump file."
db_export_timing_start="$(dr_timing_start db_export)"
"${REMOTE_SSH[@]}" "rm -f '${DR_DUMP_FILE}' && mysqldump --defaults-extra-file='${DR_MYSQL_DEFAULTS_FILE}' --single-transaction --routines --triggers --add-drop-table '${DB_NAME}' > '${DR_DUMP_FILE}' && ls -lh '${DR_DUMP_FILE}'"
dr_timing_end db_export "$db_export_timing_start"

echo "[DB FAILBACK] Restoring staged DR dump to on-premises DB."
db_restore_timing_start="$(dr_timing_start db_restore)"
"${REMOTE_SSH[@]}" "mysql --defaults-extra-file='${ONPREM_MYSQL_DEFAULTS_FILE}' '${DB_NAME}' < '${DR_DUMP_FILE}'"
dr_timing_end db_restore "$db_restore_timing_start"

echo "[DB FAILBACK] Removing staged DR dump file."
"${REMOTE_SSH[@]}" "rm -f '${DR_DUMP_FILE}'"

echo "[DB FAILBACK] Verifying row counts on on-premises DB."
"${REMOTE_SSH[@]}" "mysql --defaults-extra-file='${ONPREM_MYSQL_DEFAULTS_FILE}' -D '${DB_NAME}' -e \"SELECT COUNT(*) AS users_count FROM Users; SELECT COUNT(*) AS patients_count FROM Patients;\""

echo "[DB FAILBACK] DB failback completed. Reconfigure NR from on-premises to DR before returning to steady state."
dr_timing_end db_failback_internal "$db_failback_timing_start"
echo "=================================================="
echo "[$(date)] DB failback completed."
echo "=================================================="
