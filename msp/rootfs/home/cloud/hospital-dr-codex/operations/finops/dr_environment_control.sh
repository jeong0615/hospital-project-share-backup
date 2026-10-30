#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"
# shellcheck disable=SC1091
source "$DR_DNS_HELPER"
# shellcheck disable=SC1091
source "$DR_SSM_SSH_HELPER"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime/ec2_start_actions.sh"
source "$DR_CLOUDFLARE_AUTH_SCRIPT"

TF_DIR="${TF_DIR:-$DR_TERRAFORM_DIR}"
NAT_DIR="${NAT_DIR:-$DR_NAT_DIR}"
NAT_INSTANCE_STATUS_SCRIPT="${NAT_INSTANCE_STATUS_SCRIPT:-$DR_OPERATIONS_DIR/nat_instance/web_nat_instance_status.sh}"
INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
SSH_KEY="${SSH_KEY:-${DR_SSH_PRIVATE_KEY:-${DR_SSH_KEY:-}}}"
REGION="${AWS_REGION:-ap-northeast-2}"
ENV_LOCK="${DR_ENVIRONMENT_LOCK_FILE:-${DR_STATE_DIR}/environment.lock}"
WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR}/workflow.lock}"
LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/dr_environment.log}"
ACTION="${1:-status}"
SECRET_FILE="$DR_SECRET_FILE"
SECRET_CONFIG_READY=false
load_environment_secrets() {
  local skip_dns_was_set="${SKIP_DNS+x}"
  local skip_dns_from_caller="${SKIP_DNS-}"
  local defer_idle_was_set="${DR_ENVIRONMENT_CONTROL_DEFER_IDLE+x}"
  local defer_idle_from_caller="${DR_ENVIRONMENT_CONTROL_DEFER_IDLE-}"

  SKIP_DNS="${SKIP_DNS:-false}"
  if [ -f "$SECRET_FILE" ] && [ -r "$SECRET_FILE" ]; then
    dr_load_secret_file || return 1
    SECRET_CONFIG_READY=true
  elif [ -e "$SECRET_FILE" ]; then
    echo "[CONFIG ERROR] DR_SECRET_FILE exists but is unreadable."
    return 1
  fi

  # Caller controls the orchestration. Preserve .env values as defaults for
  # standalone operations while honoring explicit values passed by a wrapper.
  if [ "$skip_dns_was_set" = "x" ]; then
    SKIP_DNS="$skip_dns_from_caller"
  else
    SKIP_DNS="${SKIP_DNS:-false}"
  fi
  if [ "$defer_idle_was_set" = "x" ]; then
    DR_ENVIRONMENT_CONTROL_DEFER_IDLE="$defer_idle_from_caller"
  else
    unset DR_ENVIRONMENT_CONTROL_DEFER_IDLE
  fi
}
load_environment_secrets
unset -f load_environment_secrets
if [ -n "${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}" ]; then
  dr_resolve_ssh_key_config || true
fi

DR_STATE_FAILURE_STATUS=FAILED
DR_DOMAIN="${DR_DOMAIN:-hospital-web.pp.ua}"
EMR_DOMAIN="${EMR_DOMAIN:-emr.hospital-web.pp.ua}"
ONPREM_WEB_HEALTH_URL="${ONPREM_WEB_HEALTH_URL:-http://IP_REDACTED/}"
ONPREM_EMR_HEALTH_URL="${ONPREM_EMR_HEALTH_URL:-http://IP_REDACTED/emr/}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
ONPREM_TUNNEL_HOST="${ONPREM_TUNNEL_HOST:-e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com}"
ONPREM_EMR_DNS_IP_EXPECTED="${ONPREM_EMR_DNS_IP_EXPECTED:-IP_REDACTED}"
DR_WEB_EIP_EXPECTED="${DR_WEB_EIP_EXPECTED:-AWS_PUBLIC_IP_REDACTED}"
DR_WEB_PRIVATE_IP_EXPECTED="${DR_WEB_PRIVATE_IP_EXPECTED:-IP_REDACTED}"
DR_CF_WEB_RECORD_ID_EXPECTED="${DR_CF_WEB_RECORD_ID_EXPECTED:-${CF_RECORD_ID:-4c35b40ec154fb21c92fc3795ce9d5ea}}"
DR_CF_EMR_RECORD_ID_EXPECTED="${DR_CF_EMR_RECORD_ID_EXPECTED:-${CF_EMR_RECORD_ID:-4a4432c4e6290bcbd3dda5113ff8d560}}"
ONPREM_SSH_KEY="${ONPREM_SSH_KEY:-}"
ONPREM_SSH_KNOWN_HOSTS_FILE="${ONPREM_SSH_KNOWN_HOSTS_FILE:-${HOME:-/home/cloud}/.ssh/known_hosts}"
DNS_TX_DIR="${DR_DNS_TX_DIR:-${DR_STATE_DIR}/dns/environment-${ACTION}-${BASHPID}}"
DNS_ORIGIN_DIR="${DR_DNS_ORIGIN_SNAPSHOT_DIR:-${DR_STATE_DIR}/dns/origin}"
DNS_ARCHIVE_DIR="${DR_DNS_ORIGIN_ARCHIVE_DIR:-${DR_STATE_DIR}/dns/origin-archive}"
DR_STATE_TRANSITION_STARTED=0
mkdir -p "$(dirname -- "$LOG_FILE")"
dr_state_prepare
dr_workflow_lock_prepare
if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
  exec 7>"$WORKFLOW_LOCK_FILE"
  if ! flock -n 7; then
    echo "[DR ENVIRONMENT ERROR] Another DR workflow is already running."
    echo "[DR 환경 오류] 다른 DR 워크플로가 이미 실행 중입니다."
    exit 1
  fi
fi
export DR_WORKFLOW_LOCK_HELD=1

stateful_action() {
  case "$ACTION" in
    start|stop|provision) return 0 ;;
    *) return 1 ;;
  esac
}

if stateful_action; then
  trap 'rc=$?; if [ "$DR_STATE_TRANSITION_STARTED" = "1" ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi; exit "$rc"' ERR
  trap 'rc=$?; if [ "$rc" -ne 0 ] && [ "$DR_STATE_TRANSITION_STARTED" = "1" ]; then dr_state_mark_failure "${DR_STATE_FAILURE_STATUS:-FAILED}" 2>/dev/null || true; fi' EXIT
fi

# systemd exports INVOCATION_ID to every process in the service cgroup.  That
# value is therefore inherited by ChatOps workflows as well and cannot be
# used to distinguish the lifecycle unit's automatic start from an explicitly
# approved ChatOps/manual start.  Only the lifecycle unit sets the explicit
# marker below; callers such as ChatOps remain allowed to start the reviewed
# DR environment.
if [ "$ACTION" = "start" ] \
  && [ "${DR_ENVIRONMENT_SYSTEMD_AUTOSTART:-false}" = "true" ] \
  && [ "${DR_ENVIRONMENT_SYSTEMD_START_ALLOWED:-false}" != "true" ]; then
  echo "[DR ENVIRONMENT] systemd auto-start was ignored to prevent unintended failover."
  echo "[DR 환경] 의도하지 않은 페일오버 방지를 위해 systemd 자동 시작을 건너뜁니다."
  echo "[DR ENVIRONMENT] Use this script directly for manual DR start: $0 start"
  echo "[DR 환경] 수동 DR 시작은 스크립트를 직접 실행하십시오: $0 start"
  exit 0
fi

if [ "${DR_ENVIRONMENT_LOCK_HELD:-0}" != "1" ]; then
  exec 8>"$ENV_LOCK"
  if ! flock -n 8; then
    echo "[DR ENVIRONMENT ERROR] Another environment lifecycle operation is already running."
    echo "[DR 환경 오류] 다른 환경 수명주기 작업이 이미 실행 중입니다."
    exit 1
  fi
fi
exec > >(tee -a "$LOG_FILE") 2>&1

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: $name."
    return 1
  fi
}

aws_check() {
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[AWS AUTH ERROR] AWS credentials are missing, expired, or invalid."
    echo "[AWS 인증 오류] AWS 자격 증명이 없거나 만료되었거나 유효하지 않습니다."
    return 1
  fi
}

instance_ids() {
  aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text | tr '\t' '\n' | sed '/^$/d'
}

prepare_dns_snapshot() {
  require_config "CF_ZONE_ID"
  mkdir -p "$DNS_TX_DIR"
  chmod 0750 "$DNS_TX_DIR"
  load_cloudflare_ssm_token
  CF_RECORD_ID="$(dr_dns_snapshot_record "$DR_DOMAIN" "$DNS_TX_DIR/web.json" "${CF_RECORD_ID:-}")"
  CF_EMR_RECORD_ID="$(dr_dns_snapshot_record "$EMR_DOMAIN" "$DNS_TX_DIR/emr.json" "${CF_EMR_RECORD_ID:-}")"
  dr_dns_validate_snapshot_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN"
}

apply_dr_dns() {
  local public_ip="$1"
  local apply_rc preserve_rc
  if dr_dns_preserve_origin_pair \
      "$DNS_TX_DIR" "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
      "$ONPREM_TUNNEL_HOST" "$public_ip" "$ONPREM_EMR_DNS_IP_EXPECTED"; then
    :
  else
    preserve_rc=$?
    if [ "$preserve_rc" -eq 2 ]; then
      DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
      dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    else
      DR_STATE_FAILURE_STATUS=FAILED
      dr_state_write FAILED 2>/dev/null || true
    fi
    return 1
  fi

  if dr_dns_failover_transaction \
      "$DNS_TX_DIR" "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
      "$ONPREM_TUNNEL_HOST" "$public_ip" check_public_health \
      "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/" "${DR_FAILOVER_PUBLIC_HEALTH_ATTEMPTS:-4}"; then
    return 0
  else
    apply_rc=$?
  fi
  if [ "$apply_rc" -eq 2 ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  else
    DR_STATE_FAILURE_STATUS=FAILED
    dr_state_write FAILED 2>/dev/null || true
  fi
  return 1
}

check_public_health() {
  local web_url="$1"
  local emr_url="$2"
  local attempts="$3"
  dr_dns_check_public_health "$web_url" "$emr_url" \
    "$EMR_HEALTH_CHECK_HEADER" "$attempts" \
    "${PUBLIC_HEALTH_INTERVAL_SECONDS:-5}" "Public"
}

mark_state_from_current_dns() {
  if prepare_dns_snapshot \
      && dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
    DR_STATE_FAILURE_STATUS=DR_ACTIVE
    dr_state_write DR_ACTIVE 2>/dev/null || true
  else
    # Unknown or already-restored records cannot be reported as DR_ACTIVE.
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
  fi
}

# Keep the secret off argv/environment transport: it is supplied only on the
# SSH stdin channel and written remotely to a mode-0600 temporary MySQL file.
dr_run_db_remote_with_secret() {
  local remote_script="$1"
  local remote_command
  require_config MYSQL_ROOT_PASS || return 1
  if [[ "$MYSQL_ROOT_PASS" == *$'\n'* || "$MYSQL_ROOT_PASS" == *$'\r'* ]]; then
    echo "[DB PROMOTION ERROR] MYSQL_ROOT_PASS must be a single-line value."
    return 1
  fi
  printf -v remote_command 'sudo -n bash -c %q' "$remote_script"
  printf '%s\n' "$MYSQL_ROOT_PASS" | dr_ssm_ssh dr-db "$remote_command"
}

dr_db_mysql_probe() {
  local remote_script output probe_line
  remote_script="$(cat <<'REMOTE'
set -euo pipefail
IFS= read -r MYSQL_ROOT_PASS || exit 70
defaults_file="$(mktemp /run/hospital-dr-db-probe.XXXXXX)"
trap 'rm -f "$defaults_file"' EXIT
chmod 0600 "$defaults_file"
printf '[client]\nuser=root\npassword=%s\n' "$MYSQL_ROOT_PASS" > "$defaults_file"
unset MYSQL_ROOT_PASS
probe="$(mysql --defaults-extra-file="$defaults_file" --batch --raw --skip-column-names \
  -e "SELECT @@server_uuid,@@hostname,@@port,@@global.read_only,@@global.super_read_only,EXISTS(SELECT 1 FROM information_schema.schemata WHERE SCHEMA_NAME=CHAR(104,111,115,112,105,116,97,108,95,100,98)),1")"
core_stats="$(mysql --defaults-extra-file="$defaults_file" --batch --raw --skip-column-names -e "
SET SESSION group_concat_max_len=65535;
SELECT COUNT(*)
FROM information_schema.tables
WHERE TABLE_SCHEMA='hospital_db' AND TABLE_TYPE='BASE TABLE'
  AND LOWER(TABLE_NAME) IN ('users','patients','doctors','medicalrecords','accesslogs','reservationposts')
  AND TABLE_NAME REGEXP '^[A-Za-z]+$';
SELECT GROUP_CONCAT(
  CONCAT('SELECT COUNT(*) AS n FROM hospital_db.', TABLE_NAME)
  SEPARATOR ' UNION ALL '
) INTO @core_count_queries
FROM information_schema.tables
WHERE TABLE_SCHEMA='hospital_db' AND TABLE_TYPE='BASE TABLE'
  AND LOWER(TABLE_NAME) IN ('users','patients','doctors','medicalrecords','accesslogs','reservationposts')
  AND TABLE_NAME REGEXP '^[A-Za-z]+$';
SET @core_count_query=IF(@core_count_queries IS NULL,'SELECT 0',CONCAT('SELECT COALESCE(SUM(n),0) FROM (',@core_count_queries,') AS core_counts'));
PREPARE core_count_stmt FROM @core_count_query;
EXECUTE core_count_stmt;
DEALLOCATE PREPARE core_count_stmt;
SELECT COALESCE(MAX(TABLE_NAME),'') INTO @patient_table
FROM information_schema.tables
WHERE TABLE_SCHEMA='hospital_db' AND TABLE_TYPE='BASE TABLE'
  AND LOWER(TABLE_NAME)='patients' AND TABLE_NAME REGEXP '^[A-Za-z]+$';
SET @patient_count_query=IF(@patient_table='','SELECT 0',CONCAT('SELECT COUNT(*) FROM hospital_db.',@patient_table));
PREPARE patient_count_stmt FROM @patient_count_query;
EXECUTE patient_count_stmt;
DEALLOCATE PREPARE patient_count_stmt;")"
mapfile -t core_stats_lines <<< "$core_stats"
if [ "${#core_stats_lines[@]}" -ne 3 ] \
    || ! [[ "${core_stats_lines[0]}" =~ ^[0-9]+$ ]] \
    || ! [[ "${core_stats_lines[1]}" =~ ^[0-9]+$ ]] \
    || ! [[ "${core_stats_lines[2]}" =~ ^[0-9]+$ ]]; then
  exit 71
fi
printf 'DB_PROMOTION_PROBE\t%s\t%s\t%s\t%s\n' "$probe" "${core_stats_lines[0]}" "${core_stats_lines[1]}" "${core_stats_lines[2]}"
REMOTE
  )"
  output="$(dr_run_db_remote_with_secret "$remote_script")" || return 1
  probe_line="$(printf '%s\n' "$output" | awk -F '\t' '$1 == "DB_PROMOTION_PROBE" { print; count++ } END { if (count != 1) exit 1 }')" || return 1
  [ "$(printf '%s\n' "$probe_line" | awk -F '\t' '{ print NF }')" -eq 11 ] || return 1
  printf '%s\n' "$probe_line"
}

dr_read_onprem_source_coordinate() {
  local remote_command output line
  local key_path="${ONPREM_SSH_KEY:-}" known_hosts="${ONPREM_SSH_KNOWN_HOSTS_FILE:-}"
  [ -n "$key_path" ] && [ -n "$known_hosts" ] || return 1
  remote_command="set -eu
source_uuid=\$(timeout --foreground 15s mysql --protocol=socket --user=hoseo --connect-timeout=10 --batch --raw --skip-column-names -e 'SELECT @@server_uuid')
source_status=\$(timeout --foreground 15s mysql --protocol=socket --user=hoseo --connect-timeout=10 --batch --raw --skip-column-names -e 'SHOW MASTER STATUS')
source_coordinate=\$(printf '%s\\n' \"\$source_status\" | awk -F '\\t' 'NF >= 2 { if (count++ == 0) { file=\$1; position=\$2 } } END { if (count != 1) exit 1; print file \"\\t\" position }')
printf 'ONPREM_SOURCE_COORD\\t%s\\t%s\\n' \"\$source_uuid\" \"\$source_coordinate\""
  output="$(timeout --foreground 75s ssh \
    -o BatchMode=yes -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=0 \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o ConnectTimeout=45 -o ConnectionAttempts=1 \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
    -i "$key_path" hoseo@IP_REDACTED "$remote_command" 2>/dev/null)" || return 1
  line="$(printf '%s\n' "$output" | awk -F '\t' '$1 == "ONPREM_SOURCE_COORD" { print; count++ } END { if (count != 1) exit 1 }')" || return 1
  [ "$(printf '%s\n' "$line" | awk -F '\t' '{ print NF }')" -eq 4 ] || return 1
  printf '%s\n' "$line"
}

dr_verify_onprem_source_writer_fence() {
  local key_path="${ONPREM_SSH_KEY:-}" known_hosts="${ONPREM_SSH_KNOWN_HOSTS_FILE:-}"
  local remote_command output line marker read_only super_read_only
  if [ -z "$key_path" ] || [ ! -r "$key_path" ] || [ -z "$known_hosts" ] || [ ! -r "$known_hosts" ]; then
    echo "[SOURCE WRITE FENCE BLOCKED] Existing On-Prem SSH identity or known-hosts file is unavailable."
    return 1
  fi
  remote_command="set -eu
source_state=\$(timeout --foreground 15s mysql --protocol=socket --user=hoseo --connect-timeout=10 --batch --raw --skip-column-names -e 'SELECT @@global.read_only,@@global.super_read_only')
printf 'ONPREM_WRITER_FENCE\\t%s\\n' \"\$source_state\""
  if ! output="$(timeout --foreground 75s ssh \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=0 \
      -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile="$known_hosts" -o GlobalKnownHostsFile=/dev/null \
      -o ConnectTimeout=45 -o ConnectionAttempts=1 \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
      -i "$key_path" hoseo@IP_REDACTED "$remote_command" 2>/dev/null)"; then
    echo "[SOURCE WRITE FENCE BLOCKED] On-Prem MySQL write state could not be verified."
    return 1
  fi
  line="$(printf '%s\n' "$output" | awk -F '\t' '$1 == "ONPREM_WRITER_FENCE" { print; count++ } END { if (count != 1) exit 1 }')" \
    || { echo "[SOURCE WRITE FENCE BLOCKED] On-Prem MySQL write-state response was invalid."; return 1; }
  [ "$(printf '%s\n' "$line" | awk -F '\t' '{ print NF }')" -eq 3 ] \
    || { echo "[SOURCE WRITE FENCE BLOCKED] On-Prem MySQL write-state response was incomplete."; return 1; }
  IFS=$'\t' read -r marker read_only super_read_only <<< "$line"
  if [ "$marker" != "ONPREM_WRITER_FENCE" ] || [ "$read_only" != "1" ] || [ "$super_read_only" != "1" ]; then
    echo "[SOURCE WRITE FENCE BLOCKED] On-Prem MySQL must be verified read_only=1 and super_read_only=1 before DR promotion."
    return 1
  fi
  echo "[SOURCE WRITE FENCE] On-Prem MySQL read_only=1 super_read_only=1 verified."
}

dr_onprem_failback_db_wrapper() {
  local request_id="$1" action="$2" remote_command output argument quoted
  local key_path="${ONPREM_SSH_KEY:-}" known_hosts="${ONPREM_SSH_KNOWN_HOSTS_FILE:-}"
  if ! [[ "$request_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
      || [ -z "$key_path" ] || [ ! -r "$key_path" ] \
      || [ -z "$known_hosts" ] || [ ! -r "$known_hosts" ]; then
    return 1
  fi
  remote_command="sudo -n /usr/local/sbin/hospital-dr-failback-db"
  for argument in "$action" "$request_id"; do
    printf -v quoted '%q' "$argument"
    remote_command+=" $quoted"
  done
  output="$(timeout --foreground 75s ssh \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=0 \
      -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile="$known_hosts" -o GlobalKnownHostsFile=/dev/null \
      -o ConnectTimeout=45 -o ConnectionAttempts=1 \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
      -i "$key_path" hoseo@IP_REDACTED "$remote_command" 2>/dev/null)" || return 1
  printf '%s\n' "$output"
}

dr_read_dr_replica_status() {
  local remote_script
  remote_script="$(cat <<'REMOTE'
set -euo pipefail
IFS= read -r MYSQL_ROOT_PASS || exit 70
defaults_file="$(mktemp /run/hospital-dr-nr-status.XXXXXX)"
trap 'rm -f "$defaults_file"' EXIT
chmod 0600 "$defaults_file"
printf '[client]\nuser=root\npassword=%s\n' "$MYSQL_ROOT_PASS" > "$defaults_file"
unset MYSQL_ROOT_PASS
mysql --defaults-extra-file="$defaults_file" -e 'SHOW REPLICA STATUS\G' 2>/dev/null \
  || mysql --defaults-extra-file="$defaults_file" -e 'SHOW SLAVE STATUS\G' 2>/dev/null
REMOTE
  )"
  dr_run_db_remote_with_secret "$remote_script"
}

dr_verify_nr_recovery_candidate() {
  local source_line source_marker source_uuid source_file source_position replica_status result
  local source_host="${DB_SOURCE_HOST:-}" source_port="${DB_SOURCE_PORT:-3306}"
  if [ "${DB_NR_ENABLED:-false}" != "true" ]; then
    echo "[DB RECOVERY] NR candidate blocked reason=nr_disabled"
    return 1
  fi
  if [ -z "$source_host" ] || ! [[ "$source_port" =~ ^[0-9]{1,5}$ ]] \
      || (( source_port < 1 || source_port > 65535 )); then
    echo "[DB RECOVERY] NR candidate blocked reason=source_endpoint_unconfigured"
    return 1
  fi
  if ! source_line="$(dr_read_onprem_source_coordinate)"; then
    echo "[DB RECOVERY] NR candidate blocked reason=onprem_binlog_status_unavailable"
    return 1
  fi
  IFS=$'\t' read -r source_marker source_uuid source_file source_position <<< "$source_line"
  if [ "$source_marker" != "ONPREM_SOURCE_COORD" ] \
      || [ "${source_uuid,,}" != "${ONPREM_DB_SERVER_UUID_EXPECTED,,}" ] \
      || ! [[ "$source_file" =~ ^[A-Za-z0-9._-]{1,128}$ ]] \
      || ! [[ "$source_position" =~ ^[1-9][0-9]{0,19}$ ]]; then
    echo "[DB RECOVERY] NR candidate blocked reason=onprem_binlog_identity_or_coordinate_invalid"
    return 1
  fi
  if ! replica_status="$(dr_read_dr_replica_status)"; then
    echo "[DB RECOVERY] NR candidate blocked reason=dr_replica_status_unavailable"
    return 1
  fi
  if result="$(printf '%s\n' "$replica_status" | python3 "$SCRIPT_DIR/../failover/nr_readiness.py" \
      --source-uuid "$source_uuid" --source-host "$source_host" --source-port "$source_port" \
      --source-log-file "$source_file" --source-log-position "$source_position" 2>/dev/null)"; then
    case "$result" in
      "NR_READINESS=VERIFIED "*)
        DR_RECOVERY_SELECTED_MODE=NR
        export DR_RECOVERY_SELECTED_MODE
        echo "[DB RECOVERY] $result"
        return 0
        ;;
    esac
  else
    case "$result" in
      "NR_READINESS=BLOCKED reason="*)
        echo "[DB RECOVERY] NR candidate blocked ${result#NR_READINESS=BLOCKED }"
        return 1
        ;;
    esac
  fi
  echo "[DB RECOVERY] NR candidate blocked reason=replica_readiness_response_invalid"
  return 1
}

dr_verify_dump_restore_candidate() {
  local request_id="${DR_FAILOVER_REQUEST_ID:-}"
  local backup_id="${DR_FAILOVER_DUMP_BACKUP_ID:-}" checksum="${DR_FAILOVER_DUMP_SHA256:-}"
  local sidecar_checksum="${DR_FAILOVER_DUMP_SIDECAR_SHA256:-}"
  local state_dir="${DEMO_DUMP_RESTORE_STATE_DIR:-${DR_STATE_DIR}/demo-dump-restores}"
  local receipt result
  local -a validator_args=()
  if ! [[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
      || [ -z "$backup_id" ] || [ -z "$checksum" ]; then
    echo "[DB RECOVERY] Dump candidate blocked reason=request_scoped_dump_receipt_unavailable"
    return 1
  fi
  receipt="$state_dir/$request_id/result.json"
  validator_args=(--dump-receipt "$receipt" --request-id "$request_id" --backup-id "$backup_id" --sha256 "$checksum")
  if [ -n "$sidecar_checksum" ]; then
    validator_args+=(--sidecar-sha256 "$sidecar_checksum")
  fi
  if ! result="$(python3 "$SCRIPT_DIR/../failover/nr_readiness.py" "${validator_args[@]}" 2>/dev/null)"; then
    case "$result" in
      "RECOVERY_STRATEGY=BLOCKED reason="*)
        echo "[DB RECOVERY] Dump candidate blocked ${result#RECOVERY_STRATEGY=BLOCKED }"
        ;;
      *) echo "[DB RECOVERY] Dump candidate blocked reason=approved_restore_receipt_invalid" ;;
    esac
    return 1
  fi
  case "$result" in
    "RECOVERY_STRATEGY=VERIFIED mode=DUMP "*)
      DR_RECOVERY_SELECTED_MODE=DUMP
      export DR_RECOVERY_SELECTED_MODE
      echo "[DB RECOVERY] $result"
      return 0
      ;;
  esac
  echo "[DB RECOVERY] Dump candidate blocked reason=approved_restore_response_invalid"
  return 1
}

dr_execute_approved_dump_fallback() {
  local request_id="${DR_FAILOVER_REQUEST_ID:-}"
  local backup_id="${DR_FAILOVER_DUMP_BACKUP_ID:-}"
  local checksum="${DR_FAILOVER_DUMP_SHA256:-}"
  local sidecar_checksum="${DR_FAILOVER_DUMP_SIDECAR_SHA256:-}"
  local authorization_id="${DR_FAILOVER_DUMP_AUTHORIZATION_ID:-}"
  local configured="${DUMP_RESTORE_EXECUTOR:-}"
  local expected="$SCRIPT_DIR/../db/demo_dump_restore_existing_dr.sh"
  local state_dir="${DEMO_DUMP_RESTORE_STATE_DIR:-${DR_STATE_DIR}/demo-dump-restores}"

  if ! [[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
      || ! [[ "$backup_id" =~ ^db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc$ ]] \
      || ! [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] \
      || ! [[ "$sidecar_checksum" =~ ^[0-9a-f]{64}$ ]] \
      || ! [[ "$authorization_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "[DB RECOVERY BLOCKED] Dump fallback request-bound candidate or authorization is missing."
    return 1
  fi
  if [ "$(dr_state_read)" != "FAILOVER_EXECUTING" ]; then
    echo "[DB RECOVERY BLOCKED] Dump fallback requires the current Failover execution state."
    return 1
  fi
  if [ "${DUMP_RESTORE_EXEC_ENABLED:-false}" != "true" ]; then
    echo "[DB RECOVERY BLOCKED] Request-approved Dump fallback is unavailable because its global executor gate is disabled."
    return 1
  fi
  if [ -z "$configured" ] || [ -L "$configured" ] || [ ! -x "$configured" ] \
      || [ -L "$expected" ] || [ ! -x "$expected" ] \
      || ! command -v realpath >/dev/null 2>&1 \
      || [ "$(realpath -e -- "$configured" 2>/dev/null || true)" != "$(realpath -e -- "$expected" 2>/dev/null || true)" ]; then
    echo "[DB RECOVERY BLOCKED] The configured Dump fallback executor is not the reviewed existing-DR restore wrapper."
    return 1
  fi
  if [ -z "${CHATOPS_STATE_DB:-}" ] || [ -z "${DUMP_BACKUP_DIR:-}" ] \
      || [ -e "$state_dir/$request_id" ] || [ -L "$state_dir/$request_id" ]; then
    echo "[DB RECOVERY BLOCKED] Approval state or single-use restore state is unavailable for this request."
    return 1
  fi

  # A restore is destructive even though it returns the DB to standby.
  # From this point any error requires operator review; automatic retry is forbidden.
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  export DR_STATE_FAILURE_STATUS
  echo "[DB RECOVERY] NR was not verified; attempting the exact two-admin-approved Dump fallback for request_id=$request_id."
  if ! DR_DUMP_FAILOVER_FALLBACK=1 DR_DUMP_FALLBACK_REQUEST_ID="$request_id" \
      "$configured" --failover-fallback --request-id "$request_id" \
      --backup-id "$backup_id" --expected-sha256 "$checksum"; then
    echo "[DB RECOVERY PARTIAL_FAILURE] Approved Dump fallback failed or its result is uncertain; no automatic retry will occur."
    return 1
  fi
  if ! dr_verify_dump_restore_candidate; then
    echo "[DB RECOVERY PARTIAL_FAILURE] Dump executor returned success but its same-request receipt did not verify."
    return 1
  fi
  echo "[DB RECOVERY] Conditional Dump fallback verified for the current Failover request."
}

dr_select_recovery_candidate() {
  local requested_mode="${DR_FAILOVER_RECOVERY_MODE:-AUTO}"
  local rpo_status="${DR_FAILOVER_RPO_STATUS:-}"
  if [ "$requested_mode" = "APPROVED_DUMP" ]; then
    dr_verify_dump_restore_candidate
    return $?
  fi
  if [ "$rpo_status" = "NOT_MEASURED" ] || [ "$rpo_status" = "EXCEEDED_900_SECONDS" ]; then
    if [ "${DR_EXISTING_DB_DATA_VERIFIED:-0}" != "1" ]; then
      echo "[DB RECOVERY BLOCKED] RPO=$rpo_status and existing DR DB patient data is not verified; DB_RECOVERY_SUCCESS=false."
      return 1
    fi
    DR_RECOVERY_SELECTED_MODE=EXISTING_DR_DATA
    export DR_RECOVERY_SELECTED_MODE
    echo "[DB RECOVERY] EXISTING_DR_DATA=VERIFIED; RPO=$rpo_status; possible_data_loss=true; two_admin_risk_acceptance=VERIFIED; no NR or Dump restore was performed."
    return 0
  fi
  case "$requested_mode" in
    AUTO)
      if dr_verify_nr_recovery_candidate; then
        return 0
      fi
      if dr_verify_dump_restore_candidate; then
        return 0
      fi
      if dr_execute_approved_dump_fallback && dr_verify_dump_restore_candidate; then
        return 0
      fi
      echo "[DB RECOVERY BLOCKED] No request-authorized NR or Dump recovery candidate is valid."
      return 1
      ;;
    *)
      echo "[DB RECOVERY BLOCKED] Unsupported recovery mode; no promotion is allowed."
      return 1
      ;;
  esac
}

dr_validate_running_dr_db_identity() {
  local inventory_json plan db_row web_running_row web_stopped_row doc_running_row doc_stopped_row
  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)"; then
    echo "[DB PROMOTION ERROR] Could not re-read AWS DR instance identities before promotion."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$SCRIPT_DIR/../runtime/ec2_start_plan.py")"; then
    echo "[DB PROMOTION ERROR] AWS DR instance identity/state revalidation failed."
    return 1
  fi
  db_row=$'Hospital-DR-DB-Server\ti-02c9a5dfdd791503b\trunning\tnone'
  web_running_row=$'Hospital-Real-Web-Server\ti-076072b45ae492e15\trunning\tnone'
  web_stopped_row=$'Hospital-Real-Web-Server\ti-076072b45ae492e15\tstopped\tstart'
  doc_running_row=$'Hospital-DR-Doc-Server\ti-03a64d7fd25895173\trunning\tnone'
  doc_stopped_row=$'Hospital-DR-Doc-Server\ti-03a64d7fd25895173\tstopped\tstart'
  if ! grep -Fqx -- "$db_row" <<< "$plan"; then
    echo "[DB PROMOTION ERROR] Approved AWS DR DB instance is not the running promotion target."
    return 1
  fi
  if { ! grep -Fqx -- "$web_running_row" <<< "$plan" && ! grep -Fqx -- "$web_stopped_row" <<< "$plan"; } \
      || { ! grep -Fqx -- "$doc_running_row" <<< "$plan" && ! grep -Fqx -- "$doc_stopped_row" <<< "$plan"; }; then
    echo "[DB PROMOTION ERROR] Approved DR Web and EMR must be in a stable running or stopped state."
    return 1
  fi
}

dr_promote_dr_database() {
  local before_probe after_probe remote_script
  local before_marker before_uuid before_hostname before_port before_read_only before_super_read_only before_schema before_select before_core_tables before_core_rows before_patient_rows
  local after_marker after_uuid after_hostname after_port after_read_only after_super_read_only after_schema after_select after_core_tables after_core_rows after_patient_rows

  require_config MYSQL_ROOT_PASS || return 1
  echo "[DB PROMOTION] Checking the approved AWS DR DB standby identity and state."
  dr_validate_running_dr_db_identity || return 1
  if ! before_probe="$(dr_db_mysql_probe)"; then
    echo "[DB PROMOTION ERROR] Could not verify the AWS DR DB before promotion."
    return 1
  fi
  IFS=$'\t' read -r before_marker before_uuid before_hostname before_port before_read_only before_super_read_only before_schema before_select before_core_tables before_core_rows before_patient_rows <<< "$before_probe"
  if [ "$before_marker" != "DB_PROMOTION_PROBE" ] \
      || ! [[ "$before_uuid" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] \
      || [ -z "$before_hostname" ] || [ "$before_port" != "3306" ] \
      || [ "$before_schema" != "1" ] || [ "$before_select" != "1" ]; then
    echo "[DB PROMOTION ERROR] AWS DR DB identity, schema, or SQL probe did not match the expected contract."
    return 1
  fi
  if [ "$before_read_only" != "1" ] || [ "$before_super_read_only" != "1" ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    echo "[DB PROMOTION PARTIAL_FAILURE] DR DB is not confirmed as read-only standby; operator review is required."
    return 1
  fi
  if [ "$before_core_tables" != "6" ] \
      || ! [[ "$before_core_rows" =~ ^[0-9]+$ ]] \
      || (( before_core_rows == 0 )) \
      || ! [[ "$before_patient_rows" =~ ^[0-9]+$ ]] \
      || (( before_patient_rows == 0 )); then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    DR_EXISTING_DB_DATA_VERIFIED=0
    export DR_EXISTING_DB_DATA_VERIFIED
    echo "[DB RECOVERY BLOCKED] Existing DR DB has no verified usable hospital patient data; RPO=${DR_FAILOVER_RPO_STATUS:-UNAVAILABLE}; DB_RECOVERY_SUCCESS=false and DR_ACTIVE will not be recorded."
    return 1
  fi
  DR_EXISTING_DB_DATA_VERIFIED=1
  DR_EXISTING_DB_CORE_TABLES="$before_core_tables"
  DR_EXISTING_DB_CORE_ROWS="$before_core_rows"
  export DR_EXISTING_DB_DATA_VERIFIED DR_EXISTING_DB_CORE_TABLES DR_EXISTING_DB_CORE_ROWS
  echo "[DB DATA] EXISTING_DR_DATA=VERIFIED core_tables=$before_core_tables patient_records=PRESENT."

  if ! dr_select_recovery_candidate; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    if [ "${DR_FAILOVER_RPO_STATUS:-}" = "NOT_MEASURED" ] \
        || [ "${DR_FAILOVER_RPO_STATUS:-}" = "EXCEEDED_900_SECONDS" ]; then
      echo "[DB PROMOTION BLOCKED] RPO=${DR_FAILOVER_RPO_STATUS:-UNAVAILABLE} and usable existing DR patient data was not verified; DB_RECOVERY_SUCCESS=false and DR_ACTIVE will not be recorded."
    else
      echo "[DB PROMOTION BLOCKED] No verified NR position or same-request approved Dump receipt; existing DR data will not be promoted."
    fi
    return 1
  fi
  echo "[DB PROMOTION] Selected verified recovery mode=${DR_RECOVERY_SELECTED_MODE}."

  # NR/Dump recovery evidence is rechecked immediately before making AWS writable.
  if [ "$DR_RECOVERY_SELECTED_MODE" = "DUMP" ] && ! dr_verify_dump_restore_candidate; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    echo "[DB PROMOTION PARTIAL_FAILURE] Same-request Dump restore receipt changed or is no longer valid."
    return 1
  fi

  # Any failure after this point leaves the writable state uncertain.
  DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
  echo "[DB PROMOTION] Running the existing db_promote_dr.sh on the verified dr-db SSM/SSH target."
  case "${DR_RECOVERY_SELECTED_MODE:-}" in
    NR|DUMP|EXISTING_DR_DATA) ;;
    *)
      echo "[DB PROMOTION BLOCKED] Verified recovery mode is missing or unsupported; DR writes remain blocked."
      return 1
      ;;
  esac
  remote_script="$(cat <<'REMOTE'
set -euo pipefail
IFS= read -r MYSQL_ROOT_PASS || exit 70
DR_RECOVERY_SELECTED_MODE=__RECOVERY_MODE__
export DR_RECOVERY_SELECTED_MODE
export MYSQL_ROOT_PASS
test -r /home/ubuntu/scripts/db_promote_dr.sh
exec /bin/bash /home/ubuntu/scripts/db_promote_dr.sh
REMOTE
  )"
  remote_script="${remote_script//__RECOVERY_MODE__/$DR_RECOVERY_SELECTED_MODE}"
  if ! dr_run_db_remote_with_secret "$remote_script"; then
    echo "[DB PROMOTION PARTIAL_FAILURE] Promotion command failed or its result is uncertain."
    return 1
  fi

  if ! after_probe="$(dr_db_mysql_probe)"; then
    echo "[DB PROMOTION PARTIAL_FAILURE] Could not verify the DR DB after its MySQL restart."
    return 1
  fi
  IFS=$'\t' read -r after_marker after_uuid after_hostname after_port after_read_only after_super_read_only after_schema after_select after_core_tables after_core_rows after_patient_rows <<< "$after_probe"
  if [ "$after_marker" != "DB_PROMOTION_PROBE" ] \
      || [ "$after_uuid" != "$before_uuid" ] \
      || [ "$after_hostname" != "$before_hostname" ] \
      || [ "$after_port" != "$before_port" ] \
      || [ "$after_port" != "3306" ] \
      || [ "$after_read_only" != "0" ] \
      || [ "$after_super_read_only" != "0" ] \
      || [ "$after_schema" != "1" ] || [ "$after_select" != "1" ] \
      || [ "$after_core_tables" != "6" ] \
      || ! [[ "$after_core_rows" =~ ^[0-9]+$ ]] \
      || (( after_core_rows == 0 )) \
      || ! [[ "$after_patient_rows" =~ ^[0-9]+$ ]] \
      || (( after_patient_rows == 0 )); then
    echo "[DB PROMOTION PARTIAL_FAILURE] Post-restart identity, writable state, or usable hospital data verification failed."
    return 1
  fi

  echo "[DB PROMOTION] Same DR DB identity verified after restart; read_only=0 super_read_only=0; hospital_db core data remains present."
  if [ "$DR_RECOVERY_SELECTED_MODE" = "EXISTING_DR_DATA" ]; then
    echo "[DB RECOVERY] DB_RECOVERY=NOT_PERFORMED; DB_DATA=VERIFIED from existing AWS DR; RPO=${DR_FAILOVER_RPO_STATUS:-UNAVAILABLE}; possible_data_loss=true; two_admin_risk_acceptance=VERIFIED."
  else
    echo "[DB RECOVERY] DB_RECOVERY=VERIFIED mode=$DR_RECOVERY_SELECTED_MODE."
  fi
}

dr_verify_web_nat_instance_ready() {
  local output="$1" status mode
  status="$(printf '%s\n' "$output" | awk -F= '
    $1 == "NAT_INSTANCE_STATUS" { count++; value=$2 }
    END { if (count == 1) print value; else exit 1 }
  ')" || status="UNKNOWN"
  mode="$(printf '%s\n' "$output" | awk -F= '
    $1 == "CURRENT_EGRESS_MODE" { count++; value=$2 }
    END { if (count == 1) print value; else exit 1 }
  ')" || mode="UNKNOWN"
  if [ "$status" != "READY" ] || [ "$mode" != "WEB_NAT_INSTANCE" ]; then
    echo "[NAT VALIDATION ERROR] Egress is not verified ready; status=${status:-UNKNOWN} mode=${mode:-UNKNOWN}."
    return 1
  fi
  return 0
}

dr_verify_web_nat_bootstrap_ready() {
  local output="$1" key expected value
  local -a required=(
    'NAT_BOOTSTRAP_STATUS=READY_FOR_GUEST_CONFIGURATION'
    'NAT_INSTANCE_STATUS=PENDING_LIVE_TEST'
    'CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE_CANDIDATE'
    'WEB_INSTANCE_STATE=running'
    'WEB_PRIVATE_IP=IP_REDACTED'
    'WEB_PUBLIC_IP=AWS_PUBLIC_IP_REDACTED'
    'WEB_VPC_ID=AWS_RESOURCE_ID_REDACTED'
    'WEB_SUBNET_ID=AWS_RESOURCE_ID_REDACTED'
    'WEB_ENI=AWS_RESOURCE_ID_REDACTED'
    'WEB_EIP_PUBLIC_IP=AWS_PUBLIC_IP_REDACTED'
    'WEB_EIP_INSTANCE_ID=AWS_RESOURCE_ID_REDACTED'
    'WEB_EIP_ENI=AWS_RESOURCE_ID_REDACTED'
    'WEB_EIP_PRIVATE_IP=AWS_PUBLIC_IP_REDACTED'
    'SOURCE_DEST_CHECK=False'
    'PRIVATE_ROUTE_TABLE=AWS_RESOURCE_ID_REDACTED'
    'PRIVATE_DEFAULT_ROUTE_STATE=active'
    'PRIVATE_DEFAULT_ROUTE_TARGET=AWS_RESOURCE_ID_REDACTED'
  )
  local association

  for expected in "${required[@]}"; do
    key="${expected%%=*}"
    value="$(printf '%s\n' "$output" | awk -F= -v wanted="$key" '
      $1 == wanted { count++; value=$2; gsub(/\r/, "", value) }
      END { if (count == 1) print value; else exit 1 }
    ')" || value=""
    if [ "$value" != "${expected#*=}" ]; then
      echo "[NAT BOOTSTRAP BLOCKED] AWS identity/route readback mismatch at ${key}."
      return 1
    fi
  done
  association="$(printf '%s\n' "$output" | awk -F= '
    $1 == "WEB_EIP_ASSOCIATION" { count++; value=$2; gsub(/\r/, "", value) }
    END { if (count == 1) print value; else exit 1 }
  ')" || association=""
  if ! [[ "$association" =~ ^eipassoc-[0-9a-f]+$ ]]; then
    echo "[NAT BOOTSTRAP BLOCKED] Web EIP association is missing or ambiguous."
    return 1
  fi
  return 0
}

dr_check_web_nat_aws_candidate() {
  local expected_status configured_status output rc
  expected_status="$(realpath -e -- "$SCRIPT_DIR/../nat_instance/web_nat_instance_status.sh" 2>/dev/null || true)"
  configured_status="$(realpath -e -- "$NAT_INSTANCE_STATUS_SCRIPT" 2>/dev/null || true)"
  if [ ! -f "$NAT_INSTANCE_STATUS_SCRIPT" ] || [ ! -x "$NAT_INSTANCE_STATUS_SCRIPT" ] \
    || [ -z "$expected_status" ] || [ "$configured_status" != "$expected_status" ]; then
    echo "[NAT BOOTSTRAP BLOCKED] Canonical AWS read-only NAT status verifier is missing or not executable."
    return 1
  fi
  if output="$(timeout --foreground --signal=TERM --kill-after=5s 60s \
      env AWS_REGION="$REGION" "$NAT_INSTANCE_STATUS_SCRIPT" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 2 ] || ! dr_verify_web_nat_bootstrap_ready "$output"; then
    echo "[NAT BOOTSTRAP BLOCKED] AWS Web identity, EIP, ENI, Source/Dest Check, or private route readback is not the approved live candidate."
    return 1
  fi
  echo "[NAT BOOTSTRAP] AWS identity, Web EIP association, Source/Dest Check, and active route target verified; guest NAT remains separate."
}

dr_verify_web_nat_guest_ready() {
  local output="$1" status
  status="$(printf '%s\n' "$output" | awk -F= '
    $1 == "NAT_GUEST_STATUS" { count++; value=$2; gsub(/\r/, "", value) }
    END { if (count == 1) print value; else exit 1 }
  ')" || status="UNKNOWN"
  if [ "$status" != "READY" ]; then
    echo "[NAT VALIDATION ERROR] Web guest forwarding, persistent service, or owned firewall rules are not verified; status=${status:-UNKNOWN}."
    return 1
  fi
  return 0
}

dr_nat_emr_ingress_rule_present() {
  local security_group_json="$1" expected_group_id="$2" expected_vpc_id="$3" expected_group_name="$4" port="$5" source_cidr="$6"
  DR_NAT_SECURITY_GROUP_JSON="$security_group_json" python3 - "$expected_group_id" "$expected_vpc_id" "$expected_group_name" "$port" "$source_cidr" <<'PY'
import json
import os
import sys

try:
    expected_group, expected_vpc, expected_name, expected_port, source_cidr = sys.argv[1:]
    document = json.loads(os.environ["DR_NAT_SECURITY_GROUP_JSON"])
    groups = document.get("SecurityGroups", [])
    if len(groups) != 1:
        raise ValueError("security group result is missing or ambiguous")
    group = groups[0]
    if (group.get("GroupId") != expected_group or group.get("VpcId") != expected_vpc
            or group.get("GroupName") != expected_name):
        raise ValueError("security group identity changed")
    for permission in group.get("IpPermissions", []):
        if (permission.get("IpProtocol") == "tcp"
                and str(permission.get("FromPort")) == expected_port
                and str(permission.get("ToPort")) == expected_port
                and any(row.get("CidrIp") == source_cidr
                        for row in permission.get("IpRanges", []))):
            raise SystemExit(0)
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    pass
raise SystemExit(1)
PY
}

dr_ensure_web_nat_emr_ingress() {
  local web_instance_id="$1" doc_instance_id="$2" db_promotion_verified="$3"
  local request_id="${DR_FAILOVER_REQUEST_ID:-}" instance_json security_group_ids web_sg_id security_group_json port

  if [ "$SKIP_DNS" = "true" ] || [ "$db_promotion_verified" != "1" ] \
    || [ "$(dr_state_read)" != "FAILOVER_EXECUTING" ] \
    || ! [[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "[NAT SG BLOCKED] A live approved Failover with verified DB promotion is required before changing the existing Web security group."
    return 1
  fi
  if ! instance_json="$(aws ec2 describe-instances --region "$REGION" \
      --instance-ids "$web_instance_id" "$doc_instance_id" --output json)"; then
    echo "[NAT SG BLOCKED] Could not read the exact approved Web and EMR instance identities."
    return 1
  fi
  if ! security_group_ids="$(DR_NAT_INSTANCE_JSON="$instance_json" python3 - "$web_instance_id" "$doc_instance_id" <<'PY'
import json
import os
import sys

expected = {
    sys.argv[1]: ("Hospital-Real-Web-Server", "AWS_PUBLIC_IP_REDACTED", "AWS_RESOURCE_ID_REDACTED", "running"),
    sys.argv[2]: ("Hospital-DR-Doc-Server", "AWS_PUBLIC_IP_REDACTED", "AWS_RESOURCE_ID_REDACTED", "stopped"),
}
try:
    rows = [row for reservation in json.loads(os.environ["DR_NAT_INSTANCE_JSON"]).get("Reservations", [])
            for row in reservation.get("Instances", [])]
    web_sg_id = None
    for instance_id, (name, private_ip, subnet, expected_state) in expected.items():
        matches = [row for row in rows if row.get("InstanceId") == instance_id]
        if len(matches) != 1:
            raise ValueError("instance missing or ambiguous")
        row = matches[0]
        tags = {tag.get("Key"): tag.get("Value") for tag in row.get("Tags", [])}
        if (row.get("State", {}).get("Name") != expected_state
                or tags.get("Name") != name
                or row.get("PrivateIpAddress") != private_ip
                or row.get("VpcId") != "AWS_RESOURCE_ID_REDACTED"
                or row.get("SubnetId") != subnet):
            raise ValueError("instance identity or state changed")
        if instance_id == sys.argv[1]:
            candidates = [group.get("GroupId") for group in row.get("SecurityGroups", [])
                          if group.get("GroupName") == "hospital-dr-web-sg"]
            if len(candidates) != 1:
                raise ValueError("expected Web security group missing or ambiguous")
            web_sg_id = candidates[0]
    if not web_sg_id:
        raise ValueError("expected Web security group missing")
    print(web_sg_id)
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
PY
)"; then
    echo "[NAT SG BLOCKED] Web must be running and EMR stopped before NAT setup; instance IDs, private IPs, VPC, or subnets did not match."
    return 1
  fi
  web_sg_id="$security_group_ids"
  if ! [[ "$web_sg_id" =~ ^sg-[0-9a-f]+$ ]]; then
    echo "[NAT SG BLOCKED] The existing Web security group identity is invalid."
    return 1
  fi
  if ! security_group_json="$(aws ec2 describe-security-groups --region "$REGION" \
      --group-ids "$web_sg_id" --output json)"; then
    echo "[NAT SG BLOCKED] Could not read the existing Web security-group rules."
    return 1
  fi
  for port in 80 443; do
    if dr_nat_emr_ingress_rule_present "$security_group_json" "$web_sg_id" \
        "AWS_RESOURCE_ID_REDACTED" "hospital-dr-web-sg" "$port" "AWS_PUBLIC_IP_REDACTED/24"; then
      continue
    fi
    if ! aws ec2 authorize-security-group-ingress --region "$REGION" \
        --group-id "$web_sg_id" --protocol tcp --port "$port" \
        --cidr "IP_REDACTED/24" >/dev/null 2>&1; then
      security_group_json="$(aws ec2 describe-security-groups --region "$REGION" \
        --group-ids "$web_sg_id" --output json 2>/dev/null || true)"
      if ! dr_nat_emr_ingress_rule_present "$security_group_json" "$web_sg_id" \
          "AWS_RESOURCE_ID_REDACTED" "hospital-dr-web-sg" "$port" "AWS_PUBLIC_IP_REDACTED/24"; then
        echo "[NAT SG ERROR] Could not authorize TCP $port from the existing DR EMR subnet to the existing Web NAT instance."
        return 1
      fi
    fi
    security_group_json="$(aws ec2 describe-security-groups --region "$REGION" \
      --group-ids "$web_sg_id" --output json)" || {
      echo "[NAT SG ERROR] Could not read back the existing Web security-group rule after authorization."
      return 1
    }
    if ! dr_nat_emr_ingress_rule_present "$security_group_json" "$web_sg_id" \
        "AWS_RESOURCE_ID_REDACTED" "hospital-dr-web-sg" "$port" "AWS_PUBLIC_IP_REDACTED/24"; then
      echo "[NAT SG ERROR] TCP $port from the existing DR EMR subnet did not pass Web security-group readback."
      return 1
    fi
  done
  echo "[NAT SG] Existing Web security group permits only TCP 80/443 from the existing DR EMR subnet for NAT forwarding."
}

dr_verify_private_nat_egress() {
  local observed_ip
  if ! observed_ip="$(dr_ssm_ssh dr-doc 'curl --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com/' 2>/dev/null | tr -d '\r\n')"; then
    echo "[NAT VALIDATION ERROR] Private-subnet HTTPS egress probe failed from EMR."
    return 1
  fi
  if [ "$observed_ip" != "$DR_WEB_EIP_EXPECTED" ]; then
    echo "[NAT VALIDATION ERROR] Private-subnet egress did not use the approved Web EIP."
    return 1
  fi
  echo "[NAT VALIDATION] EMR private-subnet egress matched the approved Web EIP."
}

dr_ssm_instance_online_once() {
  local instance_id="$1" response
  if ! response="$(timeout --foreground 12s aws ssm describe-instance-information \
      --region "$REGION" --filters "Key=InstanceIds,Values=$instance_id" \
      --output json --cli-connect-timeout 4 --cli-read-timeout 7 2>/dev/null)"; then
    return 2
  fi
  SSM_INSTANCE_INFO_JSON="$response" python3 - "$instance_id" <<'PY'
import json
import os
import sys

try:
    expected = sys.argv[1]
    rows = json.loads(os.environ["SSM_INSTANCE_INFO_JSON"]).get("InstanceInformationList", [])
    matches = [row for row in rows if row.get("InstanceId") == expected]
    if len(matches) != 1:
        raise ValueError("instance record missing or ambiguous")
    ok = matches[0].get("PingStatus") == "Online"
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    ok = False
raise SystemExit(0 if ok else 1)
PY
}

dr_wait_for_ssm_instance_online() {
  local instance_id="$1" label="$2" attempts="${3:-18}" interval="${4:-5}" attempt rc
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if dr_ssm_instance_online_once "$instance_id"; then
      echo "[SSM] $label is Online for the exact approved instance ID."
      return 0
    else
      rc=$?
    fi
    if [ "$rc" -eq 2 ]; then
      echo "[SSM BLOCKED] Read-only SSM status query failed for $label."
      return 1
    fi
    if [ "$attempt" -lt "$attempts" ]; then sleep "$interval"; fi
  done
  echo "[SSM BLOCKED] $label did not become Online within the readiness window."
  return 1
}

dr_validate_web_nat_ansible_target() {
  local instance_id="$1"
  python3 - "$INVENTORY" "$DR_SSH_CONFIG_FILE" "$DR_ANSIBLE_SOURCE_DIR/ansible.cfg" "$instance_id" <<'PY'
import configparser
import os
import shlex
import shutil
import sys
from pathlib import Path

inventory_path = Path(sys.argv[1])
ssh_config_path = Path(sys.argv[2])
ansible_config_path = Path(sys.argv[3])
expected_instance = sys.argv[4]

try:
    inventory_text = inventory_path.read_text(encoding="utf-8")
    ssh_text = ssh_config_path.read_text(encoding="utf-8")
    ansible_config_text = ansible_config_path.read_text(encoding="utf-8")
except OSError:
    raise SystemExit(1)

group = None
web_hosts = []
for raw in inventory_text.splitlines():
    line = raw.strip()
    if not line or line.startswith(("#", ";")):
        continue
    if line.startswith("[") and line.endswith("]"):
        group = line[1:-1]
        continue
    if group == "web_servers":
        try:
            fields = shlex.split(line)
        except ValueError:
            raise SystemExit(1)
        if not fields:
            raise SystemExit(1)
        values = {}
        for item in fields[1:]:
            if "=" in item:
                key, value = item.split("=", 1)
                values[key] = value
        web_hosts.append((fields[0], values))

if len(web_hosts) != 1 or web_hosts[0][0] != "dr-web":
    raise SystemExit(1)
host_vars = web_hosts[0][1]
if host_vars.get("ansible_connection") != "ssh" or host_vars.get("ansible_host") != "dr-web" \
        or host_vars.get("ansible_user") != "ubuntu":
    raise SystemExit(1)
if host_vars.get("ansible_ssh_common_args", "").split() != ["-F", str(ssh_config_path)]:
    raise SystemExit(1)

directives = {}
matches = False
for raw in ssh_text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    try:
        fields = shlex.split(line, comments=True)
    except ValueError:
        raise SystemExit(1)
    if not fields:
        continue
    key = fields[0].lower()
    if key == "host":
        matches = "dr-web" in fields[1:]
        continue
    if matches and len(fields) >= 2:
        directives[key] = fields[1:]

proxy = directives.get("proxycommand", [])
known_hosts = directives.get("userknownhostsfile", [])
identity = directives.get("identityfile", [])
try:
    target_index = proxy.index("--target")
    target_ok = target_index + 1 < len(proxy) and proxy[target_index + 1] == expected_instance
except ValueError:
    target_ok = False
aws_cli = shutil.which("aws")
try:
    aws_proxy_ok = bool(aws_cli) and Path(proxy[0]).resolve() == Path(aws_cli).resolve()
except (IndexError, OSError):
    aws_proxy_ok = False

inventory_key = host_vars.get("ansible_ssh_private_key_file", "")
try:
    key_match = os.path.realpath(inventory_key) == os.path.realpath(identity[0])
except (IndexError, OSError):
    key_match = False

try:
    parser = configparser.ConfigParser()
    parser.read_string(ansible_config_text)
    host_key_checking = parser.getboolean("defaults", "host_key_checking")
    ssh_args = parser.get("ssh_connection", "ssh_args")
except (configparser.Error, ValueError):
    host_key_checking = False
    ssh_args = ""
if "stricthostkeychecking=no" in ssh_args.lower() or "userknownhostsfile=/dev/null" in ssh_args.lower():
    host_key_checking = False

ok = (
    directives.get("hostname") == [expected_instance]
    and aws_proxy_ok and "ssm" in proxy and "start-session" in proxy and target_ok
    and directives.get("stricthostkeychecking", [""])[0].lower() in {"yes", "accept-new"}
    and directives.get("batchmode", [""])[0].lower() == "yes"
    and directives.get("identitiesonly", [""])[0].lower() == "yes"
    and len(known_hosts) == 1 and known_hosts[0] != "/dev/null"
    and key_match
    and host_key_checking
)
raise SystemExit(0 if ok else 1)
PY
}

dr_apply_web_nat_role() {
  local web_instance_id="$1" db_promotion_verified="$2"
  local playbook="$DR_ANSIBLE_SOURCE_DIR/aws_web_nat_instance.yml"
  local ansible_config="$DR_ANSIBLE_SOURCE_DIR/ansible.cfg"
  local expected_playbook="$SCRIPT_DIR/../../automation/ansible/aws_web_nat_instance.yml"
  local expected_ansible_config="$SCRIPT_DIR/../../automation/ansible/ansible.cfg"
  local configured_real expected_real configured_config_real expected_config_real
  local request_id="${DR_FAILOVER_REQUEST_ID:-}"
  local apply_timeout="${DR_WEB_NAT_APPLY_TIMEOUT_SECONDS:-300}"

  if [ "$SKIP_DNS" = "true" ] || [ "$db_promotion_verified" != "1" ] \
    || [ "$(dr_state_read)" != "FAILOVER_EXECUTING" ] \
    || ! [[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ! [[ "$apply_timeout" =~ ^[0-9]{2,3}$ ]] \
    || (( 10#$apply_timeout < 30 || 10#$apply_timeout > 600 )); then
    echo "[NAT ROLE BLOCKED] Approved request, verified DB promotion, or production execution state is missing."
    return 1
  fi
  if ! command -v ansible-playbook >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1 \
    || [ ! -f "$playbook" ] || [ -L "$playbook" ] \
    || [ ! -f "$ansible_config" ] || [ -L "$ansible_config" ] \
    || [ ! -f "$INVENTORY" ] || [ -L "$INVENTORY" ] \
    || [ ! -f "$DR_SSH_CONFIG_FILE" ] || [ -L "$DR_SSH_CONFIG_FILE" ]; then
    echo "[NAT ROLE BLOCKED] Reviewed Ansible playbook, inventory, SSM SSH config, or timeout runtime is unavailable."
    return 1
  fi
  configured_real="$(realpath -e -- "$playbook" 2>/dev/null || true)"
  expected_real="$(realpath -e -- "$expected_playbook" 2>/dev/null || true)"
  configured_config_real="$(realpath -e -- "$ansible_config" 2>/dev/null || true)"
  expected_config_real="$(realpath -e -- "$expected_ansible_config" 2>/dev/null || true)"
  if [ -z "$expected_real" ] || [ "$configured_real" != "$expected_real" ] \
    || [ -z "$expected_config_real" ] || [ "$configured_config_real" != "$expected_config_real" ] \
    || ! dr_validate_web_nat_ansible_target "$web_instance_id"; then
    echo "[NAT ROLE BLOCKED] Ansible target is not the exact approved Web instance over its SSM transport."
    return 1
  fi

  echo "[NAT ROLE APPLY] request_id=$request_id instance_id=$web_instance_id transport=SSM limit=web_servers"
  if ! PYTHONNOUSERSITE=1 AWS_WEB_NAT_INSTANCE_ENABLED=true ANSIBLE_CONFIG="$ansible_config" \
      timeout --foreground --signal=TERM --kill-after=10s \
      "${apply_timeout}s" \
      ansible-playbook -i "$INVENTORY" "$playbook" --limit web_servers \
      -e aws_web_nat_instance_enabled=true \
      -e aws_web_nat_instance_action=apply \
      -e "aws_web_nat_instance_expected_instance_id=$web_instance_id" \
      -e aws_web_nat_instance_expected_private_ip=AWS_PUBLIC_IP_REDACTED \
      -e aws_web_nat_instance_expected_vpc_id=AWS_RESOURCE_ID_REDACTED \
      -e aws_web_nat_instance_expected_subnet_id=AWS_RESOURCE_ID_REDACTED \
      -e aws_web_nat_instance_expected_eni=AWS_RESOURCE_ID_REDACTED; then
    echo "[NAT ROLE PARTIAL_FAILURE] phase=web_nat_role_apply request_id=$request_id instance_id=$web_instance_id; stop before EMR, DNS, and DR_ACTIVE."
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    return 1
  fi
  echo "[NAT ROLE APPLY] RESULT=SUCCESS request_id=$request_id instance_id=$web_instance_id; guest and AWS readback still required."
}

verify_dr_application_db_endpoint() {
  local target="$1" container="$2"
  dr_ssm_ssh "$target" "set -eu
sudo docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' '$container' \\
  | awk -F= -v expected_host=IP_REDACTED -v expected_port=3306 '
      \$1 == \"DB_HOST\" { host=\$2; host_count++ }
      \$1 == \"DB_PORT\" { port=\$2; port_count++ }
      END { exit !(host_count == 1 && port_count == 1 && host == expected_host && port == expected_port) }'
"
}

fence_dr_application_container() {
  local target="$1" container="$2" script output
  script='set -eu
container=__CONTAINER__
sudo docker stop --time 20 "$container" >/dev/null 2>&1 || true
test "$(sudo docker inspect --format "{{.State.Running}}" "$container")" = false
printf "APP_CONTAINER_FENCED=%s\\n" "$container"
'
  script="${script//__CONTAINER__/$container}"
  output="$(dr_ssm_ssh "$target" "$script")" || return 1
  [ "$output" = "APP_CONTAINER_FENCED=$container" ]
}

start_environment() {
  local ids web_instance_id web_ip db_instance_id doc_instance_id web_role_state doc_role_state
  local web_health_code emr_health_code
  local ids_count instance_list inventory_json plan role instance_id state action
  local web_plan_row doc_plan_row db_plan_row
  local lifecycle_waited=0
  local DR_EC2_RECHECK_APPROVAL_ON_WAIT=1
  local -a pending_ids=() stopping_ids=()
  local plan_script="$SCRIPT_DIR/../runtime/ec2_start_plan.py"
  dr_verify_chatops_failover_launch || return 1
  if [ "$SECRET_CONFIG_READY" != "true" ]; then
    echo "[CONFIG ERROR] DR_SECRET_FILE is missing or unreadable."
    return 1
  fi
  if ! dr_resolve_ssh_key_config || ! dr_validate_ssh_key_files; then
    return 1
  fi
  case "$(dr_state_read)" in
    IDLE|FAILED) ;;
    *)
      echo "[START BLOCKED] Failover is allowed only from IDLE or safely retryable FAILED state."
      return 1
      ;;
  esac
  if ! instance_list="$(instance_ids)"; then
    echo "[START ERROR] Failed to list DR EC2 instances."
    echo "[시작 오류] DR EC2 인스턴스 목록을 조회하지 못했습니다."
    return 1
  fi
  mapfile -t ids <<< "$instance_list"
  ids_count=$(printf '%s\n' "${ids[@]}" | sed '/^$/d' | wc -l)
  if [ "$ids_count" -ne 3 ]; then
    echo "[START ERROR] Expected three DR instances but found $ids_count. Run '$0 provision' first."
    echo "[시작 오류] DR 인스턴스 3대가 필요하지만 $ids_count대만 확인됐습니다. 먼저 '$0 provision'을 실행하십시오."
    return 1
  fi

  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)"; then
    echo "[START ERROR] Failed to read the tagged DR EC2 inventory."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")"; then
    echo "[START ERROR] DR instance identity/state validation failed."
    return 1
  fi
  pending_ids=()
  stopping_ids=()
  while IFS=$'\t' read -r role instance_id state action; do
    case "$state" in
      pending) pending_ids+=("$instance_id") ;;
      stopping) stopping_ids+=("$instance_id") ;;
    esac
  done <<< "$plan"
  if ((${#stopping_ids[@]})); then
    if ! dr_ec2_wait_stopping_instances "$REGION" "${stopping_ids[@]}"; then
      echo "[START BLOCKED] EC2 stop transition did not settle; no DR services were started."
      return 1
    fi
    lifecycle_waited=1
  fi
  for instance_id in "${pending_ids[@]}"; do
    echo "[START] Waiting for the already-pending instance: $instance_id"
    aws ec2 wait instance-running --region "$REGION" --instance-ids "$instance_id"
    lifecycle_waited=1
  done
  if [ "$lifecycle_waited" = "1" ]; then
    inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)" || return 1
    plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")" || return 1
    if grep -Eq $'\t(pending|stopping)\t' <<< "$plan"; then
      echo "[START BLOCKED] EC2 lifecycle state did not settle; rerun after AWS reports stable states."
      return 1
    fi
    dr_verify_chatops_failover_launch || return 1
    echo "[START] Approved request and exact DR instance inventory reverified after lifecycle wait."
  fi
  db_instance_id="$(awk -F '\t' '$1 == "Hospital-DR-DB-Server" {print $2}' <<< "$plan")"
  web_instance_id="$(awk -F '\t' '$1 == "Hospital-Real-Web-Server" {print $2}' <<< "$plan")"
  doc_instance_id="$(awk -F '\t' '$1 == "Hospital-DR-Doc-Server" {print $2}' <<< "$plan")"
  web_role_state="$(awk -F '\t' '$1 == "Hospital-Real-Web-Server" {print $3}' <<< "$plan")"
  doc_role_state="$(awk -F '\t' '$1 == "Hospital-DR-Doc-Server" {print $3}' <<< "$plan")"
  if [[ "$web_role_state" != "stopped" && "$web_role_state" != "running" ]] \
    || [[ "$doc_role_state" != "stopped" && "$doc_role_state" != "running" ]]; then
    echo "[START BLOCKED] Web/EMR EC2 states must be stable; app writes are fenced at container level."
    return 1
  fi
  mapfile -t ids < <(awk -F '\t' '{print $2}' <<< "$plan")

  require_config "SSH_KEY"
  if ! dr_ssm_require_tools; then
    echo "[START ERROR] SSM SSH tools are required; direct SSH fallback is disabled."
    return 1
  fi
  if ! dr_prepare_ssh_known_hosts; then
    return 1
  fi

  if [ "$SKIP_DNS" != "true" ]; then
    require_config "CF_ZONE_ID"
    prepare_dns_snapshot
    if [ "$(dr_dns_snapshot_id "$DNS_TX_DIR/web.json")" != "$DR_CF_WEB_RECORD_ID_EXPECTED" ] \
      || [ "$(dr_dns_snapshot_id "$DNS_TX_DIR/emr.json")" != "$DR_CF_EMR_RECORD_ID_EXPECTED" ]; then
      echo "[DNS ERROR] Cloudflare Web/EMR record IDs do not match the approved pair."
      return 1
    fi
    if ! dr_dns_validate_origin_pair \
        "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
        "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED"; then
      echo "[DNS ERROR] Current Cloudflare DNS is not the approved On-Prem origin pair."
      return 1
    fi
    if ! dr_dns_preserve_origin_pair \
        "$DNS_TX_DIR" "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
        "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" "$ONPREM_EMR_DNS_IP_EXPECTED"; then
      echo "[DNS ERROR] A verified rollback snapshot is unavailable or conflicts with current DNS."
      return 1
    fi
    if ! dr_dns_validate_aws_web_eip_association \
        "$DR_WEB_EIP_EXPECTED" "$DR_WEB_EIP_EXPECTED" "$REGION"; then
      echo "[START ERROR] Approved AWS Web EIP is not associated with the expected Web instance."
      return 1
    fi
  fi

  # FAILED can be retried only after a read-back proves the current DNS and
  # persistent rollback snapshot are exactly the approved On-Prem pair.
  dr_state_write FAILOVER_EXECUTING
  DR_STATE_TRANSITION_STARTED=1
  dr_state_flag_clear

  echo "[DR START] Reusing running instances and starting stopped instances only; app containers are fenced before DB promotion."
  if ! dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-DR-DB-Server"; then
    echo "[AWS VALIDATION ERROR] Approved DR DB start request failed."
    return 1
  fi
  if ! aws ec2 wait instance-running --region "$REGION" --instance-ids "$db_instance_id"; then
    echo "[AWS VALIDATION ERROR] Approved DR DB instance did not reach running state."
    return 1
  fi
  if ! aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$db_instance_id"; then
    echo "[AWS VALIDATION ERROR] Approved DR DB instance status checks did not pass."
    return 1
  fi
  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" --output json)"; then
    echo "[AWS VALIDATION ERROR] Could not re-read the approved DR instance set after DB start."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")"; then
    echo "[AWS VALIDATION ERROR] DR instance identity verification failed after DB start."
    return 1
  fi
  if ! grep -Fqx -- $'Hospital-DR-DB-Server\t'"$db_instance_id"$'\trunning\tnone' <<< "$plan"; then
    echo "[AWS VALIDATION ERROR] Approved DR DB identity/state did not read back as running."
    return 1
  fi

  # If EMR is already running while Web is stopped, start the existing Web
  # gateway first so the current SSM jump path can fence EMR before promotion.
  if [ "$doc_role_state" = "running" ] && [ "$web_role_state" = "stopped" ]; then
    echo "[APP WRITE FENCE] Starting the stopped Web gateway to fence the already-running EMR app; EC2 is never stopped."
    if ! dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-Real-Web-Server"; then
      echo "[APPLICATION BLOCKED] Existing Web gateway could not be started for app-level fencing."
      return 1
    fi
    if ! aws ec2 wait instance-running --region "$REGION" --instance-ids "$web_instance_id"; then
      echo "[APPLICATION BLOCKED] Existing Web gateway did not reach running state for app-level fencing."
      return 1
    fi
    inventory_json="$(aws ec2 describe-instances --region "$REGION" --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" --output json)" || return 1
    plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")" || return 1
    web_role_state="running"
  fi
  if ! dr_ssm_write_ssh_config "$REGION" "$web_instance_id" "$SSH_KEY" "$DR_SSH_KNOWN_HOSTS_FILE" "${DR_DOC_PRIVATE_IP:-AWS_PUBLIC_IP_REDACTED}" "AWS_PUBLIC_IP_REDACTED" "$db_instance_id"; then
    return 1
  fi
  echo "[SSM SSH] DB management uses its verified SSM target; running Web and EMR app containers are fenced before promotion."
  if [ "$SKIP_DNS" != "true" ]; then
    if ! dr_ssm_wait_for_ssh "DR DB direct SSM IP_REDACTED" dr-db 18 5; then
      echo "[DB PROMOTION ERROR] Approved DR DB management connection was not verified."
      return 1
    fi
    if [ "$web_role_state" = "running" ]; then
      if ! dr_ssm_wait_for_ssh "DR Web app host for write fence" dr-web 18 5 \
        || ! fence_dr_application_container dr-web hospital-dr-web; then
        echo "[APP WRITE FENCE ERROR] Running DR Web app container could not be stopped and verified; DB promotion is blocked."
        return 1
      fi
    fi
    if [ "$doc_role_state" = "running" ]; then
      if ! dr_ssm_wait_for_ssh "DR EMR app host through existing Web SSM path" dr-doc 18 5 \
        || ! fence_dr_application_container dr-doc hospital-dr-emr; then
        echo "[APP WRITE FENCE ERROR] Running DR EMR app container could not be stopped and verified; DB promotion is blocked."
        return 1
      fi
    fi
    dr_promote_dr_database
  fi

  # Start Web only after the DB is verified writable; start EMR after the Web
  # identity and management connection have been read back.
  if ! dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-Real-Web-Server"; then
    echo "[AWS VALIDATION ERROR] Approved DR Web start request failed after DB promotion."
    return 1
  fi
  if ! aws ec2 wait instance-running --region "$REGION" --instance-ids "$web_instance_id"; then
    echo "[AWS VALIDATION ERROR] Approved DR Web instance did not reach running state."
    return 1
  fi
  if ! aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$web_instance_id"; then
    echo "[AWS VALIDATION ERROR] Approved DR Web instance status checks did not pass."
    return 1
  fi
  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)"; then
    echo "[AWS VALIDATION ERROR] Could not read the DR instance set after Web start."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")"; then
    echo "[AWS VALIDATION ERROR] DR instance identity/state verification failed after Web start."
    return 1
  fi
  web_plan_row=$'Hospital-Real-Web-Server\ti-076072b45ae492e15\trunning\tnone'
  doc_plan_action=none
  if [ "$doc_role_state" = "stopped" ]; then doc_plan_action=start; fi
  doc_plan_row=$'Hospital-DR-Doc-Server\ti-03a64d7fd25895173\t'"$doc_role_state"$'\t'"$doc_plan_action"
  db_plan_row=$'Hospital-DR-DB-Server\ti-02c9a5dfdd791503b\trunning\tnone'
  if ! grep -Fqx -- "$web_plan_row" <<< "$plan" \
    || ! grep -Fqx -- "$doc_plan_row" <<< "$plan" \
    || ! grep -Fqx -- "$db_plan_row" <<< "$plan"; then
    echo "[AWS VALIDATION ERROR] Web/EMR/DB states changed unexpectedly before EMR start."
    return 1
  fi
  if ! web_instance_id="$(dr_ssm_discover_web_instance_id "$REGION" "$DR_WEB_PRIVATE_IP_EXPECTED")" \
    || [ "$web_instance_id" != "AWS_RESOURCE_ID_REDACTED" ]; then
    echo "[START ERROR] Could not identify the approved running DR Web instance for SSM."
    return 1
  fi
  if ! dr_ssm_write_ssh_config "$REGION" "$web_instance_id" "$SSH_KEY" "$DR_SSH_KNOWN_HOSTS_FILE" "${DR_DOC_PRIVATE_IP:-AWS_PUBLIC_IP_REDACTED}" "AWS_PUBLIC_IP_REDACTED" "$db_instance_id"; then
    return 1
  fi
  web_ip="$DR_WEB_EIP_EXPECTED"
  echo "[AWS VALIDATION] DB recovery and promotion completed; Web is running while EMR remains stopped."
  if ! dr_ssm_wait_for_ssh "DR Web instance $web_instance_id" dr-web 18 5; then
    echo "[APPLICATION BLOCKED] Approved Web SSM SSH transport was not verified."
    return 1
  fi

  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)"; then
    echo "[AWS VALIDATION ERROR] Could not re-read DR identities before EMR start."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script")" \
    || ! grep -Fqx -- "$web_plan_row" <<< "$plan" \
    || ! grep -Fqx -- "$doc_plan_row" <<< "$plan" \
    || ! grep -Fqx -- "$db_plan_row" <<< "$plan"; then
    echo "[AWS VALIDATION ERROR] DR identities or lifecycle states drifted before EMR start."
    return 1
  fi
  if ! dr_ec2_start_instances_safely "$REGION" "$inventory_json" "Hospital-DR-Doc-Server"; then
    echo "[AWS VALIDATION ERROR] Approved DR EMR start request failed after Web readiness."
    return 1
  fi
  if ! aws ec2 wait instance-running --region "$REGION" --instance-ids "AWS_RESOURCE_ID_REDACTED"; then
    echo "[AWS VALIDATION ERROR] Approved DR EMR instance did not reach running state."
    return 1
  fi
  if ! aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "AWS_RESOURCE_ID_REDACTED"; then
    echo "[AWS VALIDATION ERROR] Approved DR EMR instance status checks did not pass."
    return 1
  fi
  if ! inventory_json="$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
      --output json)"; then
    echo "[AWS VALIDATION ERROR] Could not re-read the approved DR instance set after EMR start."
    return 1
  fi
  if ! plan="$(printf '%s\n' "$inventory_json" | python3 "$plan_script" --require-running)"; then
    echo "[AWS VALIDATION ERROR] Running DR instance identity verification failed after EMR start."
    return 1
  fi
  mapfile -t ids < <(awk -F '\t' '{print $2}' <<< "$plan")
  if ! dr_ssm_wait_for_ssh "DR Doc ${DR_DOC_PRIVATE_IP:-IP_REDACTED} through DR Web" dr-doc 18 5; then
    echo "[APPLICATION ERROR] Approved DR EMR management connection was not verified over the Web jump path."
    return 1
  fi

  if ! dr_ssm_ssh dr-web 'set -eu
sudo systemctl start docker nginx
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-web 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-web >/dev/null; fi
for attempt in $(seq 1 12); do
  health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-web 2>/dev/null || true)"
  if [ "$health" = "healthy" ]; then exit 0; fi
  sleep 5
done
exit 1' >/dev/null; then
    echo "[APPLICATION ERROR] DR Web container health verification failed."
    return 1
  fi
  if ! dr_ssm_ssh dr-doc 'set -eu
sudo systemctl start docker apache2
running="$(sudo docker inspect --format "{{.State.Running}}" hospital-dr-emr 2>/dev/null || true)"
if [ "$running" != "true" ]; then sudo docker start hospital-dr-emr >/dev/null; fi
for attempt in $(seq 1 12); do
  health="$(sudo docker inspect --format "{{.State.Health.Status}}" hospital-dr-emr 2>/dev/null || true)"
  if [ "$health" = "healthy" ]; then exit 0; fi
  sleep 5
done
exit 1' >/dev/null; then
    echo "[APPLICATION ERROR] DR EMR container health verification failed."
    return 1
  fi

  if [ "$SKIP_DNS" != "true" ]; then
    if ! verify_dr_application_db_endpoint dr-web hospital-dr-web; then
      echo "[APPLICATION VALIDATION ERROR] DR Web database endpoint identity check failed."
      return 1
    fi
    if ! verify_dr_application_db_endpoint dr-doc hospital-dr-emr; then
      echo "[APPLICATION VALIDATION ERROR] DR EMR database endpoint identity check failed."
      return 1
    fi
    if ! web_health_code="$(dr_ssm_ssh dr-web 'set -eu
code="$(curl --silent --show-error --max-time 10 --output /dev/null --write-out "%{http_code}" http://IP_REDACTED:3000/__hospital_dr/health)"
printf "WEB_HEALTH_HTTP=%s\n" "$code"
[ "$code" = "204" ]')"; then
      echo "[APPLICATION VALIDATION ERROR] DR Web health must return HTTP 204; observed ${web_health_code:-UNAVAILABLE}."
      return 1
    fi
    if ! emr_health_code="$(dr_ssm_ssh dr-doc 'set -eu
code="$(curl --silent --show-error --max-time 10 --output /dev/null --write-out "%{http_code}" http://IP_REDACTED:3000/__hospital_dr/health)"
printf "EMR_HEALTH_HTTP=%s\n" "$code"
[ "$code" = "204" ]')"; then
      echo "[APPLICATION VALIDATION ERROR] DR EMR health must return HTTP 204; observed ${emr_health_code:-UNAVAILABLE}."
      return 1
    fi
    echo "[VALIDATION] Web and EMR reached the approved DR DB endpoint and returned HTTP 204 from the non-identifying SELECT health probe."
  fi

  echo "[VALIDATION] DR Web and EMR container health passed over the approved SSH management path."
  echo "[VALIDATION] Public origin reachability will be checked through Cloudflare after DNS read-back."

  if [ "$SKIP_DNS" = "true" ]; then
    echo "[DNS] Cloudflare transition skipped because SKIP_DNS=true; SSH origin checks passed."
    echo "[DNS] SKIP_DNS=true이므로 Cloudflare 전환을 건너뛰었습니다. Origin health는 통과했습니다."
    dr_state_write IDLE
    DR_STATE_TRANSITION_STARTED=0
    return 0
  fi

  if ! dr_dns_validate_aws_web_eip "$web_ip" "$DR_WEB_EIP_EXPECTED" "$REGION"; then
    echo "[START ERROR] The current Web instance is not associated with the approved DR EIP."
    return 1
  fi

  prepare_dns_snapshot
  echo "[DNS] Switching both Cloudflare records to the verified DR Web EIP: $web_ip"
  if ! apply_dr_dns "$web_ip"; then
    return 1
  fi

  dr_state_write DR_ACTIVE
  DR_STATE_TRANSITION_STARTED=0
  echo "[DR STATE] DR_ACTIVE persisted after verified DNS and public service checks."
  echo "[DR STARTED] Web, EMR, and DB Health checks passed and Cloudflare DNS points to the approved DR Web."
  echo "[DR 시작 완료] Web·EMR·DB 상태 점검과 Cloudflare DNS 전환을 확인했습니다."
}
stop_environment() {
  local ids stop_failed ids_count instance_list dns_rc
  dr_state_write FAILBACK_EXECUTING
  DR_STATE_TRANSITION_STARTED=1
  stop_failed=0
  if ! instance_list="$(instance_ids)"; then
    echo "[DR STOP ERROR] Failed to list DR EC2 instances."
    echo "[DR 중지 오류] DR EC2 인스턴스 목록을 조회하지 못했습니다."
    return 1
  fi
  mapfile -t ids <<< "$instance_list"
  ids_count=$(printf '%s\n' "${ids[@]}" | sed '/^$/d' | wc -l)

  if [ "$SKIP_DNS" = "true" ]; then
    echo "[DNS] Cloudflare transition skipped because SKIP_DNS=true; keeping current DNS records."
    echo "[DNS] SKIP_DNS=true이므로 현재 Cloudflare DNS record를 유지합니다."
  else
    echo "[VALIDATION] Checking on-premise Web and EMR health before DNS failback."
    if ! check_public_health "$ONPREM_WEB_HEALTH_URL" "$ONPREM_EMR_HEALTH_URL" "${ONPREM_HEALTH_ATTEMPTS:-12}"; then
      echo "[VALIDATION ERROR] On-premise health failed; checking the current Cloudflare target before recording state."
      mark_state_from_current_dns
      return 1
    fi

    prepare_dns_snapshot
    if ! dr_dns_validate_origin_pair \
        "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
        "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED"; then
      echo "[DNS ERROR] A verified pre-failover On-Prem snapshot is required; failback stopped."
      if dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
        DR_STATE_FAILURE_STATUS=DR_ACTIVE
        dr_state_write DR_ACTIVE 2>/dev/null || true
      else
        DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
        dr_state_write PARTIAL_FAILURE 2>/dev/null || true
      fi
      return 1
    fi

    if dr_dns_snapshot_pairs_equal "$DNS_TX_DIR" "$DNS_ORIGIN_DIR"; then
      echo "[DNS] Cloudflare already matches the preserved On-Prem snapshot."
      if ! check_public_health "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/emr/" "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
        echo "[VALIDATION ERROR] Public On-Prem health failed while DNS already matches the origin snapshot."
        DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
        dr_state_write PARTIAL_FAILURE 2>/dev/null || true
        return 1
      fi
    else
      if ! dr_dns_validate_dr_pair "$DNS_TX_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" "$DR_WEB_EIP_EXPECTED"; then
        echo "[DNS ERROR] Current Cloudflare records are neither the preserved origin nor the approved DR pair."
        DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
        dr_state_write PARTIAL_FAILURE 2>/dev/null || true
        return 1
      fi
      if dr_dns_failback_transaction \
          "$DNS_TX_DIR" "$DNS_ORIGIN_DIR" "$DR_DOMAIN" "$EMR_DOMAIN" \
          "$ONPREM_TUNNEL_HOST" "$DR_WEB_EIP_EXPECTED" check_public_health \
          "https://$DR_DOMAIN/" "https://$EMR_DOMAIN/emr/" "${PUBLIC_HEALTH_ATTEMPTS:-12}"; then
        :
      else
        dns_rc=$?
        if [ "$dns_rc" -eq 2 ]; then
          DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
          dr_state_write PARTIAL_FAILURE 2>/dev/null || true
        else
          DR_STATE_FAILURE_STATUS=DR_ACTIVE
          dr_state_write DR_ACTIVE 2>/dev/null || true
        fi
        return 1
      fi
    fi
  fi

  if [ "$ids_count" -gt 0 ]; then
    echo "[DR STOP] Stopping $ids_count DR EC2 instances."
    echo "[DR 중지] EC2 인스턴스 $ids_count대를 중지합니다."
    if ! aws ec2 stop-instances --region "$REGION" --instance-ids "${ids[@]}" >/dev/null; then
      echo "[DR STOP ERROR] Failed to request EC2 stop."
      stop_failed=1
    fi
  fi

  if [ "$ids_count" -gt 0 ]; then
    if ! aws ec2 wait instance-stopped --region "$REGION" --instance-ids "${ids[@]}"; then
      echo "[DR STOP ERROR] EC2 stop wait failed."
      stop_failed=1
    fi
  fi

  if [ "$stop_failed" -ne 0 ]; then
    DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
    dr_state_write PARTIAL_FAILURE 2>/dev/null || true
    echo "[DR STOP PARTIAL_FAILURE] One or more DR stop or cleanup steps failed."
    return 1
  fi

  if [ "$SKIP_DNS" != "true" ] && [ -d "$DNS_ORIGIN_DIR" ]; then
    if ! dr_dns_archive_origin_pair "$DNS_ORIGIN_DIR" "$DNS_ARCHIVE_DIR"; then
      DR_STATE_FAILURE_STATUS=PARTIAL_FAILURE
      dr_state_write PARTIAL_FAILURE 2>/dev/null || true
      echo "[DR STOP PARTIAL_FAILURE] DNS was restored, but its origin snapshot could not be archived."
      return 1
    fi
  fi

  if [ "${DR_ENVIRONMENT_CONTROL_DEFER_IDLE:-0}" != "1" ]; then
    dr_state_write IDLE
  fi
  DR_STATE_TRANSITION_STARTED=0
  echo "[DR STOPPED] EC2 compute is stopped. NAT lifecycle was not changed; use operations/nat/nat_disable.sh explicitly."
  echo "[DR 중지 완료] EC2 컴퓨팅만 중지했습니다. NAT 수명주기는 변경하지 않았으며 operations/nat/nat_disable.sh를 명시적으로 사용하십시오."
}
show_status() {
  echo "[DR STATE] $(dr_state_read)"
  echo "[EC2 STATUS]"
  aws ec2 describe-instances \
    --region "$REGION" \
    --filters "Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server" \
    --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,ID:InstanceId,State:State.Name,PublicIP:PublicIpAddress}' \
    --output table

  echo "[NAT STATUS]"
  "$NAT_DIR/nat_status.sh" || true
}

aws_check
case "$ACTION" in
  start)
    start_environment
    ;;
  stop)
    stop_environment
    ;;
  status)
    show_status
    ;;
  verify-source-writer-fence)
    dr_verify_onprem_source_writer_fence
    ;;
  provision)
    dr_state_write FAILOVER_EXECUTING
    DR_STATE_TRANSITION_STARTED=1
    DR_PROVISION_ONLY=true "$TF_DIR/run_demo.sh"
    echo "[DR PROVISION] NAT lifecycle is unchanged by environment provisioning; use operations/nat/nat_disable.sh explicitly when cleanup is required."
    dr_state_write IDLE
    DR_STATE_TRANSITION_STARTED=0
    ;;
  *)
    echo "Usage: $0 {start|stop|status|verify-source-writer-fence|provision}" >&2
    exit 2
    ;;
esac
