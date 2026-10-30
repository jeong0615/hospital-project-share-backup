#!/usr/bin/env bash
set -uo pipefail

# Read-only, local On-Prem MySQL observation aid. This is NOT the production
# Write Fence verifier and its exit status/outputs must never authorize DR.
# Credentials are read only through the MySQL client's existing local option
# files or an optional named login path; no password is accepted on the CLI.

export LC_ALL=C
export MYSQL_HISTFILE=/dev/null

MYSQL_BIN="${MYSQL_BIN:-mysql}"
MYSQL_LOGIN_PATH="${MYSQL_PREFLIGHT_LOGIN_PATH:-}"
CONNECT_TIMEOUT_SECONDS=5
readonly VERIFIER_DB_HOST="IP_REDACTED"
readonly VERIFIER_DB_PORT="3306"
MYSQL_AVAILABLE=false
DB_CONNECTED=false
IDENTITY=""
VERSION=""
GRANTS=""
CURRENT_ROLE=""
PROCESS_GRANT=false

emit() {
  printf '%s=%s' "$1" "$2"
  shift 2
  for field in "$@"; do printf ' %s' "$field"; done
  printf '\n'
}

mysql_query() {
  local query="$1"
  local -a args=(--protocol=socket --connect-timeout="$CONNECT_TIMEOUT_SECONDS" --batch --raw --skip-column-names)
  if [ -n "$MYSQL_LOGIN_PATH" ]; then
    args+=(--login-path="$MYSQL_LOGIN_PATH")
  fi
  "$MYSQL_BIN" "${args[@]}" -e "$query" 2>/dev/null
}

is_on() {
  case "${1^^}" in
    1|ON|TRUE) return 0 ;;
    *) return 1 ;;
  esac
}

safe_identifier() {
  [[ "${1:-}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]
}

count_nonempty_lines() {
  awk 'NF { count++ } END { print count + 0 }'
}

missing_commands=""
for required_command in awk grep hostname sed tr; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    missing_commands="${missing_commands}${missing_commands:+,}${required_command}"
  fi
done
if ! command -v "$MYSQL_BIN" >/dev/null 2>&1; then
  missing_commands="${missing_commands}${missing_commands:+,}mysql_client"
fi
if [ -n "$missing_commands" ]; then
  emit PREFLIGHT_TOOLING UNVERIFIED 'reason=required_command_missing' "commands=$missing_commands"
  if command -v "$MYSQL_BIN" >/dev/null 2>&1; then
    emit MYSQL_CLIENT VERIFIED 'path=available'
  else
    emit MYSQL_CLIENT UNVERIFIED 'reason=mysql_client_unavailable'
  fi
  emit MYSQL_AUTH UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_CONNECTION UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_IDENTITY UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_READ_ONLY UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_SUPER_READ_ONLY UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_BINARY_LOG UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=database_checks_not_started'
  emit HOSPITAL_DB UNVERIFIED 'reason=database_checks_not_started'
  emit CURRENT_LOGIN_DML_PRIVILEGES UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_SESSION_VISIBILITY UNVERIFIED 'reason=database_checks_not_started'
  emit CURRENT_WRITE_ACTIVITY UNVERIFIED 'reason=database_checks_not_started'
  emit APPLICATION_ACCOUNT_DML UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_SCHEDULED_EVENTS UNVERIFIED 'reason=database_checks_not_started'
  emit MYSQL_SERVICE UNVERIFIED 'reason=preflight_aborted_before_service_checks'
  emit MYSQL_SERVICE_AUTOSTART UNVERIFIED 'reason=preflight_aborted_before_service_checks'
  emit SYSTEMD_TIMERS UNVERIFIED 'reason=preflight_aborted_before_service_checks'
  emit SYSTEM_CRON UNVERIFIED 'reason=preflight_aborted_before_cron_checks'
  emit WEB_EMR_WRITER_FENCE UNVERIFIED 'reason=application_hosts_and_external_writers_require_separate_field_verification'
  emit AUTOMATIC_WRITE_FENCE UNVERIFIED 'reason=observation_only_not_the_production_write_fence_verifier'
  emit PREFLIGHT_RESULT UNVERIFIED 'reason=observation_only_not_failover_authorization'
  exit 1
fi
emit PREFLIGHT_TOOLING VERIFIED 'required_commands_available=yes'

if [[ -n "${MYSQL_PWD+x}" ]]; then
  emit MYSQL_AUTH UNVERIFIED 'reason=password_environment_variable_not_allowed'
elif ! command -v "$MYSQL_BIN" >/dev/null 2>&1; then
  emit MYSQL_CLIENT UNVERIFIED 'reason=mysql_client_unavailable'
elif [[ -n "$MYSQL_LOGIN_PATH" && ! "$MYSQL_LOGIN_PATH" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
  emit MYSQL_AUTH UNVERIFIED 'reason=login_path_name_invalid'
else
  MYSQL_AVAILABLE=true
  emit MYSQL_AUTH UNVERIFIED 'reason=authentication_not_confirmed_until_query_succeeds'
fi
if command -v "$MYSQL_BIN" >/dev/null 2>&1; then
  emit MYSQL_CLIENT VERIFIED 'path=available'
fi

if [ "$MYSQL_AVAILABLE" = true ]; then
  if VERSION="$(mysql_query 'SELECT VERSION()')" && [ -n "$VERSION" ]; then
    DB_CONNECTED=true
    emit MYSQL_CONNECTION VERIFIED 'transport=local_unix_socket'
    emit MYSQL_AUTH VERIFIED 'method=authenticated_local_socket_session'
    if [[ "$VERSION" =~ ^[A-Za-z0-9.+_-]{1,128}$ ]]; then
      emit MYSQL_VERSION VERIFIED "value=$VERSION"
    else
      emit MYSQL_VERSION UNVERIFIED 'reason=version_value_invalid'
    fi
  else
    emit MYSQL_CONNECTION UNVERIFIED 'reason=local_socket_query_failed'
  fi

  if IDENTITY="$(mysql_query 'SELECT @@hostname, @@server_uuid, @@server_id, @@port')"; then
    IFS=$'\t' read -r db_hostname db_uuid db_server_id db_port <<< "$IDENTITY"
    if safe_identifier "${db_hostname:-}" \
      && [[ "${db_uuid:-}" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] \
      && [[ "${db_server_id:-}" =~ ^[1-9][0-9]*$ ]] \
      && [[ "${db_port:-}" =~ ^[1-9][0-9]*$ ]]; then
      emit MYSQL_IDENTITY VERIFIED "hostname=$db_hostname" "server_uuid=${db_uuid,,}" "server_id=$db_server_id" "port=$db_port"
    else
      emit MYSQL_IDENTITY UNVERIFIED 'reason=identity_missing_or_invalid'
    fi
  else
    emit MYSQL_IDENTITY UNVERIFIED 'reason=identity_query_unavailable'
  fi

  local_addresses="$(hostname -I 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//' || true)"
  if [ -n "$local_addresses" ]; then
    emit LOCAL_HOST_ADDRESSES VERIFIED "values=$local_addresses"
  else
    emit LOCAL_HOST_ADDRESSES UNVERIFIED 'reason=local_addresses_unavailable'
  fi
  emit WRITE_FENCE_TARGET_CONTRACT VERIFIED "expected_host=$VERIFIER_DB_HOST" "expected_port=$VERIFIER_DB_PORT" 'source=existing_verifier_contract'
  if [ -z "$local_addresses" ] || ! [[ "${db_port:-}" =~ ^[1-9][0-9]*$ ]]; then
    emit WRITE_FENCE_TARGET_MATCH UNVERIFIED 'reason=local_address_or_mysql_port_unavailable'
  elif [[ " $local_addresses " == *" $VERIFIER_DB_HOST "* ]] && [ "$db_port" = "$VERIFIER_DB_PORT" ]; then
    emit WRITE_FENCE_TARGET_MATCH VERIFIED 'value=local_address_and_mysql_port_match'
  else
    emit WRITE_FENCE_TARGET_MATCH BLOCKED 'reason=local_address_or_mysql_port_mismatch'
  fi
  expected_db_host="${ONPREM_DB_HOST:-}"
  if [ -z "$expected_db_host" ] || [ -z "$local_addresses" ]; then
    emit ONPREM_DB_HOST_CONTRACT UNVERIFIED 'reason=expected_host_or_local_address_missing'
  elif [ "$expected_db_host" != "$VERIFIER_DB_HOST" ]; then
    emit ONPREM_DB_HOST_CONTRACT BLOCKED 'reason=configured_host_differs_from_existing_verifier_target'
  elif [[ " $local_addresses " == *" $expected_db_host "* ]]; then
    emit ONPREM_DB_HOST_CONTRACT VERIFIED 'value=expected_host_assigned_locally'
  else
    emit ONPREM_DB_HOST_CONTRACT BLOCKED 'reason=expected_host_not_assigned_to_local_server'
  fi
  expected_uuid="${ONPREM_DB_SERVER_UUID_EXPECTED:-}"
  if [[ "${expected_uuid,,}" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] \
    && [[ "${db_uuid:-}" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
    if [ "${expected_uuid,,}" = "${db_uuid,,}" ]; then
      emit ONPREM_DB_UUID_PIN VERIFIED 'value=expected_uuid_matches'
    else
      emit ONPREM_DB_UUID_PIN BLOCKED 'reason=server_uuid_mismatch'
    fi
  else
    emit ONPREM_DB_UUID_PIN UNVERIFIED 'reason=expected_uuid_not_pinned_or_observed'
  fi

  if flags="$(mysql_query 'SELECT @@global.read_only, @@global.super_read_only')"; then
    IFS=$'\t' read -r read_only super_read_only <<< "$flags"
    if is_on "${read_only:-}"; then
      emit MYSQL_READ_ONLY VERIFIED 'value=ON'
    else
      emit MYSQL_READ_ONLY BLOCKED 'reason=read_only_is_not_on'
    fi
    if is_on "${super_read_only:-}"; then
      emit MYSQL_SUPER_READ_ONLY VERIFIED 'value=ON'
    else
      emit MYSQL_SUPER_READ_ONLY BLOCKED 'reason=super_read_only_is_not_on'
    fi
  else
    emit MYSQL_READ_ONLY UNVERIFIED 'reason=read_only_query_unavailable'
    emit MYSQL_SUPER_READ_ONLY UNVERIFIED 'reason=super_read_only_query_unavailable'
  fi

  if log_bin="$(mysql_query 'SELECT @@global.log_bin')"; then
    if is_on "$log_bin"; then
      emit MYSQL_BINARY_LOG VERIFIED 'value=ON'
      if coordinates="$(mysql_query 'SHOW BINARY LOG STATUS')" || [ -z "${coordinates:-}" ]; then
        coordinates="$(mysql_query 'SHOW MASTER STATUS' || true)"
      fi
      if [ -n "${coordinates:-}" ]; then
        IFS=$'\t' read -r binlog_file binlog_position _ <<< "$coordinates"
        if [[ "${binlog_file:-}" =~ ^[A-Za-z0-9._-]{1,255}$ ]] \
          && [[ "${binlog_position:-}" =~ ^[0-9]+$ ]]; then
          emit MYSQL_BINLOG_COORDINATE VERIFIED "file=$binlog_file" "position=$binlog_position"
        else
          emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=coordinate_missing_or_invalid'
        fi
      else
        emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=master_status_unavailable'
      fi
    else
      emit MYSQL_BINARY_LOG BLOCKED 'reason=binary_log_disabled'
      emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=binary_log_disabled'
    fi
  else
    emit MYSQL_BINARY_LOG UNVERIFIED 'reason=binary_log_query_unavailable'
    emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=binary_log_query_unavailable'
  fi

  if schema_exists="$(mysql_query "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='hospital_db'")" \
    && [[ "$schema_exists" =~ ^[0-9]+$ ]]; then
    if [ "$schema_exists" -eq 1 ]; then
      emit HOSPITAL_DB VERIFIED 'exists=yes'
    else
      emit HOSPITAL_DB BLOCKED 'reason=schema_not_found'
    fi
  else
    emit HOSPITAL_DB UNVERIFIED 'reason=schema_query_unavailable'
  fi

  if GRANTS="$(mysql_query 'SHOW GRANTS FOR CURRENT_USER()')" \
    && CURRENT_ROLE="$(mysql_query 'SELECT CURRENT_ROLE()')"; then
    if printf '%s' "$GRANTS" | grep -Eiq '(^|[,[:space:]])(ALL[[:space:]]+PRIVILEGES|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|INDEX|REFERENCES|TRIGGER|EVENT|EXECUTE|GRANT[[:space:]]+OPTION)([,[:space:]]|$)'; then
      emit CURRENT_LOGIN_DML_PRIVILEGES BLOCKED 'reason=current_login_has_write_or_grant_privileges'
    elif [ "$CURRENT_ROLE" = "NONE" ] || [ "$CURRENT_ROLE" = "NULL" ]; then
      emit CURRENT_LOGIN_DML_PRIVILEGES VERIFIED 'value=no_direct_dml_grant_detected'
    else
      emit CURRENT_LOGIN_DML_PRIVILEGES UNVERIFIED 'reason=active_role_privileges_not_expanded'
    fi
    if printf '%s' "$GRANTS" | grep -Eiq '(^|[,[:space:]])PROCESS([,[:space:]]|$)' \
      && { [ "$CURRENT_ROLE" = "NONE" ] || [ "$CURRENT_ROLE" = "NULL" ]; }; then
      PROCESS_GRANT=true
    fi
  else
    emit CURRENT_LOGIN_DML_PRIVILEGES UNVERIFIED 'reason=grant_visibility_unavailable'
  fi

  if [ "$PROCESS_GRANT" = true ]; then
    if sessions="$(mysql_query "SELECT COUNT(*), COALESCE(SUM(COMMAND <> 'Sleep'),0), COALESCE(SUM(USER <> SUBSTRING_INDEX(CURRENT_USER(),'@',1)),0) FROM information_schema.processlist")"; then
      IFS=$'\t' read -r total_sessions active_sessions other_users <<< "$sessions"
      if [[ "${total_sessions:-}" =~ ^[0-9]+$ && "${active_sessions:-}" =~ ^[0-9]+$ && "${other_users:-}" =~ ^[0-9]+$ ]]; then
        emit MYSQL_SESSION_VISIBILITY VERIFIED "visible_sessions=$total_sessions" "non_sleeping=$active_sessions" "other_accounts=$other_users"
      else
        emit MYSQL_SESSION_VISIBILITY UNVERIFIED 'reason=session_summary_invalid'
      fi
    else
      emit MYSQL_SESSION_VISIBILITY UNVERIFIED 'reason=processlist_query_failed'
    fi
  else
    emit MYSQL_SESSION_VISIBILITY UNVERIFIED 'reason=PROCESS_privilege_not_confirmed'
  fi
  emit CURRENT_WRITE_ACTIVITY UNVERIFIED 'reason=point_in_time_sessions_do_not_prove_writer_fencing'
  emit APPLICATION_ACCOUNT_DML UNVERIFIED 'reason=application_accounts_and_remote_configs_not_authoritatively_checked'

  if events="$(mysql_query "SELECT @@global.event_scheduler, (SELECT COUNT(*) FROM information_schema.events WHERE STATUS='ENABLED')")"; then
    IFS=$'\t' read -r event_scheduler event_count <<< "$events"
    if [[ "${event_count:-}" =~ ^[0-9]+$ ]]; then
      if is_on "${event_scheduler:-}"; then scheduler_value=ON; else scheduler_value="${event_scheduler:-UNKNOWN}"; fi
      emit MYSQL_SCHEDULED_EVENTS VERIFIED "event_scheduler=$scheduler_value" "enabled_events=$event_count"
    else
      emit MYSQL_SCHEDULED_EVENTS UNVERIFIED 'reason=event_status_invalid'
    fi
  else
    emit MYSQL_SCHEDULED_EVENTS UNVERIFIED 'reason=event_metadata_unavailable'
  fi
else
  emit MYSQL_CONNECTION UNVERIFIED 'reason=local_mysql_auth_or_connection_unavailable'
  emit MYSQL_IDENTITY UNVERIFIED 'reason=database_not_reached'
  emit LOCAL_HOST_ADDRESSES UNVERIFIED 'reason=database_not_reached'
  emit WRITE_FENCE_TARGET_CONTRACT VERIFIED "expected_host=$VERIFIER_DB_HOST" "expected_port=$VERIFIER_DB_PORT" 'source=existing_verifier_contract'
  emit WRITE_FENCE_TARGET_MATCH UNVERIFIED 'reason=database_not_reached'
  emit ONPREM_DB_HOST_CONTRACT UNVERIFIED 'reason=database_not_reached'
  emit ONPREM_DB_UUID_PIN UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_READ_ONLY UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_SUPER_READ_ONLY UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_BINARY_LOG UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_BINLOG_COORDINATE UNVERIFIED 'reason=database_not_reached'
  emit HOSPITAL_DB UNVERIFIED 'reason=database_not_reached'
  emit CURRENT_LOGIN_DML_PRIVILEGES UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_SESSION_VISIBILITY UNVERIFIED 'reason=database_not_reached'
  emit CURRENT_WRITE_ACTIVITY UNVERIFIED 'reason=database_not_reached'
  emit APPLICATION_ACCOUNT_DML UNVERIFIED 'reason=database_not_reached'
  emit MYSQL_SCHEDULED_EVENTS UNVERIFIED 'reason=database_not_reached'
fi

service_unit=""
service_state=""
if command -v systemctl >/dev/null 2>&1; then
  for candidate in mysql.service mariadb.service mysqld.service; do
    load_state="$(systemctl show -p LoadState --value "$candidate" 2>/dev/null || true)"
    if [ "$load_state" = "loaded" ]; then
      service_unit="$candidate"
      if systemctl is-active --quiet "$candidate"; then
        service_state=active
      else
        service_state=inactive_or_failed
      fi
      break
    fi
  done
  if [ -n "$service_unit" ]; then
    if [ "$service_state" = active ]; then
      emit MYSQL_SERVICE VERIFIED "unit=$service_unit" 'state=active'
    else
      emit MYSQL_SERVICE BLOCKED "unit=$service_unit" "state=$service_state"
    fi
    enabled_state="$(systemctl is-enabled "$service_unit" 2>/dev/null || true)"
    case "$enabled_state" in
      enabled|enabled-runtime|disabled|static|indirect|masked|generated|transient|alias|linked|linked-runtime)
        emit MYSQL_SERVICE_AUTOSTART VERIFIED "unit=$service_unit" "state=$enabled_state" ;;
      *) emit MYSQL_SERVICE_AUTOSTART UNVERIFIED 'reason=systemd_enablement_unavailable' ;;
    esac
  else
    emit MYSQL_SERVICE UNVERIFIED 'reason=mysql_systemd_unit_not_found'
    emit MYSQL_SERVICE_AUTOSTART UNVERIFIED 'reason=mysql_systemd_unit_not_found'
  fi
  if timers="$(systemctl list-timers --all --no-legend --no-pager 2>/dev/null)"; then
    timer_count="$(printf '%s\n' "$timers" | count_nonempty_lines)"
    emit SYSTEMD_TIMERS VERIFIED "visible_timer_count=$timer_count" 'timer_unit_names_not_printed'
  else
    emit SYSTEMD_TIMERS UNVERIFIED 'reason=systemd_timer_list_unavailable'
  fi
else
  emit MYSQL_SERVICE UNVERIFIED 'reason=systemctl_unavailable'
  emit MYSQL_SERVICE_AUTOSTART UNVERIFIED 'reason=systemctl_unavailable'
  emit SYSTEMD_TIMERS UNVERIFIED 'reason=systemctl_unavailable'
fi

cron_count=0
cron_visible=true
if [ -e /etc/crontab ]; then
  if [ -r /etc/crontab ]; then
    current_count="$(awk '!/^[[:space:]]*#/ && NF { count++ } END { print count + 0 }' /etc/crontab 2>/dev/null || echo 0)"
    cron_count=$((cron_count + current_count))
  else
    cron_visible=false
  fi
fi
if [ -d /etc/cron.d ]; then
  for cron_file in /etc/cron.d/*; do
    [ -e "$cron_file" ] || continue
    if [ -f "$cron_file" ] && [ -r "$cron_file" ]; then
      current_count="$(awk '!/^[[:space:]]*#/ && NF { count++ } END { print count + 0 }' "$cron_file" 2>/dev/null || echo 0)"
      cron_count=$((cron_count + current_count))
    elif [ -f "$cron_file" ]; then
      cron_visible=false
    fi
  done
fi
if [ "$cron_visible" = true ]; then
  emit SYSTEM_CRON VERIFIED "visible_system_entries=$cron_count" 'per_user_crontabs_not_inspected'
else
  emit SYSTEM_CRON UNVERIFIED 'reason=some_system_cron_files_not_readable'
fi

emit WEB_EMR_WRITER_FENCE UNVERIFIED 'reason=application_hosts_and_external_writers_require_separate_field_verification'
emit AUTOMATIC_WRITE_FENCE UNVERIFIED 'reason=observation_only_not_the_production_write_fence_verifier'
emit PREFLIGHT_RESULT UNVERIFIED 'reason=observation_only_not_failover_authorization'
emit FIELD_REVIEW_REQUIRED 'onprem_db_identity_pin' 'all_web_emr_scheduler_and_manual_writers' 'fence_persistence_across_restart' 'application_account_grants'

if [ "$DB_CONNECTED" = true ]; then
  exit 0
fi
exit 1
