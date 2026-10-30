#!/usr/bin/env bash
set -u

# Read-only MSP -> On-Prem DB path diagnostic. It never changes routes,
# interfaces, WireGuard services, firewall rules, or AWS resources.

EXPECTED_DB_HOST="IP_REDACTED"
EXPECTED_GATEWAY="IP_REDACTED"
EXPECTED_DB_PORT="3306"
EXPECTED_SSH_PORT="22"
EXPECTED_NEW_INTERFACE="wg-aws-dr"
EXPECTED_LEGACY_INTERFACE="wg-aws-hub"

db_host="${ONPREM_DB_HOST:-$EXPECTED_DB_HOST}"
gateway="${ONPREM_GATEWAY:-$EXPECTED_GATEWAY}"
db_port="${ONPREM_DB_PORT:-$EXPECTED_DB_PORT}"
ssh_port="${ONPREM_SSH_PORT:-$EXPECTED_SSH_PORT}"

config_error() {
  echo "AWS_DR_WG_PATH_CONFIG_ERROR=$*" >&2
  exit 2
}

[[ "$db_host" == "$EXPECTED_DB_HOST" ]] || config_error "ONPREM_DB_HOST must remain $EXPECTED_DB_HOST"
[[ "$gateway" == "$EXPECTED_GATEWAY" ]] || config_error "ONPREM_GATEWAY must remain $EXPECTED_GATEWAY"
[[ "$db_port" == "$EXPECTED_DB_PORT" ]] || config_error "ONPREM_DB_PORT must remain $EXPECTED_DB_PORT"
[[ "$ssh_port" == "$EXPECTED_SSH_PORT" ]] || config_error "ONPREM_SSH_PORT must remain $EXPECTED_SSH_PORT"

echo "MSP_ONPREM_DB_TARGET=$db_host"
echo "MSP_ONPREM_GATEWAY=$gateway"
echo "AWS_DR_NEW_INTERFACE=$EXPECTED_NEW_INTERFACE"
echo "AWS_DR_LEGACY_INTERFACE=$EXPECTED_LEGACY_INTERFACE"
echo "READ_ONLY_DIAGNOSTIC=YES"

status=0
gateway_status="UNKNOWN"
db_ping_status="UNKNOWN"
db_ssh_status="UNKNOWN"
db_mysql_status="UNKNOWN"
route_line=""

if ! command -v ip >/dev/null 2>&1; then
  echo "MSP_IP_COMMAND=UNAVAILABLE"
  status=2
else
  echo "MSP_IP_COMMAND=AVAILABLE"
  route_line="$(ip route get "$db_host" 2>/dev/null || true)"
  if [[ -n "$route_line" ]]; then
    echo "MSP_ROUTE_TO_DB=$route_line"
    if grep -Eq '(^|[[:space:]])dev[[:space:]]+wg0([[:space:]]|$)' <<<"$route_line"; then
      echo "MSP_ROUTE_CLASS=LOCAL_WG0"
    elif grep -Eq "(^|[[:space:]])via[[:space:]]+$gateway([[:space:]]|$)" <<<"$route_line"; then
      echo "MSP_ROUTE_CLASS=PF_SENSE_LAN_GATEWAY"
    else
      echo "MSP_ROUTE_CLASS=OTHER"
    fi
  else
    echo "MSP_ROUTE_TO_DB=UNAVAILABLE"
    echo "MSP_ROUTE_CLASS=UNKNOWN"
    status=2
  fi
  neigh_gateway="$(ip neigh show "$gateway" 2>/dev/null || true)"
  neigh_db="$(ip neigh show "$db_host" 2>/dev/null || true)"
  [[ -n "$neigh_gateway" ]] && echo "MSP_GATEWAY_NEIGHBOR=$neigh_gateway" || echo "MSP_GATEWAY_NEIGHBOR=NOT_REPORTED"
  [[ -n "$neigh_db" ]] && echo "MSP_DB_NEIGHBOR=$neigh_db" || echo "MSP_DB_NEIGHBOR=NOT_REPORTED"
fi

if ping -c 3 -W 1 "$gateway" >/dev/null 2>&1; then
  gateway_status="PASS"
else
  gateway_status="FAIL"
  status=1
fi
echo "MSP_GATEWAY_REACHABILITY=$gateway_status"

if ping -c 3 -W 1 "$db_host" >/dev/null 2>&1; then
  db_ping_status="PASS"
else
  db_ping_status="FAIL"
  status=1
fi
echo "ONPREM_DB_PING=$db_ping_status"

if command -v nc >/dev/null 2>&1; then
  if nc -z -w 3 "$db_host" "$ssh_port" >/dev/null 2>&1; then
    db_ssh_status="PASS"
  else
    db_ssh_status="FAIL"
    status=1
  fi
  if nc -z -w 3 "$db_host" "$db_port" >/dev/null 2>&1; then
    db_mysql_status="PASS"
  else
    db_mysql_status="FAIL"
    status=1
  fi
else
  db_ssh_status="TOOL_UNAVAILABLE"
  db_mysql_status="TOOL_UNAVAILABLE"
  status=2
fi
echo "ONPREM_DB_SSH=$db_ssh_status"
echo "ONPREM_DB_MYSQL=$db_mysql_status"

if command -v wg >/dev/null 2>&1; then
  echo "MSP_WG_TOOL=AVAILABLE"
  if wg show wg0 >/dev/null 2>&1; then
    echo "MSP_WG0_STATE=PRESENT"
  else
    echo "MSP_WG0_STATE=NOT_PRESENT_OR_UNAVAILABLE"
  fi
else
  echo "MSP_WG_TOOL=UNAVAILABLE"
  echo "MSP_WG0_STATE=NOT_OBSERVABLE"
fi

if [[ "$gateway_status" == PASS && "$db_mysql_status" == FAIL ]]; then
  echo "PATH_ROOT_CAUSE_CANDIDATE=GATEWAY_OR_ONPREM_SEGMENT"
elif [[ "$gateway_status" == FAIL ]]; then
  echo "PATH_ROOT_CAUSE_CANDIDATE=MSP_LAN_GATEWAY_UNREACHABLE"
elif [[ "$db_mysql_status" == PASS ]]; then
  echo "PATH_ROOT_CAUSE_CANDIDATE=PATH_REACHABLE"
else
  echo "PATH_ROOT_CAUSE_CANDIDATE=UNKNOWN"
fi

echo "AWS_DR_WG_CUTOVER=BLOCKED_UNTIL_ONPREM_PATH_VERIFIED"
exit "$status"
