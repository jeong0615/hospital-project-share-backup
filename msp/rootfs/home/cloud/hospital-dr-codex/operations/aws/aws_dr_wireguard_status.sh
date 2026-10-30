#!/usr/bin/env bash
set -euo pipefail

# Read-only status checker for the optional AWS DR WireGuard path.
# It never changes interfaces, routes, keys, AWS resources, or firewall state.

EXPECTED_INTERFACE="wg-aws-dr"
EXPECTED_CIDR="IP_REDACTED/24"
EXPECTED_GATEWAY_ADDRESS="IP_REDACTED/24"
EXPECTED_PEER_ADDRESS="IP_REDACTED"
EXPECTED_AWS_DB="AWS_PUBLIC_IP_REDACTED"
EXPECTED_ENDPOINT="AWS_PUBLIC_IP_REDACTED:51821"
EXPECTED_PORT="51821"
EXPECTED_INGRESS_CIDR="IP_REDACTED/32"

enabled="${AWS_DR_WG_ENABLED:-false}"
role="${AWS_DR_WG_ROLE:-gateway}"
interface="${AWS_DR_WG_INTERFACE:-$EXPECTED_INTERFACE}"
cidr="${AWS_DR_WG_CIDR:-$EXPECTED_CIDR}"
gateway_address="${AWS_DR_WG_GATEWAY_ADDRESS:-$EXPECTED_GATEWAY_ADDRESS}"
peer_address="${AWS_DR_WG_PEER_ADDRESS:-$EXPECTED_PEER_ADDRESS}"
aws_db="${AWS_DR_WG_AWS_DB_IP:-$EXPECTED_AWS_DB}"
endpoint="${AWS_DR_WG_ENDPOINT:-$EXPECTED_ENDPOINT}"
port="${AWS_DR_WG_PORT:-$EXPECTED_PORT}"
ingress_cidr="${AWS_DR_WG_PEER_INGRESS_CIDR:-$EXPECTED_INGRESS_CIDR}"

config_error() {
  echo "AWS_DR_WG_CONFIG_ERROR=$*" >&2
  exit 2
}

case "$enabled" in
  true|false) ;;
  *) config_error "AWS_DR_WG_ENABLED must be true or false" ;;
esac

case "$role" in
  gateway)
    local_address="$gateway_address"
    route_target="${EXPECTED_PEER_ADDRESS}/32"
    ;;
  client)
    local_address="${EXPECTED_PEER_ADDRESS}/32"
    route_target="${EXPECTED_AWS_DB}/32"
    ;;
  *) config_error "AWS_DR_WG_ROLE must be gateway or client" ;;
esac

[[ "$interface" == "$EXPECTED_INTERFACE" ]] || config_error "interface must be $EXPECTED_INTERFACE"
[[ "$cidr" == "$EXPECTED_CIDR" ]] || config_error "CIDR must be $EXPECTED_CIDR"
[[ "$gateway_address" == "$EXPECTED_GATEWAY_ADDRESS" ]] || config_error "gateway address must be $EXPECTED_GATEWAY_ADDRESS"
[[ "$peer_address" == "$EXPECTED_PEER_ADDRESS" ]] || config_error "peer address must be $EXPECTED_PEER_ADDRESS"
[[ "$aws_db" == "$EXPECTED_AWS_DB" ]] || config_error "AWS DB address must be $EXPECTED_AWS_DB"
[[ "$endpoint" == "$EXPECTED_ENDPOINT" ]] || config_error "endpoint must be $EXPECTED_ENDPOINT"
[[ "$port" == "$EXPECTED_PORT" ]] || config_error "WireGuard port must be UDP $EXPECTED_PORT"
[[ "$ingress_cidr" == "$EXPECTED_INGRESS_CIDR" ]] || config_error "ingress must remain $EXPECTED_INGRESS_CIDR"

case "$interface $cidr $peer_address" in
  *wg0*|*wg-aws-hub*|*10.250.*|*192.168.200.*)
    config_error "MSP/legacy WireGuard address space is forbidden" ;;
esac

echo "AWS_DR_WG_INTERFACE=$interface"
echo "AWS_DR_WG_ROLE=$role"
echo "AWS_DR_WG_CIDR=$cidr"
echo "AWS_DR_WG_ENDPOINT=$endpoint"
echo "AWS_DR_WG_INGRESS=$ingress_cidr"
echo "AWS_DR_WG_SOURCE_DEST_CHECK=REQUIRED_DISABLED_ON_WEB"
echo "AWS_DR_WG_SNAT=NOT_CONFIGURED_ROUTED_SOURCE_PRESERVED"

if [[ "$enabled" == "false" ]]; then
  echo "AWS_DR_WG_STATUS=DISABLED_BY_DESIGN"
  echo "CONFIG_AVAILABLE=YES"
  echo "LIVE_PATH_ENABLED=NO"
  exit 0
fi

command -v ip >/dev/null 2>&1 || config_error "ip command is required for enabled status checks"
command -v wg >/dev/null 2>&1 || config_error "wg command is required for enabled status checks"

status=0
if ip link show "$interface" >/dev/null 2>&1; then
  echo "AWS_DR_WG_INTERFACE_STATE=UP_OR_PRESENT"
else
  echo "AWS_DR_WG_INTERFACE_STATE=DOWN"
  status=1
fi

addresses="$(ip -4 -o addr show dev "$interface" 2>/dev/null || true)"
if grep -Fq "${local_address}" <<<"$addresses"; then
  echo "AWS_DR_WG_ADDRESS=PASS"
else
  echo "AWS_DR_WG_ADDRESS=FAIL"
  status=1
fi

route_line="$(ip route show "$route_target" 2>/dev/null || true)"
if grep -Fq "$interface" <<<"$route_line"; then
  echo "AWS_DR_WG_PEER_ROUTE=PASS"
else
  echo "AWS_DR_WG_PEER_ROUTE=NOT_PRESENT"
  status=1
fi

endpoint_line="$(wg show "$interface" endpoints 2>/dev/null | awk 'NR == 1 {print $2}')"
if [[ -n "$endpoint_line" && "$endpoint_line" != "(none)" ]]; then
  echo "AWS_DR_WG_PEER_ENDPOINT=$endpoint_line"
else
  echo "AWS_DR_WG_PEER_ENDPOINT=NOT_REPORTED"
  status=1
fi

handshake_line="$(wg show "$interface" latest-handshakes 2>/dev/null | awk 'NR == 1 {print $2}')"
if [[ -n "$handshake_line" && "$handshake_line" != "0" ]]; then
  now="$(date +%s)"
  age=$((now - handshake_line))
  (( age < 0 )) && age=0
  echo "AWS_DR_WG_LATEST_HANDSHAKE_AGE_SECONDS=$age"
else
  echo "AWS_DR_WG_LATEST_HANDSHAKE=NOT_ESTABLISHED"
  status=1
fi

transfer_line="$(wg show "$interface" transfer 2>/dev/null | awk 'NR == 1 {print $2, $3}')"
if [[ -n "$transfer_line" ]]; then
  echo "AWS_DR_WG_TRANSFER_RX_TX_BYTES=$transfer_line"
else
  echo "AWS_DR_WG_TRANSFER=NOT_REPORTED"
  status=1
fi

if [[ "${1:-}" == "--tcp-check" ]]; then
  command -v nc >/dev/null 2>&1 || config_error "nc command is required for --tcp-check"
  if nc -z -w 5 "$peer_address" 3306 >/dev/null 2>&1; then
    echo "AWS_DB_TO_ONPREM_WG_MYSQL=PASS"
  else
    echo "AWS_DB_TO_ONPREM_WG_MYSQL=FAIL"
    status=1
  fi
else
  echo "AWS_DB_TO_ONPREM_WG_MYSQL=NOT_RUN"
fi

if (( status == 0 )); then
  echo "AWS_DR_WG_STATUS=READY"
else
  echo "AWS_DR_WG_STATUS=NOT_READY"
fi
exit "$status"
