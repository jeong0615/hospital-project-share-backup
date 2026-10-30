#!/usr/bin/env bash
set -euo pipefail

# Read-only controller/local status check. It never calls Terraform apply,
# destroy, route mutation, instance mutation, or firewall mutation.

EXPECTED_REGION="${AWS_REGION:-ap-northeast-2}"
EXPECTED_VPC_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_INSTANCE_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_PRIVATE_IP="IP_REDACTED"
EXPECTED_WEB_PUBLIC_IP="AWS_PUBLIC_IP_REDACTED"
EXPECTED_WEB_ENI="AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_SUBNET_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_PRIVATE_ROUTE_TABLE="AWS_RESOURCE_ID_REDACTED"
EXPECTED_WEB_NAT_INTERFACE="wg-aws-dr"
EXPECTED_NAT_GATEWAY_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP_ALLOCATION_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP_PUBLIC_IP="AWS_PUBLIC_IP_REDACTED"
FORWARD_CHAIN="HOSPITAL-DR-NAT-FWD"
POSTROUTING_CHAIN="HOSPITAL-DR-NAT-POSTROUTING"
LOCAL_CHECK=0

if [ "${1:-}" = "--local" ]; then
  LOCAL_CHECK=1
  shift
fi
if [ "$#" -ne 0 ]; then
  echo "Usage: $0 [--local]" >&2
  exit 2
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "NAT_INSTANCE_STATUS=BLOCKED"
  echo "BLOCKER=AWS_CLI_UNAVAILABLE"
  exit 2
fi

aws_query() {
  aws ec2 "$@" --region "$EXPECTED_REGION" --output text 2>/dev/null
}

instance_record="$(aws_query describe-instances --instance-ids "$EXPECTED_WEB_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].[State.Name,PrivateIpAddress,PublicIpAddress,SourceDestCheck,VpcId,SubnetId,NetworkInterfaces[0].NetworkInterfaceId]' || true)"
route_record="$(aws_query describe-route-tables --route-table-ids "$EXPECTED_PRIVATE_ROUTE_TABLE" \
  --query "RouteTables[0].Routes[?DestinationCidrBlock=='AWS_PUBLIC_IP_REDACTED/0'].[State,NatGatewayId,NetworkInterfaceId] | [0]" || true)"
web_eip_record="$(aws_query describe-addresses --public-ips "$EXPECTED_WEB_PUBLIC_IP" \
  --query 'Addresses[0].[PublicIp,AssociationId,InstanceId,NetworkInterfaceId,PrivateIpAddress]' || true)"
eip_record="$(aws_query describe-addresses --allocation-ids "$EXPECTED_NAT_EIP_ALLOCATION_ID" \
  --query 'Addresses[0].[AllocationId,PublicIp,AssociationId]' || true)"
nat_records="$(aws_query describe-nat-gateways --filter "Name=vpc-id,Values=$EXPECTED_VPC_ID" \
  --query 'NatGateways[].[NatGatewayId,State,SubnetId,NatGatewayAddresses[0].AllocationId,NatGatewayAddresses[0].PublicIp]' || true)"

if [ -z "$instance_record" ]; then
  echo "NAT_INSTANCE_STATUS=BLOCKED"
  echo "BLOCKER=AWS_READ_ONLY_QUERY_FAILED"
  exit 2
fi

read -r web_state web_private web_public source_dest web_vpc web_subnet web_eni <<< "$instance_record"
read -r route_state route_nat route_eni <<< "${route_record:-None}"
read -r web_eip_public web_eip_association web_eip_instance web_eip_eni web_eip_private <<< "${web_eip_record:-None}"
read -r eip_alloc eip_public eip_assoc <<< "${eip_record:-None}"

echo "WEB_INSTANCE_STATE=${web_state:-UNKNOWN}"
echo "WEB_PRIVATE_IP=${web_private:-UNKNOWN}"
echo "WEB_PUBLIC_IP=${web_public:-UNKNOWN}"
echo "WEB_VPC_ID=${web_vpc:-UNKNOWN}"
echo "WEB_SUBNET_ID=${web_subnet:-UNKNOWN}"
echo "WEB_ENI=${web_eni:-UNKNOWN}"
echo "WEB_EIP_PUBLIC_IP=${web_eip_public:-UNKNOWN}"
echo "WEB_EIP_ASSOCIATION=${web_eip_association:-NONE}"
echo "WEB_EIP_INSTANCE_ID=${web_eip_instance:-NONE}"
echo "WEB_EIP_ENI=${web_eip_eni:-NONE}"
echo "WEB_EIP_PRIVATE_IP=${web_eip_private:-NONE}"
echo "SOURCE_DEST_CHECK=${source_dest:-UNKNOWN}"
echo "PRIVATE_ROUTE_TABLE=${EXPECTED_PRIVATE_ROUTE_TABLE}"
echo "PRIVATE_DEFAULT_ROUTE_STATE=${route_state:-NONE}"
if [ -n "${route_nat:-}" ] && [ "$route_nat" != "None" ]; then
  echo "PRIVATE_DEFAULT_ROUTE_TARGET=${route_nat}"
elif [ -n "${route_eni:-}" ] && [ "$route_eni" != "None" ]; then
  echo "PRIVATE_DEFAULT_ROUTE_TARGET=${route_eni}"
else
  echo "PRIVATE_DEFAULT_ROUTE_TARGET=NONE"
fi
echo "NAT_GATEWAY_EXPECTED_ID=${EXPECTED_NAT_GATEWAY_ID}"
echo "NAT_EIP=${eip_public:-UNKNOWN}"
echo "NAT_EIP_ALLOCATION_ID=${eip_alloc:-UNKNOWN}"
echo "NAT_EIP_ASSOCIATION=${eip_assoc:-NONE}"

if [ "${eip_alloc:-}" = "$EXPECTED_NAT_EIP_ALLOCATION_ID" ] \
  && [ "${eip_public:-}" = "$EXPECTED_NAT_EIP_PUBLIC_IP" ]; then
  if [ -z "${eip_assoc:-}" ] || [ "${eip_assoc:-}" = "None" ]; then
    echo "NAT_EIP_STATE=ALLOCATED_UNASSOCIATED"
    echo "NAT_EIP_DEPENDENCY=RESERVED_NOT_REQUIRED_FOR_WEB_NAT_INSTANCE"
  else
    echo "NAT_EIP_STATE=ALLOCATED_ASSOCIATED"
    echo "NAT_EIP_DEPENDENCY=ASSOCIATED_RESOURCE_PRESENT"
  fi
else
  echo "NAT_EIP_STATE=CONTRACT_MISMATCH"
  echo "NAT_EIP_DEPENDENCY=CONTRACT_MISMATCH"
fi

nat_state="NOT_FOUND"
nat_subnet="NONE"
nat_allocation="NONE"
nat_public="NONE"
while IFS=$'\t' read -r nat_id state subnet allocation public_ip; do
  [ -n "${nat_id:-}" ] || continue
  if [ "$nat_id" = "$EXPECTED_NAT_GATEWAY_ID" ]; then
    nat_state="$state"
    nat_subnet="$subnet"
    nat_allocation="$allocation"
    nat_public="$public_ip"
  fi
done <<< "$nat_records"
echo "NAT_GATEWAY_STATE=${nat_state}"
echo "NAT_GATEWAY_SUBNET=${nat_subnet}"
echo "NAT_GATEWAY_PUBLIC_IP=${nat_public}"
echo "NAT_GATEWAY_ALLOCATION_ID=${nat_allocation}"

if [ "$LOCAL_CHECK" -eq 1 ]; then
  ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo UNKNOWN)"
  firewall_backend="$(iptables --version 2>/dev/null || echo IPTABLES_UNAVAILABLE)"
  iptables -S "$FORWARD_CHAIN" >/dev/null 2>&1 && forward_rule=PRESENT || forward_rule=ABSENT
  iptables -t nat -S "$POSTROUTING_CHAIN" >/dev/null 2>&1 && nat_rule=PRESENT || nat_rule=ABSENT
  ip link show "$EXPECTED_WEB_NAT_INTERFACE" >/dev/null 2>&1 && wg_interface=UP_OR_PRESENT || wg_interface=ABSENT
  wg_route="$(ip route show IP_REDACTED/24 2>/dev/null | tr '\n' ' ' || true)"
  echo "IP_FORWARD=${ip_forward}"
  echo "WEB_FIREWALL_BACKEND=${firewall_backend}"
  echo "NAT_RULE_PRESENT=${nat_rule}"
  echo "FORWARD_RULE_PRESENT=${forward_rule}"
  echo "WIREGUARD_INTERFACE=${wg_interface}"
  echo "WIREGUARD_ROUTE=${wg_route:-NONE}"
  echo "NAT_GUEST_STATUS=LOCAL_DIAGNOSTICS_ONLY"
else
  echo "IP_FORWARD=NOT_CHECKED_CONTROLLER_ONLY"
  echo "WEB_FIREWALL_BACKEND=NOT_CHECKED_CONTROLLER_ONLY"
  echo "NAT_RULE_PRESENT=NOT_CHECKED_CONTROLLER_ONLY"
  echo "FORWARD_RULE_PRESENT=NOT_CHECKED_CONTROLLER_ONLY"
  echo "WIREGUARD_INTERFACE=NOT_CHECKED_CONTROLLER_ONLY"
  echo "WIREGUARD_ROUTE=NOT_CHECKED_CONTROLLER_ONLY"
  echo "NAT_GUEST_STATUS=NOT_CHECKED_CONTROLLER_ONLY"
fi

web_identity_ok=1
if [ "${web_private:-}" != "$EXPECTED_WEB_PRIVATE_IP" ] \
  || [ "${web_public:-}" != "$EXPECTED_WEB_PUBLIC_IP" ] \
  || [ "${web_eip_public:-}" != "$EXPECTED_WEB_PUBLIC_IP" ] \
  || [ -z "${web_eip_association:-}" ] || [ "${web_eip_association:-}" = "None" ] \
  || [ "${web_eip_instance:-}" != "$EXPECTED_WEB_INSTANCE_ID" ] \
  || [ "${web_eip_eni:-}" != "$EXPECTED_WEB_ENI" ] \
  || [ "${web_eip_private:-}" != "$EXPECTED_WEB_PRIVATE_IP" ] \
  || [ "${web_vpc:-}" != "$EXPECTED_VPC_ID" ] \
  || [ "${web_subnet:-}" != "$EXPECTED_WEB_SUBNET_ID" ] \
  || [ "${web_eni:-}" != "$EXPECTED_WEB_ENI" ] \
  || [ "${source_dest:-}" != "False" ]; then
  web_identity_ok=0
fi

blackhole_route=0
if [ "${route_state:-}" = "blackhole" ] \
  && [ "${route_nat:-}" = "$EXPECTED_NAT_GATEWAY_ID" ]; then
  blackhole_route=1
fi

if [ "$web_identity_ok" -eq 1 ] \
  && [ "${route_eni:-}" = "$EXPECTED_WEB_ENI" ] \
  && [ "${route_state:-}" = "active" ]; then
  current_mode=WEB_NAT_INSTANCE_CANDIDATE
  current_status=PENDING_LIVE_TEST
  if [ "${web_state:-}" = "running" ]; then
    bootstrap_status=READY_FOR_GUEST_CONFIGURATION
  else
    bootstrap_status=WAIT_WEB_START
  fi
elif [ "${route_nat:-}" = "$EXPECTED_NAT_GATEWAY_ID" ] \
  && [ "${route_state:-}" = "active" ] \
  && [ "$nat_state" = "available" ]; then
  current_mode=NAT_GATEWAY
  current_status=NOT_CONFIGURED
  bootstrap_status=NOT_APPLICABLE
elif [ "$blackhole_route" -eq 1 ]; then
  current_mode=BLACKHOLE
  if [ "$nat_state" = "NOT_FOUND" ] && [ "$web_identity_ok" -eq 1 ] \
    && [ "${web_state:-}" = "running" ] \
    && [ "${eip_alloc:-}" = "$EXPECTED_NAT_EIP_ALLOCATION_ID" ] \
    && [ "${eip_public:-}" = "$EXPECTED_NAT_EIP_PUBLIC_IP" ]; then
    current_status=READY_FOR_BLACKHOLE_RECOVERY
    bootstrap_status=ROUTE_RECOVERY_PLAN_ONLY
  elif [ "$web_identity_ok" -eq 0 ]; then
    current_status=DRIFT
    bootstrap_status=BLOCKED_IDENTITY_MISMATCH
  else
    current_status=NOT_READY
    bootstrap_status=BLOCKED_ROUTE_TARGET_MISMATCH
  fi
elif [ "${route_eni:-}" = "$EXPECTED_WEB_ENI" ] \
  && [ "${route_state:-}" = "blackhole" ] \
  && [ "$web_identity_ok" -eq 1 ] \
  && [ "${web_state:-}" = "stopped" ]; then
  current_mode=BLACKHOLE
  current_status=PENDING_LIVE_TEST
  bootstrap_status=READY_TO_START_WEB
elif [ "${route_eni:-}" = "$EXPECTED_WEB_ENI" ] \
  && [ "${route_state:-}" = "blackhole" ] \
  && [ "$web_identity_ok" -eq 1 ]; then
  current_mode=BLACKHOLE
  current_status=NOT_READY
  bootstrap_status=BLOCKED_ROUTE_BLACKHOLE
elif [ "${route_state:-}" = "blackhole" ] || [ "${route_state:-}" = "None" ] \
  || [ -z "${route_state:-}" ]; then
  current_mode=BLACKHOLE
  current_status=NOT_READY
  bootstrap_status=BLOCKED_ROUTE_UNEXPECTED
else
  current_mode=UNKNOWN
  current_status=DRIFT
  bootstrap_status=BLOCKED_AWS_STATE_DRIFT
fi

echo "CURRENT_EGRESS_MODE=${current_mode}"
echo "NAT_INSTANCE_STATUS=${current_status}"
echo "NAT_BOOTSTRAP_STATUS=${bootstrap_status}"

case "$current_status" in
  NOT_CONFIGURED|READY_FOR_BLACKHOLE_RECOVERY) exit 0 ;;
  PENDING_LIVE_TEST) exit 2 ;;
  NOT_READY|DRIFT) exit 1 ;;
  *) exit 2 ;;
esac
