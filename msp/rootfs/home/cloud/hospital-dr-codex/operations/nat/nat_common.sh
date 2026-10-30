#!/usr/bin/env bash
set -euo pipefail

# Shared, fail-closed implementation for the three manual NAT lifecycle
# entrypoints.  This file is intentionally owned by operations/nat rather than
# operations/finops: FinOps may report cost state, but it must not own NAT
# mutations.
NAT_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$NAT_SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

EXPECTED_TERRAFORM_DIR="/home/cloud/hospital-dr-terraform"
CANONICAL_TERRAFORM_DIR="/home/cloud/hospital-dr-codex/infra/terraform"
EXPECTED_DR_VPC_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP_ALLOCATION_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_NAT_EIP_PUBLIC_IP="AWS_PUBLIC_IP_REDACTED"
EXPECTED_PUBLIC_SUBNET_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_PRIVATE_ROUTE_TABLE_ID="AWS_RESOURCE_ID_REDACTED"
EXPECTED_DB_INSTANCE_ID="AWS_RESOURCE_ID_REDACTED"

NAT_REGION="${AWS_REGION:-ap-northeast-2}"
NAT_TF_DIR="${TF_DIR:-${DR_TERRAFORM_DIR:-}}"
NAT_SECRET_FILE="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"
NAT_LOG_FILE="${LOG_FILE:-${DR_LOG_DIR:-/var/log/hospital-dr}/nat_gateway.log}"
NAT_LOCK_FILE="${DR_TERRAFORM_LOCK_FILE:-${DR_STATE_DIR:-/var/lib/hospital-dr}/terraform.lock}"
NAT_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR:-/var/lib/hospital-dr}/workflow.lock}"
NAT_STATE_FAILURE_STATUS="PARTIAL_FAILURE"

nat_config_error() {
  echo "[NAT CONFIG ERROR] $*" >&2
  return 1
}

nat_runtime_prepare() {
  local mode="${1:-read}"

  # Loading the external env is necessary for AWS_REGION and Terraform input
  # variables, but no value from it is ever printed by this module.
  if [ -f "$NAT_SECRET_FILE" ]; then
    # shellcheck disable=SC1090
    source "$NAT_SECRET_FILE"
  fi
  NAT_REGION="${AWS_REGION:-ap-northeast-2}"
  NAT_TF_DIR="${TF_DIR:-${DR_TERRAFORM_DIR:-}}"
  NAT_LOG_FILE="${LOG_FILE:-${DR_LOG_DIR:-/var/log/hospital-dr}/nat_gateway.log}"
  NAT_LOCK_FILE="${DR_TERRAFORM_LOCK_FILE:-${DR_STATE_DIR:-/var/lib/hospital-dr}/terraform.lock}"
  NAT_WORKFLOW_LOCK_FILE="${DR_WORKFLOW_LOCK_FILE:-${DR_STATE_DIR:-/var/lib/hospital-dr}/workflow.lock}"

  if [ -z "${TF_VAR_management_ipv4_cidrs:-}" ] \
    && [ -n "${DR_MANAGEMENT_IPV4_CIDRS:-}" ]; then
    export TF_VAR_management_ipv4_cidrs="$DR_MANAGEMENT_IPV4_CIDRS"
  fi

  mkdir -p "$(dirname -- "$NAT_LOG_FILE")"
  if [ "$mode" = "mutating" ]; then
    dr_state_prepare
    dr_workflow_lock_prepare
    if [ "${DR_WORKFLOW_LOCK_HELD:-0}" != "1" ]; then
      exec 7>"$NAT_WORKFLOW_LOCK_FILE"
      if ! flock -n 7; then
        echo "[NAT ERROR] Another DR workflow is already in progress."
        exit 1
      fi
    fi
    export DR_WORKFLOW_LOCK_HELD=1

    if [ "${DR_TERRAFORM_LOCK_HELD:-0}" != "1" ]; then
      exec 8>"$NAT_LOCK_FILE"
      if ! flock -n 8; then
        echo "[NAT ERROR] Another Terraform operation is already in progress."
        exit 1
      fi
    fi
    export DR_TERRAFORM_LOCK_HELD=1
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then dr_state_mark_failure "${NAT_STATE_FAILURE_STATUS:-PARTIAL_FAILURE}" 2>/dev/null || true; fi; exit "$rc"' ERR
  fi

  # Keep the existing operational log, while status remains usable from a
  # terminal because tee also preserves stdout.
  exec > >(tee -a "$NAT_LOG_FILE") 2>&1
}

terraform_state_attribute() {
  local address="$1"
  local attribute="$2"
  local state_json value

  if ! state_json="$(terraform state pull 2>/dev/null)"; then
    nat_config_error "Operational Terraform state is missing or unreadable while reading ${address}.${attribute}."
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    nat_config_error "python3 is required to inspect operational Terraform state."
    return 1
  fi
  if ! value="$(printf '%s' "$state_json" | python3 -c '
import json
import sys

address, attribute = sys.argv[1:3]
state = json.load(sys.stdin)
for resource in state.get("resources", []):
    resource_address = resource.get("address")
    mode_prefix = "data." if resource.get("mode") == "data" else ""
    base_address = "{}{}.{}".format(mode_prefix, resource.get("type"), resource.get("name"))
    if resource.get("module"):
        base_address = "{}.{}".format(resource.get("module"), base_address)
    for instance in resource.get("instances", []):
        instance_address = resource_address or base_address
        if not resource_address:
            index_key = instance.get("index_key")
            if index_key is not None:
                instance_address = f"{base_address}[{index_key!r}]" if isinstance(index_key, str) else f"{base_address}[{index_key}]"
        if instance_address == address:
            value = instance.get("attributes", {}).get(attribute)
            if value is None or isinstance(value, (dict, list)):
                raise SystemExit(1)
            print(value)
            raise SystemExit(0)
raise SystemExit(1)
' "$address" "$attribute" 2>/dev/null)"; then
    nat_config_error "Required operational Terraform state attribute is missing: ${address}.${attribute}."
    return 1
  fi
  if [ -z "$value" ]; then
    nat_config_error "Required operational Terraform state attribute is empty: ${address}.${attribute}."
    return 1
  fi
  printf '%s\n' "$value"
}

require_terraform_state_attribute() {
  local address="$1"
  local attribute="$2"
  local expected="$3"
  local actual

  actual="$(terraform_state_attribute "$address" "$attribute")" || return 1
  if [ "$actual" != "$expected" ]; then
    nat_config_error "Operational Terraform state mismatch for ${address}.${attribute}: expected ${expected}, found ${actual}."
    return 1
  fi
}

nat_state_list() {
  terraform state list 2>/dev/null
}

nat_state_has() {
  local address="$1"
  local state_list="$2"
  printf '%s\n' "$state_list" | grep -Fqx "$address"
}

nat_state_nat_address() {
  local state_list="$1"
  if nat_state_has 'aws_nat_gateway.nat_gw[0]' "$state_list"; then
    printf '%s\n' 'aws_nat_gateway.nat_gw[0]'
    return 0
  fi
  if nat_state_has 'aws_nat_gateway.nat_gw' "$state_list"; then
    printf '%s\n' 'aws_nat_gateway.nat_gw'
    return 0
  fi
  return 1
}

nat_state_route_address() {
  local state_list="$1"
  if nat_state_has 'aws_route.private_internet[0]' "$state_list"; then
    printf '%s\n' 'aws_route.private_internet[0]'
    return 0
  fi
  if nat_state_has 'aws_route.private_internet' "$state_list"; then
    printf '%s\n' 'aws_route.private_internet'
    return 0
  fi
  return 1
}

nat_preflight() {
  local state_list resolved_tf_dir resolved_state_file

  if [ "${DR_TERRAFORM_DIR:-}" = "$CANONICAL_TERRAFORM_DIR" ] \
    || [ "$NAT_TF_DIR" = "$CANONICAL_TERRAFORM_DIR" ]; then
    nat_config_error "Canonical repository Terraform directory is not an operational state directory: ${CANONICAL_TERRAFORM_DIR}."
    return 1
  fi
  if [ "${DR_TERRAFORM_DIR:-}" != "$EXPECTED_TERRAFORM_DIR" ]; then
    nat_config_error "DR_TERRAFORM_DIR must be ${EXPECTED_TERRAFORM_DIR}; refusing to use ${DR_TERRAFORM_DIR:-unset}."
    return 1
  fi
  if [ "$NAT_TF_DIR" != "$EXPECTED_TERRAFORM_DIR" ]; then
    nat_config_error "TF_DIR must resolve to ${EXPECTED_TERRAFORM_DIR}; refusing to use ${NAT_TF_DIR}."
    return 1
  fi
  if ! resolved_tf_dir="$(realpath -e "$DR_TERRAFORM_DIR" 2>/dev/null)" \
    || [ "$resolved_tf_dir" != "$EXPECTED_TERRAFORM_DIR" ]; then
    nat_config_error "DR_TERRAFORM_DIR does not resolve to the approved operational directory: ${EXPECTED_TERRAFORM_DIR}."
    return 1
  fi
  if ! cd "$NAT_TF_DIR"; then
    nat_config_error "Operational Terraform directory cannot be entered: ${NAT_TF_DIR}."
    return 1
  fi
  if [ ! -r "$NAT_TF_DIR/terraform.tfstate" ]; then
    nat_config_error "Operational Terraform state is missing or unreadable: ${NAT_TF_DIR}/terraform.tfstate."
    return 1
  fi
  if ! resolved_state_file="$(realpath -e "$NAT_TF_DIR/terraform.tfstate" 2>/dev/null)"; then
    nat_config_error "Operational Terraform state path cannot be resolved: ${NAT_TF_DIR}/terraform.tfstate."
    return 1
  fi
  case "$resolved_state_file" in
    "$CANONICAL_TERRAFORM_DIR"/*)
      nat_config_error "Canonical repository Terraform state cannot be used as operational state: ${resolved_state_file}."
      return 1
      ;;
  esac
  if ! state_list="$(nat_state_list)"; then
    nat_config_error "Operational Terraform state could not be read from ${NAT_TF_DIR}."
    return 1
  fi
  if ! nat_state_has 'aws_vpc.dr_vpc' "$state_list"; then
    nat_config_error "Operational Terraform state does not contain aws_vpc.dr_vpc."
    return 1
  fi
  for requirement in \
    'aws_vpc.dr_vpc|id|AWS_RESOURCE_ID_REDACTED' \
    'aws_eip.nat_eip|allocation_id|AWS_RESOURCE_ID_REDACTED' \
    'aws_eip.nat_eip|public_ip|AWS_PUBLIC_IP_REDACTED' \
    'aws_subnet.public_subnet|id|AWS_RESOURCE_ID_REDACTED' \
    'aws_route_table.private_rt|id|AWS_RESOURCE_ID_REDACTED'; do
    IFS='|' read -r address attribute expected <<< "$requirement"
    require_terraform_state_attribute "$address" "$attribute" "$expected" || return 1
  done
}

nat_aws_eip_details() {
  aws ec2 describe-addresses \
    --region "$NAT_REGION" \
    --allocation-ids "$EXPECTED_NAT_EIP_ALLOCATION_ID" \
    --query 'Addresses[0].[AllocationId,PublicIp,AssociationId]' \
    --output text 2>/dev/null
}

nat_verify_eip() {
  local details allocation public_ip
  if ! details="$(nat_aws_eip_details)" || [ -z "$details" ] || [ "$details" = "None" ]; then
    nat_config_error "Expected preserved NAT EIP ${EXPECTED_NAT_EIP_ALLOCATION_ID} is missing or unreadable."
    return 1
  fi
  read -r allocation public_ip _ <<< "$details"
  if [ "$allocation" != "$EXPECTED_NAT_EIP_ALLOCATION_ID" ]; then
    nat_config_error "NAT EIP allocation mismatch: expected ${EXPECTED_NAT_EIP_ALLOCATION_ID}, found ${allocation}."
    return 1
  fi
  if [ "$public_ip" != "$EXPECTED_NAT_EIP_PUBLIC_IP" ]; then
    nat_config_error "NAT EIP public IP mismatch: expected ${EXPECTED_NAT_EIP_PUBLIC_IP}, found ${public_ip}."
    return 1
  fi
}

nat_aws_nat_records() {
  local output
  output="$(
  aws ec2 describe-nat-gateways \
    --region "$NAT_REGION" \
    --filter "Name=vpc-id,Values=${EXPECTED_DR_VPC_ID}" \
              "Name=state,Values=pending,available,deleting,failed" \
    --query 'NatGateways[].[NatGatewayId,State,SubnetId,NatGatewayAddresses[0].AllocationId,NatGatewayAddresses[0].PublicIp]' \
    --output text 2>/dev/null
  )" || return 1
  [ "$output" = "None" ] && output=""
  printf '%s\n' "$output"
}

nat_aws_nat_by_id() {
  local nat_id="$1"
  aws ec2 describe-nat-gateways \
    --region "$NAT_REGION" \
    --nat-gateway-ids "$nat_id" \
    --query 'NatGateways[0].[NatGatewayId,State,SubnetId,NatGatewayAddresses[0].AllocationId,NatGatewayAddresses[0].PublicIp]' \
    --output text 2>/dev/null
}

nat_route_details() {
  local output
  output="$(
  aws ec2 describe-route-tables \
    --region "$NAT_REGION" \
    --route-table-ids "$EXPECTED_PRIVATE_ROUTE_TABLE_ID" \
    --query "RouteTables[0].Routes[?DestinationCidrBlock=='AWS_PUBLIC_IP_REDACTED/0'].[State,NatGatewayId]" \
    --output text 2>/dev/null
  )" || return 1
  [ "$output" = "None" ] && output=""
  printf '%s\n' "$output"
}

nat_record_matches_expected() {
  local record="$1"
  local nat_id state subnet allocation public_ip
  read -r nat_id state subnet allocation public_ip <<< "$record"
  [ "$nat_id" != "" ] && [ "$nat_id" != "None" ] \
    && [ "$state" = "available" ] \
    && [ "$subnet" = "$EXPECTED_PUBLIC_SUBNET_ID" ] \
    && [ "$allocation" = "$EXPECTED_NAT_EIP_ALLOCATION_ID" ] \
    && [ "$public_ip" = "$EXPECTED_NAT_EIP_PUBLIC_IP" ]
}

nat_route_matches() {
  local route_details="$1"
  local nat_id="$2"
  printf '%s\n' "$route_details" | awk -v expected="$nat_id" '$1 == "active" && $2 == expected { found=1 } END { exit(found ? 0 : 1) }'
}

nat_verify_ready_by_id() {
  local nat_id="$1"
  local record route_details actual_id state subnet allocation public_ip
  if ! record="$(nat_aws_nat_by_id "$nat_id")"; then
    nat_config_error "NAT Gateway ${nat_id} does not match the approved available NAT identity."
    return 1
  fi
  read -r actual_id state subnet allocation public_ip <<< "$record"
  if [ "$actual_id" != "$nat_id" ]; then
    nat_config_error "NAT Gateway identity mismatch: expected ${nat_id}, found ${actual_id:-missing}."
    return 1
  fi
  if [ "$state" != "available" ]; then
    nat_config_error "NAT Gateway ${nat_id} is not available: ${state:-missing}."
    return 1
  fi
  if [ "$subnet" != "$EXPECTED_PUBLIC_SUBNET_ID" ]; then
    nat_config_error "NAT Gateway subnet mismatch: expected ${EXPECTED_PUBLIC_SUBNET_ID}, found ${subnet:-missing}."
    return 1
  fi
  if [ "$allocation" != "$EXPECTED_NAT_EIP_ALLOCATION_ID" ]; then
    nat_config_error "NAT Gateway allocation mismatch: expected ${EXPECTED_NAT_EIP_ALLOCATION_ID}, found ${allocation:-missing}."
    return 1
  fi
  if [ "$public_ip" != "$EXPECTED_NAT_EIP_PUBLIC_IP" ]; then
    nat_config_error "NAT Gateway public IP mismatch: expected ${EXPECTED_NAT_EIP_PUBLIC_IP}, found ${public_ip:-missing}."
    return 1
  fi
  route_details="$(nat_route_details)" || {
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} could not be read."
    return 1
  }
  if ! nat_route_matches "$route_details" "$nat_id"; then
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} has no active AWS_PUBLIC_IP_REDACTED/0 route to NAT Gateway ${nat_id}."
    return 1
  fi
}

nat_verify_disabled() {
  local attempts="${NAT_POSTCHECK_ATTEMPTS:-12}"
  local interval="${NAT_POSTCHECK_INTERVAL_SECONDS:-5}"
  local expected_nat_id="${1:-}"
  local attempt state_list nat_address route_address nat_id record record_id route_details

  for attempt in $(seq 1 "$attempts"); do
    state_list="$(nat_state_list)" || {
      nat_config_error "Operational Terraform state could not be read after NAT disable."
      return 1
    }
    nat_address="$(nat_state_nat_address "$state_list" || true)"
    route_address="$(nat_state_route_address "$state_list" || true)"
    route_details="$(nat_route_details)" || {
      nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} could not be read after NAT disable."
      return 1
    }
    if [ -z "$nat_address" ] && [ -z "$route_address" ] && [ -z "$route_details" ]; then
      if [ -n "$expected_nat_id" ]; then
        record="$(nat_aws_nat_by_id "$expected_nat_id" 2>/dev/null || true)"
        read -r record_id _ <<< "$record"
        if [ -n "$record_id" ] && [ "$record_id" != "None" ]; then
          nat_config_error "NAT Gateway ${expected_nat_id} still exists after disable: ${record}."
          return 1
        fi
      fi
      nat_verify_eip || return 1
      return 0
    fi
    if [ "$attempt" -lt "$attempts" ]; then
      sleep "$interval"
    fi
  done

  nat_id=""
  if [ -n "$nat_address" ]; then
    nat_id="$(terraform_state_attribute "$nat_address" id 2>/dev/null || true)"
  fi
  if [ -n "$nat_id" ]; then
    record="$(nat_aws_nat_by_id "$nat_id" 2>/dev/null || true)"
    nat_config_error "NAT Gateway ${nat_id} or its private route remains after disable: ${record:-state/route pending}."
  else
    nat_config_error "NAT Gateway state or private route remains after disable."
  fi
  return 1
}

nat_enable() {
  local state_list nat_address nat_id route_details records

  nat_preflight || return 1
  nat_verify_eip || return 1
  state_list="$(nat_state_list)" || {
    nat_config_error "Operational Terraform state could not be read before NAT enable."
    return 1
  }
  nat_address="$(nat_state_nat_address "$state_list" || true)"
  if [ -n "$nat_address" ]; then
    if ! nat_state_has 'aws_route.private_internet[0]' "$state_list" \
      && ! nat_state_has 'aws_route.private_internet' "$state_list"; then
      nat_config_error "Operational state contains a NAT Gateway but no private NAT route; refusing repair by mutation."
      return 1
    fi
    nat_id="$(terraform_state_attribute "$nat_address" id)" || return 1
    nat_verify_ready_by_id "$nat_id" || return 1
    echo "NAT_ALREADY_READY=PASS"
    echo "NAT_ENABLE=PASS"
    return 0
  fi

  records="$(nat_aws_nat_records)" || {
    nat_config_error "AWS NAT Gateway inventory could not be read before NAT enable."
    return 1
  }
  if [ -n "$records" ] && [ "$records" != "None" ]; then
    nat_config_error "An AWS NAT Gateway already exists in the approved VPC but is absent from operational Terraform state; refusing duplicate creation."
    return 1
  fi
  route_details="$(nat_route_details)" || {
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} could not be read before NAT enable."
    return 1
  }
  if [ -n "$route_details" ] && [ "$route_details" != "None" ]; then
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} already has a default route; refusing to overwrite drift."
    return 1
  fi

  echo "[NAT ENABLE] Creating only the approved NAT Gateway and private default route."
  terraform apply -input=false -auto-approve \
    -var="is_dr_mode=false" \
    -var="enable_nat_gateway=true" \
    -var="cloudflare_zone_id=${CF_ZONE_ID:-}" \
    -target='aws_eip.nat_eip' \
    -target='aws_nat_gateway.nat_gw' \
    -target='aws_route.private_internet'
  nat_id="$(terraform_state_attribute aws_nat_gateway.nat_gw[0] id 2>/dev/null || terraform_state_attribute aws_nat_gateway.nat_gw id)" || return 1
  nat_verify_ready_by_id "$nat_id" || return 1
  echo "NAT_ENABLE=PASS"
}

nat_disable() {
  local state_list nat_address route_address nat_id record route_details records

  nat_preflight || return 1
  nat_verify_eip || return 1
  state_list="$(nat_state_list)" || {
    nat_config_error "Operational Terraform state could not be read before NAT disable."
    return 1
  }
  nat_address="$(nat_state_nat_address "$state_list" || true)"
  route_address="$(nat_state_route_address "$state_list" || true)"
  records="$(nat_aws_nat_records)" || {
    nat_config_error "AWS NAT Gateway inventory could not be read before NAT disable."
    return 1
  }
  route_details="$(nat_route_details)" || {
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} could not be read before NAT disable."
    return 1
  }

  if [ -z "$nat_address" ] && [ -z "$route_address" ] && [ -z "$records" ] && [ -z "$route_details" ]; then
    echo "NAT_ALREADY_OFF=PASS"
    echo "EIP_PRESERVED=PASS"
    echo "NAT_DISABLE=PASS"
    return 0
  fi
  if [ -z "$nat_address" ] || [ -z "$route_address" ]; then
    nat_config_error "NAT state and private route are not an aligned Terraform pair; refusing destructive repair."
    return 1
  fi
  nat_id="$(terraform_state_attribute "$nat_address" id)" || return 1
  if ! record="$(nat_aws_nat_by_id "$nat_id")" || ! nat_record_matches_expected "$record"; then
    nat_config_error "NAT Gateway ${nat_id} does not match the approved identity; refusing deletion."
    return 1
  fi
  if ! nat_route_matches "$route_details" "$nat_id"; then
    nat_config_error "Private route table ${EXPECTED_PRIVATE_ROUTE_TABLE_ID} does not actively point to ${nat_id}; refusing deletion."
    return 1
  fi

  echo "[NAT DISABLE] Removing only the approved private route and NAT Gateway; preserving the EIP."
  terraform apply -input=false -auto-approve \
    -var="is_dr_mode=false" \
    -var="enable_nat_gateway=false" \
    -var="cloudflare_zone_id=${CF_ZONE_ID:-}" \
    -target='aws_route.private_internet' \
    -target='aws_nat_gateway.nat_gw'
  nat_verify_disabled "$nat_id" || return 1
  echo "NAT_DISABLE=PASS"
  echo "EIP_PRESERVED=PASS"
}

nat_status() {
  local state_list nat_address nat_id record route_details records eip_details db_state
  nat_preflight || {
    echo "NAT_STATUS=ERROR"
    return 1
  }
  if ! eip_details="$(nat_aws_eip_details)"; then
    echo "NAT_STATUS=ERROR"
    return 1
  fi
  state_list="$(nat_state_list)" || {
    echo "NAT_STATUS=ERROR"
    return 1
  }
  nat_address="$(nat_state_nat_address "$state_list" || true)"
  nat_id=""
  record=""
  if [ -n "$nat_address" ]; then
    nat_id="$(terraform_state_attribute "$nat_address" id 2>/dev/null || true)"
    if [ -n "$nat_id" ]; then
      record="$(nat_aws_nat_by_id "$nat_id" 2>/dev/null || true)"
    fi
  fi
  records="$(nat_aws_nat_records 2>/dev/null || true)"
  route_details="$(nat_route_details 2>/dev/null || true)"
  db_state="$(aws ec2 describe-instances --region "$NAT_REGION" --instance-ids "$EXPECTED_DB_INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)"

  echo "NAT_GATEWAY_ID=${nat_id:-NONE}"
  if [ -n "$record" ]; then
    read -r _nat_id nat_state nat_subnet nat_allocation nat_public <<< "$record"
    echo "NAT_GATEWAY_STATE=${nat_state:-UNKNOWN}"
    echo "NAT_EIP=${nat_public:-UNKNOWN}"
    echo "NAT_EIP_ALLOCATION_ID=${nat_allocation:-UNKNOWN}"
    echo "NAT_SUBNET=${nat_subnet:-UNKNOWN}"
  else
    echo "NAT_GATEWAY_STATE=NONE"
    echo "NAT_EIP=${EXPECTED_NAT_EIP_PUBLIC_IP}"
    echo "NAT_EIP_ALLOCATION_ID=${EXPECTED_NAT_EIP_ALLOCATION_ID}"
    echo "NAT_SUBNET=NONE"
  fi
  echo "PRIVATE_ROUTE_TABLE=${EXPECTED_PRIVATE_ROUTE_TABLE_ID}"
  if [ -n "$route_details" ]; then
    read -r route_state route_nat_id <<< "$route_details"
    echo "PRIVATE_DEFAULT_ROUTE=${route_nat_id:-UNKNOWN}"
    echo "PRIVATE_ROUTE_STATE=${route_state:-UNKNOWN}"
  else
    echo "PRIVATE_DEFAULT_ROUTE=NONE"
    echo "PRIVATE_ROUTE_STATE=NONE"
  fi
  echo "DB_EC2_STATE=${db_state:-UNKNOWN}"

  if [ -n "$nat_address" ] && nat_record_matches_expected "$record" \
    && nat_route_matches "$route_details" "$nat_id"; then
    echo "NAT_STATUS=READY"
    return 0
  fi
  if [ -z "$nat_address" ] && [ -z "$records" ] \
    && [ -z "$route_details" ] \
    && printf '%s\n' "$eip_details" | grep -Fq "$EXPECTED_NAT_EIP_ALLOCATION_ID"; then
    echo "NAT_STATUS=OFF"
    return 0
  fi
  if [ -n "$nat_address" ] || [ -n "$records" ] || [ -n "$route_details" ]; then
    echo "NAT_STATUS=DRIFTED"
  else
    echo "NAT_STATUS=ERROR"
  fi
  return 1
}
