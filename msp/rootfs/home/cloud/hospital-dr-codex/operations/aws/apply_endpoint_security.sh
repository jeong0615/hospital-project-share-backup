#!/usr/bin/env bash
set -euo pipefail

# Apply the repository-owned endpoint contract through SSM.  This wrapper
# never changes EC2 networking, IAM, DNS, or instance profiles.

REGION="${AWS_REGION:-ap-northeast-2}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SCRIPT="${AWS_ENDPOINT_BOOTSTRAP_SCRIPT:-$SCRIPT_DIR/aws_endpoint_security_bootstrap.sh}"
ZABBIX_ACTIVE_SERVER="${AWS_ZABBIX_ACTIVE_SERVER:-}"
WAZUH_MANAGER="${AWS_WAZUH_MANAGER:-}"
ZABBIX_EXTERNAL_PATH_ENABLED="${AWS_ZABBIX_EXTERNAL_PATH_ENABLED:-false}"
WAZUH_EXTERNAL_PATH_ENABLED="${AWS_WAZUH_EXTERNAL_PATH_ENABLED:-false}"
WAZUH_AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.8.0-1}"

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if ! is_true "$ZABBIX_EXTERNAL_PATH_ENABLED" || ! is_true "$WAZUH_EXTERNAL_PATH_ENABLED"; then
  echo "AWS external Zabbix/Wazuh Agent paths are DISABLED_BY_DESIGN in the current MSP topology."
  echo "CONFIG_AVAILABLE=YES LIVE_PATH_ENABLED=NO LIVE_PATH_REASON=MSP_BEHIND_UNCONTROLLED_UPSTREAM_NAT"
  exit 0
fi

if [ ! -r "$BOOTSTRAP_SCRIPT" ]; then
  echo "AWS endpoint bootstrap script is not readable." >&2
  exit 2
fi
if [ -z "$ZABBIX_ACTIVE_SERVER" ] || [ -z "$WAZUH_MANAGER" ]; then
  echo "AWS_ZABBIX_ACTIVE_SERVER and AWS_WAZUH_MANAGER are required external inputs." >&2
  exit 2
fi

declare -a IDS=(
  "AWS_RESOURCE_ID_REDACTED:web:aws-dr-web:AWS_PUBLIC_IP_REDACTED"
  "AWS_RESOURCE_ID_REDACTED:emr:aws-dr-emr:AWS_PUBLIC_IP_REDACTED"
  "AWS_RESOURCE_ID_REDACTED:db:aws-dr-db:AWS_PUBLIC_IP_REDACTED"
)

script_b64="$(base64 -w0 "$BOOTSTRAP_SCRIPT")"
overall=0
for entry in "${IDS[@]}"; do
  IFS=: read -r instance_id role hostname expected_ip <<<"$entry"
  state="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].State.Name' --output text)"
  private_ip="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
  if [ "$state" != running ] || [ "$private_ip" != "$expected_ip" ]; then
    echo "${hostname}: BLOCKED state=${state} private_ip_contract=${private_ip}"
    overall=1
    continue
  fi
  ping="$(aws ssm describe-instance-information --region "$REGION" --filters "Key=InstanceIds,Values=$instance_id" --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
  if [ "$ping" != Online ]; then
    echo "${hostname}: BLOCKED SSM=${ping:-NOT_REGISTERED}"
    overall=1
    continue
  fi
  command_text="printf '%s' $(printf '%q' "$script_b64") | base64 -d | env AWS_DR_ROLE=$(printf '%q' "$role") AWS_DR_HOSTNAME=$(printf '%q' "$hostname") ZABBIX_ACTIVE_SERVER=$(printf '%q' "$ZABBIX_ACTIVE_SERVER") WAZUH_MANAGER=$(printf '%q' "$WAZUH_MANAGER") AWS_ZABBIX_EXTERNAL_PATH_ENABLED=$(printf '%q' "$ZABBIX_EXTERNAL_PATH_ENABLED") AWS_WAZUH_EXTERNAL_PATH_ENABLED=$(printf '%q' "$WAZUH_EXTERNAL_PATH_ENABLED") WAZUH_AGENT_VERSION=$(printf '%q' "$WAZUH_AGENT_VERSION") bash"
  request_json="$(python3 - "$instance_id" "$command_text" <<'PY'
import json
import sys
print(json.dumps({
    "DocumentName": "AWS-RunShellScript",
    "InstanceIds": [sys.argv[1]],
    "Comment": "Hospital DR endpoint monitoring and security bootstrap",
    "TimeoutSeconds": 900,
    "Parameters": {"commands": [sys.argv[2]]},
}))
PY
)"
  command_id="$(aws ssm send-command --region "$REGION" --cli-input-json "$request_json" --query 'Command.CommandId' --output text)"
  echo "${hostname}: SSM_COMMAND=${command_id}"
  for attempt in $(seq 1 90); do
    status="$(aws ssm get-command-invocation --region "$REGION" --command-id "$command_id" --instance-id "$instance_id" --query 'Status' --output text 2>/dev/null || true)"
    case "$status" in
      Success|Failed|Cancelled|TimedOut|Cancelling) break ;;
    esac
    sleep 5
  done
  output="$(aws ssm get-command-invocation --region "$REGION" --command-id "$command_id" --instance-id "$instance_id" --query 'StandardOutputContent' --output text 2>/dev/null || true)"
  printf '%s\n' "$output" | tail -n 4
  if [ "$status" != Success ]; then
    echo "${hostname}: SSM_STATUS=${status:-UNKNOWN}"
    overall=1
  fi
done
exit "$overall"
