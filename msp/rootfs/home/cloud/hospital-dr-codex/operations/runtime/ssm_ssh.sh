#!/usr/bin/env bash

# Shared SSH transport for DR hosts. By default private hosts use the Web SSM
# jump host; callers may explicitly pin dr-db to its own SSM target for a
# DB-only restore while Web/EMR instances remain stopped.

dr_ssm_require_tools() {
    local required tool missing=0
    for required in aws ssh python3 session-manager-plugin; do
        if ! tool="$(command -v "$required" 2>/dev/null)"; then
            echo "[SSM SSH ERROR] Required executable is unavailable in PATH: $required" >&2
            missing=1
        fi
    done
    return "$missing"
}

dr_ssm_discover_web_instance_id() {
    local region="${1:-${AWS_REGION:-ap-northeast-2}}"
    local private_ip="${2:-${DR_WEB_PRIVATE_IP_EXPECTED:-IP_REDACTED}}"
    local response

    if ! response="$(aws ec2 describe-instances \
        --region "$region" \
        --filters \
          'Name=tag:Name,Values=Hospital-Real-Web-Server' \
          "Name=private-ip-address,Values=$private_ip" \
          'Name=instance-state-name,Values=running' \
        --output json)"; then
        echo "[SSM SSH ERROR] Could not discover the running DR Web instance by its approved identity." >&2
        return 1
    fi

    DR_SSM_INSTANCE_RESPONSE="$response" python3 - "$private_ip" <<'PY'
import json
import os
import re
import sys

expected_private_ip = sys.argv[1]
try:
    result = json.loads(os.environ["DR_SSM_INSTANCE_RESPONSE"])
    instances = [
        instance
        for reservation in result.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    if len(instances) != 1:
        raise ValueError(f"expected exactly one matching instance, found {len(instances)}")
    instance = instances[0]
    tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", [])}
    instance_id = instance.get("InstanceId", "")
    if tags.get("Name") != "Hospital-Real-Web-Server":
        raise ValueError("Name tag does not identify the DR Web host")
    if instance.get("State", {}).get("Name") != "running":
        raise ValueError("DR Web host is not running")
    if instance.get("PrivateIpAddress") != expected_private_ip:
        raise ValueError("private IP does not match the approved DR Web host")
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise ValueError("AWS returned an invalid instance ID")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"[SSM SSH ERROR] DR Web instance identity validation failed: {error}", file=sys.stderr)
    sys.exit(1)

print(instance_id)
PY
}

dr_ssm_write_ssh_config() {
    local region="$1"
    local instance_id="$2"
    local private_key="$3"
    local known_hosts="$4"
    local doc_ip="$5"
    local db_ip="$6"
    local db_instance_id="${7:-}"

    if [ "$known_hosts" = "/dev/null" ] || [ -z "$known_hosts" ]; then
        echo "[SSM SSH CONFIG ERROR] A persistent known_hosts file is required." >&2
        return 1
    fi
    if [ ! -r "$private_key" ]; then
        echo "[SSM SSH CONFIG ERROR] SSH private key is not readable: $private_key" >&2
        return 1
    fi

    DR_SSM_AWS_BIN="$(command -v aws)" DR_SSM_SSH_BIN="$(command -v ssh)" \
        python3 - "$DR_SSH_CONFIG_FILE" "$region" "$instance_id" "$private_key" "$known_hosts" "$doc_ip" "$db_ip" "$db_instance_id" <<'PY'
import os
import re
import shlex
import sys
import tempfile

config_path, region, instance_id, private_key, known_hosts, doc_ip, db_ip, db_instance_id = sys.argv[1:]
if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
    print("[SSM SSH CONFIG ERROR] Refusing an invalid Web instance ID.", file=sys.stderr)
    sys.exit(1)
if db_instance_id and not re.fullmatch(r"i-[0-9a-f]{8,17}", db_instance_id):
    print("[SSM SSH CONFIG ERROR] Refusing an invalid DB instance ID.", file=sys.stderr)
    sys.exit(1)
if not re.fullmatch(r"[a-z0-9-]+", region):
    print("[SSM SSH CONFIG ERROR] Refusing an invalid AWS region.", file=sys.stderr)
    sys.exit(1)

def config_value(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

config_dir = os.path.dirname(os.path.abspath(config_path))
os.makedirs(config_dir, mode=0o700, exist_ok=True)
os.chmod(config_dir, 0o700)
aws_path = os.environ.get("DR_SSM_AWS_BIN") or "aws"
ssh_path = os.environ.get("DR_SSM_SSH_BIN") or "ssh"
def ssm_proxy(target):
    return shlex.join([
        aws_path, "ssm", "start-session", "--region", region,
        "--target", target, "--document-name", "AWS-StartSSHSession",
        "--parameters", "portNumber=22",
    ])

jump_proxy = shlex.join([ssh_path, "-F", config_path, "-W", "%h:%p", "dr-web"])
if db_instance_id:
    db_host_name = db_instance_id
    db_host_key_alias = db_instance_id
    db_proxy = ssm_proxy(db_instance_id)
else:
    db_host_name = db_ip
    db_host_key_alias = db_ip
    db_proxy = jump_proxy
lines = [
    "Host dr-web dr-doc dr-db",
    "  User ubuntu",
    f"  IdentityFile {config_value(private_key)}",
    "  IdentitiesOnly yes",
    "  BatchMode yes",
    "  ConnectTimeout 15",
    "  StrictHostKeyChecking accept-new",
    f"  UserKnownHostsFile {config_value(known_hosts)}",
    "  GlobalKnownHostsFile /dev/null",
    "  LogLevel ERROR",
    "  ServerAliveInterval 15",
    "  ServerAliveCountMax 3",
    "",
    "Host dr-web",
    f"  HostName {instance_id}",
    f"  HostKeyAlias {instance_id}",
    f"  ProxyCommand {ssm_proxy(instance_id)}",
    "",
    "Host dr-doc",
    f"  HostName {doc_ip}",
    f"  HostKeyAlias {doc_ip}",
    f"  ProxyCommand {jump_proxy}",
    "",
    "Host dr-db",
    f"  HostName {db_host_name}",
    f"  HostKeyAlias {db_host_key_alias}",
    f"  ProxyCommand {db_proxy}",
    "",
]
fd, temporary = tempfile.mkstemp(prefix=".ssh-config.", dir=config_dir, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, config_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

dr_ssm_write_ansible_inventory() {
    local inventory="$1"
    local private_key="$2"
    local ssh_config="$3"
    local parent temporary common_args
    parent="$(dirname -- "$inventory")"
    mkdir -p -- "$parent"
    temporary="$(mktemp "$parent/.inventory.XXXXXX")"
    common_args="-F $ssh_config"
    {
        echo "[web_servers]"
        echo "dr-web ansible_connection=ssh ansible_host=dr-web ansible_user=ubuntu ansible_ssh_private_key_file=$private_key ansible_ssh_common_args='$common_args'"
        echo
        echo "[doc_servers]"
        echo "dr-doc ansible_connection=ssh ansible_host=dr-doc ansible_user=ubuntu ansible_ssh_private_key_file=$private_key ansible_ssh_common_args='$common_args'"
        echo
        echo "[db_servers]"
        echo "dr-db ansible_connection=ssh ansible_host=dr-db ansible_user=ubuntu ansible_ssh_private_key_file=$private_key ansible_ssh_common_args='$common_args'"
    } > "$temporary"
    install -m 0644 "$temporary" "$inventory"
    rm -f "$temporary"
}

dr_ssm_wait_for_ssh() {
    local label="$1"
    local target="$2"
    local attempts="${3:-18}"
    local interval="${4:-5}"
    local attempt return_code=255 output_file
    output_file="$(mktemp)"

    echo "[CONNECTIVITY] Waiting for SSH readiness over SSM transport: $label"
    for attempt in $(seq 1 "$attempts"); do
        if ssh -F "$DR_SSH_CONFIG_FILE" "$target" true >"$output_file" 2>&1; then
            echo "[CONNECTIVITY] SSH readiness confirmed: $label"
            rm -f "$output_file"
            return 0
        else
            return_code=$?
        fi
        echo "[CONNECTIVITY] SSH not ready yet ($attempt/$attempts), exit=$return_code: $label"
        if [ "$attempt" -lt "$attempts" ]; then
            sleep "$interval"
        fi
    done

    echo "[CONNECTIVITY ERROR] SSH readiness check failed, exit=$return_code: $label" >&2
    if [ -s "$output_file" ]; then
        tail -n 30 "$output_file" >&2
    fi
    rm -f "$output_file"
    return "$return_code"
}

dr_ssm_ssh() {
    local target="$1"
    shift
    ssh -F "$DR_SSH_CONFIG_FILE" "$target" "$@"
}
