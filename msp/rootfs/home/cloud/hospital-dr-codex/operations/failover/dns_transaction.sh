#!/usr/bin/env bash
# Cloudflare DNS record transaction helper.
# Callers must source cloudflare_ssm_auth.sh and load the API token first.

dr_dns_response_success() {
  local response_file="$1"
  python3 - "$response_file" <<'PYJSON'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as stream:
        response = json.load(stream)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if response.get("success") is True else 1)
PYJSON
}

dr_dns_cloudflare_error_context() {
  local status="$1"
  local body_file="$2"
  local headers_file="$3"
  python3 - "$status" "$body_file" "$headers_file" <<'PYJSON'
import re
import sys

status, body_path, headers_path = sys.argv[1:]
if status != "530":
    raise SystemExit(0)
try:
    with open(body_path, "r", encoding="utf-8", errors="replace") as stream:
        body = stream.read(65536)
except OSError:
    body = ""
try:
    with open(headers_path, "r", encoding="utf-8", errors="replace") as stream:
        headers = stream.read(16384)
except OSError:
    headers = ""

parts = []
subcode = re.search(r"\b(?:Error\s+|error\s+code\s*[:#]?\s*)(1\d{3})\b", body, re.IGNORECASE)
if subcode:
    parts.append(f"cf_error={subcode.group(1)}")
ray = re.search(r"(?im)^cf-ray:\s*([A-Za-z0-9-]{8,80})\s*$", headers)
if ray:
    parts.append(f"cf_ray={ray.group(1)}")
if parts:
    print("(" + " ".join(parts) + ")", end="")
PYJSON
}

dr_dns_check_public_health() {
  local web_url="$1"
  local emr_url="$2"
  local emr_check_header="$3"
  local attempts="$4"
  local interval="${5:-5}"
  local label="${6:-Public}"
  local attempt web_status emr_status response_dir web_context emr_context

  if [[ ! "$attempts" =~ ^[1-9][0-9]*$ ]]; then
    echo "[VALIDATION ERROR] Invalid ${label,,} health attempt count." >&2
    return 1
  fi
  response_dir="$(mktemp -d)" || return 1
  for attempt in $(seq 1 "$attempts"); do
    web_status="$(curl -sS --connect-timeout 5 --max-time 15 \
      -D "$response_dir/web.headers" -o "$response_dir/web.body" \
      -w '%{http_code}' "$web_url" 2>/dev/null || true)"
    emr_status="$(curl -sS --connect-timeout 5 --max-time 15 \
      -H "X-Hospital-DR-Check: ${emr_check_header}" \
      -D "$response_dir/emr.headers" -o "$response_dir/emr.body" \
      -w '%{http_code}' "$emr_url" 2>/dev/null || true)"
    if [[ "$web_status" =~ ^[23][0-9]{2}$ && "$emr_status" =~ ^[23][0-9]{2}$ ]]; then
      rm -f "$response_dir/web.headers" "$response_dir/web.body" \
        "$response_dir/emr.headers" "$response_dir/emr.body"
      rmdir "$response_dir"
      return 0
    fi
    web_context="$(dr_dns_cloudflare_error_context "${web_status:-000}" \
      "$response_dir/web.body" "$response_dir/web.headers")"
    emr_context="$(dr_dns_cloudflare_error_context "${emr_status:-000}" \
      "$response_dir/emr.body" "$response_dir/emr.headers")"
    printf '[VALIDATION] %s HTTP health not ready (web=%s%s emr=%s%s, attempt=%s/%s).\n' \
      "$label" "${web_status:-000}" "$web_context" \
      "${emr_status:-000}" "$emr_context" "$attempt" "$attempts"
    sleep "$interval"
  done
  rm -f "$response_dir/web.headers" "$response_dir/web.body" \
    "$response_dir/emr.headers" "$response_dir/emr.body"
  rmdir "$response_dir"
  return 1
}

dr_dns_validate_snapshot_pair() {
  local snapshot_dir="$1"
  local web_name="$2"
  local emr_name="$3"
  python3 - "$snapshot_dir" "$web_name" "$emr_name" <<'PYJSON'
import json
import os
import sys

directory, web_name, emr_name = sys.argv[1:]
for filename, expected_name in (("web.json", web_name), ("emr.json", emr_name)):
    path = os.path.join(directory, filename)
    try:
        with open(path, "r", encoding="utf-8") as stream:
            snapshot = json.load(stream)
        record_id = snapshot["id"]
        payload = snapshot["payload"]
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit(1)
    if not isinstance(record_id, str) or not record_id:
        raise SystemExit(1)
    if not isinstance(payload, dict) or payload.get("name") != expected_name:
        raise SystemExit(1)
    if any(key not in payload for key in ("type", "content", "ttl", "proxied")):
        raise SystemExit(1)
    if not isinstance(payload["proxied"], bool):
        raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_snapshot_pairs_equal() {
  local left_dir="$1"
  local right_dir="$2"
  python3 - "$left_dir" "$right_dir" <<'PYJSON'
import json
import os
import sys

left_dir, right_dir = sys.argv[1:]
for filename in ("web.json", "emr.json"):
    try:
        with open(os.path.join(left_dir, filename), "r", encoding="utf-8") as stream:
            left = json.load(stream)
        with open(os.path.join(right_dir, filename), "r", encoding="utf-8") as stream:
            right = json.load(stream)
    except (OSError, ValueError):
        raise SystemExit(1)
    if left != right:
        raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_snapshot_pairs_equal_ids() {
  local left_dir="$1"
  local right_dir="$2"
  python3 - "$left_dir" "$right_dir" <<'PYJSON'
import json
import os
import sys

left_dir, right_dir = sys.argv[1:]
for filename in ("web.json", "emr.json"):
    try:
        with open(os.path.join(left_dir, filename), "r", encoding="utf-8") as stream:
            left = json.load(stream)
        with open(os.path.join(right_dir, filename), "r", encoding="utf-8") as stream:
            right = json.load(stream)
    except (OSError, ValueError):
        raise SystemExit(1)
    if left.get("id") != right.get("id"):
        raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_preserve_origin_pair() {
  local current_dir="$1"
  local origin_dir="$2"
  local web_name="$3"
  local emr_name="$4"
  local tunnel_host="$5"
  local dr_public_ip="$6"
  local expected_emr_ip="${7:-}"

  dr_dns_validate_snapshot_pair "$current_dir" "$web_name" "$emr_name" || {
    echo "[DNS ERROR] Current Web/EMR DNS snapshot is missing or invalid." >&2
    return 1
  }

  if [ -e "$origin_dir" ]; then
    if ! dr_dns_validate_origin_pair "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_public_ip" "$expected_emr_ip"; then
      echo "[DNS ERROR] Preserved On-Prem DNS snapshot is invalid; refusing to replace it." >&2
      return 1
    fi
    if ! dr_dns_snapshot_pairs_equal "$current_dir" "$origin_dir"; then
      echo "[DNS ERROR] Current DNS differs from the preserved On-Prem snapshot." >&2
      return 2
    fi
    echo "[DNS] Preserved On-Prem DNS snapshot validated."
    return 0
  fi

  python3 - "$current_dir" "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_public_ip" "$expected_emr_ip" <<'PYJSON'
import ipaddress
import json
import os
import shutil
import sys
import tempfile

current_dir, origin_dir, web_name, emr_name, tunnel_host, dr_public_ip, expected_emr_ip = sys.argv[1:]
try:
    ipaddress.ip_address(dr_public_ip)
    records = {}
    for filename, expected_name in (("web.json", web_name), ("emr.json", emr_name)):
        with open(os.path.join(current_dir, filename), "r", encoding="utf-8") as stream:
            record = json.load(stream)
        if record["payload"]["name"] != expected_name or not record["id"]:
            raise ValueError("snapshot record identity mismatch")
        records[filename] = record
    web = records["web.json"]["payload"]
    emr = records["emr.json"]["payload"]
    if web["type"] != "CNAME" or web["proxied"] is not True:
        raise ValueError("Web record is not a proxied On-Prem CNAME")
    if web["content"].rstrip(".").lower() != tunnel_host.rstrip(".").lower():
        raise ValueError("Web CNAME does not match the configured On-Prem tunnel")
    if emr["type"] != "A" or emr["proxied"] is not True:
        raise ValueError("EMR record is not a proxied On-Prem A record")
    emr_ip = str(ipaddress.IPv4Address(emr["content"]))
    if emr_ip == str(ipaddress.ip_address(dr_public_ip)):
        raise ValueError("EMR record already points at the DR EIP")
    if expected_emr_ip and emr_ip != str(ipaddress.IPv4Address(expected_emr_ip)):
        raise ValueError("EMR record does not match the approved On-Prem origin IP")
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"[DNS ERROR] Cannot identify current DNS as the On-Prem origin: {error}", file=sys.stderr)
    raise SystemExit(1)

parent = os.path.dirname(os.path.abspath(origin_dir))
os.makedirs(parent, mode=0o750, exist_ok=True)
temporary = tempfile.mkdtemp(prefix=".origin-snapshot-", dir=parent)
try:
    for filename, record in records.items():
        target = os.path.join(temporary, filename)
        with open(target, "x", encoding="utf-8") as stream:
            json.dump(record, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(target, 0o600)
    os.chmod(temporary, 0o700)
    os.rename(temporary, origin_dir)
except BaseException:
    shutil.rmtree(temporary, ignore_errors=True)
    raise
print("[DNS] Preserved verified On-Prem DNS snapshot.")
PYJSON
}

dr_dns_validate_origin_pair() {
  local origin_dir="$1"
  local web_name="$2"
  local emr_name="$3"
  local tunnel_host="$4"
  local dr_public_ip="$5"
  local expected_emr_ip="${6:-}"
  python3 - "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_public_ip" "$expected_emr_ip" <<'PYJSON'
import ipaddress
import json
import os
import sys

directory, web_name, emr_name, tunnel_host, dr_public_ip, expected_emr_ip = sys.argv[1:]
try:
    ipaddress.ip_address(dr_public_ip)
    records = {}
    for filename, expected_name in (("web.json", web_name), ("emr.json", emr_name)):
        with open(os.path.join(directory, filename), "r", encoding="utf-8") as stream:
            records[filename] = json.load(stream)
        if records[filename]["payload"]["name"] != expected_name:
            raise ValueError("preserved DNS record name mismatch")
    web = records["web.json"]["payload"]
    emr = records["emr.json"]["payload"]
    if web["type"] != "CNAME" or web["proxied"] is not True:
        raise ValueError("preserved Web record is not a proxied CNAME")
    if web["content"].rstrip(".").lower() != tunnel_host.rstrip(".").lower():
        raise ValueError("preserved Web CNAME does not match configured tunnel")
    if emr["type"] != "A" or emr["proxied"] is not True:
        raise ValueError("preserved EMR record is not a proxied A record")
    emr_ip = str(ipaddress.IPv4Address(emr["content"]))
    if emr_ip == str(ipaddress.ip_address(dr_public_ip)):
        raise ValueError("preserved EMR record points at the DR EIP")
    if expected_emr_ip and emr_ip != str(ipaddress.IPv4Address(expected_emr_ip)):
        raise ValueError("preserved EMR record does not match the approved On-Prem origin IP")
except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_validate_dr_pair() {
  local snapshot_dir="$1"
  local web_name="$2"
  local emr_name="$3"
  local dr_public_ip="$4"
  python3 - "$snapshot_dir" "$web_name" "$emr_name" "$dr_public_ip" <<'PYJSON'
import ipaddress
import json
import os
import sys

directory, web_name, emr_name, expected_ip = sys.argv[1:]
try:
    expected_ip = str(ipaddress.IPv4Address(expected_ip))
    for filename, name in (("web.json", web_name), ("emr.json", emr_name)):
        with open(os.path.join(directory, filename), "r", encoding="utf-8") as stream:
            snapshot = json.load(stream)
        payload = snapshot["payload"]
        if not snapshot["id"] or payload["name"] != name:
            raise ValueError("DR DNS snapshot identity mismatch")
        if payload["type"] != "A" or payload["content"] != expected_ip or payload["proxied"] is not True:
            raise ValueError("DNS record does not match the approved proxied DR EIP")
except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_archive_origin_pair() {
  local origin_dir="$1"
  local archive_root="$2"
  if [ ! -d "$origin_dir" ]; then
    echo "[DNS ERROR] No active On-Prem origin snapshot exists to archive." >&2
    return 1
  fi
  python3 - "$origin_dir" "$archive_root" <<'PYJSON'
import datetime
import json
import os
import sys
import uuid

origin, archive_root = sys.argv[1:]
try:
    for filename in ("web.json", "emr.json"):
        with open(os.path.join(origin, filename), "r", encoding="utf-8") as stream:
            snapshot = json.load(stream)
        if not snapshot.get("id") or not isinstance(snapshot.get("payload"), dict):
            raise ValueError("invalid snapshot")
    os.makedirs(archive_root, mode=0o750, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = os.path.join(archive_root, f"origin-{stamp}-{uuid.uuid4().hex[:8]}")
    os.rename(origin, destination)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"[DNS ERROR] Could not archive the On-Prem snapshot: {error}", file=sys.stderr)
    raise SystemExit(1)
print(f"[DNS] Archived restored On-Prem DNS snapshot: {destination}")
PYJSON
}

dr_dns_payload() {
  python3 - "$1" "$2" "$3" <<'PYJSON'
import ipaddress
import json
import sys

kind, name, content = sys.argv[1:]
if kind != "A":
    raise SystemExit(1)
content = str(ipaddress.IPv4Address(content))
print(json.dumps({"type": kind, "name": name, "content": content, "ttl": 1, "proxied": True}, separators=(",", ":")))
PYJSON
}

dr_dns_validate_aws_web_eip() {
  local candidate_ip="$1"
  local expected_ip="$2"
  local region="$3"
  local instances addresses

  if [ "$candidate_ip" != "$expected_ip" ]; then
    echo "[DNS ERROR] Refusing unapproved DR Web public IP: ${candidate_ip}." >&2
    return 1
  fi
  if ! instances="$(aws ec2 describe-instances \
      --region "$region" \
      --filters \
        'Name=tag:Name,Values=Hospital-Real-Web-Server' \
        'Name=instance-state-name,Values=running' \
      --output json 2>/dev/null)"; then
    echo "[DNS ERROR] Could not verify the running DR Web instance." >&2
    return 1
  fi
  if ! addresses="$(aws ec2 describe-addresses \
      --region "$region" \
      --public-ips "$candidate_ip" \
      --output json 2>/dev/null)"; then
    echo "[DNS ERROR] Could not verify the DR Web EIP association." >&2
    return 1
  fi

  DR_WEB_INSTANCE_JSON="$instances" DR_WEB_ADDRESS_JSON="$addresses" \
    python3 - "$candidate_ip" <<'PYJSON'
import json
import os
import sys

expected_ip = sys.argv[1]
try:
    instance_response = json.loads(os.environ["DR_WEB_INSTANCE_JSON"])
    address_response = json.loads(os.environ["DR_WEB_ADDRESS_JSON"])
    instances = [
        instance
        for reservation in instance_response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    addresses = address_response.get("Addresses", [])
    if len(instances) != 1 or len(addresses) != 1:
        raise ValueError("expected exactly one running Web instance and one EIP")
    instance = instances[0]
    address = addresses[0]
    tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", [])}
    eni_ids = {eni.get("NetworkInterfaceId") for eni in instance.get("NetworkInterfaces", [])}
    if tags.get("Name") != "Hospital-Real-Web-Server":
        raise ValueError("instance tag does not identify the DR Web server")
    if instance.get("InstanceId") != "AWS_RESOURCE_ID_REDACTED":
        raise ValueError("instance ID does not identify the approved DR Web server")
    if instance.get("State", {}).get("Name") != "running":
        raise ValueError("DR Web instance is not running")
    if instance.get("PrivateIpAddress") != "AWS_PUBLIC_IP_REDACTED":
        raise ValueError("DR Web private IP does not match the approved host")
    if instance.get("PublicIpAddress") != expected_ip:
        raise ValueError("DR Web public IP does not match the approved EIP")
    if instance.get("SourceDestCheck") is not False:
        raise ValueError("DR Web source/destination check is not disabled")
    if address.get("PublicIp") != expected_ip or not address.get("AllocationId"):
        raise ValueError("approved EIP allocation is missing")
    if not address.get("AssociationId") or not address.get("InstanceId"):
        raise ValueError("approved EIP is not associated")
    if address.get("InstanceId") != instance.get("InstanceId"):
        raise ValueError("EIP is associated with a different instance")
    if address.get("NetworkInterfaceId") not in eni_ids:
        raise ValueError("EIP is associated with a different network interface")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"[DNS ERROR] DR Web EIP validation failed: {error}", file=sys.stderr)
    raise SystemExit(1)
PYJSON
}

dr_dns_validate_aws_web_eip_association() {
  local candidate_ip="$1"
  local expected_ip="$2"
  local region="$3"
  local response

  if [ "$candidate_ip" != "$expected_ip" ]; then
    echo "[DNS ERROR] Refusing unapproved DR Web public IP: ${candidate_ip}." >&2
    return 1
  fi
  if ! response="$(aws ec2 describe-addresses \
      --region "$region" --public-ips "$candidate_ip" --output json 2>/dev/null)"; then
    echo "[DNS ERROR] Could not read the approved DR Web EIP association." >&2
    return 1
  fi

  DR_WEB_ADDRESS_JSON="$response" python3 - "$candidate_ip" <<'PYJSON'
import json
import os
import sys

expected_ip = sys.argv[1]
try:
    response = json.loads(os.environ["DR_WEB_ADDRESS_JSON"])
    addresses = response.get("Addresses", [])
    if len(addresses) != 1:
        raise ValueError("expected exactly one address allocation")
    address = addresses[0]
    if address.get("PublicIp") != expected_ip:
        raise ValueError("EIP address mismatch")
    if not address.get("AllocationId") or not address.get("AssociationId"):
        raise ValueError("EIP is not allocated and associated")
    if address.get("InstanceId") != "AWS_RESOURCE_ID_REDACTED":
        raise ValueError("EIP is associated with a different instance")
    if address.get("PrivateIpAddress") != "AWS_PUBLIC_IP_REDACTED":
        raise ValueError("EIP association private IP mismatch")
    if not address.get("NetworkInterfaceId"):
        raise ValueError("EIP network interface association is missing")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"[DNS ERROR] DR Web EIP association validation failed: {error}", file=sys.stderr)
    raise SystemExit(1)
PYJSON
}

dr_dns_apply_dr_pair() {
  local snapshot_dir="$1" origin_dir="$2" web_name="$3" emr_name="$4" tunnel_host="$5" dr_ip="$6"
  local web_id emr_id web_payload emr_payload
  dr_dns_validate_origin_pair "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_ip" || return 1
  dr_dns_validate_snapshot_pair "$snapshot_dir" "$web_name" "$emr_name" || return 1
  dr_dns_snapshot_pairs_equal "$snapshot_dir" "$origin_dir" || return 1
  web_id="$(dr_dns_snapshot_id "$snapshot_dir/web.json")"
  emr_id="$(dr_dns_snapshot_id "$snapshot_dir/emr.json")"
  web_payload="$(dr_dns_payload A "$web_name" "$dr_ip")"
  emr_payload="$(dr_dns_payload A "$emr_name" "$dr_ip")"
  dr_dns_apply_records "$snapshot_dir" "$web_id" "$web_payload" "cutover:$web_name" "$emr_id" "$emr_payload" "cutover:$emr_name"
}

dr_dns_apply_origin_pair() {
  local snapshot_dir="$1" origin_dir="$2" web_name="$3" emr_name="$4" tunnel_host="$5" dr_ip="$6"
  local web_id emr_id web_payload emr_payload
  dr_dns_validate_origin_pair "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_ip" || return 1
  dr_dns_validate_snapshot_pair "$snapshot_dir" "$web_name" "$emr_name" || return 1
  dr_dns_validate_dr_pair "$snapshot_dir" "$web_name" "$emr_name" "$dr_ip" || return 1
  dr_dns_snapshot_pairs_equal_ids "$snapshot_dir" "$origin_dir" || return 1
  web_id="$(dr_dns_snapshot_id "$origin_dir/web.json")"
  emr_id="$(dr_dns_snapshot_id "$origin_dir/emr.json")"
  web_payload="$(dr_dns_snapshot_payload "$origin_dir/web.json")"
  emr_payload="$(dr_dns_snapshot_payload "$origin_dir/emr.json")"
  dr_dns_apply_records "$snapshot_dir" "$web_id" "$web_payload" "failback:$web_name" "$emr_id" "$emr_payload" "failback:$emr_name"
}

dr_dns_failover_transaction() {
  local snapshot_dir="$1" origin_dir="$2" web_name="$3" emr_name="$4"
  local tunnel_host="$5" dr_ip="$6" health_function="$7"
  shift 7
  local rc
  if dr_dns_apply_dr_pair "$snapshot_dir" "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_ip"; then
    :
  else
    rc=$?
    return "$rc"
  fi
  if "$health_function" "$@"; then
    echo "[DNS] DR public health passed after both records were verified."
    return 0
  fi
  echo "[DNS] DR public health failed; restoring the saved On-Prem records." >&2
  if dr_dns_rollback_snapshots "$snapshot_dir"; then
    echo "[DNS ROLLBACK] On-Prem record pair restored and verified."
    return 1
  fi
  echo "[DNS ROLLBACK ERROR] On-Prem record pair restoration failed." >&2
  return 2
}

dr_dns_failback_transaction() {
  local snapshot_dir="$1" origin_dir="$2" web_name="$3" emr_name="$4"
  local tunnel_host="$5" dr_ip="$6" health_function="$7"
  shift 7
  local rc
  if dr_dns_apply_origin_pair "$snapshot_dir" "$origin_dir" "$web_name" "$emr_name" "$tunnel_host" "$dr_ip"; then
    :
  else
    rc=$?
    return "$rc"
  fi
  if "$health_function" "$@"; then
    echo "[DNS] On-Prem public health passed after the origin pair was verified."
    return 0
  fi
  echo "[DNS] On-Prem public health failed; restoring the saved DR records." >&2
  if dr_dns_rollback_snapshots "$snapshot_dir"; then
    echo "[DNS ROLLBACK] DR record pair restored and verified."
    return 1
  fi
  echo "[DNS ROLLBACK ERROR] DR record pair restoration failed." >&2
  return 2
}

dr_dns_snapshot_record() {
  local record_name="$1"
  local snapshot_file="$2"
  local record_id="${3:-}"
  local response_file
  response_file="$(mktemp)"

  if [ -n "$record_id" ]; then
    if ! curl -fsS -G \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${record_id}" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" > "$response_file"; then
      echo "[DNS ERROR] Could not snapshot Cloudflare record: ${record_name}" >&2
      rm -f "$response_file"
      return 1
    fi
  elif ! curl -fsS -G \
      "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      --data-urlencode "name=${record_name}" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H "Content-Type: application/json" > "$response_file"; then
    echo "[DNS ERROR] Could not snapshot Cloudflare record: ${record_name}" >&2
    rm -f "$response_file"
    return 1
  fi

  if ! python3 - "$response_file" "$snapshot_file" "${record_id}" "$record_name" <<'PYJSON'
import json
import os
import sys
import tempfile

try:
    with open(sys.argv[1], "r", encoding="utf-8") as stream:
        response = json.load(stream)
    if response.get("success") is not True:
        raise ValueError("Cloudflare API did not report success")
    result = response.get("result")
    expected_id, expected_name = sys.argv[3:5]
    if isinstance(result, list):
        matches = [item for item in result if item.get("name") == expected_name]
        if len(matches) != 1:
            raise ValueError("record query did not return exactly one matching record")
        record = matches[0]
    elif isinstance(result, dict):
        record = result
    else:
        raise ValueError("Cloudflare API result is missing")
    actual_id = record.get("id")
    if not actual_id or (expected_id and actual_id != expected_id):
        raise ValueError("Cloudflare record ID mismatch")
    if record.get("name") != expected_name:
        raise ValueError("Cloudflare record name mismatch")
    required = ("type", "name", "content", "ttl", "proxied")
    if any(key not in record for key in required) or not isinstance(record["proxied"], bool):
        raise ValueError("Cloudflare record response is incomplete")
    payload = {
        key: record[key]
        for key in ("type", "name", "content", "ttl", "proxied", "data")
        if key in record
    }
except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
    print(f"[DNS ERROR] Invalid Cloudflare snapshot response: {error}", file=sys.stderr)
    raise SystemExit(1)
target = os.path.abspath(sys.argv[2])
parent = os.path.dirname(target) or "."
try:
    os.makedirs(parent, mode=0o750, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".dns-snapshot-", dir=parent, text=True)
except OSError as error:
    print(f"[DNS ERROR] Could not prepare snapshot path: {error}", file=sys.stderr)
    raise SystemExit(1)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump({"id": actual_id, "payload": payload}, output, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
print(actual_id)
PYJSON
  then
    echo "[DNS ERROR] Cloudflare record snapshot was incomplete: ${record_name}" >&2
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"
}

dr_dns_snapshot_id() {
  python3 - "$1" <<'PYJSON'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    print(json.load(stream)["id"])
PYJSON
}

dr_dns_snapshot_payload() {
  python3 - "$1" <<'PYJSON'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    print(json.dumps(json.load(stream)["payload"], separators=(",", ":")))
PYJSON
}

dr_dns_snapshot_file_valid() {
  local snapshot_file="$1"
  local expected_id="${2:-}"
  local expected_name="${3:-}"
  python3 - "$snapshot_file" "$expected_id" "$expected_name" <<'PYJSON'
import json
import sys

path, expected_id, expected_name = sys.argv[1:]
try:
    with open(path, "r", encoding="utf-8") as stream:
        snapshot = json.load(stream)
    payload = snapshot["payload"]
    if not isinstance(snapshot.get("id"), str) or not snapshot["id"]:
        raise ValueError("record ID is missing")
    if expected_id and snapshot["id"] != expected_id:
        raise ValueError("record ID does not match the snapshot")
    if not isinstance(payload, dict):
        raise ValueError("record payload is missing")
    if expected_name and payload.get("name") != expected_name:
        raise ValueError("record name does not match the snapshot")
    if any(key not in payload for key in ("type", "name", "content", "ttl", "proxied")):
        raise ValueError("record payload is incomplete")
    if not isinstance(payload["proxied"], bool):
        raise ValueError("proxy setting is invalid")
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0)
PYJSON
}

dr_dns_verify_record_payload() {
  local record_id="$1"
  local expected_payload="$2"
  local label="$3"
  local response_file
  response_file="$(mktemp)"

  if ! curl -fsS -G \
      "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${record_id}" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H "Content-Type: application/json" > "$response_file"; then
    echo "[DNS ERROR] Could not read back Cloudflare record: ${label}" >&2
    rm -f "$response_file"
    return 1
  fi
  if ! python3 - "$response_file" "$record_id" "$expected_payload" <<'PYJSON'
import json
import sys

path, expected_id, expected_raw = sys.argv[1:]
try:
    with open(path, "r", encoding="utf-8") as stream:
        response = json.load(stream)
    expected = json.loads(expected_raw)
    record = response.get("result")
    if response.get("success") is not True or not isinstance(record, dict):
        raise ValueError("Cloudflare API read-back failed")
    if record.get("id") != expected_id:
        raise ValueError("record ID mismatch")
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"record field mismatch: {key}")
except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
    print(f"[DNS ERROR] Cloudflare record read-back did not match: {error}", file=sys.stderr)
    raise SystemExit(1)
PYJSON
  then
    rm -f "$response_file"
    echo "[DNS ERROR] Cloudflare record verification failed: ${label}" >&2
    return 1
  fi
  rm -f "$response_file"
  echo "[DNS] Cloudflare record verified: ${label}"
}

dr_dns_update_record() {
  local record_id="$1"
  local payload="$2"
  local label="$3"
  local response_file
  response_file="$(mktemp)"

  if ! curl -fsS -X PUT \
      "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${record_id}" \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$payload" > "$response_file"; then
    echo "[DNS ERROR] Cloudflare update failed: ${label}" >&2
    rm -f "$response_file"
    return 1
  fi
  if ! dr_dns_response_success "$response_file"; then
    echo "[DNS ERROR] Cloudflare rejected update: ${label}" >&2
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"
  if ! dr_dns_verify_record_payload "$record_id" "$payload" "$label"; then
    return 1
  fi
  echo "[DNS] Cloudflare update and read-back succeeded: ${label}"
}

dr_dns_rollback_snapshots() {
  local snapshot_dir="$1"
  local snapshot record_id payload label
  local failed=0
  local restored_any=0

  for snapshot in "$snapshot_dir"/*.json; do
    [ -e "$snapshot" ] || continue
    restored_any=1
    if ! dr_dns_snapshot_file_valid "$snapshot"; then
      echo "[DNS ROLLBACK ERROR] Snapshot is invalid: $(basename "$snapshot")" >&2
      failed=1
      continue
    fi
    record_id="$(dr_dns_snapshot_id "$snapshot")"
    payload="$(dr_dns_snapshot_payload "$snapshot")"
    label="$(basename "$snapshot" .json)"
    if dr_dns_update_record "$record_id" "$payload" "rollback:${label}"; then
      echo "[DNS ROLLBACK] Restored ${label}."
    else
      echo "[DNS ROLLBACK ERROR] Could not restore ${label}." >&2
      failed=1
    fi
  done
  if [ "$restored_any" -eq 0 ]; then
    echo "[DNS ROLLBACK ERROR] No DNS snapshots were available." >&2
    failed=1
  fi
  if [ "$failed" -eq 0 ]; then
    echo "[DNS ROLLBACK] Snapshot record set restored and verified."
  fi
  return "$failed"
}

dr_dns_apply_records() {
  local snapshot_dir="$1"
  shift
  local record_id payload label snapshot snapshot_id found
  local index
  local rollback_failed=0
  local updates=("$@")
  local snapshots=("$snapshot_dir"/*.json)

  if [ "${#updates[@]}" -eq 0 ] || [ "$(( ${#updates[@]} % 3 ))" -ne 0 ]; then
    echo "[DNS ERROR] Invalid DNS transaction arguments." >&2
    return 2
  fi
  if [ ! -f "${snapshots[0]}" ]; then
    echo "[DNS ERROR] DNS transaction snapshots are missing." >&2
    return 2
  fi
  for record_id in "${snapshots[@]}"; do
    if ! dr_dns_snapshot_file_valid "$record_id"; then
      echo "[DNS ERROR] DNS transaction snapshot is invalid: $(basename "$record_id")" >&2
      return 2
    fi
  done

  for ((index = 0; index < ${#updates[@]}; index += 3)); do
    record_id="${updates[index]}"
    payload="${updates[index + 1]}"
    label="${updates[index + 2]}"
    found=0
    for snapshot in "${snapshots[@]}"; do
      snapshot_id="$(dr_dns_snapshot_id "$snapshot")"
      if [ "$snapshot_id" = "$record_id" ]; then
        found=1
        break
      fi
    done
    if [ "$found" -ne 1 ] || ! python3 -c 'import json,sys; json.loads(sys.argv[1])' "$payload"; then
      echo "[DNS ERROR] Update is not covered by a valid snapshot: ${label}" >&2
      return 2
    fi
  done

  for ((index = 0; index < ${#updates[@]}; index += 3)); do
    record_id="${updates[index]}"
    payload="${updates[index + 1]}"
    label="${updates[index + 2]}"
    if dr_dns_update_record "$record_id" "$payload" "$label"; then
      continue
    fi

    echo "[DNS] Rolling back all records after failed update: ${label}" >&2
    if ! dr_dns_rollback_snapshots "$snapshot_dir"; then
      rollback_failed=1
    fi
    if [ "$rollback_failed" -ne 0 ]; then
      return 2
    fi
    return 1
  done
}
