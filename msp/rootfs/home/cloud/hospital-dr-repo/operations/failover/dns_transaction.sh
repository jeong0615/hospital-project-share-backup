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

  if ! python3 - "$response_file" "$snapshot_file" "${record_id}" <<'PYJSON'
import json
import os
import sys
import tempfile

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    response = json.load(stream)
if response.get("success") is not True:
    raise SystemExit(1)
result = response.get("result")
if isinstance(result, list):
    record = result[0] if result else {}
else:
    record = result if isinstance(result, dict) else {}
actual_id = record.get("id")
expected_id = sys.argv[3]
if not actual_id or (expected_id and actual_id != expected_id):
    raise SystemExit(1)
required = ("type", "name", "content", "ttl", "proxied")
if any(key not in record for key in required):
    raise SystemExit(1)
payload = {
    key: record[key]
    for key in ("type", "name", "content", "ttl", "proxied", "data")
    if key in record
}
target = os.path.abspath(sys.argv[2])
parent = os.path.dirname(target) or "."
fd, temporary = tempfile.mkstemp(prefix=".dns-snapshot-", dir=parent, text=True)
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
  echo "[DNS] Cloudflare update succeeded: ${label}"
}

dr_dns_rollback_snapshots() {
  local snapshot_dir="$1"
  local snapshot record_id payload label
  local failed=0

  for snapshot in "$snapshot_dir"/*.json; do
    [ -e "$snapshot" ] || continue
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
  return "$failed"
}

dr_dns_apply_records() {
  local snapshot_dir="$1"
  shift
  local record_id payload label
  local rollback_failed=0

  while [ "$#" -ge 3 ]; do
    record_id="$1"
    payload="$2"
    label="$3"
    shift 3
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
  if [ "$#" -ne 0 ]; then
    echo "[DNS ERROR] Invalid DNS transaction arguments." >&2
    return 2
  fi
}
