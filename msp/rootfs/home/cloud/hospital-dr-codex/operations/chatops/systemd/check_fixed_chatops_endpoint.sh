#!/usr/bin/env bash
set -euo pipefail

# Read-only fixed endpoint check. It never changes DNS, Slack, ngrok, or the
# Cloudflare tunnel. GET 405 is valid for the POST-only Slack action routes.

BASE_URL="https://chatops.hospital-web.pp.ua"
PATHS=(
  "/slack/failover/action"
  "/slack/failback/action"
  "/slack/action"
)

if ! command -v curl >/dev/null 2>&1; then
  echo "FIXED_ENDPOINT=BLOCKED_CURL_UNAVAILABLE"
  exit 2
fi
if ! command -v getent >/dev/null 2>&1; then
  echo "FIXED_ENDPOINT=BLOCKED_GETENT_UNAVAILABLE"
  exit 2
fi

if getent ahosts chatops.hospital-web.pp.ua >/dev/null 2>&1; then
  echo "FIXED_DNS=PASS"
else
  echo "FIXED_DNS=FAIL"
  exit 1
fi

status=0
for path in "${PATHS[@]}"; do
  result="$(curl -sS -o /dev/null -w '%{http_code} %{ssl_verify_result}' \
    --connect-timeout 5 --max-time 15 "$BASE_URL$path" 2>/dev/null || true)"
  http_code="${result%% *}"
  ssl_result="${result##* }"
  if [[ "$http_code" =~ ^[2-4][0-9][0-9]$ && "$ssl_result" == "0" ]]; then
    echo "ENDPOINT $path=PASS http=$http_code tls_verify=$ssl_result"
  else
    echo "ENDPOINT $path=FAIL http=${http_code:-000} tls_verify=${ssl_result:-unknown}"
    status=1
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo "FIXED_ENDPOINT=PASS"
else
  echo "FIXED_ENDPOINT=FAIL"
fi
exit "$status"
