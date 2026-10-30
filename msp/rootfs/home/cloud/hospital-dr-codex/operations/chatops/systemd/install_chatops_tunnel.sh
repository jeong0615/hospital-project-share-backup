#!/usr/bin/env bash
set -euo pipefail

# Install the existing Hospital DR ChatOps Cloudflare Tunnel unit.
# This helper never creates a tunnel or DNS record. A tunnel connector token
# must be supplied out-of-band by the Cloudflare administrator.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="hospital-dr-chatops-tunnel.service"
SERVICE_SOURCE="$SCRIPT_DIR/$SERVICE_NAME"
SERVICE_TARGET="/etc/systemd/system/$SERVICE_NAME"
TOKEN_FILE="/etc/cloudflared/chatops-tunnel.token"
CLOUDFLARED_BIN="/usr/bin/cloudflared"
UPSTREAM_URL="http://IP_REDACTED:5000/"
BACKUP_DIR="/var/backups/hospital-dr-chatops-tunnel"

DRY_RUN=false
APPLY=false
ENABLE=false
START=false
PACKAGE_FILE=""

usage() {
  cat <<'EOF'
Usage:
  install_chatops_tunnel.sh --dry-run [--package /path/cloudflared.deb]
  install_chatops_tunnel.sh --apply [--package /path/cloudflared.deb] [--enable] [--start]

The script installs only the existing systemd unit. It never creates a
Cloudflare tunnel, DNS record, Slack endpoint, or ngrok replacement.
--start implies --apply but does not imply --enable.
EOF
}

fail() {
  echo "[CHATOPS TUNNEL CONFIG ERROR] $*" >&2
  exit 2
}

report_token_state() {
  if [[ -L "$TOKEN_FILE" || ! -f "$TOKEN_FILE" || ! -s "$TOKEN_FILE" ]]; then
    echo "TUNNEL_TOKEN=BLOCKED_BY_CLOUDFLARE_TOKEN"
    return 1
  fi

  local mode owner group
  mode="$(stat -c '%a' "$TOKEN_FILE")"
  owner="$(stat -c '%U' "$TOKEN_FILE")"
  group="$(stat -c '%G' "$TOKEN_FILE")"
  if [[ "$mode" != "600" || "$owner" != "root" || "$group" != "root" ]]; then
    echo "TUNNEL_TOKEN=BLOCKED_UNSAFE_PERMISSIONS mode=$mode owner=$owner group=$group"
    return 1
  fi
  echo "TUNNEL_TOKEN=PASS"
}

report_binary_state() {
  if [[ -x "$CLOUDFLARED_BIN" ]]; then
    echo "CLOUDFLARED_BINARY=PASS"
    return 0
  fi
  if [[ -n "$PACKAGE_FILE" && -f "$PACKAGE_FILE" ]]; then
    echo "CLOUDFLARED_BINARY=INSTALL_PACKAGE_READY"
    return 1
  fi
  echo "CLOUDFLARED_BINARY=BLOCKED_MISSING_AT_$CLOUDFLARED_BIN"
  return 1
}

report_upstream_state() {
  command -v curl >/dev/null 2>&1 || {
    echo "CHATOPS_UPSTREAM=BLOCKED_CURL_UNAVAILABLE"
    return 1
  }

  local status
  status="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 "$UPSTREAM_URL" 2>/dev/null || true)"
  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo "CHATOPS_UPSTREAM=PASS http=$status"
    return 0
  fi
  echo "CHATOPS_UPSTREAM=BLOCKED http=${status:-000}"
  return 1
}

validate_source_unit() {
  [[ -f "$SERVICE_SOURCE" ]] || fail "missing source unit: $SERVICE_SOURCE"
  grep -Fq 'LoadCredential=chatops-tunnel.token:/etc/cloudflared/chatops-tunnel.token' "$SERVICE_SOURCE" \
    || fail "source unit must use the protected tunnel token file"
  grep -Fq '/usr/bin/cloudflared tunnel --no-autoupdate run --token-file' "$SERVICE_SOURCE" \
    || fail "source unit must use the approved cloudflared connector"
  grep -Fq 'User=cloud' "$SERVICE_SOURCE" \
    || fail "source unit must run as the ChatOps service user"
}

install_unit() {
  local stamp backup
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g root -m 700 "$BACKUP_DIR"
  if [[ -e "$SERVICE_TARGET" ]]; then
    backup="$BACKUP_DIR/$SERVICE_NAME.$stamp"
    install -o root -g root -m 600 "$SERVICE_TARGET" "$backup"
    echo "SERVICE_BACKUP=$backup"
  fi
  install -o root -g root -m 644 "$SERVICE_SOURCE" "$SERVICE_TARGET"
  systemctl daemon-reload
  echo "SERVICE_INSTALL=PASS"
}

while (($#)); do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      ;;
    --apply)
      APPLY=true
      ;;
    --enable)
      ENABLE=true
      ;;
    --start)
      START=true
      ;;
    --package)
      shift
      (($#)) || fail "--package requires a path"
      PACKAGE_FILE="$1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown option: $1"
      ;;
  esac
  shift
done

[[ "$START" == true ]] && APPLY=true
[[ "$DRY_RUN" == true || "$APPLY" == true ]] || {
  usage >&2
  fail "choose exactly one of --dry-run or --apply"
}
[[ "$DRY_RUN" == true && "$APPLY" == true ]] && fail "--dry-run and --apply cannot be combined"
[[ "$DRY_RUN" == true && ( "$ENABLE" == true || "$START" == true ) ]] && fail "runtime mutation flags cannot be used with --dry-run"
[[ "$APPLY" == true && "$EUID" -ne 0 ]] && fail "--apply requires root; use sudo"

validate_source_unit
echo "FIXED_HOSTNAME=chatops.hospital-web.pp.ua"
echo "UPSTREAM_URL=$UPSTREAM_URL"
echo "NGROK_MUTATION=NONE"

token_ok=true
binary_ok=true
upstream_ok=true
report_token_state || token_ok=false
report_binary_state || binary_ok=false
report_upstream_state || upstream_ok=false

[[ "$token_ok" == true ]] || fail "BLOCKED_BY_CLOUDFLARE_TOKEN: install the existing tunnel connector token at $TOKEN_FILE"
if [[ "$binary_ok" != true && "$APPLY" == true && -n "$PACKAGE_FILE" && -f "$PACKAGE_FILE" ]]; then
  dpkg -i "$PACKAGE_FILE"
  report_binary_state || fail "cloudflared package did not install $CLOUDFLARED_BIN"
  binary_ok=true
fi
[[ "$binary_ok" == true ]] || fail "BLOCKED_BY_CLOUDFLARED_BINARY: install the approved package first"
[[ "$upstream_ok" == true ]] || fail "BLOCKED_BY_CHATOPS_UPSTREAM: $UPSTREAM_URL is not healthy"

if [[ "$DRY_RUN" == true ]]; then
  echo "SERVICE_INSTALL=WOULD_INSTALL $SERVICE_TARGET"
  echo "SERVICE_ENABLE=SKIPPED_DRY_RUN"
  echo "SERVICE_START=SKIPPED_DRY_RUN"
  echo "NO_FILE_CHANGE=YES"
  echo "CHATOPS_TUNNEL_INSTALL=DRY_RUN_PASS"
  exit 0
fi

install_unit
if [[ "$ENABLE" == true ]]; then
  systemctl enable "$SERVICE_NAME"
  echo "SERVICE_ENABLE=PASS"
else
  echo "SERVICE_ENABLE=SKIPPED_EXPLICIT_FLAG_REQUIRED"
fi
if [[ "$START" == true ]]; then
  systemctl start "$SERVICE_NAME"
  echo "SERVICE_START=PASS"
else
  echo "SERVICE_START=SKIPPED_EXPLICIT_FLAG_REQUIRED"
fi
echo "CHATOPS_TUNNEL_INSTALL=PASS"
