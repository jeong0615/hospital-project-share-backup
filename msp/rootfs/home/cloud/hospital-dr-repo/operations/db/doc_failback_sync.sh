#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

LOG_FILE="${LOG_FILE:-$DR_LOG_DIR/doc_failback.log}"
mkdir -p "$(dirname -- "$LOG_FILE")"
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [ -f "$SECRET_FILE" ]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi

require_secret() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required secret: ${name}. Set it in ${SECRET_FILE}."
    exit 1
  fi
}

require_config() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[CONFIG ERROR] Missing required configuration: ${name}."
    exit 1
  fi
}

INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
ONPREM_DOC_SSH="${ONPREM_DOC_SSH:-}"
ONPREM_DOC_SSH_KEY="${ONPREM_DOC_SSH_KEY:-${DR_SSH_KEY:-}}"
ONPREM_DOC_PATH="${ONPREM_DOC_PATH:-}"
ONPREM_DOC_PORT="${ONPREM_DOC_PORT:-5000}"
ONPREM_DOC_DB_HOST="${ONPREM_DOC_DB_HOST:-}"
ONPREM_DOC_DB_PORT="${ONPREM_DOC_DB_PORT:-3306}"
ONPREM_DOC_DB_USER="${ONPREM_DOC_DB_USER:-admin}"
ONPREM_DOC_DB_PASSWORD="${ONPREM_DOC_DB_PASSWORD:-${DOC_DB_PASSWORD:-}}"
ONPREM_DOC_DB_NAME="${ONPREM_DOC_DB_NAME:-hospital_db}"
DR_DOC_PATH="${DR_DOC_PATH:-/home/ubuntu/hospital-emr}"
CONFIRM="${DOC_FAILBACK_CONFIRM:-}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)

if [ -r "$DR_TIMING_SCRIPT" ]; then
  # shellcheck disable=SC1091
  source "$DR_TIMING_SCRIPT"
else
  dr_timing_start() { printf '0\n'; }
  dr_timing_end() { :; }
fi

exec > >(tee -a "$LOG_FILE") 2>&1
doc_sync_timing_start="$(dr_timing_start doc_sync_internal)"

require_secret "ONPREM_DOC_DB_PASSWORD"
require_config "ONPREM_DOC_SSH_KEY"
require_config "ONPREM_DOC_PATH"
require_config "ONPREM_DOC_DB_HOST"

echo "=================================================="
echo "[$(date)] Doc failback sync started."
echo "=================================================="

if [ -z "$ONPREM_DOC_SSH" ]; then
  echo "[DOC FAILBACK BLOCKED] Required variable is missing: ONPREM_DOC_SSH"
  echo "Example: ONPREM_DOC_SSH='operator@IP_REDACTED'"
  exit 2
fi

if [ "$CONFIRM" != "SYNC_DOC_TO_ONPREM" ]; then
  echo "[DOC FAILBACK BLOCKED] Set DOC_FAILBACK_CONFIRM=SYNC_DOC_TO_ONPREM to sync DR Doc files to on-premises."
  exit 2
fi

echo "[DOC FAILBACK] Packaging DR Doc application files."
ansible -i "$INVENTORY" doc_servers -m shell -a "tar -C '${DR_DOC_PATH}' --exclude='./node_modules' --exclude='./.env' -czf /tmp/hospital-emr-failback.tar.gz ."

TMP_ARCHIVE="$(mktemp /tmp/hospital-emr-failback.XXXXXX.tar.gz)"
trap 'rm -f "$TMP_ARCHIVE"' EXIT

echo "[DOC FAILBACK] Downloading Doc archive from DR Doc through the Web bastion."
WEB_HOST=$(awk '/^\[web_servers\]/{getline; print $1; exit}' "$INVENTORY")
SSH_KEY=$(awk '/^\[web_servers\]/{getline; for (i=1;i<=NF;i++) if ($i ~ /ansible_ssh_private_key_file=/) {split($i,a,"="); print a[2]; exit}}' "$INVENTORY")
scp -i "$SSH_KEY" "${SSH_OPTS[@]}" \
  -o "ProxyCommand=ssh -i ${SSH_KEY} ${SSH_OPTS[*]} -W %h:%p ubuntu@${WEB_HOST}" \
  ubuntu@IP_REDACTED:/tmp/hospital-emr-failback.tar.gz "$TMP_ARCHIVE"

echo "[DOC FAILBACK] Uploading Doc archive to on-premises Doc server."
scp -i "$ONPREM_DOC_SSH_KEY" "${SSH_OPTS[@]}" "$TMP_ARCHIVE" "${ONPREM_DOC_SSH}:/tmp/hospital-emr-failback.tar.gz"

echo "[DOC FAILBACK] Expanding Doc files on on-premises Doc server."
ssh -n -i "$ONPREM_DOC_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_DOC_SSH" "mkdir -p '${ONPREM_DOC_PATH}' && tar -C '${ONPREM_DOC_PATH}' -xzf /tmp/hospital-emr-failback.tar.gz"

echo "[DOC FAILBACK] Rendering on-premises Doc environment file."
ssh -n -i "$ONPREM_DOC_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_DOC_SSH" "cat > '${ONPREM_DOC_PATH}/.env' <<EOF
PORT=${ONPREM_DOC_PORT}
DB_HOST=${ONPREM_DOC_DB_HOST}
DB_PORT=${ONPREM_DOC_DB_PORT}
DB_USER=${ONPREM_DOC_DB_USER}
DB_PASSWORD=${ONPREM_DOC_DB_PASSWORD}
DB_NAME=${ONPREM_DOC_DB_NAME}
EOF"

echo "[DOC FAILBACK] Installing dependencies and restarting on-premises Doc service."
ssh -n -i "$ONPREM_DOC_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_DOC_SSH" "cd '${ONPREM_DOC_PATH}' && rm -f package-lock.json && npm install --omit=dev body-parser@1.20.3 cors@2.8.5 express@4.21.2 mysql2@2.3.3 && if command -v pm2 >/dev/null 2>&1; then pm2 delete hospital-emr || true; PORT='${ONPREM_DOC_PORT}' pm2 start server.js --name hospital-emr --update-env; pm2 save; else pids=\$(lsof -ti tcp:${ONPREM_DOC_PORT} 2>/dev/null || true); if [ -n \"\$pids\" ]; then kill \$pids || true; sleep 1; fi; rm -f /tmp/hospital-emr.log; setsid -f env PORT='${ONPREM_DOC_PORT}' DB_HOST='${ONPREM_DOC_DB_HOST}' DB_PORT='${ONPREM_DOC_DB_PORT}' DB_USER='${ONPREM_DOC_DB_USER}' DB_PASSWORD='${ONPREM_DOC_DB_PASSWORD}' DB_NAME='${ONPREM_DOC_DB_NAME}' node '${ONPREM_DOC_PATH}/server.js' > /tmp/hospital-emr.log 2>&1; sleep 2; fi"

echo "[DOC FAILBACK] Verifying on-premises Doc service."
ssh -n -i "$ONPREM_DOC_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_DOC_SSH" "test -f '${ONPREM_DOC_PATH}/server.js' && curl -fsS --connect-timeout 5 --max-time 15 http://IP_REDACTED:${ONPREM_DOC_PORT}/ >/dev/null"

dr_timing_end doc_sync_internal "$doc_sync_timing_start"
echo "[DOC FAILBACK] Doc failback sync completed."
echo "=================================================="
echo "[$(date)] Doc failback completed."
echo "=================================================="
