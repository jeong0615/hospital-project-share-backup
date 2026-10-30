#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS="$SCRIPT_DIR/rootfs"
MODE="${1:---dry-run}"
CONFIRM="${2:-}"

if [[ "$MODE" != "--dry-run" && "$MODE" != "--apply" ]]; then
  printf 'Usage: %s [--dry-run|--apply --confirm]\n' "$0" >&2
  exit 2
fi
if [[ "$MODE" == "--apply" && "$CONFIRM" != "--confirm" ]]; then
  printf '%s\n' '--apply requires a second argument: --confirm' >&2
  exit 2
fi
if [[ ! -d "$ROOTFS" ]]; then
  printf 'Missing rootfs: %s\n' "$ROOTFS" >&2
  exit 1
fi

if [[ "$EUID" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

RESTORE_PATHS=(
  home/hoseo/hospital_emr
  home/hoseo/doctor_web
  etc/nginx
  etc/apache2
  etc/openvpn/update-resolv-conf
  etc/vsftpd.conf
  etc/zabbix/zabbix_agentd.conf
  var/ossec/etc/ossec.conf
  var/ossec/etc/local_internal_options.conf
  var/www/html
)

for rel in "${RESTORE_PATHS[@]}"; do
  src="$ROOTFS/$rel"
  [[ -e "$src" || -L "$src" ]] || continue
  dest_parent="/$(dirname -- "$rel")"
  if [[ "$MODE" == "--dry-run" ]]; then
    "${SUDO[@]}" rsync -a --dry-run "$src" "$dest_parent/"
  else
    "${SUDO[@]}" rsync -a "$src" "$dest_parent/"
  fi
done

printf '%s\n' "Restore mode complete: $MODE"
printf '%s\n' 'No service restart or npm install was performed.'
printf '%s\n' 'Create .env from the external Secret store, then install dependencies with npm ci.'
