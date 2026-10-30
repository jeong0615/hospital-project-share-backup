#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Safe restore helper. No restore occurs without an explicit restore mode and
# either --yes or an interactive RESTORE confirmation.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS="$SCRIPT_DIR/rootfs"

usage() {
  cat <<'USAGE'
Usage:
  restore.sh --dry-run              Show all planned home and /etc changes.
  restore.sh --dry-run-home         Show only /home/cloud changes.
  restore.sh --dry-run-etc          Show only /etc changes.
  restore.sh --restore-home [--yes] Restore rootfs/home/cloud to /home/cloud.
  restore.sh --restore-etc [--yes]  Restore rootfs/etc to /etc (usually sudo).
  restore.sh --restore-all [--yes]  Restore both trees (usually sudo).

Actual restore modes never delete destination files. They may overwrite files
with the same path, so review the dry-run first. --yes skips the prompt.
USAGE
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[ERROR] required command is missing: %s\n' "$1" >&2
    exit 1
  fi
}

require_command rsync

MODE=''
ACTION='dry-run'
ASSUME_YES=0

while (($# > 0)); do
  case "$1" in
    --dry-run)
      MODE='all'
      ACTION='dry-run'
      ;;
    --dry-run-home)
      MODE='home'
      ACTION='dry-run'
      ;;
    --dry-run-etc)
      MODE='etc'
      ACTION='dry-run'
      ;;
    --restore-home)
      MODE='home'
      ACTION='restore'
      ;;
    --restore-etc)
      MODE='etc'
      ACTION='restore'
      ;;
    --restore-all)
      MODE='all'
      ACTION='restore'
      ;;
    --yes)
      ASSUME_YES=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[ERROR] unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "$MODE" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -d "$ROOTFS" ]]; then
  printf '[ERROR] backup rootfs is missing: %s\n' "$ROOTFS" >&2
  exit 1
fi

run_restore() {
  local label="$1"
  local source_path="$2"
  local destination_path="$3"
  shift 3

  if [[ ! -d "$source_path" ]]; then
    printf '[SKIP] backup path is absent: %s\n' "$source_path"
    return 0
  fi

  local args=(--archive --human-readable --itemize-changes)
  args+=(--include='**/.env.example' --include='**/*.example.tfvars')
  args+=(--include='**/*.tfvars.example')
  args+=(--exclude='**/.git/' --exclude='**/.env' --exclude='**/.env.*')
  args+=(--exclude='*.pem' --exclude='*.key' --exclude='*.secret')
  args+=(--exclude='*.tfstate' --exclude='*.tfstate.*' --exclude='*.tfvars')
  args+=(--exclude='*.sql' --exclude='*.dump' --exclude='*.enc' --exclude='*.log')
  if [[ "$ACTION" == 'dry-run' ]]; then
    args+=(--dry-run)
  fi

  printf '%s: %s -> %s\n' "$label" "$source_path" "$destination_path"
  rsync "${args[@]}" "$source_path/" "$destination_path/"
}

if [[ "$ACTION" == 'restore' ]]; then
  if (( ASSUME_YES == 0 )); then
    printf 'This will restore selected files and may overwrite same-path files.\n'
    printf 'Type RESTORE to continue: '
    read -r confirmation
    if [[ "$confirmation" != 'RESTORE' ]]; then
      printf 'Restore cancelled.\n'
      exit 0
    fi
  fi

  if [[ "$MODE" == 'etc' || "$MODE" == 'all' ]] && [[ "$(id -u)" -ne 0 ]]; then
    printf '[ERROR] /etc restore requires root; rerun with sudo.\n' >&2
    exit 1
  fi
fi

case "$MODE" in
  home)
    run_restore 'home restore' "$ROOTFS/home/cloud" /home/cloud
    ;;
  etc)
    run_restore 'etc restore' "$ROOTFS/etc" /etc
    ;;
  all)
    run_restore 'home restore' "$ROOTFS/home/cloud" /home/cloud
    run_restore 'etc restore' "$ROOTFS/etc" /etc
    ;;
esac

if [[ "$ACTION" == 'dry-run' ]]; then
  printf 'dry_run_complete=true\n'
else
  printf 'restore_complete=true\n'
fi
