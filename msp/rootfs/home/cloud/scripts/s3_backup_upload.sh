#!/usr/bin/env bash
set -euo pipefail

# MSP-only uploader. On-Prem never receives AWS credentials.
SECRET_FILE="${DR_SECRET_FILE:-/etc/hospital-dr/dr.env}"
if [[ -f "$SECRET_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$SECRET_FILE"
fi

BACKUP_DIR="${S3_BACKUP_SOURCE_DIR:-/home/cloud/db_backups}"
S3_BUCKET="${S3_BACKUP_BUCKET:-}"
S3_PREFIX="${S3_BACKUP_PREFIX:-mysql/hospital_db}"
AWS_PROFILE_NAME="${S3_BACKUP_AWS_PROFILE:-}"

# Do not allow inherited terraform-admin or other ambient credentials to
# override the dedicated MSP backup profile.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN

fail_config() {
  echo "[CONFIG ERROR] $1"
  exit 1
}

master_status_is_valid() {
  python3 - "$1" <<'PY'
import re
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
file_name = None
position = None

try:
    text = status_path.read_text(encoding="utf-8", errors="replace")
except OSError:
    raise SystemExit(1)

lines = text.splitlines()
change_statement = re.compile(
    r"\bCHANGE\s+(?:MASTER|REPLICATION\s+SOURCE)\s+TO\b"
    r"(?P<body>.*?)(?:;|$)",
    re.IGNORECASE | re.DOTALL,
)
for statement_match in change_statement.finditer(text):
    body = statement_match.group("body")
    for file_label, position_label in (
        ("MASTER_LOG_FILE", "MASTER_LOG_POS"),
        ("SOURCE_LOG_FILE", "SOURCE_LOG_POS"),
    ):
        file_match = re.search(
            rf"\b{file_label}\s*=\s*'([^']+)'",
            body,
            re.IGNORECASE,
        )
        position_match = re.search(
            rf"\b{position_label}\s*=\s*([0-9]+)",
            body,
            re.IGNORECASE,
        )
        if file_match and position_match:
            file_name = file_match.group(1)
            position = position_match.group(1)
            break
    if file_name is not None and position is not None:
        break

if file_name is None or position is None:
    for line in lines:
        if file_name is None:
            file_match = re.match(
                r"^\s*(?:File|BinlogFile)\s*:\s*(\S+)\s*$",
                line,
                re.IGNORECASE,
            )
            if file_match:
                file_name = file_match.group(1)
        if position is None:
            position_match = re.match(
                r"^\s*(?:Position|BinlogPosition)\s*:\s*([0-9]+)\s*$",
                line,
                re.IGNORECASE,
            )
            if position_match:
                position = position_match.group(1)

try:
    parsed_position = int(position) if position is not None else -1
except ValueError:
    parsed_position = -1

if not file_name or parsed_position < 0:
    raise SystemExit(1)
PY
}

s3_object_exists() {
  local key="$1"
  local listing

  if ! listing="$(aws "${AWS_ARGS[@]}" s3api list-objects-v2 \
      --bucket "$S3_BUCKET" \
      --prefix "$key" \
      --query "Contents[?Key=='${key}'].Key" \
      --output text)"; then
    echo "[S3 BACKUP] Failed to inspect S3 key: ${key}" >&2
    return 2
  fi

  grep -Fxq -- "$key" <<<"$listing"
}

[[ -n "$S3_BUCKET" ]] || fail_config "S3_BACKUP_BUCKET is required in $SECRET_FILE."
[[ -n "$AWS_PROFILE_NAME" ]] || fail_config "S3_BACKUP_AWS_PROFILE is required; do not use terraform-admin."
[[ -d "$BACKUP_DIR" ]] || fail_config "Backup directory does not exist: $BACKUP_DIR"
command -v aws >/dev/null 2>&1 || fail_config "AWS CLI is not installed on the MSP server."

LOCK_FILE="${S3_BACKUP_LOCK_FILE:-$BACKUP_DIR/.s3_backup_upload.lock}"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[S3 BACKUP] Another upload is already running; skipping this schedule."
  exit 0
fi

AWS_ARGS=(--profile "$AWS_PROFILE_NAME" --region "${AWS_REGION:-ap-northeast-2}")
DEST="s3://${S3_BUCKET%/}/${S3_PREFIX#/}"

shopt -s nullglob
mapfile -t DUMP_FILES < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.sql.gz.enc' -size +0c -print | sort)
(( ${#DUMP_FILES[@]} > 0 )) || fail_config "No encrypted backup artifacts were found in $BACKUP_DIR."

COMPLETE_PAIR_COUNT=0
UPLOADED_PAIR_COUNT=0
for dump_file in "${DUMP_FILES[@]}"; do
  dump_name="${dump_file##*/}"
  prefix="${dump_name%.sql.gz.enc}"
  status_file="$BACKUP_DIR/${prefix}.master_status"
  if [[ ! -s "$status_file" ]]; then
    echo "[S3 BACKUP] Skipping incomplete pair: ${dump_name}"
    continue
  fi

  status_name="${status_file##*/}"
  if ! master_status_is_valid "$status_file"; then
    echo "[S3 BACKUP] Skipping invalid master_status pair: ${dump_name}"
    continue
  fi
  COMPLETE_PAIR_COUNT=$((COMPLETE_PAIR_COUNT + 1))

  dump_key="${S3_PREFIX%/}/${dump_name}"
  status_key="${S3_PREFIX%/}/${status_name}"

  dump_exists=0
  if s3_object_exists "$dump_key"; then
    dump_exists=1
  else
    object_check_rc=$?
    if (( object_check_rc != 1 )); then
      exit "$object_check_rc"
    fi
  fi

  status_exists=0
  if s3_object_exists "$status_key"; then
    status_exists=1
  else
    object_check_rc=$?
    if (( object_check_rc != 1 )); then
      exit "$object_check_rc"
    fi
  fi

  if (( dump_exists == 1 && status_exists == 1 )); then
    echo "[S3 BACKUP] Pair already exists; skipping: ${dump_name} + ${status_name}"
    continue
  fi

  echo "[S3 BACKUP] Uploading missing object(s) for ${dump_name} + ${status_name}..."
  if (( dump_exists == 0 )); then
    aws "${AWS_ARGS[@]}" s3 cp "$dump_file" "${DEST}/${dump_name}" --sse AES256 --only-show-errors
  fi
  if (( status_exists == 0 )); then
    aws "${AWS_ARGS[@]}" s3 cp "$status_file" "${DEST}/${status_name}" --sse AES256 --only-show-errors
  fi
  UPLOADED_PAIR_COUNT=$((UPLOADED_PAIR_COUNT + 1))
done

(( COMPLETE_PAIR_COUNT > 0 )) || fail_config "No complete encrypted backup pairs were found in $BACKUP_DIR."

echo "[S3 BACKUP] Upload check completed; new pairs uploaded: ${UPLOADED_PAIR_COUNT}. Local MSP artifacts were preserved."
