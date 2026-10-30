#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
SCHEDULE_FLAG="${DR_TERRAFORM_DIR}/.nat-schedule-enabled"

rm -f "$SCHEDULE_FLAG"
sudo systemctl disable --now hospital-dr-nat-enable.timer
sudo systemctl enable --now hospital-dr-nat-disable.timer

echo "[NAT SCHEDULE] Automatic morning creation is disabled; the evening safety deletion remains active."
echo "[NAT 스케줄] 아침 자동 생성은 중지하고 저녁 안전 삭제는 유지합니다."
