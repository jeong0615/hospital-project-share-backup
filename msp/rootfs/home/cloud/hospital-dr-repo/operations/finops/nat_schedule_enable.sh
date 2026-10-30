#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
SCHEDULE_FLAG="${DR_TERRAFORM_DIR}/.nat-schedule-enabled"

touch "$SCHEDULE_FLAG"
sudo systemctl enable --now hospital-dr-nat-enable.timer hospital-dr-nat-disable.timer

echo "[NAT SCHEDULE] Weekday morning enable and daily evening disable schedules are active."
echo "[NAT 스케줄] 평일 아침 생성 및 매일 저녁 삭제 스케줄이 활성화되었습니다."
