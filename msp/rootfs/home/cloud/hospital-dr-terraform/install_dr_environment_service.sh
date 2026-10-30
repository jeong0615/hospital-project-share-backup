#!/bin/bash
set -euo pipefail

SOURCE="/home/cloud/hospital-dr-terraform/systemd/hospital-dr-environment.service"
TARGET="/etc/systemd/system/hospital-dr-environment.service"

sudo install -m 0644 "$SOURCE" "$TARGET"
sudo systemctl daemon-reload
sudo systemctl enable hospital-dr-environment.service

echo "[DR AUTOMATION] Controller boot/start and shutdown/stop automation is installed."
echo "[DR 자동화] 컨트롤러 부팅/시작 및 종료/중지 자동화를 설치했습니다."
echo "Run 'sudo systemctl start hospital-dr-environment.service' to activate it now."
echo "지금 활성화하려면 'sudo systemctl start hospital-dr-environment.service'를 실행하십시오."
