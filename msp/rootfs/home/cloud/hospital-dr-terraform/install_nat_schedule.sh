#!/bin/bash
set -euo pipefail

UNIT_SOURCE="/home/cloud/hospital-dr-terraform/systemd"

sudo install -m 0644 "${UNIT_SOURCE}/hospital-dr-nat-enable.service" /etc/systemd/system/
sudo install -m 0644 "${UNIT_SOURCE}/hospital-dr-nat-enable.timer" /etc/systemd/system/
sudo install -m 0644 "${UNIT_SOURCE}/hospital-dr-nat-disable.service" /etc/systemd/system/
sudo install -m 0644 "${UNIT_SOURCE}/hospital-dr-nat-disable.timer" /etc/systemd/system/
sudo install -m 0644 "${UNIT_SOURCE}/hospital-dr-nat-shutdown.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hospital-dr-nat-shutdown.service

echo "[NAT SCHEDULE] Systemd units installed. Run nat_schedule_enable.sh to activate them."
echo "[NAT 스케줄] systemd 유닛 설치 완료. nat_schedule_enable.sh로 활성화하십시오."
