#!/usr/bin/env bash
# 읽기 전용. 서비스 변경 명령 없음.
set -uo pipefail
systemctl show hospital-web nginx cloudflared zabbix-agent -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState
ss -lnt
