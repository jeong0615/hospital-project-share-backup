#!/usr/bin/env bash
# 설치 없이 필요한 실행 파일 존재만 확인.
set -uo pipefail
result=0
for name in node npm nginx cloudflared zabbix_agentd curl systemctl; do
  if command -v "$name" >/dev/null 2>&1; then printf 'FOUND %s
' "$name"; else printf 'MISSING %s
' "$name"; result=1; fi
done
exit "$result"
