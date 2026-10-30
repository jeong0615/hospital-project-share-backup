#!/usr/bin/env bash
# GET 상태 코드만 조회. 응답 본문·쿠키·Secret을 출력하지 않음.
set -uo pipefail
base=${1:-http://IP_REDACTED:3000}
result=0
for path in /login /health /check/db; do
  code=$(curl --noproxy '*' -s -o /dev/null --connect-timeout 4 --max-time 36 -w '%{http_code}' "${base%/}$path")
  rc=$?
  printf '%s http=%s curl_exit=%s
' "$path" "$code" "$rc"
  if [[ $rc -ne 0 || "$code" != 200 ]]; then result=1; fi
done
printf '%s
' '/health와 /check/db는 DB 의존. GNS3 OFF/임시 NAT에서는 미검증으로 해석할 수 있습니다.'
exit "$result"
