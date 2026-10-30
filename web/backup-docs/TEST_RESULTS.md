# Test results

조회 시각: 2026-09-17 KST (원시 JSON은 UTC). curl은 TLS 검증을 끄지 않았고 본문/쿠키/로그를 저장하지 않았습니다. GET 및 TCP connect만 수행했으며 사용자 생성·로그인·예약·삭제 요청을 보내지 않았습니다.

| 검사 | 관측 | 판정 |
|---|---|---|
| local-health `http://IP_REDACTED:3000/health` | HTTP 500, 21.181440s | NOT VERIFIED — GNS3 OFF / temporary NAT extraction environment |
| local-login `http://IP_REDACTED:3000/login` | HTTP 200, 0.038776s | PASS |
| nginx-root `http://IP_REDACTED:80/` | HTTP 200, 21.195468s | PASS |
| localhost-root `http://localhost/` | HTTP 200, 21.195809s | PASS |
| external `https://hospital-web.pp.ua` | HTTP 200, 21.644214s | PASS |
| db-check `http://IP_REDACTED:3000/check/db` | HTTP 500, 21.020795s | NOT VERIFIED — GNS3 OFF / temporary NAT extraction environment |
| emr-redirect `http://IP_REDACTED/emr` | HTTP 301, 0.000292s | PASS (redirect status; Location는 config 기준) |
| emr-proxy `http://IP_REDACTED/emr/` | HTTP 502, 21.018912s | NOT VERIFIED — GNS3 OFF / temporary NAT extraction environment |
| nginx-login `http://IP_REDACTED/login` | HTTP 200, 0.006858s | PASS |
| IP_REDACTED:3306 | TCP timeout | NOT VERIFIED — GNS3 OFF / temporary NAT extraction environment |
| IP_REDACTED:5000 | TCP timeout | NOT VERIFIED — GNS3 OFF / temporary NAT extraction environment |

GNS3 전원 상태 자체를 이 VM에서 확정하지 않았습니다. 사용자 제공 임시 NAT/GNS3 OFF 가능성에 따라 backend 실패를 설정 오류로 단정하지 않습니다. `/health`와 `/check/db`는 500, EMR proxy는 502로 실제 관측되었으며 성공으로 처리하지 않았습니다. TCP3306/5000도 timeout이었습니다. 경로 수정은 하지 않았습니다.

메인 `/`는 DB 조회 실패를 빈 목록으로 처리하므로 200이어도 DB 정상은 아닙니다. 외부 HTTPS 200/TLS verify result 0은 공용 페이지와 TLS 검증 통과만 입증하며 실제 Tunnel/AWS origin, DNS CNAME 관리값, Strict Rule 적용, 로그인 세션, 중앙 Agent 수집 성공을 입증하지 않습니다.

systemd: hospital-web/nginx/cloudflared/zabbix-agent 모두 active/running/enabled. ss: Node IP_REDACTED:3000, Nginx IP_REDACTED:80, Agent :10050. 읽기 가능한 네트워크/service 조회 성공. systemctl status 대신 로그가 없는 systemctl show 속성 수집 사용.

미검증: Netplan 원본, 권한 있는 nginx -T 전체 덤프, GNS3/Cisco ACL 재현, 중앙 Zabbix UI, Cloudflare 관리 상태, AWS DR 및 Failover/Failback, 인증/가입/예약 쓰기, 깨끗한 서버 npm ci/재구축. nginx -T 비root 결과는 권한 오류이며 최종 통과로 기재하지 않습니다.

원본 해시/복사본 구문/JSON/secret 검수 결과는 VALIDATION.json 및 SECRET_SCAN.md를 참고하세요. 재구축 스크립트는 실행하지 않고 구문만 검사했습니다.
