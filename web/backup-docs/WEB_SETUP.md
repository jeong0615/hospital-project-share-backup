# 새 Ubuntu 재구축 절차

아래는 **새 복구 대상에서만** 수행할 절차이며 현재 운영 서버에는 적용하지 않았습니다. 이 백업만으로 DB/EMR/네트워크/Secret을 자동 복구할 수 없습니다.

1. Ubuntu 및 Node/npm/Nginx/cloudflared/Zabbix Agent의 관측 버전을 INVENTORY에서 확인합니다. 필요한 패키지와 공급원은 운영자가 준비합니다. 이번 수집에서는 패키지를 설치하지 않았습니다.
2. 네트워크 담당자가 새 VM의 최종 Web IP IP_REDACTED/24 및 Gateway IP_REDACTED, NIC/VLAN/ACL을 확인합니다. 기존 VM과 IP가 중복된 채 동시에 연결하지 않도록 복구 계획에서 조정합니다. 임시 NAT/목적 미확인 wg0를 복제하지 않습니다.
3. `web/scripts/deploy-web.sh /새로운/빈/대상경로`로 소스와 `.env.example`을 준비합니다. 기존 경로면 거부합니다. 스크립트는 서비스를 변경하지 않습니다.
4. 새 대상의 `.env.example`을 `.env`로 직접 복사하고 소유자 제한 권한을 설정한 뒤 안전한 경로로 DB_USER/PASSWORD/NAME, SESSION_SECRET을 입력합니다. 코드가 참조하는 이름은 ENVIRONMENT 문서를 따릅니다. SESSION_SECRET placeholder/fallback은 운영값으로 사용하지 않습니다. ZABBIX_URL은 필요한 API 진단만 위한 값이며 Agent 설정과 별개입니다.
5. 새 앱 디렉터리에서 `npm ci --omit=dev`를 실행합니다. package-lock.json을 사용하며 원본 서버/node_modules에는 실행하지 않습니다. 패키지 lifecycle script가 실행될 수 있으므로 배포자가 lock을 검토합니다.
6. DB 담당자로부터 Users/Patients/Doctors/AccessLogs 등 실제 전체 schema/backup을 확보합니다. 포함된 ReservationPosts DDL만으로 전체 DB를 구축할 수 없습니다. SQL seed/DDL을 자동 실행하지 않습니다.
7. `hospital-web.service`를 새 대상 경로, User, EnvironmentFile, node 경로에 맞게 **새 서버에서** 검토합니다. 관측 원본은 User=root입니다. 이 저장소에는 현재 상태를 보존했으며 새 대상 권한 정책은 배포자가 결정합니다. systemd를 설치/enable/start하는 작업은 수집 스크립트가 수행하지 않습니다.
8. Nginx 주 hospital server block을 검토하고 설치합니다. `.bak`와 inactive/default를 무조건 활성화하지 않습니다. 새 서버에서 `nginx -t` 및 unit 설정을 확인한 뒤 운영자가 필요한 서비스를 시작합니다.
9. cloudflared config의 `<CREDENTIAL_FILE>`을 별도 보관 credential 경로로 지정합니다. credential 파일을 Git에 넣지 않습니다. Tunnel/DNS 전환은 별도 운영자 작업입니다.
10. Zabbix Agent Server/ServerActive/Hostname을 중앙 담당자와 맞추고 중앙 등록을 확인합니다. 관리자 계정/중앙 설정은 이 저장소 범위 밖입니다.
11. 로컬 `/login` → Nginx `/login` → `/health` 및 `/check/db` → `/emr/` → 외부 HTTPS 순으로 검사합니다. `/`도 DB 대기를 포함하므로 단순 프로세스 liveness와 구분합니다. secure cookie 때문에 로컬 HTTP 조회만으로 로그인 세션 성공을 증명할 수 없습니다.

현재 복사본의 소스 구문과 lock 구조만 확인했으며 깨끗한 Ubuntu 설치/의존성 다운로드/회원가입·예약 쓰기 검증은 미수행입니다.
