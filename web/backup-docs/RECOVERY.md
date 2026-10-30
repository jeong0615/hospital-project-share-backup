# Recovery runbook

복구 시작 전에 장애 범위(Web/DB/EMR/네트워크/Cloudflare)를 나눠 확인합니다. `/health` 실패만으로 Node 중단이라고 판단하지 않습니다. 별도 새 Ubuntu 대상에서 WEB_SETUP 절차를 수행하고 운영 원본에 이 디렉터리를 덮어쓰지 않습니다.

필요물: 이 저장소, 별도 Secret, DB 전체 schema/backup과 복구 시점, Tunnel credential, Cisco/GNS3 설정 및 네트워크 증빙. OVA/VDI/IOS 원본과 DB dump는 여기 포함하지 않았습니다.

복구 순서: 네트워크 담당자 준비 → DB/EMR 복구·읽기 연결 확인 → Node 의존성 및 EnvironmentFile → systemd Web → Nginx 주 설정 → local/proxy 검사 → cloudflared/공용 DNS → external/EMR → Zabbix 중앙 수집 확인. 비밀번호/데이터 변경을 동반하는 기능 검증은 별도 테스트 데이터와 승인이 필요합니다.

DB/EMR이 꺼진 수집 환경의 미검증 결과를 운영 장애 확정으로 재사용하지 않습니다. 현재 메모리 세션은 재시작/DR 전환 시 유지되지 않습니다. RPO/RTO/DB 복제 지연·데이터 일관성은 팀 자료가 없어 숫자를 제시하지 않습니다.

복구 실패 시 전환한 새 대상의 변경 이력과 이전 DNS 값을 확인하여 승인된 이전 대상으로 돌립니다. DNS만 되돌려도 데이터/세션이 자동 병합되는 것은 아닙니다. 원본 변경/서비스 중지는 이번 작업에서 하지 않았습니다.
