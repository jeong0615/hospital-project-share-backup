# 최종 수집 보고

**READY_FOR_MANUAL_INPUT — 보호된 로컬 자료 2종 사용자 보완 완료**

백업 디렉터리: `/home/vboxuser/hospital-github-backup`. 복사 48개, 생성 Markdown 문서 38개, 제외 1540개, 사용자 보완 자료 2종, 저장소 전체 123개 파일. 고정 비밀값/예시 탐지 3곳, 민감값·경로 치환 6곳, 잔존 고신뢰 secret/금지 파일 0건.

성공: 로컬 로그인, Nginx 로그인/메인, localhost 메인, 외부 HTTPS 200 및 TLS 검증, EMR redirect 301, 네 서비스 active/enabled, 원본 수집 대상 48개 해시 일치, 복사본 구문/JSON/lock 검사. 상세 TEST_RESULTS.md 및 inventory/VALIDATION.json 참조.

NOT VERIFIED: DB·EMR 및 DB 의존 health (현재 임시 NAT / GNS3 OFF 상태이므로 검증하지 못함; GNS3 전원 자체는 미확인). 또한 Netplan 원본 직접 대조, 중앙 Zabbix 등록, Cisco/GNS3 ACL, AWS DR 전환 및 로그인/쓰기/신규 구축 검증 미완료.

차이 5항목: Nginx wildcard에 포함된 bak, 임시 NAT Gateway, 목적 미확인 wg0, 과거 배포 설명, npm CLI/package 버전 차이. 원본 수정 없이 CONFLICT_REPORT.md에 기록.

수동 보완: Cisco 4종 설정/show, GNS3 및 WEB-IN/SERVER-IN/Cloud Node, 물리 Port Map, 중앙 Zabbix/Cloudflare/DR 외부 증빙, 외부 검증 및 자료 보완 (Netplan과 nginx -T는 사용자 제공본으로 보완 완료). Secret·DB dump·VM·IOS 원본은 Git 외부에 보관. 전체 18개 분류는 MISSING_ITEMS.md 참조.

자동 수집은 접근 가능한 범위에서 마쳤습니다. 최초 미수집 Netplan과 nginx -T는 사용자 제공 자료로 보완했습니다. nginx -T의 설정 검사 통과와 bak 포함을 확인했습니다. 자료 출처는 자동 수집과 구분하며 실행 중 메모리 설정 일치나 완전 복구를 보장하지 않습니다. 수동 자료를 추가한 후 별도 최종 보안 검수가 필요하며 READY_FOR_GITHUB 또는 재구축 성공을 선언하지 않습니다. Git 초기화/commit/push 및 운영 소스·설정 변경/서비스 조작/패키지 설치는 수행하지 않았습니다.

전체 트리: REPOSITORY_TREE.txt. 원본 매핑 COLLECTED_FILES.md, 제외 목록 EXCLUDED_FILES.md, 보안 SECRET_SCAN.md.
