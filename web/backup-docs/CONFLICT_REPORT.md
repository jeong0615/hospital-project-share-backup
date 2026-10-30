# Conflict report

원본은 수정하지 않았습니다. 사용자 최종 외부 컨텍스트와 현재 로컬 증거가 다른 항목을 구분합니다.

| ID | 관측 | 최종 기준/차이 | 처리 |
|---|---|---|---|
| C1 | sites-enabled의 hospital.bak도 wildcard include 대상, EMR→IP_REDACTED:3000 및 분리된 server_name | 최종 EMR→IP_REDACTED:5000 | 주 hospital은 일치; bak를 활성 include 후보로 보존·경고, 실제 로드 덤프 미확보 |
| C2 | 기본 경로 IP_REDACTED enp0s8 | 최종 Gateway IP_REDACTED | 사용자 설명과 일치하는 임시 NAT 예외; 변경 안 함 |
| C3 | wg0 IP_REDACTED 및 IP_REDACTED/24 route | 최종 외부 컨텍스트에 목적 미기재 | 실제 관측만 기록, 최종 포함 여부 수동 확인 |
| C4 | 과거 배포 문서의 IP_REDACTED 바인딩/다른 Web IP/실제 진료기록 조회 설명 | 현재 IP_REDACTED 및 빈 records 마이페이지 | legacy 폴더로 분리 |
| C5 | npm CLI 10.9.4, dpkg npm 8.5.1~ds-1 | 실행 버전과 OS package inventory 불일치 | 양쪽 기록, 설치 경로/공급 방식 재구축 때 확인 |

Zabbix Hostname web_sever와 OS hostname hospital-web-server-1은 다른 식별자이며 프롬프트와 충돌한다고 단정하지 않습니다. 중앙 등록 확인 전 수정하지 않습니다. Cloudflare DNS/Rule은 원격 관리 상태를 확인하지 않아 충돌 유무 자체가 미검증입니다.

앱 보안상의 한계(평문 비교, 공개 예약 목록, root 실행, MemoryStore)는 설계 충돌과 별도로 APPLICATION.md에 기록했습니다.
