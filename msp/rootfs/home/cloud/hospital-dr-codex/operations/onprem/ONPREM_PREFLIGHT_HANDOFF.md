# On-Prem DB Preflight 전달 안내

이 안내와 함께 전달할 파일은 `onprem_db_preflight.sh` 하나다. 저장소를 설치하거나, 운영 DB에 원격 접속할 필요가 없다. 도구는 현장에서 실행하는 읽기 전용 관찰 도구이며, Failover Write Fence verifier가 아니다.

## 전달 및 파일 배치

1. MSP 담당자는 다음 파일만 현장 DB 담당자에게 전달한다.
   - `operations/onprem/onprem_db_preflight.sh`
2. 승인된 파일 전달 수단을 사용한다. 실제 원격 복사나 계정·경로 설정은 이 문서의 범위가 아니다.
3. 파일을 별도 디렉터리에 저장하고, 전달 전후 `sha256sum onprem_db_preflight.sh` 값이 MSP 측 확인값과 일치하는지 확인한다.
4. 스크립트는 저장소 경로를 참조하지 않는다. 실행 권한 부여 없이 Bash로 호출할 수 있다. 실행 비트를 부여하려면 현장 담당자가 복사본에만 `chmod u+x`를 사용할 수 있다.

## 필요한 프로그램과 권한

- Ubuntu 기본 Bash(버전 4 이상), `awk`, `grep`, `hostname`, `sed`, `tr`
- MySQL 호환 `mysql` CLI. `--protocol=socket`, `--login-path`(선택), `SELECT`, `SHOW` 조회를 지원해야 한다.
- `systemctl`은 선택 사항이다. 없거나 접근이 제한되면 서비스·타이머 항목은 `UNVERIFIED`로 출력된다.
- DB 서버에서 로컬 Unix socket 접속이 가능한 기존 인증 방식과 읽기 전용 조회 권한이 필요하다. root/sudo 권한은 요구하지 않는다. 일부 전역 상태·프로세스 목록 권한이 부족하면 해당 항목은 `UNVERIFIED`로 남는다. 필요한 권한을 새로 부여하지 않는다.

이 도구는 MySQL 호환 서버에서 사용할 수 있지만, `server_uuid`, `super_read_only` 등 서버별 지원 차이가 있으면 해당 관측값을 `UNVERIFIED`로 남길 수 있다.

## 실행

DB 서버에서 파일을 저장한 디렉터리로 이동한 뒤 실행한다.

```bash
bash ./onprem_db_preflight.sh
```

이미 구성된 MySQL login path를 사용할 경우, 비밀번호가 아닌 login path 이름만 선택적으로 지정한다.

```bash
MYSQL_PREFLIGHT_LOGIN_PATH='기존-login-path-이름' bash ./onprem_db_preflight.sh
```

위 이름은 예시 자리표시자이며, 현장에 이미 설정된 이름만 사용한다. 로컬 MySQL option file/socket 인증도 사용할 수 있다. 비밀번호를 명령행, 환경변수, 문서 또는 결과에 넣지 않는다. `MYSQL_PWD` 환경변수가 설정되어 있으면 스크립트는 DB 조회를 거부한다. 새 계정이나 login path를 만들기 위해 운영 설정을 변경하지 않는다.

## 결과 읽기

각 결과는 `VERIFIED`, `BLOCKED`, `UNVERIFIED`로 표시된다. 현재 Write Fence 계약 주소 `IP_REDACTED:3306`과 서버의 로컬 주소/DB 포트가 맞는지 관찰하지만, 이 계약값 자체가 실제 현장 서버 주소임을 증명하지는 않는다. `ONPREM_DB_HOST`와 `ONPREM_DB_SERVER_UUID_EXPECTED`가 사전에 확정되어 있지 않으면 해당 pin 비교는 `UNVERIFIED`다. 임의로 값을 채우지 않는다.

특히 다음은 서로 다른 결과다.

- `MYSQL_READ_ONLY=VERIFIED value=ON`: 조회 시점의 DB 설정 관찰
- `MYSQL_SUPER_READ_ONLY=VERIFIED value=ON`: 조회 시점의 관리자 쓰기 제한 설정 관찰
- `WEB_EMR_WRITER_FENCE=UNVERIFIED`: 앱 호스트와 외부 writer는 별도 확인 필요
- `CURRENT_WRITE_ACTIVITY=UNVERIFIED`: 한 시점의 세션 목록으로 writer 차단을 증명할 수 없음
- `APPLICATION_ACCOUNT_DML=UNVERIFIED`: 애플리케이션 계정 전체와 원격 설정을 확인하지 않음
- `AUTOMATIC_WRITE_FENCE=UNVERIFIED` 및 `PREFLIGHT_RESULT=UNVERIFIED`: 이 도구는 자동 Write Fence verifier가 아님

systemd 타이머와 일부 시스템 cron은 이름·명령을 출력하지 않고 관찰 가능한 개수만 표시한다. 사용자별 crontab, 외부 애플리케이션 호스트, 수동 작업, 재시작 후 fence 지속성은 별도로 확인해야 한다.

종료 코드 0은 DB 조회 세션을 열어 기본 수집을 수행했다는 뜻일 뿐, 모든 항목이 검증됐거나 Failover가 승인됐다는 뜻이 아니다. 종료 코드가 0이 아니면 도구 의존성, MySQL CLI, 로컬 인증 및 socket 접근을 확인한다. 권한 부족으로 일부 조회만 실패한 경우 해당 항목이 `UNVERIFIED`인지 확인하고 권한을 임의 변경하지 않는다.

## MSP 담당자에게 전달할 결과

현장 담당자는 출력 전체와 실행 시각을 승인된 제한 접근 채널로 전달한다. 출력에는 호스트명, UUID, 주소, server ID 및 DB 설정이 포함될 수 있으므로 공개 문서나 발표 자료에 그대로 붙이지 않는다. 스크립트는 환자 레코드, DB 비밀번호, 토큰을 출력하거나 결과 파일을 만들지 않는다.

MSP 측에서는 다음을 확인한다.

1. hostname, `server_uuid`, `server_id`, 포트와 조회 시각이 현장 DB 담당자가 확인한 실제 서버와 일치하는지
2. 현장 주소 및 UUID pin이 승인된 설정과 일치하는지
3. `read_only`와 `super_read_only` 관찰 결과 및 조회 시각
4. binlog 상태와 File/Position이 조회 가능했는지(이는 NR/RPO 성공 증명이 아님)
5. 현재 계정 권한·세션 가시성의 한계와 MySQL 이벤트/시스템 예약 작업 결과
6. Web/EMR, 배치·수동 writer의 실제 격리 방법 및 재시작·자동 복구 이후에도 유지되는 fence 증거

## 점검 실패 시

- 도구 의존성 누락 또는 DB 연결 실패: 설치·설정을 임의 변경하지 말고 항목과 오류 시각을 담당자에게 전달한다.
- 신원 불일치, 읽기 전용 설정 불일치, binlog 비활성: 설정을 변경하지 말고 현장 DB 담당자에게 확인한다.
- 조회 권한 부족: 계정 권한을 늘리지 말고 `UNVERIFIED` 항목을 전달한다.
- 앱/외부 writer 또는 fence 지속성이 확인되지 않으면 자동 Failover를 진행하지 않는다.

이 스크립트의 출력·종료 코드·화면 캡처는 참고용 현장 관찰 결과다. Canonical Failover는 이 스크립트를 호출하거나 결과를 게이트로 사용하지 않는다.
