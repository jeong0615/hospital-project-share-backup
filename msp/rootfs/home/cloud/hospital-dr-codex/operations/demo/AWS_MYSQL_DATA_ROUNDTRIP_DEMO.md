# 10/25 합성 MySQL 데이터 왕복 시연

이 절차는 격리된 합성 Canary EC2만 사용한다. 운영 DB, 병원 애플리케이션, 운영 Failover 경로에는 연결하지 않는다.

## 재실행

MSP 프로젝트 루트에서 실행:

```bash
python3 operations/demo/aws_mysql_data_roundtrip.py \
  --confirm-synthetic-mysql-demo \
  --reset-existing-synthetic-db
```

Runner가 계정·고정 인스턴스·VPC·합성 태그·공인 IP 없음·초기 `stopped`를 확인한다. AWS의 `hospital_demo`가 없거나, 지정된 테이블/스키마와 알려진 합성 행 A 또는 A+B만 있을 때만 재설정한다. 다른 DB, 행, 테이블, 트리거·루틴·이벤트가 있으면 초기화 전에 중단한다. reset은 이 합성 데이터베이스 하나에만 적용되고, 로컬 운영 MySQL이나 운영 DB는 사용하지 않는다.

Runner는 시작 후 `/etc/my.cnf` 원본을 권한 0600 백업하고 합성 설정 조각을 로드한다. MySQL의 실제 bind 값, TCP listener(`IP_REDACTED:3306`만), mysqlx 비활성, 서비스 자동시작 비활성을 확인하기 전에는 합성 DB를 reset하지 않는다. MySQL 설정/검증이 실패하면 현재 인스턴스의 DB를 건드리지 않고 종료하며, 다른 합성 상태면 fail-closed 한다.

성공 JSON에서 다음을 확인한다.

- `AWS_MYSQL_FAILOVER=PASS`: 원본 역할의 A dump가 AWS MySQL에 복원되고 A가 조회됨
- `AWS_ROWS_AFTER_B=[A,B]`: AWS에서 B 추가 후 A와 B 모두 조회됨
- `AWS_MYSQL_FAILBACK=PASS`, `SOURCE_ROWS_AFTER_FAILBACK=[A,B]`: AWS dump를 원본 역할 MySQL에 복원한 뒤 A+B 확인
- `DATA_A_B=PASS`, `AWS_INSTANCE_FINAL_STATE=stopped`

## 실패 시

Runner는 비밀값을 출력하지 않고 안전한 reason code를 반환하며 임시 원본 MySQL을 제거하고 Canary EC2를 `stopped`로 복구한다. DB reset 전에 실패했으면 기존 A/B는 보존된다. reset 이후 실패해도 재실행 시 AWS의 상태가 허용된 합성 스키마와 A/B/빈 행 상태 중 하나일 때만 다시 시작할 수 있다. 알 수 없는 상태는 수동 DROP/수정하지 말고 그대로 중단해 읽기 전용으로 원인을 확인한다. 운영 DB, SG, Route, DNS를 이용한 우회 복구는 하지 않는다.

MySQL 설정 원복이 필요하면 인스턴스가 `stopped`인지 먼저 확인하고 `/etc/my.cnf.hospital-synthetic-demo.baseline`의 소유자·0600 모드와 현재 파일의 합성 include 차이를 검증한 뒤에만 원래 파일을 복구한다. 원본 설정은 MySQL을 wildcard bind로 되돌릴 수 있으므로 시연 인스턴스를 다시 시작하기 전에는 loopback 검증을 다시 통과시킨다.

실제 재현 증거: [`aws-mysql-data-roundtrip-replay-2026-10-19.json`](../../docs/evidence/aws-mysql-data-roundtrip-replay-2026-10-19.json). 이는 합성 AWS MySQL의 데이터 왕복 증거이며 실제 병원 Failover나 Node EMR 애플리케이션 E2E 증거가 아니다.
