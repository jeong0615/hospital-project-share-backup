# 격리 Dump 검증 MySQL

이 구성은 일반 DR DB나 On-Prem DB를 복원 대상으로 사용하지 않는다. ChatOps
Executor 및 Failover/DNS 경로와도 연결되지 않은 별도 검증 환경이다.

## 격리 경계

- Terraform의 `enable_dump_restore_isolated_host` 기본값은 `false`다. 이 작업에서는
  Terraform plan/apply를 실행하지 않았고 AWS 리소스도 만들거나 시작하지 않았다.
- 별도 EC2는 private DB subnet에만 배치하고 public IP를 붙이지 않는다. EC2 metadata는
  IMDSv2만 허용하고 instance profile은 부여하지 않는다.
- 격리 보안 그룹은 DR Web SG에서 오는 TCP/22만 ingress로 허용하며, egress는 TCP
  80/443으로 제한한다. MySQL 포트 ingress/egress는 허용하지 않는다.
- MySQL 데이터(`/var/lib/mysql`)와 암호화 Dump/검증 결과는 각각 별도의 암호화된 EBS에
  둔다. 두 볼륨 모두 serial과 AWS API의 volume ID/tag/attachment를 대조한다.
- MySQL은 격리 EC2에서 별도 프로세스로 실행하고 `AWS_PUBLIC_IP_REDACTED:3307`만 사용한다. 기존
  운영 MySQL의 3306과 다른 포트이며 외부 listener는 허용하지 않는다.
- AWS DB instance `AWS_RESOURCE_ID_REDACTED`, AWS DB IP `AWS_PUBLIC_IP_REDACTED`, On-Prem DB IP
  `IP_REDACTED`를 코드에서 명시적으로 거부한다.
- 실제 복원은 스키마가 없는 경우에만 시작한다. 복원 사용자는 `hospital_db` 스키마에
  한정되고, SQL import는 root가 아닌 socket 인증의 제한 사용자로 실행된다. 실패한
  schema를 자동 삭제하거나 재사용하지 않는다.

## 격리 DB 서비스 연결 준비 (별도 승인 필요)

복원 환경과 서비스 listener는 분리되어 있다. Terraform의
`enable_dump_restore_service_sg` 기본값은 `false`이며, 별도 SG는 Web/Doc SG만 source로
허용하는 TCP/3307 규칙을 정의하지만 Terraform에서 격리 EC2에 자동 연결하지 않는다.
기본 복원 단계는 loopback `IP_REDACTED:3307`만 유지한다.

`service-preflight`는 AWS instance/VPC/private subnet/SG/EBS identity 및 격리 호스트의
root-owned 성공 restore receipt, 실제 EBS serial, MySQL loopback listener를 재검증한다.
명시적 `prepare-service --confirm-isolated-service-prepare`만 이 검증 뒤 전용 SG를 붙이고,
복원 DB에 `hospital_dr_service` 계정을 Web/Doc 고정 사설 IP별로 준비한 다음 MySQL을
`IP_REDACTED,<격리 DB private IP>:3307`에 바인딩한다. 이 과정은 `read_only`와
`super_read_only`를 켠 채 검증한다. 예상치 못한 listener/실패가 있으면 loopback 전용,
read-only 상태로 격리(quarantine)하고, 네트워크 SG를 분리한다. 자동 rollback이 확인되지
않으면 `PARTIAL_FAILURE`로 중단한다.

서비스 계정은 `hospital_db`의 SELECT/INSERT/UPDATE/DELETE만 받으며 MySQL root가 아니다.
비밀번호는 짧게 존재하는 mode-0600 tmpfs 파일과 Ansible `no_log` 경로만 통과한다.
일반 Failover의 Web/EMR DB endpoint는 계속 `AWS_PUBLIC_IP_REDACTED:3306`이며, 이 준비 경로는
앱 설정, Failover/Failback, DR state 또는 DNS를 바꾸지 않는다. `DUMP_RESTORE_EXEC_ENABLED=false`
유지 및 `DUMP_RESTORE_EXECUTOR` 미설정 조건도 바뀌지 않는다.

이 작업에서는 Terraform 적용, SG 연결, MySQL 설정 변경/재시작, 복원, endpoint 전환을
수행하지 않았다. Terraform에서 서비스 SG를 생성한 뒤에도, 운영자는 별도 변경 승인과
백업/성공 receipt 검토 후 `service-preflight`를 먼저 실행해야 한다. 준비를 실행할 때는
비밀번호를 명령행에 넣지 말고 secret manager에서 허가된 `DUMP_RESTORE_SERVICE_DB_PASSWORD`
환경으로 wrapper에 전달한다. `prepare-service`는 실제로 격리 EC2의 SG와 MySQL 설정을
변경하고 MySQL을 재시작하므로 이번 단계에서는 실행하지 않는다.

## 복원 검증

Controller는 AWS Describe API만 호출하며, 대상 instance/tag/IP/VPC/subnet/SG, root·data·
staging EBS 암호화와 attachment를 확인한다. instance가 이미 `running`이 아니면 중단하며
시작/중지하지 않는다. Ansible은 EC2 metadata와 NVMe serial을 재검증한 뒤에만 각 volume을
mount한다. 대상 mountpoint가 비어 있지 않거나 알 수 없는 파일시스템이면 거부한다.

복원은 선택된 `.sql.gz.enc`와 동일 이름의 `.master_status`, 요청 SHA-256, OpenSSL
`Salted__` container, 복호화, gzip 검사, SQL 안의 binlog File/Position과 sidecar 일치를
검증한다. 복호화 키는 controller `/dev/shm`과 대상 `/run`의 mode 0600 임시 파일만 통과하고
명령행 값이나 로그에는 넣지 않는다. import 후 table 수와 `mysqlcheck`가 성공해야 상태를
`SUCCESS`로 기록한다. 이 검증은 스키마/테이블 무결성 확인이지 업무 데이터의 완전성이나
실제 HIS 애플리케이션 호환성 보증은 아니다.

`DUMP_RESTORE_EXEC_ENABLED=false`와 `DUMP_RESTORE_EXECUTOR` 미설정은 그대로 둔다. 이 도구는
ChatOps 승인/실행 경로가 아니며 DNS, DR state, 서비스 DB 전환을 수행하지 않는다.

## 향후 별도 승인 후 사용할 명령 형태

아래 명령은 이번 작업에서 실행하지 않았다. isolated Terraform 리소스를 만드는 작업은
EC2를 실제 생성·기동하고 EBS 비용을 발생시키므로 별도 승인과 plan 검토가 필요하다.
`enable_dump_restore_isolated_host=true`로 만든 plan은 isolated instance, SG, 두 EBS 및
attachment 외의 기존 DR 리소스 변경이 없어야 한다.

## EC2/EBS 삭제 보호 및 서비스 승격 상태

기본값은 계속 `enable_dump_restore_isolated_host=false`,
`enable_dump_restore_service_sg=false`, `dump_restore_isolated_service_promoted=false`다.
기본 상태에서는 격리 리소스가 생성되지 않는다. 리소스가 생성된 뒤에는 격리 EC2,
root/data/staging EBS, 두 volume attachment, 복원/서비스 SG에 항상
`lifecycle.prevent_destroy=true`가 적용된다. 따라서 `enable_dump_restore_isolated_host` 또는
서비스 SG 옵션을 끄는 plan은 자동 삭제 대신 Terraform 오류로 차단되어야 한다.

EC2에는 AWS API termination protection도 켜고, root EBS는
`delete_on_termination=false`와 식별 tag를 사용한다. data/staging EBS는 EC2와 별도 리소스로
관리하며 volume 자체와 attachment 모두 삭제/분리 보호한다. 이는 Terraform plan 보호,
AWS API 종료 보호, 직접 EC2 종료 뒤 데이터 볼륨 보존을 겹친 것이다. `prevent_destroy`는
resource block 자체가 코드에서 제거되면 그 block의 보호를 더 이상 적용할 수 없으므로,
보호 제거/리소스 block 삭제는 별도 검토·승인된 폐기 변경에서만 허용한다.

`dump_restore_isolated_service_promoted=true`는 운영자가 승격 완료를 기록하는 tag/state
표시일 뿐, 승격을 수행하거나 AWS runtime을 검증하는 스위치가 아니다. 이 값은 host와 전용
service SG가 계속 enabled일 때만 허용된다. 이 표시를 `false`로 바꿔도 위 삭제 보호는
해제되지 않는다. 기존 일반 DR DB (`AWS_RESOURCE_ID_REDACTED`, `AWS_PUBLIC_IP_REDACTED`)와 On-Prem DB는
이번 보호 변경의 대상이 아니며 Terraform 설정도 수정하지 않았다.

19:00 비용 Lambda는 코드상 `Hospital-Real-Web-Server`, `Hospital-DR-Doc-Server`,
`Hospital-DR-DB-Server`라는 정확한 Name tag만 Stop하며 `TerminateInstances`/EBS 삭제를
호출할 권한이나 코드를 갖지 않는다. 격리 호스트는 그 Name 목록에 없다. Lambda는 이번에
수정하지 않았다. EC2 Stop은 EBS를 삭제하지 않지만, stopped EC2의 root/data/staging EBS는
계속 비용이 발생한다. root `DeleteOnTermination=false`는 EC2가 별도로 종료되더라도 root
볼륨을 남기므로, 폐기하지 않는 동안 그 볼륨 비용도 계속된다.

### 명시적 운영자 승인 폐기 절차

격리 DB가 서비스 승격된 적이 있으면 일반 비용 정리만으로 폐기하지 않는다. 서비스 소유자와
DB 담당자의 명시 승인, 애플리케이션이 해당 DB endpoint를 더 이상 사용하지 않는 증거,
필요한 보존 백업/snapshot 및 복구 확인을 먼저 남긴다. 그런 다음 별도 코드리뷰에서 격리
리소스의 `prevent_destroy` 제거와 종료 보호 해제를 명시적으로 승인하고, Terraform plan을
저장해 격리 EC2/SG/EBS/attachment만 영향받는지 두 사람이 확인한다. 이 변경 없이는 flag를
끄는 것만으로 폐기할 수 없어야 한다. State에서 리소스를 제거하거나 AWS Console/CLI로
Terraform 관리 리소스를 우회 삭제하지 않는다.

적용 승인을 받은 폐기 후에는 EC2가 실제 종료됐는지, data/staging EBS가 의도대로 삭제 또는
보존됐는지 확인한다. root EBS는 `DeleteOnTermination=false` 때문에 별도로 남을 수 있다.
태그 `Role=isolated-dump-restore-root`와 실제 volume ID/attachment 상태를 대조하고, 승인된
보존 snapshot과 복구 가능성을 확인한 뒤에만 해당 volume ID를 대상으로 별도 폐기 승인을
받는다. 승격 DB의 데이터 보존 필요성이 해결되지 않았거나 식별이 모호하면 중단한다.

리소스 준비 후 read-only preflight:

```bash
backup_file=/home/cloud/db_backups/db_backup_YYYYMMDD_HHMMSS.sql.gz.enc
expected_sha256=$(sha256sum "$backup_file" | awk '{print $1}')

bash operations/db/isolated_dump_restore.sh preflight \
  --instance-id "$(terraform -chdir=infra/terraform output -raw dump_restore_isolated_instance_id)" \
  --private-ip "$(terraform -chdir=infra/terraform output -raw dump_restore_isolated_private_ip)" \
  --data-volume-id "$(terraform -chdir=infra/terraform output -raw dump_restore_isolated_data_volume_id)" \
  --stage-volume-id "$(terraform -chdir=infra/terraform output -raw dump_restore_isolated_stage_volume_id)" \
  --backup "$backup_file" \
  --expected-sha256 "$expected_sha256"
```

격리 복원은 운영자가 백업/대상/비용을 다시 확인하고 별도 실행을 승인한 뒤에만
`restore --confirm-isolated-restore`로 요청한다. 이 명령은 **실제 격리 DB를 변경**한다.
키 값은 기존 외부 `DR_SECRET_FILE`의 `DB_BACKUP_ENCRYPTION_KEY`에서 읽으며 명령행에 넣지
않는다. 이 단계에서는 실행하지 않는다.

성공 이후에도 데이터는 격리 DB에만 남는다. 실제 서비스 DB로 전환하거나 DNS를 변경하는
동작은 이 구성에 없다. 향후 별도 설계/승인에서 schema 호환성, app 계정·권한, DB endpoint
전환, post-restore application health, 재시도/격리 실패물 보존 및 비용 cleanup을 정해야 한다.
