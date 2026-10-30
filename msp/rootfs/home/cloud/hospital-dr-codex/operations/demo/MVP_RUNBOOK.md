# 2026-10-28 병원 DR MVP 시연 Runbook

작성 기준: 2026-10-13. 이 문서는 저장소의 실행 코드·환경변수 계약을 읽어 정리했다. 학교 MSP, AWS, Slack, Zabbix, Wazuh, Cloudflare 및 Grafana에 접속해 상태를 확인한 결과는 아니다. 사용자가 제공한 운영 현황은 별도로 표시했다.

> **실전 성공은 아직 검증되지 않았다.** 아래 절차는 학교에서 확인할 체크리스트이며, 한 번의 시나리오에서 모든 경로를 연속 실행하라는 뜻이 아니다. Slack 2인 승인과 기존 DR DB 데이터 검증은 유지한다.

## 1. 현재 MVP 기능 상태

`READY`는 코드/경로가 준비됐다는 뜻이지 실전 성공 증명이 아니다. 실전 검증 여부는 별도 열에 표시했다.

| 기능 | 상태 | 코드에서 확인된 경로·현재 조건 | 실전 검증 |
|---|---|---|---|
| ChatOps 일반 2인 승인 | READY | 기본 승인 수 2, 서로 다른 관리자 ID가 필요하다. 최신 4개 모듈이 Runtime에 반영됐다는 사용자 제공 현황을 반영했다. | NOT_TESTED |
| 일반 Failover | IMPLEMENTED | `infra/terraform/full_failover.sh` → `operations/failover/full_failover.sh` → `operations/finops/dr_environment_control.sh start`. 실제 On-Prem Writer Fence 확인은 실행 게이트에서 제거했다. | NOT_TESTED |
| 긴급 Failover | IMPLEMENTED | Emergency Console의 긴급 요청도 서로 다른 관리자 2명 승인 후 같은 Failover 경로를 사용한다. | NOT_TESTED |
| 일반 Dump Restore Failover | BLOCKED | Slack에서 Dump 선택·체크섬 확인·2인 승인까지 요청을 만들 수 있지만 `DUMP_RESTORE_EXEC_ENABLED=false`라 복원 실행은 차단된다. | NOT_TESTED |
| 긴급 Dump Restore Failover | BLOCKED | Emergency Console에서 선택·승인 UI를 사용하며 동일 복원 실행기에서 `EMERGENCY` 출처를 구별한다. Executor 게이트는 동일하게 비활성이다. | NOT_TESTED |
| Dump 후 앱 준비 / DNS 후속 단계 | BLOCKED | 후속 CLI와 요청별 receipt는 존재한다. 앱 단계에는 별도 opt-in이 필요하다. Finalizer에는 실제 On-Prem DB 쓰기 차단을 조회하는 운영 verifier가 없어 DNS 변경 전에 중단된다. `DR_ACTIVE`/쓰기 개방은 이 Finalizer의 성공 결과가 아니다. | NOT_TESTED |
| 일반·긴급 Failback | BLOCKED | 2인 승인 경로는 있으나 현재 Wazuh provider 및 필수 agent 설정 부재로 `UNKNOWN`/FAIL_CLOSED이며 승인·실행이 차단된다. 기존 DB 복귀 스크립트는 On-Prem `hospital_db`를 직접 덮어쓸 수 있다. | NOT_TESTED |
| On-Prem → AWS DR Position NR | BLOCKED | 사용자 제공 현황 `DB_NR_ENABLED=false`. Ansible `db_recovery` role의 조건부 경로이며 실전 source/replica 설정·좌표 검증은 수행하지 않았다. | NOT_TESTED |
| Zabbix Production Aggregate | BLOCKED | Canonical source contract는 Web AND EMR/Doc AND DB 장애 300초다. 독립 Monitoring Path 신호가 없어 reconciler는 `DR_Escalate=1`을 적용하지 않는다. | NOT_TESTED |
| 운영 Zabbix Trigger 24712 | BLOCKED | 마지막으로 제공된 API readback은 구형 OR Trigger `status=1`(비활성), Action 3 `status=0`(활성)이었다. 이번 Runbook 점검에서는 live API를 다시 조회하지 않았다. | NOT_TESTED |
| RTO 기록 코드 | READY | ChatOps timeline과 `dr_timing.sh`에 실제 이벤트·승인·실행·복구 시각을 연결하는 코드가 있다. 장애 감지 시각이 없으면 임의 시각을 넣지 않는다. 목표는 3600초. | NOT_TESTED |
| RPO 기록 코드 | READY | 데이터 복구 기준 시각 및 복제 증거가 없으면 `NOT_MEASURED`다. NR 비활성 상태에서는 `DB_NR_ENABLED_FALSE`로 측정하지 않는다. 목표는 900초. | NOT_TESTED |
| Grafana 운영 대시보드 | NOT_TESTED | 저장소에 대시보드 JSON은 있으나 운영 Grafana에 배포·연결됐는지는 학교에서 확인해야 한다. | NOT_TESTED |
| 요청별 Slack 실행 로그 | READY | `[실행 로그 확인]`은 요청 ID의 제한된 실행 로그 tail을 보여준다. 실제 실행 이력은 아직 확인되지 않았다. | NOT_TESTED |

기존에 검증한 Dump 데이터 기준 시각은 **2026-06-26**으로 기록돼 있다. 이는 Dump 파일 생성 시각과 다르며 10월 시연 데이터가 최신임을 뜻하지 않는다. 당일 선택 백업의 실제 데이터 기준 시각을 다시 확인하고, 환자 레코드는 출력·공유하지 않는다.

## 2. 학교에서 필요한 사전조건 및 환경변수

### 먼저 확인할 항목

1. 승인된 MSP 운영 호스트에서 ChatOps service가 active이고 Slack 상태 점검이 응답하는지 확인한다.
2. Slack에서 기존 `PENDING`/`PARTIALLY_APPROVED` 요청을 확인해 다른 장애 요청과 혼동되지 않게 하고, Emergency Console의 `상태 점검`에서 `Execution Lock=FREE`와 DR state를 확인한다. 다른 운영자가 workflow를 시작하지 않는 것도 조율한다. lock/state 확인이 안 되거나 이미 다른 workflow가 있으면 시작하지 않는다.
3. On-Prem Web/EMR/DB의 정상 상태와 Zabbix 수집 최신성을 확인한다. Canonical source는 Web AND EMR/Doc AND DB가 300초 지속되는 조건이다. 별도 독립 Monitoring Path 신호가 없어 Production escalation 적용은 차단된다. 마지막 제공된 운영 API readback에서 Trigger 24712는 구형 OR 조건으로 비활성화됐고 Action 3은 활성 상태였다. 이 Runbook 확인은 live API 재조회가 아니므로, 현장에서는 Trigger 상태를 읽기 전용으로 다시 확인한다. 이 후보 알림만으로 장애 판정을 확정하지 않는다.
4. On-Prem DB 연결은 NR(CDC) 확인에 필요하지만, 일반 Failover 실행의 필수 게이트는 아니다. Failover 실행 중 원본 쓰기 상태를 자동 차단하거나 확인하지 않는다.
5. AWS 계정·리전·기존 DR EC2 3대의 ID/상태와 SSH/SSM, Ansible inventory, 보안 그룹 및 TLS/Cloudflare 설정이 승인된 값인지 확인한다. DR 서비스의 실제 동작을 코드만으로 추정하지 않는다.

### On-Prem DB 주소·신원 및 학교 사용 시간

- 저장소의 현재 모니터링/Production 계약은 DB TCP probe를 **`IP_REDACTED:3306`**으로 둔다. 같은 정책 파일에서 Web은 `.3`, EMR/Doc은 `.5`다. Dump 보호 코드도 `.4`를 기존 On-Prem DB 대상으로 고정한다. 이는 코드가 기대하는 주소이지, 실제 On-Prem 호스트에 접속해 확인한 결과는 아니다.
- `operations/chatops/.env.example`의 `ONPREM_DB_HOST`와 `ONPREM_DB_SERVER_UUID_EXPECTED`는 비어 있고 `automation/ansible/inventory.example.ini`는 placeholder만 담는다. 실제 inventory/Secret이나 DB에 접근하지 않았으므로 실접속 주소, 서버 UUID, `@@server_id`는 **미확인**이다. `AWS_PUBLIC_IP_REDACTED:3306`은 폐기된 public/NAT-era 경로로 문서화되어 있고, `AWS_PUBLIC_IP_REDACTED:3306`은 기본 비활성인 별도 AWS DR WireGuard/NR 후보다. 두 값을 현재 On-Prem DB 접속 주소로 간주하지 않는다.
- 현장 DB 담당자는 승인된 On-Prem 콘솔 또는 기존 인증 경로에서 다음 읽기 전용 SQL을 실행해 결과와 조회 시각을 기록한다. 환자 데이터나 인증정보는 수집하지 않으며 비밀번호를 명령행 인자에 넣지 않는다.

  ```sql
  SELECT @@server_uuid, @@hostname, @@port, @@server_id,
         @@global.read_only, @@global.super_read_only;
  ```

- Failover 경로는 On-Prem Web/EMR/DB writer를 중지하거나 MySQL `read_only`/`super_read_only`를 확인하지 않는다. 원본 쓰기가 계속되는 상태에서 DR DB를 승격하면 양쪽 DB에 쓰기가 발생해 데이터가 갈라질 수 있다. 이는 현재 승인된 실행 경로의 알려진 위험이다.
- Dump Finalizer는 별도 복구 경로이며 자체 On-Prem 쓰기 보호 검사를 유지한다. 일반 Failover의 Writer Fence 제거가 Dump 경로의 보호 조건을 바꾸지는 않는다.
- 학교의 DB 사용 가능 날짜·시간은 저장소에 일정 정보가 없고 이번에 학교 시스템을 조회하지 않았으므로 **미확인 (`SCHEDULE_UNCONFIRMED`)**이다. 학교/On-Prem DB 담당자와 날짜, 시작·종료 시각 및 현장 참석자를 확정한다. 매일 **19:00 KST FinOps 자동 종료 정책**과 겹치지 않도록 종료 여유를 포함한 창을 별도로 합의한다. 가능한 시간을 추정하지 않는다.

### 확인해야 하는 설정 이름

비밀값은 출력하거나 이 문서에 복사하지 않는다. 외부 Secret은 systemd 기준 `/home/cloud/hospital-dr-secrets/dr.env`이며, ChatOps Runtime의 `WorkingDirectory`는 `/home/cloud/dr_project`, Python 코드는 현재 `/home/cloud/hospital-dr-codex`에서 직접 참조된다.

| 용도 | 설정 이름 |
|---|---|
| ChatOps / 관리자 | `SLACK_ADMIN_USER_IDS`, `DR_APPROVAL_REQUIRED=2`, `DR_SINGLE_APPROVAL_TEST_EXPIRES_AT`(미설정), `SLACK_CHANNEL_ID`, `SLACK_FAILOVER_BOT_TOKEN`, `SLACK_FAILBACK_BOT_TOKEN` 및 해당 Signing Secret |
| 긴급 Console | `SLACK_EMERGENCY_CHANNEL_ID`, `SLACK_EMERGENCY_BOT_TOKEN`, `SLACK_EMERGENCY_SIGNING_SECRET`, `EMERGENCY_TTL_SECONDS`(기본 900초) |
| 상태·로그 | `DR_STATE_DIR`, `DR_SECRET_FILE`, `CHATOPS_STATE_DB`, `CHATOPS_EXECUTION_LOCK_FILE`, `CHATOPS_EXECUTION_LOG_DIR`, `CHATOPS_AUDIT_FILE`, `DR_LOG_DIR`, `DR_RTO_TIMELINE_FILE` |
| AWS / SSH / Ansible | `AWS_REGION`, `SSH_KEY` 또는 `DR_SSH_PRIVATE_KEY`/`DR_SSH_KEY`, `DR_TERRAFORM_DIR`, `DR_ANSIBLE_DIR`, `DR_ANSIBLE_SOURCE_DIR`, `INVENTORY` |
| DNS / origin | `CF_ZONE_ID`, `CF_RECORD_ID`, `CF_EMR_RECORD_ID`, `CF_TOKEN_PARAM_NAME`, `DR_WEB_EIP_EXPECTED`, `ONPREM_TUNNEL_HOST`, `ONPREM_EMR_DNS_IP_EXPECTED`, `ONPREM_WEB_HEALTH_URL`, `ONPREM_DOC_HEALTH_URL` |
| Dump 선택·실행 | `DUMP_BACKUP_DIR`, 전역 `DUMP_RESTORE_EXEC_ENABLED=false`, `DUMP_RESTORE_EXECUTOR`(미설정). 요청별 덮어쓰기 허가는 Slack 요청의 SQLite 레코드에 백업 ID·전체 SHA-256·정확한 AWS DB 대상·범위를 저장하고, 서로 다른 관리자 2인의 최종 승인과 같은 트랜잭션에서 발급한다. 요청별 `dr.env` 수정이나 재시작은 사용하지 않는다. |
| Dump 후속 | `DEMO_DUMP_APPS_START_ENABLED`, `DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID`, `DEMO_DUMP_FINALIZE_ENABLED`, `DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID`, `DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID`, `DEMO_DUMP_FINALIZE_APPROVED_SHA256`, `ONPREM_DB_SERVER_UUID_EXPECTED` |
| Wazuh Failback gate | `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_CA_CERT`, `WAZUH_FAILBACK_REQUIRED_AGENTS` |
| NR | `DB_NR_ENABLED=false`, `DB_REPL_MODE`, `DB_SOURCE_HOST`, `DB_SOURCE_PORT`, `DB_SOURCE_LOG_FILE`, `DB_SOURCE_LOG_POS`, `DB_REPL_USER`, `DB_REPL_PASSWORD`, `DB_BACKUP_FILE` |

현재 운영 현황으로 제공된 값은 `DB_NR_ENABLED=false`, Dump executor 비활성, Wazuh provider/필수 agent 미설정이다. 시연 준비 중 이 값을 임의로 활성화하지 않는다. `dr.env` 전체를 `cat`, `env`, `systemctl show -p Environment`로 출력하지 않는다.

### 비파괴적 기본 확인 명령

승인된 MSP 터미널에서 실행한다. 아래 확인만으로 Failover가 허가되지는 않는다.

```bash
sudo -n systemctl is-active hospital-dr-chatops.service
sudo -n systemctl show hospital-dr-chatops.service -p MainPID -p WorkingDirectory -p ExecStart --no-pager
sudo -n cat /var/lib/hospital-dr/dr_state
```

현재 등록된 DR 인스턴스의 이름·상태만 확인할 때:

```bash
aws ec2 describe-instances --region "${AWS_REGION:-ap-northeast-2}" \
  --filters 'Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server' \
            'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,State:State.Name}' \
  --output table
```

`dr_environment_control.sh status`는 인프라 조회 외에도 로컬 state/lock 준비 코드를 실행하므로 위의 순수 조회 명령을 대신하는 것으로 취급하지 않는다.

## 3. 일반 Failover 실행 절차

Failover는 유효한 ChatOps 요청에 서로 다른 관리자 2명의 승인이 있고, 요청별 RPO 처리 및 기존 DR DB 데이터 확인이 통과할 때 기존 경로에서 실행된다. On-Prem writer 상태는 확인하거나 차단하지 않는다. 원본이 쓰기 가능한 상태일 수 있어 split-brain 위험이 남는다. 실제 성공은 실행 로그, DR 서비스 Health, DNS readback 및 `DR_ACTIVE`로 확인한다.

코드상 실행 절차:

1. Zabbix의 검증된 Production Action 또는 운영자가 의도적으로 생성한 일반 요청으로 Slack 승인 후보를 확인한다. 일반 요청을 수동 생성하는 기존 helper는 다음과 같다. 아래 명령은 **실제 요청을 생성**하므로 사전 점검 때 실행하지 않는다.

   ```bash
   : "${INCIDENT_ID:?실제 Zabbix event ID를 지정}" "${INCIDENT_SUMMARY:?요청 요약을 지정}"
   bash /home/cloud/hospital-dr-codex/operations/chatops/send_slack.sh "$INCIDENT_ID" "$INCIDENT_SUMMARY"
   ```

2. Slack에서 서로 다른 관리자 2명이 같은 요청 ID를 확인하고 승인한다. 승인 전 AWS 시작 명령을 직접 호출하지 않는다.
3. 승인 후 ChatOps가 `/home/cloud/hospital-dr-codex/infra/terraform/full_failover.sh` wrapper를 실행한다. 이는 `operations/failover/full_failover.sh`로 위임한다.
4. `dr_environment_control.sh`에는 기존 AWS DR DB 신원 확인과 승격 함수가 있다. Ansible role `automation/ansible/roles/db_recovery/files/db_promote_dr.sh`가 배포한 `/home/ubuntu/scripts/db_promote_dr.sh`를 원격 호출하고, MySQL 재시작 전후에 같은 DB 신원, 기존 데이터, `read_only`/`super_read_only` 상태를 확인한다. 이 DB 보호 검사가 통과하면 On-Prem 상태 조회 없이 기존 DR DB를 승격한다.
5. 모든 검증 및 On-Prem 단일 쓰기 증거가 성공한 경우에만 state가 `DR_ACTIVE`여야 한다. 오류·결과 불명은 `FAILED` 또는 `PARTIAL_FAILURE`로 확인하고 성공으로 해석하지 않는다.

현재 독립 Monitoring Path/Sentinel 신호가 없어 서비스 3중 장애와 공통 monitoring path 정상 여부를 독립적으로 증명할 수 없다. Canonical source의 AND/300초 정책과 무관하게 Production escalation 적용은 차단 상태다. 마지막 제공된 운영 상태에서 Trigger 24712도 비활성이다. Zabbix에서 Service Health 값이 실패했다는 사실만으로 자동 Failover를 승인하지 않는다.

## 4. 긴급 Failover 실행 절차

1. Slack의 별도 비공개 `긴급승인` 채널에서 ChatOps Emergency Console의 `상태 점검`으로 DR state, 실행 lock, AWS/On-Prem/Zabbix/Wazuh 상태를 확인한다. `UNKNOWN`은 정상으로 간주하지 않는다.
2. `긴급 Failover 요청`을 누르고 실제 긴급 사유를 입력한다. 요청은 기본 15분 TTL이며 승인 2인을 생략하지 않는다.
3. 서로 다른 관리자 2명이 같은 긴급 요청을 승인한다.
4. 긴급 요청도 기존 `full_failover.sh` 공통 실행 흐름을 사용한다. 일반 요청과 마찬가지로 서로 다른 관리자 2인의 승인, 요청별 RPO 처리, 기존 DR DB 데이터 검증은 유지된다. On-Prem writer 상태 검사는 실행 게이트에 없다.

일반 Failover와 긴급 Failover는 별개 요청 경로지만 동일한 `infra/terraform/full_failover.sh` wrapper와 일반 실행기를 사용한다. On-Prem이 계속 쓰기 가능한 상태면 DR 승격 후 split-brain이 발생할 수 있다. 실제 실행 성공은 아직 검증되지 않았다.

## 5. Dump Restore 실행 절차

### 현재 상태

`DUMP_RESTORE_EXEC_ENABLED=false`이며 executor 미설정이면 Slack에서 백업 선택 및 두 관리자 승인까지 만들어져도 실제 복원은 차단된다. 이 전역 스위치와 요청별 덮어쓰기 허가는 별개다. 요청별 허가는 보호된 ChatOps SQLite 승인 레코드에서만 검증하고, `dr.env` 요청 ID 바인딩은 사용하지 않는다. 기존 AWS DR DB 복원에는 현장 승인, 복구 전 백업·대상 신원·Web/EMR 격리·Read-only 조건이 별도로 필요하다.

### 게이트가 별도 승인되어 열린 경우의 코드상 순서

1. 일반 Failover Slack 메시지의 Dump 선택 버튼 또는 Emergency Console의 `긴급 Failover (Dump)`에서 백업을 고른다. 선택 후 확인 화면에서 Backup ID, SHA-256, `.master_status` 쌍을 대조한 뒤에만 요청을 확정한다.
2. 요청 ID, Backup ID, SHA-256 및 `GENERAL`/`EMERGENCY` 출처를 확인하고, 서로 다른 관리자 2명이 승인한다. 요청별 기존 DB 덮어쓰기 허용이 맞지 않으면 진행하지 않는다.
3. ChatOps가 다음 runner와 세 인자를 호출한다. 이는 **ChatOps 승인·요청별 gate 하에서만 실행되는 계약**이다. 아래 명령을 운영자가 직접 실행해 승인 경로를 대체하지 않는다.

   ```bash
   /home/cloud/hospital-dr-codex/operations/db/demo_dump_restore_existing_dr.sh \
     --request-id "$REQUEST_ID" \
     --backup-id "$BACKUP_ID" \
     --expected-sha256 "$EXPECTED_SHA256"
   ```

4. 복원 결과 `DB_RESTORED_NOT_FAILOVER_COMPLETE`는 DB 복원 완료만 뜻한다. 전체 Failover 성공, 앱 공개, DNS 변경 또는 `DR_ACTIVE`를 뜻하지 않는다. request-scoped receipt는 기본 `/var/lib/hospital-dr/demo-dump-restores/<REQUEST_ID>/result.json`에 저장된다.
5. 앱 후속 CLI 계약은 다음과 같다. 별도 앱 gate와 같은 요청 receipt가 필요한 독립 단계이며, DB 복원을 다시 하지 않는다. 현재 승인된 운용 경로로 판정되기 전에는 실행하지 않는다.

   ```bash
   bash /home/cloud/hospital-dr-codex/operations/db/demo_dump_restore_existing_dr_apps.sh \
     --request-id "$REQUEST_ID" \
     --backup-id "$BACKUP_ID" \
     --expected-sha256 "$EXPECTED_SHA256"
   ```

   성공 상태는 `APPS_READY_NOT_DNS_SWITCHED`이며 receipt는 같은 요청 디렉터리의 `apps_result.json`이다. 이 상태도 DNS 전환/전체 복구 완료가 아니다.

6. DNS Finalizer의 확인된 CLI는 다음 형식이다. 하지만 현재 production adapter에 `verify_onprem_write_fence` live DB 조회 기능이 없고, 실제 On-Prem DB 신원 계약도 현장 확인이 필요하므로 **현재는 실행 금지**다. 수동 확인, 환경변수 Boolean, receipt만으로 이 게이트를 통과했다고 표시하지 않는다.

   ```bash
   bash /home/cloud/hospital-dr-codex/operations/db/demo_dump_finalize_existing_dr.sh \
     --request-id "$REQUEST_ID" \
     --backup-id "$BACKUP_ID" \
     --expected-sha256 "$EXPECTED_SHA256" \
     --confirm-finalize
   ```

   현 코드에서 On-Prem verifier가 없으면 DNS 변경 전에 실패한다. 향후 verifier가 추가되더라도 Finalizer는 maintenance/write fence를 유지하며 `DR_ACTIVE`를 기록하지 않는 별도 단계다. Finalizer 결과를 성공으로 바꾸어 해석하지 않는다. 최신 검증 데이터 기준이 6월 26일인 기존 Dump를 사용할 경우 오래된 진료 데이터가 표시될 수 있다.

### 실패 구분

- DB 복원 실패: 앱/DNS/DR state가 성공으로 바뀌지 않았는지 확인한다. 자동 재복원이나 임의 DB rollback을 하지 않는다.
- 앱 단계 실패: `PARTIAL_FAILURE` 또는 receipt 상태를 확인하고 DNS를 건드리지 않는다.
- DNS 이후 결과 불명/쓰기 위험: 자동 DNS·DB rollback을 하지 말고 운영자 개입으로 중지한다.

일반 Dump와 긴급 Dump는 다른 출처의 요청·승인 증거를 사용하지만 복원 코드와 안전 gate를 공유한다. 긴급 승인이라고 해서 복원, checksum, 기존 DB 보존 또는 fence 조건을 줄이지 않는다.

## 6. NR 검증 절차

현재 `DB_NR_ENABLED=false`이므로 replication은 Failover의 데이터 공급 경로가 아니다. 실제 복제 설정은 실행하지 않는다. `operations/db/db_nr_source_setup.sh`는 source MySQL 설정을 쓰고 서비스를 재시작하며 replication 계정을 생성·권한 부여하므로 시연 사전 점검 명령으로 실행하면 안 된다.

학교 현장에서 NR 검증을 별도로 승인한 경우, 기존 DB 접속 도구로 **읽기 전용 조회만** 수행한다.

```sql
SELECT @@server_uuid, @@hostname, @@port;
SHOW MASTER STATUS;
SHOW REPLICA STATUS\G
```

MySQL 버전에서 `SHOW MASTER STATUS`가 지원되지 않으면 `SHOW BINARY LOG STATUS`를 사용한다. Replica 조회는 구형 버전에서 `SHOW SLAVE STATUS\G`를 사용할 수 있다. 대상 replica의 `Source_Log_File`, `Read_Source_Log_Pos`, `Exec_Source_Log_Pos`, `Seconds_Behind_Source`, `Last_IO_Error`, `Last_SQL_Error`, `Replica_IO_Running`, `Replica_SQL_Running`을 확인한다. source log/position은 선택해 실제 복원한 Dump의 정확히 대응하는 `.master_status`와 일치해야 한다. 상태 row가 없거나 오류/지연 값이 unknown이면 NR 정상으로 표시하지 않는다.

`DB_NR_ENABLED=true` 전환, source setup, `STOP/RESET/CHANGE REPLICATION`은 이번 Runbook 범위가 아니다. RPO 0 또는 15분 달성은 실제 좌표·데이터 시각·lag 근거 없이는 주장하지 않는다.

## 7. Failback 실행 가능 조건

**현재 Failback은 BLOCKED이며 실행하지 않는다.** 일반 helper는 요청을 만들 수 있지만 ChatOps 승인 callback은 Network 및 Wazuh security status를 다시 확인한다. Wazuh live provider/필수 agent 설정이 없으면 `UNKNOWN`으로 fail-closed되며, 두 승인만으로 실행되지 않는다.

ChatOps의 일반 Failback 요청 후 실행 경로는 `infra/terraform/web_db_failback.sh` → `operations/db/web_db_failback.sh` → `operations/failover/full_failback.sh`다. 긴급 Failback도 같은 실행 계약으로 들어간다. 코드상 일반 요청 생성 helper(실제 요청을 생성하므로 준비 점검 때 호출하지 않는다):

```bash
: "${RECOVERY_EVENT_ID:?실제 복구 event ID를 지정}" "${SUMMARY:?요청 요약을 지정}"
bash /home/cloud/hospital-dr-codex/operations/chatops/send_failback.sh "$RECOVERY_EVENT_ID" "$SUMMARY"
```

긴급 Failback은 Emergency Console의 별도 요청 버튼을 사용하지만 같은 2인 승인 및 Failback 보안 게이트가 적용된다. `operations/db/web_db_failback.sh`는 DB와 Doc failback을 모두 켜고, 기존 DB 복귀는 On-Prem `hospital_db`에 직접 적용될 수 있다. `DB_FAILBACK_CONFIRM=OVERWRITE_ONPREM_DB` 같은 확인값을 설정해도 데이터 보존 검증을 대신하지 않는다. 기존 On-Prem 운영 DB를 덮어쓰기 전에 안전한 staged restore·데이터 비교 절차가 마련되고 별도 승인을 받기 전까지 두 경로 모두 실행 금지다.

## 8. RTO/RPO 및 Grafana 확인

목표는 RTO **3600초(1시간)**, RPO **900초(15분)**다. RTO timeline 파일 기본 경로는 `/var/lib/hospital-dr/rto_timeline.json`이다. timeline은 실제 `incident_at`/감지, 요청 생성, 2인 승인, 실행 시작, 검증된 `service_recovered_at`을 사용한다. 이벤트 시각 또는 검증된 서비스 복구가 빠지면 수치를 만들지 않는다. `DB_RESTORED_NOT_FAILOVER_COMPLETE`, `APPS_READY_NOT_DNS_SWITCHED`, `PARTIAL_FAILURE`는 RTO 종료 시각이 아니다.

실제 시연이 끝나고 승인된 운영 호스트에서 evidence bundle을 생성할 때의 기존 명령 계약:

```bash
: "${RUN_ID:?시연 식별자를 지정}" "${ZABBIX_EVENT_ID:?실제 Zabbix problem event ID를 지정}"
python3 /home/cloud/hospital-dr-codex/operations/preflight/rto_rpo_evidence_collector.py \
  --run-id "$RUN_ID" \
  --incident-id "$ZABBIX_EVENT_ID" \
  --timeline /var/lib/hospital-dr/rto_timeline.json \
  --state-db /var/lib/hospital-dr/chatops_state.sqlite3 \
  --audit /var/lib/hospital-dr/audit/chatops_audit.jsonl \
  --timing-log /var/lib/hospital-dr/dr_timing.jsonl \
  --db-nr-enabled false \
  --output-root /var/lib/hospital-dr/evidence
```

이 명령은 증거 bundle을 저장하므로 실제 시연 후에만 실행한다. 현재 NR false이므로 RPO는 `NOT_MEASURED`여야 한다. Dump 생성 timestamp만으로 RPO를 계산하지 않는다.

저장소 내 dashboard 정의:

- `monitoring/grafana/provisioning/dashboards/json/hospital-dr-automation.json` — `Hospital DR Automation`
- `monitoring/grafana/provisioning/dashboards/json/hospital-dr-rto.json` — `Hospital DR RTO / RPO Readiness`
- 정의 파일의 Zabbix datasource UID: `PA67C5EADE9207728`

학교 Grafana UI에서 dashboard·datasource·`Hospital_DR_Automation` 호스트의 `DR total RTO seconds` item을 실제 확인한다. 저장소 JSON 존재만으로 운영 Grafana 반영이나 데이터 수신을 인정하지 않는다. 측정값이 없으면 `NO COMPLETED DR RUN`/`NOT_MEASURED`로 남긴다.

## 9. 실패 시 로그 확인

1. Slack 요청 메시지의 `[실행 로그 확인]`을 우선 사용한다. 요청별 로그 기본 경로는 `/var/lib/hospital-dr/execution-logs/<REQUEST_ID>.log`다.
2. 학교 운영자가 로컬에서 확인해야 할 때만, UUID 형식의 실제 요청 ID를 확인하고 bounded tail을 읽는다.

   ```bash
   REQUEST_ID='<승인 메시지에 표시된 요청 UUID>'
   [[ "$REQUEST_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo 'invalid request id' >&2; exit 2; }
   sudo -n tail -n 80 -- "/var/lib/hospital-dr/execution-logs/${REQUEST_ID}.log"
   ```

   로그를 Slack 외부나 PPT에 붙이기 전 개인정보·인증정보가 없는지 검토하고 민감한 줄을 공유하지 않는다.
3. 공통 workflow 로그 기본 위치는 `DR_LOG_DIR=/home/cloud/hospital-dr-terraform`이며 코드 기본 이름은 `full_failover.log`, `dr_environment.log`, `full_failback.log`다. 파일이 없거나 읽을 수 없으면 성공/실패를 추측하지 않는다.
4. Dump request receipt 기본 위치는 `/var/lib/hospital-dr/demo-dump-restores/<REQUEST_ID>/result.json`, 앱 결과는 `apps_result.json`이다. Finalizer는 같은 요청 디렉터리에 `finalize_result.json`을 기록한다. request ID·Backup ID·SHA-256·출처가 서로 일치해야 한다.
5. 서비스 상태/시작 오류는 다음처럼 확인한다. `journalctl` 내용을 외부에 공유하기 전 민감정보를 검토한다.

   ```bash
   sudo -n systemctl is-active hospital-dr-chatops.service
   sudo -n journalctl -u hospital-dr-chatops.service --since '30 minutes ago' --priority=err --no-pager
   ```

실패가 `PARTIAL_FAILURE`이거나 AWS·DB·DNS 상태가 불명확하면 재실행/수동 rollback 대신 현장 담당자와 운영자에게 에스컬레이션한다.

## 10. 시연 종료 후 정리

1. Slack 최종 상태, `dr_state`, Cloudflare Web/EMR 양쪽 readback, Web/EMR Health, 실제 DB writer를 각각 확인한다. DB 복원 완료 상태만으로 DNS를 돌리거나 DR EC2를 멈추지 않는다.
2. On-Prem으로의 실제 데이터 복귀와 서비스 Health가 확인되지 않았다면 DR을 계속 유지하고, 기존 운영 On-Prem DB를 덮어쓰거나 DR EC2를 중지하지 않는다.
3. Failback은 현재 Wazuh gate 및 On-Prem overwrite 위험으로 BLOCKED다. 따라서 일반적인 “시연 종료”만으로 Failback/stop 명령을 실행하지 않는다.
4. 19:00 KST FinOps 자동 종료 정책은 유지한다. 시연은 이 정책과 충돌하지 않게 계획하고, 운영자가 별도 정책을 끄거나 Lambda/EventBridge를 변경하지 않는다. 종료 시각 전에 현재 DNS·DB writer·DR state를 담당자와 확인한다.
5. 실전 검증이 별도 승인·검증으로 완료된 뒤에만 기존 Failback 절차에 따라 트래픽 원복 및 비용 정리를 수행한다. `dr_environment_control.sh stop` 단독 실행은 데이터 복귀가 아니므로 사용하지 않는다.

## 실전 GO로 바뀌기 위한 핵심 차단 조건 (최대 3개)

1. **단일 writer와 Failover 판정:** live On-Prem DB verifier가 없어 승격/DNS gate는 닫혀 있다. Canonical Zabbix source policy는 Web AND EMR/Doc AND DB 300초지만 독립 Monitoring Path 신호가 없어 Production escalation 적용은 차단된다. 마지막 제공된 운영 readback의 Trigger 24712는 구형 OR 조건으로 비활성이고, 이 문서 갱신 시점의 live 상태는 재조회하지 않았다. DB 대상·신원·현장 일정도 담당자 확인 전까지 확정하지 않는다.
2. **Dump 전체 흐름:** Dump Executor는 꺼져 있다. 복원·앱 준비·DNS 후속은 별도 승인/gate/receipt 단계이고 Finalizer도 On-Prem verifier 부재로 중단된다. DB 복원이나 앱 준비만으로 전체 Failover 성공이 아니다.
3. **Failback 및 계측:** Wazuh provider/필수 agent 설정 부재로 Failback은 fail-closed이며, 기존 경로는 On-Prem 운영 DB를 덮어쓸 수 있다. NR은 꺼져 있어 RPO는 `NOT_MEASURED`; 운영 Grafana 연결과 실제 측정값도 학교에서 확인해야 한다.
