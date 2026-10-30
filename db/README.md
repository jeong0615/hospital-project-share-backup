# DB Server

이 디렉터리는 Hospital DR 프로젝트의 DB Server 재구성에 필요한 설명과 암호화된 데이터베이스 백업 파일을 보관한다.

평문 Database Dump는 Repository에서 제거했다. 실제 운영 데이터는 복호화 Key/Password와 함께 별도의 안전한 저장소에서 관리해야 하며, 이 Repository에는 승인된 암호화 백업만 보관한다.

운영 복구에는 별도의 Secret 관리와 DB 접근 권한 확인이 필요하다.

<br>

## 구조

```text
db/
├── .gitignore
├── README.md
├── backups/
│   ├── db_backup_20261029_100000.sql.gz.enc
│   └── db_backup_20261029_100000.master_status
├── configs/
│   └── etc/mysql/
├── inventory/
│   ├── server-summary.txt
│   ├── mysql-variables.txt
│   ├── mysql-accounts.txt
│   ├── mysql-tables.txt
│   ├── packages.txt
│   ├── enabled-services.txt
│   ├── backup-sources.txt
│   ├── cron-db-backup.txt
│   └── config-sources.txt
├── scripts/
│   └── db_backup.sh
└── systemd/
    ├── hospital-db-backup.service
    └── hospital-db-backup.timer
```

`backups/`에는 2026-10-29 10:00:00 시점의 최신 완성 암호화 Dump와 동일 시점의 Binary Log 위치 정보가 저장되어 있다. 복호화 Key/Password는 Repository에 포함하지 않는다. 원격 DB에서 확인된 `nr-fresh/` 및 failback용 평문 압축 Dump는 보안상 업로드하지 않았다.

`scripts/db_backup.sh`는 외부 Secret 환경변수를 사용하도록 정리한 Repository용 백업 템플릿이며, `systemd/`에는 해당 흐름을 호출하는 service/timer 정의가 있다. 원격 서버의 운영 스크립트는 확인했지만 inline 암호화 Credential이 포함되어 있어 그대로 복사하지 않았다. MySQL 설정 파일, 암호화 키와 운영 Credential은 이 디렉터리에 포함하지 않는다.

원격 운영 스크립트에서 inline 암호화 Credential 사용이 확인되었으므로 운영 Key는 별도 Secret 저장소의 새 값으로 교체하고, 기존 값은 폐기·교체하는 것을 권장한다.

`configs/etc/mysql/`에는 `/etc/mysql`의 비밀이 아닌 설정을 원래 경로 기준으로 보관한다. `/etc/mysql/debian.cnf`와 TLS/private key는 제외했다.

`inventory/`에는 복구에 필요한 OS·MySQL 변수·계정 목록(인증값 제외)·테이블·패키지·서비스·백업 경로 정보를 보관한다. 계정 비밀번호와 실제 Secret은 포함하지 않는다.

복구 시에는 암호화 Dump를 별도 보관한 Key/Password로 복호화한 뒤 형식과 대상 MySQL Version을 확인한다.

<br>

## DB 구성

Hospital DR 프로젝트의 Database는 MySQL을 사용하며 주요 Database는 다음과 같다.

```text
Database: hospital_db
DBMS: MySQL
Replication Mode: Binary Log Position 방식
```

현재 환경에서는 GTID를 사용하지 않고 Binary Log의 `File`과 `Position`을 기준으로 Replication을 구성한다.

주요 설정 항목은 다음과 같다.

```ini
server_id=1
log_bin=ON
binlog_format=ROW
gtid_mode=OFF
```

실제 설정값은 서버 역할에 따라 달라질 수 있으므로 복구 시 원본 설정과 현재 DR 구조를 함께 확인한다.

<br>

## Replication

DB DR 구성에서는 MySQL Binary Log 기반 Replication을 사용한다.

GTID가 아닌 Position 방식을 사용하므로 초기 동기화 시 Database Dump 시점과 Master Status의 File/Position이 일치해야 한다.

확인 예시:

```sql
SHOW MASTER STATUS;
```

```text
File: mysql-bin.xxxxxx
Position: xxxxx
```

Replication 계정에는 필요한 최소 권한을 부여한다.

예시 확인:

```sql
SHOW GRANTS FOR 'repl'@'%';
```

주요 권한:

```text
REPLICATION SLAVE
REPLICATION CLIENT
```

Replication 구성 전 DB Server 간 `3306/tcp` 통신이 가능한지 확인한다.

```bash
nc -vz <DB_SOURCE_HOST> 3306
```

<br>

## DB 백업

Database 백업은 `mysqldump`를 기반으로 수행한다.

백업 시 다음 항목을 포함한다.

```text
--single-transaction
--master-data=2
--routines
--triggers
```

기본 처리 흐름은 다음과 같다.

```text
MySQL Dump
→ gzip 압축
→ OpenSSL 암호화
→ 백업 서버 또는 지정 위치 전송
→ Master Status 저장
→ 백업 검증
```

Dump 파일과 Master Status 파일은 동일한 Timestamp를 사용하여 서로 대응할 수 있도록 관리한다.

예시:

```text
hospital_db_YYYYMMDD_HHMMSS.sql.gz.enc
hospital_db_YYYYMMDD_HHMMSS.master_status
```

현재 업로드한 `scripts/db_backup.sh`는 `DB_BACKUP_ENCRYPTION_KEY`를 외부 Secret 환경변수로 주입받아 다음 흐름을 사용한다.

```text
mysqldump
→ gzip 압축
→ OpenSSL 암호화
→ SCP 전송
→ Master Status 저장
```

스크립트는 운영본만 보관했으며 `before-*` 과거 사본은 제외했다. 실행 전 대상 경로, 외부 Credential 주입 방식, 암호화 Key/Password, 원격 전송 대상과 보존 정책을 반드시 검토한다. 이 Repository 백업 단계에서는 systemd service/timer를 enable/start하지 않는다.

현재 서버의 사용자 cron에는 존재하지 않는 `/home/hoseo/db_backup.sh`를 호출하는 오래된 항목이 확인되었다. 실제 활성 자동화는 `hospital-db-backup.timer`와 `/home/hoseo/scripts/db_backup.sh` 조합이므로 stale cron은 복원하지 않는다.

<br>

## DB 복구

DB 복구 시 다음 순서를 기준으로 한다.

1. 새 Ubuntu Server에 MySQL을 설치한다.
2. MySQL Version 및 주요 설정값을 확인한다.
3. `configs/etc/mysql/`의 비밀이 아닌 설정을 검토하여 `/etc/mysql/`에 반영한다.
4. `hospital_db` 및 필요한 DB 계정을 준비하고 비밀번호는 별도 Secret 저장소에서 주입한다.
5. 암호화된 Dump를 안전한 위치에서 가져온다.
6. 별도 보관한 Key/Password로 Dump를 복호화하고 압축을 해제한다.
7. Database를 Import한다.
8. Dump와 동일 시점의 Master Status를 확인한다.
9. `systemd/` unit/timer를 검토하고 필요한 경우에만 `daemon-reload`, enable/start를 수행한다.
10. Replication Source 정보를 설정한다.
11. Replication을 시작한다.
12. 상태와 데이터 일관성을 검증한다.

복구 자동화가 존재하는 경우에도 실제 Database Import 및 Replication 시작 전에 대상 서버와 Source 정보를 확인한다.

암호화 백업 복구 시에는 다음 조건을 모두 확인한다.

1. `backups/`의 `.sql.gz.enc`와 동일 Timestamp의 `.master_status`를 함께 준비한다.
2. 암호화 Key/Password를 GitHub가 아닌 별도 Secret 저장소에서 준비한다.
3. 복호화와 압축 해제는 접근 통제된 복구 서버에서 수행한다.
4. 복호화된 Dump를 Repository에 다시 업로드하지 않는다.

<br>

## Replication 검증

Replication 구성 후 다음 상태를 확인한다.

```sql
SHOW SLAVE STATUS\G
```

또는 MySQL Version에 맞는 Replica 상태 확인 명령어를 사용한다.

주요 확인 항목:

```text
Replica IO Thread
Replica SQL Thread
Source Host
Binary Log File
Position
Replication Error
Replication Delay
```

Replication 구성 후 테스트 데이터를 입력하여 Source DB의 변경사항이 DR DB에 정상 반영되는지 확인한다.

<br>

## 백업 검증

백업 파일이 생성된 것만으로 정상 백업으로 판단하지 않는다.

다음 항목을 확인한다.

- Dump 파일 생성 여부
- 암호화 파일 생성 여부
- Master Status 생성 여부
- Dump와 Master Status Timestamp 일치 여부
- 파일 크기 확인
- 복호화 가능 여부
- Dump Import 가능 여부
- 주요 Table 존재 여부
- 주요 Row 확인
- Replication 재구성 가능 여부

<br>

## S3 2차 백업

DB Backup은 필요한 경우 AWS S3에 2차 보관할 수 있다.

S3 사용 시 다음 항목을 확인한다.

- Public Access 차단
- Server Side Encryption
- Versioning
- Lifecycle Policy
- Upload 성공 여부
- 오래된 Backup 정리 정책

AWS Credential 및 Bucket 접근 권한은 Repository에 저장하지 않고 별도의 Credential 관리 방식을 사용한다.

<br>

## Git 제외 및 별도 관리 항목

다음 파일과 정보는 원칙적으로 Repository에 직접 저장하지 않는다.

```text
*.sql
*.dump
*.enc
*.gz
*.tar
*.zip
*.pem
*.key
.env
.env.*
db_backups/
backup/
backups/
```

현재 `db/backups/db_backup_20261008_134830.sql.gz.enc`와 대응하는 `.master_status`는 승인된 암호화 백업 예외 항목이다. 복호화 Key/Password 없이는 내용을 복원할 수 없도록 관리하며, 다른 `.enc`, `.part`, raw MySQL data directory, MySQL private key는 업로드 대상이 아니다.

다음 정보 역시 GitHub 외부에서 별도로 관리한다.

- MySQL root password
- Application DB password
- Replication password
- AWS Credential
- 복호화된 실제 Database Dump
- 암호화 Key / Password
- SSH Private Key
- 운영 환경변수

Example 또는 Template 파일만 Repository에 포함한다.

<br>

## 안전 원칙

- 운영 Database를 백업하기 위해 임의로 삭제하거나 초기화하지 않는다.
- `DROP DATABASE`, `DROP TABLE`, `RESET MASTER` 등 데이터 손실 가능 명령어는 백업 과정에서 실행하지 않는다.
- Replication 재구성 전 Source와 Replica 역할을 확인한다.
- Dump와 Master Status가 동일 시점인지 확인한다.
- 복호화된 실제 Dump와 Credential은 GitHub에 업로드하지 않는다.
- 복구 작업 전 대상 Database와 기존 데이터를 반드시 확인한다.
