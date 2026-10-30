# MSP Server

이 디렉터리는 GitHub Repository를 clone하여 Hospital DR 운영 환경을 재구성할 수 있도록, 코드·배포 정의·선별한 시스템 설정을 `/` 기준의 `rootfs/` 형태로 보관한다. 이 백업은 운영 파일을 이동하거나 서비스 상태를 변경하지 않으며, commit/push도 자동 수행하지 않는다.

<br>

## 구조

```text
msp/
├── rootfs/
│   ├── home/
│   │   └── cloud/
│   │       ├── dr_project/
│   │       │   ├── app.py
│   │       │   ├── wsgi.py
│   │       │   └── ...
│   │       ├── grafana/
│   │       ├── hospital-dr-ansible/
│   │       ├── hospital-dr-codex/
│   │       │   ├── .gitignore
│   │       │   ├── .gitleaks.toml
│   │       │   ├── automation/
│   │       │   ├── docs/
│   │       │   │   ├── architecture/
│   │       │   │   └── runbooks/
│   │       │   ├── infra/
│   │       │   │   └── terraform/
│   │       │   ├── monitoring/
│   │       │   ├── operations/
│   │       │   ├── .github/workflows/
│   │       │   │   ├── artifact-retention-cleanup.yml
│   │       │   │   ├── docker-security-scan.yml
│   │       │   │   └── ...
│   │       ├── hospital-dr-repo/
│   │       ├── hospital-dr-terraform/
│   │       │   ├── iam_least_privilege_candidates.tf
│   │       │   ├── main.tf
│   │       │   └── ...
│   │       ├── scripts/
│   │       ├── wazuh-docker/
│   │       └── zabbix/
│   └── etc/
│       └── systemd/system/
├── inventory/
│   ├── packages.txt
│   ├── manual-packages.txt
│   ├── enabled-services.txt
│   ├── docker-containers.txt
│   ├── docker-images.txt
│   ├── docker-networks.txt
│   ├── docker-volumes.txt
│   ├── listening-sockets.txt
│   ├── running-services.txt
│   └── system-info.txt
├── backup.sh
├── restore.sh
├── .gitignore
└── README.md
```

`hospital-dr-repo`는 현재 작업 트리의 미커밋 변경사항을 포함할 수 있는 canonical source로 복사한다. 각 원본의 `.git/`은 복사하지 않는다.

<br>
`hospital-dr-codex`는 실행 중인 systemd unit이 참조하는 `automation/`, `infra/`, `operations/`와 `docs/`, `monitoring/`, `.github/workflows/`를 별도 보관한다. CI 보안 workflow가 참조하는 `.gitignore`와 `.gitleaks.toml`도 보관한다. `services/`는 EMR/Web 백업 영역과 중복되므로 복사하지 않는다.

<br>

Top-level `db/`, `emr/`, `web/`은 각각 DB·EMR·Web Server 백업 영역이다. 이 디렉터리의 `rootfs/`는 MSP Ubuntu의 `/` 구조와 MSP 운영 재구성 파일을 보관하며, 형제 백업 영역을 자동으로 대체하거나 중복 보관하지 않는다.

<br>

## 포함한 MSP 원본 경로

- `/home/cloud/hospital-dr-repo`
- `/home/cloud/hospital-dr-codex/automation`
- `/home/cloud/hospital-dr-codex/docs`
- `/home/cloud/hospital-dr-codex/infra`
- `/home/cloud/hospital-dr-codex/monitoring`
- `/home/cloud/hospital-dr-codex/operations`
- `/home/cloud/hospital-dr-codex/.github/workflows`
- `/home/cloud/hospital-dr-ansible`의 orchestration 및 비밀이 아닌 deployment payload
- `/home/cloud/hospital-dr-terraform`의 Terraform source, 정책, Lambda, systemd template
- `/home/cloud/grafana`의 compose/provisioning
- `/home/cloud/zabbix/docker-compose.yml`
- `/home/cloud/wazuh-docker`의 배포 source/configuration
- `/home/cloud/dr_project`의 source code
- `/home/cloud/scripts`의 최신 운영 script

`/etc`에서는 다음 MSP 전용 systemd unit만 포함한다.

- `hospital-dr-chatops-ngrok.service`
- `hospital-dr-chatops.service`
- `hospital-dr-environment.service`
- `hospital-dr-nat-disable.service` 및 `.timer`
- `hospital-dr-nat-enable.service` 및 `.timer`
- `hospital-dr-nat-shutdown.service`
- `hospital-dr-s3-upload.service` 및 `.timer`
- `hospital-dr-zabbix-proxy.service`

현재 호스트에서 MSP 전용 Nginx/Apache/WireGuard/cron 파일은 별도로 발견되지 않아 `/etc` 전체나 기본 OS unit은 복사하지 않았다.

<br>

## 백업 실행

현재 MSP 원본 서버에서 다음을 실행한다.

```bash
cd /path/to/hospital-project-backup/msp
./backup.sh
git status --short
git diff --stat
```

`backup.sh`는 선택한 `/home/cloud` 원본을 `rootfs/home/cloud/`로 동기화하고, 선별한 `/etc/systemd/system` 파일을 `rootfs/etc/systemd/system/`으로 복사한다. 다음 inventory도 갱신한다.

- `packages.txt`
- `manual-packages.txt`
- `enabled-services.txt`
- `docker-containers.txt`
- `docker-images.txt`
- `docker-networks.txt`
- `docker-volumes.txt`
- `running-services.txt`
- `listening-sockets.txt` (프로세스 상세정보 없이 listen endpoint만 기록)
- `system-info.txt`

스크립트는 `git add`, `git commit`, `git push`를 실행하지 않는다. secret 검사에서 경고가 나오면 해당 경로를 먼저 제거·교체하고 `git status`와 `git diff`를 다시 검토한다.

<br>

## 복원 실행

새 MSP Ubuntu에서 먼저 Git, rsync 및 필요한 OS/Docker 도구를 준비하고 Repository를 clone한다. 실제 덮어쓰기 전에 반드시 dry-run을 확인한다.

```bash
cd /path/to/hospital-project-backup/msp
./restore.sh --dry-run
./restore.sh --dry-run-home
./restore.sh --dry-run-etc
```

검토가 끝난 뒤에만 명시적 restore 옵션을 사용한다. home 복원은 `/home/cloud`에 같은 경로의 파일을 덮어쓸 수 있고, `/etc` 복원은 root 권한이 필요하다.

```bash
./restore.sh --restore-home
sudo ./restore.sh --restore-etc
sudo ./restore.sh --restore-all
```

자동화 환경에서는 대화형 확인 대신 dry-run 검토가 끝난 경우에만 `--yes`를 추가한다. restore는 destination 파일을 삭제하지 않지만 동일 경로 파일은 덮어쓸 수 있다.

<br>

## 새 MSP Ubuntu 재구성 순서

1. 새 Ubuntu의 OS, DNS, 시간 동기화, SSH 접근과 기본 계정을 준비한다.
2. Repository를 clone하고 `msp/restore.sh --dry-run` 결과를 검토한다.
3. `inventory/manual-packages.txt`를 검토해 필요한 패키지만 설치하고, Docker/Compose 및 Ansible/Terraform 버전을 맞춘다.
4. `--restore-home`으로 코드·compose·스크립트를 복원한다.
5. 별도 secret 저장소에서 `.env`, AWS/Cloudflare/Slack/DB credential, SSH/WireGuard/TLS key, Firebase credential, Wazuh credential/certificate를 안전하게 주입한다.
6. Docker network/volume을 검토하고 Grafana, Zabbix, Wazuh 및 Hospital DR compose 구성을 순서대로 재생성한다. 백업에서 제외된 runtime data와 Wazuh 인증서/비밀번호는 새로 생성한다.
7. `--restore-etc`를 실행한 뒤 unit 파일의 경로와 secret 주입 방식을 검토하고 `systemctl daemon-reload` 및 enable/start 여부를 수동 승인한다.
8. Ansible playbook은 inventory와 SSH credential을 확인한 후 review된 plan으로 실행한다.
9. Terraform은 backend/state/variable/credential을 별도로 복구하고 `terraform init`, `terraform plan` 결과를 검토한 후에만 apply한다. 이 백업 절차는 `apply`나 `destroy`를 실행하지 않는다.
10. 애플리케이션 health check, monitoring, alerting, backup timer, failover/failback runbook을 검증한다.

<br>

## Git 제외 항목과 별도 보관 항목

`.gitignore`와 `backup.sh`는 nested `.git`, `.env` 계열, `.aws`, `.ssh`, `.docker`, Terraform provider/state/tfvars, `*.pem`, `*.key`, `*.secret`, 인증서 파일, `node_modules`, cache/venv/pycache, SQLite/DB runtime, `*backup*`·`*legacy*` 디렉터리, `*.pre-*` snapshot 파일, `*.sql`/`*.dump`/`*.enc`, archive, log, Wazuh generated cert/password files를 제외한다. Wazuh compose의 upstream 기본 credential 예시는 백업 복사본에서 secret-store placeholder로 치환한다. `.env.example`와 검토된 example/template tfvars만 허용한다.

현재 호스트의 `hospital-dr-cloudflare-preflight.*`, `hospital-dr-cloudflare-wrapper-backup.*`, `hospital-dr-ops-backup-*`, `hospital-dr-legacy-backup`, `.hospital-dr-runtime-backups`, `db_backups`, `zabbix-backups`, `hospital-dr-secrets`, `hospital-dr-recovery`와 같은 임시·과거·Secret·runtime·중복 경로는 백업하지 않는다. `/home/cloud` 바로 아래의 이전 배포용 helper 복사본도 canonical `hospital-dr-repo/operations`와 중복되므로 제외한다.

다음은 GitHub 밖의 접근 통제된 secret 저장소에 별도로 보관해야 한다.

- AWS access key/secret, IAM role/SSO/OIDC 설정값 및 SSM/Secrets Manager 접근 정보
- Cloudflare API/access token
- Slack bot token/signing secret
- DB password, application credential, Firebase credential
- SSH private key, WireGuard private key, TLS/private certificate key
- Wazuh/Grafana/Zabbix 관리자 비밀번호·인증서·generated credential
- 실제 `.env`, Terraform `*.tfvars`/state, 운영용 host-specific credential

백업의 secret scanner는 파일 경로와 위험 유형만 출력하며 secret 값은 출력하지 않는다. 코드의 환경변수 이름이나 문서의 일반적인 `password` 단어는 검토 대상이 될 수 있으므로, 경고가 발생하면 실제 literal인지 외부 secret 참조인지 확인한다.

백업 복사본을 생성할 때 알려진 token prefix, bearer token, private-key block, credential literal은 `<SET_IN_SECRET_STORE>` 또는 유형별 redacted placeholder로 치환한다. AWS account ID, literal ARN, resource ID, S3 URI와 AWS public endpoint/IP처럼 운영 식별에 사용되는 값도 백업본에는 그대로 남기지 않는다. 이 치환은 현재 트리만 대상으로 하며 Git 과거 이력에 이미 들어간 값까지 제거하지 않으므로, 실제 credential이 노출된 적이 있으면 별도로 즉시 폐기·재발급하고 필요 시 이력 정리를 검토한다.

<br>

## Owner/group/permission 주의사항

`rootfs`는 원본 mode를 가능한 한 보존하지만, 새 서버의 UID/GID가 다를 수 있다. 복원 후 `cloud` 계정의 owner/group, 실행 파일 mode, systemd unit의 root-readable 범위, secret 파일의 `0600` 권한을 확인한다. `/etc` 복원은 root로 실행하고, systemd unit의 `ExecStart`, `WorkingDirectory`, `EnvironmentFile` 경로와 secret 주입을 수동 검토한다.

<br>

## 안전 원칙

- 원본 `/home/cloud` 파일은 읽기/복사만 하며 이동·삭제·수정하지 않는다.
- 원본 `hospital-dr-repo`의 `.git` 상태를 reset/checkout/clean/add/commit/stash하지 않는다.
- 서비스 중지, Docker container 삭제, Terraform apply/destroy, Ansible 실행은 이 백업 단계에서 수행하지 않는다.
- 최종 검토가 끝날 때까지 commit/push하지 않는다.
