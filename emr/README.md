# EMR Server Backup

이 디렉터리는 EMR 서버를 새 Ubuntu 환경에서 재구성하고 유지보수하기 위한 소스, 웹 라우팅, 안전한 운영 설정, 인벤토리를 보관한다. 원본 서버는 `hoseo@IP_REDACTED`이며, 이번 수집은 원본 서비스를 중지하거나 설정을 변경하지 않고 읽기·복사만 수행했다.

## 구조

```text
emr/
├── .gitignore
├── README.md
├── backup.sh
├── restore.sh
├── inventory/
│   ├── active-services.txt
│   ├── config-sources.txt
│   ├── env-variables.txt
│   ├── excluded-items.txt
│   ├── listening-sockets.txt
│   ├── packages.txt
│   ├── projects.txt
│   ├── server-summary.txt
│   └── web-routing.txt
└── rootfs/
    ├── etc/
    │   ├── apache2/
    │   ├── nginx/
    │   ├── openvpn/update-resolv-conf
    │   ├── vsftpd.conf
    │   └── zabbix/zabbix_agentd.conf
    ├── home/hoseo/
    │   ├── doctor_web/
    │   └── hospital_emr/
    ├── var/ossec/etc/
    │   ├── local_internal_options.conf
    │   └── ossec.conf
    └── var/www/html/
```

`rootfs/` 아래 경로는 EMR Ubuntu 서버의 실제 절대경로를 표현한다. 예를 들어 `emr/rootfs/home/hoseo/hospital_emr/server.js`는 원본 `/home/hoseo/hospital_emr/server.js`에 대응한다.

## 포함한 원본

- `/home/hoseo/hospital_emr`: 현재 EMR Node/Express 소스, frontend, backend, `package.json`, `package-lock.json`
- `/home/hoseo/doctor_web`: 별도 Python 프로젝트의 `app.py`와 template
- `/etc/nginx`: 현재 Nginx 설정 및 default site
- `/etc/apache2/sites-available/000-default.conf`, `sites-enabled/000-default.conf`, `ports.conf`
- `/var/www/html`: 현재 Nginx document root
- 비밀값이 없는 `/etc/vsftpd.conf`, `/etc/zabbix/zabbix_agentd.conf`, Wazuh 운영 설정 일부
- 패키지, 서비스, 포트, 라우팅, 환경변수 이름 인벤토리

최근 조사 시 Nginx는 `/var/www/html`을 80번 포트에서 서비스하고 있었고, `hospital_emr` Node/Express 프로세스는 `/home/hoseo/hospital_emr`에서 5000번 포트로 실행 중이었다. 다만 Nginx default site에는 `proxy_pass`가 없어 현재 공개 경로가 Node 앱으로 연결된다고 가정하지 않는다. Apache는 enable 상태지만 failed 상태였으므로 Nginx와 포트 충돌 여부를 복구 시 확인한다.

## 제외한 원본

`.env`, `.env.*`, `node_modules/`, `nohup.out`, 로그, ZIP/설치 패키지, `.git/`, SSH 키, Wazuh `client.keys`, Wazuh `wpk_root.pem`, TLS/private key, 중복·legacy 파일은 포함하지 않았다. 원본 코드의 DB 비밀번호 fallback과 테스트 계정 비밀번호는 백업본에 저장하지 않고 환경변수 참조로 치환했다. `.env.example`에는 변수명만 기록하고 실제 값은 별도 Secret 저장소에서 주입한다.

DB 데이터와 DB 비밀번호는 `db/` 백업에서 관리하며, 이 디렉터리에는 DB Dump를 중복 저장하지 않는다.

## 백업 갱신

사전 조건: 백업 작업 PC에 SSH key 인증과 `rsync`가 준비되어 있어야 한다.

```bash
cd /path/to/hospital-project-backup/emr
EMR_SSH_TARGET=hoseo@IP_REDACTED ./backup.sh --dry-run
EMR_SSH_TARGET=hoseo@IP_REDACTED ./backup.sh --apply
git status
git diff -- emr/
```

`backup.sh`는 remote 파일을 읽어 local `rootfs/`에 복사하고, `.git`, runtime/dependency, key·dump·archive를 제외하며 알려진 소스 내 inline DB/test 비밀번호를 환경변수 참조로 치환한다. `git add`, `git commit`, `git push`, 서비스 재시작, 원격 파일 삭제는 수행하지 않는다. root 권한이 필요한 Wazuh 파일은 자동 갱신 대상에서 제외될 수 있으므로 별도 검토한다.

## 복구

새 Ubuntu 서버에서 다음 순서를 따른다.

1. Ubuntu, OpenSSH, Node.js 및 Python을 설치하고 원본 버전에 맞춰 런타임을 준비한다.
2. Repository를 clone하고 `emr/`의 구조와 `inventory/`를 확인한다.
3. 외부 Secret 저장소에서 `PORT`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`을 준비하여 `/home/hoseo/hospital_emr/.env`를 생성한다.
4. 먼저 dry-run을 확인한다.

   ```bash
   sudo ./emr/restore.sh --dry-run
   ```

5. 대상 경로·owner/group·permission을 확인한 뒤 명시적으로 적용한다.

   ```bash
   sudo ./emr/restore.sh --apply --confirm
   ```

6. `/home/hoseo/hospital_emr`에서 `npm ci`를 실행한다.
7. Node 앱을 systemd 또는 승인된 process manager로 등록하되, 실제 포트와 DB 연결을 확인한다.
8. Nginx를 EMR frontend 또는 Node reverse proxy에 연결하고 `nginx -t` 후에만 reload한다.
9. Apache, OpenVPN, vsftpd, Wazuh, Zabbix는 필요성을 확인한 뒤 각각의 인증서·키·등록값을 외부 보관본으로 복원한다.
10. EMR 로그인, DB 연결, 환자/진료기록 API, Nginx 접근 로그와 모니터링을 검증한다.

`restore.sh` 기본 동작은 dry-run이며, `--apply --confirm` 없이는 시스템 파일을 덮어쓰지 않는다. 서비스 start/stop/restart와 `npm ci`는 자동으로 실행하지 않는다.

## 유지보수 주의사항

- 실제 `.env`, DB password, Wazuh agent key, SSH key, TLS certificate/private key는 GitHub에 저장하지 않는다.
- Linux owner/group/permission은 원본과 복구 대상의 계정·그룹을 먼저 만든 뒤 확인한다.
- `node_modules`는 백업하지 않고 `package-lock.json` 기준으로 `npm ci`로 재생성한다.
- `hospital_emr` 소스의 DB 연결은 외부 환경변수에 의존하므로 DB 서버 주소와 계정은 `db/` 복구 절차와 함께 확인한다.
- Nginx가 현재 `/var/www/html`을 서비스하고 있어, 소스 복구만으로 EMR이 자동 공개되는 것은 아니다. 라우팅 변경은 별도 검토·승인 후 수행한다.
- Apache가 enable이지만 failed였으므로 Nginx와 동시에 80번 포트를 점유하도록 복구하지 않는다.
- 실제 운영 데이터와 로그는 별도 보안·보존 정책으로 관리한다.
