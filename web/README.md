# Web Server

이 디렉터리는 Hospital DR 프로젝트에서 사용하는 Web Server를 새로운 Ubuntu 또는 DR 환경에서 재구성할 수 있도록 Web Application Source, Web Server 설정, Docker 구성, 배포 Script 및 검증 절차를 보관한다.

Web Server는 병원 서비스의 외부 접근 영역을 담당하며, Application 구성과 네트워크/보안 구성을 분리하여 관리한다.

<br>

## 구조

```text
web/
├── README.md
├── BackUP_README.md
├── backup-docs/
│   ├── ARCHITECTURE.md
│   ├── RECOVERY.md
│   ├── SECRET_SCAN.md
│   └── ...
├── cloudflare/
│   ├── DNS.md
│   ├── FAILOVER_FAILBACK.md
│   └── README.md
├── dr/
│   ├── README.md
│   └── environment.example
├── monitoring/
│   └── zabbix-agent/README.md
└── server-backup/
    ├── app/
    │   ├── app.js
    │   ├── public/
    │   ├── routes/
    │   ├── sql/
    │   ├── views/
    │   ├── package.json
    │   └── package-lock.json
    ├── configs/
    │   ├── cloudflared/
    │   ├── netplan/
    │   ├── nginx/
    │   ├── systemd/
    │   └── zabbix-agent/
    ├── docs/
    ├── inventory/
    └── scripts/
```

`server-backup/app/`에는 Web Application Source, 정적 파일, Route, View와 Dependency 정의를 보관한다.

`server-backup/configs/`에는 Cloudflared, Netplan, Nginx, systemd 및 Zabbix Agent 설정을 보관한다.

`server-backup/docs/`에는 Application, Environment, systemd 및 복구 문서를 보관한다.

`server-backup/inventory/`에는 수집 당시의 시스템·네트워크·서비스 검증 결과를 보관한다.

`server-backup/scripts/`에는 배포, 실행 및 점검 Script를 보관한다.

`backup-docs/`, `cloudflare/`, `dr/`, `monitoring/`은 Web 백업의 운영·DR·연계 문서 영역이다. `docs/legacy/`와 `.bak` 파일은 현재 활성 설정으로 간주하지 않고 복구 전에 검토한다.

`server-backup/app/sql/`의 SQL은 애플리케이션용 예시 또는 fixture로만 취급한다. 실제 운영 DB Dump는 `db/`에서 별도로 관리한다.

<br>

## Web Server 역할

Web Server는 Hospital DR 프로젝트의 외부 Web Service를 제공한다.

주요 역할은 다음과 같다.

- 외부 사용자 HTTP/HTTPS 요청 처리
- Application Service 제공
- Reverse Proxy
- EMR / Backend Service 연계
- DR 전환 시 AWS Web Server에서 서비스 재개
- Monitoring 대상 제공

실제 네트워크 경로와 Firewall 구성은 GNS3 및 Physical Network 문서에서 별도로 관리한다.

<br>

## 포함 대상

Web Server 백업에는 다음 내용을 포함한다.

- Web Application Source
- Dependency 정의
- Application Runtime 구성에 필요한 정의
- Nginx / Apache 설정
- Application Process Manager 설정
- Deployment Script
- Health Check
- Reverse Proxy 설정
- DR 환경 배포에 필요한 Template
- 운영 및 복구 문서

실제 환경에서 사용하지 않는 Web Server 설정은 포함하지 않는다.

현재 백업 snapshot에는 Dockerfile과 docker-compose 파일이 없으므로, Docker 방식으로 복구할 때는 별도의 배포 정의를 확인하거나 재작성해야 한다.

<br>

## 새 Web Ubuntu 재구성 순서

1. 새 Ubuntu Server를 준비한다.
2. Network, DNS 및 시간 동기화를 확인한다.
3. Repository를 clone한다.
4. 필요한 Runtime, Docker 및 Web Server Package를 설치한다.
5. `web/server-backup/app/`의 Web Application Source를 배치한다.
6. 환경변수와 필요한 Secret을 별도 저장소에서 주입한다.
7. Docker 또는 Application Runtime을 구성한다.
8. Nginx / Apache 설정을 적용한다.
9. Application을 실행한다.
10. Local Health Check를 수행한다.
11. Reverse Proxy를 통해 Application 접근을 확인한다.
12. 외부망에서 Web Service 접근 여부를 확인한다.
13. MSP Monitoring 및 Alert 연동을 확인한다.

Node.js Application인 경우에는 `web/server-backup/app/`에서 Dependency를 설치하고, 실제 운영 방식에 맞춰 Process Manager 또는 systemd를 구성한다.

<br>

## 검증 항목

Web Server 구성 완료 후 다음 항목을 확인한다.

```text
Application Process
Docker Container
Application Port
Web Server Process
HTTP Response
Reverse Proxy
외부 접근
Backend / EMR 연결
Log Error
MSP Monitoring
DR Failover 이후 Web Service
```

필요한 경우 다음 명령어를 사용한다.

```bash
ss -lntp
docker ps
docker logs <container>
curl http://IP_REDACTED:<PORT>
curl http://<WEB_SERVER>
systemctl status nginx
systemctl status apache2
```

실제로 사용하는 Web Server에 맞는 명령어만 적용한다.

<br>

## Network 및 보안 구성

Web Server 자체의 Application 설정과 Network 보안 정책은 구분하여 관리한다.

관련 영역:

```text
gns3/
→ GNS3 VLAN / Routing / Firewall

physical/
→ 실제 Network 장비

web/
→ Web Application / Web Server

msp/
→ Monitoring / DR / Alert / Automation
```

Cloudflare 또는 WAF를 사용하는 경우 실제 Token이나 Credential은 저장하지 않고 Configuration과 적용 방법만 문서화한다.

<br>

## DR 환경

DR Failover 시 Web Server는 재해복구 환경에서 동일한 서비스를 제공할 수 있어야 한다.

주요 검증 항목:

1. DR Web Server가 정상 시작되는지 확인한다.
2. Web Application Process를 확인한다.
3. Backend/DB 연결을 확인한다.
4. Health Check가 성공하는지 확인한다.
5. 외부 Web 요청이 DR Server로 정상 전달되는지 확인한다.
6. Monitoring에서 서비스 정상 상태를 확인한다.

Failover 실행 자체와 승인 절차는 MSP의 DR Automation 및 Runbook에서 관리한다.

<br>

## Git 제외 및 별도 관리 항목

다음 정보는 Repository에 직접 저장하지 않는다.

- `.env`
- Application Secret
- DB Password
- Cloudflare Token
- API Token
- SSH Private Key
- TLS Private Key
- 실제 인증서 Private Key
- Runtime Log
- Cache
- Upload Data
- `node_modules`
- Docker Runtime Data
- 실제 운영 DB Dump
- 운영용 Archive 및 임시 Backup

실제 Secret 대신 Example 또는 Placeholder를 사용한다.

```env
DB_HOST=<DB_HOST>
DB_PASSWORD=<SECRET>
API_TOKEN=<SECRET>
```

<br>

## 안전 원칙

- 운영 Credential을 Source Code에 Hard Coding하지 않는다.
- 기존 Web Server를 백업하기 위해 서비스를 임의로 중지하거나 삭제하지 않는다.
- Docker Image보다 재생성 가능한 Source와 확인된 배포 정의를 관리한다.
- Web Server 복구 후 Local → Reverse Proxy → External 순서로 통신을 확인한다.
- 실제 네트워크 설정과 Web Application 설정을 분리하여 관리한다.
- GitHub 업로드 전 Secret, Key 및 Credential 포함 여부를 확인한다.
