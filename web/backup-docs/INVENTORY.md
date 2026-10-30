# 재구축 주요 Inventory

| 항목 | 직접 관측 |
|---|---|
| OS | Ubuntu 22.04.5 LTS |
| Kernel | 6.8.0-138-generic |
| Hostname | hospital-web-server-1 |
| Node | v22.22.1; dpkg nodejs 22.22.1-1nodesource1 |
| npm 실행 버전 | 10.9.4 |
| npm dpkg 버전 | 8.5.1~ds-1; 실행 버전과 다름 |
| Nginx | 1.18.0; Ubuntu package 1.18.0-6ubuntu14.20 |
| cloudflared | 2026.3.0 |
| Zabbix Agent | 5.0.17; package 1:5.0.17+dfsg-1 |
| MySQL client | 8.0.46-0ubuntuIP_REDACTED |
| 기타 | curl, ca-certificates, openssh-server |

전체 dpkg 조회는 `web/inventory/raw-packages.txt`입니다. 이 목록 전체를 새 서버의 필수 설치 목록으로 사용하지 않습니다. Nginx active modules-enabled에 geoip2/image-filter/xslt/mail/stream 관련 모듈 include가 있으므로 그대로 재현하려면 해당 패키지를 별도 확인합니다. Node 재현 버전은 관측값이며 향후 업데이트 권고를 의미하지 않습니다.

Dependency/DevDependency는 package.json 및 lock을 기준으로 아래에 기록합니다. node_modules는 제외했으며 npm ci는 현재 서버에서 실행하지 않았습니다. npm CLI 경로와 패키지 버전 차이는 충돌 보고에 기록합니다.

| Dependency | package.json range |
|---|---|
| axios | ^1.14.0 |
| bcrypt | ^6.0.0 |
| dotenv | ^16.6.1 |
| ejs | ^3.1.10 |
| express | ^4.22.1 |
| express-rate-limit | ^8.5.2 |
| express-session | ^1.19.0 |
| helmet | ^8.1.0 |
| mysql2 | ^3.20.0 |
| sqlstring | ^2.3.3 |
| xss-clean | ^0.1.4 |

DevDependency: 없음
