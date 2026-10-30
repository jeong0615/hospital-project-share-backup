# 수집 파일 목록

원본→복사본 매핑입니다. symlink는 내용만 일반 파일로 보존했으며 Nginx include 대상과 비활성을 구분했습니다. 조회 산출물은 web/inventory, 새 문서는 docs 및 영역별 README에 있습니다.

| 원본 | 복사본 |
|---|---|
| `/home/vboxuser/hospital-web/.firebaserc` | `web/docs/legacy/.firebaserc` |
| `/home/vboxuser/hospital-web/test-db.js` | `web/app/test-db.js` |
| `/home/vboxuser/hospital-web/package.json` | `web/app/package.json` |
| `/home/vboxuser/hospital-web/app.js` | `web/app/app.js` |
| `/home/vboxuser/hospital-web/배포_및_실행_설명.txt` | `web/docs/legacy/배포_및_실행_설명.txt` |
| `/home/vboxuser/hospital-web/firebase_backup.json` | `web/docs/legacy/firebase_backup.json` |
| `/home/vboxuser/hospital-web/.gitignore` | `web/app/.gitignore` |
| `/home/vboxuser/hospital-web/package-lock.json` | `web/app/package-lock.json` |
| `/home/vboxuser/hospital-web/routes/check.js` | `web/app/routes/check.js` |
| `/home/vboxuser/hospital-web/sql/sample_data.sql` | `web/app/sql/sample_data.sql` |
| `/home/vboxuser/hospital-web/sql/reservation_posts.sql` | `web/app/sql/reservation_posts.sql` |
| `/home/vboxuser/hospital-web/views/index.ejs` | `web/app/views/index.ejs` |
| `/home/vboxuser/hospital-web/views/reservations/check.ejs` | `web/app/views/reservations/check.ejs` |
| `/home/vboxuser/hospital-web/views/reservations/new.ejs` | `web/app/views/reservations/new.ejs` |
| `/home/vboxuser/hospital-web/views/reservations/list.ejs` | `web/app/views/reservations/list.ejs` |
| `/home/vboxuser/hospital-web/views/community/notices.ejs` | `web/app/views/community/notices.ejs` |
| `/home/vboxuser/hospital-web/views/community/index.ejs` | `web/app/views/community/index.ejs` |
| `/home/vboxuser/hospital-web/views/community/faq.ejs` | `web/app/views/community/faq.ejs` |
| `/home/vboxuser/hospital-web/views/partials/header.ejs` | `web/app/views/partials/header.ejs` |
| `/home/vboxuser/hospital-web/views/partials/footer.ejs` | `web/app/views/partials/footer.ejs` |
| `/home/vboxuser/hospital-web/views/health/list.ejs` | `web/app/views/health/list.ejs` |
| `/home/vboxuser/hospital-web/views/pages/detail.ejs` | `web/app/views/pages/detail.ejs` |
| `/home/vboxuser/hospital-web/views/pages/not-found.ejs` | `web/app/views/pages/not-found.ejs` |
| `/home/vboxuser/hospital-web/views/pages/list.ejs` | `web/app/views/pages/list.ejs` |
| `/home/vboxuser/hospital-web/views/auth/login.ejs` | `web/app/views/auth/login.ejs` |
| `/home/vboxuser/hospital-web/views/auth/signup.ejs` | `web/app/views/auth/signup.ejs` |
| `/home/vboxuser/hospital-web/views/auth/mypage.ejs` | `web/app/views/auth/mypage.ejs` |
| `/home/vboxuser/hospital-web/views/auth/forbidden.ejs` | `web/app/views/auth/forbidden.ejs` |
| `/home/vboxuser/hospital-web/public/404.html` | `web/app/public/404.html` |
| `/home/vboxuser/hospital-web/public/js/menu.js` | `web/app/public/js/menu.js` |
| `/home/vboxuser/hospital-web/public/css/style.css` | `web/app/public/css/style.css` |
| `/etc/nginx/nginx.conf` | `web/configs/nginx/nginx.conf` |
| `/etc/nginx/mime.types` | `web/configs/nginx/mime.types` |
| `/etc/nginx/sites-enabled/hospital` | `web/configs/nginx/active/sites-enabled/hospital` |
| `/etc/nginx/sites-enabled/hospital.bak_20260625_123126` | `web/configs/nginx/active/sites-enabled/hospital.bak_20260625_123126` |
| `/etc/nginx/modules-enabled/50-mod-http-geoip2.conf` | `web/configs/nginx/active/modules-enabled/50-mod-http-geoip2.conf` |
| `/etc/nginx/modules-enabled/50-mod-http-image-filter.conf` | `web/configs/nginx/active/modules-enabled/50-mod-http-image-filter.conf` |
| `/etc/nginx/modules-enabled/50-mod-http-xslt-filter.conf` | `web/configs/nginx/active/modules-enabled/50-mod-http-xslt-filter.conf` |
| `/etc/nginx/modules-enabled/50-mod-mail.conf` | `web/configs/nginx/active/modules-enabled/50-mod-mail.conf` |
| `/etc/nginx/modules-enabled/50-mod-stream.conf` | `web/configs/nginx/active/modules-enabled/50-mod-stream.conf` |
| `/etc/nginx/modules-enabled/70-mod-stream-geoip2.conf` | `web/configs/nginx/active/modules-enabled/70-mod-stream-geoip2.conf` |
| `/etc/nginx/sites-available/default` | `web/configs/nginx/inactive/default` |
| `/etc/cloudflared/config.yml` | `web/configs/cloudflared/config.yml.example` |
| `/etc/zabbix/zabbix_agentd.conf` | `web/configs/zabbix-agent/zabbix_agentd.conf` |
| `/etc/systemd/system/hospital-web.service` | `web/configs/systemd/hospital-web.service` |
| `/etc/systemd/system/cloudflared.service` | `web/configs/systemd/cloudflared.service` |
| `/lib/systemd/system/zabbix-agent.service` | `web/configs/systemd/zabbix-agent.service` |
| `/lib/systemd/system/nginx.service` | `web/configs/systemd/nginx.service` |
