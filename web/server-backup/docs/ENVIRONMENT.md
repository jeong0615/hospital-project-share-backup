# 환경변수 사용 위치

실제 `.env` 값은 수록하지 않습니다. `.env.example`은 소스에서 참조된 이름만 포함합니다. `ZABBIX_USER/PASSWORD`는 미마운트 모듈 전용으로 주석 처리했습니다.

- `DB_HOST`: web/app/test-db.js:7, web/app/test-db.js:14, web/app/app.js:36, web/app/routes/check.js:13, web/app/routes/check.js:26, web/app/routes/check.js:35
- `DB_NAME`: web/app/test-db.js:10, web/app/test-db.js:18, web/app/app.js:40, web/app/routes/check.js:17, web/app/routes/check.js:28
- `DB_PASSWORD`: web/app/test-db.js:17, web/app/app.js:39, web/app/routes/check.js:16
- `DB_PORT`: web/app/test-db.js:8, web/app/test-db.js:15, web/app/app.js:37, web/app/routes/check.js:14, web/app/routes/check.js:27, web/app/routes/check.js:36
- `DB_USER`: web/app/test-db.js:9, web/app/test-db.js:16, web/app/app.js:38, web/app/routes/check.js:15
- `PORT`: web/app/app.js:14
- `SERVER_ROLE`: web/app/app.js:752, web/app/app.js:758, web/app/app.js:765, web/app/app.js:771
- `SESSION_SECRET`: web/app/app.js:160
- `ZABBIX_PASSWORD`: web/app/routes/check.js:59
- `ZABBIX_URL`: web/app/app.js:493, web/app/routes/check.js:48
- `ZABBIX_USER`: web/app/routes/check.js:58
