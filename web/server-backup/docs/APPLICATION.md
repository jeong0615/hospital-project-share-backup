# 실제 소스 분석

근거: `web/app/app.js`, `routes/check.js`, `views/`, `package.json`. 코드의 정적 분석이며 인증/DB 쓰기 테스트는 하지 않았습니다.

- Entry: package main `app.js`, start `node app.js`; Express 4, EJS view engine; public 정적 제공.
- DB: mysql2/promise pool, connectionLimit 10, queueLimit 0, connectTimeout 30000ms. 시작 시 연결 확인. `query`/`execute`와 `?` 파라미터 사용.
- 파서: urlencoded가 두 번 등록되고 JSON parser 사용. 정적 middleware가 보안 middleware보다 앞에 있어 정적 응답은 뒤쪽 제어를 거치지 않을 수 있음.
- URL/body/query 문자열에 정규식 차단, Helmet, 전체 5분/300회 제한, 로그인 POST 5분/10회 제한, xss-clean, sqlstring escape 전처리 사용. 실제 공격 방어 완전성이나 부하 한계를 입증한 것은 아님.
- trust proxy = 1. express-session, 기본 MemoryStore, resave false, saveUninitialized false, 쿠키 httpOnly/secure true/sameSite lax/4시간. 고정 session fallback은 복사본에서 `<SESSION_SECRET>` 치환.
- 로그인: Users를 login_id로 조회 후 문자열 비밀번호 비교. bcrypt 패키지는 있으나 app.js에서 해시 처리를 하지 않음. 성공 시 session.user 설정, AccessLogs 기록.
- 가입: Users와 Patients INSERT. 요청의 role을 저장하며 서버 측 허용 역할 목록 제한은 확인되지 않음. 두 INSERT의 명시적 transaction 없음.
- 로그아웃: 로그인 필요, 로그 기록 후 session.destroy. 로그인 시 명시적 session.regenerate 없음.
- 마이페이지: requireLogin + role PAT 조건; Users에서 본인 user_id 조회. patient 상세는 null, records는 빈 배열. 실제 진료기록 조회 구현으로 표현하지 않음.
- 예약: 등록, 번호+비밀번호 조회, 번호+비밀번호 DELETE, 목록 제공. 예약 비밀번호는 문자열 저장/비교. 목록 GET에는 인증 middleware가 없고 환자 이름·부서·제목을 조회함.
- 오류: 다수 DB 핸들러 try/catch 및 500 응답, 마지막 404 페이지. 통합 4-인자 Express 오류 middleware 없음. 일부 응답에 DB 오류 메시지가 노출됨.
- 로깅: console 및 AccessLogs. 일부 사용자 이름/로그인 ID/공격 의심 payload를 로그에 넣는 코드가 있음. 로그는 백업에서 제외.
- EJS `<%=` 출력, `<%-`는 조사한 템플릿에서 include 용도. CSRF 전용 middleware는 발견되지 않음. 이 항목들은 개선 과제이며 운영 소스는 수정하지 않음.

| Method | 경로 | 실제 동작 |
|---|---|---|
| GET | / | Doctors 조회, 실패 시 빈 목록, 메인 렌더 |
| GET/POST | /login | 폼 / 인증 |
| GET/POST | /signup | 폼 / Users·Patients 생성 |
| POST | /logout | 세션 종료 |
| GET | /mypage | PAT 전용 기본 정보 페이지 |
| GET | /check/db | SELECT 1 AS ok |
| GET | /check/zabbix | ZABBIX_URL에 apiinfo.version 요청; 중앙 Agent 등록 증명 아님 |
| GET | /guide/:section, /pages/:slug | 안내 페이지 |
| GET | /health-info, /health-info/:slug | 건강 정보 |
| GET | /community, /community/notices, /community/faq | 커뮤니티 정적 내용 |
| GET/POST | /reservations/new | 예약 생성 |
| GET/POST | /reservations/check | 예약 확인 |
| POST | /reservations/delete | 예약 삭제 |
| GET | /reservations/list | 예약 목록 |
| GET | /health | DB SELECT 1 성공 200, 실패 500 |

`routes/check.js`는 존재하지만 app.js가 require/mount하지 않습니다. 이 파일의 Zabbix user.login/token 반환 기능은 활성 동작이 아닙니다. `test-db.js`는 별도 DB 진단 도구이며 실행하지 않았습니다. `sql/reservation_posts.sql`은 ReservationPosts 스키마, `sample_data.sql`은 코드에 포함된 Doctors 예시 seed이며 DB dump가 아닙니다.

재구축 시 placeholder session fallback을 그대로 사용하면 안 됩니다. 실제 비밀값을 EnvironmentFile로 공급해야 하며 백업에 공급하지 않습니다.
