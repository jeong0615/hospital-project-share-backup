# Secret scan

기존 rg + Python 표준 라이브러리만 사용했습니다. gitleaks는 미설치이므로 설치하지 않았습니다. 검사: 키워드, 파일명, private key/token 형태, 환경변수 secret literal, 원래 고정 session fallback 잔존. JSON/소스/설정/문서/SQL과 별도 생성 파일을 대상으로 수행했습니다. archive/binary/실제 .env/credential은 저장소에 없습니다.

- 원본에서 확인한 비밀값 또는 고정 비밀값 예시 위치: **3곳** (app session fallback, 과거 문서 DB password, 과거 문서 session secret). 실제값은 보고하지 않습니다.
- 복사본 치환 위치: **6곳** (위 3곳 + 문서 DB user/DB name + cloudflared credential 경로). collector의 7회 문자열 치환 집계는 같은 줄 중복 처리를 포함하므로 위치 수와 다릅니다.
- 키워드 검사: **116개 일치 줄**. 변수명/SQL 컬럼/HTML password field/placeholder/보안 설명/주석과 include credential 경로 참조는 실제 secret 값과 구별했습니다. 위치만 inventory/secret-keyword-locations.json에 기록했습니다.
- 검사 후 확정 위험 파일/고신뢰 secret 잔존: **0건**. 원래 session fallback 값도 잔존하지 않습니다.

원본 .env/.env.zip은 복사하지 않았고 Tunnel credential JSON의 내용은 읽거나 복사하지 않았습니다. 패키지 lock의 integrity hash는 credential이 아닙니다. sample_data.sql은 Doctors 예시 INSERT로 비밀번호/실제 DB dump가 아닙니다. 알려진 공개 서비스 이름과 비밀번호가 우연히 같은 문자열이어도 공용 서비스 이름 자체를 비밀값으로 치환해 구성을 손상시키지 않았습니다.

정적 패턴 검사는 모든 종류의 비밀정보 부재를 수학적으로 보장하지 않습니다. 수동 입력 자료를 추가한 뒤 전체 재검수를 해야 합니다. 앱의 보안 한계는 APPLICATION.md에 별도 기록했으며 이번 수집에서 수정하지 않았습니다.

최종 생성 문서를 포함한 재검사: inventory/final-secret-scan.json. 키워드 위치 자체를 저장한 메타데이터의 재귀 일치는 제외했습니다.
