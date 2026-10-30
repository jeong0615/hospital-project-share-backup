hospital_emr/
│
├── index.html              ← 로그인 페이지
├── dashboard.html          ← 역할별 메인 (DOC/PA/ADMIN)
├── patients.html           ← 환자 목록/검색
├── patient_detail.html     ← 환자 상세 + 진료기록
├── patient_register.html   ← 환자 신규 등록
├── medical_record.html     ← 진료기록 작성 (DOC 전용)
├── access_logs.html        ← 접근 로그 조회 (ADMIN 전용)
│
├── css/
│   └── style.css           ← 공통 스타일 (EMR 테마)
│
├── js/
│   ├── auth.js             ← 로그인/세션/역할 권한 체크
│   ├── api.js              ← DB API 호출 공통 모듈
│   ├── patients.js         ← 환자 CRUD 로직
│   ├── medical-records.js  ← 진료기록 로직
│   └── utils.js            ← 날짜 포맷, 유효성검사 등
│
└── backend/                ← PHP
    ├── db.js               ← MySQL 연결 (접속정보 관리)
    ├── auth.js             ← 로그인 API
    ├── patients.js         ← 환자 CRUD API
    ├── medical_records.js  ← 진료기록 API
    └── logs.js             ← 접근 로그 API