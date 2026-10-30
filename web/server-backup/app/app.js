require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const mysql = require('mysql2/promise');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const SqlString = require('sqlstring');

const app = express();
app.use(express.urlencoded({ extended: true }));
const PORT = process.env.PORT || 3000;

function nowKST() {
  return new Date().toLocaleString('ko-KR', {
    timeZone: 'Asia/Seoul',
    hour12: false
  });
}

function appLog(type, message, req = null) {
  const ip = req ? req.ip : '-';
  console.log(`[${nowKST()}] [${type}] ${message} ip=${ip}`);
}

function maskForLog(value) {
  if (!value) return '-';
  const text = String(value);
  if (text.length <= 2) return '*'.repeat(text.length);
  return `${text[0]}${'*'.repeat(text.length - 2)}${text[text.length - 1]}`;
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 30000
});

(async () => {
  try {
    const conn = await pool.getConnection();
    console.log('DB 연결 성공');
    conn.release();
  } catch (err) {
    console.error('DB 연결 실패:', err.message);
  }
})();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => {
  const decodedUrl = decodeURIComponent(req.originalUrl || req.url || '');

  const wafPattern = /hack|<script|<\/script|javascript:|onerror=|onload=|alert\(|union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|--|drop\s+table|delete\s+from|insert\s+into/i;

  if (wafPattern.test(decodedUrl)) {
    appLog(
      'WAF 차단',
      `URL에서 공격 의심 패턴 감지 payload="${decodedUrl}"`,
      req
    );
    return res.status(403).send('<h1>403 Forbidden: Blocked by Express WAF</h1>');
  }

  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string' && wafPattern.test(req.body[key])) {
        appLog(
          'WAF 차단',
          `요청 본문에서 공격 의심 패턴 감지 항목=${key} payload="${req.body[key]}"`,
          req
        );
        return res.status(403).send('<h1>403 Forbidden: Blocked by Express WAF</h1>');
      }
    }
  }

  if (req.query) {
    for (const key in req.query) {
      if (typeof req.query[key] === 'string' && wafPattern.test(req.query[key])) {
        appLog(
          'WAF 차단',
          `쿼리스트링에서 공격 의심 패턴 감지 항목=${key} payload="${req.query[key]}"`,
          req
        );
        return res.status(403).send('<h1>403 Forbidden: Blocked by Express WAF</h1>');
      }
    }
  }

  next();
});

app.use(helmet());

const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 300,
  handler: (req, res) => {
    appLog(
      '전체 요청 제한',
      `요청이 너무 많아서 차단됨 method=${req.method} url=${req.originalUrl}`,
      req
    );
    return res.status(429).send("과도한 요청이 감지되어 WAF에 의해 접속이 제한되었습니다.");
  }
});

app.use(limiter);

// 로그인 전용 요청 제한
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  handler: (req, res) => {
    appLog(
      '로그인 요청 제한',
      `로그인 시도가 너무 많아서 차단됨 url=${req.originalUrl}`,
      req
    );
    return res.status(429).send("로그인 시도가 너무 많습니다. 5분 후 다시 시도해주세요.");
  }
});
app.use(xss());

app.use((req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = SqlString.escape(req.body[key]).replace(/^'|'$/g, '');
      }
    }
  }

  if (req.query) {
    for (let key in req.query) {
      if (typeof req.query[key] === 'string') {
        req.query[key] = SqlString.escape(req.query[key]).replace(/^'|'$/g, '');
      }
    }
  }

  next();
});

app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || '<SESSION_SECRET>',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: 1000 * 60 * 60 * 4
  }
}));

const menuData = {
  medical: [
    { label: '본원', url: '/pages/medical-main' },
    { label: '어린이병원', url: '/pages/medical-child' },
    { label: '암병원', url: '/pages/medical-cancer' },
    { label: '인터넷 진료예약', url: '/reservations/new' },
    { label: '예약확인/취소', url: '/reservations/check' },
    { label: '예약목록', url: '/reservations/list' }

  ],
  usage: [
    { label: '오시는 길', url: '/pages/usage-location' },
    { label: '원내외래위치도', url: '/pages/usage-map' },
    { label: '진료과/검사실', url: '/pages/usage-departments' },
    { label: '증명서 발급', url: '/pages/usage-certificate' },
    { label: 'FAQ', url: '/pages/usage-faq' }
  ],
  about: [
    { label: '병원개요', url: '/pages/about-overview' },
    { label: '미션/비전', url: '/pages/about-vision' },
    { label: '연혁', url: '/pages/about-history' },
    { label: '조직도', url: '/pages/about-organization' },
    { label: '현황 및 통계', url: '/pages/about-stats' }
  ],
  health: [
    { label: '건강칼럼', url: '/health-info/column' },
    { label: '생활 건강정보', url: '/health-info/lifestyle' },
    { label: '예방접종 안내', url: '/health-info/vaccine' },
    { label: '만성질환 관리', url: '/health-info/chronic' }
  ],
  community: [
    { label: '고객참여 안내', url: '/community' },
    { label: '공지사항', url: '/community/notices' },
    { label: '자주 묻는 질문', url: '/community/faq' },
  ]
};

const pageMap = {
  'medical-main': { title: '본원 진료안내', body: '본원 진료 절차, 접수 순서, 준비사항을 안내합니다. 초진은 신분증을 지참해 수납 창구에서 접수하고, 재진은 무인수납기 또는 온라인 예약 후 내원할 수 있습니다.' },
  'medical-child': { title: '어린이병원 안내', body: '소아청소년 환자를 위한 외래, 검사, 예방접종, 입원 절차를 안내합니다. 보호자 동반과 사전 예약을 권장합니다.' },
  'medical-cancer': { title: '암병원 안내', body: '암 진료센터 진료예약, 협진 절차, 입원 및 항암치료 안내를 확인할 수 있습니다. 상담 전 검사자료를 준비해 주세요.' },
  'usage-location': { title: '오시는 길', body: '병원 주소, 대표번호, 대중교통 경로, 주차장 위치를 제공합니다. 내원 전 교통상황을 확인해 주세요.' },
  'usage-map': { title: '원내 위치도', body: '주요 진료동, 영상의학과, 검사실, 수납창구, 약국 위치를 층별로 확인할 수 있습니다.' },
  'usage-departments': { title: '진료과/검사실', body: '내과, 외과, 정형외과, 소아청소년과, 영상의학과 등 진료과와 검사실 운영 정보를 안내합니다.' },
  'usage-certificate': { title: '증명서 발급', body: '진단서, 입퇴원확인서, 진료확인서 발급 절차와 신분증 지참 여부를 안내합니다.' },
  'usage-faq': { title: 'FAQ', body: '예약, 수납, 접수, 증명서 발급, 주차 등 자주 묻는 질문을 정리했습니다.' },
  'about-overview': { title: '병원개요', body: '지역사회 중심의 종합의료 서비스를 제공하는 병원으로, 환자 안전과 정확한 진료를 핵심 가치로 운영합니다.' },
  'about-vision': { title: '미션/비전', body: '환자 중심, 안전 중심, 신뢰 중심의 진료체계를 바탕으로 지속 가능한 의료서비스를 제공합니다.' },
  'about-history': { title: '연혁', body: '개원 이후 외래 진료 확대, 진료센터 개설, 의료장비 도입 등 주요 발전 과정을 소개합니다.' },
  'about-organization': { title: '조직도', body: '진료부, 간호부, 행정부, 원무부, 전산팀 등 병원 주요 조직 구성을 확인할 수 있습니다.' },
  'about-stats': { title: '현황 및 통계', body: '진료과 수, 병상 수, 일평균 외래 환자 수 등 운영 현황을 요약해 제공합니다.' }
};

const healthMap = {
  column: { title: '건강칼럼', body: '계절별 감염병 예방, 수면 관리, 식습관 개선처럼 일상에서 실천 가능한 건강관리 정보를 제공합니다.' },
  lifestyle: { title: '생활 건강정보', body: '혈압 관리, 금연, 운동, 수분 섭취, 스트레스 조절 등 생활습관 중심의 건강정보를 안내합니다.' },
  vaccine: { title: '예방접종 안내', body: '연령별 예방접종 권장 일정, 접종 전 주의사항, 접종 후 관찰사항을 정리했습니다.' },
  chronic: { title: '만성질환 관리', body: '당뇨, 고혈압, 고지혈증 등 만성질환자의 정기검진과 식이·운동 관리 방법을 안내합니다.' }
};

const communityMap = {
  notices: {
    title: '공지사항',
    items: [
      { title: '2026년 4월 외래 진료 일정 안내', date: '2026-04-03' },
      { title: '주차장 정비에 따른 일부 구역 통제 안내', date: '2026-04-01' },
      { title: '건강검진센터 예약 운영시간 변경', date: '2026-03-28' }
    ]
  },
  faq: {
    title: '고객참여 FAQ',
    items: [
      { q: '초진 예약 없이 방문해도 되나요?', a: '진료과에 따라 당일 접수가 가능하지만 대기시간이 길어질 수 있어 예약을 권장합니다.' },
      { q: '진료확인서는 어디서 발급받나요?', a: '외래 수납창구 또는 원무팀에서 발급받을 수 있습니다.' },
      { q: '인터넷 예약 글은 누가 볼 수 있나요?', a: '예약번호와 예약 시 설정한 비밀번호를 가진 본인만 확인할 수 있습니다.' }
    ]
  }
};

async function query(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function run(sql, params = []) {
  const [result] = await pool.execute(sql, params);
  return result;
}

async function logAccess(userId, actionType, req) {
  try {
    await run(
      'INSERT INTO AccessLogs (user_id, action_type, ip_address) VALUES (?, ?, ?)',
      [userId || null, actionType, req.ip]
    );
  } catch (err) {
    console.error('AccessLogs insert failed:', err.message);
  }
}

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.menuData = menuData;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requirePatient(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'PAT') {
    return res.status(403).render('auth/forbidden', { message: '환자 계정만 접근할 수 있습니다.' });
  }
  next();
}

app.get('/', async (req, res) => {
  const doctors = await query('SELECT doctor_id, name, department FROM Doctors ORDER BY doctor_id ASC LIMIT 4').catch(() => []);
  const notices = [
    { title: '개인정보 보호 안내', date: '2026-03-19' },
    { title: '외래 진료 예약 절차 변경 안내', date: '2026-04-02' },
    { title: '건강검진 예약 운영시간 공지', date: '2026-04-01' },
    { title: '내원 전 준비사항 안내', date: '2026-03-31' }
  ];
  res.render('index', { doctors, notices });
});

app.get('/login', (req, res) => {
  res.render('auth/login', { error: null });
});

app.post('/login', loginLimiter, async (req, res) => {
  const { login_id, password } = req.body;
  try {
    const users = await query(
      'SELECT user_id, login_id, password, role FROM Users WHERE login_id = ? LIMIT 1',
      [login_id]
    );

    if (!users.length) {
      appLog(
        '로그인 실패',
        `존재하지 않는 계정 login_id=${login_id}`,
        req
      );

      return res.status(401).render('auth/login', { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }

    const user = users[0];

    if (user.password !== password) {
      appLog(
        '로그인 실패',
        `비밀번호 불일치 login_id=${login_id}`,
        req
      );

      return res.status(401).render('auth/login', { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }

    req.session.user = {
      user_id: user.user_id,
      login_id: user.login_id,
      role: user.role,
      patient_id: null,
      display_name: user.login_id
    };

    await logAccess(user.user_id, 'LOGIN', req);

    appLog(
      '로그인 성공',
      `사용자=${user.login_id} 권한=${user.role}`,
      req
    );

    return res.redirect('/');
  } catch (err) {
    appLog(
      '로그인 오류',
      `login_id=${login_id} 오류=${err.message}`,
      req
    );

    console.error(err);
    return res.status(500).render('auth/login', { error: '로그인 처리 중 오류가 발생했습니다.' });
  }
});

app.get('/signup', (req, res) => {
  res.render('auth/signup', { error: null, success: null });
});

app.post('/signup', async (req, res) => {
  console.log("🔥 signup 들어옴");

  const { login_id, password, role, name, birth_date, gender, phone } = req.body;

  appLog(
    '회원가입 시도',
    `login_id=${maskForLog(login_id)} 이름=${maskForLog(name)}`,
    req
  );

  try {
    const [result] = await pool.query(
      `INSERT INTO Users (login_id, password, role)
       VALUES (?, ?, ?)`,
      [login_id, password, role]
    );

    const user_id = result.insertId;

    await pool.query(
      `INSERT INTO Patients (user_id, name, birth_date, gender, phone)
       VALUES (?, ?, ?, ?, ?)`,
      [user_id, name, birth_date, gender, phone]
    );

    appLog(
      '회원가입 성공',
      `login_id=${maskForLog(login_id)} 이름=${maskForLog(name)}`,
      req
    );

    return res.redirect('/login');

  } catch (err) {
    appLog(
      '회원가입 오류',
      `login_id=${maskForLog(login_id)} 오류=${err.code || '처리 실패'}`,
      req
    );

    console.error("회원가입 에러:", err);
    return res.status(500).send("회원가입 실패");
  }
});

app.post('/logout', requireLogin, async (req, res) => {
  const userId = req.session.user.user_id;
  const loginId = req.session.user.login_id;
  await logAccess(userId, 'LOGOUT', req);

  appLog(
    '로그아웃',
    `사용자=${loginId}`,
    req
  );

  req.session.destroy(() => res.redirect('/'));
});

app.get('/mypage', requireLogin, requirePatient, async (req, res) => {
  try {
    const users = await query(
      'SELECT user_id, login_id, role FROM Users WHERE user_id = ? LIMIT 1',
      [req.session.user.user_id]
    );

    const user = users[0];
    if (!user) {
      return res.status(404).render('auth/forbidden', { message: '사용자 정보를 찾을 수 없습니다.' });
    }

    await logAccess(req.session.user.user_id, 'VIEW_SELF_RECORDS', req);

    res.render('auth/mypage', {
      patient: {
        patient_id: null,
        name: user.login_id,
        birth_date: null,
        gender: null,
        phone: null
      },
      records: []
    });
  } catch (err) {
    console.error(err);
    res.status(500).render('auth/forbidden', { message: '마이페이지 조회 중 오류가 발생했습니다.' });
  }
});

app.get('/check/db', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');

    appLog(
      'DB 점검 성공',
      '경로=/check/db',
      req
    );

    res.json({
      status: 'success',
      message: 'DB 연결 성공',
      rows
    });
  } catch (err) {
    appLog(
      'DB 점검 실패',
      `오류=${err.message}`,
      req
    );

    console.error('DB 체크 오류:', err.message);
    res.status(500).json({
      status: 'fail',
      message: 'DB 연결 실패',
      error: err.message
    });
  }
});

app.get('/check/zabbix', async (req, res) => {
  try {
    const response = await axios.post(
      process.env.ZABBIX_URL,
      {
        jsonrpc: '2.0',
        method: 'apiinfo.version',
        params: [],
        id: 1
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000
      }
    );

    appLog(
      'Zabbix 점검 성공',
      `버전=${response.data && response.data.result ? response.data.result : 'unknown'}`,
      req
    );

    res.json({
      status: 'success',
      message: 'Zabbix 서버 연결 성공',
      result: response.data
    });
  } catch (err) {
    appLog(
      'Zabbix 점검 실패',
      `오류=${err.message}`,
      req
    );

    console.error('Zabbix 체크 오류:', err.message);
    res.status(500).json({
      status: 'fail',
      message: 'Zabbix 서버 연결 실패',
      error: err.message
    });
  }
});

app.get('/guide/:section', (req, res) => {
  const section = req.params.section;
  const allowed = {
    medical: { title: '진료안내', items: menuData.medical },
    usage: { title: '이용안내', items: menuData.usage },
    about: { title: '병원소개', items: menuData.about }
  };
  if (!allowed[section]) {
    return res.status(404).render('pages/not-found');
  }
  res.render('pages/list', allowed[section]);
});

app.get('/pages/:slug', (req, res) => {
  const page = pageMap[req.params.slug];
  if (!page) return res.status(404).render('pages/not-found');
  res.render('pages/detail', { page });
});

app.get('/health-info', (req, res) => {
  res.render('health/list', { title: '건강정보', items: menuData.health });
});

app.get('/health-info/:slug', (req, res) => {
  const page = healthMap[req.params.slug];
  if (!page) return res.status(404).render('pages/not-found');
  res.render('pages/detail', { page });
});

app.get('/community', (req, res) => {
  res.render('community/index', { title: '고객참여', items: menuData.community });
});

app.get('/community/notices', (req, res) => {
  res.render('community/notices', communityMap.notices);
});

app.get('/community/faq', (req, res) => {
  res.render('community/faq', communityMap.faq);
});

app.get('/reservations/new', (req, res) => {
  res.render('reservations/new', { error: null, success: null, reservationNumber: null });
});

app.post('/reservations/new', async (req, res) => {
  const { patient_name, phone, department, title, content, access_password } = req.body;
  try {
    const result = await run(
      `INSERT INTO ReservationPosts
       (patient_name, phone, department, title, content, access_password)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [patient_name, phone, department, title, content, access_password]
    );

    appLog(
      '예약 등록 성공',
      `예약번호=${result.insertId} 이름=${patient_name} 진료과=${department}`,
      req
    );

    res.render('reservations/new', {
      error: null,
      success: '예약 글이 등록되었습니다. 예약번호와 비밀번호를 따로 보관하세요.',
      reservationNumber: result.insertId
    });
  } catch (err) {
    appLog(
      '예약 등록 오류',
      `이름=${patient_name} 오류=${err.message}`,
      req
    );

    console.error(err);
    res.status(500).render('reservations/new', {
      error: '예약 글 등록 중 오류가 발생했습니다. ReservationPosts 테이블이 생성되어 있는지 확인하세요.',
      success: null,
      reservationNumber: null
    });
  }
});

app.get('/reservations/check', (req, res) => {
  res.render('reservations/check', { error: null, post: null });
});

app.post('/reservations/check', async (req, res) => {
  const { reservation_id, access_password } = req.body;
  try {
    const rows = await query(
      `SELECT reservation_id, patient_name, phone, department, title, content, created_at
       FROM ReservationPosts
       WHERE reservation_id = ? AND access_password = ? LIMIT 1`,
      [reservation_id, access_password]
    );

    if (!rows.length) {
      appLog(
        '예약 조회 실패',
        `예약번호=${reservation_id}`,
        req
      );

      return res.status(404).render('reservations/check', { error: '예약번호 또는 비밀번호가 올바르지 않습니다.', post: null });
    }

    appLog(
      '예약 조회 성공',
      `예약번호=${reservation_id}`,
      req
    );

    res.render('reservations/check', { error: null, post: rows[0] });
  } catch (err) {
    appLog(
      '예약 조회 오류',
      `예약번호=${reservation_id} 오류=${err.message}`,
      req
    );

    console.error(err);
    res.status(500).render('reservations/check', { error: '예약 조회 중 오류가 발생했습니다.', post: null });
  }
});

app.post('/reservations/delete', async (req, res) => {
  const { reservation_id, access_password } = req.body;

  try {
    const result = await run(
      `DELETE FROM ReservationPosts
       WHERE reservation_id = ? AND access_password = ?`,
      [reservation_id, access_password]
    );

    if (result.affectedRows === 0) {
      appLog(
        '예약 취소 실패',
        `예약번호=${reservation_id}`,
        req
      );

      return res.status(404).render('reservations/check', {
        error: '예약번호 또는 비밀번호가 올바르지 않습니다.',
        success: null,
        post: null
      });
    }

    appLog(
      '예약 취소 성공',
      `예약번호=${reservation_id}`,
      req
    );

    res.render('reservations/check', {
      error: null,
      success: '예약이 취소되었습니다.',
      post: null
    });

  } catch (err) {
    appLog(
      '예약 취소 오류',
      `예약번호=${reservation_id} 오류=${err.message}`,
      req
    );

    console.error(err);
    res.status(500).render('reservations/check', {
      error: '예약 취소 중 오류',
      success: null,
      post: null
    });
  }
});

app.get('/reservations/list', async (req, res) => {
  try {
    const reservations = await query(
      `SELECT reservation_id, patient_name, department, title, created_at
       FROM ReservationPosts
       ORDER BY reservation_id DESC`
    );

    appLog(
      '예약 목록 조회',
      `건수=${reservations.length}`,
      req
    );

    res.render('reservations/list', {
      pageTitle: '예약 목록',
      reservations,
      error: null
    });
  } catch (err) {
    appLog(
      '예약 목록 조회 오류',
      `오류=${err.message}`,
      req
    );

    console.error('예약 목록 조회 오류:', err);
    res.status(500).render('reservations/list', {
      pageTitle: '예약 목록',
      reservations: [],
      error: '예약목록을 불러오는 중 오류가 발생했습니다.'
    });
  }
});


app.get('/health', async (req, res) => {
  try {
    await query('SELECT 1');

    appLog(
      '헬스체크 성공',
      `DB=연결됨 서버=${process.env.SERVER_ROLE || 'onprem-web'}`,
      req
    );

    res.json({
      status: 'ok',
      server: process.env.SERVER_ROLE || 'onprem-web',
      db: 'connected',
      time: nowKST()
    });
  } catch (err) {
    appLog(
      '헬스체크 실패',
      `DB=연결실패 서버=${process.env.SERVER_ROLE || 'onprem-web'} 오류=${err.message}`,
      req
    );

    res.status(500).json({
      status: 'fail',
      server: process.env.SERVER_ROLE || 'onprem-web',
      db: 'disconnected',
      error: err.message,
      time: nowKST()
    });
  }
});

app.use((req, res) => res.status(404).render('pages/not-found'));

app.listen(PORT, 'IP_REDACTED', () => {
  console.log(`Hospital web server listening on port ${PORT}`);
});
