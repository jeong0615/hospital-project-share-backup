const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// API 라우터 연결
app.use('/api/auth', require('./backend/auth'));
app.use('/api/patients', require('./backend/patients'));
app.use('/api/medical-records', require('./backend/medical_records'));
app.use('/api/logs', require('./backend/logs'));

// 정적 파일 서빙 (프론트엔드 HTML, CSS, JS)
app.use(express.static('.'));

const PORT = process.env.PORT || 3000;

app.listen(PORT, 'IP_REDACTED', () => {
    console.log(`EMR 서버가 http://IP_REDACTED:${PORT} 에서 실행 중입니다.`);
});
