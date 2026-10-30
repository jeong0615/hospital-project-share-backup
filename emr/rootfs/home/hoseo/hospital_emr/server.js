const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./backend/db');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// API 라우터 연결
app.use('/api/auth', require('./backend/auth'));
app.use('/api/patients', require('./backend/patients'));
app.use('/api/medical-records', require('./backend/medical_records'));
app.use('/api/logs', require('./backend/logs'));


// Web 예약 목록에 필요한 항목만 조회합니다. 비밀번호·전화번호·자유 입력 내용은 반환하지 않습니다.
app.get('/api/reservations/recent', async (_req, res) => {
    try {
        const [reservations] = await db.query(
            `SELECT reservation_id, patient_name, department, title,
                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
             FROM ReservationPosts
             ORDER BY reservation_id DESC
             LIMIT 10`
        );
        res.status(200).json({ success: true, data: reservations });
    } catch (error) {
        console.error('Web 예약 조회 오류:', error);
        res.status(500).json({ success: false, message: '예약 목록을 불러오지 못했습니다.' });
    }
});

// 정적 파일 서빙 (프론트엔드 HTML, CSS, JS)
app.use(express.static('.'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, 'IP_REDACTED', () => {
    console.log(`EMR 서버가 http://IP_REDACTED:${PORT} 에서 실행 중입니다.`);
});
