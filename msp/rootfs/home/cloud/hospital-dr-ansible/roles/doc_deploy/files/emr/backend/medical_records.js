/**
 * backend/MedicalRecords.js
 * 진료 기록(Medical Records) CRUD API 라우터
 */
const express = require('express');
const router = express.Router();
const db = require('./db');

// 1. 특정 환자의 진료 기록 목록 조회
// GET /api/medical-records/patient/:patient_id
router.get('/patient/:patient_id', async (req, res) => {
    const { patient_id } = req.params;

    try {
        // [수정] Doctors 테이블을 JOIN하여 의사의 이름(Doctor)과 진료과(department)를 정상적으로 가져옵니다.
        const [records] = await db.query(
            `SELECT m.record_id,
                    DATE_FORMAT(m.visit_date, '%Y-%m-%dT%H:%i') as visit_date,
                    m.diagnosis,
                    d.name as Doctor,
                    d.department
             FROM MedicalRecords m
             LEFT JOIN Doctors d ON m.doctor_id = d.doctor_id
             WHERE m.patient_id = ?
             ORDER BY m.visit_date DESC`,
            [patient_id]
        );

        res.status(200).json({ success: true, data: records });
    } catch (error) {
        console.error('진료 기록 조회 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

// 2. 진료 기록 신규 추가 (의사 전용)
// POST /api/medical-records
router.post('/', async (req, res) => {
    // [참고] 프론트엔드에서 doctor_id를 보내주도록 변경해야 안전합니다.
    const { patient_id, visit_date, diagnosis, doctor_id } = req.body;

    if (!patient_id || !visit_date || !diagnosis) {
        return res.status(400).json({
            success: false,
            message: '진단 내용 및 필수 항목을 모두 입력해주세요.'
        });
    }

    try {
        // [수정] 테이블 구조에 맞게 doctor_id 컬럼에 데이터를 넣습니다.
        const [result] = await db.query(
            `INSERT INTO MedicalRecords (patient_id, visit_date, diagnosis, doctor_id)
             VALUES (?, ?, ?, ?)`,
            [patient_id, visit_date, diagnosis, doctor_id || null]
        );

        res.status(201).json({
            success: true,
            message: '진료 기록이 성공적으로 추가되었습니다.',
            record_id: result.insertId
        });
    } catch (error) {
        console.error('진료 기록 추가 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

// 3. 최근 진료 기록 조회 (대시보드 노출용)
// GET /api/medical-records/recent
router.get('/recent', async (req, res) => {
    try {
        // [수정] m.department, m.Doctor 대신 Doctors 테이블을 JOIN 하여 정확한 정보를 가져옵니다.
        const [records] = await db.query(
            `SELECT p.name, d.department, DATE_FORMAT(m.visit_date, '%Y-%m-%d') as date, d.name as Doctor
             FROM MedicalRecords m
             JOIN Patients p ON m.patient_id = p.patient_id
             LEFT JOIN Doctors d ON m.doctor_id = d.doctor_id
             ORDER BY m.visit_date DESC
             LIMIT 5`
        );

        res.status(200).json({ success: true, data: records });
    } catch (error) {
        console.error('최근 진료 기록 조회 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

// 4. 월간/오늘 통계 집계 (대시보드용)
// GET /api/medical-records/stats
router.get('/stats', async (req, res) => {
    try {
        // 오늘 진료 건수
        const [[todayStat]] = await db.query(
            `SELECT COUNT(DISTINCT patient_id) as todayCount
             FROM MedicalRecords
             WHERE DATE(visit_date) = CURDATE()`
        );

        // 이번 달 진료 건수
        const [[monthStat]] = await db.query(
            `SELECT COUNT(record_id) as monthCount
             FROM MedicalRecords
             WHERE MONTH(visit_date) = MONTH(CURDATE())
               AND YEAR(visit_date) = YEAR(CURDATE())`
        );

        // 전체 환자 수
        const [[totalStat]] = await db.query('SELECT COUNT(patient_id) as totalCount FROM Patients');

        res.status(200).json({
            success: true,
            data: {
                today_visits: todayStat.todayCount,
                total_Patients: totalStat.totalCount,
                month_records: monthStat.monthCount
            }
        });
    } catch (error) {
        console.error('통계 집계 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

module.exports = router;
