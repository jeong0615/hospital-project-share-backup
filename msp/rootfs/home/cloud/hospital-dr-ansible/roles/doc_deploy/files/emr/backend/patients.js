/**
 * backend/Patients.js
 * 환자 정보 CRUD API 라우터
 */
const express = require('express');
const router = express.Router();
const db = require('./db');

// 1. 환자 목록 조회 (검색 및 필터링 지원)
// GET /api/Patients
router.get('/', async (req, res) => {
    const { search, gender } = req.query;

    // 목록 페이지에서 필요한 최근 진료일(last_visit)을 구하기 위해 LEFT JOIN 사용
    let query = `
        SELECT p.patient_id, p.name, p.gender, DATE_FORMAT(p.birth_date, '%Y-%m-%d') as birth_date, p.phone,
               DATE_FORMAT(MAX(m.visit_date), '%Y-%m-%d') as last_visit
        FROM Patients p
        LEFT JOIN MedicalRecords m ON p.patient_id = m.patient_id
        WHERE 1=1
    `;
    const params = [];

    // 검색어 필터 (환자명, 전화번호, 환자ID)
    if (search) {
        query += ` AND (p.name LIKE ? OR p.phone LIKE ? OR p.patient_id = ?)`;
        const searchParam = `%${search}%`;
        params.push(searchParam, searchParam, search);
    }

    // 성별 필터
    if (gender) {
        query += ` AND p.gender = ?`;
        params.push(gender);
    }

    query += ` GROUP BY p.patient_id ORDER BY p.patient_id DESC`;

    try {
        const [rows] = await db.query(query, params);
        res.status(200).json({ success: true, data: rows });
    } catch (error) {
        console.error('환자 목록 조회 오류:', error);
        res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

// 2. 환자 상세 정보 조회
// GET /api/Patients/:id
router.get('/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query(
            `SELECT patient_id, name, gender, DATE_FORMAT(birth_date, '%Y-%m-%d') as birth_date, phone
             FROM Patients WHERE patient_id = ?`,
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: '해당 환자를 찾을 수 없습니다.' });
        }

        res.status(200).json({ success: true, data: rows[0] });
    } catch (error) {
        console.error('환자 상세 조회 오류:', error);
        res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

// 3. 환자 신규 등록
// POST /api/Patients
router.post('/', async (req, res) => {
    const { name, birth_date, gender, phone } = req.body;

    // 필수 값 검증
    if (!name || !birth_date || !gender) {
        return res.status(400).json({
            success: false,
            message: '성명, 생년월일, 성별은 필수 입력 항목입니다.'
        });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO Patients (name, birth_date, gender, phone) VALUES (?, ?, ?, ?)',
            [name, birth_date, gender, phone || null]
        );

        res.status(201).json({
            success: true,
            message: '환자가 성공적으로 등록되었습니다.',
            patient_id: result.insertId
        });
    } catch (error) {
        console.error('환자 등록 오류:', error);
        res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

// 4. 환자 정보 수정
// PATCH /api/Patients/:id
router.patch('/:id', async (req, res) => {
    const { id } = req.params;
    const { name, birth_date, gender, phone } = req.body;

    try {
        // 수정할 데이터가 실제로 존재하는지 먼저 확인
        const [check] = await db.query('SELECT patient_id FROM Patients WHERE patient_id = ?', [id]);
        if (check.length === 0) {
            return res.status(404).json({ success: false, message: '해당 환자를 찾을 수 없습니다.' });
        }

        await db.query(
            'UPDATE Patients SET name = ?, birth_date = ?, gender = ?, phone = ? WHERE patient_id = ?',
            [name, birth_date, gender, phone || null, id]
        );

        res.status(200).json({ success: true, message: '환자 정보가 성공적으로 수정되었습니다.' });
    } catch (error) {
        console.error('환자 수정 오류:', error);
        res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

module.exports = router;