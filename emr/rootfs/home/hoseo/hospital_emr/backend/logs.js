/**
 * backend/logs.js
 * 시스템 접근 로그(Access Logs) API 라우터
 */
const express = require('express');
const router = express.Router();
const db = require('./db');

// 1. 접근 로그 목록 조회 (ADMIN 전용)
// GET /api/logs
router.get('/', async (req, res) => {
    // 프론트엔드의 actionFilter, dateFilter, searchLog 값을 쿼리 파라미터로 받습니다.
    const { search, action, date } = req.query;

    let query = `
        SELECT log_id, user_id, action_type,
               DATE_FORMAT(access_time, '%Y-%m-%dT%H:%i:%s') as access_time,
               ip_address
        FROM AccessLogs
        WHERE 1=1
    `;
    const params = [];

    // 검색어 필터 (사용자 ID 또는 IP 주소)
    if (search) {
        query += ` AND (user_id LIKE ? OR ip_address LIKE ?)`;
        const searchParam = `%${search}%`;
        params.push(searchParam, searchParam);
    }

    // 액션 타입 필터 (LOGIN, VIEW_EMR, EDIT_PATIENT 등)
    if (action) {
        query += ` AND action_type = ?`;
        params.push(action);
    }

    // 날짜 필터 (YYYY-MM-DD 형식 매칭)
    if (date) {
        query += ` AND DATE(access_time) = ?`;
        params.push(date);
    }

    // 최신 로그가 먼저 보이도록 정렬
    query += ` ORDER BY log_id DESC`;

    try {
        const [logs] = await db.query(query, params);
        res.status(200).json({ success: true, data: logs });
    } catch (error) {
        console.error('로그 조회 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

// 2. 새로운 로그 기록 추가 (내부 API 호출 및 프론트엔드 요청용)
// POST /api/logs
router.post('/', async (req, res) => {
    const { user_id, action_type } = req.body;

    if (!user_id || !action_type) {
        return res.status(400).json({
            success: false,
            message: '사용자 ID와 액션 타입이 필요합니다.'
        });
    }

    // 요청 헤더를 통해 IP 주소 추출
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        await db.query(
            'INSERT INTO AccessLogs (user_id, action_type, access_time, ip_address) VALUES (?, ?, NOW(), ?)',
            [user_id, action_type, ipAddress]
        );

        res.status(201).json({ success: true, message: '로그가 성공적으로 기록되었습니다.' });
    } catch (error) {
        console.error('로그 기록 오류:', error);
        res.status(500).json({ success: false, message: '서버 내부 오류가 발생했습니다.' });
    }
});

module.exports = router;