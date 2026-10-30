/**
 * backend/auth.js
 * 로그인 및 인증 처리 API 모듈 (테스트 하드코딩 포함)
 */
const express = require('express');
const router = express.Router();
const db = require('./db'); // MySQL 커넥션 풀을 가져옴

// 로그인 API (POST /api/auth/login)
router.post('/login', async (req, res) => {
    const { login_id, password } = req.body;
console.log("로그인 요청 접수됨!");
    // 1. 유효성 검사
    if (!login_id || !password) {
        return res.status(400).json({
            success: false,
            message: '아이디와 비밀번호를 모두 입력해주세요.'
        });
    }
    // ...
    // ==========================================
    // [테스트용 하드코딩 계정 확인]
    // 환경변수 기반 테스트 계정일 때 임시 계정으로 로그인 처리
    const testUsers = {
        'admin': { user_id: 999, login_id: 'admin', role: 'ADMIN', name: '임시관리자' },
        'pa':    { user_id: 998, login_id: 'pa', role: 'PA', name: '임시간호사' },
        'doc':   { user_id: 997, login_id: 'doc', role: 'DOC', name: '임시의사' }
    };

    if (testUsers[login_id] && process.env.EMR_TEST_ACCOUNT_PASSWORD && password === process.env.EMR_TEST_ACCOUNT_PASSWORD) {
        const user = testUsers[login_id];
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 접근 로그 기록 (유저 ID 999 등이 Users 테이블에 없어 발생할 수 있는 외래키 에러 방지)
        await db.query(
            'INSERT INTO AccessLogs (user_id, action_type, access_time, ip_address) VALUES (?, ?, NOW(), ?)',
            [user.user_id, 'LOGIN', ipAddress]
        ).catch(err => console.log('※ 테스트 계정 로그인: DB 로그 기록 생략 (정상)'));

        return res.status(200).json({
            success: true,
            message: '테스트 계정 로그인 성공',
            data: user
        });
    }
    // ==========================================

    try {
        // 2. DB에서 유저 정보 조회 (테스트 계정이 아닌 경우)
        const [Users] = await db.query(
            'SELECT user_id, login_id, role, name, password FROM Users WHERE login_id = ?',
            [login_id]
        );

        if (Users.length === 0) {
            return res.status(401).json({
                success: false,
                message: '아이디 또는 비밀번호를 확인해주세요.'
            });
        }

        const user = Users[0];

        // 3. 비밀번호 검증
        if (user.password !== password) {
            return res.status(401).json({
                success: false,
                message: '아이디 또는 비밀번호를 확인해주세요.'
            });
        }

        // 4. 로그인 성공 시 접근 로그(AccessLogs) 기록
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        await db.query(
            'INSERT INTO AccessLogs (user_id, action_type, access_time, ip_address) VALUES (?, ?, NOW(), ?)',
            [user.user_id, 'LOGIN', ipAddress]
        );

        // 5. 프론트엔드 세션(sessionStorage)에 저장할 정보 반환 (보안상 비밀번호 제외)
        const { password: _, ...userInfo } = user;

        return res.status(200).json({
            success: true,
            message: '로그인에 성공했습니다.',
            data: userInfo // { user_id, login_id, role, name }
        });

    } catch (error) {
        console.error('Login API Error:', error);
        return res.status(500).json({
            success: false,
            message: '서버 내부 오류가 발생했습니다.'
        });
    }
});

module.exports = router;
