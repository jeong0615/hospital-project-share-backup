/**
 * backend/db.js
 * MySQL 데이터베이스 연결 풀 설정
 */
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'IP_REDACTED',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'hospital_db',
    waitForConnections: true,
    connectionLimit: 10,         // 동시 연결 최대 수
    queueLimit: 0
});

// 서버 구동 시 초기 DB 연결 상태 확인용
pool.getConnection()
    .then(connection => {
        console.log('MySQL DB(hospital_db) 연결 성공!');
        connection.release();
    })
    .catch(err => {
        console.error('MySQL DB 연결 실패:', err.message);
    });

module.exports = pool;
