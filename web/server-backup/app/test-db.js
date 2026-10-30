require('dotenv').config();

const mysql = require('mysql2/promise');

(async () => {
  console.log('DB ENV:', {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    database: process.env.DB_NAME
  });

  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectTimeout: 30000    
  });

  const [rows] = await conn.query('SELECT 1 AS ok');
  console.log(rows);

  await conn.end();
})().catch((err) => {
  console.error('DB TEST ERROR:', err.code, err.message);
  process.exit(1);
});
