const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});

// Check connection on startup (optional, for debugging)
pool.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err.code);
        console.log('Ensure MySQL is running and .env variables are set.');
    } else {
        console.log('Connected to MySQL database.');
        connection.release();
    }
});

module.exports = pool.promise();