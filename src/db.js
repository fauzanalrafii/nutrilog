const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: 'YOUR_CLOUD_SQL_HOST',
    user: 'YOUR_DB_USER',
    password: 'YOUR_DB_PASSWORD',
    database: 'YOUR_DATABASE_NAME'
});

module.exports = pool;
