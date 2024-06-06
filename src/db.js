// db.js
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: '34.34.221.182',
    user: 'root',
    password: 'capstonenutrilog',
    database: 'Nutrilog-db'
});

module.exports = pool;
