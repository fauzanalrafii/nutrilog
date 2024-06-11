const mysql = require('mysql2/promise');
require('dotenv').config();


const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    timezone: 'Z'
};

let connection;

const getConnection = async () => {
    if (!connection) {
        connection = await mysql.createConnection(dbConfig);
    }
    return connection;
};

module.exports = {
    getConnection
};
