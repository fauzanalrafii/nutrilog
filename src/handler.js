require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {userInfo} = require('os');
const pool = require('./db');
const { DateTime } = require('luxon');


async function postRegister(request, h) {
    const { name, email, password } = request.payload;

    const connection = await pool.getConnection();
    try {
        // Cek apakah email sudah terdaftar
        const [rows] = await connection.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (rows.length > 0) {
            // Jika email sudah terdaftar, kirim respons dengan pesan error
            const response = h.response({
                status: 'error',
                message: 'Email sudah terdaftar',
            });
            response.code(400);
            return response;
        }

        // Jika email belum terdaftar, lanjutkan dengan pendaftaran
        const id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, 10);

        await connection.execute(
            'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
            [id, name, email, hashedPassword]
        );

        const response = h.response({
            status: 'success',
            message: 'Register user berhasil, data berhasil ditambahkan',
        });
        response.code(201);
        return response;
    } finally {
        connection.release();
    }
};

async function loginUser(request, h){

    const {email, password} = request.payload;

    const connection = await pool.getConnection();
    let user;
    try{
        const [rows] = await connection.execute(
            'SELECT id, name, email, password FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0){
            return h.response({
                status: 'error',
                message: 'Email atau password salah'
            }).code(400);
        }

        user = rows[0];
    }finally{
        connection.release();
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return h.response({
            status: 'error',
            message: 'Email atau password salah'
        }).code(400);
    }

    const token = jwt.sign({user_id: user.id}, process.env.JWT_SECRET);

    delete user.password;

    return h.response ({
        status: 'success',
        message: 'berhasil login',
        data: {...user, token}
    }).code(200);
};

async function postPredict(request, h) {
    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Header autorisasi tidak valid atau tidak ditemukan'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    const decodedToken = jwt.verify(token, JWT_SECRET);
    const user_id = decodedToken.user_id;

    const id = crypto.randomUUID();

    const { food_name, carbohydrate, proteins, fat, calories } = request.payload;

    const connection = await pool.getConnection();
    try {
        await connection.execute(
            'INSERT INTO predictions (id, user_id, food_name, carbohydrate, proteins, fat, calories) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, user_id, food_name, carbohydrate, proteins, fat, calories]
        );

        // Ambil seluruh kolom dari tabel predictions yang sesuai dengan id yang baru saja dimasukkan
        const [result] = await connection.execute(
            'SELECT * FROM predictions WHERE id = ?',
            [id]
        );

        const data = result[0]; // Gunakan hasil query untuk mendapatkan data lengkap

        const response = h.response({
            status: 'success',
            message: 'Data berhasil ditambahkan',
            data
        });
        response.code(201);
        return response;
    } catch (err) {
        console.error('Error during postPredict:', err);
        const response = h.response({
            status: 'error',
            message: 'Server Internal Error'
        });
        response.code(500);
        return response;
    } finally {
        connection.release();
    }
};


async function fetchNutrients(request, h) {
    const { date } = request.query;

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Header autorisasi tidak valid atau tidak ditemukan'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    const decodedToken = jwt.verify(token, JWT_SECRET);
    const user_id = decodedToken.user_id;

    const connection = await pool.getConnection();
    let rows;
    try {
        const [results] = await connection.execute(
            'SELECT * FROM predictions WHERE DATE(created_at) = ? AND user_id = ?',
            [date, user_id]
        );
        rows = results;
    } finally {
        connection.release();
    }

    if (rows.length === 0) {
        return h.response({
            status: 'error',
            message: 'Data tidak ditemukan'
        }).code(404); // Ganti kode respons menjadi 404 jika data tidak ditemukan
    }

    const data = rows.map(row => ({
        id: row.id,
        ...row
    }));

    return h.response({
        status: 'success',
        message: 'Berhasil mengambil data',
        data
    }).code(200);
}


module.exports = {postPredict, postRegister, loginUser, fetchNutrients};