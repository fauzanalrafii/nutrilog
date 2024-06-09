require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');


async function postRegister(request, h) {
    const { name, email, password, gender, age } = request.payload;

    // Validasi apakah semua field diperlukan terisi
    if (!name || !email || !password || !gender || !age) {
        const response = h.response({
            status: 'error',
            message: 'Name, email, password, gender, and age are required'
        });
        response.code(400);
        return response;
    }

    // Validasi panjang password
    if (password.length < 8) {
        const response = h.response({
            status: 'error',
            message: 'Password must be at least 8 characters'
        });
        response.code(400);
        return response;
    }

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
                message: 'Email already registered'
            });
            response.code(400);
            return response;
        }

        // Jika email belum terdaftar, lanjutkan dengan pendaftaran
        const id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, 10);

        await connection.execute(
            'INSERT INTO users (id, name, email, password, gender, age) VALUES (?, ?, ?, ?, ?, ?)',
            [id, name, email, hashedPassword, gender, age]
        );

        const response = h.response({
            status: 'success',
            message: 'User registered successfully'
        });
        response.code(200);
        return response;
    } catch (error) {
        console.error('Error during user registration:', error);
        const response = h.response({
            status: 'error',
            message: 'Internal Server Error'
        });
        response.code(500);
        return response;
    } finally {
        connection.release();
    }
}

async function loginUser(request, h){

    const {email, password} = request.payload;

    if (!email || !password) {
        const response = h.response({
            status: 'error',
            message: 'email and password are required'
        });
        response.code(400);
        return response;
    }

    const connection = await pool.getConnection();
    let user;
    try{
        const [rows] = await connection.execute(
            'SELECT id, name, email, password, gender, age FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0){
            return h.response({
                status: 'error',
                message: 'wrong email or password'
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
            message: 'Wrong email or password'
        }).code(400);
    }

    const token = jwt.sign({user_id: user.id}, process.env.JWT_SECRET);

    delete user.password;

    return h.response ({
        status: 'success',
        message: 'Login success',
        data: {...user, token}
    }).code(200);
};

async function postPredict(request, h) {
    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Authorizarion missing'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    let decodedToken;
    try {
        decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return h.response({
            status: 'error',
            message: 'Invalid token'
        }).code(401);
    }
    
    const user_id = decodedToken.user_id;
    const id = crypto.randomUUID();
    const { food_name, carbohydrate, proteins, fat, calories } = request.payload;

    if (!food_name || !carbohydrate || !proteins || !fat || !calories) {
        const response = h.response({
            status: 'error',
            message: 'food_name, carbohydrate, proteins, fat, and calories are required'
        });
        response.code(400);
        return response;
    }

    const connection = await pool.getConnection();
    try {
        // Insert data ke tabel predictions
        await connection.execute(
            'INSERT INTO predictions (id, user_id, food_name, carbohydrate, proteins, fat, calories) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, user_id, food_name, carbohydrate, proteins, fat, calories]
        );

        // Ambil seluruh kolom dari tabel predictions yang sesuai dengan id yang baru saja dimasukkan
        const [result] = await connection.execute(
            'SELECT id, user_id, food_name, carbohydrate, proteins, fat, calories, created_at FROM predictions WHERE id = ?',
            [id]
        );

        let data = result[0]; // Gunakan hasil query untuk mendapatkan data lengkap

        // Hapus kolom updated_at dari hasil output
        delete data.updated_at;

        const response = h.response({
            status: 'success',
            message: 'Data added successfully',
            data
        });
        response.code(200);
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
}



async function fetchNutrients(request, h) {
    const { date } = request.query;

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Authorizarion missing'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    let decodedToken;
    try {
        decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return h.response({
            status: 'error',
            message: 'Invalid token'
        }).code(401);
    }

    const user_id = decodedToken.user_id;

    const connection = await pool.getConnection();
    let rows;
    try {
        const [results] = await connection.execute(
            'SELECT id, user_id, food_name, carbohydrate, proteins, fat, calories, created_at FROM predictions WHERE DATE(created_at) = ? AND user_id = ?',
            [date, user_id]
        );
        rows = results;
    } finally {
        connection.release();
    }

    // Siapkan data yang akan dikembalikan
    let data = rows.map(row => ({
        id: row.id,
        user_id: row.user_id,
        food_name: row.food_name,
        carbohydrate: row.carbohydrate,
        proteins: row.proteins,
        fat: row.fat,
        calories: row.calories,
    }));

    // Jika tidak ada data, kembalikan array kosong
    if (rows.length === 0) {
        data = [];
    }

    return h.response({
        status: 'success',
        message: 'Success fetch data',
        data
    }).code(200);
}


module.exports = {postPredict, postRegister, loginUser, fetchNutrients};