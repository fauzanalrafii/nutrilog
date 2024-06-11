require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getConnection } = require('./db');
const { omit, formatStringToDate, formatDateToString, omitFromArray } = require('./utils');

async function postRegister(request, h) {
    const { name, email, password, gender, date_of_birth } = request.payload;

    if (!name || !email || !password || !gender || !date_of_birth) {
        return h.response({
            status: 'error',
            message: 'Name, email, password, gender, and age are required'
        }).code(400);
    } else if (password.length < 8) {
        return h.response({
            status: 'error',
            message: 'Password must be at least 8 characters'
        }).code(400);
    } else if(gender !== "female" && gender !== "male"){
        return h.response({
            status: 'error',
            message: 'Gender must be male or female'
        }).code(400);
    }

    const db = await getConnection();
    try {
        const [rows] = await db.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (rows.length > 0) {
            return h.response({
                status: 'error',
                message: 'Email already registered'
            }).code(400);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const formattedDateOfBirth = formatStringToDate(date_of_birth).split('T')[0];
        await db.execute(
            'INSERT INTO users (name, email, password, gender, date_of_birth) VALUES (?, ?, ?, ?, ?)',
            [name, email, hashedPassword, gender, formattedDateOfBirth]
        );

        return h.response({
            status: 'success',
            message: 'User registered successfully'
        }).code(200);
    } catch (error) {
        console.error('Error during user registration:', error);
        return h.response({
            status: 'error',
            message: 'Internal Server Error'
        }).code(500);
    }
}

async function loginUser(request, h) {
    const { email, password } = request.payload;

    if (!email || !password) {
        return h.response({
            status: 'error',
            message: 'Email and password are required'
        }).code(400);
    }

    const db = await getConnection();
    let user;
    try {
        const [rows] = await db.execute(
            'SELECT id, name, email, password, gender, date_of_birth FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return h.response({
                status: 'error',
                message: 'Wrong email or password'
            }).code(400);
        }

        user = rows[0];
    } catch (error) {
        console.error('Error during user login:', error);
        return h.response({
            status: 'error',
            message: 'Internal Server Error'
        }).code(500);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return h.response({
            status: 'error',
            message: 'Wrong email or password'
        }).code(400);
    }
    

    const token = jwt.sign({ user_id: user.id }, process.env.JWT_SECRET);
    const userWithoutPassword = omit(user, 'password');

    return h.response({
        status: 'success',
        message: 'Login success',
        data: {
            ...userWithoutPassword,
            date_of_birth: formatDateToString(user.date_of_birth),
            token
        }
    }).code(200);
}

async function postPredict(request, h) {
    const { food_name, carbohydrate, proteins, fat, calories } = request.payload;

    if (!food_name || !carbohydrate || !proteins || !fat || !calories) {
        return h.response({
            status: 'error',
            message: 'Food name, carbohydrate, proteins, fat, and calories are required'
        }).code(400);
    }

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Authorization missing'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    let decodedToken;
    try {
        decodedToken = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
    } catch (err) {
        console.error('Token verification error:', err);
        return h.response({
            status: 'error',
            message: 'Invalid token'
        }).code(401);
    }

    const db = await getConnection();
    try {
        const [result] = await db.execute(
            'INSERT INTO nutrients (user_id, food_name, carbohydrate, proteins, fat, calories) VALUES (?, ?, ?, ?, ?, ?)',
            [decodedToken.user_id, food_name, carbohydrate, proteins, fat, calories]
        );

        const [rows] = await db.execute(
            'SELECT * FROM nutrients WHERE id = ?',
            [result.insertId]
        );

        let data = rows[0];
        const nutrientsWithoutUpdatedAt = omit(data, 'updated_at');

        return h.response({
            status: 'success',
            message: 'Data added successfully',
            data: nutrientsWithoutUpdatedAt
        }).code(200);
    } catch (err) {
        console.error('Error during analyze:', err);
        return h.response({
            status: 'error',
            message: 'Internal Server Error'
        }).code(500);
    }
}

async function fetchNutrients(request, h) {
    const { date } = request.query;

    if (!date) {
        return h.response({
            status: 'error',
            message: 'Date is required'
        }).code(400);
    }

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
            status: 'error',
            message: 'Authorization missing'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];
    let decodedToken;
    try {
        decodedToken = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
    } catch (err) {
        console.error('Token verification error:', err);
        return h.response({
            status: 'error',
            message: 'Invalid token'
        }).code(401);
    }

    const connection = await getConnection();
    let rows;
    try {
        const [results] = await connection.execute(
            'SELECT * FROM nutrients WHERE DATE(created_at) = ? AND user_id = ?',
            [date, decodedToken.user_id]
        );
        rows = results;
    } catch (err) {
        console.error('Error during fetchNutrients:', err);
        return h.response({
            status: 'error',
            message: 'Internal Server Error'
        }).code(500);
    }

    const data = omitFromArray(rows, 'updated_at');

    return h.response({
        status: 'success',
        message: 'Data fetched successfully',
        data
    }).code(200);
}

module.exports = { postRegister, loginUser, postPredict, fetchNutrients };
