// const storeData = require('../services/storeData');
// const registerUser = require('../services/registerUser');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const { Firestore } = require('@google-cloud/firestore');
const {userInfo} = require('os');
const pool = require('./db');


async function postRegister(request, h){
    
    const {name, email, password} = request.payload

    const user_id = crypto.randomUUID();
    const token = crypto.randomUUID();

    const hashedPassword = await bcrypt .hash(password, 10);

    const connection = await pool.getConnection();
    try{
        await connection.execute(
            'INSERT INTO users (user_id, name, email, password, token) VALUES (?, ?, ?, ?, ?)',
            [user_id, name, email, hashedPassword, token]
        );
    }finally{
        connection.release();
    }


    // const data_user = {
    //     "user_id": user_id,
    //     "name": name,
    //     "email": email,
    //     "password": hashedPassword,
    //     "token": token
    // }

    // await registerUser(name, data_user)

    const response = h.response({
        status: 'success',
        message: 'Register user berhasil, data berhasil ditambahkan',
    })
    response.code(201);
    return response;
};

async function loginUser(request, h){
    //const token = crypto.randomUUID();

    // const db = new Firestore();

    const {email, password} = request.payload;

    // let collectionRef = db.collection('user');

    // const snapshot = await collectionRef.get();

    // if(snapshot.empty){
    //     return h.response({
    //         status: 'error',
    //         message: 'Email atau password salah'
    //     }).code(400);
    // }

    // let user;
    // snapshot.forEach(doc => {
    //     user = { user_id: doc.id, ...doc.data() };
    // });

    const connection = await pool.getConnection();
    let user;
    try{
        const [rows] = await connection.execute(
            'SELECT user_id, name, email, password FROM users WHERE email = ?',
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

    const token = jwt.sign({user_id: user.user_id}, process.env.JWT_SECRET);

    delete user.password;
    delete user.user_id;

    return h.response ({
        status: 'success',
        message: 'berhasil login',
        data: user, token
    }).code(200);
};

async function postPredict(request, h){
    
    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
          status: 'error',
          message: 'Missing or invalid authorization header'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    const decodedToken = jwt.verify(token, JWT_SECRET)
    const user_id = decodedToken.user_id;

    const id = crypto.randomUUID();
    const date = new Date().toISOString().slice(0, 19).replace('T', ' ');;
    const dateCreated = date.slice(0,10);
    

    const {food_name, carbohydrate, proteins, fat, calories} = request.payload

    const data = {
        "id": id,
        "user_id": user_id, // Ensure this user_id is set correctly or dynamically if needed
        "food_name": food_name,
        "carbohydrate": carbohydrate,
        "proteins": proteins,
        "fat": fat,
        "calories": calories,
        "created_at": date,
        "dateCreated": dateCreated
    }

    // await storeData(id, data)

    const connection = await pool.getConnection();
    try {
        await connection.execute(
            'INSERT INTO predictions (id, user_id, food_name, carbohydrate, proteins, fat, calories, created_at, dateCreated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [data.id, data.user_id, data.food_name, data.carbohydrate, data.proteins, data.fat, data.calories, data.created_at, data.dateCreated]
        );

        delete(data.dateCreated);

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
            message: 'Internal Server Error'
        });
        response.code(500);
        return response;
    } finally {
        connection.release();
    }
};

async function fetchNutrients(request, h){
    const {date} = request.query

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return h.response({
          status: 'error',
          message: 'Missing or invalid authorization header'
        }).code(401);
    }

    const token = authorizationHeader.split(' ')[1];

    const JWT_SECRET = process.env.JWT_SECRET;

    const decodedToken = jwt.verify(token, JWT_SECRET);
    const userid = decodedToken.user_id;

    // const db = new Firestore();

    // let collectionRef = db.collection('prediction');

    // if(date) {
    //     collectionRef = collectionRef.where('dateCreated', 'in', [date])
    // }

    // const snapshot = await collectionRef.get();

    // if (snapshot.empty){
    //     return h.response({
    //         status: 'error',
    //         message: 'Data tidak ditemukan'
    //     }).code(400);
    // }

    // const data = [];

    // snapshot.forEach(doc => {
    //     data.push({id: doc.id, ...doc.data()});
    // });

    const connection = await pool.getConnection();
    let rows;
    try {
        const [results] = await connection.execute(
            'SELECT * FROM predictions WHERE dateCreated = ?',
            [date]
        );
        rows = results;
    } finally {
        connection.release();
    }

    if (rows.length === 0) {
        return h.response({
            status: 'error',
            message: 'Data tidak ditemukan'
        }).code(400);
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