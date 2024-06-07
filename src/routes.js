const {
    postPredict,
    postRegister,
    loginUser,
    fetchNutrients
} = require('./handler');

const routes = [
    {
        method: 'POST',
        path: '/register',
        handler: postRegister,
    },
    {
        method: 'POST',
        path: '/login',
        handler: loginUser,
    },
    {
        method: 'POST',
        path: '/analiyze',
        handler: postPredict,
    },
    {
        method: 'GET',
        path: '/fetch',
        handler: fetchNutrients,
    },
    {
        method: '*',
        path: '/{any*}',
        handler: (request, h) => {
            return "Halaman belum dibuat";
        },
    },
];

module.exports = routes;