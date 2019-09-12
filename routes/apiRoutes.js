const { Router } = require('express');

const apiRoutes = Router();

const auth = require('./api/auth');
const passport = require('./api/passport');

apiRoutes.use('/', auth);
apiRoutes.use('/', passport);

module.exports = apiRoutes;