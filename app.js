const createError = require('http-errors');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require('mongoose');
const { mongoURI, secret } = require('./db/config');

const apiRoutes = require('./routes/apiRoutes');

const app = express();

require('./routes/passport/passport-local');
// require('./routes/passport/passport-facebook');
// require('./routes/passport/passport-google');

passport.serializeUser((user, cb)=>  {
  cb(null, user);
});

passport.deserializeUser((obj, cb) => {
  cb(null, obj);
});

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret, resave: true, saveUninitialized: true }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB successfully connected"))
    .catch(err => console.log(err));

app.use('/api', apiRoutes);

app.use((req, res, next) => {
  next(createError(404));
});

app.use((err, req, res, next) => {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  res.status(err.status || 500);
  res.json({ message: err.message });
});

module.exports = app;
