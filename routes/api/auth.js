const router = require('express').Router();
const User = require('../../models/user');
const bcrypt = require('bcryptjs');
const { secret } = require('../../db/config');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const randomstring = require('randomstring');
const notify = require('../services/notification-mail-service');
const appConfigService = require('../services/app-config-service');
const utilityService = require('../services/utility-service');
const SchemaValidatorService = require('../services/schema-validator-service');

/**
 * @api {post} /api/register Register new User
 * @apiName Register User
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (Body) {String} name User's name.
 * @apiParam (Body) {String} email User's email.
 * @apiParam (Body) {String} password User's password.
 *
 * @apiParamExample {json} Body:
 *      {
 *        "name": "Nick",
 *        "email": "example@example.com",
 *        "password": "some-password",
 *      }
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "active": false,
 *       "_id": "5d7969d239396c65ca989657",
 *       "name": "5d7969d239396c65ca989657",
 *       "email": "5d7969d239396c65ca989657",
 *       "password": "$2a$10$pPDb/ZiGtRNDBflQfs6yC.rxSIy9basL4daAXDYUSCt38AFdfT3VT5BEitc.",
 *       "date": "2019-09-11T21:40:34.248Z",
 *       "token": "sNGCr2g4cGiA1ZezXo4jlYlIzF5gUVXv",
 *     }
 *
 * @apiErrorExample Email-Exists:
 *     HTTP/1.1 403 Error
 *     {
 *       "success": false,
 *       "message": "Email address is already exists in DB."
 *     }
 */
router.post('/register', async (req,res) => {
  try {
    const schemaValidatorService = new SchemaValidatorService();
    await schemaValidatorService.customSchemaValidation('register', req.body);

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findOne({ email });

    if (user) {
      return res.status(403).json({
        success: false,
        message: 'Email address is already exists in DB.'
      });
    } else {
      utilityService.isEmail(email, 'It is not an email string.', 422);

      const newUser = new User({ name, email, password });

      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hashSync(req.body.password, salt);

      const token = randomstring.generate();
      newUser.password = hash;
      newUser.token = token;

      const user = await newUser.save();
      await notify.sendEmailAfterRegister(user, token);

      res.status(201).json(user);
    }
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {post} /api/login Login User
 * @apiName Login User
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (Body) {String} email User's email.
 * @apiParam (Body) {String} password User's password.
 *
 * @apiParamExample {json} Body:
 *      {
 *        "email": "example@example.com",
 *        "password": "some-password",
 *      }
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiErrorExample No-Account-Found:
 *     HTTP/1.1 404 Error
 *     {
 *       "success": false,
 *       "message": "No account found."
 *     }
 *
 * @apiErrorExample Password-Incorrect:
 *     HTTP/1.1 403 Error
 *     {
 *       "success": false,
 *       "message": "Password is incorrect."
 *     }
 *
 * @apiErrorExample Account-Not-Active:
 *     HTTP/1.1 403 Error
 *     {
 *       "success": false,
 *       "message": "Your account is not active."
 *     }
 */
router.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  let errors = {};

  try {
    utilityService.isEmail(email, 'It is not an email string.', 422);

    const schemaValidatorService = new SchemaValidatorService();
    await schemaValidatorService.customSchemaValidation('login', req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'No account found.'
      });
    }

    if (!user.active) {
      return res.status(400).json({
        success: false,
        message: 'Your account is not active.'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const payload = {
        id: user._id,
        name: user.name
      };
      jwt.sign(payload, secret, {expiresIn: 36000}, (err, token) => {
        if (err) res.status(500).json({ error: 'Error signing token', raw: err });
        res.set({ 'Content-Type': 'application/json', 'Authorization': token });
        res.redirect('/api/profile');
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Password is incorrect.'
      });
    }
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {post} /api/confirm-activate?name=Robin&token=JASd1AS4dr7uijsd4TJU Confirm Activate User
 * @apiName Activate User
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (params) {String} name User's name.
 * @apiParam (params) {String} token User's token for activating account.
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "User activated successfully"
 *     }
 *
 *
 * @apiErrorExample Token-Incorrect:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "Token is incorrect."
 *     }
 */
router.post('/confirm-activate', async (req, res) => {
  try {
    const token = req.query.token;
    const name = req.query.name;

    const user = await User.findOne({ name });

    if (token !== user.token) {
      return res.status(422).json({
        success: false,
        message: 'Token is incorrect.'
      })
    }

    if (!user.active) {
      user.active = true;
      user.token = randomstring.generate();
      await user.save();
    }

    res.status(201).json({
      success: true,
      message: 'User activated successfully'
    });
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {post} /api/change-password Change User Password
 * @apiName Change User Password
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (Body) {String} email User's email.
 * @apiParam (Body) {String} password User's password.
 *
 * @apiParamExample {json} Body:
 *      {
 *        "password": "old password",
 *        "newPassword": "new-password",
 *        "newPassword2": "repeat-password",
 *      }
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "User password was changed."
 *     }
 *
 *
 * @apiErrorExample No-Account-Found:
 *     HTTP/1.1 401 Error
 *     {
 *       Unauthorized
 *     }
 *
 * @apiErrorExample Current-Password-Incorrect:
 *     HTTP/1.1 403 Error
 *     {
 *       "success": false,
 *       "message": "Current password is incorrect."
 *     }
 *
 * @apiErrorExample User-Not-Defined:
 *     HTTP/1.1 403 Error
 *     {
 *       "success": false,
 *       "message": "User is not defined."
 *     }
 *
 * @apiErrorExample Account-Not-Active:
 *     HTTP/1.1 400 Error
 *     {
 *       "success": false,
 *       "message": "Your account is not active."
 *     }
 *
 * @apiErrorExample Password-Not-Match:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "Password should be equal two times."
 *     }
 *
 * @apiErrorExample Password-Not-Match:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "Password should be different."
 *     }
 */
router.post('/change-password', passport.authenticate('jwt', {session: false}), async (req, res) => {
  const password = req.body.password;
  const newPassword = req.body.newPassword;
  const newPassword2 = req.body.newPassword2;
  const { name } = await appConfigService.extractUsersInfoFromToken(req);

  try {
    const schemaValidatorService = new SchemaValidatorService();
    await schemaValidatorService.customSchemaValidation('change-password', req.body);

    const user = await User.findOne({ name });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User is not defined.'
      });
    }

    if (!user.active) {
      return res.status(400).json({
        success: false,
        message: 'Your account is not active.'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(422).json({
        success: false,
        message: 'Current password is incorrect.'
      });
    }

    if (newPassword !== newPassword2) {
      return res.status(422).json({
        success: false,
        message: 'Password should be equal two times.'
      });
    }

    if (password === newPassword2) {
      return res.status(422).json({
        success: false,
        message: 'Password should be different.'
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hashSync(req.body.newPassword2, salt);

    user.password = hash;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'User password was changed.'
    });
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {post} /api/recover-password Recover Password
 * @apiName Recover Password
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (Body) {String} email User's email.
 * @apiParam (Body) {String} password User's password.
 *
 * @apiParamExample {json} Body:
 *      {
 *        "name": "Smith",
 *        "email": "example@gmail.com"
 *      }
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "Confirmation email was sent to your email."
 *     }
 *
 * @apiErrorExample User-Not-Found:
 *     HTTP/1.1 404 Error
 *     {
 *       "success": false,
 *       "message": "User was not found."
 *     }
 *
 * @apiErrorExample User-Not-Defined:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "Your account is not active."
 *     }
 *
 * @apiErrorExample Information-Incorrect:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "User name or email is incorrect."
 *     }
 */
router.post('/recover-password', async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;

  try {
    utilityService.isEmail(email, 'It is not an email string.', 422);

    const schemaValidatorService = new SchemaValidatorService();
    await schemaValidatorService.customSchemaValidation('recover-password', req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User was not found.'
      })
    }

    if (!user.active) {
      return res.status(422).json({
        success: false,
        message: 'Your account is not active.'
      });
    }

    if (user.email !== email || name !== user.name) {
      return res.status(422).json({
        success: false,
        message: 'User name or email is incorrect.'
      })
    }

    const token = randomstring.generate();
    user.token = token;

    await Promise.all([user.save(), notify.sendMailAfterRecoverPassword(user, token)]);

    res.status(200).json({
      success: true,
      message: 'Confirmation email was sent to your email.'
    })
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {post} /api/confirm-recover-password Confirm Recover Password
 * @apiName Confirm Recover Password
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiParam (params) {String} name User's name.
 * @apiParam (params) {String} token User's token for recover password.
 *
 * @apiSuccess {String} success indicates the status of procedure.
 * @apiSuccess {String} token indicates which user was created.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "Password was reseted. Please wait for email."
 *     }
 *
 * @apiErrorExample Confirmation-Token-Incorrect:
 *     HTTP/1.1 422 Error
 *     {
 *       "success": false,
 *       "message": "Confirmation token is incorrect."
 *     }
 */
router.post('/confirm-recover-password', async (req, res) => {
  try {
    const token = req.query.token;
    const name = req.query.name;

    const user = await User.findOne({ name });

    if (user.token !== token) {
      return res.status(422).json({
        success: false,
        message: 'Confirmation token is incorrect.'
      });
    }

    const resetedPassword = randomstring.generate(10);
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hashSync(resetedPassword, salt);

    user.password = hash;
    user.token = randomstring.generate();
    await Promise.all([user.save(), notify.sendEmailWithResetedPassword(user, resetedPassword)]);

    res.status(201).json({
      success: true,
      message: 'Password was reseted. Please wait for email.'
    });
  } catch (e) {
    const code = e.code ? e.code : 500;
    const message = e.message ? e.message : 'Server error.';
    res.status(e.code).json({ code, message });
  }
});

/**
 * @api {get} /api/profile Get User's Profile
 * @apiName Get User's Profile
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiSuccess {String} token user's token.
 * @apiSuccess {Boolean} active user's active status.
 * @apiSuccess {Number/null} googleId google's account id.
 * @apiSuccess {Number/null} faceBookId facebook's account id.
 * @apiSuccess {String} _id user's id.
 * @apiSuccess {String} name user's name.
 * @apiSuccess {String} email user's email.
 * @apiSuccess {String} password user's password.
 * @apiSuccess {String} date date of creatin account.
 *
 * @apiSuccessExample Success-Response:
 *     {
 *        "token": "hWL6eQRisuu0H8tnYqmewLl8kPDLFUYG",
 *        "active": true,
 *        "googleId": null,
 *        "faceBookId": null,
 *        "_id": "5d7969d239396c65ca989657",
 *        "name": "Josh",
 *        "email": "andrii.zilnyk@gmail.com",
 *        "password": "$2a$10$pPDb/ZiGtRNDBflQfs6yC.rxSIy9bXDYUSCt38AFdfT3VT5BEitc.",
 *        "date": "2019-09-11T21:40:34.248Z",
 *        "__v": 0
 *     }
 *
 */
router.get('/profile', passport.authenticate('jwt', {session: false}), async (req, res) => {
  const { name } = await appConfigService.extractUsersInfoFromToken(req);
  const user = await User.findOne({ name });
  res.status(200).json(user);
});

/**
 * @api {post} /api/logout Logout
 * @apiName Logout User
 * @apiGroup User
 *
 * @apiVersion 1.0.0
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 */
router.get('/logout', (req, res) => {
  req.logout();
  res.send(null)
});

module.exports = router;