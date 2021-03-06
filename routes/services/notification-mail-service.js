const nodemailer = require('nodemailer');

class NotificationMailService {

  /**
   * Create transport for email
   * @private
   */
  _createTransporter() {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: '', // Email address
        pass: '' // Password
      }
    });

    return transporter;
  }

  /**
   * Transporter send email
   * @param transporter
   * @param mailOptions
   * @private
   */
  async _transporterSendMail(transporter, mailOptions) {
    await transporter.sendMail(mailOptions, (err, info) => {
      if(err) return console.log(err);
      return info;
    });
  }

  /**
   * Send email after login
   * @returns {Promise<string>}
   */
  async sendEmailAfterRegister(user, token) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'pavelcopywriting@gmail.com',
      to: user.email,
      subject: 'User was registered.',
      html: `<h2>Dear ${user.name}</h2>
            <h3>System Notification User's Accaunt sent to you this message</h3>
            <p>We want to inform you, that you are registered your accaunt in <b><a href="">https://www.localhost.com</a></b> page.</p>
            <p>Please confirm it on address <b><a href="localhost:3000/confirm?token=${token}"><b>Confirm:<b> localhost:3000/api/confirm-activate?name=${user.name}&token=${token}</a></b></p>
            `
    };
    await this._transporterSendMail(transporter, mailOptions);
    return 'success';
  }

  /**
   * Send email after login
   * @returns {Promise<string>}
   */
  async sendEmailAfterLogIn(user) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'asdlvcom@email.com',
      to: user.email,
      subject: 'Attention! Logged User In',
      html: `<h2>Dear ${user.name}</h2>
            <h3>System Notification User's Accaunt sent to you this message</h3>
            <p>We want to inform you, that you are logged in your accaunt in <b><a href="">https://www.localhost.com</a></b> page.</p>
            `
    };
    await this._transporterSendMail(transporter, mailOptions);
    return 'success';
  }

  /**
   * Send email with reseted password
   * @param {object} user
   * @param {string} newPassword
   * @returns {Promise<string>}
   */
  async sendEmailWithResetedPassword(user, newPassword) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'asdlvcom@email.com',
      to: user.email,
      subject: 'Reset password',
      html: `<h2>Dear ${user.name}</h2>
            <h3>System Notification User's Accaunt sent to you this message</h3>
            <p>You reseted your password. Now it's <b>${newPassword}</b>.</p>
            <p>Change it please.</p>
            `
    };

    await this._transporterSendMail(transporter, mailOptions);
    return 'success';
  }

  /**
   * Send email after user creating
   * @param {object} user
   * @returns {Promise<string>}
   */
  async sendEmailAfterUserCreating({ username, creationgDate, id, smsCodeKey }) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'asdlvcom@email.com',
      to: username,
      subject: 'User was successfully created',
      html: `<h2>Dear User</h2>
            <h3>System Notification User's Accaunt Of Expedition sent to you this message</h3>
            <h4>You accaunt ${username} was created.</h4>
            <ul>
              <li>1. UserId: <b>${id}</b></li>
              <li>2. smsCodeKey: <b>${smsCodeKey}</b></li>
            </ul>
            <p>Date: ${creationgDate}</p>
            `
    };

    await this._transporterSendMail(transporter, mailOptions);
    return 'result';
  }

  /**
   * Send email after changed password
   * @param {string} newPassword
   * @param {string} username
   * @param {number} id
   * @returns {Promise<string>}
   */
  async sendEmailAfterChangedPassword(newPassword, username, id) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'asdlvcom@email.com',
      to: username,
      subject: 'User was successfully created',
      html: `<h2>Dear User</h2>
            <h3>System Notification User's Accaunt Of Expedition sent to you this message</h3>
            <h4>You password of ${username} accaunt was changed.</h4>
            <ul>
              <li>1. UserId: <b>${id}</b></li>
              <li>2. New Password: <b>${newPassword}</b></li>
            </ul>`
    };

    await this._transporterSendMail(transporter, mailOptions);
    return 'result';
  }

  async sendMailAfterRecoverPassword(user, token) {
    const transporter = this._createTransporter();

    const mailOptions = {
      from: 'asdlvcom@email.com',
      to: user.email,
      subject: 'Recover password confirmation',
      html: `<h2>Dear ${user.name}</h2>
            <h3>System Notification User's Accaunt sent to you this message</h3>
            <p>localhost:3000/api/confirm-recover-password?name=${user.name}&token=${token}</p>`
    };

    await this._transporterSendMail(transporter, mailOptions);
    return 'result';
  }

}

module.exports = new NotificationMailService();