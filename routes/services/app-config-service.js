const jwtDecode = require('jwt-decode');

class AppConfigService {

  async extractUsersInfoFromToken(req) {
    if (!req.headers.authorization) {
      const error = new Error('User must be authorized');
      error.code = 403;
      throw error;
    }
    const token = req.headers.authorization;
    const userInfo = await jwtDecode(token);

    return userInfo;
  }

}

module.exports = new AppConfigService();