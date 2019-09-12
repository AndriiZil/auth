class UtilityService {

  isEmail(value, message, code) {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    const condition = re.test(String(value).toLowerCase());
    return this._getResult(condition, message, code);
  }

  /**
   * Get boolean result or correct error
   * @param {boolean} condition If condition equeal true - don't throw an error
   * @param {(string|null)} message Error massage.
   * @param {(number|null)} code Error code. Default: 500
   * @returns {boolean} Result of check
   */
  _getResult(condition, message, code) {
    if (condition === false && message !== null) {
      const error = new Error(message);
      error.code = (code !== null) ? code : 500;
      throw error;
    }
    return condition;
  }

}

module.exports = new UtilityService();