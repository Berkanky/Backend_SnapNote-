const crypto = require('crypto');

const createVerifyCode = () => {
  return crypto.randomInt(100000, 1000000);
};

module.exports = createVerifyCode;