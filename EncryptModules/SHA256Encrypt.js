const crypto = require("crypto");

function EncryptDataFunction(plainString, UserId) {
  plainString = String(plainString);
  UserId = String(UserId);
  try {
    var hmac = crypto.createHmac("sha256", UserId);
    hmac.update(plainString);
    var hashedValue = hmac.digest("hex");
    return hashedValue;
  } catch (err) {
    throw err;
  }
}

module.exports = EncryptDataFunction