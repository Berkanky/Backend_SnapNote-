const crypto = require("crypto");

function aes256Decrypt(encryptedText, userId) {
  encryptedText = String(encryptedText);
  var algorithm = "aes-256-cbc";
  var key = crypto.createHash("sha256").update(userId).digest();
  var iv = crypto.createHash("md5").update(userId).digest().slice(0, 16);

  var decipher = crypto.createDecipheriv(algorithm, key, iv);
  var decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = aes256Decrypt;