const crypto = require("crypto");

function aes256Crypto(text, userId, encrypt = true) {
  text = String(text)
  var algorithm = "aes-256-cbc";
  var key = crypto.createHash("sha256").update(userId).digest();
  var iv = crypto.createHash("md5").update(userId).digest().slice(0, 16); 

  if (encrypt) {
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    var encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
  } else {
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    var decrypted = decipher.update(text, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }
}

module.exports = aes256Crypto