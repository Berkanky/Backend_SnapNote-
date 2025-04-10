const crypto = require("crypto");

function generateMongoId() {
  // 12 bayt uzunluğunda rastgele bir buffer oluştur
  var randomBytes = crypto.randomBytes(12);

  // Buffer'ı hexadecimal string formatına çevir
  var mongoId = randomBytes.toString("hex");

  return mongoId;
}

module.exports = generateMongoId;
