const jwt = require("jsonwebtoken");
require("dotenv").config(); // .env dosyasını yükler

var secret_key = process.env.SECRET_KEY;

const CreateJWTToken = async (req, res, EMailAddress, UserId) => {
  var token = jwt.sign(
    { EMailAddress: EMailAddress, UserId: UserId }, // Token'da saklanacak payload
    secret_key, // Gizli anahtar (Çevre değişkeninde saklayın)
    { expiresIn: "5h" } // Token'ın geçerlilik süresi
  );

  if (!token) return res.status(404).json({ message: " Token oluşturulamadı. " });

  return token;
};

module.exports = CreateJWTToken;
