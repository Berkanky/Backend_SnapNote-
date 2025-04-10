require("dotenv").config();

const Token = require("../Schemas/InvalidToken");
const User = require("../Schemas/User");

const jwt = require("jsonwebtoken");

var secret_key = process.env.SECRET_KEY;

const AuthenticateJWTToken = async (req, res, next) => {
  var token = req.get("Authorization") && req.get("Authorization").split(" ")[1];
  jwt.verify(token, secret_key, async(err, user) => {
    if (err) {

      var EMailAddress = req.params.EMailAddress;
      var filter = {EMailAddress: EMailAddress};
      var Auth = await User.findOne(filter);

      var isTokenInserted = await Token.findOne({UserId: Auth.id, JWTToken: token});
      if(!isTokenInserted){
        var newTokenObj = {
          UserId: Auth.id,
          JWTToken: token,
          JWTTokenExpireDate: new Date()
        };
  
        var newToken = new Token(newTokenObj);
        await newToken.save();
      }

      return res.status(403).json({ message: "Kullanıcı geçici tokeni geçersiz, oturum zaman aşımına uğramış bulunmaktadır. Lütfen tekrar deneyiniz. " });
    }
    req.user = user;
    next();
  });
};

module.exports = AuthenticateJWTToken;