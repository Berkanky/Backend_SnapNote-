const Token = require("../Schemas/InvalidToken");

async function InvalidTokenControlFunction(req, res, next) {
  var {id} = req.params;
  var token = req.get("Authorization") && req.get("Authorization").split(" ")[1];
  if(!token) return res.status(401).json({ message: "Authorization token gerekli." });

  var filter = { UserId: id, JWTToken: token };
  var tokens = await Token.find(filter);
  
  if (tokens.length)  return res.status(401).json({ message: "Geçersiz veya süresi dolmuş token. Lütfen yeniden giriş yapın." });
  next();
}

module.exports = InvalidTokenControlFunction;