const User = require("../Schemas/User");

const AuthControl = async (req, res, next) => {
  var { EMailAddress } = req.params;
  var Auth = await User.findOne({EMailAddress});
  if (!Auth) return res.status(404).json({ message: " Kullanıcı bulunamadı. " });
  next();
};

module.exports = AuthControl;
