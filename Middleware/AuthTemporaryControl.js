const User = require("../Schemas/User");

const AuthTemporaryControl = async(req, res, next) => {
    var { EMailAddress} = req.params;
    var filter = { EMailAddress};

    var Auth = await User.findOne(filter);

    if ( Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. "});    
    next();
};

module.exports = AuthTemporaryControl;