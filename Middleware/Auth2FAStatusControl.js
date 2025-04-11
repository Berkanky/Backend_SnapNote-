const User = require("../Schemas/User");

const Auth2FAStatusControl = async(req, res, next) => {
    var { EMailAddress} = req.params;
    var filter = { EMailAddress};

    var Auth = await User.findOne(filter);

    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. "});    
    next();
};

module.exports = Auth2FAStatusControl;