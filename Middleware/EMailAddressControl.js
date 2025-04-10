const EMailAddressRegex = require("../MyFunctions/EMailAddressRegex");

const EMailAddressControl = async (req, res, next) => {
  console.log("Email : ", req.params.EMailAddress);
  if (!req.params.EMailAddress || !EMailAddressRegex(req.params.EMailAddress))
    return res
      .status(400)
      .json({
        message: "Email adresi eksik veya hatalı, lütfen tekrar deneyiniz. ",
      });
  next();
};

module.exports = EMailAddressControl;