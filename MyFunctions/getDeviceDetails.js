const aes256Crypto = require("../EncryptModules/AES256Encrypt");

const getDeviceDetails = (req, res, UserId) => {
  var ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  var userAgent = req.headers["user-agent"];
  var DeviceId = req.body.DeviceId;

  ipAddress = aes256Crypto(ipAddress, UserId, (encrypt = true));
  userAgent = aes256Crypto(userAgent, UserId, (encrypt = true));
  DeviceId = aes256Crypto(DeviceId, UserId, (encrypt = true));
  return { IPAddress: ipAddress, DeviceName: userAgent, Date: new Date(), DeviceId: DeviceId };
};

module.exports = getDeviceDetails;
