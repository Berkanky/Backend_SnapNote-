//AES256 Decrypt Device details.
const aes256Decrypt = require("../EncryptModules/AES256Decrypt");

const ReadDeviceDetails = (Auth) => {
  var decryptedIPAddress, decryptedDeviceName;
  if (Auth.DeviceDetails.length) {
    if (Auth.DeviceDetails[0]["IPAddress"]) {
      decryptedIPAddress = aes256Decrypt(
        Auth.DeviceDetails[0]["IPAddress"],
        Auth.UserId
      );
    }
    if (Auth.DeviceDetails[0]["DeviceName"]) {
      decryptedDeviceName = aes256Decrypt(
        Auth.DeviceDetails[0]["DeviceName"],
        Auth.UserId
      );
    }

    Auth.DeviceDetails[0]["DeviceName"] = decryptedDeviceName;
    Auth.DeviceDetails[0]["IPAddress"] = decryptedIPAddress;

    return Auth;
  }
};

module.exports = ReadDeviceDetails;
