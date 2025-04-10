const mongoose = require('mongoose');

var enumList = [ 'Close_App', 'Register', 'Login', 'Set_Password', 'Register_Email_Verification', 'Login_Email_Verification'];

const LogSchema = new mongoose.Schema({
    UserId:{
        type:String,
        required:true
    },
    Action:{
        type:String
    },
    Date:{
        type:Date
    },
    IPAddress:{
        type:String
    },
    DeviceName:{
        type:String
    },
    DeviceId: {
        type:String
    }
});

const Log = mongoose.model('Log', LogSchema);
module.exports = Log;