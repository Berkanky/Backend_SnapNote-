const mongoose = require('mongoose');

const TrustedDevicesSchema = new mongoose.Schema(
    {
        DeviceName:{ type: String },
        Platform: { type: String },
        Type: { type: String },
        IPAddress: { type: String },
        DeviceId : { type: String }
    }
)

const UserSchema = new mongoose.Schema({
    EMailAddress:{
        type:String,
        unique:true,
        required:true
    },
    ProfileImage:{
        type:String
    },
    Name:{
        type:String
    },
    Surname:{
        type:String
    },
    Bio:{
        type:String
    },
    UserName:{
        type:String
    },
    Password:{
        type:String
    },
    CreatedDate:{
        type:Date
    },
    UpdatedDate:{
        type:Date
    },
    LastLoginDate:{
        type:Date
    },
    IsTemporary:{
        type:Boolean
    },
    TwoFAStatus:{
        type:Boolean
    },
    Active:{
        type:Boolean
    },
    IsRemindDeviceActive:{
        type:Boolean
    },
    TrustedDevices:[TrustedDevicesSchema]   
});

const User = mongoose.model('User', UserSchema);
module.exports = User