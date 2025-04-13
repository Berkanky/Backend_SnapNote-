const mongoose = require('mongoose');

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
    UserName:{ //Kullanıcı Adı
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
});

const User = mongoose.model('User', UserSchema);
module.exports = User