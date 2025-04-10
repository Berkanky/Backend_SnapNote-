const mongoose = require('mongoose');

const TokenSchema = new mongoose.Schema({
    UserId:{
        type:String,
        required:true
    },
    JWTToken:{
        type:String,
        required:false
    },
    JWTTokenExpireDate:{
        type:Date,
        required:false
    },
});

const Token = mongoose.model('Token', TokenSchema);
module.exports = Token