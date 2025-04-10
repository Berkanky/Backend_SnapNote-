const mongoose = require('mongoose');

var enumList = [ 'Auto_Login', 'Register', 'Login', 'Set_Password', 'Register_Email_Verification', 'Login_Email_Verification'];

const AuthTokenSchema = new mongoose.Schema({
  UserId: {
    type: String,
    required: true
  },
  TokenType: {
    type: String,
    enum: enumList,
    required: true
  },
  Token: {
    type: String,
    required: true
  },
  TokenUsed: {
    type: Boolean,
    required:true
  },
  TokenCreatedDate: {
    type: Date,
    required:true
  },
  TokenExpiredDate: {
    type: Date,
    required: true,
  }
});

var AuthToken = mongoose.model('AuthToken', AuthTokenSchema);
module.exports = AuthToken;