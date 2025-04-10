const express = require("express");
const app = express.Router();

//Node-Cache.
const NodeCache = require( "node-cache" );
const ServerCache = new NodeCache({ 
  stdTTL: 900, // 15 dakika
  checkperiod: 120 // 2 dakikada bir temizlik
});

//Şemalar.
const User = require("../Schemas/User");
const Token = require("../Schemas/InvalidToken");
const Folder = require("../Schemas/FolderSchema");
const Note = require("../Schemas/NoteSchema");
const Log = require("../Schemas/Log");
const AuthToken = require("../Schemas/AuthToken");

//Fonksiyonlar.
const getDeviceDetails = require("../MyFunctions/getDeviceDetails");
const createVerifyCode = require("../MyFunctions/GenerateVerifyCode");
const FormatDateFunction = require("../MyFunctions/FormatDateFunction");
const formatBytes = require("../MyFunctions/FormatFileSize");
const GetMimeTypeDetail = require("../MyFunctions/GetMimeTypeDetail");
const CalculateExpireDate = require("../MyFunctions/CalculateExpireDate");

//Encryp Fonksiyonlar.
var EncryptDataFunction = require("../EncryptModules/SHA256Encrypt");
var aes256Crypto = require("../EncryptModules/AES256Encrypt");
var aes256Decrypt = require("../EncryptModules/AES256Decrypt");

//Handler
const asyncHandler = require("../Handler/Handler");

//Email Template.
const RegisterEmailVerification = require("../EmailTemplates/RegisterEmailVerification");
const SetPasswordEmailVerification = require("../EmailTemplates/SetPasswordEmailVerification");
const LoginEmailVerification = require("../EmailTemplates//SigninEmailVerification");

//Middlewares.
const EMailAddressControl = require("../Middleware/EMailAddressControl");
const rateLimiter = require("../Middleware/RateLimiter");
const AuthControl = require("../Middleware/AuthControl");
const InvalidTokenControlFunction = require("../Middleware/InvalidTokenControl");

//JWT.
const AuthenticateJWTToken = require("../JWTModules/JWTTokenControl");
const CreateJWTToken = require("../JWTModules/CreateJWTToken");

const newLogFunction = async(req, res, body) => {
  
  var newLogObj = {
    UserId: body.Id,
    Action: body.Type,
    Date: new Date(),
    IPAddress: getDeviceDetails(req, res, body.Id).IPAddress,
    DeviceName: getDeviceDetails(req, res, body.Id).DeviceName,
    DeviceId: getDeviceDetails(req, res, body.Id).DeviceId
  };

  var newLog = new Log(newLogObj);
  await newLog.save();
  return newLogObj
};

const newAuthTokenFunction = async(req, res, body) => {
  var ExpiredDate = new Date().getTime() + 15 * 60 * 1000;

  var newAuthTokenObj = {
    UserId: body.Id,
    TokenType: body.Type,
    Token: body.Token,
    TokenUsed: false,
    TokenCreatedDate: new Date(),
    TokenExpiredDate: ExpiredDate
  };

  var newAuthToken = new AuthToken(newAuthTokenObj);
  await newAuthToken.save();
  return newAuthTokenObj
};

const newTokenFunction = async(req, res, body) => {
  var newTokenObj = {
    UserId: body.Id,
    JWTToken: body.Token,
    JWTTokenExpireDate: new Date()
  };

  var newToken = new Token(newTokenObj);
  await newToken.save();
  return newTokenObj;
};

//Kayıt Ol Doğrulama Kodu Gönder.
app.put(
  "/signup-verification/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (!Auth) {
      var newAuth = new User({
        EMailAddress: EMailAddress,
        IsTemporary: true,
      });

      await newAuth.save();
    }

    Auth = await User.findOne(filter);

    if (!Auth.IsTemporary) return res.status(409).json({ message: " Bu email ile kayıtlı bir hesap zaten mevcut. " });

    var VerificationId = await RegisterEmailVerification(EMailAddress);
    var ExpireDate = CalculateExpireDate( { hours: 0, minutes: 15});

    var createdToken = await AuthToken.findOne({
      UserId: Auth.id,
      TokenType: "Register_Email_Verification"
    });

    if ( createdToken ) {

      var update = {
        $set: {
          Token: VerificationId,
          TokenExpiredDate: ExpireDate,
          TokenCreatedDate: new Date(),
          TokenUsed: false,
        },
      };

      await AuthToken.findByIdAndUpdate(createdToken._id, update);

    } else {
      await newAuthTokenFunction(req, res, {Id: Auth.id, Type: "Register_Email_Verification", Token: VerificationId});
    }

    return res.status(200).json({
      message: " Kayıt olmak için doğrulama kodu emailinize gönderildi, lütfen emailinizi kontrol ediniz. "
    });
  })
);

//Kayıt ol Doğrulama kodu onayla.
app.put(
  "/signup-verification-confirm/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var VerificationId = req.body.VerificationId;

    if (!VerificationId) return res.status(400).json({ message: "Lütfen doğrulama kodunuzu giriniz. " });

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (!Auth.IsTemporary) return res.status(409).json({ message: "Bu email ile kayıtlı bir hesap zaten mevcut. " });

    var AuthTokenFilter = {
      UserId: Auth.id,
      TokenType: "Register_Email_Verification",
      TokenUsed: false
    };
    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    if(!createdToken) return res.status(404).json({message:' Doğrulama kodu eksik veya geçersiz, lütfen tekrar deneyiniz. '});
    if(createdToken.Token != VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if(new Date() > new Date(String(createdToken.TokenExpiredDate))) return res.status(410).json({ message: "Doğrulama kodu süresi dolmuş, lütfen tekrar deneyiniz. " });
    
    var authTokenUpdate = {
      $set:{
        TokenUsed: true
      },
      $unset:{
        Token: ''
      }
    };

    await AuthToken.findByIdAndUpdate(createdToken._id, authTokenUpdate);    

    return res.status(200).json({
      message:
        "Email başarıyla doğrulandı, şifrenizi belirleyerek hesabınızı oluşturabilirsiniz. "
    });
  })
);

//Kayıt ol.
app.post(
  "/create-account/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var Password = req.body.Password;
    var PasswordConfirm = req.body.PasswordConfirm;

    if (!Password || !PasswordConfirm || Password !== PasswordConfirm) return res.status(400).json({ message: "Şifrenizin doğrulaması başarısız, lütfen şifrenizi tekrardan giriniz. " });

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (Auth.IsTemporary === false) return res.status(409).json({ message: "Bu email ile kayıtlı bir hesap zaten mevcut. " });

    Password = EncryptDataFunction(Password, Auth.id);

    var update = {
      $set: {
        Password: Password,
        CreatedDate: new Date(),
        IsTemporary: false,
      },
    };
  
    await newLogFunction(req, res, {Id: Auth.id, Type:"Register"});
    await User.findOneAndUpdate(filter, update);

    return res
      .status(201)
      .json({ message: "Hesabınzı başarıyla oluşturdunuz, giriş yapabilirsiniz. " });
  })
);

//Kullanıcı bilgilerini çek.
app.get(
  "/auth-detail/:EMailAddress",
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async (req, res) => {
    var {EMailAddress} = req.params;
    var filter = {EMailAddress};

    var cacheKey = `Auth:${EMailAddress}`;

    var AuthInCache = ServerCache.get(cacheKey);
    if( AuthInCache) return res.status(200).json({ message: " Kullanıcı bilgileri başarıyla getirildi. ( N-C )", Auth: AuthInCache });

    var Auth = await User.findOne(filter).lean();

    if ( Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. " });

    Auth.ProfileImage = aes256Decrypt(Auth.ProfileImage, Auth._id.toString());

    ServerCache.set(cacheKey, Auth);

    return res.status(200).json({ message: " Kullanıcı oturumu başarıyla doğrulandı, notlarınızı tutmaya devam edebilirsiniz. ", Auth: Auth });
  })
);

//Şifreyi değiştir linki gönder.
app.get(
  "/set-password-verification/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (Auth.IsTemporary) return res.status(403).json({message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    
    var AuthTokenFilter = {
      UserId: Auth.id,
      TokenType: "Set_Password"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    var VerificationId = await SetPasswordEmailVerification(EMailAddress);
    var ExpireDate = CalculateExpireDate({ hours: 0, minutes: 15 });

    if(!createdToken){

      await newAuthTokenFunction(req, res, {Id: Auth.id, Type: "Set_Password", Token: VerificationId});
    }else{
      var update = {
        $set:{
          TokenCreatedDate: new Date(),
          TokenExpiredDate: ExpireDate,
          Token: VerificationId,
          TokenUsed: false,
        }
      };

      await AuthToken.findOneAndUpdate(AuthTokenFilter, update);
    }

    return res.status(200).json({ message: "Şifre yenileme linki belirttiğiniz email adresine gönderildi, lütfen email adresinizi kontrol ediniz. " });
  })
);

//Şifreyi değiştir kodunu onayla.
app.put(
  "/set-password-email-verification-confirm/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async(req, res) => {
    var { EMailAddress} = req.params;
    var VerificationId = req.body.VerificationId;

    if(!VerificationId) return res.status(400).json({message:' Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. '});

    var filter = { EMailAddress};
    var Auth = await User.findOne(filter);

    var AuthTokenFilter = {
      UserId: Auth.id,
      TokenType: "Set_Password"
    };

    var authToken = await AuthToken.findOne(AuthTokenFilter);

    if(authToken.Token !== VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if( new Date() > new Date(String(authToken.TokenExpiredDate))) return res.status(400).json({message:' Şifre sıfırlama doğrulama kodunun süresi geçmiş, lütfen tekrar deneyiniz. '});


    var authTokenUpdate = {
      $set:{
        TokenUsed: true
      },
      $unset:{
        Token: '',
        TokenExpiredDate: '',
        TokenCreatedDate: ''
      }
    };

    await AuthToken.findByIdAndUpdate(authToken._id, authTokenUpdate);

    return res.status(200).json({message:' Doğrulama kodu başarıyla onaylandı, şifrenizi değiştirebilirsiniz. '});
  })
);

//Şifreyi değiştir.
app.put(
  "/set-password/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var { Password, PasswordConfirm} = req.body;

    var filter = { EMailAddress };

    if (!Password || !PasswordConfirm || Password !== PasswordConfirm) return res.status(400).json({ message: "Şifrenizin doğrulaması başarısız, lütfen şifrenizi tekrardan giriniz. " });

    var Auth = await User.findOne(filter);

    Password = EncryptDataFunction(Password, Auth.id);

    var update = {
      $set: {
        Password: Password,
        UpdatedDate: new Date(),
      }
    };

    await User.findOneAndUpdate(filter, update);
    await newLogFunction(req, res, {Id: Auth.id, Type:"Set_Password"});

    return res.status(200).json({ message: "Şifreniz başarıyla değiştirildi, yeni şifrenizi kullanarak giriş yapabilirsiniz. " });
  })
);

//Giriş yap email 2fa doğrulama kodu gönder.
app.put(
  "/login-email-verification/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var Password = req.body.Password;

    if (!Password) return res.status(400).json({ message: " Şifre eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız." });
    if (Auth.Password !== EncryptDataFunction(Password, Auth.id)) return res.status(401).json({ message: "Email veya şifreniz hatalı, lütfen tekrar deneyiniz. " });

    var VerificationId = await LoginEmailVerification(Auth.EMailAddress);
    var ExpireDate = CalculateExpireDate({ hours: 0, minutes: 15 });
    
    var AuthTokenFilter = {
      UserId: Auth.id,
      TokenType: "Login"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);
    if(!createdToken){

      await newAuthTokenFunction(req, res, {Id: Auth.id, Type: "Login", Token: VerificationId});
    }else{
      var update = {
        TokenCreatedDate: new Date(),
        TokenExpiredDate: ExpireDate,
        Token: VerificationId,
        TokenUsed: false,
      };

      await AuthToken.findByIdAndUpdate(createdToken._id, update);
    }

    var update = {
      $set: {
        Active: false,
        TwoFAStatus: false,
      }
    };
    await User.findOneAndUpdate(filter, update);

    return res
      .status(200)
      .json({ message: "2 faktörlü doğrulama kodu emailinize başarıyla gönderildi, lütfen emailinizi kontrol ediniz. " });
  })
);

//Login servisi doğrulama kodu onayla.
app.put(
  "/login-email-verification-confirm/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var VerificationId = req.body.VerificationId;

    if (!VerificationId) return res.status(400).json({ message: " Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    var AuthTokenFilter = {
      UserId: Auth.id,
      TokenType: "Login"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    if(!createdToken) return res.status(404).json({message:' Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. '});
    if(createdToken.Token != VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if(new Date() > new Date(String(createdToken.TokenExpiredDate))) return res.status(410).json({ message: " Doğrulama kodunuz geçersiz, lütfen yeniden deneyiniz. " });
    
    var update = {
      $set: {
        TwoFAStatus: true,
      }
    };

    var authTokenUpdate = {
      $set:{
        TokenUsed: true
      },
      $unset:{
        Token: ''
      }
    };

    await AuthToken.findByIdAndUpdate(createdToken._id, authTokenUpdate);    
    await User.findOneAndUpdate(filter, update);

    return res
      .status(200)
      .json({ message: " 2FA doğrulaması başarılı. Giriş yapabilirsiniz. " });
  })
);

//Giriş yap.
app.post(
  "/login/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;

    var Password = req.body.Password;

    if (!Password) return res.status(400).json({ message: " Şifre eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);

    if (!Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen daha sonra tekrar deneyiniz. " });
    if (Auth.Password !== EncryptDataFunction(Password, Auth.id)) return res.status(401).json({ message: " Email veya şifreniz hatalı, lütfen tekrar deneyiniz. " });

    var update = {
      $set: {
        Active: true,
      },
      $unset: {
        LastLoginDate: "",
      }
    };

    await User.findOneAndUpdate(filter, update);
    await newLogFunction(req, res, {Id: Auth.id, Type:"Login"});

    var token = await CreateJWTToken(req, res, Auth.EMailAddress, Auth.id);
    if(!token) return res.status(400).json({message:' Session token oluşturulamadı, lüfen tekrar deneyiniz.'});

    var LogedAuth = await User.findOne(filter).lean();
    LogedAuth.ProfileImage = aes256Decrypt(LogedAuth.ProfileImage, LogedAuth._id.toString());

    return res
      .status(200)
      .json({ 
        message: " Giriş başarıyla gerçekleştirildi, kullanıcı oturumu aktif.  ", 
        token,
        Auth: LogedAuth
      });
  })
);

//Çıkış yap.
app.put(
  "/logout/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async (req, res) => {
    var { EMailAddress } = req.params;
    var token = req.get("Authorization") && req.get("Authorization").split(" ")[1];

    var filter = { EMailAddress };
    var Auth = await User.findOne(filter);
    
    var update = {
      $set: {
        Active: false,
        LastLoginDate: new Date(),
        TwoFAStatus: false
      }
    };

    await User.findOneAndUpdate(filter, update);
    await newTokenFunction(req, res, {Id: Auth.id, Token: token});
    await newLogFunction(req, res, {Id: Auth.id, Type:"Logout"});
    
    return res.status(200).json({ message: "Oturum başarıyla sonlandırıldı, tekrar bekleriz. " });
  })
);

//Uygulamayı kapat. ( Session Token Aktifken )
app.put(
  "/close-app/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var token = req.get("Authorization") && req.get("Authorization").split(" ")[1];
    var { EMailAddress} = req.params;

    var filter = { EMailAddress};
    var update = {
      $set:{
        TwoFAStatus: false,
        Active: false,
        LastLoginDate: new Date()
      }
    };

    var Auth = await User.findOneAndUpdate(filter, update);
    await newLogFunction(req, res, {Id: Auth.id, Type: 'Close_App'});
    await newTokenFunction(req, res, {Id: Auth.id, Token: token});

    return res.status(200).json({message:' Uygulama başarıyla kapatıldı, Tekrar bekleriz.'});
  })  
);

//Not oluştur
app.post(
  "/create-note/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req,res) => {
    var {EMailAddress} = req.params;
    var NoteDataNonEncrypted = {};
    var NoteData = req.body.NoteData;
    NoteDataNonEncrypted = JSON.parse(JSON.stringify(NoteData));

    var filter = {EMailAddress};
    var Auth = await User.findOne(filter);

    NoteData.SelectedFiles.forEach(function(item){
      item.Url = aes256Crypto(item.Url, Auth.id);
      item.Name = aes256Crypto(item.Name, Auth.id);
    });

    NoteData.Audio.forEach(function(item){
      item.Content = aes256Crypto(item.Content, Auth.id);
      item.Url = aes256Crypto(item.Url, Auth.id);
    });

    var newNoteObj = {
      UserId: Auth.id,
      NoteName: NoteData.NoteName,
      TextContent: aes256Crypto(NoteData.TextContent, Auth.id),
      TextContentHTML: aes256Crypto(NoteData.TextContentHTML, Auth.id),
      Audio:NoteData.Audio.length ?  NoteData.Audio : [],
      SelectedFiles: NoteData.SelectedFiles.length ? NoteData.SelectedFiles : []
    };
    
    var newNote = new Note(newNoteObj);
    var savedNewNote = await newNote.save();

    NoteDataNonEncrypted._id = savedNewNote._id;
    NoteDataNonEncrypted.CreatedDate = new Date();
    NoteDataNonEncrypted.CreatedDateFormatted = FormatDateFunction(new Date())

    var CacheKey = `Notes:${EMailAddress}`;
    var NotesInCache = ServerCache.get(CacheKey)
    if(NotesInCache) NotesInCache.push(NoteDataNonEncrypted), ServerCache.set(CacheKey, NotesInCache);

    return res.status(201).json({message:' Not başarıyla oluşturuldu. '});
  })
);

//Notları Getir
app.get(
  "/get-my-notes/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress} = req.params;
    var filter = {EMailAddress };

    var cacheKey = `Notes:${EMailAddress}`;
    var NotesInCache = ServerCache.get(cacheKey);
    if(NotesInCache) return res.status(200).json({ message:' Notlar başarıyla getirildi. ( N-C )', Notes: NotesInCache });

    var Auth = await User.findOne(filter);

    var NoteFilter = {UserId: Auth.id};
    var Notes = await Note.find(NoteFilter).lean();
    
    Notes.forEach(function(note){
      
      note.TextContent = aes256Decrypt(note.TextContent, Auth.id);
      note.TextContentHTML = aes256Decrypt(note.TextContentHTML, Auth.id);
      note.CreatedDateFormatted = FormatDateFunction(note.CreatedDate);

      note.Audio.forEach(function(item){
        item.Content = aes256Decrypt(item.Content, Auth.id);
        item.Url = aes256Decrypt(item.Url, Auth.id);
      });

      note.SelectedFiles.forEach(function(item){
        item.Url = aes256Decrypt(item.Url, Auth.id);
        item.Name = aes256Decrypt(item.Name, Auth.id);
        item.CreatedDateFormatted = FormatDateFunction(item.CreatedDate);
      });
    });

    ServerCache.set(cacheKey, Notes);

    return res.status(200).json({ message:' Notlar başarıyla getirildi. ', Notes});
  })
);

//Seçilin notun bilgilerini getir
app.get(
  "/note-detail/:EMailAddress/:Id",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress, Id} = req.params;
    console.log("Seçilen Notun ID'si : ", Id);
    var CacheKey = `Note:${Id}`;
    var NoteInCache = ServerCache.get(CacheKey);
    if(NoteInCache) return res.status(200).json({message:' Not detayları başarıyla getirildi. ( N-C )', Note: NoteInCache });

    var filter = {EMailAddress};
    var Auth = await User.findOne(filter);

    var note = await Note.findById(Id).lean();
    if(!note) return res.status(404).json({message:' Not bulunamadı, lütfen tekrar deneyiniz. '});
    
    note.CreatedDateFormatted = FormatDateFunction(note.CreatedDate);
    note.UpdatedDateFormatted = note.UpdatedDate ? FormatDateFunction(note.UpdatedDate) : null;
    note.TextContent = aes256Decrypt(note.TextContent, Auth.id);
    note.TextContentHTML = aes256Decrypt(note.TextContentHTML, Auth.id);

    note.SelectedFiles.forEach(function(item){
      item.CreatedDateFormatted = FormatDateFunction(item.CreatedDate);
      item.UpdatedDateFormatted = item.UpdatedDate ? FormatDateFunction(item.UpdatedDate) : null;
      item.SizeDetail = formatBytes(item.Size, 2);
      item.MimeTypeDetail = GetMimeTypeDetail(item.MimeType, item.Name);

      item.Url = aes256Decrypt(item.Url, Auth.id);
      item.Name = aes256Decrypt(item.Name, Auth.id);
    });

    note.Audio.forEach(function(item){ 
      item.Content = aes256Decrypt(item.Content, Auth.id);
      item.Url = aes256Decrypt(item.Url, Auth.id);
    });

    var update = {
      $set:{
        LastSeenDate: new Date()
      }
    };

    await Note.findByIdAndUpdate(Id, update);

    ServerCache.set(CacheKey, note);  

    return res.status(200).json({ message:" Not detayları başarıyla getirildi. ", Note: note, RequestDate: new Date()});
  })
);

//Seçili notu sil
app.delete(
  "/delete-note/:EMailAddress/:Id",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress, Id} = req.params;
    if(!Id) return res.status(400).json({message:' Lütfen silmek istediğiniz notu seçtiğinizden emin olun. '});

    var filter = {EMailAddress};
    var Auth = await User.findOne(filter);

    var NoteFilter = { UserId: Auth.id, _id: Id };
    var deletedNoted = await Note.findOneAndDelete(NoteFilter);
    if(!deletedNoted) return res.status(400).json({message:' Silme işlemi başarısız, lütfen tekrar deneyiniz.'});

    var CacheKey = `Note:${Id}`;
    var NoteInCache = ServerCache.get(CacheKey);
    if(NoteInCache) ServerCache.del(CacheKey);

    CacheKey = `Notes:${EMailAddress}`;
    var NotesInCache = ServerCache.get(CacheKey);
    if(NotesInCache) {
      NotesInCache = NotesInCache.filter(function(item){ return item._id.toString() !== Id});
      ServerCache.set(CacheKey, NotesInCache);
    }

    return res.status(200).json({message:'Seçili not başarıyla silindi. ', Id: Id});
  })
);

//Seçili notu güncelle
app.put(
  "/update-selected-note/:EMailAddress/:Id",
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress, Id} = req.params;
    var { NoteData} = req.body;

    var NoteDataNonEncrypted = JSON.parse(JSON.stringify(NoteData));

    if(!Id) return res.status(400).json({message: 'Lütfen güncellemek istediğiniz notu doğru bir şekilde seçtiğinizden emin olun. '});
    if(!Object.keys(NoteData).length) return res.status(400).json({message: ' Lütfen güncellemek istediğiniz notu doğru bir şekilde seçtiğinizden emin olun. '});
    
    var filter = { EMailAddress};
    var Auth = await User.findOne(filter);

    NoteData.UpdatedDate = new Date();
    NoteData.TextContent = aes256Crypto(NoteData.TextContent, Auth.id);
    NoteData.TextContentHTML = aes256Crypto(NoteData.TextContentHTML, Auth.id);

    NoteData.SelectedFiles.forEach(function(item){
      if('State' in item && item.State === "Deleted") return NoteData.SelectedFiles = NoteData.SelectedFiles.filter(function(obj){ return obj._id !== item._id});
      
      item.Url = aes256Crypto(item.Url, Auth.id);
      item.Name = aes256Crypto(item.Name, Auth.id);
    });

    NoteData.Audio.forEach(function(item){
      if('State' in item && item.State === "Deleted") return NoteData.Audio = NoteData.Audio.filter(function(obj){ return obj._id !== item._id});
      
      item.Content = aes256Crypto(item.Content, Auth.id);
      item.Url = aes256Crypto(item.Url, Auth.id);
    });

    var noteFilter = { UserId: Auth.id, _id: Id };
    var updatedNote = await Note.findOneAndUpdate(noteFilter, NoteData, {new: true});

    if(!updatedNote) return res.status(400).json({message:' Güncelleme işlemi başarısız, lütfen tekrar deneyiniz.'});

    var CacheKey = `Note:${updatedNote.id}`;
    var NoteInCache = ServerCache.get(CacheKey);  
    if(NoteInCache) {

      NoteDataNonEncrypted.UpdatedDate = new Date();
      ServerCache.set(CacheKey, NoteDataNonEncrypted);

      CacheKey = `Notes:${EMailAddress}`;
      var NotesInCache = ServerCache.get(CacheKey);
      if(NotesInCache) NotesInCache = NotesInCache.map(function(item){ return item._id.toString() === updatedNote.id ? NoteDataNonEncrypted : item}), ServerCache.set(CacheKey, NotesInCache);
    }

    return res.status(200).json({message:'Not başarıyla güncellendi. ', NoteData: {Id: updatedNote.id} });
  })
);

//Kullanıcı bilgilerini güncelle
app.put(
  "/update-user-informations/:EMailAddress",
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress} = req.params;
    var { UserData} = req.body;
    if ( !Object.keys(UserData).length) return res.status(400).json({message:' Kullanıcı bilgileri güncellenemedi, eksik veya hatalı bilgi mevcut, lütfen tekrar deneyiniz. '});

    var filter = { EMailAddress};
    var Auth = await User.findOne(filter);
    if ( !Auth) return res.status(404).json({message:' Kullanıcı bulunamadı.'});
    if ( Auth.IsTemporary === true) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. " });
    
    UserData.ProfileImage = aes256Crypto(UserData.ProfileImage, Auth.id);

    var update = {
      $set:{
        Name: UserData.Name,
        Surname: UserData.Surname,
        Bio: UserData.Bio,
        UpdatedDate: new Date(),
        ProfileImage: UserData.ProfileImage
      }
    };

    await User.findOneAndUpdate(filter, update);

    return res.status(200).json({ message:' Kullanıcı bilgileri başarıyla güncellendi. '});
  })
);

module.exports = app;