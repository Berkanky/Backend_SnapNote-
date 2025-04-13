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
var Sha256Crypto = require("../EncryptModules/SHA256Encrypt");
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

const GetAuthDetails = async(req, res) => {
  var { EMailAddress} = req.params;
  var filter = { EMailAddress};
  var Auth = await User.findOne(filter).lean();
  return Auth
}; 

//Kayıt Ol Doğrulama Kodu Gönder.
app.put(
  "/signup-verification/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  asyncHandler(async (req, res) => {

    var { EMailAddress } = req.params;
    var Auth = await GetAuthDetails(req, res);
    
    if (!Auth) {
      var newAuth = new User({
        EMailAddress: EMailAddress,
        IsTemporary: true,
      });

      Auth = await newAuth.save();
    }

    if (!Auth.IsTemporary) return res.status(409).json({ message: " Bu email ile kayıtlı bir hesap zaten mevcut. " });

    var VerificationId = await RegisterEmailVerification(EMailAddress);
    var ExpireDate = CalculateExpireDate( { hours: 0, minutes: 15});

    var createdToken = await AuthToken.findOne({
      UserId: Auth._id.toString(),
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

    } 

    if(!createdToken) await newAuthTokenFunction(req, res, {Id: Auth._id.toString(), Type: "Register_Email_Verification", Token: VerificationId});

    return res.status(200).json({ message: " Kayıt olmak için doğrulama kodu emailinize gönderildi, lütfen emailinizi kontrol ediniz. "});
  })
);

//Kayıt ol Doğrulama kodu onayla.
app.put(
  "/signup-verification-confirm/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  asyncHandler(async (req, res) => {
    var { VerificationId} = req.body;
    if (!VerificationId) return res.status(400).json({ message: "Lütfen doğrulama kodunuzu giriniz. " });

    var Auth = await GetAuthDetails(req, res);
    if (!Auth.IsTemporary) return res.status(409).json({ message: "Bu email ile kayıtlı bir hesap zaten mevcut. " });

    var AuthTokenFilter = {
      UserId: Auth._id.toString(),
      TokenType: "Register_Email_Verification",
      TokenUsed: false
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    if( !createdToken) return res.status(404).json({message:' Doğrulama kodu eksik veya geçersiz, lütfen tekrar deneyiniz. '});
    if( createdToken.Token != VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if( new Date() > new Date(String(createdToken.TokenExpiredDate))) return res.status(410).json({ message: "Doğrulama kodu süresi dolmuş, lütfen tekrar deneyiniz. " });
    
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
    var { Password, PasswordConfirm} = req.body;

    if ( !Password || !PasswordConfirm || !Password === PasswordConfirm) return res.status(400).json({ message: "Şifrenizin doğrulaması başarısız, lütfen şifrenizi tekrardan giriniz. " });

    var Auth = await GetAuthDetails(req, res);

    if ( !Auth.IsTemporary) return res.status(409).json({ message: "Bu email ile kayıtlı bir hesap zaten mevcut. " });

    Password = Sha256Crypto(Password, Auth._id.toString());

    var update = {
      $set: {
        Password: Password,
        CreatedDate: new Date(),
        IsTemporary: false
      }
    };
  
    await newLogFunction(req, res, {Id: Auth._id.toString(), Type:"Register"});
    await User.findByIdAndUpdate(Auth._id.toString(), update);

    return res.status(201).json({ message: "Hesabınzı başarıyla oluşturdunuz, giriş yapabilirsiniz. " });
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
    var cacheKey = `Auth:${EMailAddress}`;

    var AuthInCache = ServerCache.get(cacheKey);
    if( AuthInCache) return res.status(200).json({ message: " Kullanıcı bilgileri başarıyla getirildi. ( N-C )", Auth: AuthInCache });

    var Auth = await GetAuthDetails(req, res);

    if ( Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. " });

    if( Auth.ProfileImage) Auth.ProfileImage = aes256Decrypt(Auth.ProfileImage, Auth._id.toString());

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

    var Auth = await GetAuthDetails(req, res);
    if ( Auth.IsTemporary) return res.status(403).json({message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    
    var AuthTokenFilter = {
      UserId: Auth._id.toString(),
      TokenType: "Set_Password"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    var VerificationId = await SetPasswordEmailVerification(EMailAddress);
    var ExpireDate = CalculateExpireDate({ hours: 0, minutes: 15 });

    if( !createdToken) await newAuthTokenFunction(req, res, {Id: Auth._id.toString(), Type: "Set_Password", Token: VerificationId});

    if( createdToken){
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
    var { VerificationId} = req.body;
    if( !VerificationId) return res.status(400).json({message:' Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. '});

    var Auth = await GetAuthDetails(req, res);

    var AuthTokenFilter = {
      UserId: Auth._id.toString(),
      TokenType: "Set_Password"
    };

    var authToken = await AuthToken.findOne(AuthTokenFilter);
    if( !authToken) return res.status(404).json({ message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if( authToken.Token !== VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
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
    var { Password, PasswordConfirm } = req.body;

    if (!Password || !PasswordConfirm || !Password === PasswordConfirm) return res.status(400).json({ message: "Şifrenizin doğrulaması başarısız, lütfen şifrenizi tekrardan giriniz. " });

    var Auth = await GetAuthDetails(req, res);

    Password = Sha256Crypto(Password, Auth._id.toString());

    var update = {
      $set: {
        Password: Password,
        UpdatedDate: new Date(),
      }
    };

    await User.findByIdAndUpdate(Auth._id.toString(), update);
    await newLogFunction(req, res, {Id: Auth._id.toString(), Type:"Set_Password"});

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
    var { Password } = req.body;

    if ( !Password) return res.status(400).json({ message: " Şifre eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var Auth = await GetAuthDetails(req, res);

    if ( Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız." });
    if ( !Auth.Password === Sha256Crypto(Password, Auth._id.toString())) return res.status(401).json({ message: "Email veya şifreniz hatalı, lütfen tekrar deneyiniz. " });

    var VerificationId = await LoginEmailVerification(Auth.EMailAddress);
    var ExpireDate = CalculateExpireDate({ hours: 0, minutes: 15 });
    
    var AuthTokenFilter = {
      UserId: Auth._id.toString(),
      TokenType: "Login"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);
    if( !createdToken) await newAuthTokenFunction(req, res, {Id: Auth._id.toString(), Type: "Login", Token: VerificationId});
    if( createdToken){
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

    await User.findByIdAndUpdate(Auth._id.toString(), update);

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
    var { VerificationId } = req.body;

    if ( !VerificationId) return res.status(400).json({ message: " Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var Auth = await GetAuthDetails(req, res);

    var AuthTokenFilter = {
      UserId: Auth._id.toString(),
      TokenType: "Login"
    };

    var createdToken = await AuthToken.findOne(AuthTokenFilter);

    if( !createdToken) return res.status(404).json({message:' Doğrulama kodu eksik veya hatalı, lütfen tekrar deneyiniz. '});
    if( createdToken.Token !== VerificationId) return res.status(400).json({message:' Doğrulama kodu eşleşmedi, lütfen tekrar deneyiniz. '});
    if( new Date() > new Date(String(createdToken.TokenExpiredDate))) return res.status(410).json({ message: " Doğrulama kodunuz geçersiz, lütfen yeniden deneyiniz. " });
    
    var update = {
      $set: {
        TwoFAStatus: true,
      }
    };
    
    await User.findByIdAndUpdate(Auth._id.toString(), update);

    var authTokenUpdate = {
      $set:{
        TokenUsed: true
      },
      $unset:{
        Token: ''
      }
    };

    await AuthToken.findByIdAndUpdate(createdToken._id, authTokenUpdate);    
    
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
    var { Password } = req.body;
    if ( !Password) return res.status(400).json({ message: " Şifre eksik veya hatalı, lütfen tekrar deneyiniz. " });

    var Auth = await GetAuthDetails(req, res);

    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. " });
    if ( Auth.Password !== Sha256Crypto(Password, Auth._id.toString())) return res.status(401).json({ message: " Email veya şifreniz hatalı, lütfen tekrar deneyiniz. " });

    var update = {
      $set: {
        Active: true,
      },
      $unset: {
        LastLoginDate: "",
      }
    };

    Auth = await User.findByIdAndUpdate(Auth._id.toString(), update, { new: true});
    await newLogFunction(req, res, {Id: Auth._id.toString(), Type:"Login"});

    var token = await CreateJWTToken(req, res, Auth.EMailAddress, Auth._id.toString());
    if( !token) return res.status(400).json({message:' Session token oluşturulamadı, lüfen tekrar deneyiniz.'});

    if( Auth.ProfileImage) Auth.ProfileImage = aes256Decrypt(Auth.ProfileImage, Auth._id.toString());
    if( Auth.UpdatedDate) Auth.UpdatedDate = FormatDateFunction(Auth.UpdatedDate);

    return res
      .status(200)
      .json({ 
        message: " Giriş başarıyla gerçekleştirildi, kullanıcı oturumu aktif.  ", 
        token,
        Auth
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
    var token = req.get("Authorization") && req.get("Authorization").split(" ")[1];

    var Auth = await GetAuthDetails(req, res);
    
    var update = {
      $set: {
        Active: false,
        LastLoginDate: new Date(),
        TwoFAStatus: false
      }
    };

    await User.findByIdAndUpdate(Auth._id.toString(), update);
    await newTokenFunction(req, res, {Id: Auth._id.toString(), Token: token});
    await newLogFunction(req, res, {Id: Auth._id.toString(), Type:"Logout"});
    
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

    var update = {
      $set:{
        TwoFAStatus: false,
        Active: false,
        LastLoginDate: new Date()
      }
    };

    var Auth = await User.findOneAndUpdate({EMailAddress: req.params.EMailAddress}, update);
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
    var { NoteData } = req.body;
    var NoteDataNonEncrypted = JSON.parse(JSON.stringify(NoteData));

    var Auth = await GetAuthDetails(req, res);

    NoteData.SelectedFiles.forEach(function(item){
      item.Url = aes256Crypto(item.Url, Auth._id.toString());
      item.Name = aes256Crypto(item.Name, Auth._id.toString());
    });

    NoteData.Audio.forEach(function(item){
      item.Content = aes256Crypto(item.Content, Auth._id.toString());
      item.Url = aes256Crypto(item.Url, Auth._id.toString());
    });

    var newNoteObj = {
      UserId: Auth._id.toString(),
      NoteName: NoteData.NoteName,
      TextContent: aes256Crypto(NoteData.TextContent, Auth._id.toString()),
      TextContentHTML: aes256Crypto(NoteData.TextContentHTML, Auth._id.toString()),
      Audio:NoteData.Audio.length ?  NoteData.Audio : [],
      SelectedFiles: NoteData.SelectedFiles.length ? NoteData.SelectedFiles : []
    };
    
    var newNote = new Note(newNoteObj);
    var savedNewNote = await newNote.save();

    NoteDataNonEncrypted._id = savedNewNote._id;
    NoteDataNonEncrypted.CreatedDate = new Date();
    NoteDataNonEncrypted.CreatedDateFormatted = FormatDateFunction(new Date())

    var CacheKey = `Notes:${Auth.EMailAddress}`;
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
    var Auth = await GetAuthDetails(req, res);

    var cacheKey = `Notes:${Auth.EMailAddress}`;
    var NotesInCache = ServerCache.get(cacheKey);
    if(NotesInCache) return res.status(200).json({ message:' Notlar başarıyla getirildi. ( N-C )', Notes: NotesInCache });

    var NoteFilter = {UserId: Auth._id.toString()};
    var Notes = await Note.find(NoteFilter).lean();
    
    Notes.forEach(function(note){
      
      note.TextContent = aes256Decrypt(note.TextContent, Auth._id.toString());
      note.TextContentHTML = aes256Decrypt(note.TextContentHTML, Auth._id.toString());
      note.CreatedDateFormatted = FormatDateFunction(note.CreatedDate);

      note.Audio.forEach(function(item){
        item.Content = aes256Decrypt(item.Content, Auth._id.toString());
        item.Url = aes256Decrypt(item.Url, Auth._id.toString());
      });

      note.SelectedFiles.forEach(function(item){
        item.Url = aes256Decrypt(item.Url, Auth._id.toString());
        item.Name = aes256Decrypt(item.Name, Auth._id.toString());
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

    var Auth = await GetAuthDetails(req, res);

    var CacheKey = `Note:${Id}`;
    var NoteInCache = ServerCache.get(CacheKey);
    if( NoteInCache) return res.status(200).json({message:' Not detayları başarıyla getirildi. ( N-C )', Note: NoteInCache });

    var note = await Note.findById(Id).lean();
    if( !note) return res.status(404).json({message:' Not bulunamadı, lütfen tekrar deneyiniz. '});
    
    note.CreatedDateFormatted = FormatDateFunction(note.CreatedDate);
    note.UpdatedDateFormatted = note.UpdatedDate ? FormatDateFunction(note.UpdatedDate) : null;
    note.TextContent = aes256Decrypt(note.TextContent, Auth._id.toString());
    note.TextContentHTML = aes256Decrypt(note.TextContentHTML, Auth._id.toString());

    note.SelectedFiles.forEach(function(item){
      item.CreatedDateFormatted = FormatDateFunction(item.CreatedDate);
      item.UpdatedDateFormatted = item.UpdatedDate ? FormatDateFunction(item.UpdatedDate) : null;
      item.SizeDetail = formatBytes(item.Size, 2);
      item.MimeTypeDetail = GetMimeTypeDetail(item.MimeType, item.Name);

      item.Url = aes256Decrypt(item.Url, Auth._id.toString());
      item.Name = aes256Decrypt(item.Name, Auth._id.toString());
    });

    note.Audio.forEach(function(item){ 
      item.Content = aes256Decrypt(item.Content, Auth._id.toString());
      item.Url = aes256Decrypt(item.Url, Auth._id.toString());
    });

    var update = {
      $set:{
        LastSeenDate: new Date()
      }
    };

    await Note.findByIdAndUpdate(Id, update);

    ServerCache.set(CacheKey, note);  

    return res.status(200).json({ message:" Not detayları başarıyla getirildi. ", Note: note});
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
    if( !Id) return res.status(400).json({message:' Lütfen silmek istediğiniz notu seçtiğinizden emin olun. '});

    var Auth = await GetAuthDetails(req, res);

    var NoteFilter = { UserId: Auth._id.toString(), _id: Id };
    var deletedNoted = await Note.findOneAndDelete(NoteFilter);
    if( !deletedNoted) return res.status(400).json({message:' Silme işlemi başarısız, lütfen tekrar deneyiniz.'});

    var CacheKey = `Note:${Id}`;
    var NoteInCache = ServerCache.get(CacheKey);
    if(NoteInCache) ServerCache.del(CacheKey);

    CacheKey = `Notes:${EMailAddress}`;
    var NotesInCache = ServerCache.get(CacheKey);
    if(NotesInCache) {
      NotesInCache = NotesInCache.filter(function(item){ return item._id.toString() !== Id});
      ServerCache.set(CacheKey, NotesInCache);
    }

    return res.status(200).json({message:'Seçili not başarıyla silindi. ', Id});
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
    
    var Auth = await GetAuthDetails(req, res);

    NoteData.UpdatedDate = new Date();
    NoteData.TextContent = aes256Crypto(NoteData.TextContent, Auth._id.toString());
    NoteData.TextContentHTML = aes256Crypto(NoteData.TextContentHTML, Auth._id.toString());

    NoteData.SelectedFiles.forEach(function(item){
      if('State' in item && item.State === "Deleted") return NoteData.SelectedFiles = NoteData.SelectedFiles.filter(function(obj){ return obj._id !== item._id});
      
      item.Url = aes256Crypto(item.Url, Auth._id.toString());
      item.Name = aes256Crypto(item.Name, Auth._id.toString());
    });

    NoteData.Audio.forEach(function(item){
      if('State' in item && item.State === "Deleted") return NoteData.Audio = NoteData.Audio.filter(function(obj){ return obj._id !== item._id});
      
      item.Content = aes256Crypto(item.Content, Auth._id.toString());
      item.Url = aes256Crypto(item.Url, Auth._id.toString());
    });

    var noteFilter = { UserId: Auth._id.toString(), _id: Id };
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
    var { UserData } = req.body;
    if ( !Object.keys(UserData).length) return res.status(400).json({message:' Kullanıcı bilgileri güncellenemedi, eksik veya hatalı bilgi mevcut, lütfen tekrar deneyiniz. '});

    var Auth = await GetAuthDetails(req, res);
    if ( !Auth) return res.status(404).json({message:' Kullanıcı bulunamadı.'});
    if ( Auth.IsTemporary) return res.status(403).json({ message: "Kullanıcı kayıt doğrulaması tamamlanmamış, lütfen kayıt işlemlerinizi tamamlayınız. " });
    if ( !Auth.TwoFAStatus) return res.status(403).json({ message: "2 faktörlü doğrulama tamamlanmamış, lütfen tekrar deneyiniz. " });
    
    if( UserData.ProfileImage) UserData.ProfileImage = aes256Crypto(UserData.ProfileImage, Auth._id.toString());

    var update = {
      $set:{
        Name: UserData.Name || '',
        Surname: UserData.Surname || '',
        Bio: UserData.Bio || '',
        UpdatedDate: new Date(),
        ProfileImage: UserData.ProfileImage || ''
      }
    };

    await User.findByIdAndUpdate( Auth._id.toString(), update);

    return res.status(200).json({ message:' Kullanıcı bilgileri başarıyla güncellendi. '});
  })
);

//Log kayıtlarını getir.
function GetArrayKey(param){
  for(var key in param){ return key }
};

app.get(
  "/log-details/:EMailAddress",
  EMailAddressControl,
  AuthControl,
  asyncHandler(async(req, res) => {
  var Auth = await GetAuthDetails(req, res);

  var enumList = [ 
    {'Close_App': 'Uygulama başarıyla kapatıldı.'}, 
    {'Register': 'Uygulama kaydı başarıyla tamamlandı. '}, 
    {'Login': 'Uygulama oturumu başarıyla başlatıldı. '}, 
    {'Set_Password': 'Uygulama şifresi başarıyla değiştirildi. '}, 
    {'Register_Email_Verification': 'Uygulama kaydı mail doğrulama kodu başarıyla gönderildi. '}, 
    {'Login_Email_Verification': 'Uygulama oturumu başlatılması için mail doğrulama kodu başarıyla gönderildi. '},
    {'Logout': 'Uygulama oturumu başarıyla sonlandırıldı. '}
  ];

  var encryptList = [ 'IPAddress', 'DeviceName', 'DeviceId'];

  var ActionArrays = {
    Close_App_Array: [],
    Register_Array: [],
    Login_Array: [],
    Set_Password_Array: [],
    Register_Email_Verification_Array: [],
    Login_Email_Verification_Array: [],
    Logout_Array: []
  };

  var Logs = await Log.find({ UserId: Auth._id.toString()}).lean();
  if( !Logs.length) return res.status(404).json({ message:' Log kaydı bulunamadı. ', Logs: []});

  Logs = Logs.sort(function( a, b) { return ( new Date(String(a.Date)).getTime() ) - ( new Date(String(b.Date)).getTime()  )  });

  Logs.forEach(function(item){
    item.Date = FormatDateFunction(item.Date);
    for(var key in item){ 
      if( encryptList.some(function(row){ return row === key}) ) item[key] = aes256Decrypt(item[key], Auth._id.toString()); 
    };

    var action_array = `${item.Action}_Array`;
    for(var key in ActionArrays){
      if( key === action_array) ActionArrays[key].push({...item, Description: enumList.find(function(row) { return GetArrayKey(row) === item.Action})[GetArrayKey(row)]});
    }
  });

  return res.status(200).json({
    message:' Log kayıtları başarıyla getirilmiştir.', 
    Logs: JSON.stringify(ActionArrays)
  });
}));

module.exports = app;