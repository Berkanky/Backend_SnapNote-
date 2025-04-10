const express = require("express");
const app = express.Router();

const multer = require("multer");

//Middlewares.
const EMailAddressControl = require("../Middleware/EMailAddressControl");
const rateLimiter = require("../Middleware/RateLimiter");
const AuthControl = require("../Middleware/AuthControl");

//JWT.
const AuthenticateJWTToken = require("../JWTModules/JWTTokenControl");
const asyncHandler = require("../Handler/Handler");

//Fonksiyonlar
const generateMongoId = require("../MyFunctions/generateMongoId");
const GetMimeTypeDetail = require("../MyFunctions/GetMimeTypeDetail");
const formatBytes = require("../MyFunctions/FormatFileSize");

//Şemalar
const User = require("../Schemas/User");
const Note = require("../Schemas/NoteSchema");
const aes256Decrypt = require("../EncryptModules/AES256Decrypt");

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post(
  "/select-file/:EMailAddress",
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  upload.array("files"),
  asyncHandler(async (req, res) => {
    if (!req.files || !req.files.length) return res.status(400).json({ message: "Dosya yüklenmedi." });
    var url;
    var File = {};
    var saveFilesPromises = req.files.map((file) => {

      var fileBuffer = file.buffer;
      var base64Data = fileBuffer.toString("base64");
      url = `data:${file.mimetype};base64,${base64Data}`;

      File = {
        Id: generateMongoId(),
        Name: file.originalname,
        Url: url,
        MimeType: file.mimetype,
        MimeTypeDetail: GetMimeTypeDetail(file.mimetype, file.originalname),
        Encoding: file.encoding,
        Size: file.size,
        SizeDetail: formatBytes(file.size, 2)
      };

    });
    await Promise.all(saveFilesPromises);
    return res.status(200).json({message:'Dosyalar başarıyla seçildi. ', File });
  })
);

app.delete(
  "/delete-file/:EMailAddress/:FileId",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
  var { EMailAddress, FileId} = req.params;
  
  return res.status(200).json({message:' Dosya başarıyla silindi. ', FileId:FileId});
}));

app.post(
  "/select-single-file/:EMailAddress",
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  upload.array("files"),
  asyncHandler(async (req, res) => {
    if (!req.files || !req.files.length) return res.status(400).json({ message: "Dosya yüklenmedi." });
    var url;
    var File = {};
    var saveFilePromises = req.files.map((file) => {

      var fileBuffer = file.buffer;
      var base64Data = fileBuffer.toString("base64");
      url = `data:${file.mimetype};base64,${base64Data}`;

      File = {
        Id: generateMongoId(),
        Name: file.originalname,
        Url: url,
        MimeType: file.mimetype,
        MimeTypeDetail: GetMimeTypeDetail(file.mimetype, file.originalname),
        Encoding: file.encoding,
        Size: file.size,
        SizeDetail: formatBytes(file.size, 2)
      };

    });
    await Promise.all(saveFilePromises);
    return res.status(200).json({message:'Dosya başarıyla yüklendi. ', File });
  })
);

app.get(
  "/download-file/:EMailAddress/:NoteId/:FileId",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async(req, res) => {
    var { EMailAddress, NoteId, FileId} = req.params;

    var filter = {EMailAddress};
    var Auth = await User.findOne(filter);

    var noteFilter = { UserId: Auth.id, _id: NoteId};
    var note = await Note.findOne(noteFilter).lean();
    if(!note) return res.status(404).json({message:' Not bulunamadı. '});

    var file = note.SelectedFiles.find(function(item){ return item._id.toString() === FileId});
    if(!file) return res.status(404).json({message:' İndirilmek istenen dosya bulunamadı. '});
    
    file.LastDownloadDate = new Date()

    var update = {
      $set:{
        SelectedFiles: note.SelectedFiles
      }
    };

    await Note.findOneAndUpdate(noteFilter, update);

    file.Name = aes256Decrypt(file.Name, Auth.id);
    file.Url = aes256Decrypt(file.Url, Auth.id);

    return res.status(200).json({message:'Dosya indirme işlemi başarıyla başlatıldı.', File: file});
  })
);

module.exports = app;