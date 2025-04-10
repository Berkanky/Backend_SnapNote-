const express = require("express");

//Nodejs modülleri.
const fs = require("fs");
const fsPromises = require("fs").promises;
const os = require("os");
const path = require("path");

//Open ai.
const OpenAI = require("openai");

//dosya okumak için multer.
const multer = require("multer");

//Middlewares
const EMailAddressControl = require("../Middleware/EMailAddressControl");
const AuthControl = require("../Middleware/AuthControl");
const rateLimiter = require("../Middleware/RateLimiter");

//JWT Controller.
const AuthenticateJWTToken = require("../JWTModules/JWTTokenControl");
const asyncHandler = require("../Handler/Handler");

require("dotenv").config();

const app = express.Router();

var apiKey = process.env.OPEN_AI_API_KEY;

const openai = new OpenAI({
  apiKey: apiKey,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

async function writeTempFile(buffer, originalName) {
  var tempDir = os.tmpdir();
  var fileName = originalName || `tempfile-${Date.now()}.webm`;
  var filePath = path.join(tempDir, fileName);
  await fsPromises.writeFile(filePath, buffer);
  return filePath;
}

const SpeechToTextAI = async (filePath) => {
  const transcription = await openai.audio.transcriptions.create({
    file: fs.createReadStream(filePath),
    model: "whisper-1",
  });

  return transcription.text;
};

const editMyNoteFunction = async (note) => {
  //özel istek alanı ekle (optional olcak)
  const textGeneration = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You are a helpful and creative assistant." },
      {
        role: "assistant",
        content: `Please rewrite the note below neatly and in accordance with the note rules; 
          ${note}
        `,
      },
    ],
    store: true,
  });
  return textGeneration.choices[0].message?.content;
};

app.post(
  "/open-ai-speech-to-text/:EMailAddress",
  upload.single("audio"),
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  async (req, res) => {
    if (!req.file) return res.status(400).json({ message: "Dosya bulunamadı. " });

    var tempFilePath = await writeTempFile(
      req.file.buffer,
      req.file.originalname
    );

    var speechedText = await SpeechToTextAI(tempFilePath);

    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Temp dosya silinemedi:", err);
    });

    var base64Data = req.file.buffer.toString("base64");
    var url = `data:${req.file.mimetype};base64,${base64Data}`;

    return res.status(200).json({
      Url: url,
      Content: speechedText,
      Type: req.file.mimetype,
    });
  }
);

app.put(
  "/open-ai-edit-text/:EMailAddress",
  rateLimiter,
  EMailAddressControl,
  AuthControl,
  AuthenticateJWTToken,
  asyncHandler(async (req, res) => {
    var note  = req.body.FileNote;
    if(!note) return res.status(400).json({message:' Lütfen geçerli bir not giriniz. '});
    var fixedNote = ( await editMyNoteFunction(note));
    return res.status(200).json({Note: fixedNote});
  })
);

module.exports = app;