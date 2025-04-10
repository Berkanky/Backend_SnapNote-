require("dotenv").config();

//Şemalar
const User = require("./Schemas/User");

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");
const http = require("http");

const { MONGODB_URI, PORT = 3000 } = process.env;

mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: "SnapNote",
  })
  .then(() => console.log("MongoDB Atlas bağlantısı başarılı"))
  .catch((err) => console.error("MongoDB bağlantı hatası:", err));

app.use(cors());
app.use(express.json({ limit: "350mb" }));
app.use(express.urlencoded({ limit: "350mb", extended: true }));

const FileOperationsJS = require("./FileOperations/FileOperations");
const CrudJS = require("./Cruds/Crud");
const OpenAIJs = require("./openai/openAIWhisper");
app.use("/", CrudJS, OpenAIJs, FileOperationsJS);

app.use((err, req, res, next) => {
  console.error(err);
  return res.status(err.status || 500).json({ message: err.message });
});

//app.listen(PORT, () => {}); // ws için buraya gerek yok ws yi kaldıracağın zaman açarsın geri.

const server = http.createServer(app);
console.log("WS Created Server : ", server);
const WebSocket = require("ws");
const wss = new WebSocket.Server({ server });

wss.on("connection", (ws) => {
  console.log("Yeni bir WebSocket bağlantısı sağlandı.");
  ws.on("message", (msg) => {
    try {
      var data = JSON.parse(msg);
      if (data.UserData) {
        ws.userId = data.UserData._id;
        console.log("Kullanıcı kimliği atandı:", data.UserData._id);
      } else {

        console.log("Gelen mesaj:", msg);
        ws.send(`Sunucudan echo: ${msg}`);
      }
    } catch (error) {
      console.error("Mesaj parse hatası:", error);
    }
  });
  
  ws.send("WebSocket bağlantısı başarılı! Hoş geldiniz.");
});

const userChangeStream = User.watch();

userChangeStream.on("change", (change) => {
  console.log("User şeması değişikliği:", change);
  var changedUserId = change.documentKey._id.toString();

  wss.clients.forEach((client) => {
    if (
      client.readyState === WebSocket.OPEN &&
      client.userId === changedUserId
    ) {
      client.send(JSON.stringify({ type: "UserUpdate", payload: change.updateDescription.updatedFields }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server ${PORT} portunda çalışıyor...`);
});

module.exports = app;