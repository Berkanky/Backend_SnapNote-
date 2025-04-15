require("dotenv").config();

//Şemalar
const User = require("./Schemas/User");

//Şifreleme Modülleri
const aes256Decrypt = require("./EncryptModules/AES256Decrypt");

//Express
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
const WebSocket = require("ws");

const wss = new WebSocket.Server({ server });

const FindInUsers = async(DeviceId) => {
  var Users = await User.find().lean();
  if( !Users.length) return
  
  var findedUsers = [];

  Users.forEach(function(user){
    var UserDeviceId = aes256Decrypt(user.DeviceId, user._id.toString());
    if( UserDeviceId === DeviceId && !findedUsers.some(function(item){ return item._id.toString() === user._id.toString()})) findedUsers.push(user);
  });

  return findedUsers;
};

wss.on("connection", (ws) => {
  ws.on("message", async (msg) => {
    try {
      var data = JSON.parse(msg);

      if (data.UserData) {
        ws.userId = data.UserData._id;
      } 
      
      if(data.DeviceId){
        var DeviceId = data.DeviceId;
        console.log("Sunucu tarafında yakalanan DeviceID : ", DeviceId);
        var FindedUsers = [];
        FindedUsers = await FindInUsers(DeviceId);
        ws.send(JSON.stringify({quickAccess:{ FindedUsers}}));
      }
      
      if(!Object.keys(data).length) {
        ws.send(JSON.stringify({payload:{}}));
      }
    } catch (error) {
      console.error("Mesaj parse hatası:", error);
    }
    ws.send(JSON.stringify({payload:{}}));
  });
});

const userChangeStream = User.watch();

userChangeStream.on("change", (change) => {
  var changedUserId = change.documentKey._id.toString();
  wss.clients.forEach((client) => {
    var ChangedAuthFields = change.updateDescription.updatedFields;
    if(ChangedAuthFields.ProfileImage) ChangedAuthFields.ProfileImage = aes256Decrypt(ChangedAuthFields.ProfileImage, changedUserId);
    if ( client.readyState === WebSocket.OPEN && client.userId === changedUserId) client.send(JSON.stringify({ type: "UserUpdate", payload: ChangedAuthFields }));
  });
});

server.listen(PORT, () => {});
module.exports = app;