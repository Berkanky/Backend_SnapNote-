require("dotenv").config();

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");

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

app.listen(PORT, () => {});
module.exports = app;