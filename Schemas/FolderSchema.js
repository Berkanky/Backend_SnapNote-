const mongoose = require('mongoose');

const FolderSchema = new mongoose.Schema({
    UserId:{
        type:String,
        required:true
    },
    Name:{
        type:String,
        unique:true
    },
    Description:{
        type:String
    },
    CreatedDate:{
        type:Date
    },
    UpdatedDate:{
        type:Date
    }
});

const Folder = mongoose.model('Folder', FolderSchema);
module.exports = Folder