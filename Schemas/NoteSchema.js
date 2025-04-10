const mongoose = require('mongoose');

const AudioSchema = new mongoose.Schema({
    Content:{
        type: String
    },
    Url:{
        type: String
    },
    Type:{
        type: String
    },
    State:{
        type: String
    },
    CreatedDate:{
        type: Date,
        default: new Date()
    }
});

const FileSchema = new mongoose.Schema({
    Name:{ type:String },
    CreatedDate:{ type:Date, default: new Date() },
    Url:{ type:String },
    MimeType:{ type:String },
    Encoding: { type:String },
    Size: { type:Number },
    State: { type: String},
    LastDownloadDate:{ type: Date}
});

const NoteSchema = new mongoose.Schema({
    UserId:{
        type:String,
        required:true
    },
    FolderId:{
        type:String
    },
    NoteName:{
        type:String
    },
    TextContent:{
        type:String
    },
    TextContentHTML:{
        type:String
    },
    DeadlineDate:{
        type:Date
    },
    CreatedDate:{
        type:Date,
        default: new Date()
    },
    UpdatedDate:{
        type:Date
    },
    IsCompleted:{
        type:Boolean,
        default: false
    },
    Audio:[AudioSchema],
    SelectedFiles:[FileSchema],
    LastSeenDate:{
        type:Date
    }
});

const Note = mongoose.model('Note', NoteSchema);
module.exports = Note