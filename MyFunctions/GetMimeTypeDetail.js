function GetMimeTypeDetail(MimeType, FileName) {
  var fileType = null;

  if (MimeType && MimeType && typeof MimeType === "string") {
    var mimeParts = MimeType.split("/");
    if (mimeParts.length > 1) {
      fileType = mimeParts[1];
      if (fileType === "plain") fileType = "txt";
    }
  }

  if (!fileType && MimeType && FileName && typeof FileName === "string") {
    var lastDotIndex = FileName.lastIndexOf(".");
    if (lastDotIndex !== -1 && lastDotIndex < FileName.length - 1) fileType = FileName.substring(lastDotIndex + 1);
  }

  return fileType ? fileType.toLowerCase() : null;
}

module.exports = GetMimeTypeDetail;