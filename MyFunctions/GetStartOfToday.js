function GetStartOfToday() {
    var now = new Date();
    // Yıl, ay ve günü alarak yeni bir Date nesnesi oluşturuyoruz; saat 00:00:00 otomatik olarak ayarlanır.
    var startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    return startOfDay;
}

module.exports = GetStartOfToday;