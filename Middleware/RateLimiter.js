var ipRequestCounts = new Map();
var LIMIT = 10;
var TIME_FRAME = 60000;

const rateLimiter = async (req, res, next) => {

  var ip = req.ip;
  var currentTime = Date.now();

  if (!ipRequestCounts.has(ip)) {

    ipRequestCounts.set(ip, { count: 1, lastRequest: currentTime });
    return next();
  }

  var ipData = ipRequestCounts.get(ip);

  if (currentTime - ipData.lastRequest > TIME_FRAME) {
    
    ipRequestCounts.set(ip, { count: 1, lastRequest: currentTime });
    return next();
  }

  if (ipData.count >= LIMIT) {

    return res
      .status(429)
      .json({ message: "Çok fazla istek! Lütfen daha sonra tekrar deneyin." });
  }

  ipData.count += 1;
  ipData.lastRequest = currentTime;
  ipRequestCounts.set(ip, ipData);
  next();
};

module.exports = rateLimiter;