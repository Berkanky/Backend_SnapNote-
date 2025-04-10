function EMailAddressRegex(EMailAddress) {
    var EMailAddressRegex =
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/; //RFC5322
    return EMailAddressRegex.test(EMailAddress);
}

module.exports = EMailAddressRegex;
