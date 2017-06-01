var whois = require('whois-json');

module.exports = function (context, callback) {
  var domain = context.data.domain;
  if (!domain) {
    callback(null, {
      status: 'ERROR',
      msg: 'missing query parameter <domain>'
    });
  } else {
    whois(domain, function(err, whoisResult){
      var tld = domain.split('.').pop();
      var result;
      switch(tld) {
        case 'com':
          result = {
            status: 'OK',
            expirationDate: whoisResult.expirationDate,
            nameServers: whoisResult.nameServer.toLowerCase().split(' ')
          };
          break;
        case 'io':
          result = {
            status: 'OK',
            expirationDate: whoisResult.expiry,
            nameServers: Object.keys(whoisResult).filter(function(key) { 
                return key.startsWith('ns'); 
              }).map(function(key) { 
                return whoisResult[key]; 
              })
          };
          break;
        case 'me':
          result = {
            status: 'OK',
            expirationDate: whoisResult.registryExpiryDate,
            nameServers: whoisResult.nameServer.toLowerCase().split(' ')
          };
          break;
        case 'ee':
          result = {
            status: 'OK',
            expirationDate: whoisResult.expire,
            nameServers: whoisResult.nserver.toLowerCase().split(' ')
          };
          break;
        default:
          result = {
            status: 'ERROR',
            msg: 'TLD ' + tld + ' unsupported'
          };
      }
      result.source = whoisResult;
  	  callback(null, result);
    });
  }
};
