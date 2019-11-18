const jwt = require('jsonwebtoken');

module.exports.createToken = function(key, kid, payload) {
  return jwt.sign(payload, key, { noTimestamp: true, algorithm: 'RS256', header: { alg: 'RS256', kid } });
}

module.exports.createSymmetricToken = function(key, payload) {
  return jwt.sign(payload, key, { noTimestamp: true, algorithm: 'HS256', header: { alg: 'HS256' } });
}
