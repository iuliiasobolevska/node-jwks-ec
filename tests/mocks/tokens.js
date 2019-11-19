const jwt = require('jsonwebtoken');

module.exports.createToken = function(key, kid, payload) {
  return jwt.sign(payload, key, {  algorithm: 'ES256', header: { alg: 'ES256', kid } });
}

module.exports.createSymmetricToken = function(key, payload) {
  return jwt.sign(payload, key, {  algorithm: 'ES256', header: { alg: 'ES256' } });
}
