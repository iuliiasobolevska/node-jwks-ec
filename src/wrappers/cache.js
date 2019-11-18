const ms = require('ms');
const debug = require('debug');
const memoizer = require('lru-memoizer');

 module.exports.default = function(client, { cacheMaxEntries = 5, cacheMaxAge = ms('10h') } = options) {
  const logger = debug('jwks');
  const getSigningKey = client.getSigningKey;

  logger(`Configured caching of singing keys. Max: ${cacheMaxEntries} / Age: ${cacheMaxAge}`);
  return memoizer({
    load: (kid, callback) => {
      getSigningKey(kid, (err, key) => {
        if (err) {
          return callback(err);
        }

        logger(`Caching signing key for '${kid}':`, key);
        return callback(null, key);
      });
    },
    hash: (kid) => kid,
    maxAge: cacheMaxAge,
    max: cacheMaxEntries
  });
}
