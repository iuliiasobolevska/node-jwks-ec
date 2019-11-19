const debug = require('debug');
const request = require('request');
const jwkToPem = require('jwk-to-pem');

const JwksError = require('./errors/JwksError');
const SigningKeyNotFoundError = require('./errors/SigningKeyNotFoundError');


const {
  cacheSigningKey,
  rateLimitSigningKey
} = require('./wrappers');

module.exports.JwksClient = class JwksClient {
  constructor(options) {
    this.options = {
      rateLimit: false,
      cache: false,
      strictSsl: true,
      ...options
    };
    this.logger = debug('jwks');

    // Initialize wrappers.
    if (this.options.rateLimit) {
      this.getSigningKey = rateLimitSigningKey(this, options);
    }
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options);
    }
    this.getSigningKey = (kid, cb) => {
      this.logger(`Fetching signing key for '${kid}'`);

      this.getSigningKeys((err, keys) => {
        if (err) {
          return cb(err);
        }

        const key = keys.find(k => k.kid === kid);
        if (key) {
          return cb(null, key);
        } else {
          this.logger(`Unable to find a signing key that matches '${kid}'`);
          return cb(new SigningKeyNotFoundError(`Unable to find a signing key that matches '${kid}'`));
        }
      });
    }
  }

  getKeys(cb) {
    this.logger(`Fetching keys from '${this.options.jwksUri}'`);
    request({
      json: true,
      uri: this.options.jwksUri,
      strictSSL: this.options.strictSsl,
      headers: this.options.requestHeaders,
      agentOptions: this.options.requestAgentOptions
    }, (err, res) => {
      if (err || res.statusCode < 200 || res.statusCode >= 300) {
        this.logger('Failure:', res && res.body || err);
        if (res) {
          return cb(new JwksError(res.body && (res.body.message || res.body) || res.statusMessage || `Http Error ${res.statusCode}`));
        }
        return cb(err);
      }
      
      let keysToReturn = res.body.keys ? res.body.keys : res.body;

      this.logger('Keys:', keysToReturn);
      return cb(null, keysToReturn);
    });
  }

  getSigningKeys(cb) {
    this.getKeys((err, keys) => {
      if (err) {
        return cb(err);
      }
      
      if (!keys) {
        return cb(new JwksError('The JWKS endpoint did not contain any keys'));
      }

      if (!keys.length) {
        keys = [keys]
      }

      const signingKeys = keys
        .filter(key => key.use === 'sig' && key.kty === 'EC' && key.kid && (key.x && key.y))
        .map(key => {
            return {
              kid: key.kid,
              public: jwkToPem(key),
              private: key.d ? jwkToPem(key, {private: true}) : undefined
            };
        });

      if (!signingKeys.length) {
        return cb(new JwksError('The JWKS endpoint did not contain any signing keys'));
      }

      this.logger('Signing Keys:', signingKeys);
      return cb(null, signingKeys);
    });
  }
}

