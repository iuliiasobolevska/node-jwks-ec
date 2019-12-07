const debug = require('debug')
const request = require('request')
const jwkToPem = require('jwk-to-pem')
const LRU = require('lru-cache')

const {JwksError} = require('./errors')
const SigningKeyNotFoundError = require('./errors/SigningKeyNotFoundError')
/**
 * @callbck Callback
 * @param {Error} error
 * @param {object} key
 */

/**
 * @typedef {object} JwksClientOptions
 * @prop {boolean} cache
 * @prop {boolean} strictSsl
 */

/**
 * @class
 */
module.exports.JwksClient = class JwksClient {
  /**
   * @param {JwksClientOptions} options
   */
  constructor (options) {
    this.options = {
      cache: false,
      strictSsl: true,
      ...options
    }

    this.logger = debug('jwks')

    // Initialize Utils.
    if (this.options.cache) {
      this.cache = new LRU(options)
    }
  }
  /**
   * @param {Callback} cb
   */
  getKeys (cb) {
    this.logger(`Fetching keys from '${this.options.jwksUri}'`)
    request({
      json: true,
      uri: this.options.jwksUri,
      strictSSL: this.options.strictSsl,
      headers: this.options.requestHeaders,
      agentOptions: this.options.requestAgentOptions
    }, (err, res) => {
      if (err || res.statusCode < 200 || res.statusCode >= 300) {
        this.logger('Failure:', (res && res.body) || err)
        if (res) {
          return cb(new JwksError((res.body && (res.body.message || res.body)) || res.statusMessage || `Http Error ${res.statusCode}`))
        }
        return cb(err)
      }

      const keysToReturn = res.body.keys ? res.body.keys : res.body

      this.logger('Keys:', keysToReturn)
      return cb(null, keysToReturn)
    })
  }

  /**
   * @param {Callback} cb
   */
  getSigningKeys (cb) {
    this.getKeys((err, keys) => {
      if (err) {
        return cb(err)
      }

      if (!keys) {
        return cb(new JwksError('The JWKS endpoint did not contain any keys'))
      }

      if (!keys.length) {
        keys = [keys]
      }

      const signingKeys = keys
        .filter(key => key.use === 'sig' && key.kty === 'EC' && key.kid && (key.x && key.y))
        .map(key => {
          return {
            kid: key.kid,
            publicKey: jwkToPem(key),
            privateKey: key.d ? jwkToPem(key, { private: true }) : undefined
          }
        })

      if (!signingKeys.length) {
        return cb(new JwksError('The JWKS endpoint did not contain any signing keys'))
      }

      this.logger('Signing Keys:', signingKeys)
      return cb(null, signingKeys)
    })
  }


  /**
   * @param {string} kid
   * @param {Callback} cb
   */
  getSigningKey (kid, cb) {
    this.logger(`Fetching signing key for '${kid}'`)
   
    if (this.options.cache && this.cache.get(kid) !== undefined) {
      const cachedKey = this.cache.get(kid)
      cb(null, cachedKey)
    } else {
      this.getSigningKeys((err, keys) => {
        if (err) {
          return cb(err)
        }

        const key = keys.find(k => k.kid === kid)
        if (key) {
          if (this.options.cache) {
            this.cache.set(kid, key);
          }
          return cb(null, key)
        } else {
          this.logger(`Unable to find a signing key that matches '${kid}'`)
          return cb(new SigningKeyNotFoundError(`Unable to find a signing key that matches '${kid}'`))
        }
      })
    }
  }
}
