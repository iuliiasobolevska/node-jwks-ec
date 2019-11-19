const nock = require('nock');
const { expect } = require('chai');

const { jwksEndpoint } = require('./mocks/jwks');
const { publicKey, privateKey, randomPublicKey1 } = require('./mocks/keys');
const { createToken, createSymmetricToken } = require('./mocks/tokens');

const jwksRsa = require('../src');
const expressJwt = require('express-jwt');

describe('expressJwtSecret', () => {


  describe('#expressJwt', () => {
    beforeEach(() => {
      nock.cleanAll();
    });

    it('should accept the secret function', () => {
      expressJwt({
        secret: jwksRsa.expressJwtSecret({
          jwksUri: 'http://localhost/.well-known/jwks.json'
        })
      });
    });

    it('should not provide a key if token is invalid', () => {
      const middleware = expressJwt({
        secret: jwksRsa.expressJwtSecret({
          jwksUri: 'http://localhost/.well-known/jwks.json'
        })
      });

      middleware({ headers: { authorization: 'Bearer abc' } }, { }, function(err) {
        expect(err.code).to.equal('invalid_token');
      });
    });

    it('should not provide a key if token is HS256', (done) => {
      const middleware = expressJwt({
        secret: jwksRsa.expressJwtSecret({
          jwksUri: 'http://localhost/.well-known/jwks.json'
        })
      });

      const token = createSymmetricToken('mykey', { sub: 'john' });
      middleware({ headers: { authorization: `Bearer ${token}` } }, { }, function(err) {
        expect(err.code).to.equal('invalid_token');
        done();
      });
    });
    
    it('should not authenticate the user if KID matches but the keys dont', (done) => {
      const middleware = expressJwt({
        secret: jwksRsa.expressJwtSecret({
          jwksUri: 'http://localhost/.well-known/jwks.json'
        })
      });

      jwksEndpoint('http://localhost', [ { pub: randomPublicKey1, kid: '123' } ]);

      const token = createToken(privateKey, '123', { sub: 'john' });
      middleware({ headers: { authorization: `Bearer ${token}` } }, { }, function(err) {
        expect(err.message).to.equal('The JWKS endpoint did not contain any signing keys');
        done();
      });
    });
  });
});
