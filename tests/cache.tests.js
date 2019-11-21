const nock = require('nock');
const { expect } = require('chai');

const { single } = require('./keys');
const { JwksClient } = require('../src/JwksClient');

describe('JwksClient (cache)', () => {
  const jwksHost = 'http://my-authz-server';

  beforeEach(() => {
    nock.cleanAll();
  });

  describe('#getSigningKeys', () => {
    it('should cache requests', (done) => {
      nock(jwksHost)
        .get('/.well-known/jwks.json')
        .reply(200, single);

      const client = new JwksClient({
        cache: true,
        jwksUri: `${jwksHost}/.well-known/jwks.json`,
      });

      client.getSigningKey('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA', (err, key) => {
        expect(key.kid).to.equal('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA');
        nock.cleanAll();

        client.getSigningKey('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA', (err, key) => {
          expect(err).to.be.null;
          expect(key).not.to.be.undefined;
          expect(key.kid).to.equal('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA');
          done();
        });
      });
    });

    it('should cache requests per kid', (done) => {
      nock(jwksHost)
        .get('/.well-known/jwks.json')
        .reply(200, single);

      const client = new JwksClient({
        cache: true,
        jwksUri: `${jwksHost}/.well-known/jwks.json`,
      });

      client.getSigningKey('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA', (err, key) => {
        expect(key.kid).to.equal('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA');
        nock.cleanAll();

        // This second call should fail because we "stopped the server" and this key was not cached.
        client.getSigningKey('12345', (err) => {
          expect(err).not.to.be.null;
          expect(err.code).to.equal('ENOTFOUND');
          done();
        });
      });
    });
  });
});
