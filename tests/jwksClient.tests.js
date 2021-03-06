const nock = require("nock");
const { expect } = require("chai");

const { multiple, single, public } = require("./keys");
const { JwksClient } = require("../src/JwksClient");

describe("JwksClient", () => {
  const jwksHost = "http://my-authz-server";

  beforeEach(() => {
    nock.cleanAll();
  });

  describe("#getKeys", () => {
    it("should handle errors", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(500, "Unknown Server Error");

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getKeys(err => {
        expect(err).not.to.be.null;
        expect(err.message).to.equal("Unknown Server Error");
        done();
      });
    });

    it("should return multiple keys", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, multiple);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getKeys((err, keys) => {
        expect(err).to.be.null;
        expect(keys).not.to.be.null;
        expect(keys.length).to.equal(2);
        expect(keys[1].kid).to.equal(multiple.keys[1].kid);
        done();
      });
    });

    it("should return single key", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, single);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getKeys((err, key) => {
        expect(err).to.be.null;
        expect(key).not.to.be.null;
        expect(key.kid).to.equal(single.kid);
        done();
      });
    });
    it("should set request agentOptions when provided", done => {
      nock(jwksHost)
        .get("./well-known/jwks.json")
        .reply(function() {
          expect(this.req.agentOptions).not.to.be.null;
          expect(this.req.agentOptions["ca"]).to.be.equal("loadCA()");
          return 200;
        });

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`,
        requestAgentOptions: {
          ca: "loadCA()"
        }
      });

      client.getKeys((err, keys) => {
        done();
      });
    });

    it("should not set request agentOptions by default", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(function() {
          expect(this.req).to.not.have.property("agentOptions");
          return 200;
        });

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getKeys((err, keys) => {
        done();
      });
    });

    it("should send extra header", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(function(uri, requestBody) {
          expect(this.req.headers).not.to.be.null;
          expect(this.req.headers["user-agent"]).to.be.equal("My-bot");
          expect(Object.keys(this.req.headers).length).to.be.equal(3);
          return (
            200,
            {
              keys: [
                {
                  alg: "RS256",
                  kty: "RSA",
                  use: "sig",
                  x5c: ["pk1"],
                  kid: "ABC"
                },
                {
                  alg: "RS256",
                  kty: "RSA",
                  use: "sig",
                  x5c: [],
                  kid: "123"
                }
              ]
            }
          );
        });

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`,
        requestHeaders: {
          "User-Agent": "My-bot"
        }
      });

      client.getKeys((err, keys) => {
        done();
      });
    });

    it("should not send the extra headers when not provided", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(function(uri, requestBody) {
          expect(this.req.headers).not.to.be.null;
          expect(this.req.headers["accept"]).not.to.be.undefined;
          expect(this.req.headers["host"]).not.to.be.undefined;
          expect(Object.keys(this.req.headers).length).to.be.equal(2);
          return (
            200,
            {
              keys: [
                {
                  alg: "RS256",
                  kty: "RSA",
                  use: "sig",
                  x5c: ["pk1"],
                  kid: "ABC"
                },
                {
                  alg: "RS256",
                  kty: "RSA",
                  use: "sig",
                  x5c: [],
                  kid: "123"
                }
              ]
            }
          );
        });

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getKeys((err, keys) => {
        done();
      });
    });
  });

  describe("#getSigningKeys", () => {
    it("should handle errors", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(500, "Unknown Server Error");

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKeys(err => {
        expect(err).not.to.be.null;
        expect(err.message).to.equal("Unknown Server Error");
        done();
      });
    });

    it("should return signing keys", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, multiple);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKeys((err, keys) => {
        expect(err).to.be.null;
        expect(keys).not.to.be.null;
        expect(keys.length).to.equal(2);
        expect(keys[0].publicKey).not.to.be.null;
        expect(keys[0].privateKey).not.to.be.null;
        expect(keys[0].kid).to.equal(
          "NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA"
        );
        expect(keys[1].kid).to.equal(
          "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
        );
        expect(keys[1].publicKey).not.to.be.null;
        expect(keys[1].privateKey).not.to.be.null;
        done();
      });
    });
    
    it("should return a single signing key", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, single);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKeys((err, keys) => {
        expect(err).to.be.null;
        expect(keys).not.to.be.null;
        expect(keys.length).to.equal(1);
        expect(keys[0].publicKey).not.to.be.null;
        expect(keys[0].privateKey).not.to.be.null;
        expect(keys[0].kid).to.equal(
          "NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA"
        );
        done();
      });
    });
    
    it("should return a public signing key", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, public);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKeys((err, keys) => {
        expect(err).to.be.null;
        expect(keys).not.to.be.null;
        expect(keys.length).to.equal(1);
        expect(keys[0].publicKey).not.to.be.null;
        expect(keys[0].privateKey).to.be.undefined;
        expect(keys[0].kid).to.equal(
          "NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA"
        );
        done();
      });
    });

     it("should only take the signing keys from the keys", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, {
          keys: [
            {
              kty: "something",
              use: "else",
              x5c: [
                "MIIDDTCCAfWgAwIBAgIJAJVkuSv2H8mDMA0GCSqGSIb3DQEBBQUAMB0xGzAZBgNVBAMMEnNhbmRyaW5vLmF1dGgwLmNvbTAeFw0xNDA1MTQyMTIyMjZaFw0yODAxMjEyMTIyMjZaMB0xGzAZBgNVBAMMEnNhbmRyaW5vLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6jWASkHhXz5Ug6t5BsYBrXDIgrWu05f3oq2fE+5J5REKJiY0Ddc+Kda34ZwOptnUoef3JwKPDAckTJQDugweNNZPwOmFMRKj4xqEpxEkIX8C+zHs41Q6x54ZZy0xU+WvTGcdjzyZTZ/h0iOYisswFQT/s6750tZG0BOBtZ5qS/80tmWH7xFitgewdWteJaASE/eO1qMtdNsp9fxOtN5U/pZDUyFm3YRfOcODzVqp3wOz+dcKb7cdZN11EYGZOkjEekpcedzHCo9H4aOmdKCpytqL/9FXoihcBMg39s1OW3cfwfgf5/kvOJdcqR4PoATQTfsDVoeMWVB4XLGR6SC5kCAwEAAaNQME4wHQYDVR0OBBYEFHDYn9BQdup1CoeoFi0Rmf5xn/W9MB8GA1UdIwQYMBaAFHDYn9BQdup1CoeoFi0Rmf5xn/W9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGLpQZdd2ICVnGjc6CYfT3VNoujKYWk7E0shGaCXFXptrZ8yaryfo6WAizTfgOpQNJH+Jz+QsCjvkRt6PBSYX/hb5OUDU2zNJN48/VOw57nzWdjI70H2Ar4oJLck36xkIRs/+QX+mSNCjZboRwh0LxanXeALHSbCgJkbzWbjVnfJEQUP9P/7NGf0MkO5I95C/Pz9g91y8gU+R3imGppLy9Zx+OwADFwKAEJak4JrNgcjHBQenakAXnXP6HG4hHH4MzO8LnLiKv8ZkKVL67da/80PcpO0miMNPaqBBMd2Cy6GzQYE0ag6k0nk+DMIFn7K+o21gjUuOEJqIbAvhbf2KcM="
              ],
              n:
                "vqNYBKQeFfPlSDq3kGxgGtcMiCta7Tl_eirZ8T7knlEQomJjQN1z4p1rfhnA6m2dSh5_cnAo8MByRMlAO6DB401k_A6YUxEqPjGoSnESQhfwL7MezjVDrHnhlnLTFT5a9MZx2PPJlNn-HSI5iKyzAVBP-zrvnS1kbQE4G1nmpL_zS2ZYfvEWK2B7B1a14loBIT947Woy102yn1_E603lT-lkNTIWbdhF85w4PNWqnfA7P51wpvtx1k3XURgZk6SMR6Slx53McKj0fho6Z0oKnK2ov_0VeiKFwEyDf2zU5bdx_B-B_n-S84l1ypHg-gBNBN-wNWh4xZUHhcsZHpILmQ",
              e: "AQAB",
              kid: "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg",
              x5t: "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
            },
            {
              kty: "something",
              use: "else",
              nbf: 123,
              x5c: [
                "MIIDGzCCAgOgAwIBAgIJAPQM5+PwmOcPMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMMGXNhbmRyaW5vLWRldi5ldS5hdXRoMC5jb20wHhcNMTUwMzMxMDkwNTQ3WhcNMjgxMjA3MDkwNTQ3WjAkMSIwIAYDVQQDDBlzYW5kcmluby1kZXYuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv/SECtT7H4rxKtX2HpGhSyeYTe3Vet8YQpjBAr+1TnQ1fcYfvfmnVRHvhmTwABktD1erF1lxFsrRw92yBDOHlL7lj1n2fcfLftSoStgvRHVg52kR+CkBVQ6/mF1lYkefIjik6YRMf55Eu4FqDyVG2dgd5EA8kNO4J8OPc7vAtZyXrRYOZjVXbEgyjje/V+OpMQxAHP2Er11TLuzJjioP0ICVqhAZdq2sLk7agoxn64md6fqOk4N+7lJkU4+412VD0qYwKxD7nGsEclYawKoZD9/xhCk2qfQ/HptIumrdQ5ox3Sq5t2a7VKa41dBUQ1MQtXG2iY7S9RlfcMIyQwGhOQIDAQABo1AwTjAdBgNVHQ4EFgQUHpS1fvO/54G2c1VpEDNUZRSl44gwHwYDVR0jBBgwFoAUHpS1fvO/54G2c1VpEDNUZRSl44gwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtm9I0nr6eXF5aq4yllfiqZcQ6mKrJLH9Rm4Jv+olniNynTcnpwprRVLToIawc8MmzIGZTtCn7u+dSxWf1UNE+SH7XgEnGtO74239vleEx1+Tf5viIdsnCxgvFiPdOqRlc9KcFSWd6a7RzcglnyU7GEx0K5GLv1wPA6qEM+3uwNwjAyVSu5dFw8kCfaSvlk5rXKRUzSoW9NVomw6+tADR8vMZS+4KThZ+4GH0rMN4KjIaRFxW8OMVYOn12uq33fLCd6MuPHW/rklxLbQBoHIU/ClNhbD0t6f00w9lHhPy4IP73rv7Oow0Ny6i70Iq0ijqj+kAtnrphlOvLFxqn6nCvQ=="
              ],
              n:
                "v_SECtT7H4rxKtX2HpGhSyeYTe3Vet8YQpjBAr-1TnQ1fcYfvfmnVRHvhmTwABktD1erF1lxFsrRw92yBDOHlL7lj1n2fcfLftSoStgvRHVg52kR-CkBVQ6_mF1lYkefIjik6YRMf55Eu4FqDyVG2dgd5EA8kNO4J8OPc7vAtZyXrRYOZjVXbEgyjje_V-OpMQxAHP2Er11TLuzJjioP0ICVqhAZdq2sLk7agoxn64md6fqOk4N-7lJkU4-412VD0qYwKxD7nGsEclYawKoZD9_xhCk2qfQ_HptIumrdQ5ox3Sq5t2a7VKa41dBUQ1MQtXG2iY7S9RlfcMIyQwGhOQ",
              e: "AQAB",
              kid: "NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA",
              x5t: "NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA"
            }
          ]
        });

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKeys(err => {
        expect(err).not.to.be.null;
        expect(err.name).to.equal("JwksError");
        expect(err.message).to.equal(
          "The JWKS endpoint did not contain any signing keys"
        );
        done();
      });
    });
  });

  describe("#getSigningKey", () => {
    it("should return error if signing key is not found", done => {
      nock(jwksHost)
        .get("/.well-known/jwks.json")
        .reply(200, multiple);

      const client = new JwksClient({
        jwksUri: `${jwksHost}/.well-known/jwks.json`
      });

      client.getSigningKey("1234", err => {
        expect(err).not.to.be.null;
        expect(err.name).to.equal("SigningKeyNotFoundError");
        done();
      });
    });
  });
});
