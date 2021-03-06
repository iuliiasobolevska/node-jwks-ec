# jwks-ec

[![NPM version][npm-image]][npm-url]
[![License][license-image]][license-url]
[![Downloads][downloads-image]][downloads-url]

A library to retrieve EC signing keys from a JWKS (JSON Web Key Set) endpoint.

> npm install --save jwks-ec

## Usage

You'll provide the client with the JWKS endpoint which exposes your signing keys. Using the `getSigningKey` you can then get the signing key that matches a specific `kid`.

```js
const jwksClient = require('jwks-ec');

const client = jwksClient({
  strictSsl: true, // Default value
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json',
  requestHeaders: {}, // Optional
  requestAgentOptions: {} // Optional
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.privateKey;

  // Now I can use this to configure my Express or Hapi middleware
});
```


### Caching

In order to prevent a call to be made each time a signing key needs to be retrieved you can also configure a cache as follows. If a signing key matching the `kid` is found, this will be cached and the next time this `kid` is requested the signing key will be served from the cache instead of calling back to the JWKS endpoint.

```js
const jwksClient = require('jwks-ec');

const client = jwksClient({
  cache: true,
  cacheMaxEntries: 5, // Default value
  cacheMaxAge: ms('10h'), // Default value
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.privateKey;

  // Now I can use this to configure my Express or Hapi middleware
});
```

### Using AgentOptions for TLS/SSL Configuration

The `requestAgentOptions` property can be used to configure SSL/TLS options. An
example use case is providing a trusted private (i.e. enterprise/corporate) root
certificate authority to establish TLS communication with the `jwks_uri`.

```js
const jwksClient = require("jwks-ec");
const client = jwksClient({
  strictSsl: true, // Default value
  jwksUri: 'https://my-enterprise-id-provider/.well-known/jwks.json',
  requestHeaders: {}, // Optional
  requestAgentOptions: {
    ca: fs.readFileSync(caFile)
  }
});
```

For more information, see [the NodeJS request library `agentOptions`
documentation](https://github.com/request/request#using-optionsagentoptions).

## Running Tests

```
npm run test
```

## Showing Trace Logs

To show trace logs you can set the following environment variable:

```
DEBUG=jwks
```

Output:

```
jwks Retrieving keys from http://my-authz-server/.well-known/jwks.json +5ms
jwks Keys: +8ms [ { alg: 'ES256',
  kty: 'RSA',
  use: 'sig',
  x5c: [ 'pk1' ],
  kid: 'ABC' },
{ alg: 'RS256', kty: 'RSA', use: 'sig', x5c: [], kid: '123' } ]
```

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

[npm-image]: https://img.shields.io/npm/v/jwks-ec.svg?style=flat-square
[npm-url]: https://npmjs.org/package/jwks-ec
[license-image]: http://img.shields.io/npm/l/jwks-ec.svg?style=flat-square
[license-url]: #license
[downloads-image]: http://img.shields.io/npm/dm/jwks-ec.svg?style=flat-square
[downloads-url]: https://npmjs.org/package/jwks-ec
