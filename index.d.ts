import { SecretCallback, SecretCallbackLong } from 'express-jwt';

declare function JwksEc(options: JwksEc.ClientOptions): JwksEc.JwksClient;

declare namespace JwksEc {
  class JwksClient {
    constructor(options: ClientOptions);

    getKeys(cb: (err: Error | null, keys: unknown) => void): void;
    getSigningKeys(cb: (err: Error | null, keys: SigningKey[]) => void): void;
    getSigningKey: (kid: string, cb: (err: Error | null, key: SigningKey) => void) => void;
  }

  interface Headers {
    [key: string]: string;
  }

  interface ClientOptions {
    jwksUri: string;
    rateLimit?: boolean;
    cache?: boolean;
    cacheMaxEntries?: number;
    cacheMaxAge?: number;
    jwksRequestsPerMinute?: number;
    strictSsl?: boolean;
    requestHeaders?: Headers;
  }

  interface SigningKey {
    kid: string;
    nbf: string;
    publicKey: string;
    privateKey: string|undefined;
  }

  interface AgentOptions {
    [key: string]: string;
  }

  interface Options {
    jwksUri: string;
    rateLimit?: boolean;
    cache?: boolean;
    cacheMaxEntries?: number;
    cacheMaxAge?: number;
    jwksRequestsPerMinute?: number;
    strictSsl?: boolean;
    requestHeaders?: Headers;
    requestAgentOptions?: AgentOptions;
    handleSigningKeyError?(err: Error, cb: (err: Error) => void): any;
  }

  function expressJwtSecret(options: ExpressJwtOptions): SecretCallbackLong;

  function passportJwtSecret(options: ExpressJwtOptions): SecretCallback;

  interface ExpressJwtOptions extends ClientOptions {
    handleSigningKeyError?: (err: Error | null, cb: (err: Error | null) => void) => void;
  }

  function hapiJwt2Key(options: HapiJwtOptions): (decodedToken: DecodedToken, cb: HapiCallback) => void;

  interface HapiJwtOptions extends ClientOptions {
    handleSigningKeyError?: (err: Error | null, cb: HapiCallback) => void;
  }

  type HapiCallback = (err: Error | null, publicKey: string, signingKey: SigningKey) => void;

  interface DecodedToken {
    header: TokenHeader;
  }

  interface TokenHeader {
    alg: string;
    kid: string;
  }

  function hapiJwt2KeyAsync(options: HapiJwtOptions): (decodedToken: DecodedToken) => Promise<{ key: string }>;

  function koaJwtSecret(options: KoaJwtOptions): (header: TokenHeader) => Promise<string>;

  interface KoaJwtOptions extends ClientOptions {
    handleSigningKeyError?(err: Error | null): Promise<void>;
  }

  class ArgumentError extends Error {
    name: 'ArgumentError';
    constructor(message: string);
  }

  class JwksError extends Error {
    name: 'JwksError';
    constructor(message: string);
  }

  class JwksRateLimitError extends Error {
    name: 'JwksRateLimitError';
    constructor(message: string);
  }

  class SigningKeyNotFoundError extends Error {
    name: 'SigningKeyNotFoundError';
    constructor(message: string);
  }
}

export = JwksEc;
