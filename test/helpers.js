'use strict';

// A fake AuthFI issuer for unit tests: it answers discovery and the JWKS like a project does, and
// signs tokens with each algorithm a project uses. Every URL the SDK fetches is recorded, so a test
// can assert what was actually asked for rather than a string it rebuilt itself.

const crypto = require('crypto');

const ISSUER = 'https://acme.authfi.io';
const AUDIENCE = 'https://api.acme.example';

function b64u(obj) {
  return Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj)).toString('base64url');
}

/** A signing key of one algorithm, with the public JWK an issuer would publish for it. */
function issuerKey(alg, kid = `${alg.toLowerCase()}-1`) {
  let pair;
  if (alg === 'EdDSA') pair = crypto.generateKeyPairSync('ed25519');
  else if (alg === 'ES256') pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  else pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg };
  return { alg, kid, privateKey: pair.privateKey, publicKey: pair.publicKey, jwk };
}

function signWith(alg, privateKey, data) {
  switch (alg) {
    case 'EdDSA':
      return crypto.sign(null, data, privateKey);
    case 'ES256':
      return crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    case 'PS256':
      return crypto.sign('sha256', data, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });
    default:
      return crypto.sign('sha256', data, privateKey);
  }
}

/**
 * Signs a token. `header` overrides header fields (to lie about alg or kid); `signAlg` signs with a
 * different algorithm from the one the key is published for.
 */
function sign(key, claims, { header = {}, signAlg } = {}) {
  const h = { alg: key.alg, typ: 'at+jwt', kid: key.kid, ...header };
  const input = `${b64u(h)}.${b64u(claims)}`;
  const sig = signWith(signAlg || key.alg, key.privateKey, Buffer.from(input));
  return `${input}.${sig.toString('base64url')}`;
}

/** Claims a project would put in an access token for AUDIENCE, valid for an hour. */
function claims(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, sub: 'agt_0123', aud: AUDIENCE, iat: now, exp: now + 3600, ...extra };
}

/**
 * A fetch that serves one issuer: discovery at both well-known paths (or only the ones listed in
 * `wellKnown`), the JWKS at `jwksUri`. `keys` can be swapped between calls to simulate rotation.
 */
function fakeIssuer({ issuer = ISSUER, keys = [], jwksUri = `${issuer}/keys/jwks.json`, docIssuer = issuer, wellKnown, extra = {}, routes = {} } = {}) {
  const state = { keys, calls: [] };
  const served = wellKnown || ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'];
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
  state.fetch = async (input, init = {}) => {
    const url = String(typeof input === 'string' ? input : input.url);
    state.calls.push({ url, init });
    if (routes[url]) return routes[url](init, state);
    for (const p of served) {
      if (url === issuer + p) return json(200, { issuer: docIssuer, jwks_uri: jwksUri, ...extra });
    }
    if (url === jwksUri) return json(200, { keys: state.keys.map((k) => k.jwk || k) });
    return json(404, { error: 'not_found' });
  };
  state.urls = () => state.calls.map((c) => c.url);
  return state;
}

module.exports = { ISSUER, AUDIENCE, issuerKey, sign, claims, fakeIssuer, b64u };
