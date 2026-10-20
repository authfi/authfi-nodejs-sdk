'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const authfi = require('..');
const { ISSUER, AUDIENCE, issuerKey, sign, claims, fakeIssuer, b64u } = require('./helpers');

function client(server, extra = {}) {
  return authfi({ issuer: ISSUER, audience: AUDIENCE, autoSync: false, fetch: server.fetch, ...extra });
}

describe('verifyToken: algorithms the issuer publishes', () => {
  for (const alg of ['EdDSA', 'ES256', 'RS256', 'PS256']) {
    it(`verifies an ${alg} token with the key from jwks_uri`, async () => {
      const key = issuerKey(alg);
      const server = fakeIssuer({ keys: [key] });
      const out = await client(server).verifyToken(sign(key, claims({ sub: `sub-${alg}` })));
      assert.equal(out.sub, `sub-${alg}`);
      assert.deepEqual(server.urls(), [
        `${ISSUER}/.well-known/oauth-authorization-server`,
        `${ISSUER}/keys/jwks.json`,
      ]);
    });
  }

  it('verifies an agent token held for a person (sub = person, act.sub = agent)', async () => {
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ keys: [key] });
    const out = await client(server).verifyToken(sign(key, claims({ sub: 'user:p@example.com', act: { sub: 'agent:agt_1' } })));
    assert.equal(out.act.sub, 'agent:agt_1');
  });

  it('falls back to OpenID discovery when RFC 8414 metadata is absent', async () => {
    const key = issuerKey('RS256');
    const server = fakeIssuer({ keys: [key], wellKnown: ['/.well-known/openid-configuration'] });
    await client(server).verifyToken(sign(key, claims()));
    assert.equal(server.urls()[1], `${ISSUER}/.well-known/openid-configuration`);
  });
});

describe('verifyToken: the key chooses the algorithm, never the header', () => {
  it('refuses an EdDSA-key token whose header says RS256', async () => {
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims(), { header: { alg: 'RS256' } })), { code: 'alg_mismatch' });
  });

  it('refuses an RS256 key used for PS256', async () => {
    const key = issuerKey('RS256');
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims(), { header: { alg: 'PS256' }, signAlg: 'PS256' })), { code: 'alg_mismatch' });
  });

  it('refuses HS256 signed with the public key as the secret', async () => {
    const key = issuerKey('RS256');
    const server = fakeIssuer({ keys: [key] });
    const pem = key.publicKey.export({ type: 'spki', format: 'pem' });
    const input = `${b64u({ alg: 'HS256', kid: key.kid })}.${b64u(claims())}`;
    const mac = crypto.createHmac('sha256', pem).update(input).digest('base64url');
    await assert.rejects(client(server).verifyToken(`${input}.${mac}`), { code: 'alg_mismatch' });
  });

  it('refuses alg none', async () => {
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ keys: [key] });
    const token = `${b64u({ alg: 'none', kid: key.kid })}.${b64u(claims())}.x`;
    await assert.rejects(client(server).verifyToken(token), { code: 'alg_mismatch' });
  });

  it('refuses a JWK whose alg disagrees with its key type', async () => {
    const key = issuerKey('EdDSA');
    key.jwk = { ...key.jwk, alg: 'RS256' };
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims(), { header: { alg: 'EdDSA' } })), { code: 'key_unusable' });
  });

  it('refuses a published key that carries a private component', async () => {
    const key = issuerKey('ES256');
    key.jwk = { ...key.privateKey.export({ format: 'jwk' }), kid: key.kid, alg: 'ES256' };
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims())), { code: 'key_unusable' });
  });

  it('refuses a token signed by another key under a known kid', async () => {
    const key = issuerKey('EdDSA');
    const other = issuerKey('EdDSA', key.kid);
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(other, claims())), { code: 'signature_invalid', message: 'Invalid signature' });
  });
});

describe('verifyToken: iss, aud and exp are required', () => {
  const key = issuerKey('EdDSA');

  it('refuses a token from another project', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ iss: 'https://other.authfi.io' }))), { code: 'issuer_mismatch' });
  });

  it('refuses a token for another audience', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ aud: 'https://other.example' }))), { code: 'audience_mismatch' });
  });

  it('refuses a token with no aud', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ aud: undefined }))), { code: 'audience_mismatch' });
  });

  it('accepts aud as a list containing the audience, and a list of accepted audiences', async () => {
    const server = fakeIssuer({ keys: [key] });
    await client(server).verifyToken(sign(key, claims({ aud: ['x', AUDIENCE] })));
    await client(server, { audience: ['https://a.example', AUDIENCE] }).verifyToken(sign(key, claims()));
  });

  it('refuses a token with no exp', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ exp: undefined }))), { code: 'exp_missing' });
  });

  it('refuses an expired token', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ exp: Math.floor(Date.now() / 1000) - 120 }))), { code: 'token_expired' });
  });

  it('refuses a token not valid yet', async () => {
    const server = fakeIssuer({ keys: [key] });
    await assert.rejects(client(server).verifyToken(sign(key, claims({ nbf: Math.floor(Date.now() / 1000) + 600 }))), { code: 'token_not_yet_valid' });
  });
});

describe('verifyToken: discovery and keys', () => {
  it('refuses discovery that names another issuer', async () => {
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ keys: [key], docIssuer: 'https://evil.example' });
    await assert.rejects(client(server).verifyToken(sign(key, claims())), /names issuer/);
  });

  it('builds the issuer from tenant and baseDomain when no issuer is given', async () => {
    const issuer = 'https://acme.authfi.app';
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ issuer, keys: [key] });
    const auth = authfi({ tenant: 'acme', baseDomain: 'authfi.app', audience: AUDIENCE, fetch: server.fetch });
    await auth.verifyToken(sign(key, claims({ iss: issuer })));
    assert.equal(server.urls()[0], `${issuer}/.well-known/oauth-authorization-server`);
  });

  it('does not let apiUrl move where keys come from', async () => {
    const key = issuerKey('EdDSA');
    const server = fakeIssuer({ keys: [key] });
    await client(server, { apiUrl: 'https://custom.api.example' }).verifyToken(sign(key, claims()));
    assert.ok(server.urls().every((u) => u.startsWith(ISSUER)));
  });

  it('refetches the JWKS once for a rotated key, and refuses a kid it still does not publish', async () => {
    const oldKey = issuerKey('EdDSA', 'old');
    const newKey = issuerKey('EdDSA', 'new');
    const server = fakeIssuer({ keys: [oldKey] });
    const auth = client(server);
    await auth.verifyToken(sign(oldKey, claims()));
    server.keys = [oldKey, newKey];
    const realNow = Date.now;
    Date.now = () => realNow() + 31000;
    try {
      await auth.verifyToken(sign(newKey, claims()));
      const before = server.calls.length;
      await assert.rejects(auth.verifyToken(sign(issuerKey('EdDSA', 'made-up'), claims())), { code: 'kid_unknown' });
      assert.equal(server.calls.length, before, 'a made-up kid right after a refetch must not fetch again');
    } finally {
      Date.now = realNow;
    }
  });

  it('does not cache a failed discovery', async () => {
    const key = issuerKey('EdDSA');
    const good = fakeIssuer({ keys: [key] });
    let fail = true;
    const fetch = async (url, init) => (fail ? new Response('down', { status: 503 }) : good.fetch(url, init));
    const auth = authfi({ issuer: ISSUER, audience: AUDIENCE, fetch });
    await assert.rejects(auth.verifyToken(sign(key, claims())), /HTTP 503/);
    fail = false;
    await auth.verifyToken(sign(key, claims()));
  });

  it('refuses a malformed token', async () => {
    const server = fakeIssuer({ keys: [issuerKey('EdDSA')] });
    await assert.rejects(client(server).verifyToken('not-a-token'), { code: 'token_malformed' });
    await assert.rejects(client(server).verifyToken('a.b'), { code: 'token_malformed' });
  });
});

describe('verifyToken: configuration', () => {
  it('requires an audience', async () => {
    const auth = authfi({ issuer: ISSUER });
    await assert.rejects(auth.verifyToken('a.b.c'), { name: 'ConfigError' });
  });

  it('requires an https issuer', async () => {
    const auth = authfi({ issuer: 'http://acme.authfi.io', audience: AUDIENCE });
    await assert.rejects(auth.verifyToken('a.b.c'), { name: 'ConfigError' });
  });

  it('answers 500, not 401, from the middleware when it is not configured', async () => {
    const auth = authfi({ issuer: ISSUER, autoSync: false });
    let status = 0;
    const res = { status(c) { status = c; return this; }, json() {} };
    const err = console.error;
    console.error = () => {};
    try {
      await auth.authenticate()({ headers: { authorization: 'Bearer a.b.c' } }, res, () => assert.fail('next'));
    } finally {
      console.error = err;
    }
    assert.equal(status, 500);
  });
});
