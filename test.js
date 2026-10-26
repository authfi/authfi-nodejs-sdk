'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const authfi = require('./index');
const { scenario, rejectsWith, signJWS, b64u, ISSUER, AUD } = require('./test-helpers/fixture');

const nowSec = (s) => Math.floor(s.clock.t / 1000);
const bearer = (s, t) => s.request(t, { scheme: 'Bearer', proofs: [] });

// refuse: the control (a good token on the same client) verifies, then the broken one is refused.
async function refuse(code, make, cfg) {
  const s = scenario(cfg);
  assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1', 'control leg');
  const bad = make(s);
  const err = await rejectsWith(s.client.verifyToken(bad), code, assert);
  assert.ok(!err.message.includes(bad), 'the message must not hold the token');
  return err;
}

describe('authfi()', () => {
  it('returns an object with expected methods', () => {
    const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
    for (const m of ['require', 'requireRole', 'authenticate', 'verifyToken', 'verifyRequest', 'start', 'registerPermission', 'syncPermissions']) {
      assert.equal(typeof auth[m], 'function', m);
    }
    assert.equal(typeof auth.cloud, 'object');
  });
});

describe('configuration fails closed', () => {
  const cases = {
    'no issuer': { audience: AUD },
    'no audience': { issuer: ISSUER },
    'empty audience': { issuer: ISSUER, audience: [] },
    'blank audience value': { issuer: ISSUER, audience: ['  '] },
    'the issuer as audience': { issuer: ISSUER, audience: ISSUER },
    'a path of the issuer as audience': { issuer: ISSUER, audience: `${ISSUER}/api` },
    'the AuthFI console as audience': { issuer: ISSUER, audience: 'authfi-console' },
    'the AuthFI workspace as audience': { issuer: ISSUER, audience: ['api', 'authfi-workspace'] },
    'the API URL as audience': { issuer: ISSUER, audience: 'https://api.authfi.io', apiUrl: 'https://api.authfi.io' },
    'a plain http issuer': { issuer: 'http://acme.authfi.io', audience: AUD },
    'an issuer that is not a URL': { issuer: 'acme', audience: AUD },
    'leeway above 300 s': { issuer: ISSUER, audience: AUD, leeway: 301 },
  };
  for (const [name, cfg] of Object.entries(cases)) {
    it(`sdk_not_configured: ${name}`, async () => {
      const s = scenario();
      const good = s.token(s.claims());
      const bad = authfi({ tenant: 'acme', apiKey: 'k', fetch: s.config.fetch, now: s.config.now, ...cfg });
      await rejectsWith(bad.verifyToken(good), 'sdk_not_configured', assert);
      assert.equal((await s.client.verifyToken(good)).sub, 'usr_1');
    });
  }
  it('http is allowed for a loopback issuer (local development)', async () => {
    const s = scenario({ config: { issuer: 'http://localhost:8080' } });
    const t = s.token(s.claims({ iss: 'http://localhost:8080' }));
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
  });
});

describe('baseline verification', () => {
  it('accepts a valid access token and returns its claims', async () => {
    const s = scenario();
    const claims = await s.client.verifyToken(s.token(s.claims({ roles: ['admin'], permissions: ['read:users'] })));
    assert.equal(claims.sub, 'usr_1');
    assert.deepEqual(claims.roles, ['admin']);
  });
  it('accepts an RS256 token on an RSA key and an EdDSA token on an Ed25519 key', async () => {
    for (const kind of ['rsa', 'ed']) {
      const pair = kind === 'rsa' ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }) : crypto.generateKeyPairSync('ed25519');
      const alg = kind === 'rsa' ? 'RS256' : 'EdDSA';
      const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' };
      const s = scenario({ jwks: { keys: [jwk] } });
      const t = signJWS({ alg, typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, alg);
      assert.equal((await s.client.verifyToken(t)).sub, 'usr_1', alg);
    }
  });
  it('accepts a PS256 token on an RSA key', async () => {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const s = scenario({ jwks: { keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' }] } });
    const t = signJWS({ alg: 'PS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, 'PS256');
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
  });
  it('accepts the typ application/at+jwt, an array audience, a trailing slash on the issuer and a tenant match', async () => {
    const s = scenario({ config: { tenantId: 'tnt_1' } });
    const t = s.token(s.claims({ aud: ['x', AUD], iss: `${ISSUER}/` }), { typ: 'application/at+jwt' });
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
  });
  it('token_malformed: not three parts', () => refuse('token_malformed', () => 'a.b'));
  it('token_malformed: four parts', () => refuse('token_malformed', (s) => `${s.token(s.claims())}.x`));
  it('token_malformed: an empty token and a non-string', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyToken(''), 'token_malformed', assert);
    await rejectsWith(s.client.verifyToken(undefined), 'token_malformed', assert);
  });
  it('token_malformed: header or payload that is not JSON, or JSON that is not an object', async () => {
    await refuse('token_malformed', () => `${b64u('nope')}.${b64u('{}')}.${b64u('x')}`);
    await refuse('token_malformed', (s) => s.token(b64u('[1]')));
  });
  it('token_malformed: padded base64, non-canonical trailing bits and a newline', async () => {
    await refuse('token_malformed', (s) => { const [h, p, g] = s.token(s.claims()).split('.'); return `${h}=.${p}.${g}`; });
    await refuse('token_malformed', (s) => { const [h, p, g] = s.token(s.claims()).split('.'); return `${h}.${p}.${g.slice(0, -1)}B`; });
    await refuse('token_malformed', (s) => { const [h, p, g] = s.token(s.claims()).split('.'); return `${h}\n.${p}.${g}`; });
  });
  it('token_malformed: an empty signature', () => refuse('token_malformed', (s) => { const [h, p] = s.token(s.claims()).split('.'); return `${h}.${p}.`; }));
  it('token_too_large: over 16 KiB', () => refuse('token_too_large', (s) => s.token(s.claims({ pad: 'x'.repeat(17000) }))));
  it('token_alg_not_allowed: none', () => refuse('token_alg_not_allowed', (s) => signJWS({ alg: 'none', typ: 'at+jwt', kid: 'k1' }, s.claims(), null, 'none')));
  it('token_alg_not_allowed: HS256 signed with the public key as the secret', async () => {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = pair.publicKey.export({ type: 'spki', format: 'pem' });
    const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };
    const s = scenario({ jwks: { keys: [jwk] } });
    const t = signJWS({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pem, 'HS256');
    await rejectsWith(s.client.verifyToken(t), 'token_alg_not_allowed', assert);
    const t2 = signJWS({ alg: 'RS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, 'RS256');
    assert.equal((await s.client.verifyToken(t2)).sub, 'usr_1');
  });
  it('token_alg_not_allowed: HS512, RS512, ES384, a lower-case alg and an empty one', async () => {
    for (const alg of ['HS512', 'RS512', 'ES384', 'es256', '']) {
      await refuse('token_alg_not_allowed', (s) => s.token(s.claims(), { alg }));
    }
  });
  it('token_alg_key_mismatch: an RS256 token against an EC key (algorithm confusion)', () =>
    refuse('token_alg_key_mismatch', (s) => s.token(s.claims(), { alg: 'RS256' })));
  it('token_alg_key_mismatch: a key pinned to ES256 by its alg refuses PS256', () =>
    refuse('token_alg_key_mismatch', (s) => s.token(s.claims(), { alg: 'PS256' })));
  it('token_kid_required: no kid', () => refuse('token_kid_required', (s) => s.token(s.claims(), { kid: undefined })));
  it('token_crit_not_supported: a crit header', () => refuse('token_crit_not_supported', (s) => s.token(s.claims(), { crit: ['exp'] })));
  it('token_typ_invalid: an ID token, a plain JWT, a missing typ, a proof type', async () => {
    await refuse('token_typ_invalid', (s) => s.token(s.claims(), { typ: 'JWT' }));
    await refuse('token_typ_invalid', (s) => s.token(s.claims(), { typ: 'id+jwt' }));
    await refuse('token_typ_invalid', (s) => s.token(s.claims(), { typ: undefined }));
    await refuse('token_typ_invalid', (s) => s.token(s.claims(), { typ: 'dpop+jwt' }));
  });
  it('token_unknown_key: a kid the issuer never published', () => refuse('token_unknown_key', (s) => s.token(s.claims(), { kid: 'nope' })));
  it('token_unknown_key: keys never come from the token (embedded jwk and jku are ignored)', async () => {
    const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    await refuse('token_unknown_key', (s) => s.token(s.claims(), { kid: 'evil', jwk: attacker.publicKey.export({ format: 'jwk' }), jku: 'https://evil.example/jwks' }, attacker.privateKey));
  });
  it('token_signature_invalid: signed by another key, and a tampered payload', async () => {
    await refuse('token_signature_invalid', (s) => s.token(s.claims(), {}, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey));
    await refuse('token_signature_invalid', (s) => { const [h, , g] = s.token(s.claims()).split('.'); return `${h}.${b64u(JSON.stringify(s.claims({ sub: 'usr_2' })))}.${g}`; });
  });
  it('token_issuer_mismatch', async () => {
    await refuse('token_issuer_mismatch', (s) => s.token(s.claims({ iss: 'https://other.authfi.io' })));
    await refuse('token_issuer_mismatch', (s) => s.token(s.claims({ iss: undefined })));
  });
  it('token_audience_mismatch: wrong, missing and empty audiences', async () => {
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: 'other-api' })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: undefined })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: [] })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: [5, null] })));
  });
  it('token_audience_mismatch: a token minted for the AuthFI console is not accepted by an API', () =>
    refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: 'authfi-console' }))));
  it('token_expired: past exp, even with the leeway', () => refuse('token_expired', (s) => s.token(s.claims({ exp: nowSec(s) - 61 }))));
  it('the leeway lets a token that expired 30 s ago through, and leeway 0 does not', async () => {
    const s = scenario();
    assert.equal((await s.client.verifyToken(s.token(s.claims({ exp: nowSec(s) - 30 })))).sub, 'usr_1');
    const strict = scenario({ config: { leeway: 0 } });
    await rejectsWith(strict.client.verifyToken(strict.token(strict.claims({ exp: nowSec(strict) - 1 }))), 'token_expired', assert);
  });
  it('token_exp_required: no exp, or one that is not a number', async () => {
    await refuse('token_exp_required', (s) => s.token(s.claims({ exp: undefined })));
    await refuse('token_exp_required', (s) => s.token(s.claims({ exp: '9999999999' })));
    await refuse('token_exp_required', (s) => s.token(s.claims({ exp: -1 })));
  });
  it('token_not_yet_valid: nbf and iat in the future', async () => {
    await refuse('token_not_yet_valid', (s) => s.token(s.claims({ nbf: nowSec(s) + 120 })));
    await refuse('token_not_yet_valid', (s) => s.token(s.claims({ iat: nowSec(s) + 120 })));
  });
  it('token_sub_required', () => refuse('token_sub_required', (s) => s.token(s.claims({ sub: undefined }))));
  it('token_tenant_required', () => refuse('token_tenant_required', (s) => s.token(s.claims({ tenant_id: undefined }))));
  it('token_tenant_not_issuers: tenant_id differs from the configured tenantId', async () => {
    const s = scenario({ config: { tenantId: 'tnt_1' } });
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).tenant_id, 'tnt_1');
    await rejectsWith(s.client.verifyToken(s.token(s.claims({ tenant_id: 'tnt_2' }))), 'token_tenant_not_issuers', assert);
  });
});

describe('the key set', () => {
  it('is fetched from the issuer origin and cached', async () => {
    const s = scenario();
    await s.client.verifyToken(s.token(s.claims()));
    await s.client.verifyToken(s.token(s.claims()));
    assert.deepEqual(s.fetches, [`${ISSUER}/.well-known/jwks.json`]);
  });
  it('is fetched from jwksUrl when one is configured', async () => {
    const s = scenario({ config: { jwksUrl: 'https://keys.example.com/jwks' } });
    await s.client.verifyToken(s.token(s.claims()));
    assert.deepEqual(s.fetches, ['https://keys.example.com/jwks']);
  });
  it('an unknown kid refetches at most once every 15 s', async () => {
    const s = scenario();
    await s.client.verifyToken(s.token(s.claims()));
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'n1' })), 'token_unknown_key', assert);
    assert.equal(s.fetches.length, 1);
    s.clock.t += 20000;
    await rejectsWith(s.client.verifyToken(s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }), { kid: 'n1' })), 'token_unknown_key', assert);
    assert.equal(s.fetches.length, 2);
  });
  it('jwks_unavailable: the fetch fails, answers 500, is not JSON, is too large, or holds no key', async () => {
    const fetches = [
      async () => { throw new Error('down'); },
      async () => new Response('x', { status: 500 }),
      async () => new Response('not json', { status: 200 }),
      async () => new Response(' '.repeat(1100000), { status: 200 }),
      async () => new Response(JSON.stringify({ keys: [] }), { status: 200 }),
    ];
    for (const fetch of fetches) {
      const s = scenario({ config: { fetch } });
      await rejectsWith(s.client.verifyToken(s.token(s.claims())), 'jwks_unavailable', assert);
    }
  });
  it('serves a stale key for a while when a refresh fails, and not forever', async () => {
    const s = scenario();
    const good = s.config.fetch;
    let down = false;
    const c = authfi({ ...s.config, fetch: async (u) => { if (down) throw new Error('down'); return good(u); } });
    await c.verifyToken(s.token(s.claims()));
    down = true;
    s.clock.t += 10 * 60 * 1000;
    const t = s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }));
    assert.equal((await c.verifyToken(t)).sub, 'usr_1');
    s.clock.t += 2 * 3600 * 1000;
    const t2 = s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }));
    await rejectsWith(c.verifyToken(t2), 'jwks_unavailable', assert);
  });
  it('ignores a key with use=enc, a small RSA key and a key that does not parse', async () => {
    const small = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    const enc = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const s = scenario();
    s.jwks.keys.push({ ...small.publicKey.export({ format: 'jwk' }), kid: 'small', use: 'sig' });
    s.jwks.keys.push({ ...enc.publicKey.export({ format: 'jwk' }), kid: 'enc', use: 'enc' });
    s.jwks.keys.push({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA', kid: 'junk' });
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1');
    await rejectsWith(s.client.verifyToken(signJWS({ alg: 'RS256', typ: 'at+jwt', kid: 'small' }, s.claims(), small.privateKey, 'RS256')), 'token_unknown_key', assert);
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'enc' }, enc.privateKey)), 'token_unknown_key', assert);
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'junk' })), 'token_unknown_key', assert);
  });
});

describe('verifyRequest on a person token', () => {
  it('accepts a Bearer token and returns the claims', async () => {
    const s = scenario();
    assert.equal((await s.client.verifyRequest(bearer(s, s.token(s.claims())))).sub, 'usr_1');
  });
  it('missing_authorization: no header, wrong scheme, two Authorization values', async () => {
    const s = scenario();
    const t = s.token(s.claims());
    assert.equal((await s.client.verifyRequest(bearer(s, t))).sub, 'usr_1');
    const r1 = bearer(s, t); delete r1.headers.authorization; r1.rawHeaders = [];
    await rejectsWith(s.client.verifyRequest(r1), 'missing_authorization', assert);
    await rejectsWith(s.client.verifyRequest(s.request(t, { scheme: 'Basic', proofs: [] })), 'missing_authorization', assert);
    const r3 = bearer(s, t); r3.rawHeaders.push('Authorization', `Bearer ${t}`);
    await rejectsWith(s.client.verifyRequest(r3), 'missing_authorization', assert);
  });
});

describe('require() and requireRole() middleware', () => {
  const res = () => {
    const r = { statusCode: 200, headers: {}, body: undefined };
    r.status = (c) => { r.statusCode = c; return r; };
    r.json = (b) => { r.body = b; return r; };
    r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
    return r;
  };
  it('passes with a valid token and permission, sets req.user', async () => {
    const s = scenario();
    const req = bearer(s, s.token(s.claims({ permissions: ['read:users'], roles: ['admin'] })));
    let called = false;
    await s.client.require('read:users')(req, res(), () => { called = true; });
    assert.ok(called);
    assert.equal(req.user.sub, 'usr_1');
    called = false;
    await s.client.requireRole('admin')(req, res(), () => { called = true; });
    assert.ok(called);
  });
  it('403 on a missing permission or role', async () => {
    const s = scenario();
    const req = bearer(s, s.token(s.claims({ permissions: [], roles: [] })));
    const r1 = res(); let called = false;
    await s.client.require('read:users')(req, r1, () => { called = true; });
    assert.equal(r1.statusCode, 403);
    const r2 = res();
    await s.client.requireRole('admin')(req, r2, () => { called = true; });
    assert.equal(r2.statusCode, 403);
    assert.ok(!called);
  });
  it('401 with the refusal code on a bad token, and 503 when the key set is down', async () => {
    const s = scenario();
    const r1 = res();
    await s.client.require('x')(bearer(s, s.token(s.claims({ aud: 'other' }))), r1, () => assert.fail('next'));
    assert.equal(r1.statusCode, 401);
    assert.deepEqual(r1.body, { error: 'token_audience_mismatch' });
    const down = scenario({ config: { fetch: async () => { throw new Error('down'); } } });
    const r2 = res();
    await down.client.require('x')(bearer(down, down.token(down.claims())), r2, () => assert.fail('next'));
    assert.equal(r2.statusCode, 503);
  });
  it('401 missing_authorization without a header', async () => {
    const s = scenario();
    const r = res();
    const req = bearer(s, 'x'); delete req.headers.authorization; req.rawHeaders = [];
    await s.client.require('x')(req, r, () => assert.fail('next'));
    assert.deepEqual(r.body, { error: 'missing_authorization' });
  });
});

describe('registerPermission()', () => {
  it('registers permissions', () => {
    const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
    // Should not throw
    auth.registerPermission('read:users', 'Read user data');
    auth.registerPermission('write:users');
  });
});

describe('syncPermissions()', () => {
  it('sends permissions to API', async () => {
    let received = null;
    const originalFetch = global.fetch;
    global.fetch = async (url, opts) => {
      if (url.includes('/permissions/sync')) {
        received = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ synced: 2, total: 2 }) };
      }
      return { ok: true, json: async () => ({ keys: [] }) };
    };

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', autoSync: false });
      auth.registerPermission('read:users', 'Read');
      auth.registerPermission('write:users', 'Write');
      await auth.syncPermissions();

      assert.ok(received);
      assert.equal(received.permissions.length, 2);
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('skips sync when no permissions registered', async () => {
    let fetchCalled = false;
    const originalFetch = global.fetch;
    global.fetch = async () => { fetchCalled = true; };

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', autoSync: false });
      await auth.syncPermissions();
      assert.ok(!fetchCalled, 'fetch should not be called for empty sync');
    } finally {
      global.fetch = originalFetch;
    }
  });
});
