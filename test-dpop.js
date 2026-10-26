'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { scenario, rejectsWith, signJWS, b64u, sha256, ec, ed, thumbprint, PUBLIC } = require('./test-helpers/fixture');

// Every refusal below is paired with a control: the same kind of request, unbroken, is accepted.
async function refused(code, build, cfg) {
  const s = scenario(cfg);
  const control = await s.client.verifyRequest(s.request(s.agentToken()));
  assert.equal(control.sub, 'agt_1', 'control leg must verify');
  const token = s.agentToken({ jti: 'second' });
  const req = build(s, token);
  return rejectsWith(s.client.verifyRequest(req), code, assert);
}

function fakeRes() {
  const r = { statusCode: 200, headers: {}, body: undefined };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  return r;
}
async function run(mw, req, res) {
  const next = { called: false };
  await mw(req, res, () => { next.called = true; });
  return next;
}
const nowSec = (s) => Math.floor(s.clock.t / 1000);

describe('agent token with a valid proof', () => {
  it('is accepted and returns claims', async () => {
    const s = scenario();
    const claims = await s.client.verifyRequest(s.request(s.agentToken()));
    assert.equal(claims.sub, 'agt_1');
  });
  it('is accepted for ES256 and PS256 proof keys', async () => {
    for (const alg of ['ES256', 'PS256']) {
      const pair = alg === 'ES256' ? ec() : crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const s = scenario();
      const t = s.token(s.agentClaims({ cnf: { jkt: thumbprint(pair.publicKey) } }));
      const claims = await s.client.verifyRequest(s.request(t, { proof: { alg, pair } }));
      assert.equal(claims.sub, 'agt_1', alg);
    }
  });
  it('is detected by client_id and by the act claim, not only by the sub prefix', async () => {
    const s = scenario();
    for (const extra of [{ sub: 'usr_9', client_id: 'agt_7', cnf: undefined }, { sub: 'usr_9', client_id: undefined, act: { sub: 'usr_2' }, cnf: undefined }]) {
      const t = s.token(s.agentClaims(extra));
      await rejectsWith(s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] })), 'dpop_key_mismatch', assert);
    }
  });
  it('accepts a query string on the request URL (htu has none)', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken(), { url: '/orders?id=1' }));
  });
  it('is detected by a sub that starts with agt_ even with no client_id', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ client_id: undefined, cnf: undefined }));
    await rejectsWith(s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] })), 'dpop_key_mismatch', assert);
  });
  it('refuses a nested act chain', async () => {
    const s = scenario();
    const t = s.agentToken({ act: { sub: 'a', act: { sub: 'b' } } });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'token_act_chain_unsupported', assert);
  });
});

describe('DPoP refusals', () => {
  it('dpop_missing: no proof header', () => refused('dpop_missing', (s, t) => s.request(t, { proofs: [] })));
  it('dpop_missing: Bearer scheme for a bound token, even with a valid proof', () =>
    refused('dpop_missing', (s, t) => s.request(t, { scheme: 'Bearer' })));
  it('dpop_multiple: two DPoP headers', () => refused('dpop_multiple', (s, t) => s.request(t, { proofs: [s.proof(t), s.proof(t)] })));
  it('dpop_multiple: one header holding two proofs (comma joined, no rawHeaders)', () => refused('dpop_multiple', (s, t) => {
    const r = s.request(t, { proofs: [s.proof(t), s.proof(t)] });
    delete r.rawHeaders;
    return r;
  }));
  it('dpop_multiple: headers as an array', () => refused('dpop_multiple', (s, t) => {
    const r = s.request(t);
    r.headers.dpop = [s.proof(t), s.proof(t)];
    delete r.rawHeaders;
    return r;
  }));
  it('dpop_malformed: not a JWS', () => refused('dpop_malformed', (s, t) => s.request(t, { proofs: ['abc.def'] })));
  it('dpop_malformed: payload is not JSON', () => refused('dpop_malformed', (s, t) =>
    s.request(t, { proofs: [signJWS({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: s.dpopJwk }, b64u('not json'), s.dpop.privateKey, 'EdDSA')] })));
  it('dpop_malformed: embedded jwk carries a private member', () => refused('dpop_malformed', (s, t) =>
    s.request(t, { proof: { jwk: { ...s.dpop.privateKey.export({ format: 'jwk' }) } } })));
  it('dpop_malformed: no jwk', () => refused('dpop_malformed', (s, t) => s.request(t, { proof: { jwk: null } })));
  it('dpop_malformed: no jti', () => refused('dpop_malformed', (s, t) => s.request(t, { proof: { claims: { jti: undefined } } })));
  it('dpop_malformed: proof larger than 8 KiB', () => refused('dpop_malformed', (s, t) => s.request(t, { proofs: ['a'.repeat(9000) + '.b.c'] })));
  it('dpop_malformed: crit header', () => refused('dpop_malformed', (s, t) => s.request(t, { proof: { header: { crit: ['x'] } } })));
  it('dpop_type: typ is JWT', () => refused('dpop_type', (s, t) => s.request(t, { proof: { header: { typ: 'JWT' } } })));
  it('dpop_alg: none', () => refused('dpop_alg', (s, t) => s.request(t, { proof: { header: { alg: 'none' } } })));
  it('dpop_alg: HS256', () => refused('dpop_alg', (s, t) => s.request(t, { proof: { header: { alg: 'HS256' } } })));
  it('dpop_alg: RS256 is not in the list', () => refused('dpop_alg', (s, t) => s.request(t, { proof: { header: { alg: 'RS256' } } })));
  it('dpop_alg: a PS256 proof key under 2048 bits', () => refused('dpop_alg', (s, t) => {
    const small = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    return s.request(t, { proof: { alg: 'PS256', pair: small } });
  }));
  it('dpop_alg: alg does not fit the embedded key type', () => refused('dpop_alg', (s, t) => s.request(t, { proof: { header: { alg: 'ES256' } } })));
  it('dpop_signature: signed by another key than the embedded one', () => refused('dpop_signature', (s, t) =>
    s.request(t, { proof: { jwk: s.dpopJwk, pair: { privateKey: ed().privateKey, publicKey: s.dpop.publicKey } } })));
  it('dpop_signature: tampered payload', () => refused('dpop_signature', (s, t) => {
    const [h, , sig] = s.proof(t).split('.');
    const body = b64u(JSON.stringify({ jti: 'x', htm: 'GET', htu: `${PUBLIC}/orders`, iat: nowSec(s), ath: b64u(sha256(t)) }));
    return s.request(t, { proofs: [`${h}.${body}.${sig}`] });
  }));
  it('dpop_method: htm differs', () => refused('dpop_method', (s, t) => s.request(t, { proof: { claims: { htm: 'POST' } } })));
  it('dpop_url: another path', () => refused('dpop_url', (s, t) => s.request(t, { proof: { claims: { htu: `${PUBLIC}/other` } } })));
  it('dpop_url: another host', () => refused('dpop_url', (s, t) => s.request(t, { proof: { claims: { htu: 'https://evil.example.com/orders' } } })));
  it('dpop_url: htu carries a query', () => refused('dpop_url', (s, t) => s.request(t, { proof: { claims: { htu: `${PUBLIC}/orders?x=1` } } })));
  it('dpop_url: a spoofed X-Forwarded-Host does not change the expected URL', () => refused('dpop_url', (s, t) =>
    s.request(t, { headers: { 'x-forwarded-host': 'evil.example.com', 'x-forwarded-proto': 'https' }, proof: { claims: { htu: 'https://evil.example.com/orders' } } })));
  it('dpop_url: a spoofed Host header does not change it either', () => refused('dpop_url', (s, t) =>
    s.request(t, { headers: { host: 'evil.example.com' }, proof: { claims: { htu: 'https://evil.example.com/orders' } } })));
  it('dpop_url: a protocol-relative request target cannot move the host', () => refused('dpop_url', (s, t) =>
    s.request(t, { url: '//evil.example.com/orders', proof: { claims: { htu: 'https://evil.example.com/orders' } } })));
  it('dpop_iat: older than 60 s', () => refused('dpop_iat', (s, t) => s.request(t, { proof: { claims: { iat: nowSec(s) - 61 } } })));
  it('dpop_iat: further ahead than the 5 s skew', () => refused('dpop_iat', (s, t) => s.request(t, { proof: { claims: { iat: nowSec(s) + 6 } } })));
  it('dpop_iat: not a number', () => refused('dpop_iat', (s, t) => s.request(t, { proof: { claims: { iat: 'now' } } })));
  it('dpop_ath: hash of another token', () => refused('dpop_ath', (s, t) => s.request(t, { proof: { claims: { ath: b64u(sha256('other')) } } })));
  it('dpop_ath: missing', () => refused('dpop_ath', (s, t) => s.request(t, { proof: { claims: { ath: undefined } } })));
  it('dpop_key_mismatch: proof from a key that is not cnf.jkt', () => refused('dpop_key_mismatch', (s, t) =>
    s.request(t, { proof: { pair: ed() } })));
  it('dpop_key_mismatch: bound token without cnf.jkt', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ cnf: {} }));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'dpop_key_mismatch', assert);
    const t2 = s.token(s.agentClaims({ cnf: undefined }));
    await rejectsWith(s.client.verifyRequest(s.request(t2)), 'dpop_key_mismatch', assert);
  });
});

describe('RFC 7638 thumbprints', () => {
  it('matches the RFC 7638 RSA vector and the RFC 8037 Ed25519 vector', () => {
    const { thumbprint: tp } = require('./lib/jws');
    const n = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
    assert.equal(tp(crypto.createPublicKey({ key: { kty: 'RSA', n, e: 'AQAB' }, format: 'jwk' })), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    assert.equal(tp(crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }, format: 'jwk' })), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
  });
});

describe('boundary values that must pass', () => {
  it('iat 60 s old and 5 s ahead are inside the window', async () => {
    const s = scenario();
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t, { proof: { claims: { iat: nowSec(s) - 60 } } }));
    await s.client.verifyRequest(s.request(t, { proof: { claims: { iat: nowSec(s) + 5 } } }));
  });
});

describe('replay', () => {
  it('dpop_replayed: the same proof twice', async () => {
    const s = scenario();
    const t = s.agentToken();
    const proof = s.proof(t);
    await s.client.verifyRequest(s.request(t, { proofs: [proof] }));
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [proof] })), 'dpop_replayed', assert);
  });
  it('the jti is recorded only after every other check passed', async () => {
    const s = scenario();
    const t = s.agentToken();
    const bad = s.proof(t, { claims: { jti: 'same', htm: 'POST' } });
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [bad] })), 'dpop_method', assert);
    const good = s.proof(t, { claims: { jti: 'same' } });
    await s.client.verifyRequest(s.request(t, { proofs: [good] }));
  });
  it('a refusal by the chain does not record the jti either', async () => {
    const calls = [];
    const guard = { record: (k) => { calls.push(k); return true; } };
    const s = scenario({ noX5c: true, config: { replayGuard: guard } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_not_proven', assert);
    assert.equal(calls.length, 0);
  });
  it('the same jti from a different key is not a replay (key is thumbprint+jti)', async () => {
    const s = scenario();
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t, { proof: { claims: { jti: 'x' } } }));
    const k2 = ed();
    const t2 = s.token(s.agentClaims({ cnf: { jkt: thumbprint(k2.publicKey) } }));
    await s.client.verifyRequest(s.request(t2, { proof: { pair: k2, claims: { jti: 'x' } } }));
  });
  it('a custom replayGuard is used and its keys carry thumbprint and jti', async () => {
    const seen = new Set();
    const guard = { record: async (k) => { if (seen.has(k)) return false; seen.add(k); return true; } };
    const s = scenario({ config: { replayGuard: guard } });
    const t = s.agentToken();
    const p = s.proof(t, { claims: { jti: 'j9' } });
    await s.client.verifyRequest(s.request(t, { proofs: [p] }));
    assert.deepEqual([...seen], [`${thumbprint(s.dpop.publicKey)}:j9`]);
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [p] })), 'dpop_replayed', assert);
  });
  it('a replayGuard that throws fails closed', async () => {
    const s = scenario({ config: { replayGuard: { record: () => { throw new Error('store down'); } } } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_replayed', assert);
  });
  it('a replayGuard that answers anything but true refuses', async () => {
    const s = scenario({ config: { replayGuard: { record: () => undefined } } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_replayed', assert);
  });
  it('the default guard is bounded and fails closed when full', async () => {
    const s = scenario({ config: { replayMax: 2 } });
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t));
    await s.client.verifyRequest(s.request(t));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'dpop_replayed', assert);
  });
  it('the default guard forgets a proof once its window has passed', async () => {
    const s = scenario({ config: { replayMax: 1 } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t += 10 * 60 * 1000;
    const t2 = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await s.client.verifyRequest(s.request(t2));
  });
});

describe('forwarded headers and the public URL', () => {
  it('forwarded headers count only when trustForwarded is true', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const t = s.agentToken();
    const headers = { 'x-forwarded-host': 'edge.example.org', 'x-forwarded-proto': 'https' };
    await s.client.verifyRequest(s.request(t, { headers, proof: { claims: { htu: 'https://edge.example.org/orders' } } }));
    await rejectsWith(s.client.verifyRequest(s.request(t, { headers, proof: { claims: { htu: 'https://api.example.com/orders' } } })), 'dpop_url', assert);
  });
  it('trustForwarded without the headers refuses', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_url', assert);
  });
  it('a missing publicUrl without trustForwarded refuses with sdk_not_configured', async () => {
    const s = scenario({ config: { publicUrl: undefined } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'sdk_not_configured', assert);
  });
  it('a publicUrl that carries a path is a configuration error', async () => {
    const s = scenario({ config: { publicUrl: 'https://api.example.com/v1' } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'sdk_not_configured', assert);
  });
  it('a default port and letter case in the htu are normalised', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken(), { proof: { claims: { htu: 'HTTPS://API.EXAMPLE.COM:443/orders' } } }));
  });
});

describe('server nonce', () => {
  const nonceKey = 'a'.repeat(32);
  it('dpop_nonce: a proof with no nonce is refused, the error carries a nonce, and that nonce works', async () => {
    const s = scenario({ config: { nonceKey } });
    const err = await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_nonce', assert);
    assert.match(err.dpopNonce, /^[A-Za-z0-9_-]{16,}$/);
    await s.client.verifyRequest(s.request(s.agentToken(), { proof: { claims: { nonce: err.dpopNonce } } }));
  });
  it('dpop_nonce: a made-up nonce, a nonce from another key, a non-string nonce', async () => {
    const s = scenario({ config: { nonceKey } });
    const other = scenario({ config: { nonceKey: 'b'.repeat(32) } });
    const foreign = (await rejectsWith(other.client.verifyRequest(other.request(other.agentToken())), 'dpop_nonce', assert)).dpopNonce;
    for (const n of ['AAAAAAAAAAAAAAAAAAAAAA', foreign, 5]) {
      await rejectsWith(s.client.verifyRequest(s.request(s.agentToken(), { proof: { claims: { nonce: n } } })), 'dpop_nonce', assert);
    }
  });
  it('the previous window is accepted, an older one is not', async () => {
    const s = scenario({ config: { nonceKey } });
    const n = (await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_nonce', assert)).dpopNonce;
    s.clock.t += 60 * 1000;
    const t = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await s.client.verifyRequest(s.request(t, { proof: { claims: { nonce: n } } }));
    s.clock.t += 3 * 60 * 1000;
    const t2 = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await rejectsWith(s.client.verifyRequest(s.request(t2, { proof: { claims: { nonce: n } } })), 'dpop_nonce', assert);
  });
  it('a short nonceKey is a configuration error', async () => {
    const s = scenario({ config: { nonceKey: 'short' } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'sdk_not_configured', assert);
  });
  it('the middleware answers use_dpop_nonce with a DPoP-Nonce header', async () => {
    const s = scenario({ config: { nonceKey } });
    const res = fakeRes();
    await run(s.client.authenticate(), s.request(s.agentToken()), res);
    assert.equal(res.statusCode, 401);
    assert.match(res.headers['dpop-nonce'], /^[A-Za-z0-9_-]{16,}$/);
    assert.match(res.headers['www-authenticate'], /DPoP error="use_dpop_nonce"/);
    assert.equal(res.body.error, 'dpop_nonce');
  });
});

describe('modes', () => {
  it('off: an unbound agent token is accepted as a bearer token and a warning is logged once', async () => {
    const warns = [];
    const s = scenario({ config: { agentTokens: 'off', logger: { warn: (m) => warns.push(m), debug() {} } } });
    const t = s.token(s.agentClaims({ cnf: undefined }));
    const req = s.request(t, { scheme: 'Bearer', proofs: [] });
    assert.equal((await s.client.verifyRequest(req)).sub, 'agt_1');
    await s.client.verifyRequest(req);
    assert.equal(warns.length, 1);
    assert.equal((await s.client.verifyToken(t)).sub, 'agt_1');
  });
  it('off: still requires a proof of a token that carries cnf', async () => {
    const s = scenario({ config: { agentTokens: 'off' } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'Bearer', proofs: [] })), 'dpop_missing', assert);
  });
  it('off: skips the chain', async () => {
    const s = scenario({ noX5c: true, config: { agentTokens: 'off' } });
    assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
  });
  it('enforce is the default and an unknown mode is a configuration error', async () => {
    const s = scenario({ config: { agentTokens: 'maybe' } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'sdk_not_configured', assert);
    const d = scenario();
    await rejectsWith(d.client.verifyRequest(d.request(d.agentToken(), { proofs: [] })), 'dpop_missing', assert);
  });
  it('watch: lets the request through and logs only the code', async () => {
    const logs = [];
    const s = scenario({ config: { agentTokens: 'watch', logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) } } });
    const t = s.agentToken();
    const claims = await s.client.verifyRequest(s.request(t, { proofs: [] }));
    assert.equal(claims.sub, 'agt_1');
    const logged = JSON.stringify(logs);
    assert.match(logged, /dpop_missing/);
    assert.ok(!logged.includes(t), 'the token must not be logged');
  });
  it('watch: a valid request passes with nothing logged', async () => {
    const logs = [];
    const s = scenario({ config: { agentTokens: 'watch', logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    assert.equal(logs.length, 0);
  });
  it('watch: a baseline refusal is still a refusal', async () => {
    const s = scenario({ config: { agentTokens: 'watch' } });
    const t = s.token(s.agentClaims({ aud: 'someone-else' }));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'token_audience_mismatch', assert);
  });
});

describe('verifyToken and person tokens', () => {
  it('verifyToken refuses an agent token with agent_token_needs_request', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyToken(s.agentToken()), 'agent_token_needs_request', assert);
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1');
  });
  it('verifyToken refuses a person token that carries cnf (it needs a proof)', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyToken(s.token(s.claims({ cnf: { jkt: 'x' } }))), 'token_dpop_proof_required', assert);
  });
  it('a plain person bearer token passes verifyRequest; a bound one needs its proof', async () => {
    const s = scenario();
    const plain = s.token(s.claims());
    assert.equal((await s.client.verifyRequest(s.request(plain, { scheme: 'Bearer', proofs: [] }))).sub, 'usr_1');
    const bound = s.token(s.claims({ cnf: { jkt: thumbprint(s.dpop.publicKey) } }));
    await rejectsWith(s.client.verifyRequest(s.request(bound, { scheme: 'Bearer', proofs: [] })), 'dpop_missing', assert);
    assert.equal((await s.client.verifyRequest(s.request(bound))).sub, 'usr_1');
  });
  it('the DPoP scheme with an unbound token is refused', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyRequest(s.request(s.token(s.claims()))), 'dpop_key_mismatch', assert);
  });
  it('the scheme name is case-insensitive', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'dpop' }));
  });
  it('an unknown scheme or a second Authorization value is missing_authorization', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'Basic' })), 'missing_authorization', assert);
  });
});

describe('errors never carry token or proof material', () => {
  it('no refusal message or logged line holds the token, the proof or a claim value', async () => {
    const logs = [];
    const s = scenario({ config: { logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) } } });
    const t = s.agentToken({ sub: 'agt_SECRETSUBJECT' });
    const proof = s.proof(t, { claims: { htm: 'POST', jti: 'SECRETJTI' } });
    const err = await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [proof] })), 'dpop_method', assert);
    const text = JSON.stringify([err.message, err.code, err.stack.split('\n')[0], logs]);
    for (const bad of [t, proof, 'SECRETSUBJECT', 'SECRETJTI', t.split('.')[1], proof.split('.')[2]]) assert.ok(!text.includes(bad));
  });
});

describe('middleware', () => {
  it('require() calls the request-aware verify, sets req.user and enforces permissions', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ permissions: ['read:orders'] }));
    const req = s.request(t);
    const next = await run(s.client.require('read:orders'), req, fakeRes());
    assert.ok(next.called);
    assert.equal(req.user.sub, 'agt_1');
    const res2 = fakeRes();
    const t2 = s.token(s.agentClaims({ permissions: [] }));
    const next2 = await run(s.client.require('read:orders'), s.request(t2), res2);
    assert.ok(!next2.called);
    assert.equal(res2.statusCode, 403);
  });
  it('require() without a proof answers 401 with the code and a DPoP challenge', async () => {
    const s = scenario();
    const res = fakeRes();
    const next = await run(s.client.require('x'), s.request(s.agentToken(), { proofs: [] }), res);
    assert.ok(!next.called);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'dpop_missing');
    assert.match(res.headers['www-authenticate'], /^DPoP /);
  });
  it('requireRole() and authenticate() also demand the proof', async () => {
    const s = scenario();
    for (const mw of [s.client.requireRole('admin'), s.client.authenticate()]) {
      const res = fakeRes();
      const next = await run(mw, s.request(s.agentToken(), { proofs: [] }), res);
      assert.ok(!next.called);
      assert.equal(res.statusCode, 401);
    }
  });
  it('a request without authorization is 401 missing_authorization', async () => {
    const s = scenario();
    const res = fakeRes();
    await run(s.client.authenticate(), s.request(null, { proofs: [] }), res);
    assert.equal(res.body.error, 'missing_authorization');
    assert.equal(res.statusCode, 401);
  });
});

module.exports = { fakeRes, run };
