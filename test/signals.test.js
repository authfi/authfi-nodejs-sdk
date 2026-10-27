'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('http');
const authfi = require('../index');
const { createSeenSet, createReceiver } = require('../signals');
const { STREAM_AUD, API_AUD, AGENT, EV, SECEVENT, b64, Issuer, open, rig, err, refused } = require('./support');

afterEach(() => {
  while (open.length) open.pop()();
});

describe('an accepted revocation', () => {
  it('refuses earlier tokens and allows later ones', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const before = r.issuer.token(AGENT, now - 10);
    await r.auth.verifyToken(before); // fine before any revocation
    assert.equal((await r.push(r.issuer.set())).status, 202);

    await refused(r.auth.verifyToken(before), 'token_revoked');
    await refused(r.auth.verifyToken(r.issuer.token(AGENT, now)), 'token_revoked'); // same second: not provably later
    r.issuer.advance(2000);
    await r.auth.verifyToken(r.issuer.token(AGENT, r.issuer.seconds()));
    await r.auth.verifyToken(r.issuer.token('agent:agt_other', now - 10));
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0].revoked, true);
    assert.equal(r.signals[0].subject, AGENT);
    assert.equal(r.signals[0].event, EV.revoked);
  });

  for (const [name, ev] of [['session-revoked', EV.revoked], ['account-purged', EV.purged], ['credential-compromise', EV.compromise]]) {
    it(`${name} revokes`, async () => {
      const r = await rig();
      const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
      assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims(ev) }))).status, 202);
      await refused(r.auth.verifyToken(tok), 'token_revoked');
    });
  }

  it('refuses a delegated token whose actor is revoked, and leaves the person alone', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, { act: { sub: AGENT } });
    await r.auth.verifyToken(tok);
    await r.push(r.issuer.set());
    await refused(r.auth.verifyToken(tok), 'token_revoked');
    await r.auth.verifyToken(r.issuer.token('usr_7', r.issuer.seconds() - 1));
  });

  it('refuses a token with no iat, whatever its subject, when a store is configured', async () => {
    const r = await rig();
    await r.push(r.issuer.set());
    const noIat = (sub) => {
      const p = { iss: r.issuer.url, sub, aud: API_AUD, exp: r.issuer.seconds() + 3600 };
      return r.issuer.sign('ed1', { typ: 'at+jwt' }, p);
    };
    await refused(r.auth.verifyToken(noIat(AGENT)), 'token_iat_exp_required');
    await refused(r.auth.verifyToken(noIat('agent:agt_9')), 'token_iat_exp_required');
  });

  it('uses the iat of the SET, so a late delivery does not refuse newer tokens', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const claims = r.issuer.setClaims();
    claims.iat = now - 30;
    await r.push(r.issuer.set({ claims }));
    await r.auth.verifyToken(r.issuer.token(AGENT, now - 5));
    await refused(r.auth.verifyToken(r.issuer.token(AGENT, now - 40)), 'token_revoked');
  });

  it('accepts a resume, tells the hook, and does not lift the revocation', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    await r.push(r.issuer.set());
    r.issuer.advance(1000);
    assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { resumed: true }) }))).status, 202);
    await refused(r.auth.verifyToken(tok), 'token_revoked');
    await r.auth.verifyToken(r.issuer.token(AGENT, r.issuer.seconds() + 1));
    assert.equal(r.signals.length, 2);
    assert.equal(r.signals[1].resumed, true);
    assert.equal(r.signals[1].revoked, false);
  });

  it('revokes nothing for a claims change without resume or for an unknown event', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { revoked_permission: 'x' }) }))).status, 202);
    assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims('https://example.test/unknown') }))).status, 202);
    await r.auth.verifyToken(tok);
    assert.equal(r.store.size, 0);
  });

  it('reads the iss_sub subject format, for this issuer only', async () => {
    const r = await rig();
    const good = r.issuer.setClaims();
    good.sub_id = { format: 'iss_sub', iss: r.issuer.url, sub: 'usr_5' };
    assert.equal((await r.push(r.issuer.set({ claims: good }))).status, 202);
    await refused(r.auth.verifyToken(r.issuer.token('usr_5', r.issuer.seconds() - 1)), 'token_revoked');
    const foreign = r.issuer.setClaims();
    foreign.sub_id = { format: 'iss_sub', iss: 'https://elsewhere.test', sub: 'usr_6' };
    const res = await r.push(r.issuer.set({ claims: foreign }));
    assert.equal(res.status, 400);
    assert.equal(err(res), 'invalid_request');
  });
});

describe('a refused SET changes nothing', () => {
  const flipSig = (tok) => {
    const i = tok.lastIndexOf('.');
    const sig = Buffer.from(tok.slice(i + 1), 'base64url');
    sig[0] ^= 0xff;
    return `${tok.slice(0, i + 1)}${b64(sig)}`;
  };
  const withClaims = (i, mut) => {
    const c = i.setClaims();
    mut(c);
    return i.set({ claims: c });
  };
  const cases = [
    ['bad signature', (i) => flipSig(i.set()), 'authentication_failed'],
    ['payload tampered', (i) => {
      const parts = i.set().split('.');
      const c = i.setClaims();
      c.sub_id = { format: 'opaque', id: 'agent:agt_attacker_choice' };
      return `${parts[0]}.${b64(JSON.stringify(c))}.${parts[2]}`;
    }, 'authentication_failed'],
    ['unknown kid is retryable, not final', (i) => i.set({ header: { kid: 'nope' } }), 'temporarily_unavailable'],
    ['no kid', (i) => i.set({ header: { kid: '' } }), 'invalid_key'],
    ['alg none', (i) => i.set({ header: { alg: 'none' } }), 'invalid_key'],
    ['alg HS256', (i) => i.set({ header: { alg: 'HS256' } }), 'invalid_key'],
    ['alg does not match the key', (i) => i.set({ header: { alg: 'RS256' } }), 'invalid_key'],
    ['crit header', (i) => i.set({ header: { crit: ['x'] } }), 'invalid_key'],
    ['wrong issuer', (i) => withClaims(i, (c) => { c.iss = 'https://evil.test'; }), 'invalid_issuer'],
    ['no issuer', (i) => i.set({ drop: ['iss'] }), 'invalid_issuer'],
    ['wrong audience', (i) => withClaims(i, (c) => { c.aud = 'someone-else'; }), 'invalid_audience'],
    ['no audience', (i) => i.set({ drop: ['aud'] }), 'invalid_audience'],
    ['the API audience is not the stream audience', (i) => withClaims(i, (c) => { c.aud = API_AUD; }), 'invalid_audience'],
    ['expired', (i) => withClaims(i, (c) => { c.exp = i.seconds() - 600; }), 'invalid_request'],
    ['exp is not a number', (i) => withClaims(i, (c) => { c.exp = 'soon'; }), 'invalid_request'],
    ['iat ahead of this clock is retryable, not final', (i) => withClaims(i, (c) => { c.iat = i.seconds() + 600; }), 'temporarily_unavailable'],
    ['iat is a string', (i) => withClaims(i, (c) => { c.iat = String(i.seconds()); }), 'invalid_request'],
    ['no iat', (i) => i.set({ drop: ['iat'] }), 'invalid_request'],
    ['no jti', (i) => i.set({ drop: ['jti'] }), 'invalid_request'],
    ['no events', (i) => i.set({ drop: ['events'] }), 'invalid_request'],
    ['empty events', (i) => withClaims(i, (c) => { c.events = {}; }), 'invalid_request'],
    ['event body is not an object', (i) => withClaims(i, (c) => { c.events = { [EV.revoked]: 'yes' }; }), 'invalid_request'],
    ['no subject', (i) => i.set({ drop: ['sub_id'] }), 'invalid_request'],
    ['empty subject', (i) => withClaims(i, (c) => { c.sub_id = { format: 'opaque', id: '' }; }), 'invalid_request'],
    ['unsupported subject format', (i) => withClaims(i, (c) => { c.sub_id = { format: 'email', email: 'a@b.test' }; }), 'invalid_request'],
    ['an access token is not a SET', (i) => i.token(AGENT, i.seconds()), 'invalid_request'],
    ['not a JWT', () => 'hello', 'invalid_request'],
    ['empty body', () => '', 'invalid_request'],
    ['too large', () => 'a'.repeat(20 * 1024), 'invalid_request'],
  ];
  for (const [name, build, code] of cases) {
    it(name, async () => {
      const r = await rig();
      const res = await r.push(build(r.issuer));
      assert.equal(res.status, code === 'temporarily_unavailable' ? 503 : 400, res.text);
      assert.equal(err(res), code);
      assert.equal(r.store.size, 0);
      assert.equal(r.signals.length, 0);
      await r.auth.verifyToken(r.issuer.token(AGENT, r.issuer.seconds() - 1)); // nothing was revoked
    });
  }

  it('enforces the request shape', async () => {
    const r = await rig();
    const set = r.issuer.set();
    for (const ct of ['', 'application/json', 'application/jwt', 'text/plain']) {
      const res = await r.push(set, { 'Content-Type': ct });
      assert.equal(res.status, 400, `content-type ${ct}`);
      assert.equal(err(res), 'invalid_request');
    }
    for (const m of ['GET', 'PUT', 'DELETE']) {
      const res = await r.push(undefined, {}, m);
      assert.equal(res.status, 405, m);
      assert.equal(res.headers.get('allow'), 'POST');
    }
    assert.equal(r.store.size, 0);
    assert.equal((await r.push(set, { 'Content-Type': 'Application/SecEvent+JWT; charset=utf-8' })).status, 202);
  });

  it('bounds a body that a body parser already read', async () => {
    const r = await rig();
    const auth = authfi({ tenant: 't', apiKey: 'k', issuer: r.issuer.url, revocations: r.store, clock: () => r.issuer.clock() });
    const handler = auth.receiver({ audience: STREAM_AUD });
    const server = http.createServer((req, res) => {
      req.body = 'a'.repeat(20 * 1024);
      handler(req, res);
    });
    await new Promise((x) => server.listen(0, '127.0.0.1', x));
    open.push(() => { server.closeAllConnections(); server.close(); });
    const res = await fetch(`http://127.0.0.1:${server.address().port}/`, { method: 'POST', headers: { 'Content-Type': SECEVENT }, body: 'x' });
    assert.equal(res.status, 400);
    assert.equal(JSON.parse(await res.text()).err, 'invalid_request');
  });

  it('echoes nothing of the input', async () => {
    const r = await rig();
    const set = r.issuer.set({ header: { kid: 'nope' } });
    const res = await r.push(set);
    assert.ok(!res.text.includes(set.slice(0, 20)) && !res.text.includes(AGENT), res.text);
    assert.equal(res.headers.get('content-type'), 'application/json');
  });
});

describe('retries and late deliveries', () => {
  it('accepts and ignores a SET older than any token it could affect', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.iat = r.issuer.seconds() - 25 * 3600;
    assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
    assert.equal(r.store.size, 0);
    assert.equal(r.signals.length, 0);
  });

  it('treats an issuer spelled with a trailing slash as the same issuer', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.iss = `${r.issuer.url}/`;
    assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
  });

  it('answers a pre-parsed object body instead of hanging', async () => {
    const r = await rig();
    const auth = authfi({ tenant: 't', apiKey: 'k', issuer: r.issuer.url, revocations: r.store, clock: () => r.issuer.clock() });
    const handler = auth.receiver({ audience: STREAM_AUD });
    const server = http.createServer((req, res) => {
      req.on('data', () => {});
      req.on('end', () => { req.body = { not: 'raw' }; handler(req, res); });
    });
    await new Promise((x) => server.listen(0, '127.0.0.1', x));
    open.push(() => { server.closeAllConnections(); server.close(); });
    const res = await fetch(`http://127.0.0.1:${server.address().port}/`, { method: 'POST', headers: { 'Content-Type': SECEVENT }, body: 'x', signal: AbortSignal.timeout(3000) });
    assert.equal(res.status, 400);
  });
});

describe('replay', () => {
  it('applies a repeated jti once and answers 202 each time', async () => {
    const r = await rig();
    const set = r.issuer.set();
    for (let i = 0; i < 3; i++) assert.equal((await r.push(set)).status, 202);
    assert.equal(r.signals.length, 1);
  });

  it('does not burn the jti of a refused SET', async () => {
    const r = await rig();
    const good = r.issuer.setClaims();
    const bad = { ...good, aud: 'wrong' };
    assert.equal(err(await r.push(r.issuer.set({ claims: bad }))), 'invalid_audience');
    assert.equal((await r.push(r.issuer.set({ claims: good }))).status, 202);
    assert.equal(r.signals.length, 1);
  });

  it('applies concurrent duplicates once', async () => {
    const r = await rig();
    const set = r.issuer.set();
    const results = await Promise.all(Array.from({ length: 30 }, () => r.push(set)));
    assert.ok(results.every((x) => x.status === 202));
    assert.equal(r.signals.length, 1);
  });

  it('keeps the seen set bounded and expiring', () => {
    let now = 1_000_000_000;
    const s = createSeenSet(3, 60, () => now);
    for (const id of ['a', 'b', 'c']) assert.equal(s.claim(id), true);
    assert.equal(s.claim('b'), false);
    assert.equal(s.claim('d'), true); // full: forgets the oldest
    assert.equal(s.size, 3);
    assert.equal(s.claim('a'), true); // a was forgotten
    now += 120_000;
    assert.equal(s.claim('b'), true);
    assert.equal(s.size, 1); // everything else expired
    for (let i = 0; i < 5000; i++) s.claim(`x${i}`);
    assert.ok(s.size <= 3);
  });
});

describe('authentication of the push', () => {
  it('requires the bearer when one is configured', async () => {
    const r = await rig({ receiver: { authToken: 's3cret-push' } });
    const set = r.issuer.set();
    for (const h of [undefined, 'Bearer wrong', 'Bearer s3cret-pus', 'Bearer s3cret-pushX', 'Basic s3cret-push', 's3cret-push']) {
      const res = await r.push(set, h ? { Authorization: h } : {});
      assert.equal(res.status, 401, String(h));
    }
    assert.equal(r.store.size, 0);
    assert.equal((await r.push(set, { Authorization: 'Bearer s3cret-push' })).status, 202);
  });
});

describe('the key set', () => {
  it('answers 503 under an outage, records nothing, and takes the retry', async () => {
    const r = await rig();
    const set = r.issuer.set();
    r.issuer.jwksStatus = 500;
    const res = await r.push(set);
    assert.equal(res.status, 503);
    assert.equal(res.headers.get('retry-after'), '5');
    assert.equal(r.store.size, 0);
    r.issuer.jwksStatus = 200;
    assert.equal((await r.push(set)).status, 202); // its jti was not burned
  });

  it('picks up a rotated key, with at most one refetch per 15 seconds for an unknown kid', async () => {
    const r = await rig();
    await r.push(r.issuer.set()); // loads the key set
    const hits = r.issuer.jwksHits;
    r.issuer.add('ed2', 'EdDSA', crypto.generateKeyPairSync('ed25519'));
    // 400 would be final for the transmitter, which disables the stream and loses the revocation
    for (let i = 0; i < 5; i++) assert.equal((await r.push(r.issuer.set({ kid: 'ed2' }))).status, 503);
    assert.equal(r.issuer.jwksHits, hits, 'forged-kid traffic inside the interval must not refetch');
    r.issuer.advance(16000);
    assert.equal((await r.push(r.issuer.set({ kid: 'ed2' }))).status, 202);
    assert.equal(r.issuer.jwksHits, hits + 1);
  });

  it('does not let a kid-less SET match a kid-less key', async () => {
    const r = await rig();
    r.issuer.kidless = true;
    const res = await r.push(r.issuer.set({ header: { kid: undefined } }));
    assert.equal(res.status, 400);
    assert.equal(err(res), 'invalid_key');
    assert.equal(r.store.size, 0);
  });

  it('fetches the key set once for a burst of pushes', async () => {
    const r = await rig();
    const results = await Promise.all(Array.from({ length: 20 }, () => r.push(r.issuer.set())));
    assert.ok(results.every((x) => x.status === 202));
    assert.equal(r.issuer.jwksHits, 1);
  });

  it('verifies a SET signed with RS256, PS256 or ES256 as well', async () => {
    const r = await rig();
    for (const kid of ['rs1', 'ps1', 'es1']) assert.equal((await r.push(r.issuer.set({ kid }))).status, 202, kid);
  });
});

describe('revocation lifetime and chains', () => {
  it('refuses a token that lives longer than the store remembers', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const store = authfi.createRevocationStore({ tokenLifetimeSeconds: 3600, clock: () => issuer.clock() });
    const auth = authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, revocations: store, clock: () => issuer.clock() });
    const now = issuer.seconds();
    await assert.rejects(auth.verifyToken(issuer.token(AGENT, now, { exp: now + 7200 })), (e) => e.code === 'revocation_store_misconfigured');
    await auth.verifyToken(issuer.token(AGENT, now, { exp: now + 3600 }));
  });

  it('refuses a token whose deeper actor in a delegation chain is revoked', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, { act: { sub: 'agent:mid', act: { sub: AGENT } } });
    await r.auth.verifyToken(tok);
    await r.push(r.issuer.set());
    await refused(r.auth.verifyToken(tok), 'token_revoked');
  });
});

describe('configuration fails closed', () => {
  it('refuses an authToken that would silently switch the bearer check off', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const store = authfi.createRevocationStore();
    const build = (authToken) => authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, revocations: store }).receiver({ audience: 'a', authToken });
    for (const bad of [Buffer.from('s3cret'), 12345, '', {}, null]) assert.throws(() => build(bad), /authToken/);
    build(undefined);
    build('ok');
  });

  it('refuses a store that is not from createRevocationStore', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const custom = { revoke() {}, isRevoked() { return false; } };
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, revocations: custom }).receiver({ audience: 'a' }), /createRevocationStore/);
  });

  it('does not accept a bearer followed by anything else', async () => {
    const r = await rig({ receiver: { authToken: 's3cret' } });
    const set = r.issuer.set();
    assert.equal((await r.push(set, { Authorization: 'Bearer s3cret trailing' })).status, 401);
    assert.equal((await r.push(set, { Authorization: 'bearer   s3cret' })).status, 202);
  });

  it('refuses a receiver that cannot work', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const store = authfi.createRevocationStore();
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url }).receiver({ audience: 'a' }), /revocations/);
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', revocations: store }).receiver({ audience: 'a' }), /issuer/);
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, revocations: store }).receiver({}), /audience/);
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, revocations: store }).receiver(), /audience/);
    assert.throws(() => authfi({ tenant: 't', apiKey: 'k', issuer: 'http://acme.example.com', revocations: store }).receiver({ audience: 'a' }), /https/);
  });

  it('checks nothing without a store, and refuses a SET as an access token', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const auth = authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, clock: () => issuer.clock() });
    await auth.verifyToken(issuer.token(AGENT, issuer.seconds()));
    await assert.rejects(auth.verifyToken(issuer.set()), /Not an access token/);
  });

  it('verifies agent tokens signed with EdDSA, ES256 and PS256', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const auth = authfi({ tenant: 't', apiKey: 'k', issuer: issuer.url, clock: () => issuer.clock() });
    for (const kid of ['ed1', 'es1', 'ps1', 'rs1']) {
      const tok = issuer.sign(kid, { typ: 'at+jwt' }, { iss: issuer.url, sub: AGENT, iat: issuer.seconds(), exp: issuer.seconds() + 60 });
      assert.equal((await auth.verifyToken(tok)).sub, AGENT, kid);
    }
    await assert.rejects(auth.verifyToken(issuer.sign('ed1', { typ: 'at+jwt', alg: 'HS256' }, { sub: 'x' })), /Unsupported algorithm/);
    await assert.rejects(auth.verifyToken(issuer.sign('ed1', { typ: 'at+jwt', alg: 'RS256' }, { sub: 'x' })), /Unsupported algorithm|Invalid signature/);
  });

  it('keeps the revocation when the hook throws or rejects', async () => {
    for (const hook of [() => { throw new Error('boom'); }, async () => { throw new Error('boom'); }]) {
      const r = await rig({ receiver: { onSignal: hook } });
      const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
      assert.equal((await r.push(r.issuer.set())).status, 202);
      await refused(r.auth.verifyToken(tok), 'token_revoked');
    }
  });

  it('logs refusals without the token', async () => {
    const r = await rig();
    const set = r.issuer.set({ header: { kid: 'nope' } });
    await r.push(set);
    const text = JSON.stringify(r.logs);
    assert.ok(r.logs.some((l) => l[0] === 'warn'));
    assert.ok(!text.includes(set.slice(0, 30)));
  });
});

describe('the revocation store', () => {
  const fixed = (state) => authfi.createRevocationStore({ ...state.opts, clock: () => state.now });

  it('is monotone and expires', () => {
    const st = { now: 2_000_000_000, opts: { tokenLifetimeSeconds: 3600 } };
    const s = fixed(st);
    const t = st.now / 1000;
    s.revoke('a', t);
    s.revoke('a', t - 60); // an earlier time never lowers the line
    assert.equal(s.isRevoked('a', t), true);
    s.revoke('a', t + 60);
    assert.equal(s.isRevoked('a', t + 60), true);
    assert.equal(s.isRevoked('a', t + 61), false);
    assert.equal(s.isRevoked('a', undefined), true); // unknown issue time
    assert.equal(s.isRevoked('a', 'x'), true);
    assert.equal(s.isRevoked('y', undefined), false);
    st.now += 3600_000 + 120_000;
    assert.equal(s.isRevoked('a', t - 7200), false);
    s.revoke('old', st.now / 1000 - 7200);
    assert.equal(s.size, 1, 'a revocation already past the lifetime is not stored');
    assert.equal(s.revoke('', t), 0);
    assert.equal(s.revoke('z', 'not a number'), 0);
    assert.equal(s.size, 1);
  });

  it('raises a floor instead of forgetting a revocation when full', () => {
    const st = { now: 3_000_000_000, opts: { maxEntries: 20, tokenLifetimeSeconds: 3600 } };
    const s = fixed(st);
    const t = st.now / 1000;
    for (let i = 0; i < 20; i++) s.revoke(`s${i}`, t + i);
    assert.equal(s.size, 20);
    const dropped = s.revoke('newcomer', t + 30);
    assert.ok(dropped > 0 && s.size <= 20, `dropped ${dropped} size ${s.size}`);
    assert.equal(s.isRevoked('s0', t - 60), true, 'a dropped revocation still refuses what it covered');
    assert.equal(s.isRevoked('unrelated', t - 60), true, 'the floor applies to every subject');
    assert.equal(s.isRevoked('unrelated', t + 20), false, 'newer than the floor');
    st.now += 7200_000;
    assert.equal(s.isRevoked('unrelated', t - 60), false, 'the floor ages out');
  });

  it('stays bounded under a flood', () => {
    const st = { now: 4_000_000_000, opts: { maxEntries: 500, tokenLifetimeSeconds: 3600 } };
    const s = fixed(st);
    for (let i = 0; i < 20000; i++) s.revoke(`subject-${i}`, st.now / 1000 + i / 100);
    assert.ok(s.size <= 500, `size ${s.size}`);
  });
});

describe('registerStream', () => {
  async function transmitter({ meta, status = 201, reply }) {
    const hits = [];
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        if (req.url === '/.well-known/ssf-configuration') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(meta(`http://127.0.0.1:${server.address().port}`)));
          return;
        }
        hits.push({ url: req.url, method: req.method, auth: req.headers.authorization, body: Buffer.concat(chunks).toString() });
        res.statusCode = status;
        res.end(reply || JSON.stringify({ data: { id: 'str_1', audience: STREAM_AUD, endpoint_url: 'https://rp.test/ssf', status: 'enabled', events_requested: [EV.revoked] } }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    open.push(() => {
      server.closeAllConnections();
      server.close();
    });
    return { url: `http://127.0.0.1:${server.address().port}`, hits };
  }
  const client = (url) => authfi({ tenant: 't', apiKey: 'k', issuer: url });
  const request = { audience: STREAM_AUD, endpointUrl: 'https://rp.test/ssf', authToken: 'push-secret', events: [EV.revoked] };

  it('registers a stream with the bearer and the documented body', async () => {
    const t = await transmitter({ meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }) });
    const st = await client(t.url).registerStream('operator-token', request);
    assert.deepEqual(st, { id: 'str_1', audience: STREAM_AUD, endpointUrl: 'https://rp.test/ssf', status: 'enabled', events: [EV.revoked] });
    assert.equal(t.hits.length, 1);
    assert.equal(t.hits[0].url, '/v1/ssf/streams');
    assert.equal(t.hits[0].auth, 'Bearer operator-token');
    assert.deepEqual(JSON.parse(t.hits[0].body), { audience: STREAM_AUD, endpoint_url: 'https://rp.test/ssf', auth_token: 'push-secret', events_requested: [EV.revoked] });
    assert.ok(!JSON.stringify(st).includes('push-secret'));
  });

  it('never sends the bearer to another host', async () => {
    const evil = await transmitter({ meta: () => ({}) });
    const t = await transmitter({ meta: (b) => ({ issuer: b, configuration_endpoint: `${evil.url}/v1/ssf/streams` }) });
    await assert.rejects(client(t.url).registerStream('operator-token', request), /not on the issuer/);
    assert.equal(evil.hits.length, 0);
    assert.equal(t.hits.length, 0);
  });

  it('does not follow a redirect with the bearer', async () => {
    const evil = await transmitter({ meta: () => ({}) });
    const redirecting = http.createServer((req, res) => {
      res.statusCode = 307;
      res.setHeader('Location', `${evil.url}${req.url}`);
      res.end();
    });
    await new Promise((x) => redirecting.listen(0, '127.0.0.1', x));
    open.push(() => { redirecting.closeAllConnections(); redirecting.close(); });
    await assert.rejects(client(`http://127.0.0.1:${redirecting.address().port}`).registerStream('operator-token', request));
    const t = await transmitter({ meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }) });
    const post = http.createServer((req, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ issuer: `http://127.0.0.1:${post.address().port}`, configuration_endpoint: `http://127.0.0.1:${post.address().port}/v1/ssf/streams` }));
        return;
      }
      res.statusCode = 307;
      res.setHeader('Location', `${evil.url}/stolen`);
      res.end();
    });
    await new Promise((x) => post.listen(0, '127.0.0.1', x));
    open.push(() => { post.closeAllConnections(); post.close(); });
    await assert.rejects(client(`http://127.0.0.1:${post.address().port}`).registerStream('operator-token', request));
    assert.equal(evil.hits.length, 0, 'the bearer must never reach the redirect target');
    assert.equal(t.hits.length, 0);
  });

  it('refuses metadata that names another issuer', async () => {
    const t = await transmitter({ meta: (b) => ({ issuer: 'https://other.test', configuration_endpoint: `${b}/v1/ssf/streams` }) });
    await assert.rejects(client(t.url).registerStream('operator-token', request), /another issuer/);
    assert.equal(t.hits.length, 0);
  });

  it('turns a refusal into an error that holds no secret', async () => {
    const t = await transmitter({ meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }), status: 403, reply: '{"error":"operator-token and push-secret leaked"}' });
    await assert.rejects(client(t.url).registerStream('operator-token', request), (e) => /refused \(403\)/.test(e.message) && !e.message.includes('operator-token') && !e.message.includes('push-secret'));
  });

  it('refuses invalid requests before any request is made', async () => {
    const t = await transmitter({ meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }) });
    const c = client(t.url);
    await assert.rejects(c.registerStream('', request), /bearer/);
    await assert.rejects(c.registerStream('b', { ...request, audience: '' }), /audience/);
    await assert.rejects(c.registerStream('b', { ...request, endpointUrl: 'http://rp.test/ssf' }), /https/);
    await assert.rejects(c.registerStream('b', { ...request, endpointUrl: 'https://u:p@rp.test/ssf' }), /https/);
    await assert.rejects(c.registerStream('b', { ...request, endpointUrl: 'nonsense' }), /https/);
    await assert.rejects(authfi({ tenant: 't', apiKey: 'k' }).registerStream('b', request), /issuer/);
    assert.equal(t.hits.length, 0);
    await c.registerStream('b', request); // control
    assert.equal(t.hits.length, 1);
  });
});

describe('receipt to refusal latency', () => {
  it('measures push start to verifyToken refusal over 50 runs', async () => {
    const r = await rig();
    const runs = 50;
    const total = [];
    for (let i = 0; i < runs; i++) {
      const sub = `agent:agt_lat_${i}`;
      const tok = r.issuer.token(sub, r.issuer.seconds() - 1);
      await r.auth.verifyToken(tok);
      const claims = r.issuer.setClaims();
      claims.sub_id = { format: 'opaque', id: sub };
      const set = r.issuer.set({ claims });
      const start = process.hrtime.bigint();
      const res = await r.push(set);
      assert.equal(res.status, 202);
      await refused(r.auth.verifyToken(tok), 'token_revoked');
      total.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    const sorted = [...total].sort((a, b) => a - b);
    const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length * p) / 100))];
    const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
    const f = (n) => `${n.toFixed(3)}ms`;
    const out = [
      'Node SDK receiver: push start to verifyToken refusal, loopback HTTP, 50 runs',
      `push -> refused (HTTP + handler)   n=${sorted.length} min=${f(sorted[0])} p50=${f(q(50))} p95=${f(q(95))} p99=${f(q(99))} max=${f(sorted[sorted.length - 1])} mean=${f(mean)}`,
      'Excludes the transmitter queue and drain delay; that part is measured on the platform side.',
      '',
    ].join('\n');
    if (process.env.LATENCY_OUT) require('fs').writeFileSync(process.env.LATENCY_OUT, out);
    assert.ok(q(99) < 1000, `p99 ${q(99)}ms is not under 1s`);
  });
});

const LIFE = 3600;
const storeAt = (opts = {}) => {
  const c = { now: 1_800_000_000_000 };
  const s = authfi.createRevocationStore({ tokenLifetimeSeconds: LIFE, clock: () => c.now, ...opts });
  return { s, c, t0: c.now / 1000 };
};
const { EventEmitter } = require('events');
const fakeReq = (body) => {
  const req = new EventEmitter();
  req.method = 'POST';
  req.headers = { 'content-type': SECEVENT };
  req.body = body;
  return req;
};

describe('kill: store', () => {
  it('eviction drops the oldest tenth and raises the floor to the newest dropped', () => {
    const { s, t0 } = storeAt({ maxEntries: 20 });
    for (let i = 0; i < 20; i++) s.revoke(`s${i}`, t0 + i);
    const dropped = s.revoke('newcomer', t0 + 30);
    assert.equal(dropped, 3); // floor(20/10)+1
    assert.ok(s.size <= 20);
    assert.equal(s.isRevoked('s0', t0 - 60), true);
    assert.equal(s.isRevoked('unrelated', t0 + 2), true); // floor boundary: equal iat is refused
    assert.equal(s.isRevoked('unrelated', t0 + 5), false); // newer than the floor: untouched
    assert.equal(s.isRevoked('s10', t0 + 10), true); // a retained entry still refuses its own subject
  });

  it('sweeps expired entries first and evicts nothing live when that makes room', () => {
    const { s, c, t0 } = storeAt({ maxEntries: 10 });
    s.revoke('old1', t0);
    s.revoke('old2', t0 + 1);
    for (let i = 0; i < 8; i++) s.revoke(`new${i}`, t0 + 3000 + i);
    c.now = (t0 + LIFE + 1) * 1000; // old1 and old2 expired
    assert.equal(s.revoke('newcomer', t0 + LIFE), 0);
    assert.equal(s.isRevoked('unrelated', t0 + 100), false); // no floor was raised
  });

  it('an entry exactly one lifetime old is expired for sweep, revoke and isRevoked', () => {
    const { s, c, t0 } = storeAt({ maxEntries: 2 });
    s.revoke('a', t0);
    s.revoke('b', t0 + 100);
    c.now = (t0 + LIFE) * 1000;
    assert.equal(s.isRevoked('a', 0), false);
    assert.equal(s.revoke('c', t0 + LIFE), 0); // the sweep removed a at exactly t0+LIFE
    assert.equal(s.revoke('late', t0), 0);
    assert.equal(s.size, 2);
    assert.equal(s.isRevoked('late', t0 - 1), false);
  });

  it('ignores an empty subject and non-finite times', () => {
    const { s, t0 } = storeAt();
    s.revoke('', t0);
    s.revoke('a', Infinity);
    s.revoke('b', NaN);
    assert.equal(s.size, 0);
    assert.equal(s.isRevoked('a', 1e12), false);
  });

  it('the jti set expires exactly at its ttl and not before', () => {
    let now = 1_800_000_000_000;
    const seen = createSeenSet(10, 100, () => now);
    assert.equal(seen.claim('j'), true);
    now += 99_000;
    assert.equal(seen.claim('j'), false);
    now += 1_000;
    assert.equal(seen.claim('j'), true);
  });
});

describe('kill: receiver edges', () => {
  const claimsWith = (r, mod) => {
    const c = r.issuer.setClaims();
    mod(c, r.issuer.seconds());
    return r.issuer.set({ claims: c });
  };
  const cases = [
    ['jti 256', (c) => { c.jti = 'j'.repeat(256); }, 202],
    ['jti 257', (c) => { c.jti = 'j'.repeat(257); }, 400],
    ['subject 512', (c) => { c.sub_id = { format: 'opaque', id: 's'.repeat(512) }; }, 202],
    ['subject 513', (c) => { c.sub_id = { format: 'opaque', id: 's'.repeat(513) }; }, 400],
    ['opaque with sub only', (c) => { c.sub_id = { format: 'opaque', sub: 'agent:x' }; }, 400],
    ['iat +30', (c, n) => { c.iat = n + 30; }, 202],
    ['iat +60', (c, n) => { c.iat = n + 60; }, 202],
    ['iat +61', (c, n) => { c.iat = n + 61; }, 503],
    ['iat one lifetime old is ignored, not refused', (c, n) => { c.iat = n - 86400; }, 202],
    ['iat one second inside', (c, n) => { c.iat = n - 86399; }, 202],
    ['exp -30', (c, n) => { c.exp = n - 30; }, 202],
    ['exp -61', (c, n) => { c.exp = n - 61; }, 400],
    ['exp absurdly far', (c) => { c.exp = 1e13; }, 400],
    ['aud array containing the stream', (c) => { c.aud = ['other', STREAM_AUD]; }, 202],
    ['events as an array', (c) => { c.events = [{}]; }, 400],
  ];
  for (const [name, mod, want] of cases) {
    it(name, async () => {
      const r = await rig();
      const res = await r.push(claimsWith(r, mod));
      assert.equal(res.status, want, res.text);
    });
  }

  it('a JSON-array payload is invalid_request', async () => {
    const r = await rig();
    const k = r.issuer.keys.get('ed1');
    const h = b64(JSON.stringify({ alg: 'EdDSA', typ: 'secevent+jwt', kid: 'ed1' }));
    const p = b64(JSON.stringify([1]));
    const sig = crypto.sign(null, Buffer.from(`${h}.${p}`), k.pair.privateKey);
    const res = await r.push(`${h}.${p}.${b64(sig)}`);
    assert.equal(err(res), 'invalid_request');
  });

  it('resumed is true only for the boolean true; ignored events never reach the hook', async () => {
    const r = await rig();
    await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { resumed: 'false' }) }));
    await r.push(r.issuer.set({ claims: r.issuer.setClaims('https://example.test/unknown') }));
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0].resumed, false);
  });

  it('401 carries WWW-Authenticate; bearer parsing tolerates case and repeated spaces', async () => {
    const r = await rig({ receiver: { authToken: 's3cret' } });
    const no = await r.push(r.issuer.set());
    assert.equal(no.status, 401);
    assert.match(no.headers.get('www-authenticate'), /Bearer/);
    for (const h of ['bearer s3cret', 'BEARER s3cret', 'Bearer   s3cret']) {
      assert.equal((await r.push(r.issuer.set(), { Authorization: h })).status, 202, h);
    }
  });

  it('answers only after an async hook finished', async () => {
    let done = false;
    const r = await rig({ receiver: { onSignal: async () => { await new Promise((ok) => setTimeout(ok, 50)); done = true; } } });
    assert.equal((await r.push(r.issuer.set())).status, 202);
    assert.equal(done, true);
  });

  it('a verifier failure that is not a JwsError is retryable', async () => {
    const store = authfi.createRevocationStore();
    const h = createReceiver({ issuer: 'https://acme.example', store, verifyJws: async () => { throw new Error('boom'); }, clock: Date.now, logger: { info() {}, warn() {} } }, { audience: 'a' });
    const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end() {}, statusCode: 0 };
    await h(fakeReq('x.y.z'), res);
    assert.equal(res.statusCode, 503);
  });

  it('a pre-parsed string or Buffer body is used as is', async () => {
    const r = await rig();
    const handler = r.auth.receiver({ audience: STREAM_AUD });
    for (const body of [r.issuer.set(), Buffer.from(r.issuer.set())]) {
      const res = { setHeader() {}, end() { this.done = true; }, statusCode: 0 };
      await Promise.race([handler(fakeReq(body), res), new Promise((ok) => setTimeout(ok, 500))]);
      assert.equal(res.statusCode, 202);
    }
  });

  it('an issuer with a query or fragment cannot build a receiver', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    for (const bad of [`${issuer.url}/?x=1`, `${issuer.url}/#f`]) {
      const auth = authfi({ tenant: 'acme', apiKey: 'k', issuer: bad, revocations: authfi.createRevocationStore() });
      assert.throws(() => auth.receiver({ audience: 'a' }), /issuer/);
    }
  });
});

// --- keys with the wrong shape, served from a custom key set ---

const startJwks = async (jwks) => {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ keys: jwks }));
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  open.push(() => { server.closeAllConnections(); server.close(); });
  return `http://127.0.0.1:${server.address().port}`;
};
const NOW_MS = Date.UTC(2026, 9, 26, 12, 0, 0);
const signWith = (alg, kid, privateKey, payload, header = {}) => {
  const h = b64(JSON.stringify({ alg, typ: 'at+jwt', kid, ...header }));
  const p = b64(JSON.stringify(payload));
  const data = Buffer.from(`${h}.${p}`);
  const sig = alg === 'EdDSA' ? crypto.sign(null, data, privateKey) : crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${b64(sig)}`;
};
const accessPayload = (iss) => ({ iss, sub: 'usr_1', aud: 'api', tenant_id: 't1', iat: NOW_MS / 1000 - 5, exp: NOW_MS / 1000 + 3600 });
const verifierFor = (issuer) => authfi({ tenant: 'acme', apiKey: 'k', issuer, clock: () => NOW_MS });

describe('kill: key shape binding', () => {
  it('a key whose own alg, use, curve or size does not fit the token alg is refused', async () => {
    const ed = crypto.generateKeyPairSync('ed25519');
    const ed448 = crypto.generateKeyPairSync('ed448');
    const k1 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const rsa1024 = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    const jwk = (pair, extra) => ({ ...pair.publicKey.export({ format: 'jwk' }), ...extra });
    const issuer = await startJwks([
      jwk(ed, { kid: 'good', use: 'sig', alg: 'EdDSA' }),
      jwk(ed, { kid: 'wrongalg', use: 'sig', alg: 'ES256' }),
      jwk(ed, { kid: 'enc', use: 'enc' }),
      jwk(ed448, { kid: 'ed448' }),
      jwk(k1, { kid: 'k1' }),
      jwk(rsa1024, { kid: 'rsa1024' }),
    ]);
    const auth = verifierFor(issuer);
    const p = accessPayload(issuer);
    await auth.verifyToken(signWith('EdDSA', 'good', ed.privateKey, p));
    await assert.rejects(auth.verifyToken(signWith('EdDSA', 'wrongalg', ed.privateKey, p)));
    await assert.rejects(auth.verifyToken(signWith('EdDSA', 'enc', ed.privateKey, p)));
    await assert.rejects(auth.verifyToken(signWith('EdDSA', 'ed448', ed448.privateKey, p)));
    await assert.rejects(auth.verifyToken(signWith('ES256', 'k1', k1.privateKey, p)));
    const rs = (priv) => {
      const h = b64(JSON.stringify({ alg: 'RS256', typ: 'at+jwt', kid: 'rsa1024' }));
      const body = b64(JSON.stringify(p));
      return `${h}.${body}.${b64(crypto.sign('sha256', Buffer.from(`${h}.${body}`), priv))}`;
    };
    await assert.rejects(auth.verifyToken(rs(rsa1024.privateKey)));
  });
});

describe('kill: JWS structure on the receiver path', () => {
  const sendRaw = async (r, build) => {
    const k = r.issuer.keys.get('ed1');
    const c = r.issuer.setClaims();
    const { h, p, sigOf, tail = '' } = build(c, k);
    const hb = h !== undefined ? h : b64(JSON.stringify({ alg: 'EdDSA', typ: 'secevent+jwt', kid: 'ed1' }));
    const pb = p !== undefined ? p : b64(JSON.stringify(c));
    const sig = crypto.sign(null, Buffer.from(`${hb}.${pb}`), k.pair.privateKey);
    return r.push(`${hb}.${pb}.${b64(sig)}${sigOf || ''}${tail}`);
  };

  it('a fourth part is malformed', async () => {
    const r = await rig();
    const res = await r.push(`${r.issuer.set()}.extra`);
    assert.equal(res.status, 400);
    assert.equal(err(res), 'invalid_request');
  });

  it('a signature with base64 padding is malformed, not a different spelling of the same signature', async () => {
    const r = await rig();
    const res = await r.push(`${r.issuer.set()}=`);
    assert.equal(err(res), 'invalid_request');
  });

  it('a padded header segment that is correctly signed is malformed', async () => {
    const r = await rig();
    const h = `${b64(JSON.stringify({ alg: 'EdDSA', typ: 'secevent+jwt', kid: 'ed1' }))}=`;
    const res = await sendRaw(r, () => ({ h }));
    assert.equal(err(res), 'invalid_request');
  });

  it('any crit header, even a falsy one, is refused', async () => {
    const r = await rig();
    const res = await r.push(r.issuer.set({ header: { crit: false } }));
    assert.equal(err(res), 'invalid_key');
  });

  it('a pre-parsed body over 16 KiB is refused', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.pad = 'x'.repeat(20000);
    const handler = r.auth.receiver({ audience: STREAM_AUD });
    const res = { setHeader() {}, end(b) { this.body = b; }, statusCode: 0 };
    await handler(fakeReq(r.issuer.set({ claims: c })), res);
    assert.equal(res.statusCode, 400);
  });

  it('the key set is refetched after its refresh interval', async () => {
    const r = await rig();
    assert.equal((await r.push(r.issuer.set())).status, 202);
    const before = r.issuer.jwksHits;
    r.issuer.advance(6 * 60 * 1000);
    assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims() }))).status, 202);
    assert.ok(r.issuer.jwksHits > before, 'the cached key set never expires');
  });

  it('an issuer with a trailing slash still finds its key set', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const auth = authfi({ tenant: 'acme', apiKey: 'k', issuer: `${issuer.url}/`, clock: () => issuer.clock() });
    await auth.verifyToken(issuer.token('usr_1', issuer.seconds() - 1));
  });
});

describe('kill: registerStream', () => {
  const serve = async (handler) => {
    const server = http.createServer(handler);
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    open.push(() => { server.closeAllConnections(); server.close(); });
    return `http://127.0.0.1:${server.address().port}`;
  };
  const run = async (mk) => {
    let base;
    base = await serve((req, res) => mk(base, req, res));
    const auth = authfi({ tenant: 'acme', apiKey: 'k', issuer: base });
    return auth.registerStream('operator-token', { audience: 'a', endpointUrl: 'https://rp.test/ssf' });
  };
  const meta = (base, ep) => JSON.stringify({ issuer: base, configuration_endpoint: ep === undefined ? `${base}/v1/ssf/streams` : ep });

  it('control: a valid registration works', async () => {
    const s = await run((base, req, res) => {
      if (req.url.startsWith('/.well-known')) return res.end(meta(base));
      res.statusCode = 201;
      res.end('{"data":{"id":"s1"}}');
    });
    assert.equal(s.id, 's1');
  });

  it('a reply without a stream id is not a registration', async () => {
    await assert.rejects(run((base, req, res) => {
      if (req.url.startsWith('/.well-known')) return res.end(meta(base));
      res.statusCode = 201;
      res.end('{"data":{}}');
    }));
  });

  it('a failing discovery document stops the registration', async () => {
    let posted = 0;
    await assert.rejects(run((base, req, res) => {
      if (req.url.startsWith('/.well-known')) { res.statusCode = 500; return res.end(meta(base)); }
      posted += 1;
      res.statusCode = 201;
      res.end('{"data":{"id":"s1"}}');
    }));
    assert.equal(posted, 0);
  });

  it('a configuration endpoint with a fragment is refused', async () => {
    await assert.rejects(run((base, req, res) => {
      if (req.url.startsWith('/.well-known')) return res.end(meta(base, `${base}/v1/ssf/streams#frag`));
      res.statusCode = 201;
      res.end('{"data":{"id":"s1"}}');
    }));
  });

  it('a redirect on discovery is an error, not a hop', async () => {
    let other = 0;
    const evil = await serve((req, res) => { other += 1; res.end('{}'); });
    await assert.rejects(run((base, req, res) => {
      if (req.url.startsWith('/.well-known')) { res.statusCode = 302; res.setHeader('Location', `${evil}/x`); return res.end(); }
      res.end('{}');
    }));
    assert.equal(other, 0);
  });
});

describe('stale boundary', () => {
  it('ignores a SET exactly one lifetime old and applies one a second younger', async () => {
    for (const [age, applied] of [[86400, false], [86399, true]]) {
      const r = await rig();
      const c = r.issuer.setClaims();
      c.iat = r.issuer.seconds() - age;
      assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
      assert.equal(r.store.size === 1, applied, `age ${age}`);
    }
  });
});

describe('round 2', () => {
  it('Express 4 + global express.json(): req.body is {} for a non-JSON type and the stream is unread', async () => {
    const r = await rig();
    const handler = r.auth.receiver({ audience: STREAM_AUD });
    const server = http.createServer((req, res) => { req.body = {}; handler(req, res); }); // what body-parser 1.x does for a skipped type
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    open.push(() => { server.closeAllConnections(); server.close(); });
    const res = await fetch(`http://127.0.0.1:${server.address().port}/`, { method: 'POST', headers: { 'Content-Type': SECEVENT }, body: r.issuer.set() });
    assert.equal(res.status, 202, await res.text());
  });

  it('an unknown kid heals: 503 inside the window, 202 on the retry after it', async () => {
    const r = await rig();
    assert.equal((await r.push(r.issuer.set())).status, 202);
    r.issuer.add('ed2', 'EdDSA', crypto.generateKeyPairSync('ed25519'));
    r.issuer.advance(2000);
    const set = r.issuer.set({ kid: 'ed2', claims: r.issuer.setClaims() });
    assert.equal((await r.push(set)).status, 503);
    r.issuer.advance(16000);
    assert.equal((await r.push(set)).status, 202);
  });

  it('a token with no exp is refused outright, so it is never forgotten into validity', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const noExp = r.issuer.sign('ed1', { typ: 'at+jwt' }, { iss: r.issuer.url, sub: AGENT, aud: API_AUD, tenant_id: 't1', iat: now - 5 });
    await r.push(r.issuer.set());
    await refused(r.auth.verifyToken(noExp), 'token_iat_exp_required');
    r.issuer.advance(86400 * 1000 + 5000);
    await refused(r.auth.verifyToken(noExp), 'token_iat_exp_required');
  });
});

describe('r2 kill', () => {
  it('a SET exactly one lifetime old is ignored, not applied', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.iat = r.issuer.seconds() - 86400;
    assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
    assert.equal(r.store.size, 0);
  });
  it('a chain three actors deep is walked', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, { act: { sub: 'agent:a', act: { sub: 'agent:b', act: { sub: AGENT } } } });
    await r.push(r.issuer.set());
    await refused(r.auth.verifyToken(tok), 'token_revoked');
  });
  it('store shape: each missing part is refused', () => {
    const good = authfi.createRevocationStore();
    for (const bad of [{ ...good, revoke: undefined }, { isRevoked: good.isRevoked, revoke: good.revoke, tokenLifetimeSeconds: 0, maxEntries: 5 }, { isRevoked: good.isRevoked, revoke: good.revoke, tokenLifetimeSeconds: 10 }, { revoke: good.revoke, tokenLifetimeSeconds: 10, maxEntries: 5 }]) {
      assert.throws(() => createReceiver(mk({ store: bad }), { audience: 'a' }));
    }
  });
  it('Express 4 body-parser leaves req.body = {} with the stream unread: the SET must be read', async () => {
    const r = await rig();
    const handler = r.auth.receiver({ audience: STREAM_AUD });
    const server = http.createServer((req, res) => { req.body = {}; handler(req, res); });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    open.push(() => { server.closeAllConnections(); server.close(); });
    const res = await fetch(`http://127.0.0.1:${server.address().port}/`, { method: 'POST', headers: { 'Content-Type': SECEVENT }, body: r.issuer.set() });
    assert.equal(res.status, 202);
  });
});
