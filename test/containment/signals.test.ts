// Containment track C: refuse an agent's tokens the moment AuthFI withdraws it. Ported from the 0.1
// JavaScript suite (test/signals.test.js): the Shared Signals receiver (RFC 8935), the revocation
// store, the verifier's refusal of a revoked subject, and stream registration.

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import {
  SeenSet,
  createReceiver,
  createRevocationStore,
  registerStream,
  type PushRequest,
  type PushResponse,
  type StreamRequest,
} from '../../src/signals/index.js';
import { requestCredentials } from '../../src/express/index.js';
import {
  AGENT,
  API_AUD,
  EV,
  Issuer,
  SECEVENT,
  STREAM_AUD,
  b64,
  closeAfterEach,
  err,
  open,
  refused,
  rig,
  serve,
  type Rig,
} from './rig.js';

closeAfterEach();

const verify = (r: Rig, token: string) => r.verifier.verify(token);

describe('an accepted revocation', () => {
  it('refuses earlier tokens and allows later ones', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const before = r.issuer.token(AGENT, now - 10);
    await verify(r, before); // fine before any revocation
    assert.equal((await r.push(r.issuer.set())).status, 202);

    await refused(verify(r, before), 'token_revoked');
    await refused(verify(r, r.issuer.token(AGENT, now)), 'token_revoked'); // same second: not provably later
    r.issuer.advance(2000);
    await verify(r, r.issuer.token(AGENT, r.issuer.seconds()));
    await verify(r, r.issuer.token('agent:agt_other', now - 10));
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0]?.revoked, true);
    assert.equal(r.signals[0]?.subject, AGENT);
    assert.equal(r.signals[0]?.event, EV.revoked);
  });

  for (const [name, ev] of [
    ['session-revoked', EV.revoked],
    ['account-purged', EV.purged],
    ['credential-compromise', EV.compromise],
  ] as const) {
    it(`${name} revokes`, async () => {
      const r = await rig();
      const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
      assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims(ev) }))).status, 202);
      await refused(verify(r, tok), 'token_revoked');
    });
  }

  it('refuses a delegated token whose actor is revoked, and leaves the person alone', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, { act: { sub: AGENT } });
    // An agent token's proof needs its request: before the revocation it is refused for that, never as revoked.
    await refused(verify(r, tok), 'agent_token_needs_request');
    await r.push(r.issuer.set());
    await refused(verify(r, tok), 'token_revoked');
    await verify(r, r.issuer.token('usr_7', r.issuer.seconds() - 1));
  });

  it('carries the jti of the revoking SET as the reference of the refusal', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    const claims = r.issuer.setClaims();
    await r.push(r.issuer.set({ claims }));
    await expect(verify(r, tok)).rejects.toMatchObject({
      name: 'TokenRevoked',
      code: 'token_revoked',
      ref: claims.jti,
    });
  });

  it('refuses a revoked agent on verifyRequest too, before its proof is read', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    const req = { method: 'GET', url: '/orders', headers: { authorization: `DPoP ${tok}` } };
    const before = await r.verifier.verifyRequest(requestCredentials(req)).then(
      () => null,
      (e: unknown) => (e as { code: string }).code,
    );
    assert.notEqual(before, 'token_revoked');
    await r.push(r.issuer.set());
    await refused(r.verifier.verifyRequest(requestCredentials(req)), 'token_revoked');
  });

  it('refuses a token with no iat, whatever its subject, when a store is configured', async () => {
    const r = await rig();
    await r.push(r.issuer.set());
    const noIat = (sub: string): string =>
      r.issuer.sign(
        'ed1',
        { typ: 'at+jwt' },
        { iss: r.issuer.url, sub, aud: API_AUD, tenant_id: 't1', exp: r.issuer.seconds() + 3600 },
      );
    await refused(verify(r, noIat(AGENT)), 'token_iat_exp_required');
    await refused(verify(r, noIat('agent:agt_9')), 'token_iat_exp_required');
  });

  it('uses the iat of the SET, so a late delivery does not refuse newer tokens', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const claims = r.issuer.setClaims();
    claims.iat = now - 30;
    await r.push(r.issuer.set({ claims }));
    await verify(r, r.issuer.token(AGENT, now - 5));
    await refused(verify(r, r.issuer.token(AGENT, now - 40)), 'token_revoked');
  });

  it('accepts a resume, tells the hook, and does not lift the revocation', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    await r.push(r.issuer.set());
    r.issuer.advance(1000);
    assert.equal(
      (await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { resumed: true }) }))).status,
      202,
    );
    await refused(verify(r, tok), 'token_revoked');
    await verify(r, r.issuer.token(AGENT, r.issuer.seconds() + 1));
    assert.equal(r.signals.length, 2);
    assert.equal(r.signals[1]?.resumed, true);
    assert.equal(r.signals[1]?.revoked, false);
  });

  it('revokes nothing for a claims change without resume or for an unknown event', async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
    assert.equal(
      (await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { revoked_permission: 'x' }) })))
        .status,
      202,
    );
    assert.equal(
      (await r.push(r.issuer.set({ claims: r.issuer.setClaims('https://example.test/unknown') }))).status,
      202,
    );
    await verify(r, tok);
    assert.equal(r.store.size, 0);
  });

  it('reads the iss_sub subject format, for this issuer only', async () => {
    const r = await rig();
    const good = r.issuer.setClaims();
    good.sub_id = { format: 'iss_sub', iss: r.issuer.url, sub: 'usr_5' };
    assert.equal((await r.push(r.issuer.set({ claims: good }))).status, 202);
    await refused(verify(r, r.issuer.token('usr_5', r.issuer.seconds() - 1)), 'token_revoked');
    const foreign = r.issuer.setClaims();
    foreign.sub_id = { format: 'iss_sub', iss: 'https://elsewhere.test', sub: 'usr_6' };
    const res = await r.push(r.issuer.set({ claims: foreign }));
    assert.equal(res.status, 400);
    assert.equal(err(res), 'invalid_request');
  });
});

describe('a refused SET changes nothing', () => {
  const flipSig = (tok: string): string => {
    const i = tok.lastIndexOf('.');
    const sig = Buffer.from(tok.slice(i + 1), 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0xff;
    return `${tok.slice(0, i + 1)}${b64(sig)}`;
  };
  const withClaims = (i: Issuer, mut: (c: Record<string, unknown>) => void): string => {
    const c = i.setClaims();
    mut(c);
    return i.set({ claims: c });
  };
  const cases: [string, (i: Issuer) => string, string][] = [
    ['bad signature', (i) => flipSig(i.set()), 'authentication_failed'],
    [
      'payload tampered',
      (i) => {
        const parts = i.set().split('.');
        const c = i.setClaims();
        c.sub_id = { format: 'opaque', id: 'agent:agt_attacker_choice' };
        return `${parts[0]}.${b64(JSON.stringify(c))}.${parts[2]}`;
      },
      'authentication_failed',
    ],
    [
      'unknown kid is retryable, not final',
      (i) => i.set({ header: { kid: 'nope' } }),
      'temporarily_unavailable',
    ],
    ['no kid', (i) => i.set({ header: { kid: '' } }), 'invalid_key'],
    ['alg none', (i) => i.set({ header: { alg: 'none' } }), 'invalid_key'],
    ['alg HS256', (i) => i.set({ header: { alg: 'HS256' } }), 'invalid_key'],
    ['alg does not match the key', (i) => i.set({ header: { alg: 'RS256' } }), 'invalid_key'],
    ['crit header', (i) => i.set({ header: { crit: ['x'] } }), 'invalid_key'],
    ['wrong issuer', (i) => withClaims(i, (c) => (c.iss = 'https://evil.test')), 'invalid_issuer'],
    ['no issuer', (i) => i.set({ drop: ['iss'] }), 'invalid_issuer'],
    ['wrong audience', (i) => withClaims(i, (c) => (c.aud = 'someone-else')), 'invalid_audience'],
    ['no audience', (i) => i.set({ drop: ['aud'] }), 'invalid_audience'],
    [
      'the API audience is not the stream audience',
      (i) => withClaims(i, (c) => (c.aud = API_AUD)),
      'invalid_audience',
    ],
    ['expired', (i) => withClaims(i, (c) => (c.exp = i.seconds() - 600)), 'invalid_request'],
    ['exp is not a number', (i) => withClaims(i, (c) => (c.exp = 'soon')), 'invalid_request'],
    [
      'iat ahead of this clock is retryable, not final',
      (i) => withClaims(i, (c) => (c.iat = i.seconds() + 600)),
      'temporarily_unavailable',
    ],
    ['iat is a string', (i) => withClaims(i, (c) => (c.iat = String(i.seconds()))), 'invalid_request'],
    ['no iat', (i) => i.set({ drop: ['iat'] }), 'invalid_request'],
    ['no jti', (i) => i.set({ drop: ['jti'] }), 'invalid_request'],
    ['no events', (i) => i.set({ drop: ['events'] }), 'invalid_request'],
    ['empty events', (i) => withClaims(i, (c) => (c.events = {})), 'invalid_request'],
    [
      'event body is not an object',
      (i) => withClaims(i, (c) => (c.events = { [EV.revoked]: 'yes' })),
      'invalid_request',
    ],
    ['no subject', (i) => i.set({ drop: ['sub_id'] }), 'invalid_request'],
    [
      'empty subject',
      (i) => withClaims(i, (c) => (c.sub_id = { format: 'opaque', id: '' })),
      'invalid_request',
    ],
    [
      'unsupported subject format',
      (i) => withClaims(i, (c) => (c.sub_id = { format: 'email', email: 'a@b.test' })),
      'invalid_request',
    ],
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
      await verify(r, r.issuer.token(AGENT, r.issuer.seconds() - 1)); // nothing was revoked
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
    assert.equal(
      (await r.push(set, { 'Content-Type': 'Application/SecEvent+JWT; charset=utf-8' })).status,
      202,
    );
  });

  it('bounds a body that a body parser already read', async () => {
    const r = await rig();
    const handler = createReceiver(r.af, { revocations: r.store, audience: STREAM_AUD });
    const url = await serve((req, res) => {
      (req as unknown as { body: unknown }).body = 'a'.repeat(20 * 1024);
      void handler(req, res);
    });
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': SECEVENT }, body: 'x' });
    assert.equal(res.status, 400);
    assert.equal((JSON.parse(await res.text()) as { err: string }).err, 'invalid_request');
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
    const handler = createReceiver(r.af, { revocations: r.store, audience: STREAM_AUD });
    const url = await serve((req, res) => {
      req.on('data', () => undefined);
      req.on('end', () => {
        (req as unknown as { body: unknown }).body = { not: 'raw' };
        void handler(req, res);
      });
    });
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': SECEVENT },
      body: 'x',
      signal: AbortSignal.timeout(3000),
    });
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
    const s = new SeenSet(3, 60, () => now);
    for (const id of ['a', 'b', 'c']) assert.equal(s.claim(id), true);
    assert.equal(s.claim('b'), false);
    assert.equal(s.claim('d'), true); // full: forgets the oldest
    assert.equal(s.claim('a'), true); // a was forgotten
    now += 120_000;
    assert.equal(s.claim('b'), true);
    for (let i = 0; i < 5000; i++) s.claim(`x${String(i)}`);
    assert.equal(s.claim('x4999'), false); // the newest are kept
    assert.equal(s.claim('x0'), true); // the oldest were forgotten
  });
});

describe('authentication of the push', () => {
  it('requires the bearer when one is configured', async () => {
    const r = await rig({ receiver: { authToken: 's3cret-push' } });
    const set = r.issuer.set();
    for (const h of [
      undefined,
      'Bearer wrong',
      'Bearer s3cret-pus',
      'Bearer s3cret-pushX',
      'Basic s3cret-push',
      's3cret-push',
    ]) {
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
    const hits = r.issuer.jwksHits;
    assert.equal((await r.push(set)).status, 503); // a failed key-set fetch is not retried on every request
    assert.equal(r.issuer.jwksHits, hits);
    r.issuer.advance(16_000); // ... but after 15 seconds
    assert.equal((await r.push(set)).status, 202); // its jti was not burned
  });

  it('picks up a rotated key, with at most one refetch per interval for an unknown kid', async () => {
    const r = await rig();
    await r.push(r.issuer.set()); // loads the key set
    const hits = r.issuer.jwksHits;
    // 400 would be final for the transmitter, which disables the stream and loses the revocation
    for (let i = 0; i < 5; i++)
      assert.equal((await r.push(r.issuer.set({ header: { kid: 'nope' } }))).status, 503);
    assert.equal(r.issuer.jwksHits, hits + 1, 'forged-kid traffic inside the interval must not refetch');
    r.issuer.add('ed2', 'EdDSA', generateKeyPairSync('ed25519'));
    for (let i = 0; i < 5; i++) assert.equal((await r.push(r.issuer.set({ kid: 'ed2' }))).status, 503);
    assert.equal(r.issuer.jwksHits, hits + 1, 'the rotated key is not fetched before the interval ends');
    r.issuer.advance(31_000);
    assert.equal((await r.push(r.issuer.set({ kid: 'ed2' }))).status, 202);
    assert.equal(r.issuer.jwksHits, hits + 2);
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
    for (const kid of ['rs1', 'ps1', 'es1'])
      assert.equal((await r.push(r.issuer.set({ kid }))).status, 202, kid);
  });
});

describe('revocation lifetime and chains', () => {
  it('refuses a token that lives longer than the store remembers', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const store = createRevocationStore({ tokenLifetimeSeconds: 3600, clock: () => issuer.clock() });
    const af = new AuthFI({ issuer: issuer.url, clock: issuer.sdkClock() });
    const verifier = af.verifier({ audience: API_AUD, revocations: store });
    const now = issuer.seconds();
    await expect(verifier.verify(issuer.token(AGENT, now, { exp: now + 7200 }))).rejects.toMatchObject({
      code: 'configuration_invalid',
      message: expect.stringContaining('tokenLifetimeSeconds') as string,
    });
    await verifier.verify(issuer.token(AGENT, now, { exp: now + 3600 }));
  });

  it('refuses a token whose deeper actor in a delegation chain is revoked', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, {
      act: { sub: 'agent:mid', act: { sub: AGENT } },
    });
    // A delegation chain is refused outright, before and after the revocation.
    await refused(verify(r, tok), 'token_act_chain_unsupported');
    await r.push(r.issuer.set());
    await refused(verify(r, tok), 'token_act_chain_unsupported');
  });
});

describe('configuration fails closed', () => {
  it('refuses an authToken that would silently switch the bearer check off', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const af = new AuthFI({ issuer: issuer.url });
    const store = createRevocationStore();
    const build = (authToken: unknown) =>
      createReceiver(af, { revocations: store, audience: 'a', authToken: authToken as string });
    for (const bad of [Buffer.from('s3cret'), 12345, '', {}, null])
      assert.throws(() => build(bad), /authToken/);
    build(undefined);
    build('ok');
  });

  it('refuses a store that is not from createRevocationStore', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const af = new AuthFI({ issuer: issuer.url });
    const custom = { revoke() {}, isRevoked: () => false };
    assert.throws(
      () => createReceiver(af, { revocations: custom as never, audience: 'a' }),
      /createRevocationStore/,
    );
  });

  it('does not accept a bearer followed by anything else', async () => {
    const r = await rig({ receiver: { authToken: 's3cret' } });
    const set = r.issuer.set();
    assert.equal((await r.push(set, { Authorization: 'Bearer s3cret trailing' })).status, 401);
    assert.equal((await r.push(set, { Authorization: 'bearer   s3cret' })).status, 202);
  });

  it('refuses a receiver that cannot work', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const af = new AuthFI({ issuer: issuer.url });
    const store = createRevocationStore();
    assert.throws(() => createReceiver(af, { audience: 'a' } as never), /createRevocationStore/);
    assert.throws(() => createReceiver(af, { revocations: store } as never), /audience/);
    assert.throws(() => createReceiver(af, { revocations: store, audience: ' ' }), /audience/);
    assert.throws(() => new AuthFI({ issuer: 'http://acme.example.com' }), /https/);
    for (const bad of [`${issuer.url}/?x=1`, `${issuer.url}/#f`, `${issuer.url}/`]) {
      assert.throws(() => new AuthFI({ issuer: bad }), /issuer/);
    }
  });

  it('checks nothing without a store, and refuses a SET as an access token', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const af = new AuthFI({ issuer: issuer.url, clock: issuer.sdkClock() });
    const verifier = af.verifier({ audience: API_AUD });
    await verifier.verify(issuer.token('usr_7', issuer.seconds()));
    await refused(verifier.verify(issuer.set()), 'token_not_access_token');
  });

  it('verifies access tokens signed with EdDSA, ES256 and RS256', async () => {
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const af = new AuthFI({ issuer: issuer.url, clock: issuer.sdkClock() });
    const verifier = af.verifier({ audience: API_AUD });
    for (const kid of ['ed1', 'es1', 'rs1']) {
      const tok = issuer.sign(
        kid,
        { typ: 'at+jwt' },
        {
          iss: issuer.url,
          sub: 'usr_7',
          aud: API_AUD,
          tenant_id: 't1',
          iat: issuer.seconds(),
          exp: issuer.seconds() + 60,
        },
      );
      assert.equal((await verifier.verify(tok)).claims.sub, 'usr_7', kid);
    }
    await refused(
      verifier.verify(issuer.sign('ed1', { typ: 'at+jwt', alg: 'HS256' }, { sub: 'x' })),
      'token_signature_invalid',
    );
    await refused(
      verifier.verify(issuer.sign('ed1', { typ: 'at+jwt', alg: 'RS256' }, { sub: 'x' })),
      'token_key_unknown',
    );
  });

  it('keeps the revocation when the hook throws or rejects', async () => {
    for (const hook of [
      () => {
        throw new Error('boom');
      },
      () => Promise.reject(new Error('boom')),
    ]) {
      const r = await rig({ receiver: { onSignal: hook } });
      const tok = r.issuer.token(AGENT, r.issuer.seconds() - 1);
      assert.equal((await r.push(r.issuer.set())).status, 202);
      await refused(verify(r, tok), 'token_revoked');
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
  const fixed = (state: { now: number; opts: Parameters<typeof createRevocationStore>[0] }) =>
    createRevocationStore({ ...state.opts, clock: () => state.now });

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
    assert.equal(s.isRevoked('a', 'x' as never), true);
    assert.equal(s.isRevoked('y', undefined), false);
    st.now += 3600_000 + 120_000;
    assert.equal(s.isRevoked('a', t - 7200), false);
    s.revoke('old', st.now / 1000 - 7200);
    assert.equal(s.size, 1, 'a revocation already past the lifetime is not stored');
    assert.equal(s.revoke('', t), 0);
    assert.equal(s.revoke('z', 'not a number' as never), 0);
    assert.equal(s.size, 1);
  });

  it('raises a floor instead of forgetting a revocation when full', () => {
    const st = { now: 3_000_000_000, opts: { maxEntries: 20, tokenLifetimeSeconds: 3600 } };
    const s = fixed(st);
    const t = st.now / 1000;
    for (let i = 0; i < 20; i++) s.revoke(`s${String(i)}`, t + i);
    assert.equal(s.size, 20);
    const dropped = s.revoke('newcomer', t + 30);
    assert.ok(dropped > 0 && s.size <= 20, `dropped ${String(dropped)} size ${String(s.size)}`);
    assert.equal(s.isRevoked('s0', t - 60), true, 'a dropped revocation still refuses what it covered');
    assert.equal(s.isRevoked('unrelated', t - 60), true, 'the floor applies to every subject');
    assert.equal(s.isRevoked('unrelated', t + 20), false, 'newer than the floor');
    st.now += 7200_000;
    assert.equal(s.isRevoked('unrelated', t - 60), false, 'the floor ages out');
  });

  it('stays bounded under a flood', () => {
    const st = { now: 4_000_000_000, opts: { maxEntries: 500, tokenLifetimeSeconds: 3600 } };
    const s = fixed(st);
    for (let i = 0; i < 20_000; i++) s.revoke(`subject-${String(i)}`, st.now / 1000 + i / 100);
    assert.ok(s.size <= 500, `size ${String(s.size)}`);
  });

  it('uses its defaults for a missing or invalid size and lifetime', () => {
    const s = createRevocationStore({ maxEntries: -3, tokenLifetimeSeconds: Number.NaN });
    assert.equal(s.maxEntries, 100_000);
    assert.equal(s.tokenLifetimeSeconds, 86_400);
    assert.equal(createRevocationStore({ tokenLifetimeSeconds: 90.9 }).tokenLifetimeSeconds, 90);
    // without a clock option it reads the system clock
    const live = createRevocationStore();
    live.revoke('now', Date.now() / 1000);
    assert.equal(live.isRevoked('now', 1), true);
  });
});

describe('registerStream', () => {
  interface Hit {
    url: string | undefined;
    method: string | undefined;
    auth: string | undefined;
    body: string;
  }
  async function transmitter({
    meta,
    status = 201,
    reply,
  }: {
    meta: (base: string) => Record<string, unknown>;
    status?: number;
    reply?: string;
  }) {
    const hits: Hit[] = [];
    let base = '';
    base = await serve((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        if (req.url === '/.well-known/ssf-configuration') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(meta(base)));
          return;
        }
        hits.push({
          url: req.url,
          method: req.method,
          auth: req.headers.authorization,
          body: Buffer.concat(chunks).toString(),
        });
        res.statusCode = status;
        res.end(
          reply ??
            JSON.stringify({
              data: {
                id: 'str_1',
                audience: STREAM_AUD,
                endpoint_url: 'https://rp.test/ssf',
                status: 'enabled',
                events_requested: [EV.revoked],
              },
            }),
        );
      });
    });
    return { url: base, hits };
  }
  const client = (url: string) => new AuthFI({ issuer: url });
  const request: StreamRequest = {
    audience: STREAM_AUD,
    endpointUrl: 'https://rp.test/ssf',
    authToken: 'push-secret',
    events: [EV.revoked],
  };

  it('registers a stream with the bearer and the documented body', async () => {
    const t = await transmitter({
      meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }),
    });
    const st = await registerStream(client(t.url), 'operator-token', request);
    assert.deepEqual(st, {
      id: 'str_1',
      audience: STREAM_AUD,
      endpointUrl: 'https://rp.test/ssf',
      status: 'enabled',
      events: [EV.revoked],
    });
    assert.equal(t.hits.length, 1);
    assert.equal(t.hits[0]?.url, '/v1/ssf/streams');
    assert.equal(t.hits[0]?.auth, 'Bearer operator-token');
    assert.deepEqual(JSON.parse(t.hits[0]?.body ?? ''), {
      audience: STREAM_AUD,
      endpoint_url: 'https://rp.test/ssf',
      auth_token: 'push-secret',
      events_requested: [EV.revoked],
    });
    assert.ok(!JSON.stringify(st).includes('push-secret'));
  });

  it('never sends the bearer to another host', async () => {
    const evil = await transmitter({ meta: () => ({}) });
    const t = await transmitter({
      meta: (b) => ({ issuer: b, configuration_endpoint: `${evil.url}/v1/ssf/streams` }),
    });
    await assert.rejects(registerStream(client(t.url), 'operator-token', request), /not on the issuer/);
    assert.equal(evil.hits.length, 0);
    assert.equal(t.hits.length, 0);
  });

  it('does not follow a redirect with the bearer', async () => {
    const evil = await transmitter({ meta: () => ({}) });
    const redirecting = await serve((req, res) => {
      res.statusCode = 307;
      res.setHeader('Location', `${evil.url}${req.url ?? ''}`);
      res.end();
    });
    await assert.rejects(registerStream(client(redirecting), 'operator-token', request));
    let post = '';
    post = await serve((req, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ issuer: post, configuration_endpoint: `${post}/v1/ssf/streams` }));
        return;
      }
      res.statusCode = 307;
      res.setHeader('Location', `${evil.url}/stolen`);
      res.end();
    });
    await assert.rejects(registerStream(client(post), 'operator-token', request));
    assert.equal(evil.hits.length, 0, 'the bearer must never reach the redirect target');
  });

  it('refuses metadata that names another issuer', async () => {
    const t = await transmitter({
      meta: (b) => ({ issuer: 'https://other.test', configuration_endpoint: `${b}/v1/ssf/streams` }),
    });
    await assert.rejects(registerStream(client(t.url), 'operator-token', request), /another issuer/);
    assert.equal(t.hits.length, 0);
  });

  it('turns a refusal into an error that holds no secret', async () => {
    const t = await transmitter({
      meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }),
      status: 403,
      reply: '{"error":"operator-token and push-secret leaked"}',
    });
    await assert.rejects(
      registerStream(client(t.url), 'operator-token', request),
      (e: Error) =>
        e.message.includes('refused (403)') &&
        !e.message.includes('operator-token') &&
        !e.message.includes('push-secret'),
    );
  });

  it('refuses invalid requests before any request is made', async () => {
    const t = await transmitter({
      meta: (b) => ({ issuer: b, configuration_endpoint: `${b}/v1/ssf/streams` }),
    });
    const c = client(t.url);
    await assert.rejects(registerStream(c, '', request), /bearer/);
    await assert.rejects(registerStream(c, 'b', { ...request, audience: '' }), /audience/);
    await assert.rejects(registerStream(c, 'b', { ...request, endpointUrl: 'http://rp.test/ssf' }), /https/);
    await assert.rejects(
      registerStream(c, 'b', { ...request, endpointUrl: 'https://u:p@rp.test/ssf' }),
      /https/,
    );
    await assert.rejects(registerStream(c, 'b', { ...request, endpointUrl: 'nonsense' }), /https/);
    assert.equal(t.hits.length, 0);
    await registerStream(c, 'b', request); // control
    assert.equal(t.hits.length, 1);
  });

  const run = async (
    mk: (
      base: string,
      req: import('node:http').IncomingMessage,
      res: import('node:http').ServerResponse,
    ) => void,
  ) => {
    let base = '';
    base = await serve((req, res) => {
      mk(base, req, res);
    });
    return registerStream(client(base), 'operator-token', {
      audience: 'a',
      endpointUrl: 'https://rp.test/ssf',
    });
  };
  const meta = (base: string, ep?: string): string =>
    JSON.stringify({ issuer: base, configuration_endpoint: ep ?? `${base}/v1/ssf/streams` });

  it('control: a valid registration works', async () => {
    const s = await run((base, req, res) => {
      if (req.url?.startsWith('/.well-known') === true) {
        res.end(meta(base));
        return;
      }
      res.statusCode = 201;
      res.end('{"data":{"id":"s1"}}');
    });
    assert.equal(s.id, 's1');
    assert.deepEqual(s.events, []);
  });
  it('a reply without a stream id is not a registration', async () => {
    await assert.rejects(
      run((base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.end(meta(base));
          return;
        }
        res.statusCode = 201;
        res.end('{"data":{}}');
      }),
    );
    await assert.rejects(
      run((base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.end(meta(base));
          return;
        }
        res.statusCode = 201;
        res.end('not json');
      }),
      /holds no stream/,
    );
  });
  it('a failing discovery document stops the registration', async () => {
    let posted = 0;
    await assert.rejects(
      run((base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.statusCode = 500;
          res.end(meta(base));
          return;
        }
        posted += 1;
        res.statusCode = 201;
        res.end('{"data":{"id":"s1"}}');
      }),
    );
    assert.equal(posted, 0);
  });
  it('a configuration endpoint with a fragment, or none, is refused', async () => {
    await assert.rejects(
      run((base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.end(meta(base, `${base}/v1/ssf/streams#frag`));
          return;
        }
        res.statusCode = 201;
        res.end('{"data":{"id":"s1"}}');
      }),
    );
    await assert.rejects(
      run((base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.end(JSON.stringify({ issuer: base }));
          return;
        }
        res.end('{}');
      }),
      /configuration_endpoint/,
    );
  });
  it('a redirect on discovery is an error, not a hop', async () => {
    let other = 0;
    const evil = await serve((_req, res) => {
      other += 1;
      res.end('{}');
    });
    await assert.rejects(
      run((_base, req, res) => {
        if (req.url?.startsWith('/.well-known') === true) {
          res.statusCode = 302;
          res.setHeader('Location', `${evil}/x`);
          res.end();
          return;
        }
        res.end('{}');
      }),
    );
    assert.equal(other, 0);
  });
});

describe('receipt to refusal latency', () => {
  it('measures push start to refusal over 50 runs', async () => {
    const r = await rig();
    const total: number[] = [];
    for (let i = 0; i < 50; i++) {
      const sub = `agent:agt_lat_${String(i)}`;
      const tok = r.issuer.token(sub, r.issuer.seconds() - 1);
      await verify(r, tok);
      const claims = r.issuer.setClaims();
      claims.sub_id = { format: 'opaque', id: sub };
      const set = r.issuer.set({ claims });
      const start = process.hrtime.bigint();
      const res = await r.push(set);
      assert.equal(res.status, 202);
      await refused(verify(r, tok), 'token_revoked');
      total.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    const sorted = [...total].sort((a, b) => a - b);
    const q = (p: number): number =>
      sorted[Math.min(sorted.length - 1, Math.floor((sorted.length * p) / 100))] ?? 0;
    const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
    const f = (n: number): string => `${n.toFixed(3)}ms`;
    const out = [
      'Node SDK receiver: push start to verify refusal, loopback HTTP, 50 runs',
      `push -> refused (HTTP + handler)   n=${String(sorted.length)} min=${f(sorted[0] ?? 0)} p50=${f(q(50))} p95=${f(q(95))} p99=${f(q(99))} max=${f(sorted[sorted.length - 1] ?? 0)} mean=${f(mean)}`,
      'Excludes the transmitter queue and drain delay; that part is measured on the platform side.',
      '',
    ].join('\n');
    if (process.env.LATENCY_OUT) writeFileSync(process.env.LATENCY_OUT, out);
    assert.ok(q(99) < 1000, `p99 ${String(q(99))}ms is not under 1s`);
  });
});

const LIFE = 3600;
const storeAt = (opts: Parameters<typeof createRevocationStore>[0] = {}) => {
  const c = { now: 1_800_000_000_000 };
  const s = createRevocationStore({ tokenLifetimeSeconds: LIFE, clock: () => c.now, ...opts });
  return { s, c, t0: c.now / 1000 };
};

describe('kill: store', () => {
  it('eviction drops the oldest tenth and raises the floor to the newest dropped', () => {
    const { s, t0 } = storeAt({ maxEntries: 20 });
    for (let i = 0; i < 20; i++) s.revoke(`s${String(i)}`, t0 + i);
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
    for (let i = 0; i < 8; i++) s.revoke(`new${String(i)}`, t0 + 3000 + i);
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
    const seen = new SeenSet(10, 100, () => now);
    assert.equal(seen.claim('j'), true);
    now += 99_000;
    assert.equal(seen.claim('j'), false);
    now += 1_000;
    assert.equal(seen.claim('j'), true);
  });
});

describe('kill: receiver edges', () => {
  const claimsWith = (r: Rig, mod: (c: Record<string, unknown>, now: number) => void): string => {
    const c = r.issuer.setClaims();
    mod(c, r.issuer.seconds());
    return r.issuer.set({ claims: c });
  };
  const cases: [string, (c: Record<string, unknown>, now: number) => void, number][] = [
    ['jti 256', (c) => (c.jti = 'j'.repeat(256)), 202],
    ['jti 257', (c) => (c.jti = 'j'.repeat(257)), 400],
    ['subject 512', (c) => (c.sub_id = { format: 'opaque', id: 's'.repeat(512) }), 202],
    ['subject 513', (c) => (c.sub_id = { format: 'opaque', id: 's'.repeat(513) }), 400],
    ['opaque with sub only', (c) => (c.sub_id = { format: 'opaque', sub: 'agent:x' }), 400],
    ['iat +30', (c, n) => (c.iat = n + 30), 202],
    ['iat +60', (c, n) => (c.iat = n + 60), 202],
    ['iat +61', (c, n) => (c.iat = n + 61), 503],
    ['iat one lifetime old is ignored, not refused', (c, n) => (c.iat = n - 86_400), 202],
    ['iat one second inside', (c, n) => (c.iat = n - 86_399), 202],
    ['exp -30', (c, n) => (c.exp = n - 30), 202],
    ['exp -61', (c, n) => (c.exp = n - 61), 400],
    ['exp absurdly far', (c) => (c.exp = 1e13), 400],
    ['aud array containing the stream', (c) => (c.aud = ['other', STREAM_AUD]), 202],
    ['events as an array', (c) => (c.events = [{}]), 400],
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
    const sig = sign(null, Buffer.from(`${h}.${p}`), k?.pair.privateKey as never);
    const res = await r.push(`${h}.${p}.${b64(sig)}`);
    assert.equal(err(res), 'invalid_request');
  });

  it('resumed is true only for the boolean true; ignored events never reach the hook', async () => {
    const r = await rig();
    await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { resumed: 'false' }) }));
    await r.push(r.issuer.set({ claims: r.issuer.setClaims('https://example.test/unknown') }));
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0]?.resumed, false);
  });

  it('401 carries WWW-Authenticate; bearer parsing tolerates case and repeated spaces', async () => {
    const r = await rig({ receiver: { authToken: 's3cret' } });
    const no = await r.push(r.issuer.set());
    assert.equal(no.status, 401);
    assert.match(no.headers.get('www-authenticate') ?? '', /Bearer/);
    for (const h of ['bearer s3cret', 'BEARER s3cret', 'Bearer   s3cret']) {
      assert.equal((await r.push(r.issuer.set(), { Authorization: h })).status, 202, h);
    }
  });

  it('answers only after an async hook finished', async () => {
    let done = false;
    const r = await rig({
      receiver: {
        onSignal: async () => {
          await new Promise((ok) => setTimeout(ok, 50));
          done = true;
        },
      },
    });
    assert.equal((await r.push(r.issuer.set())).status, 202);
    assert.equal(done, true);
  });

  const fakeRes = () => {
    const out = { headers: {} as Record<string, string>, statusCode: 0, body: '' };
    const res: PushResponse = {
      get statusCode() {
        return out.statusCode;
      },
      set statusCode(v: number) {
        out.statusCode = v;
      },
      setHeader(k: string, v: string) {
        out.headers[k] = v;
      },
      end(b?: string) {
        out.body = b ?? '';
      },
    };
    return { res, out };
  };
  const fakeReq = (body: unknown, extra: Partial<PushRequest> = {}): PushRequest => ({
    method: 'POST',
    headers: { 'content-type': SECEVENT },
    body,
    on: () => undefined,
    ...extra,
  });

  it('a failure the receiver did not expect is retryable, not final', async () => {
    const r = await rig();
    const { res, out } = fakeRes();
    const req = fakeReq('x.y.z');
    Object.defineProperty(req, 'headers', {
      get(): never {
        throw new Error('boom');
      },
    });
    await r.handler(req, res);
    assert.equal(out.statusCode, 503);
    assert.equal(out.headers['Retry-After'], '5');
  });

  it('a pre-parsed string or byte body is used as is', async () => {
    const r = await rig();
    for (const body of [r.issuer.set(), Buffer.from(r.issuer.set())]) {
      const { res, out } = fakeRes();
      await Promise.race([r.handler(fakeReq(body), res), new Promise((ok) => setTimeout(ok, 500))]);
      assert.equal(out.statusCode, 202);
    }
  });

  it('a pre-parsed body over 16 KiB is refused', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.pad = 'x'.repeat(20_000);
    const { res, out } = fakeRes();
    await r.handler(fakeReq(r.issuer.set({ claims: c })), res);
    assert.equal(out.statusCode, 400);
  });

  it('a stream that errors, or ends after being read, is a bad body', async () => {
    const r = await rig();
    const { res, out } = fakeRes();
    await r.handler(fakeReq({}, { readableEnded: true }), res);
    assert.equal(out.statusCode, 400);
    const { res: res2, out: out2 } = fakeRes();
    const failing = fakeReq(undefined, {
      on: ((event: string, listener: (e?: unknown) => void) => {
        if (event === 'error') listener(new Error('reset'));
      }) as PushRequest['on'],
    });
    await r.handler(failing, res2);
    assert.equal(out2.statusCode, 400);
    const { res: res3, out: out3 } = fakeRes();
    const badUtf8 = fakeReq(undefined, {
      on: ((event: string, listener: (e?: unknown) => void) => {
        if (event === 'data') listener(new Uint8Array([0xff, 0xfe]));
        if (event === 'end') listener();
      }) as PushRequest['on'],
    });
    await r.handler(badUtf8, res3);
    assert.equal(out3.statusCode, 400);
  });
});

// --- keys with the wrong shape, served from a custom key set ---

const NOW_MS = Date.UTC(2026, 9, 26, 12, 0, 0);
const signWith = (
  alg: string,
  kid: string,
  privateKey: import('node:crypto').KeyObject,
  payload: Record<string, unknown>,
): string => {
  const h = b64(JSON.stringify({ alg, typ: 'at+jwt', kid }));
  const p = b64(JSON.stringify(payload));
  const data = Buffer.from(`${h}.${p}`);
  const sig =
    alg === 'EdDSA'
      ? sign(null, data, privateKey)
      : sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${b64(sig)}`;
};

describe('kill: key shape binding', () => {
  it('a key whose own alg, use, curve or size does not fit the token alg is refused', async () => {
    const ed = generateKeyPairSync('ed25519');
    const ed448 = generateKeyPairSync('ed448');
    const k1 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const rsa1024 = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const jwk = (pair: { publicKey: import('node:crypto').KeyObject }, extra: Record<string, unknown>) => ({
      ...pair.publicKey.export({ format: 'jwk' }),
      ...extra,
    });
    const keys = [
      jwk(ed, { kid: 'good', use: 'sig', alg: 'EdDSA' }),
      jwk(ed, { kid: 'wrongalg', use: 'sig', alg: 'ES256' }),
      jwk(ed, { kid: 'enc', use: 'enc' }),
      jwk(ed448, { kid: 'ed448' }),
      jwk(k1, { kid: 'k1' }),
      jwk(rsa1024, { kid: 'rsa1024' }),
    ];
    let base = '';
    base = await serve((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        req.url === '/.well-known/openid-configuration'
          ? JSON.stringify({ issuer: base, token_endpoint: `${base}/t`, jwks_uri: `${base}/jwks` })
          : JSON.stringify({ keys }),
      );
    });
    const af = new AuthFI({
      issuer: base,
      clock: { now: () => NOW_MS, monotonic: () => NOW_MS, sleep: () => Promise.resolve() },
    });
    const verifier = af.verifier({ audience: API_AUD });
    const p = {
      iss: base,
      sub: 'usr_1',
      aud: API_AUD,
      tenant_id: 't1',
      iat: NOW_MS / 1000 - 5,
      exp: NOW_MS / 1000 + 3600,
    };
    await verifier.verify(signWith('EdDSA', 'good', ed.privateKey, p));
    await assert.rejects(verifier.verify(signWith('EdDSA', 'wrongalg', ed.privateKey, p)));
    await assert.rejects(verifier.verify(signWith('EdDSA', 'enc', ed.privateKey, p)));
    await assert.rejects(verifier.verify(signWith('EdDSA', 'ed448', ed448.privateKey, p)));
    await assert.rejects(verifier.verify(signWith('ES256', 'k1', k1.privateKey, p)));
    const h = b64(JSON.stringify({ alg: 'RS256', typ: 'at+jwt', kid: 'rsa1024' }));
    const body = b64(JSON.stringify(p));
    const rs = `${h}.${body}.${b64(sign('sha256', Buffer.from(`${h}.${body}`), rsa1024.privateKey))}`;
    await assert.rejects(verifier.verify(rs));
  });
});

describe('kill: JWS structure on the receiver path', () => {
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
    const k = r.issuer.keys.get('ed1');
    const h = `${b64(JSON.stringify({ alg: 'EdDSA', typ: 'secevent+jwt', kid: 'ed1' }))}=`;
    const p = b64(JSON.stringify(r.issuer.setClaims()));
    const sig = sign(null, Buffer.from(`${h}.${p}`), k?.pair.privateKey as never);
    const res = await r.push(`${h}.${p}.${b64(sig)}`);
    assert.equal(err(res), 'invalid_request');
  });

  it('any crit header, even a falsy one, is refused', async () => {
    const r = await rig();
    const res = await r.push(r.issuer.set({ header: { crit: false } }));
    assert.equal(err(res), 'invalid_key');
  });

  it('a non-canonical or missing signature is refused before a key is looked up', async () => {
    const r = await rig();
    const [h, p] = r.issuer.set().split('.');
    assert.equal(err(await r.push(`${h}.${p}.`)), 'invalid_request');
    assert.equal(r.issuer.jwksHits, 0);
  });

  it('the key set is refetched after its refresh interval', async () => {
    const r = await rig();
    assert.equal((await r.push(r.issuer.set())).status, 202);
    const before = r.issuer.jwksHits;
    r.issuer.advance(6 * 60 * 1000);
    assert.equal((await r.push(r.issuer.set({ claims: r.issuer.setClaims() }))).status, 202);
    assert.ok(r.issuer.jwksHits > before, 'the cached key set never expires');
  });
});

describe('stale boundary', () => {
  it('ignores a SET exactly one lifetime old and applies one a second younger', async () => {
    for (const [age, applied] of [
      [86_400, false],
      [86_399, true],
    ] as const) {
      const r = await rig();
      const c = r.issuer.setClaims();
      c.iat = r.issuer.seconds() - age;
      assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
      assert.equal(r.store.size === 1, applied, `age ${String(age)}`);
    }
  });
});

describe('round 2', () => {
  it('Express body-parser leaves req.body = {} with the stream unread: the SET must be read', async () => {
    const r = await rig();
    const url = await serve((req, res) => {
      (req as unknown as { body: unknown }).body = {};
      void r.handler(req, res);
    });
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': SECEVENT },
      body: r.issuer.set(),
    });
    assert.equal(res.status, 202, await res.text());
  });

  it('an unknown kid heals: 503 inside the window, 202 on the retry after it', async () => {
    const r = await rig();
    assert.equal((await r.push(r.issuer.set())).status, 202);
    assert.equal((await r.push(r.issuer.set({ header: { kid: 'nope' } }))).status, 503); // spends the refetch
    r.issuer.add('ed2', 'EdDSA', generateKeyPairSync('ed25519'));
    r.issuer.advance(2000);
    const set = r.issuer.set({ kid: 'ed2', claims: r.issuer.setClaims() });
    assert.equal((await r.push(set)).status, 503);
    r.issuer.advance(31_000);
    assert.equal((await r.push(set)).status, 202);
  });

  it('a rotated key is found by the first request when no refetch was spent', async () => {
    const r = await rig();
    assert.equal((await r.push(r.issuer.set())).status, 202);
    r.issuer.add('ed2', 'EdDSA', generateKeyPairSync('ed25519'));
    assert.equal((await r.push(r.issuer.set({ kid: 'ed2' }))).status, 202);
  });

  it('a token with no exp is refused outright, so it is never forgotten into validity', async () => {
    const r = await rig();
    const now = r.issuer.seconds();
    const noExp = r.issuer.sign(
      'ed1',
      { typ: 'at+jwt' },
      { iss: r.issuer.url, sub: AGENT, aud: API_AUD, tenant_id: 't1', iat: now - 5 },
    );
    await r.push(r.issuer.set());
    await refused(verify(r, noExp), 'token_claims_invalid');
    r.issuer.advance(86_400 * 1000 + 5000);
    await refused(verify(r, noExp), 'token_claims_invalid');
  });
});

describe('r2 kill', () => {
  it('a SET exactly one lifetime old is ignored, not applied', async () => {
    const r = await rig();
    const c = r.issuer.setClaims();
    c.iat = r.issuer.seconds() - 86_400;
    assert.equal((await r.push(r.issuer.set({ claims: c }))).status, 202);
    assert.equal(r.store.size, 0);
  });
  it('a chain three actors deep is refused whatever its depth', async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 1, {
      act: { sub: 'agent:a', act: { sub: 'agent:b', act: { sub: AGENT } } },
    });
    await r.push(r.issuer.set());
    await refused(verify(r, tok), 'token_act_chain_unsupported');
  });
  it('store shape: each missing part is refused', () => {
    const issuer = new AuthFI({ issuer: 'https://acme.authfi.io' });
    const revoke = () => 0;
    const isRevoked = () => false;
    for (const bad of [
      { isRevoked, tokenLifetimeSeconds: 10, maxEntries: 5 },
      { isRevoked, revoke, tokenLifetimeSeconds: 0, maxEntries: 5 },
      { isRevoked, revoke, tokenLifetimeSeconds: 10 },
      { revoke, tokenLifetimeSeconds: 10, maxEntries: 5 },
    ]) {
      assert.throws(() => createReceiver(issuer, { revocations: bad as never, audience: 'a' }));
    }
  });
});
