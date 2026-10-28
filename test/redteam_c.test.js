'use strict';

// The kill-switch corpus (track C, invariant I7): attacks on the revocation receiver and the store,
// shared with the Go SDK as testdata/corpus-C-containment.json. Each case names a scenario below by
// its id and states the stable result. A case this file has no scenario for, or a scenario the file
// has no case for, fails the test, so the corpus and the code cannot drift apart.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const authfi = require('../index');
const { STREAM_AUD, API_AUD, AGENT, EV, SECEVENT, Issuer, open, rig } = require('./support');

afterEach(() => {
  while (open.length) open.pop()();
});

const accepted = { accepted: true };
const pushResult = (res) => (res.status === 202 ? accepted : { code: JSON.parse(res.text).err });
const verifyResult = async (r, tok) => {
  try {
    await r.auth.verifyToken(tok);
    return accepted;
  } catch (e) {
    return { code: e.code || 'not_an_authfi_error', ref: e.ref || '' };
  }
};
const revokeSET = (r) => {
  const claims = r.issuer.setClaims();
  return { set: r.issuer.set({ claims }), jti: claims.jti };
};
const flip = (tok) => {
  const i = tok.lastIndexOf('.');
  const sig = Buffer.from(tok.slice(i + 1), 'base64url');
  sig[0] ^= 0xff;
  return `${tok.slice(0, i + 1)}${sig.toString('base64url')}`;
};

const scenarios = {
  'set-forged-signature': async () => {
    const r = await rig();
    return pushResult(await r.push(flip(r.issuer.set())));
  },
  'set-other-aud': async () => {
    const r = await rig();
    const claims = r.issuer.setClaims();
    claims.aud = 'another-stream';
    return pushResult(await r.push(r.issuer.set({ claims })));
  },
  'set-other-iss': async () => {
    const r = await rig();
    const claims = r.issuer.setClaims();
    claims.iss = 'https://another-project.example';
    return pushResult(await r.push(r.issuer.set({ claims })));
  },
  'set-replayed-jti': async () => {
    const r = await rig();
    const { set } = revokeSET(r);
    for (let i = 0; i < 3; i++) {
      const res = pushResult(await r.push(set));
      if (!res.accepted) return res;
    }
    return r.signals.length === 1 ? accepted : { code: 'applied_more_than_once' };
  },
  'set-expired': async () => {
    const r = await rig();
    const claims = r.issuer.setClaims();
    claims.exp = r.issuer.seconds() - 600;
    return pushResult(await r.push(r.issuer.set({ claims })));
  },
  'set-alg-none': async () => {
    const r = await rig();
    return pushResult(await r.push(r.issuer.set({ header: { alg: 'none' } })));
  },
  'set-alg-hs256-confusion': async () => {
    const r = await rig();
    return pushResult(await r.push(r.issuer.set({ header: { alg: 'HS256' } })));
  },
  'set-alg-key-mismatch': async () => {
    const r = await rig();
    return pushResult(await r.push(r.issuer.set({ header: { alg: 'RS256' } })));
  },
  'set-kid-not-in-jwks': async () => {
    const r = await rig();
    return pushResult(await r.push(r.issuer.set({ header: { kid: 'not-in-the-key-set' } })));
  },
  'token-issued-before-revocation': async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds() - 10);
    const { set, jti } = revokeSET(r);
    const pushed = pushResult(await r.push(set));
    if (!pushed.accepted) return pushed;
    return { ...(await verifyResult(r, tok)), wantRef: jti };
  },
  'token-issued-same-second': async () => {
    const r = await rig();
    const tok = r.issuer.token(AGENT, r.issuer.seconds());
    const { set, jti } = revokeSET(r);
    const pushed = pushResult(await r.push(set));
    if (!pushed.accepted) return pushed;
    return { ...(await verifyResult(r, tok)), wantRef: jti };
  },
  'token-issued-after-revocation-resume': async () => {
    const r = await rig();
    const old = r.issuer.token(AGENT, r.issuer.seconds() - 10);
    await r.push(revokeSET(r).set);
    r.issuer.advance(2000);
    await r.push(r.issuer.set({ claims: r.issuer.setClaims(EV.claims, { resumed: true }) }));
    if ((await verifyResult(r, old)).code !== 'token_revoked') return { code: 'old_token_not_refused' };
    return verifyResult(r, r.issuer.token(AGENT, r.issuer.seconds()));
  },
  'token-delegated-actor-revoked': async () => {
    const r = await rig();
    const tok = r.issuer.token('usr_7', r.issuer.seconds() - 10, { act: { sub: AGENT } });
    const { set, jti } = revokeSET(r);
    await r.push(set);
    return { ...(await verifyResult(r, tok)), wantRef: jti };
  },
  'subject-case-variant': async () => {
    const r = await rig();
    await r.push(revokeSET(r).set);
    return verifyResult(r, r.issuer.token('AGENT:AGT_42', r.issuer.seconds() - 10));
  },
  'subject-prefix-missing': async () => {
    const r = await rig();
    const claims = r.issuer.setClaims();
    claims.sub_id = { format: 'opaque', id: 'agt_42' };
    await r.push(r.issuer.set({ claims }));
    return verifyResult(r, r.issuer.token(AGENT, r.issuer.seconds() - 10));
  },
  'body-oversize': async () => {
    const r = await rig();
    return pushResult(await r.push('a'.repeat(64 * 1024)));
  },
  'content-type-wrong': async () => {
    const r = await rig();
    return pushResult(await r.push(revokeSET(r).set, { 'Content-Type': 'application/json' }));
  },
  'flood-past-store-cap': async () => {
    const issuer = await new Issuer().listen();
    open.push(() => issuer.close());
    const store = authfi.createRevocationStore({ maxEntries: 20, clock: () => issuer.clock() });
    const auth = authfi({ tenant: 't', apiKey: 'k', audience: API_AUD, issuer: issuer.url, revocations: store, clock: () => issuer.clock() });
    const now = issuer.seconds();
    const tok = issuer.token('agent:agt_first', now - 10);
    store.revoke('agent:agt_first', now, 'jti-first');
    for (let i = 0; i < 60; i++) store.revoke(`agent:flood_${i}`, now + i + 1, `jti-flood-${i}`);
    if (store.size > 20) return { code: 'store_over_cap' };
    return verifyResult({ auth }, tok);
  },
};

describe('red-team corpus C (kill switch)', () => {
  const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'testdata', 'corpus-C-containment.json'), 'utf8'));
  const mine = corpus.cases.filter((c) => String(c.component).split(',').includes('node-sdk'));

  for (const tc of mine) {
    it(tc.id, async () => {
      assert.equal(tc.kind, 'revocation_scenario', `${tc.id}: kind ${tc.kind} is not one this harness can run`);
      const run = scenarios[tc.id];
      assert.ok(run, `${tc.id}: no scenario with this id; add it or the case is not tested`);
      assert.ok(tc.expect_code || tc.expect_accept, `${tc.id}: the case states neither expect_code nor expect_accept`);
      const got = await run();
      if (tc.expect_accept) assert.equal(got.accepted, true, `want accepted, got ${got.code} (${tc.why})`);
      if (tc.expect_code) assert.equal(got.code, tc.expect_code, `${tc.why}`);
      if (tc.expect_ref) {
        // I1: the refusal names the SET that decided it.
        assert.ok(got.ref, 'the refusal carries no decision reference');
        if (got.wantRef) assert.equal(got.ref, got.wantRef);
      }
    });
  }

  it('has a case for every scenario', () => {
    const ids = new Set(mine.map((c) => c.id));
    for (const id of Object.keys(scenarios)) assert.ok(ids.has(id), `scenario ${id} has no case in the corpus`);
  });
});
