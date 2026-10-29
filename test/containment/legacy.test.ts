// The 0.1 factory kept the containment surface of #30 and #31 (verifyRequest, receiver,
// registerStream, createRevocationStore, DEFAULT_ROOT_PINS): code written against it keeps working
// for the one minor the factory stays, on the same checks as the new API.

import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import authfi from '../../src/legacy.js';
import { Issuer, SECEVENT, STREAM_AUD, API_AUD, AGENT, closeAfterEach, open } from './rig.js';
import { ISSUER, PUBLIC, T0, rejectsWith, scenario } from './scenario.js';

closeAfterEach();
const quiet = { debug() {}, info() {}, warn() {}, error() {} };

describe('the 0.1 factory and containment', () => {
  it('verifies an agent request with its proof and chain, and refuses without them', async () => {
    const s = scenario();
    const auth = authfi({
      issuer: ISSUER,
      audience: 'orders-api',
      publicUrl: PUBLIC,
      rootPins: [s.pki.rootPin],
      fetch: s.fetchImpl,
      now: () => s.clock.t,
      logger: quiet,
    });
    const claims = await auth.verifyRequest(s.request(s.agentToken()));
    assert.equal(claims.sub, 'agt_1');
    await rejectsWith(auth.verifyRequest(s.request(s.agentToken(), { proofs: [] })), 'dpop_proof_missing');
    await rejectsWith(auth.verifyToken(s.agentToken()), 'agent_token_needs_request');
    assert.equal(s.clock.t, T0);
  });

  it('takes the 0.1 settings: leeway in seconds, tenantId, agentTokens, jwksUrl ignored', async () => {
    const s = scenario();
    const warns: string[] = [];
    const auth = authfi({
      issuer: ISSUER,
      audience: 'orders-api',
      leeway: 0,
      tenantId: 'tnt_1',
      agentTokens: 'off',
      jwksUrl: 'https://keys.example.com/jwks',
      clock: () => s.clock.t,
      fetch: s.fetchImpl,
      logger: { ...quiet, warn: (m) => warns.push(m) },
    });
    assert.equal((await auth.verifyToken(s.token(s.claims()))).sub, 'usr_1');
    await rejectsWith(
      auth.verifyToken(s.token(s.claims({ exp: Math.floor(s.clock.t / 1000) - 1 }))),
      'token_expired',
    );
    await rejectsWith(
      auth.verifyToken(s.token(s.claims({ tenant_id: 'tnt_2' }))),
      'token_tenant_not_issuers',
    );
    assert.ok(warns.some((w) => w.includes('jwksUrl is ignored')));
  });

  it('exposes createRevocationStore, DEFAULT_ROOT_PINS, receiver and registerStream', async () => {
    assert.equal(typeof authfi.createRevocationStore, 'function');
    assert.equal(authfi.DEFAULT_ROOT_PINS[0]?.length, 64);
    const issuer = await new Issuer().listen();
    open.push(() => {
      issuer.close();
    });
    const store = authfi.createRevocationStore({ clock: () => issuer.clock() });
    const auth = authfi({
      issuer: issuer.url,
      audience: API_AUD,
      revocations: store,
      clock: () => issuer.clock(),
      logger: quiet,
    });
    const handler = auth.receiver({ audience: STREAM_AUD });
    const out = { status: 0 };
    const set = issuer.set();
    await handler(
      {
        method: 'POST',
        headers: { 'content-type': SECEVENT },
        body: set,
        on: () => undefined,
      },
      {
        get statusCode() {
          return out.status;
        },
        set statusCode(v: number) {
          out.status = v;
        },
        setHeader: () => undefined,
        end: () => undefined,
      },
    );
    assert.equal(out.status, 202);
    await rejectsWith(auth.verifyToken(issuer.token(AGENT, issuer.seconds() - 1)), 'token_revoked');
    await assert.rejects(
      auth.registerStream('b', { audience: 'a', endpointUrl: 'http://not-https' }),
      /https/,
    );
  });

  it('refuses a receiver without a store', () => {
    const auth = authfi({ issuer: ISSUER, audience: 'orders-api', logger: quiet });
    assert.throws(() => auth.receiver({ audience: 'a' }), /revocations/);
  });
});
