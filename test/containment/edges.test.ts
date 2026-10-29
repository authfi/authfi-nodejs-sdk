// Edges of the containment code that the ported suites do not reach: guards, headers, multi-issuer.

import assert from 'node:assert/strict';
import { describe, expect, it } from 'vitest';
import { createRevocationStore } from '../../src/signals/index.js';
import { memoryReplayGuard } from '../../src/verify/dpop-proof.js';
import { MultiIssuerVerifier } from '../../src/verify/verifier.js';
import { AUD, ISSUER, rejectsWith, scenario } from './scenario.js';

describe('the memory replay guard', () => {
  it('keeps a key counted while some of its entries remain, and sweeps only the expired', () => {
    let now = 0;
    const g = memoryReplayGuard(10, () => now, 5);
    assert.equal(g.record('a:1', 1000), true);
    assert.equal(g.record('a:2', 5000), true);
    now = 2000;
    assert.equal(g.record('b:1', 9000), true); // sweeps a:1 only
    assert.equal(g.record('a:2', 5000), false);
    assert.equal(g.record('a:1', 5000), true);
  });
});

describe('proof keys and headers', () => {
  it('refuses a PS256 key whose modulus is not text, and a coordinate that is not canonical', async () => {
    const s = scenario();
    const t = s.agentToken();
    await rejectsWith(
      s.client.verifyRequest(
        s.request(t, {
          proof: { header: { alg: 'PS256' }, jwk: { kty: 'RSA', n: 5, e: 'AQAB' } },
        }),
      ),
      'dpop_proof_alg_mismatch',
    );
    const jwk = s.dpopJwk as { x: string };
    const bent = { ...s.dpopJwk, x: `${jwk.x.slice(0, -1)}B` };
    await rejectsWith(
      s.client.verifyRequest(s.request(t, { proof: { jwk: bent } })),
      'dpop_proof_key_invalid',
    );
  });

  it('takes a forwarded host alone as no address, and a request with no target as not a path', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const t = s.agentToken();
    await rejectsWith(
      s.client.verifyRequest(s.request(t, { headers: { 'x-forwarded-host': 'edge.example.org' } })),
      'dpop_proof_htu_mismatch',
    );
    const plain = scenario();
    const tok = plain.agentToken();
    await rejectsWith(
      plain.client.verifier.verifyRequest({
        authorization: `DPoP ${tok}`,
        dpop: plain.proof(tok),
        method: 'GET',
      }),
      'dpop_proof_htu_mismatch',
    );
  });

  it('accepts an htu with no path for the root', async () => {
    const s = scenario();
    const t = s.agentToken();
    await s.client.verifyRequest(
      s.request(t, { url: '/', proof: { claims: { htu: 'https://api.example.com' } } }),
    );
  });

  it('does not swallow a failure that is no verdict on the token, in watch mode', async () => {
    const s = scenario({ config: { agentTokens: 'watch' } });
    const t = s.agentToken();
    await expect(
      s.client.verifier.verifyRequest({
        authorization: `DPoP ${t}`,
        dpop: 5 as never,
        method: 'GET',
        url: '/orders',
      }),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it('refuses a replay guard that cannot record', () => {
    assert.throws(() => scenario({ config: { replayGuard: {} as never } }), /record/);
  });
});

describe('revocation details', () => {
  it('refuses with no reference when the revoking event had none', async () => {
    const s = scenario();
    const store = createRevocationStore({ clock: () => s.clock.t });
    const c = s.build({ revocations: store });
    const t = s.token(s.claims());
    store.revoke('usr_1', Math.floor(s.clock.t / 1000));
    const err = await rejectsWith(c.verifyToken(t), 'token_revoked');
    assert.equal(err.ref, '');
    assert.ok(!err.message.includes('ref'));
  });
});

describe('several issuers', () => {
  it('counts a second Authorization header and refuses a token with no issuer', async () => {
    const s = scenario();
    const multi = new MultiIssuerVerifier({ [ISSUER]: { verifier: s.client.verifier, tenantId: 'tnt_1' } });
    const t = s.token(s.claims());
    await rejectsWith(
      multi.verifyRequest({ authorization: `Bearer ${t}`, headerCounts: { authorization: 2 } }),
      'token_missing',
    );
    await rejectsWith(multi.verify(s.token(s.claims({ iss: undefined }))), 'token_issuer_not_accepted');
    assert.equal((await multi.verifyRequest({ authorization: `Bearer ${t}` })).principal.id, 'usr_1');
    assert.equal(AUD, 'orders-api');
  });
  it('prints a delegated token and a typed person without actor', async () => {
    const s = scenario({ config: { agentTokens: 'off' } });
    const t = await s.client.verifier.verify(
      s.token(s.claims({ sub: 'user:u1', act: { sub: 'agent:agt_1' } })),
    );
    assert.match(String(t), /delegated user:u1 by agent:agt_1/);
    const p = await s.client.verifier.verify(s.token(s.claims({ sub: 'user:u2' })));
    assert.equal(p.tokenKind, 'person');
  });
});
