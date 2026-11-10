// B3: what the SDK does when the platform turns the DPoP rules on (identity's nonce, the Bearer window closing).
// The platform side is in plans/ga-o/B3.md. Each test is a rule the SDK must keep once DPOP_NONCE_KEY is set at the
// token endpoint and an unbound agent token is dead:
//   - a token renewed after the server's nonce rotated is challenged once at the token endpoint, answered once;
//   - no request that follows a refusal goes out as Bearer, so a refusal never downgrades the credential;
//   - every attempt, a nonce retry included, carries a proof of its own (a proof is good once);
//   - a query string is not part of what a proof names (htu).
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { call, platform } from '../support/platform-setup.js';

const claimsOf = (proof: string | null): Record<string, unknown> => decodeJwt(proof ?? '');

describe('B3: the DPoP rules turned on', () => {
  it('challenges a token renewed after the nonce rotated once, and binds it again', async () => {
    const { agent, p, fake } = await platform();
    p.nonce = { token: 'n1', gateway: 'g1' };
    const first = await agent.token();
    p.nonce = { token: 'n2', gateway: 'g1' }; // identity's nonce rotated between the two mints
    const second = await agent.token({ force: true });

    expect(second).not.toBe(first);
    const minted = fake.to(`${p.issuer}/oauth/token`);
    expect(minted).toHaveLength(4); // two mints, each asked once and answered once
    const proofs = minted.map((r) => claimsOf(r.headers.get('dpop')));
    expect(proofs.map((c) => c.nonce)).toEqual([undefined, 'n1', 'n1', 'n2']);
    expect(new Set(proofs.map((c) => c.jti)).size).toBe(4); // the retry is a new proof
    expect(p.refusals.filter((r) => !r.includes('use_dpop_nonce'))).toEqual([]);
  });

  it('never sends the request that follows a refusal as Bearer', async () => {
    const { agent, p, fake } = await platform();
    p.nonce = { gateway: 'g1' };
    p.rotate = true; // a server that keeps asking: the refusal stands after one answer
    const res = await agent.fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(401);
    await agent.fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });

    const schemes = fake.to(`${p.issuer}/mcp`).map((r) => r.headers.get('authorization')?.split(' ')[0]);
    expect(schemes.length).toBeGreaterThanOrEqual(3);
    expect(new Set(schemes)).toEqual(new Set(['DPoP']));
  });

  it('answers a nonce with a new proof for the same request, carrying the nonce', async () => {
    const { agent, p, fake } = await platform();
    await agent.token();
    p.nonce = { gateway: 'g9' };
    const res = await agent.fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);

    const sent = fake.to(`${p.issuer}/mcp`);
    expect(sent).toHaveLength(2);
    const [asked, answered] = sent.map((r) => claimsOf(r.headers.get('dpop')));
    expect(asked!.jti).not.toBe(answered!.jti);
    expect(answered!.nonce).toBe('g9');
    expect(answered!.htu).toBe(asked!.htu);
  });

  it('names the URL without its query in the proof', async () => {
    const { agent, p } = await platform();
    const headers = await agent.headers('POST', `${p.issuer}/mcp?session=abc#frag`);
    const claims = claimsOf(headers.dpop ?? null);
    expect(claims.htu).toBe(`${p.issuer}/mcp`);
    expect(claims.htm).toBe('POST');
  });
});
