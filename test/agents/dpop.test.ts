import { describe, expect, it } from 'vitest';
import { decodeJwt } from 'jose';
import { AGENT } from '../support/fake-platform.js';
import { call, person, platform } from '../support/platform-setup.js';

const mcp = (p: { issuer: string }) => `${p.issuer}/mcp`;

describe("DPoP: the agent's tokens are bound to this process's key", () => {
  it('mints a token bound to the key, and says so', async () => {
    const { agent, p } = await platform();
    const token = await agent.token();
    const key = agent.dpop;
    expect(key).toBeDefined();
    expect(decodeJwt(token).cnf).toEqual({ jkt: key!.thumbprint });
    expect(p.refusals).toEqual([]);
    // The mint carried a proof of the key at the token endpoint.
    const mint = p.t.fake.to(`${p.issuer}/oauth/token`)[0]!;
    expect(mint.headers.get('dpop')).toMatch(/^eyJ/);
  });

  it('sends every gateway call as DPoP with a proof made for that request', async () => {
    const { agent, p } = await platform();
    const gateway = agent.gateway();
    const a = await gateway.fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    const b = await gateway.fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const sent = p.t.fake.to(mcp(p));
    expect(sent.map((r) => r.headers.get('authorization')?.split(' ')[0])).toEqual(['DPoP', 'DPoP']);
    expect(sent[0]!.headers.get('dpop')).not.toBe(sent[1]!.headers.get('dpop'));
    expect(p.refusals).toEqual([]);
  });

  it('headers() gives a fresh proof for the method and URL asked for', async () => {
    const { agent, p } = await platform();
    const url = `${p.issuer}/mcp/v1/messages`;
    const h = await agent.headers('POST', url);
    expect(h.authorization).toMatch(/^DPoP eyJ/);
    const claims = decodeJwt(h.dpop!);
    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe(url);
    expect(claims.ath).toBeDefined();
  });

  it('is refused by the platform in every way a proof can be wrong', async () => {
    const { agent, p, clock } = await platform();
    const url = mcp(p);
    const send = (headers: Record<string, string>, to = url) =>
      p.fetch(to, { method: 'POST', headers, body: call('billing__lookup') });

    // the bound token as Bearer
    const token = await agent.token();
    expect((await send({ authorization: `Bearer ${token}` })).status).toBe(401);
    expect(p.refusals.at(-1)).toContain('a bound token is not Bearer');

    // a proof replayed
    const good = await agent.headers('POST', url);
    expect((await send(good)).status).toBe(200);
    expect((await send(good)).status).toBe(401);
    expect(p.refusals.at(-1)).toContain('jti replayed');

    // a proof for another URL
    const other = await agent.headers('POST', `${p.issuer}/mcp/v1/messages`);
    expect((await send(other)).status).toBe(401);
    expect(p.refusals.at(-1)).toContain('htu');

    // a stale proof
    const stale = await agent.headers('POST', url);
    clock.advance(120_000);
    expect((await send(stale)).status).toBe(401);
    expect(p.refusals.at(-1)).toContain('iat');

    // a proof made for another token
    const first = await agent.token({ force: true });
    const second = await agent.token({ force: true });
    expect(second).not.toBe(first);
    const forSecond = await agent.headers('POST', url);
    expect((await send({ ...forSecond, authorization: `DPoP ${first}` })).status).toBe(401);
    expect(p.refusals.at(-1)).toMatch(/ath|not of the key/);
  });

  it("answers the server's nonce once, at the token endpoint, the gateway and the cloud door", async () => {
    const { agent, p, af } = await platform();
    p.nonce = { token: 'tn', gateway: 'gn', cloud: 'cn' };
    await agent.token();
    expect(p.t.fake.to(`${p.issuer}/oauth/token`)).toHaveLength(2);
    const res = await agent.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(p.t.fake.to(mcp(p))).toHaveLength(2);
    const out = await agent.gateway().cloudCredentials({ account: 'acct', role: 'reader' });
    expect(out.kind).toBe('issued');
    expect(p.t.fake.to(`${p.issuer}/mcp/v1/cloud/credentials`)).toHaveLength(2);
    expect(af).toBeDefined();
  });

  it('retries a nonce challenge once only: a server that keeps challenging is the answer', async () => {
    const { agent, p } = await platform();
    p.nonce = { gateway: 'g1' };
    p.rotate = true;
    await agent.token();
    await expect(
      agent.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') }),
    ).rejects.toMatchObject({ name: 'GatewayTokenRefused' });
    expect(p.t.fake.to(mcp(p))).toHaveLength(2);
  });

  it('a token for a customer API stays Bearer: a verifier built on this SDK takes no proof', async () => {
    const { agent } = await platform();
    const api = agent.forResource('api_orders', { sendTo: ['https://orders.example.com'] });
    const headers = await api.headers('GET', 'https://orders.example.com/v1/orders');
    expect(headers.authorization).toMatch(/^Bearer eyJ/);
    expect(headers.dpop).toBeUndefined();
    expect(api.dpop).toBeUndefined();
  });

  it('a token for AuthFI itself from forResource is bound', async () => {
    const { agent, p } = await platform();
    const own = agent.forResource(`${p.issuer}/mcp`);
    const headers = await own.headers('POST', mcp(p));
    expect(headers.authorization).toMatch(/^DPoP /);
    expect(own.dpop).toBeDefined();
  });

  it('is off when asked: the token is Bearer and the gateway takes an unbound token', async () => {
    const { af, p, key } = await platform();
    const agent = af.agent({ agentId: AGENT, key, dpop: false });
    const token = await agent.token();
    expect(decodeJwt(token).cnf).toBeUndefined();
    expect(agent.dpop).toBeUndefined();
    const res = await agent.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(p.t.fake.to(mcp(p))[0]!.headers.get('authorization')).toMatch(/^Bearer /);
  });

  it('keeps a Bearer token when the project leaves it unbound', async () => {
    const { agent, p } = await platform();
    p.bind = false;
    const res = await agent.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(agent.dpop).toBeUndefined();
    expect(p.t.fake.to(mcp(p))[0]!.headers.get('authorization')).toMatch(/^Bearer /);
  });

  it('refuses a token the platform bound to a key this process does not hold', async () => {
    const { agent, p } = await platform();
    p.bindTo = 'someone-elses-thumbprint';
    await expect(agent.token()).rejects.toMatchObject({ code: 'dpop_binding_mismatch' });
  });

  it('leaves the project alone that accepts no algorithm this SDK signs: tokens stay Bearer and it says so', async () => {
    const { agent, p, warns } = await platform();
    p.t.metadataExtra = { dpop_signing_alg_values_supported: ['EdDSA'] };
    const res = await agent.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(agent.dpop).toBeUndefined();
    expect(warns.some((w) => w.includes('proof-of-possession algorithm'))).toBe(true);
  });
});

describe('acting for a person is bound to the same key', () => {
  it('CIBA: the delegated token is bound to the key of the agent, and its calls carry the proof', async () => {
    const { agent, p } = await platform();
    const delegated = await agent.tokenAsUser({ loginHint: 'priya@acme.com', bindingMessage: 'Refund 4411' });
    await agent.token();
    expect(delegated.dpop?.thumbprint).toBe(agent.dpop!.thumbprint);
    const res = await delegated.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(p.t.fake.to(mcp(p)).at(-1)!.headers.get('authorization')).toMatch(/^DPoP /);
    const poll = p.t.fake.to(`${p.issuer}/oauth/token`).at(-1)!;
    expect(poll.headers.get('dpop')).toMatch(/^eyJ/);
  });

  it('token exchange: the delegated token is bound, and renews bound', async () => {
    const { agent, p, clock } = await platform();
    const delegated = await agent.exchange(await person(p, clock));
    const first = await delegated.token();
    await agent.token();
    expect(decodeJwt(first).cnf).toEqual({ jkt: agent.dpop!.thumbprint });
    clock.advance(p.tokenLifetime * 1000);
    const renewed = await delegated.token();
    expect(renewed).not.toBe(first);
    expect(delegated.dpop).toBeDefined();
    const res = await delegated.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
  });

  it('follows a renewal the platform leaves unbound: the next call is Bearer, not a proof for a token it does not bind', async () => {
    const { agent, p, clock } = await platform();
    const delegated = await agent.exchange(await person(p, clock));
    expect(delegated.dpop).toBeDefined();
    p.bind = false;
    clock.advance(p.tokenLifetime * 1000);
    await delegated.token();
    expect(delegated.dpop).toBeUndefined();
    const res = await delegated
      .gateway()
      .fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    expect(p.t.fake.to(`${p.issuer}/mcp`).at(-1)!.headers.get('authorization')).toMatch(/^Bearer /);
  });

  it('token exchange for a customer API stays Bearer', async () => {
    const { agent, p, clock } = await platform();
    const delegated = await agent.exchange(await person(p, clock), {
      resource: 'api_orders',
      sendTo: ['https://orders.example.com'],
    });
    expect(delegated.dpop).toBeUndefined();
    expect((await delegated.headers('GET', 'https://orders.example.com/x')).authorization).toMatch(
      /^Bearer /,
    );
  });
});

describe('the action gate and approvals carry the proof', () => {
  it('sends the transaction token request as DPoP', async () => {
    const { agent, p, fake } = await platform();
    fake.on('POST', `${p.issuer}/apis/regional/v1/ai/auth/transaction-token`, async (r) => {
      const seen = r.headers.get('authorization') ?? '';
      expect(seen).toMatch(/^DPoP /);
      expect(r.headers.get('dpop')).toMatch(/^eyJ/);
      return new Response(
        JSON.stringify({ data: { transaction_token: 't', txn: 'txn-1', expires_in: 60 } }),
        { headers: { 'content-type': 'application/json' } },
      );
    });
    const txn = await agent.transactionToken('refund');
    expect(txn.txn).toBe('txn-1');
  });
});
