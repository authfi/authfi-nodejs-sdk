import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { json } from '../support/fake-fetch.js';
import { AGENT_ID, CIBA, FakeAS } from '../support/fake-as.js';
import { TestClock } from '../support/issuer.js';

async function setup() {
  const key = await AgentKey.generate();
  const as = await FakeAS.create(key);
  const clock = new TestClock();
  clock.wall = Date.now();
  const warns: string[] = [];
  const af = new AuthFI({
    issuer: as.issuer,
    fetch: as.t.fake.fetch,
    clock,
    logger: { debug() {}, info() {}, warn: (m) => warns.push(m), error() {} },
  });
  const agent = af.agent({ agentId: AGENT_ID, key });
  return { key, as, clock, af, agent, warns, fake: as.t.fake };
}

describe("the agent's own token", () => {
  it('mints with a fresh assertion at <issuer>/oauth/token, caches, and renews before expiry', async () => {
    const { as, agent, clock, fake } = await setup();
    const [a, b] = await Promise.all([agent.token(), agent.token()]);
    expect(a).toBe(b);
    expect(as.minted).toBe(1);
    expect(fake.requests.some((r) => r.url.includes('/ai/auth/token'))).toBe(false);
    clock.advance(830_000);
    expect(await agent.token()).toBe(a);
    clock.advance(20_000);
    expect(await agent.token()).not.toBe(a);
    expect(as.minted).toBe(2);
    expect(new Set(as.assertions.map((x) => x.jti)).size).toBe(2);
  });

  it('signs a new assertion on a retried mint', async () => {
    const { as, agent, fake } = await setup();
    let n = 0;
    const original = as;
    fake.on('POST', `${as.issuer}/oauth/token`, async (r) => {
      n += 1;
      if (n === 1) throw new TypeError('fetch failed');
      const form = new URLSearchParams(r.body);
      expect(await original.checkAssertion(form)).toBeUndefined();
      return json({ access_token: await original.agentToken(), expires_in: 60 });
    });
    await agent.token();
    const assertions = fake
      .to(`${as.issuer}/oauth/token`)
      .map((r) => new URLSearchParams(r.body).get('client_assertion'));
    expect(assertions).toHaveLength(2);
    expect(assertions[0]).not.toBe(assertions[1]);
  });

  it('lists its capabilities, and mints per resource', async () => {
    const { agent, as } = await setup();
    expect([...(await agent.capabilities())]).toEqual(['mcp:docs.read', 'mcp:docs.write']);
    const forApi = agent.forResource('api_orders', { sendTo: ['https://api.example.com'] });
    await forApi.token();
    expect(as.minted).toBe(2);
    await expect(forApi.headers('GET', 'https://evil.example.com')).rejects.toThrow('refusing to send');
    expect(await forApi.headers('GET', 'https://api.example.com/x')).toHaveProperty('authorization');
    expect((forApi as { toString(): string }).toString()).toBe(`AgentAuth(${AGENT_ID} for api_orders)`);
  });

  it('sends its own token only to AuthFI', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/mcp`, (r) => json({ auth: r.headers.get('authorization')?.slice(0, 10) }));
    expect(await (await agent.fetch(`${as.issuer}/mcp`, { method: 'POST', body: '{}' })).json()).toEqual({
      auth: 'Bearer eyJ',
    });
    await expect(agent.fetch('https://api.example.com/')).rejects.toThrow('refusing to send');
    expect(agent.sendTo).toEqual([as.issuer]);
  });

  it('refuses a customer resource without sendTo, and a bad key', async () => {
    const { af, agent, key } = await setup();
    expect(() => agent.forResource('api_orders')).toThrow('sendTo is required');
    expect(() => agent.forResource('')).toThrow('resource is required');
    expect(() => af.agent({ agentId: AGENT_ID, key, resource: 'api_orders' })).toThrow('forResource');
    expect(() => af.agent({ agentId: '', key })).toThrow('agentId');
    expect(() => af.agent({ agentId: AGENT_ID, key: 's3cret' as unknown as AgentKey })).toThrow(
      'never a secret',
    );
    expect(() => af.agent({ agentId: AGENT_ID, key, refreshSkewMs: -1 })).toThrow('refreshSkewMs');
    expect(af.agent({ agentId: AGENT_ID, key, resource: `${af.issuer}/mcp` }).agentId).toBe(AGENT_ID);
  });

  it('reports a project that does not accept its key', async () => {
    const { as, agent } = await setup();
    as.t.metadataExtra = { token_endpoint_auth_signing_alg_values_supported: ['ES256'] };
    await expect(agent.token()).rejects.toMatchObject({ name: 'NotSupportedError', feature: 'EdDSA' });
    as.t.metadataExtra = { token_endpoint_auth_methods_supported: ['client_secret_basic'] };
    const fresh = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch }).agent({
      agentId: AGENT_ID,
      key: as.key,
    });
    await expect(fresh.token()).rejects.toMatchObject({ feature: 'private_key_jwt' });
  });

  it('prints its id and key id, never a token', async () => {
    const { agent } = await setup();
    const token = await agent.token();
    for (const text of [
      inspect(agent, { showHidden: true }),
      String(agent),
      JSON.stringify(agent),
      JSON.stringify(Object.entries(agent)),
    ]) {
      expect(text).not.toContain(token.split('.')[2]);
    }
  });
});

describe('CIBA', () => {
  it('asks the person with a binding message, polls after the interval, honours slow_down, and returns the delegated token', async () => {
    const { agent, as, clock, fake } = await setup();
    as.ciba.answers = ['pending', 'slow_down', 'approve'];
    const request = await agent.requestUserToken({
      loginHint: 'ada@example.com',
      bindingMessage: 'Refund order 4411',
      scope: ['mcp:refunds.create'],
      expiresInSeconds: 120,
    });
    const form = new URLSearchParams(fake.to(`${as.issuer}${CIBA}`)[0]!.body);
    expect([
      form.get('login_hint'),
      form.get('binding_message'),
      form.get('scope'),
      form.get('requested_expiry'),
    ]).toEqual(['ada@example.com', 'Refund order 4411', 'mcp:refunds.create', '120']);
    expect(String(request.authReqId)).toBe('Secret(***)');
    const token = await agent.awaitUserToken(request);
    expect(clock.sleeps).toEqual([2000, 2000, 7000]);
    expect(token.via).toBe('ciba');
    expect(token.subject?.toString()).toBe('user:usr_9');
    expect(token.actor?.toString()).toBe(`agent:${AGENT_ID}`);
    expect([...token.scopes]).toEqual(['mcp:refunds.create']);
    expect(JSON.stringify(token)).not.toContain('eyJ');
    expect(inspect(token)).toBe(`DelegatedToken(user:usr_9 by agent:${AGENT_ID} via ciba)`);
  });

  it('a refusal is ConsentDenied, a lapsed request ConsentExpired', async () => {
    const { agent, as } = await setup();
    as.ciba.answers = ['deny'];
    await expect(agent.tokenAsUser({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      name: 'ConsentDenied',
    });
    as.ciba = { answers: ['expire'], redeemed: false };
    await expect(agent.tokenAsUser({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      name: 'ConsentExpired',
    });
    as.ciba = { answers: [], redeemed: true };
    await expect(agent.tokenAsUser({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      name: 'OAuthError',
      code: 'invalid_grant',
    });
  });

  it('stops at its deadline and when cancelled', async () => {
    const { agent, as } = await setup();
    as.ciba.answers = Array(100).fill('pending');
    await expect(
      agent.tokenAsUser({ loginHint: 'a', bindingMessage: 'b', timeoutMs: 9000 }),
    ).rejects.toMatchObject({ code: 'authorization_pending' });
    const controller = new AbortController();
    controller.abort(new Error('caller stopped'));
    const request = await agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' });
    await expect(agent.awaitUserToken(request, { signal: controller.signal })).rejects.toThrow(
      'caller stopped',
    );
  });

  it('requires a binding message and a login hint, sends the request once, and refuses a project without CIBA', async () => {
    const { agent, as, fake } = await setup();
    await expect(agent.requestUserToken({ loginHint: 'a', bindingMessage: ' ' })).rejects.toThrow(
      'bindingMessage is required',
    );
    await expect(agent.requestUserToken({ loginHint: '', bindingMessage: 'b' })).rejects.toThrow(
      'loginHint is required',
    );
    fake.on('POST', `${as.issuer}${CIBA}`, () => {
      throw new TypeError('fetch failed');
    });
    await expect(agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      code: 'network_error',
    });
    expect(fake.to(`${as.issuer}${CIBA}`)).toHaveLength(1);
    as.t.metadataExtra = { grant_types_supported: ['client_credentials'] };
    const fresh = new AuthFI({ issuer: as.issuer, fetch: fake.fetch }).agent({
      agentId: AGENT_ID,
      key: as.key,
    });
    await expect(fresh.requestUserToken({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      name: 'NotSupportedError',
      feature: 'ciba',
    });
  });

  it('a CIBA token never renews: it ends in ConsentExpired', async () => {
    const { agent, clock } = await setup();
    const token = await agent.tokenAsUser({ loginHint: 'a', bindingMessage: 'b' });
    await token.token();
    clock.advance(850_000);
    await expect(token.token()).rejects.toMatchObject({ name: 'ConsentExpired' });
  });
});

describe('token exchange', () => {
  it('sends no client authentication, the agent as actor, and renews by exchanging again', async () => {
    const { agent, as, clock, fake } = await setup();
    const personToken = await as.t.sign({ sub: 'usr_9', exp: Math.floor(clock.now() / 1000) + 3600 });
    const delegated = await agent.exchange(new Secret(personToken), { scope: ['mcp:docs.read'] });
    const form = new URLSearchParams(fake.to(`${as.issuer}/oauth/token`).at(-1)!.body);
    expect(form.has('client_id')).toBe(false);
    expect(form.has('client_assertion')).toBe(false);
    expect(form.get('subject_token')).toBe(personToken);
    expect(form.get('actor_token')?.startsWith('eyJ')).toBe(true);
    expect([delegated.via, delegated.subject?.toString(), delegated.actor?.toString()]).toEqual([
      'exchange',
      'user:usr_9',
      `agent:${AGENT_ID}`,
    ]);
    const first = await delegated.token();
    clock.advance(850_000);
    const second = await delegated.token();
    expect(second).not.toBe(first);
    expect(fake.to(`${as.issuer}/oauth/token`).filter((r) => r.body.includes('token-exchange'))).toHaveLength(
      2,
    );
  });

  it('stops renewing once the person token has expired', async () => {
    const { agent, as, clock } = await setup();
    const personToken = await as.t.sign({ sub: 'usr_9', exp: Math.floor(clock.now() / 1000) + 600 });
    const delegated = await agent.exchange(new Secret(personToken));
    clock.advance(860_000);
    await expect(delegated.token()).rejects.toMatchObject({ name: 'ConsentExpired' });
  });

  it('takes a TokenSource for the person, and refuses a raw string', async () => {
    const { agent, as, fake } = await setup();
    const person = {
      sendTo: [],
      token: async () => as.t.sign({ sub: 'usr_9' }),
      headers: async () => ({}),
      fetch,
    };
    const delegated = await agent.exchange(person, {
      resource: 'api_orders',
      sendTo: ['https://api.example.com'],
    });
    expect(delegated.sendTo).toEqual(['https://api.example.com']);
    expect(new URLSearchParams(fake.to(`${as.issuer}/oauth/token`).at(-1)!.body).get('resource')).toBe(
      'api_orders',
    );
    await expect(agent.exchange('raw' as unknown as Secret)).rejects.toThrow('TokenSource or a Secret');
    await expect(agent.exchange(new Secret('x'), { resource: 'api_orders' })).rejects.toThrow(
      'sendTo is required',
    );
  });

  it('a refused exchange keeps its code', async () => {
    const { agent, as } = await setup();
    as.exchangeAllowed = false;
    await expect(agent.exchange(new Secret(await as.t.sign()))).rejects.toMatchObject({
      name: 'OAuthError',
      code: 'access_denied',
    });
  });
});

describe('the action gate', () => {
  it('freezes an action and asks the gate about it', async () => {
    const { agent } = await setup();
    const txn = await agent.transactionToken('refund.small', {
      resource: 'order:4411',
      context: { amount: 12 },
    });
    expect([txn.txn, txn.action, String(txn.token)]).toEqual(['txn-1', 'refund.small', 'Secret(***)']);
    expect(await agent.authorizeAction(txn)).toEqual({
      decision: 'allow',
      approvalId: undefined,
      reason: undefined,
    });
    const large = await agent.transactionToken('refund.large');
    expect(await agent.authorizeAction(large)).toEqual({
      decision: 'approval_required',
      approvalId: 'apr-9',
      reason: undefined,
    });
    await expect(agent.transactionToken('')).rejects.toThrow('action is required');
  });

  it('maps refusals and malformed answers', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/transaction-token`, () =>
      json({ error: 'constraint_violation' }, 403),
    );
    await expect(agent.transactionToken('x')).rejects.toMatchObject({
      name: 'APIError',
      code: 'constraint_violation',
    });
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/authorize`, () =>
      json({ data: { decision: 'maybe' } }),
    );
    await expect(
      agent.authorizeAction({
        token: new Secret('t'),
        txn: 'x',
        action: 'a',
        resource: undefined,
        context: undefined,
        expiresAt: new Date(),
      }),
    ).rejects.toMatchObject({
      code: 'response_invalid',
    });
  });
});

describe('approvals', () => {
  it('opens an approval with a signed assertion, once', async () => {
    const { agent, as, fake } = await setup();
    const approval = await agent.requestApproval('refund', {
      context: { order: '4411' },
      expiresInSeconds: 120,
    });
    expect(approval).toMatchObject({
      id: 'apr-1',
      status: 'pending',
      action: 'refund',
      context: { order: '4411' },
    });
    const body = JSON.parse(
      fake.to(`${as.issuer}/apis/regional/v1/ai/auth/request-approval`)[0]!.body,
    ) as Record<string, unknown>;
    expect(body).toMatchObject({ agent_id: AGENT_ID, requesting_action: 'refund', timeout_seconds: 120 });
  });

  it("maps the platform's 403 on approval status to NotSupportedError, and never polls it", async () => {
    const { agent, as } = await setup();
    await expect(agent.approval('apr-1')).rejects.toMatchObject({
      name: 'NotSupportedError',
      feature: 'agent_approval_status',
    });
    await expect(agent.waitForApproval('apr-1')).rejects.toMatchObject({ feature: 'agent_approval_status' });
    expect(as.approvalPolls).toBe(2);
  });

  it('waits for the decision once the project opens approval status to agents', async () => {
    const { agent, as, clock } = await setup();
    as.approvalStatus = 'approved';
    const done = await agent.waitForApproval('apr-1', { intervalMs: 1000 });
    expect(done.status).toBe('approved');
    expect(clock.sleeps).toContain(1000);
    as.approvalStatus = 'pending';
    expect((await agent.waitForApproval('apr-1', { timeoutMs: 2500, intervalMs: 1000 })).status).toBe(
      'pending',
    );
  });

  it('refuses an agent-configuration that points elsewhere', async () => {
    const { agent, as, fake } = await setup();
    fake.on('GET', `${as.issuer}/.well-known/agent-configuration`, () =>
      json({
        issuer: as.issuer,
        endpoints: { request_approval: 'https://evil.example/ra', approval: `${as.issuer}/a/{id}` },
      }),
    );
    await expect(agent.requestApproval('x')).rejects.toMatchObject({ name: 'DiscoveryError' });
    await expect(agent.requestApproval('')).rejects.toThrow('action is required');
  });
});
