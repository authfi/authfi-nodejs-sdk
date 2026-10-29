// The agent module against malformed and refusing answers: every one becomes a typed error, never
// a value.

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
  const af = new AuthFI({
    issuer: as.issuer,
    fetch: as.t.fake.fetch,
    clock,
    retries: 0,
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  return { as, clock, agent: af.agent({ agentId: AGENT_ID, key }), fake: as.t.fake, af };
}

describe('malformed answers', () => {
  it('a CIBA answer without auth_req_id, a refused CIBA request, and defaults for interval and expiry', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}${CIBA}`, () => json({ expires_in: 60 }));
    await expect(agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    fake.on('POST', `${as.issuer}${CIBA}`, () => json({ error: 'unknown_user_id' }, 400));
    await expect(agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' })).rejects.toMatchObject({
      name: 'OAuthError',
      code: 'unknown_user_id',
    });
    fake.on('POST', `${as.issuer}${CIBA}`, () => json({ auth_req_id: 'req-1' }));
    const req = await agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' });
    expect(req.intervalMs).toBe(5000);
    as.t.metadataExtra = { backchannel_authentication_endpoint: undefined };
    const af2 = new AuthFI({ issuer: as.issuer, fetch: fake.fetch });
    await expect(
      af2.agent({ agentId: AGENT_ID, key: as.key }).requestUserToken({ loginHint: 'a', bindingMessage: 'b' }),
    ).rejects.toMatchObject({
      name: 'NotSupportedError',
    });
  });

  it('a transport failure while polling is not swallowed', async () => {
    const { agent, as, fake } = await setup();
    const req = await agent.requestUserToken({ loginHint: 'a', bindingMessage: 'b' });
    fake.on('POST', `${as.issuer}/oauth/token`, () => new Response('down', { status: 500 }));
    await expect(agent.awaitUserToken(req)).rejects.toMatchObject({ name: 'APIError', code: 'server_error' });
  });

  it('a transaction-token answer without a token', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/transaction-token`, () =>
      json({ data: { txn: 'x' } }),
    );
    await expect(agent.transactionToken('a')).rejects.toMatchObject({ code: 'response_invalid' });
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/transaction-token`, () =>
      json({ data: { transaction_token: 't', txn: 'x' } }),
    );
    const txn = await agent.transactionToken('a');
    expect(txn.expiresAt.getTime() - Date.now()).toBeGreaterThan(50_000);
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/authorize`, () =>
      json({ error: 'unauthorized' }, 401),
    );
    await expect(agent.authorizeAction(txn)).rejects.toMatchObject({ name: 'APIError', status: 401 });
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/authorize`, () =>
      json({ data: { decision: 'deny', reason: 'over limit' } }),
    );
    expect(await agent.authorizeAction(txn)).toEqual({
      decision: 'deny',
      approvalId: undefined,
      reason: 'over limit',
    });
  });

  it('approval answers: refused, not found, malformed', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/request-approval`, () =>
      json({ error: 'invalid_body' }, 400),
    );
    await expect(agent.requestApproval('a')).rejects.toMatchObject({
      name: 'APIError',
      code: 'invalid_body',
    });
    fake.on('POST', `${as.issuer}/apis/regional/v1/ai/auth/request-approval`, () =>
      json({ data: { status: 'pending' } }, 202),
    );
    await expect(agent.requestApproval('a')).rejects.toMatchObject({ code: 'response_invalid' });
    fake.on(
      'GET',
      (u) => u.includes('/approvals/'),
      () => json({ error: 'not_found' }, 404),
    );
    await expect(agent.approval('nope')).rejects.toMatchObject({ name: 'APIError', code: 'not_found' });
    fake.on(
      'GET',
      (u) => u.includes('/approvals/'),
      () => json({ data: { approval_id: 'a', status: 'denied' } }),
    );
    expect(await agent.approval('a')).toMatchObject({ status: 'denied', action: '', createdAt: undefined });
  });

  it('an agent-configuration that is missing or names another issuer', async () => {
    const { agent, as, fake } = await setup();
    fake.on('GET', `${as.issuer}/.well-known/agent-configuration`, () => json({}, 404));
    await expect(agent.requestApproval('a')).rejects.toMatchObject({ name: 'DiscoveryError', status: 404 });
    fake.on('GET', `${as.issuer}/.well-known/agent-configuration`, () =>
      json({ issuer: 'https://evil.authfi.io', endpoints: {} }),
    );
    await expect(agent.requestApproval('a')).rejects.toMatchObject({ code: 'issuer_mismatch' });
  });

  it('capabilities fall back to the scope when the answer lists none', async () => {
    const { agent, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/oauth/token`, async () =>
      json({ access_token: await as.agentToken(), expires_in: 60, scope: 'a b' }),
    );
    expect([...(await agent.capabilities())]).toEqual(['a', 'b']);
  });
});

describe('delegated tokens', () => {
  it('to AuthFI by default, renewed on force, and an opaque token has an unknown subject', async () => {
    const { agent, as, fake } = await setup();
    const delegated = await agent.exchange(new Secret(await as.t.sign()));
    expect(delegated.sendTo).toEqual([as.issuer]);
    expect(await delegated.headers('POST', `${as.issuer}/mcp`)).toHaveProperty('authorization');
    const first = await delegated.token();
    expect(await delegated.token({ force: true })).not.toBe(first);
    expect(delegated.expiresAt.getTime()).toBeGreaterThan(Date.now());
    fake.on('POST', `${as.issuer}/oauth/token`, () => json({ access_token: 'opaque', expires_in: 60 }));
    const opaque = await agent.exchange(new Secret(await as.t.sign()));
    expect(String(opaque)).toBe('DelegatedToken(unknown by unknown via exchange)');
    const sourceToken = { sendTo: [], token: async () => as.t.sign(), headers: async () => ({}), fetch };
    expect((await agent.exchange(sourceToken)).via).toBe('exchange');
  });
});
