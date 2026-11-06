import { readFileSync } from 'node:fs';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, HOLD_PATTERN } from '../../src/gateway/gateway.js';
import { json } from '../support/fake-fetch.js';
import { AGENT_ID, FakeAS } from '../support/fake-as.js';

async function setup() {
  const key = await AgentKey.generate();
  const as = await FakeAS.create(key);
  const af = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch, retries: 0 });
  const agent = af.agent({ agentId: AGENT_ID, key });
  return { as, af, agent, gateway: agent.gateway(), fake: as.t.fake };
}

const text = (t: string, extra: Record<string, unknown> = {}) => ({
  content: [{ type: 'text', text: t }],
  isError: true,
  ...extra,
});

describe('reading a tool result', () => {
  it("reads the gateway's exact hold message, held verbatim in the shared fixture", async () => {
    const { gateway } = await setup();
    const fixture = JSON.parse(
      readFileSync(new URL('../support/hold-result.json', import.meta.url), 'utf8'),
    ) as { content: { text: string }[] };
    const hold = fixture.content[0]!.text;
    const id = '7f1c2a9e-5d1b-4f3a-9a77-2b0c8e1d4f00';
    expect(gateway.readResult(text(hold))).toEqual({
      kind: 'approval_required',
      approvalId: id,
      code: 'approval_required',
    });
    expect(gateway.readResult(text(hold.replace('approval_required', 'approval_pending')))).toMatchObject({
      code: 'approval_pending',
    });
  });

  it('uses the hold pattern and message every AuthFI SDK uses', () => {
    // The same two strings are asserted in the Python SDK's tests; change them together.
    expect(HOLD_PATTERN).toBe(
      String.raw`^Waiting for approval ([A-Za-z0-9_-]+) \(([a-z_]+)\)\. A person must approve this action`,
    );
    expect(HOLD_MESSAGE).toBe("This action is waiting for a person's approval in AuthFI.");
  });

  it("reads text that is not the whole hold as the tool's own answer", async () => {
    const { gateway } = await setup();
    for (const t of [
      'Waiting for approval 7f1c2a9e (approval_required).',
      'Waiting for approval a.b (approval_required). A person must approve this action in the AuthFI console.',
      'Note: Waiting for approval x (approval_required). A person must approve this action',
    ]) {
      expect(gateway.readResult(text(t)).kind).toBe('allowed');
    }
  });

  it('reads a refusal from _meta, as the gateway answers it', async () => {
    const { gateway } = await setup();
    const refused = gateway.readResult(
      text(
        'Refused (insufficient_scope, ETOOL003): no grant (approval x). The call needs the scope mcp:a.b.',
        {
          _meta: {
            'io.authfi/refusal': {
              reason: 'no grant',
              code: 'ETOOL003',
              error: 'insufficient_scope',
              required_scope: 'mcp:a.b',
            },
          },
        },
      ),
    );
    expect(refused).toMatchObject({
      kind: 'refused',
      reason: 'no grant',
      code: 'ETOOL003',
      error: 'insufficient_scope',
      requiredScope: 'mcp:a.b',
    });
    const bare = gateway.readResult(text('Refused: x', { _meta: { 'io.authfi/refusal': {} } }));
    expect(bare).toMatchObject({ kind: 'refused', reason: 'Refused: x', code: undefined });
  });

  it("leaves a tool's own error and a plain result as the tool's answer", async () => {
    const { gateway } = await setup();
    expect(gateway.readResult(text('upstream: repository not found')).kind).toBe('allowed');
    expect(gateway.readResult({ content: [{ type: 'text', text: 'ok' }] }).kind).toBe('allowed');
    expect(gateway.readResult({ isError: true, content: [{ type: 'image' }] }).kind).toBe('allowed');
    expect(() => gateway.readResult('nope')).toThrow('not an object');
  });

  it('names the grant object, the model routes and the argument', async () => {
    const { gateway, as } = await setup();
    expect(gateway.scopeOf({ _meta: { 'io.authfi/scope': 'mcp:a.b' } })).toBe('mcp:a.b');
    expect(gateway.scopeOf({})).toBeUndefined();
    // the outlook is read from _meta first (a client may drop annotations), then the annotation
    const key = 'io.authfi/governance';
    expect(gateway.governanceOf({ _meta: { [key]: 'never_allowed' } })).toBe('never_allowed');
    expect(gateway.governanceOf({ annotations: { [key]: 'may_require_approval' } })).toBe(
      'may_require_approval',
    );
    expect(
      gateway.governanceOf({
        _meta: { [key]: 'never_allowed' },
        annotations: { [key]: 'no_policy_restriction' },
      }),
    ).toBe('never_allowed');
    expect(gateway.governanceOf({})).toBeUndefined();
    expect(gateway.modelBaseUrl('anthropic')).toBe(`${as.issuer}/llm`);
    expect(gateway.modelBaseUrl('openai')).toBe(`${as.issuer}/llm/v1`);
    expect(gateway.mcpUrl).toBe(`${as.issuer}/mcp`);
    expect(gateway.llmUrl).toBe(`${as.issuer}/llm`);
    expect(APPROVAL_ARGUMENT).toBe('_authfi_approval_id');
    expect(String(gateway)).toBe(`Gateway(${as.issuer}/mcp as ${AGENT_ID})`);
  });
});

describe('the gateway fetch', () => {
  it('sends the credential and a request id to AuthFI only, and turns a 401 into GatewayTokenRefused', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/mcp`, (r) =>
      json({
        auth: r.headers.get('authorization')?.slice(0, 10),
        id: r.headers.get('x-request-id'),
        key: r.headers.get('x-api-key'),
      }),
    );
    const res = await gateway.fetch(`${as.issuer}/mcp`, {
      method: 'POST',
      body: '{}',
      headers: { 'x-api-key': 'leak' },
    });
    expect(await res.json()).toMatchObject({ auth: 'Bearer eyJ', key: null });
    await expect(gateway.fetch('https://api.anthropic.com/v1/messages', { method: 'POST' })).rejects.toThrow(
      'refusing to send',
    );
    fake.on('POST', `${as.issuer}/mcp`, () =>
      json({ error: 'invalid_token' }, 401, { 'x-request-id': 'srv-1' }),
    );
    await expect(gateway.fetch(`${as.issuer}/mcp`, { method: 'POST', body: '{}' })).rejects.toMatchObject({
      name: 'GatewayTokenRefused',
      requestId: 'srv-1',
    });
  });

  it('a delegated token has its own gateway, as the actor', async () => {
    const { agent, as } = await setup();
    const delegated = await agent.exchange(new Secret(await as.t.sign()));
    expect(delegated.gateway().agentId).toBe(AGENT_ID);
    expect(delegated.gateway()).toBe(delegated.gateway());
    expect(agent.gateway()).toBe(agent.gateway());
  });
});

describe('cloud credentials', () => {
  const mcp = (issuer: string) => `${issuer}/mcp`;
  const redeem = (issuer: string, id: string) => `${issuer}/mcp/cloud/credentials/${id}/secret`;
  const rpc = (result: unknown) => json({ jsonrpc: '2.0', id: 1, result });
  const handle = (id: string, extra: Record<string, unknown> = {}) => {
    const h = {
      credential_id: id,
      account: 'acct',
      role: 'reader',
      expires_at: '2026-10-20T12:00:00Z',
      ...extra,
    };
    return rpc({
      content: [{ type: 'text', text: JSON.stringify(h) }],
      structuredContent: h,
      isError: false,
    });
  };

  it('issues a handle by tools/call of cloud.credentials on /mcp, and redeems the secret once at the /mcp path', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', mcp(as.issuer), (r) => {
      expect(JSON.parse(r.body)).toEqual({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'cloud.credentials',
          arguments: { account: 'acct', role: 'reader', duration_seconds: 600 },
        },
      });
      expect(r.headers.get('authorization')?.startsWith('Bearer ')).toBe(true);
      return handle('c1', { scope: 'cloud.credentials' });
    });
    fake.on('POST', redeem(as.issuer, 'c1'), () =>
      json(
        {
          data: {
            provider: 'aws',
            credential_id: 'c1',
            access_key_id: 'AKIA',
            secret_access_key: 'sk',
            session_token: 'st',
            expiration: '2026-10-20T12:00:00Z',
          },
        },
        200,
      ),
    );
    const out = await gateway.cloudCredentials({ account: 'acct', role: 'reader', expiresInSeconds: 600 });
    expect(out.kind).toBe('issued');
    if (out.kind !== 'issued') return;
    expect(out.handle).toEqual({
      credentialId: 'c1',
      account: 'acct',
      role: 'reader',
      expiresAt: new Date('2026-10-20T12:00:00Z'),
      scope: 'cloud.credentials',
    });
    expect(JSON.stringify(out)).not.toContain('sk');
    const credential = await gateway.cloud.secret(out.handle);
    expect(credential).toMatchObject({ provider: 'aws', credentialId: 'c1', accessKeyId: 'AKIA' });
    expect(credential.secretAccessKey?.reveal()).toBe('sk');
    expect(JSON.stringify(credential)).not.toContain('"sk"');
    expect(credential.expiresAt?.toISOString()).toBe('2026-10-20T12:00:00.000Z');
    expect(fake.to(redeem(as.issuer, 'c1'))).toHaveLength(1);
    // the removed HTTP door is never called
    expect(fake.requests.filter((r) => r.url.includes('/mcp/v1/'))).toEqual([]);
  });

  it('reads the handle from the result text when the gateway sends no structuredContent', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', mcp(as.issuer), () =>
      rpc({ content: [{ type: 'text', text: JSON.stringify({ credential_id: 'c5' }) }] }),
    );
    const out = await gateway.cloudCredentials({ account: 'a', role: 'r' });
    expect(out.kind === 'issued' && out.handle.credentialId).toBe('c5');
  });

  it('answers approval_required from the hold result, and passes the approval id as the tool argument on the retry', async () => {
    const { gateway, as, fake } = await setup();
    const held = JSON.parse(
      readFileSync(new URL('../support/hold-result.json', import.meta.url), 'utf8'),
    ) as { content: { text: string }[] };
    const holdId = '7f1c2a9e-5d1b-4f3a-9a77-2b0c8e1d4f00';
    fake.on('POST', mcp(as.issuer), (r) =>
      (JSON.parse(r.body).params.arguments as Record<string, unknown>)[APPROVAL_ARGUMENT] === holdId
        ? handle('c2', { role: 'admin' })
        : rpc(held),
    );
    fake.on('POST', redeem(as.issuer, 'c2'), () =>
      json({ data: { provider: 'gcp', credential_id: 'c2', access_token: 'gat', expires_in: 900 } }),
    );
    expect(await gateway.cloudCredentials({ account: 'a', role: 'admin' })).toEqual({
      kind: 'approval_required',
      approvalId: holdId,
    });
    const out = await gateway.cloudCredentials({ account: 'a', role: 'admin', approvalId: holdId });
    expect(out.kind === 'issued' && out.handle.credentialId).toBe('c2');
    const both = await gateway.cloud.fetchCredential({ account: 'a', role: 'admin', approvalId: holdId });
    expect(both.kind === 'issued' && both.credential.accessToken?.reveal()).toBe('gat');
    expect(both.kind === 'issued' && both.credential.expiresAt).toBeInstanceOf(Date);
  });

  it('is a refusal (APIError with the ECLOUDCRED code) when the tool result carries one', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', mcp(as.issuer), () =>
      rpc({
        isError: true,
        content: [{ type: 'text', text: 'Refused (ECLOUDCRED003): not granted.' }],
        _meta: { 'io.authfi/refusal': { code: 'ECLOUDCRED003', reason: 'the role is not granted' } },
      }),
    );
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      name: 'APIError',
      code: 'ECLOUDCRED003',
    });
  });

  it('refuses a duration the platform would refuse, naming its 900 s limit, before sending anything', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', mcp(as.issuer), () => handle('c1'));
    for (const bad of [901, 43_200, 0, -5, 1.5, Number.NaN]) {
      await expect(
        gateway.cloudCredentials({ account: 'a', role: 'r', expiresInSeconds: bad }),
      ).rejects.toThrow(/expiresInSeconds.*1 to 900/);
    }
    expect(fake.to(mcp(as.issuer))).toHaveLength(0);
    const ok = await gateway.cloudCredentials({ account: 'a', role: 'r', expiresInSeconds: 900 });
    expect(ok.kind).toBe('issued');
  });

  it('sends the issue call once: a gateway failure after it was sent is not retried', async () => {
    const key = await AgentKey.generate();
    const as = await FakeAS.create(key);
    const af = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch, retries: 3 });
    const gateway = af.agent({ agentId: AGENT_ID, key }).gateway();
    as.t.fake.on('POST', mcp(as.issuer), () => json({ error: 'server_error' }, 503));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toBeInstanceOf(Error);
    expect(as.t.fake.to(mcp(as.issuer))).toHaveLength(1);
  });

  it('maps failures: the token refused, a JSON-RPC error, and malformed answers', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', mcp(as.issuer), () => json({ error: 'unauthorized' }, 401));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      name: 'GatewayTokenRefused',
    });
    fake.on('POST', mcp(as.issuer), () =>
      json({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'tool call failed' } }),
    );
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      name: 'APIError',
      code: 'jsonrpc_-32000',
    });
    fake.on('POST', mcp(as.issuer), () => json({ jsonrpc: '2.0', id: 1 }));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    fake.on('POST', mcp(as.issuer), () => rpc({ content: [{ type: 'text', text: 'not a handle' }] }));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    fake.on('POST', mcp(as.issuer), () => rpc({ content: [{ type: 'text', text: '42' }] }));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    fake.on('POST', mcp(as.issuer), () => json({ jsonrpc: '2.0', id: 1, error: { code: -32603 } }));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'jsonrpc_-32603',
    });
    fake.on('POST', mcp(as.issuer), () =>
      rpc({ isError: true, content: [], _meta: { 'io.authfi/refusal': { reason: 'no' } } }),
    );
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'refused',
    });
    await expect(gateway.cloudCredentials({ account: '', role: 'r' })).rejects.toThrow('account and role');
    fake.on('POST', mcp(as.issuer), () => rpc({ structuredContent: { credential_id: 'c9' } }));
    const bare = await gateway.cloudCredentials({ account: 'a', role: 'r' });
    expect(bare.kind === 'issued' && bare.handle.expiresAt).toBeUndefined();
  });
});

describe('the two doors', () => {
  const aud = (authorization: string | null): unknown => decodeJwt((authorization ?? '').slice(7)).aud;

  it('asks for a second token with resource <issuer>/llm for a model call, and sends each door only its own', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/mcp`, () => json({ jsonrpc: '2.0', id: 1, result: {} }));
    fake.on('POST', `${as.issuer}/llm/v1/messages`, () => json({ type: 'message' }));
    for (let i = 0; i < 2; i++) {
      await gateway.fetch(`${as.issuer}/mcp`, { method: 'POST', body: '{}' });
      await gateway.fetch(`${as.issuer}/llm/v1/messages`, { method: 'POST', body: '{}' });
    }
    const mints = fake.to(`${as.issuer}/oauth/token`).map((r) => new URLSearchParams(r.body));
    // one token per door, each minted once and cached apart
    expect(mints.map((f) => f.get('resource'))).toEqual([null, `${as.issuer}/llm`]);
    const toMcp = fake.to(`${as.issuer}/mcp`).map((r) => aud(r.headers.get('authorization')));
    const toLlm = fake.to(`${as.issuer}/llm/v1/messages`).map((r) => aud(r.headers.get('authorization')));
    expect(toMcp).toEqual([`${as.issuer}/mcp`, `${as.issuer}/mcp`]);
    expect(toLlm).toEqual([`${as.issuer}/llm`, `${as.issuer}/llm`]);
  });

  it('sends the llm token on every model route and the mcp token on the cloud call', async () => {
    const { gateway, as, fake } = await setup();
    const routes = ['messages', 'chat/completions', 'responses'];
    for (const route of routes) fake.on('POST', `${as.issuer}/llm/v1/${route}`, () => json({}));
    fake.on('POST', `${as.issuer}/mcp`, () =>
      json({ jsonrpc: '2.0', id: 1, result: { structuredContent: { credential_id: 'c1' } } }),
    );
    for (const route of routes)
      await gateway.fetch(`${gateway.llmUrl}/v1/${route}`, { method: 'POST', body: '{}' });
    await gateway.cloudCredentials({ account: 'a', role: 'r' });
    for (const route of routes)
      expect(aud(fake.to(`${as.issuer}/llm/v1/${route}`)[0]!.headers.get('authorization'))).toBe(
        `${as.issuer}/llm`,
      );
    expect(aud(fake.to(`${as.issuer}/mcp`)[0]!.headers.get('authorization'))).toBe(`${as.issuer}/mcp`);
  });

  it('keeps the llm token on a gateway made for a run, with the run id on its calls', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', `${as.issuer}/llm/v1/responses`, () => json({}));
    const run = gateway.forRun('run-xyz');
    await run.fetch(`${run.llmUrl}/v1/responses`, { method: 'POST', body: '{}' });
    const sent = fake.to(`${as.issuer}/llm/v1/responses`)[0]!;
    expect(aud(sent.headers.get('authorization'))).toBe(`${as.issuer}/llm`);
    expect(sent.headers.get('x-request-id')).toBe('run-xyz.1');
  });

  it('refuses a model call before sending it when the credential has no token for the llm door', async () => {
    const { agent, as, fake } = await setup();
    const delegated = await agent.exchange(new Secret(await as.t.sign()));
    fake.on('POST', `${as.issuer}/llm/v1/messages`, () => json({}));
    await expect(
      delegated.gateway().fetch(`${as.issuer}/llm/v1/messages`, { method: 'POST', body: '{}' }),
    ).rejects.toThrow(/LLM door/);
    expect(fake.to(`${as.issuer}/llm/v1/messages`)).toHaveLength(0);
    // given its own token for the door, the call goes with that token
    const llm = await agent.exchange(new Secret(await as.t.sign()), { resource: `${as.issuer}/llm` });
    const res = await delegated
      .gateway()
      .withLlmSource(llm)
      .fetch(`${as.issuer}/llm/v1/messages`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(200);
    expect(aud(fake.to(`${as.issuer}/llm/v1/messages`)[0]!.headers.get('authorization'))).toEqual([
      `${as.issuer}/llm`,
    ]);
  });

  it("keeps AuthFI's credential for AuthFI's doors: a customer API gets no token and none is minted", async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', 'https://api.customer.example/llm/v1/messages', () => json({}));
    await expect(
      gateway.fetch('https://api.customer.example/llm/v1/messages', { method: 'POST', body: '{}' }),
    ).rejects.toThrow('refusing to send');
    expect(fake.to('https://api.customer.example/llm/v1/messages')).toHaveLength(0);
    expect(fake.to(`${as.issuer}/oauth/token`)).toHaveLength(0);
  });
});

describe('a run on the gateway', () => {
  it('prefixes each call with the run id and exposes the run the gateway derived', async () => {
    const { as, agent, fake } = await setup();
    as.t.fake.on('POST', `${as.issuer}/mcp`, () =>
      json({ jsonrpc: '2.0', id: 1, result: {} }, 200, { 'AuthFI-Run-Id': 'run_derived' }),
    );
    const run = agent.gateway().forRun('run-abc');
    expect(run.runId).toBe('run-abc');
    expect(run.agentId).toBe(agent.agentId);
    expect(run.serverRunId).toBeUndefined();
    await run.fetch(run.mcpUrl, { method: 'POST', body: '{}' });
    await run.fetch(run.mcpUrl, { method: 'POST', body: '{}' });
    const ids = fake.to(`${as.issuer}/mcp`).map((r) => r.headers.get('x-request-id'));
    expect(ids).toEqual(['run-abc.1', 'run-abc.2']);
    expect(run.serverRunId).toBe('run_derived');
    expect(run.otlpTracesUrl).toBe(`${as.issuer}/otlp/v1/traces`);
    // A caller's valid request id is kept; the agent gateway itself is not bound to a run.
    await run.fetch(run.mcpUrl, { method: 'POST', body: '{}', headers: { 'x-request-id': 'mine-1' } });
    expect(fake.to(`${as.issuer}/mcp`).at(-1)!.headers.get('x-request-id')).toBe('mine-1');
    expect(agent.gateway().runId).toBeUndefined();
  });

  it('makes a run id when none is given, refuses one the platform would drop, and labels an agent', async () => {
    const { agent, fake, as } = await setup();
    as.t.fake.on('POST', `${as.issuer}/mcp`, () =>
      json({ error: 'invalid_token' }, 401, { 'AuthFI-Run-Id': 'run_x' }),
    );
    const run = agent.gateway().forRun();
    expect(run.runId).toMatch(/^run-[0-9a-f]{24}$/);
    expect(() => agent.gateway().forRun('bad id')).toThrow('runId');
    expect(() => agent.gateway().forRun('x'.repeat(97))).toThrow('runId');
    await expect(run.fetch(run.mcpUrl, { method: 'POST', body: '{}' })).rejects.toBeInstanceOf(Error);
    // A refusal carries the run too.
    expect(run.serverRunId).toBe('run_x');
    expect(fake.to(`${as.issuer}/mcp`)[0]!.headers.get('user-agent')).toMatch(/\(agent\)$/);
  });

  it("keeps a caller's own User-Agent", async () => {
    const { as, agent, fake } = await setup();
    as.t.fake.on('POST', `${as.issuer}/mcp`, () => json({ jsonrpc: '2.0', id: 1, result: {} }));
    const g = agent.gateway();
    await g.fetch(g.mcpUrl, { method: 'POST', body: '{}', headers: { 'user-agent': 'my-agent/1' } });
    expect(fake.to(`${as.issuer}/mcp`)[0]!.headers.get('user-agent')).toBe('my-agent/1');
  });
});
