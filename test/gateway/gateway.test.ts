import { describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { APPROVAL_ARGUMENT } from '../../src/gateway/gateway.js';
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
  it('reads the hold in the exact format of authfi-regional-mcp dispatch.go', async () => {
    const { gateway } = await setup();
    // Contract: the format string at internal/http/mcp/dispatch.go (mcp 3617565), rendered.
    const id = '611e6ce1-ca7e-4fab-8b76-0655a62d414b';
    const hold = `Waiting for approval ${id} (approval_required). A person must approve this action in the AuthFI console. Retry this call with an argument "_authfi_approval_id": "${id}" once it is approved.`;
    expect(gateway.readResult(text(hold))).toEqual({
      kind: 'approval_required',
      approvalId: id,
      code: 'approval_required',
    });
    expect(gateway.readResult(text(hold.replace('approval_required', 'approval_pending')))).toMatchObject({
      code: 'approval_pending',
    });
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
    expect(gateway.modelBaseUrl('anthropic')).toBe(`${as.issuer}/mcp`);
    expect(gateway.modelBaseUrl('openai')).toBe(`${as.issuer}/mcp/v1`);
    expect(gateway.mcpUrl).toBe(`${as.issuer}/mcp`);
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
  });
});

describe('cloud credentials', () => {
  const url = (issuer: string) => `${issuer}/mcp/v1/cloud/credentials`;

  it('issues a credential whose secrets are Secrets', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', url(as.issuer), (r) => {
      expect(JSON.parse(r.body)).toEqual({ account: 'acct', role: 'reader', duration_seconds: 600 });
      expect(r.headers.get('authorization')?.startsWith('Bearer ')).toBe(true);
      return json(
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
        201,
      );
    });
    const out = await gateway.cloudCredentials({ account: 'acct', role: 'reader', expiresInSeconds: 600 });
    expect(out.kind).toBe('issued');
    if (out.kind !== 'issued') return;
    expect(out.credential).toMatchObject({ provider: 'aws', credentialId: 'c1', accessKeyId: 'AKIA' });
    expect(out.credential.secretAccessKey?.reveal()).toBe('sk');
    expect(JSON.stringify(out)).not.toContain('"sk"');
    expect(out.credential.expiresAt?.toISOString()).toBe('2026-10-20T12:00:00.000Z');
  });

  it('answers approval_required, and passes the approval id on the retry', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', url(as.issuer), (r) =>
      JSON.parse(r.body).approval_id === 'apr-1'
        ? json({ data: { provider: 'gcp', credential_id: 'c2', access_token: 'gat', expires_in: 900 } }, 201)
        : json({ data: { status: 'approval_required', approval_id: 'apr-1', message: 'm' } }, 202),
    );
    expect(await gateway.cloudCredentials({ account: 'a', role: 'admin' })).toEqual({
      kind: 'approval_required',
      approvalId: 'apr-1',
    });
    const out = await gateway.cloudCredentials({ account: 'a', role: 'admin', approvalId: 'apr-1' });
    expect(out.kind === 'issued' && out.credential.accessToken?.reveal()).toBe('gat');
    expect(out.kind === 'issued' && out.credential.expiresAt).toBeInstanceOf(Date);
  });

  it('maps refusals: the token refused, a coded refusal, and malformed answers', async () => {
    const { gateway, as, fake } = await setup();
    fake.on('POST', url(as.issuer), () => json({ error: 'unauthorized' }, 401));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      name: 'GatewayTokenRefused',
    });
    fake.on('POST', url(as.issuer), () =>
      json({ error: 'ECLOUD004', error_description: 'role not granted' }, 403),
    );
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      name: 'APIError',
      code: 'ECLOUD004',
    });
    fake.on('POST', url(as.issuer), () => json({ data: {} }, 202));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    fake.on('POST', url(as.issuer), () => json({ data: {} }, 201));
    await expect(gateway.cloudCredentials({ account: 'a', role: 'r' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
    await expect(gateway.cloudCredentials({ account: '', role: 'r' })).rejects.toThrow('account and role');
    fake.on('POST', url(as.issuer), () => json({ data: { provider: 'aws' } }, 201));
    const bare = await gateway.cloudCredentials({ account: 'a', role: 'r' });
    expect(bare.kind === 'issued' && bare.credential.expiresAt).toBeUndefined();
  });
});
