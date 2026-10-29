import { describe, expect, it } from 'vitest';
import { GatewayTokenRefused } from '../../src/core/errors.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { json } from '../support/fake-fetch.js';
import { ISSUER, TestIssuer } from '../support/issuer.js';

async function setup() {
  const t = await TestIssuer.create();
  const warns: string[] = [];
  const af = new AuthFI({
    issuer: t.issuer,
    fetch: t.fake.fetch,
    retries: 0,
    logger: { debug() {}, info() {}, warn: (m) => warns.push(m), error() {} },
  });
  let n = 0;
  t.fake.on('POST', `${ISSUER}/oauth/token`, () => {
    n += 1;
    return json({ access_token: `at-${n}`, token_type: 'Bearer', expires_in: 900 });
  });
  t.fake.on('POST', `${ISSUER}/mcp`, () => json({ jsonrpc: '2.0', id: 1, result: {} }));
  const m2m = af.clientCredentials({ clientId: 'app_m', clientSecret: new Secret('s3cret') });
  return { t, af, m2m, warns };
}

describe('a client-credentials token as a gateway source', () => {
  it('mints a token for the gateway, labels the caller a client, and carries no agent id', async () => {
    const { t, m2m, warns } = await setup();
    const before = warns.length;
    const gateway = m2m.gateway();
    expect(gateway.agentId).toBeUndefined();
    expect(gateway.kind).toBe('client_credentials');
    expect(gateway.mcpUrl).toBe(`${ISSUER}/mcp`);
    await gateway.fetch(gateway.mcpUrl, { method: 'POST', body: '{}' });
    const mint = new URLSearchParams(t.fake.to(`${ISSUER}/oauth/token`)[0]!.body);
    expect(mint.get('grant_type')).toBe('client_credentials');
    expect(mint.get('resource')).toBe(`${ISSUER}/mcp`);
    expect(t.fake.to(`${ISSUER}/oauth/token`)[0]!.headers.get('authorization')).toMatch(/^Basic /);
    const call = t.fake.to(`${ISSUER}/mcp`)[0]!;
    expect(call.headers.get('authorization')).toBe('Bearer at-1');
    expect(call.headers.get('user-agent')).toMatch(/^authfi-node\/\S+ \(client-credentials\)$/);
    expect(call.headers.get('x-request-id')).toMatch(/^afr-/);
    // The gateway is the intended audience, so the "audience is this client" warning is not raised.
    expect(warns).toHaveLength(before);
  });

  it('does not change the credential for other APIs, and the gateway is one object', async () => {
    const { m2m } = await setup();
    expect(m2m.gateway()).toBe(m2m.gateway());
    expect(m2m.resource).toBeUndefined();
    expect(m2m.toString()).not.toContain('s3cret');
  });

  it('sends the gateway token only to AuthFI, never to another origin', async () => {
    const { m2m } = await setup();
    await expect(m2m.gateway().fetch('https://evil.example.com/mcp')).rejects.toThrow(
      'refusing to send this credential',
    );
  });

  it('ends the run when the gateway refuses the token, as for an agent', async () => {
    const { t, m2m } = await setup();
    t.fake.on('POST', `${ISSUER}/mcp`, () => json({ error: 'invalid_token' }, 401));
    await expect(m2m.gateway().fetch(`${ISSUER}/mcp`, { method: 'POST', body: '{}' })).rejects.toBeInstanceOf(
      GatewayTokenRefused,
    );
  });

  it("keeps the token's own resource apart from the gateway's", async () => {
    const { t, af } = await setup();
    const m2m = af.clientCredentials({
      clientId: 'app_m',
      clientSecret: new Secret('s3cret'),
      resource: 'api_orders',
      sendTo: ['https://api.example.com'],
    });
    await m2m.gateway().fetch(`${ISSUER}/mcp`, { method: 'POST', body: '{}' });
    expect(new URLSearchParams(t.fake.to(`${ISSUER}/oauth/token`)[0]!.body).get('resource')).toBe(
      `${ISSUER}/mcp`,
    );
    expect(m2m.resource).toBe('api_orders');
  });
});
