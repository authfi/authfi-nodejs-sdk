import { describe, expect, it } from 'vitest';
import { person, platform } from '../support/platform-setup.js';

describe('cloud credentials by handle: no secret reaches a model', () => {
  it('a handle carries no secret, and the secret is fetched once, under the same key', async () => {
    const { agent, p } = await platform();
    const out = await agent.cloud.credentials({ account: 'acct', role: 'reader', expiresInSeconds: 300 });
    if (out.kind !== 'issued') throw new Error('expected a handle');
    const text = JSON.stringify(out);
    expect(text).toContain('cred_1');
    expect(text).not.toMatch(/secret|AKIA|session/i);
    expect(out.handle).toMatchObject({ account: 'acct', role: 'reader', scope: 'cloud.credentials' });
    // the door took the request as DPoP
    expect(p.t.fake.to(`${p.issuer}/mcp/v1/cloud/credentials`)[0]!.headers.get('authorization')).toMatch(
      /^DPoP /,
    );
    const credential = await agent.cloud.secret(out.handle);
    expect(credential.secretAccessKey?.reveal()).toBe('the-secret-key');
    expect(credential.sessionToken?.reveal()).toBe('the-session-token');
    expect(JSON.stringify(credential)).not.toContain('the-secret-key');
    expect(String(credential.secretAccessKey)).not.toContain('the-secret-key');
    expect(p.refusals).toEqual([]);
  });

  it('is single use: the second fetch is refused, and says to ask for a new credential', async () => {
    const { agent } = await platform();
    const out = await agent.cloud.credentials({ account: 'a', role: 'r' });
    if (out.kind !== 'issued') throw new Error('expected a handle');
    await agent.cloud.secret(out.handle);
    await expect(agent.cloud.secret(out.handle)).rejects.toMatchObject({
      name: 'APIError',
      code: 'ECLOUDCRED014',
    });
  });

  it('is refused for any key but the instance the handle was issued to', async () => {
    const { agent, p } = await platform();
    const out = await agent.cloud.credentials({ account: 'a', role: 'r' });
    if (out.kind !== 'issued') throw new Error('expected a handle');
    p.handles.get(out.handle.credentialId)!.jkt = 'another-instances-key';
    await expect(agent.cloud.secret(out.handle)).rejects.toMatchObject({ code: 'ECLOUDCRED012' });
    expect(p.handles.get(out.handle.credentialId)!.spent).toBe(false);
  });

  it('is refused after it expired, and for a handle nobody issued', async () => {
    const { agent, clock } = await platform();
    const out = await agent.cloud.credentials({ account: 'a', role: 'r' });
    if (out.kind !== 'issued') throw new Error('expected a handle');
    clock.advance(901_000);
    await expect(agent.cloud.secret(out.handle)).rejects.toMatchObject({ code: 'ECLOUDCRED015' });
    await expect(agent.cloud.secret('cred_404')).rejects.toMatchObject({ code: 'ECLOUDCRED013' });
    await expect(agent.cloud.secret('  ')).rejects.toThrow(/credentialId is required/);
  });

  it('is refused when the token is Bearer for a project that bound it: the door takes no unproven bound token', async () => {
    const { agent, p } = await platform();
    const token = await agent.token();
    const res = await p.fetch(`${p.issuer}/mcp/v1/cloud/credentials/cred_1/secret`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(res.status).toBe(401);
    expect(p.refusals.at(-1)).toContain('a bound token is not Bearer');
  });

  it('fetchCredential asks and fetches in one step for the runtime, and passes an approval wait through', async () => {
    const { agent, p } = await platform();
    const both = await agent.cloud.fetchCredential({ account: 'a', role: 'r' });
    expect(both.kind === 'issued' && both.credential.accessKeyId).toBe('AKIAFAKEFAKEFAKE1234');
    p.t.fake.on(
      'POST',
      `${p.issuer}/mcp/v1/cloud/credentials`,
      () => new Response(JSON.stringify({ data: { approval_id: 'apr-1' } }), { status: 202 }),
    );
    expect(await agent.cloud.fetchCredential({ account: 'a', role: 'r' })).toEqual({
      kind: 'approval_required',
      approvalId: 'apr-1',
    });
  });

  it('works from a mandate and from a delegated token as it does from the agent', async () => {
    const s = await platform();
    const mandate = await s.agent.mandate('support.refund', { subjectToken: await person(s.p, s.clock) });
    const out = await mandate.cloud.credentials({ account: 'a', role: 'r' });
    expect(out.kind).toBe('issued');
    const delegated = await s.agent.exchange(await person(s.p, s.clock));
    expect((await delegated.gateway().cloud.credentials({ account: 'a', role: 'r' })).kind).toBe('issued');
  });
});
