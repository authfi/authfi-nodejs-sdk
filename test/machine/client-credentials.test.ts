import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import authfi from '../../src/legacy.js';
import { json } from '../support/fake-fetch.js';
import { API, ISSUER, TestClock, TestIssuer } from '../support/issuer.js';

function capture() {
  const warns: string[] = [];
  return { warns, debug() {}, info() {}, warn: (m: string) => warns.push(m), error() {} };
}

async function setup() {
  const t = await TestIssuer.create();
  const clock = new TestClock();
  const log = capture();
  const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch, clock, logger: log });
  let n = 0;
  t.fake.on('POST', `${ISSUER}/oauth/token`, () => {
    n += 1;
    return json({ access_token: `at-${n}`, token_type: 'Bearer', expires_in: 900 });
  });
  return { t, af, clock, log };
}

describe('clientCredentials', () => {
  it('mints with resource and Basic auth, caches, and renews at two thirds of the lifetime', async () => {
    const { t, af, clock } = await setup();
    const m2m = af.clientCredentials({
      clientId: 'app_m',
      clientSecret: new Secret('s3cret'),
      resource: API,
      sendTo: ['https://api.example.com'],
      scope: ['a', 'b'],
    });
    const [a, b] = await Promise.all([m2m.token(), m2m.token()]);
    expect([a, b]).toEqual(['at-1', 'at-1']);
    const req = t.fake.to(`${ISSUER}/oauth/token`)[0]!;
    expect(new URLSearchParams(req.body).get('resource')).toBe(API);
    expect(new URLSearchParams(req.body).get('scope')).toBe('a b');
    expect(new URLSearchParams(req.body).get('grant_type')).toBe('client_credentials');
    expect(req.headers.get('authorization')).toBe(`Basic ${btoa('app_m:s3cret')}`);
    clock.advance(599_000);
    expect(await m2m.token()).toBe('at-1');
    clock.advance(2_000);
    expect(await m2m.token()).toBe('at-2');
    expect(await m2m.token({ force: true })).toBe('at-3');
  });

  it('sends the token to its API and nowhere else', async () => {
    const { t, af } = await setup();
    t.fake.on('GET', 'https://api.example.com/orders', (r) => json({ auth: r.headers.get('authorization') }));
    const m2m = af.clientCredentials({
      clientId: 'app_m',
      clientSecret: new Secret('s'),
      resource: API,
      sendTo: ['https://api.example.com'],
    });
    expect(await (await m2m.fetch('https://api.example.com/orders')).json()).toEqual({ auth: 'Bearer at-1' });
    await expect(m2m.fetch(`${ISSUER}/apis/regional/v1/check`)).rejects.toThrow('refusing to send');
    await expect(m2m.headers('GET', 'https://evil.example.com')).rejects.toThrow('refusing to send');
  });

  it('requires sendTo with a resource, and no sendTo without one', async () => {
    const { af } = await setup();
    expect(() =>
      af.clientCredentials({ clientId: 'a', clientSecret: new Secret('s'), resource: API }),
    ).toThrow('sendTo is required');
    expect(() =>
      af.clientCredentials({ clientId: 'a', clientSecret: new Secret('s'), sendTo: ['https://x.io'] }),
    ).toThrow('no resource');
    expect(() =>
      af.clientCredentials({
        clientId: 'a',
        clientSecret: new Secret('s'),
        resource: API,
        sendTo: ['https://x.io/v1'],
      }),
    ).toThrow('origin only');
  });

  it('warns once for a token with no resource, which goes only to the project', async () => {
    const { af, log } = await setup();
    const own = af.clientCredentials({ clientId: 'a', clientSecret: new Secret('s') });
    af.clientCredentials({ clientId: 'a', clientSecret: new Secret('s') });
    expect(log.warns.filter((w) => w.includes('without resource'))).toHaveLength(1);
    expect(await own.headers('GET', `${ISSUER}/apis/regional/v1/users`)).toEqual({
      authorization: 'Bearer at-1',
    });
    await expect(own.headers('GET', 'https://api.example.com/')).rejects.toThrow('refusing to send');
    expect(own.sendTo).toEqual([ISSUER]);
  });

  it('uses client_secret_post when asked, and refuses any other method', async () => {
    const { t, af } = await setup();
    await af
      .clientCredentials({
        clientId: 'a',
        clientSecret: new Secret('s'),
        authMethod: 'client_secret_post',
        resource: API,
        sendTo: ['https://x.io'],
      })
      .token();
    const body = new URLSearchParams(t.fake.to(`${ISSUER}/oauth/token`)[0]!.body);
    expect([body.get('client_id'), body.get('client_secret')]).toEqual(['a', 's']);
    // private_key_jwt is not in the type (agents use their key through af.agent()); a JS caller
    // that passes it anyway is refused.
    expect(() =>
      af.clientCredentials({
        clientId: 'a',
        clientSecret: new Secret('s'),
        authMethod: 'private_key_jwt' as unknown as 'client_secret_basic',
      }),
    ).toThrow(
      expect.objectContaining({ name: 'ConfigurationError', message: expect.stringContaining('authMethod') }),
    );
    expect(() => af.clientCredentials({ clientId: '', clientSecret: new Secret('s') })).toThrow('clientId');
    expect(() => af.clientCredentials({ clientId: 'a', clientSecret: 's' as unknown as Secret })).toThrow(
      'must be a Secret',
    );
  });

  it('retries the mint on a network failure, with the same request id', async () => {
    const { t, af } = await setup();
    let n = 0;
    t.fake.on('POST', `${ISSUER}/oauth/token`, () => {
      n += 1;
      if (n === 1) throw new TypeError('fetch failed');
      return json({ access_token: 'ok', expires_in: 60 });
    });
    expect(
      await af
        .clientCredentials({
          clientId: 'a',
          clientSecret: new Secret('s'),
          resource: API,
          sendTo: ['https://x.io'],
        })
        .token(),
    ).toBe('ok');
    const ids = t.fake.to(`${ISSUER}/oauth/token`).map((r) => r.headers.get('x-request-id'));
    expect(ids).toHaveLength(2);
    expect(ids[0]).toBe(ids[1]);
  });

  it('prints its client id, never the secret or a token', async () => {
    const { af } = await setup();
    const m2m = af.clientCredentials({
      clientId: 'app_m',
      clientSecret: new Secret('s3cret'),
      resource: API,
      sendTo: ['https://x.io'],
    });
    await m2m.token();
    for (const text of [
      inspect(m2m, { showHidden: true }),
      String(m2m),
      JSON.stringify(m2m),
      JSON.stringify(Object.entries(m2m)),
    ]) {
      expect(text).not.toContain('s3cret');
      expect(text).not.toContain('at-1');
    }
  });
});

describe('check', () => {
  it('asks the decision point with the credential and reads the answer', async () => {
    const { t, af } = await setup();
    t.fake.on('POST', `${ISSUER}/apis/regional/v1/check`, (r) => {
      expect(r.headers.get('authorization')).toBe('Bearer user-token');
      expect(JSON.parse(r.body)).toEqual({
        subject: 'user:u1',
        relation: 'refund',
        object: 'order:1',
        context: { amount: 5 },
      });
      return json({ data: { allowed: false, requires_approval: true, reason: 'policy_step_up' } });
    });
    const res = await af.check(new Secret('user-token'), {
      subject: 'user:u1',
      relation: 'refund',
      object: 'order:1',
      context: { amount: 5 },
    });
    expect(res).toEqual({ allowed: false, approvalRequired: true, reason: 'policy_step_up' });
  });

  it('takes a TokenSource and maps a refusal', async () => {
    const { t, af } = await setup();
    t.fake.on('POST', `${ISSUER}/apis/regional/v1/check`, () =>
      json({ data: { allowed: true, requires_approval: false, reason: '' } }),
    );
    const own = af.clientCredentials({ clientId: 'a', clientSecret: new Secret('s') });
    expect(await af.check(own, { subject: 'app:a', relation: 'r', object: 'o' })).toEqual({
      allowed: true,
      approvalRequired: false,
      reason: undefined,
    });
    t.fake.on('POST', `${ISSUER}/apis/regional/v1/check`, () => json({ error: 'unauthorized' }, 401));
    await expect(af.check(own, { subject: 'app:a', relation: 'r', object: 'o' })).rejects.toMatchObject({
      name: 'APIError',
      code: 'unauthorized',
      status: 401,
    });
    t.fake.on('POST', `${ISSUER}/apis/regional/v1/check`, () => json({ data: {} }));
    await expect(af.check(own, { subject: 'app:a', relation: 'r', object: 'o' })).rejects.toMatchObject({
      code: 'response_invalid',
    });
  });
});

describe('the 0.1 factory', () => {
  it('builds the issuer from the tenant, warns, and verifies strictly', async () => {
    const t = await TestIssuer.create();
    const log = capture();
    const legacy = authfi({
      tenant: 'acme',
      apiKey: 'sk_live_x',
      audience: [API],
      fetch: t.fake.fetch,
      logger: log,
    });
    const claims = await legacy.verifyToken(await t.sign());
    expect(claims.sub).toBe('usr_123');
    expect(log.warns.join('\n')).toContain('issuer was built from tenant as https://acme.authfi.io');
    expect(log.warns.join('\n')).toContain('apiKey is ignored');
    await legacy.start();
  });

  it('refuses to verify without an audience, and refuses the dead calls', async () => {
    const legacy = authfi({ issuer: ISSUER, logger: capture() });
    await expect(legacy.verifyToken('x.y.z')).rejects.toMatchObject({ name: 'ConfigurationError' });
    expect(() => legacy.registerPermission('a')).toThrow(
      expect.objectContaining({ feature: 'permission_sync' }),
    );
    await expect(legacy.syncPermissions()).rejects.toMatchObject({ feature: 'permission_sync' });
    await expect(legacy.cloud.credentials('t', 'aws')).rejects.toMatchObject({
      feature: 'cloud_credentials',
    });
    await expect(legacy.cloud.token('t', 'aud')).rejects.toMatchObject({ feature: 'cloud_credentials' });
    expect(() => authfi({})).toThrow('issuer is required');
  });

  it('keeps require, requireRole and authenticate as middleware, with req.user', async () => {
    const t = await TestIssuer.create();
    const legacy = authfi({ issuer: t.issuer, audience: API, fetch: t.fake.fetch, logger: capture() });
    const raw = await t.sign({ permissions: ['read:users'], roles: ['admin'] });
    const run = (mw: ReturnType<typeof legacy.require>) =>
      new Promise<{ next?: unknown; status?: number; user?: unknown }>((resolve) => {
        const req: Parameters<typeof mw>[0] = {
          headers: { authorization: `Bearer ${raw}` },
          method: 'GET',
          url: '/',
        };
        const res = {
          status(code: number) {
            resolve({ status: code });
            return this;
          },
          set() {
            return this;
          },
          json() {
            return this;
          },
        };
        mw(req, res, (err?: unknown) => resolve({ next: err, user: req.user }));
      });
    expect(await run(legacy.require('read:users'))).toMatchObject({
      next: undefined,
      user: expect.objectContaining({ sub: 'usr_123' }),
    });
    expect(await run(legacy.require('delete:users'))).toEqual({ status: 403 });
    expect(await run(legacy.requireRole('admin', 'x'))).toMatchObject({ next: undefined });
    expect(await run(legacy.authenticate())).toMatchObject({ next: undefined });
  });
});
