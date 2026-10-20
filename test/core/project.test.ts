import { readFileSync } from 'node:fs';
import { inspect } from 'node:util';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { coreOf, AuthFI } from '../../src/core/project.js';
import { requireToken } from '../support/oauth.js';
import { refusalOf, UNKNOWN_KID_REFETCH_MS } from '../../src/core/jwks.js';
import {
  applyClientAuth,
  apiErrorOf,
  dataOf,
  oauthErrorOf,
  requestToken,
  scopeList,
} from '../../src/core/oauth.js';
import { Secret } from '../../src/core/secret.js';
import { BaseTokenSource, checkSendTo, type TokenOptions } from '../../src/core/token-source.js';
import { SDK_VERSION } from '../../src/core/version.js';
import { FakeFetch, json } from '../support/fake-fetch.js';
import { ISSUER, TestClock, TestIssuer } from '../support/issuer.js';

function project(t: TestIssuer, extra: Partial<ConstructorParameters<typeof AuthFI>[0]> = {}) {
  return new AuthFI({
    issuer: t.issuer,
    fetch: t.fake.fetch,
    clock: new TestClock(),
    logger: silent(),
    ...extra,
  });
}

function silent() {
  const warns: string[] = [];
  return { warns, debug() {}, info() {}, warn: (m: string) => warns.push(m), error() {} };
}

describe('AuthFI', () => {
  it('keeps its version equal to package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as {
      version: string;
    };
    expect(SDK_VERSION).toBe(pkg.version);
  });

  it('validates its settings', () => {
    expect(() => new AuthFI({ issuer: 'acme' })).toThrow('not a URL');
    expect(() => new AuthFI({ issuer: ISSUER, apiOrigin: 'https://x.io/path' })).toThrow('origin only');
    expect(() => new AuthFI({ issuer: ISSUER, retries: -1 })).toThrow('retries');
    expect(() => new AuthFI({ issuer: ISSUER, leewayMs: 301_000 })).toThrow('leewayMs');
    expect(() => new AuthFI({ issuer: ISSUER, timeout: { attemptMs: 0 } })).toThrow('attemptMs');
  });

  it('builds from the environment', () => {
    const af = AuthFI.fromEnv({ AUTHFI_ISSUER: ISSUER, AUTHFI_API_ORIGIN: 'https://acme-api.authfi.io' });
    expect(af.issuer).toBe(ISSUER);
    expect(af.apiOrigin).toBe('https://acme-api.authfi.io');
    expect(() => AuthFI.fromEnv({})).toThrow('AUTHFI_ISSUER');
    expect(AuthFI.fromEnv({ AUTHFI_ISSUER: ISSUER, AUTHFI_API_ORIGIN: '' }).apiOrigin).toBe(ISSUER);
  });

  it('prints only its issuer', () => {
    const af = new AuthFI({ issuer: ISSUER });
    expect(String(af)).toBe(`AuthFI(${ISSUER})`);
    expect(inspect(af)).toBe(`AuthFI(${ISSUER})`);
    expect(JSON.stringify(af)).toBe(JSON.stringify({ issuer: ISSUER }));
  });

  it('reads discovery once, and learns the API origin from it', async () => {
    const t = await TestIssuer.create('https://login.acme.com');
    t.metadataExtra = {
      backchannel_authentication_endpoint:
        'https://acme.authfi.io/apis/regional/v1/ai/auth/backchannel-authorize',
    };
    const af = project(t);
    expect(af.apiOrigin).toBe('https://login.acme.com');
    const [a, b] = await Promise.all([af.metadata(), af.metadata()]);
    expect(a).toBe(b);
    expect(t.fake.to('https://login.acme.com/.well-known/openid-configuration')).toHaveLength(1);
    expect(af.apiOrigin).toBe('https://acme.authfi.io');
    expect(await coreOf(af).ownOrigins()).toEqual(['https://login.acme.com', 'https://acme.authfi.io']);
  });

  it('a configured API origin wins', async () => {
    const t = await TestIssuer.create();
    const af = project(t, { apiOrigin: 'https://other.authfi.io' });
    await af.metadata();
    expect(af.apiOrigin).toBe('https://other.authfi.io');
    expect(await coreOf(af).apiOrigin()).toBe('https://other.authfi.io');
  });

  it('coreOf refuses an object it did not build', () => {
    expect(() => coreOf({} as AuthFI)).toThrow('not an AuthFI project');
  });
});

describe('discovery', () => {
  it('falls back to the RFC 8414 document', async () => {
    const t = await TestIssuer.create();
    t.fake.on('GET', `${ISSUER}/.well-known/openid-configuration`, () => json({}, 404));
    t.fake.on('GET', `${ISSUER}/.well-known/oauth-authorization-server`, () => json(t.metadata()));
    expect((await project(t).metadata()).token_endpoint).toBe(`${ISSUER}/oauth/token`);
  });

  it.each([
    [{ issuer: 'https://evil.authfi.io' }, 'issuer_mismatch'],
    [{ issuer: `${ISSUER}/` }, 'issuer_mismatch'],
    [{ token_endpoint: undefined }, 'discovery_failed'],
    [{ jwks_uri: '' }, 'discovery_failed'],
    [{ grant_types_supported: 'client_credentials' }, 'discovery_failed'],
  ])('refuses a document with %j', async (patch, code) => {
    const t = await TestIssuer.create();
    t.metadataExtra = patch;
    await expect(project(t).metadata()).rejects.toMatchObject({ name: 'DiscoveryError', code });
  });

  it('refuses a document that is not an object, and answers that are not 200', async () => {
    const t = await TestIssuer.create();
    t.fake.on('GET', `${ISSUER}/.well-known/openid-configuration`, () => json([1, 2]));
    await expect(project(t).metadata()).rejects.toMatchObject({ code: 'discovery_failed' });
    t.fake.on('GET', `${ISSUER}/.well-known/openid-configuration`, () => json({}, 500));
    await expect(project(t, { retries: 0 }).metadata()).rejects.toMatchObject({
      code: 'discovery_failed',
      status: 500,
    });
  });

  it('reports no document at all', async () => {
    const fake = new FakeFetch();
    const af = new AuthFI({ issuer: ISSUER, fetch: fake.fetch });
    await expect(af.metadata()).rejects.toMatchObject({ code: 'discovery_failed', status: 404 });
  });
});

describe('the key set', () => {
  it('ignores keys it must not use', () => {
    const rsa = { kty: 'RSA', kid: 'r', n: 'A'.repeat(342), e: 'AQAB' };
    expect(refusalOf({ ...rsa, n: 'AQAB'.repeat(10) })).toMatch(/under 2048/);
    expect(refusalOf({ ...rsa, use: 'enc' })).toMatch(/use is enc/);
    expect(refusalOf({ ...rsa, d: 'x' })).toMatch(/private member/);
    expect(refusalOf({ ...rsa, alg: 'ES256' })).toMatch(/disagrees/);
    expect(refusalOf({ ...rsa, kid: undefined } as unknown as JWK)).toMatch(/no kid/);
    expect(refusalOf({ kty: 'oct', kid: 'h', k: 'x' })).toMatch(/private member/);
    expect(refusalOf({ kty: 'EC', crv: 'P-384', kid: 'e', x: 'a', y: 'b' })).toMatch(/not verified/);
    expect(refusalOf({ ...rsa, n: 'a+b' })).toMatch(/not base64url/);
    expect(refusalOf({ kty: 'OKP', crv: 'Ed25519', kid: 'o', x: 'abc' })).toBeUndefined();
  });

  it('refetches once for an unknown kid, at most once per 30 seconds', async () => {
    const t = await TestIssuer.create();
    const clock = new TestClock();
    const af = project(t, { clock });
    const keys = coreOf(af).keys;
    await keys.key('rsa-1', 'RS256');
    expect(t.fake.to(`${ISSUER}/.well-known/jwks.json`)).toHaveLength(1);
    await expect(keys.key('invented-1', 'RS256')).rejects.toMatchObject({ code: 'token_key_unknown' });
    await expect(keys.key('invented-2', 'RS256')).rejects.toMatchObject({ code: 'token_key_unknown' });
    expect(t.fake.to(`${ISSUER}/.well-known/jwks.json`)).toHaveLength(2);
    clock.advance(UNKNOWN_KID_REFETCH_MS);
    await expect(keys.key('invented-3', 'RS256')).rejects.toMatchObject({ code: 'token_key_unknown' });
    expect(t.fake.to(`${ISSUER}/.well-known/jwks.json`)).toHaveLength(3);
  });

  it("refuses a header alg that is not the key's as an unknown key, as the kernel does", async () => {
    const t = await TestIssuer.create();
    const keys = coreOf(project(t)).keys;
    await expect(keys.key('okp-1', 'RS256')).rejects.toMatchObject({ code: 'token_key_unknown' });
    await expect(keys.key('rsa-1', 'ES256')).rejects.toMatchObject({ code: 'token_key_unknown' });
    expect((await keys.key('okp-1', 'EdDSA')).alg).toBe('EdDSA');
    expect((await keys.key('ec-1', 'ES256')).alg).toBe('ES256');
  });

  it('reports a key set it cannot read as a discovery failure', async () => {
    const t = await TestIssuer.create();
    t.fake.on('GET', `${ISSUER}/.well-known/jwks.json`, () => json({ nokeys: true }));
    await expect(coreOf(project(t)).keys.key('rsa-1', 'RS256')).rejects.toMatchObject({
      name: 'DiscoveryError',
    });
    t.fake.on('GET', `${ISSUER}/.well-known/jwks.json`, () => json({}, 403));
    await expect(coreOf(project(t)).keys.key('rsa-1', 'RS256')).rejects.toMatchObject({ status: 403 });
  });
});

describe('the token endpoint wire', () => {
  it('encodes Basic credentials as RFC 6749 §2.3.1 says', async () => {
    const form = new URLSearchParams();
    const headers: Record<string, string> = {};
    await applyClientAuth(
      { method: 'client_secret_basic', clientId: 'app 1', clientSecret: new Secret('p:ss/é') },
      form,
      headers,
      'x',
    );
    expect(atob(headers.authorization!.slice(6))).toBe('app+1:p%3Ass%2F%C3%A9');
    expect(form.toString()).toBe('');
  });

  it('sends a public client id, a posted secret, or a fresh assertion', async () => {
    const f1 = new URLSearchParams();
    await applyClientAuth({ method: 'none', clientId: 'spa' }, f1, {}, 'x');
    expect(f1.get('client_id')).toBe('spa');
    const f2 = new URLSearchParams();
    await applyClientAuth(
      { method: 'client_secret_post', clientId: 'm', clientSecret: new Secret('s') },
      f2,
      {},
      'x',
    );
    expect([f2.get('client_id'), f2.get('client_secret')]).toEqual(['m', 's']);
    const f3 = new URLSearchParams();
    await applyClientAuth(
      {
        method: 'private_key_jwt',
        clientId: 'agt_1',
        assertion: async (aud) => new Secret(`signed-for-${aud}`),
      },
      f3,
      {},
      'https://t',
    );
    expect(f3.get('client_assertion')).toBe('signed-for-https://t');
    expect(f3.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  });

  it('parses a token answer and keeps the unmodelled fields', async () => {
    const t = await TestIssuer.create();
    t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
      json({
        access_token: 'at',
        token_type: 'Bearer',
        expires_in: 900,
        scope: 'a b',
        capabilities: ['x'],
        refresh_token: 'rt',
      }),
    );
    const res = await requireToken(t);
    expect(res.accessToken.reveal()).toBe('at');
    expect(res.refreshToken?.reveal()).toBe('rt');
    expect(res.scope).toEqual(['a', 'b']);
    expect(res.extra).toEqual({ capabilities: ['x'] });
    expect(res.expiresAt - Date.now()).toBeGreaterThan(890_000);
  });

  it('falls back to the token exp when expires_in is absent', async () => {
    const t = await TestIssuer.create();
    const jwt = await t.sign({ exp: Math.floor(Date.now() / 1000) + 120 });
    t.fake.on('POST', `${ISSUER}/oauth/token`, () => json({ access_token: jwt }));
    const res = await requireToken(t);
    expect(res.expiresAt - Date.now()).toBeGreaterThan(100_000);
    expect(res.expiresAt - Date.now()).toBeLessThanOrEqual(121_000);
  });

  it.each([
    [
      401,
      { error: 'insufficient_user_authentication', error_description: 'x (acr: urn:authfi:acr:mfa)' },
      'StepUpRequired',
    ],
    [503, { error: 'temporarily_unavailable' }, 'TemporarilyUnavailable'],
    [400, { error: 'invalid_grant', error_description: 'spent' }, 'OAuthError'],
    [500, 'boom', 'APIError'],
  ])('maps an HTTP %i refusal to its type', async (status, body, name) => {
    const t = await TestIssuer.create();
    t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
      typeof body === 'string' ? new Response(body, { status }) : json(body, status),
    );
    const err = await requireToken(t, { retries: 0 }).catch((e: unknown) => e);
    expect(err).toMatchObject({ name, status });
    if (name === 'StepUpRequired') expect((err as { acrValues: string[] }).acrValues).toEqual([]);
  });

  it('refuses a token answer with no token', async () => {
    const t = await TestIssuer.create();
    t.fake.on('POST', `${ISSUER}/oauth/token`, () => json({ token_type: 'Bearer' }));
    await expect(requireToken(t)).rejects.toMatchObject({ code: 'response_invalid' });
    t.fake.on('POST', `${ISSUER}/oauth/token`, () => json('str'));
    await expect(requireToken(t)).rejects.toMatchObject({ code: 'response_invalid' });
  });

  it('builds the form from list and string params and skips empty ones', async () => {
    const t = await TestIssuer.create();
    t.fake.on('POST', `${ISSUER}/oauth/token`, () => json({ access_token: 'at', expires_in: 60 }));
    const af = project(t);
    await requestToken(
      coreOf(af).transport,
      {
        tokenEndpoint: `${ISSUER}/oauth/token`,
        params: { grant_type: 'client_credentials', resource: ['a', 'b'], scope: '', audience: undefined },
        retry: 'safe',
      },
      () => Date.now(),
    );
    expect(t.fake.requests.at(-1)!.body).toBe('grant_type=client_credentials&resource=a&resource=b');
  });

  it('reads our API envelopes', () => {
    const res = (status: number, body: string) => ({
      status,
      headers: new Headers(),
      body: new TextEncoder().encode(body),
      url: 'u',
      requestId: 'r',
      platformRequestId: undefined,
      runId: undefined,
      droppedHeader: undefined,
    });
    expect(dataOf(res(200, '{"data":{"a":1}}'))).toEqual({ a: 1 });
    expect(() => dataOf(res(200, '{"a":1}'))).toThrow('data envelope');
    expect(apiErrorOf(res(403, '{"error":"forbidden","error_description":"no"}'))).toMatchObject({
      code: 'forbidden',
      description: 'no',
    });
    expect(apiErrorOf(res(502, 'x')).code).toBe('server_error');
    expect(apiErrorOf(res(404, '')).code).toBe('http_404');
    expect(oauthErrorOf(res(400, '{}')).code).toBe('response_invalid');
    expect(scopeList(['a', 1, ''])).toEqual(['a']);
    expect(scopeList(undefined)).toEqual([]);
  });
});

class StaticSource extends BaseTokenSource {
  readonly sendTo: readonly string[];
  calls = 0;
  constructor(sendTo: string[], baseFetch: typeof fetch) {
    super(baseFetch);
    this.sendTo = checkSendTo(sendTo);
  }
  token(_options?: TokenOptions): Promise<string> {
    this.calls += 1;
    return Promise.resolve(`tok-${this.calls}`);
  }
}

describe('a token source', () => {
  it('sends its credential only to its origins', async () => {
    const fake = new FakeFetch().on('GET', 'https://api.example.com/orders', (r) =>
      json({ auth: r.headers.get('authorization') }),
    );
    const src = new StaticSource(['https://api.example.com'], fake.fetch);
    expect(await src.headers('GET', 'https://api.example.com/x')).toEqual({ authorization: 'Bearer tok-1' });
    await expect(src.headers('GET', 'https://evil.example.com/x')).rejects.toThrow('refusing to send');
    const res = await src.fetch('https://api.example.com/orders', { headers: { 'x-a': '1' } });
    expect(await res.json()).toEqual({ auth: 'Bearer tok-2' });
    await expect(src.fetch('https://evil.example.com/')).rejects.toThrow('refusing to send');
    expect(fake.requests).toHaveLength(1);
  });

  it('refuses a sendTo that is not an exact origin', () => {
    expect(() => checkSendTo(['https://api.example.com/v1'])).toThrow('origin only');
    expect(checkSendTo(['https://a.io', 'https://a.io/'])).toEqual(['https://a.io']);
  });

  it('does not follow a redirect with the credential', async () => {
    const seen: string[] = [];
    const base: typeof fetch = async (input) => {
      const req = input as Request;
      seen.push(req.redirect);
      return new Response(null, { status: 200 });
    };
    await new StaticSource(['https://api.example.com'], base).fetch('https://api.example.com/');
    expect(seen).toEqual(['error']);
  });
});
