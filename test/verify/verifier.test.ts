// The verifier matrix (design §6.1): each rule of §1.8, both ways, with the exact refusal code.

import { SignJWT, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { AccessToken } from '../../src/verify/access-token.js';
import {
  MultiIssuerVerifier,
  TokenVerifier,
  decodeUnverified,
  parseAuthorization,
} from '../../src/verify/verifier.js';
import { json } from '../support/fake-fetch.js';
import { API, ISSUER, TENANT, TestIssuer, unsignedJwt } from '../support/issuer.js';

const silent = { debug() {}, info() {}, warn() {}, error() {} };

async function setup(options: { expectedTenantId?: string; audience?: string[] } = {}) {
  const t = await TestIssuer.create();
  const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch, logger: silent });
  const verifier = af.verifier({
    audience: options.audience ?? [API],
    expectedTenantId: options.expectedTenantId,
  });
  return { t, af, verifier };
}

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return (e as { code: string }).code;
  }
  throw new Error('expected a refusal');
}

describe('a valid token', () => {
  for (const alg of ['RS256', 'EdDSA', 'ES256'] as const) {
    it(`verifies under ${alg}`, async () => {
      const { t, verifier } = await setup();
      const token = await verifier.verify(await t.sign({}, { alg }));
      expect(token).toBeInstanceOf(AccessToken);
      expect(token.tenantId).toBe(TENANT);
    });
  }

  it('accepts typ application/at+jwt in any case, a string aud, and a Secret', async () => {
    const { t, verifier } = await setup();
    const raw = await t.sign({ aud: API }, { header: { typ: 'Application/AT+JWT' } });
    expect((await verifier.verify(new Secret(raw))).audience).toEqual([API]);
  });

  it('honours the leeway', async () => {
    const { t, verifier } = await setup();
    const now = Math.floor(Date.now() / 1000);
    await expect(verifier.verify(await t.sign({ exp: now - 30 }))).resolves.toBeDefined();
    await expect(verifier.verify(await t.sign({ nbf: now + 30, iat: now + 30 }))).resolves.toBeDefined();
  });
});

describe('refusals', () => {
  const now = () => Math.floor(Date.now() / 1000);
  const cases: [string, (t: TestIssuer) => Promise<string>, string][] = [
    ['an empty token', async () => '', 'token_missing'],
    ['two parts', async () => 'a.b', 'token_malformed'],
    ['a JWE (five parts)', async () => 'a.b.c.d.e', 'token_malformed'],
    ['over 16 KiB', async () => `${'a'.repeat(17_000)}.b.c`, 'token_malformed'],
    ['a header that is not JSON', async () => 'bm90anNvbg.e30.c2ln', 'token_malformed'],
    [
      'alg none',
      async () => unsignedJwt({ alg: 'none', typ: 'at+jwt', kid: 'rsa-1' }, {}),
      'token_signature_invalid',
    ],
    [
      'HS256',
      async () => unsignedJwt({ alg: 'HS256', typ: 'at+jwt', kid: 'rsa-1' }, {}),
      'token_signature_invalid',
    ],
    [
      'PS256 (not issued by the platform)',
      async () => unsignedJwt({ alg: 'PS256', typ: 'at+jwt', kid: 'rsa-1' }, {}),
      'token_signature_invalid',
    ],
    ['an ID token (typ JWT)', (t) => t.sign({}, { header: { typ: 'JWT' } }), 'token_not_access_token'],
    [
      'a transaction token',
      (t) => t.sign({}, { header: { typ: 'txn_token+jwt' } }),
      'token_not_access_token',
    ],
    ['a security event', (t) => t.sign({}, { header: { typ: 'secevent+jwt' } }), 'token_not_access_token'],
    [
      'no typ',
      async (t) => unsignedJwt({ alg: 'RS256', kid: t.key('RS256').kid }, {}),
      'token_not_access_token',
    ],
    [
      'an unknown crit',
      async () => unsignedJwt({ alg: 'RS256', typ: 'at+jwt', kid: 'rsa-1', crit: ['exp2'] }, {}),
      'token_claims_invalid',
    ],
    ['no kid', async () => unsignedJwt({ alg: 'RS256', typ: 'at+jwt' }, {}), 'token_key_unknown'],
    [
      'an unknown kid',
      async () => unsignedJwt({ alg: 'RS256', typ: 'at+jwt', kid: 'nope' }, {}),
      'token_key_unknown',
    ],
    [
      'an alg that disagrees with the key',
      async () => unsignedJwt({ alg: 'EdDSA', typ: 'at+jwt', kid: 'rsa-1' }, {}),
      'token_signature_invalid',
    ],
    [
      'a bad signature',
      async (t) => (await t.sign()).replace(/\.[^.]+$/, '.AAAA'),
      'token_signature_invalid',
    ],
    ['another issuer', (t) => t.sign({ iss: 'https://evil.authfi.io' }), 'token_issuer_not_accepted'],
    ['the issuer with a trailing slash', (t) => t.sign({ iss: `${ISSUER}/` }), 'token_issuer_not_accepted'],
    ['no exp', (t) => t.sign({ exp: undefined }), 'token_claims_invalid'],
    ['expired beyond the leeway', (t) => t.sign({ exp: now() - 120 }), 'token_expired'],
    ['nbf in the future', (t) => t.sign({ nbf: now() + 600 }), 'token_claims_invalid'],
    ['iat in the future', (t) => t.sign({ iat: now() + 600 }), 'token_claims_invalid'],
    ['no aud', (t) => t.sign({ aud: undefined }), 'token_audience_mismatch'],
    ['another aud', (t) => t.sign({ aud: ['api_other'] }), 'token_audience_mismatch'],
    ['no sub', (t) => t.sign({ sub: undefined }), 'token_claims_invalid'],
    ['no tenant_id', (t) => t.sign({ tenant_id: undefined }), 'token_no_tenant'],
    ['cnf presented as Bearer', (t) => t.sign({ cnf: { jkt: 'x' } }), 'token_dpop_proof_required'],
    [
      'a mandate presented as Bearer',
      (t) => t.sign({ authfi_mandate: { id: 'm' } }),
      'token_dpop_proof_required',
    ],
    [
      'a nested act',
      (t) => t.sign({ sub: 'user:u1', act: { sub: 'agent:agt_1', act: { sub: 'agent:agt_2' } } }),
      'token_act_chain_unsupported',
    ],
    ['an act with no sub', (t) => t.sign({ act: { iss: 'x' } }), 'token_claims_invalid'],
  ];

  for (const [what, make, code] of cases) {
    it(`refuses ${what} as ${code}`, async () => {
      const { t, verifier } = await setup();
      expect(await refusal(verifier.verify(await make(t)))).toBe(code);
    });
  }

  it('refuses an HS256 token signed with the RSA public key (alg confusion)', async () => {
    const { t, verifier } = await setup();
    const pub = new TextEncoder().encode(JSON.stringify(t.key('RS256').publicJwk));
    const forged = await new SignJWT({ iss: ISSUER, sub: 'x', aud: [API], exp: 9e9, tenant_id: TENANT })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt', kid: 'rsa-1' })
      .sign(pub);
    expect(await refusal(verifier.verify(forged))).toBe('token_signature_invalid');
  });

  it('refuses a token signed by a key the issuer does not publish, under a published kid', async () => {
    const { verifier } = await setup();
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ iss: ISSUER, sub: 'x', aud: [API], exp: 9e9, tenant_id: TENANT })
      .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'rsa-1' })
      .sign(privateKey);
    expect(await refusal(verifier.verify(forged))).toBe('token_signature_invalid');
  });

  it('ignores jku, x5u and an embedded jwk: keys never come from the token', async () => {
    const { t, verifier } = await setup();
    t.fake.on('GET', 'https://evil.example/jwks', () => json({ keys: [] }));
    const raw = await t.sign(
      {},
      { header: { jku: 'https://evil.example/jwks', x5u: 'https://evil.example/x5u' } },
    );
    await expect(verifier.verify(raw)).resolves.toBeDefined();
    expect(t.fake.requests.some((r) => r.url.startsWith('https://evil.example'))).toBe(false);
  });

  it('pins the tenant when given one', async () => {
    const { t, verifier } = await setup({ expectedTenantId: TENANT });
    await expect(verifier.verify(await t.sign())).resolves.toBeDefined();
    expect(
      await refusal(verifier.verify(await t.sign({ tenant_id: '9a1d0000-0000-0000-0000-000000000000' }))),
    ).toBe('token_tenant_not_issuers');
  });

  it('refuses at construction a leeway out of range and an empty tenant', async () => {
    const t = await TestIssuer.create();
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch });
    expect(() => af.verifier({ audience: API, leewayMs: 400_000 })).toThrow('leewayMs');
    expect(() => af.verifier({ audience: API, expectedTenantId: ' ' })).toThrow('expectedTenantId');
  });
});

describe('the audience', () => {
  it('is required, with no skip', async () => {
    const t = await TestIssuer.create();
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch });
    expect(() => af.verifier({ audience: [] })).toThrow('audience is required');
    expect(() => af.verifier({ audience: '' })).toThrow('audience is required');
  });

  it.each([
    [ISSUER],
    [`${ISSUER}/mcp`],
    [`${ISSUER}/mcp/v1`],
    ['https://api.acme.example/x'],
    ['authfi-console'],
    ['authfi-workspace'],
  ])("refuses AuthFI's own audience %s", async (audience) => {
    const t = await TestIssuer.create();
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch, apiOrigin: 'https://api.acme.example' });
    expect(() => af.verifier({ audience: [API, audience] })).toThrow(/AuthFI/);
  });

  it('refuses an audience under the API origin learned from discovery, at the first verify', async () => {
    const t = await TestIssuer.create('https://login.acme.com');
    t.metadataExtra = {
      backchannel_authentication_endpoint:
        'https://acme.authfi.io/apis/regional/v1/ai/auth/backchannel-authorize',
    };
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch });
    const verifier = af.verifier({ audience: [API, 'https://acme.authfi.io/mcp'] });
    await expect(verifier.verify(await t.sign())).rejects.toMatchObject({ name: 'ConfigurationError' });
  });
});

describe('the seven token shapes', () => {
  const shapes: [string, Record<string, unknown>, string, string | undefined, string][] = [
    ['T1 a person', { sub: 'usr_1', client_id: 'app_web' }, 'user:usr_1', undefined, 'person'],
    ['T2 a machine client', { sub: 'app_m2m', client_id: 'app_m2m' }, 'app:app_m2m', undefined, 'machine'],
    ['T4 an agent', { sub: 'agt_1', client_id: 'agt_1' }, 'agent:agt_1', undefined, 'agent'],
    [
      'T5 delegated by CIBA',
      { sub: 'user:usr_1', act: { sub: 'agent:agt_1' }, client_id: 'agt_1' },
      'user:usr_1',
      'agent:agt_1',
      'delegated',
    ],
    [
      'T6 delegated by exchange',
      { sub: 'usr_1', act: { sub: 'agt_1' }, client_id: 'agt_1' },
      'user:usr_1',
      'agent:agt_1',
      'delegated',
    ],
    [
      'T6 with an app actor',
      { sub: 'usr_1', act: { sub: 'app_x' }, client_id: 'app_x' },
      'user:usr_1',
      'app:app_x',
      'delegated',
    ],
    ['a typed app', { sub: 'app:app_m', client_id: 'other' }, 'app:app_m', undefined, 'machine'],
    ['a typed agent', { sub: 'agent:agt_9' }, 'agent:agt_9', undefined, 'agent'],
  ];
  for (const [what, claims, principal, actor, kind] of shapes) {
    it(`reads ${what}`, async () => {
      const { t, verifier } = await setup();
      const token = await verifier.verify(
        await t.sign(claims, { alg: kind === 'agent' || what.startsWith('T5') ? 'EdDSA' : 'RS256' }),
      );
      expect(token.principal.toString()).toBe(principal);
      expect(token.actor?.toString()).toBe(actor);
      expect(token.tokenKind).toBe(kind);
    });
  }

  it("exposes the claims the platform puts on a person's token", async () => {
    const { t, verifier } = await setup();
    const authTime = Math.floor(Date.now() / 1000) - 60;
    const token = await verifier.verify(
      await t.sign({
        scope: 'openid orders:read',
        permissions: ['orders:read', 'orders:write'],
        roles: ['support'],
        groups: ['eu'],
        custom: { org_id: 'org_1' },
        acr: 'urn:authfi:acr:mfa',
        amr: ['pwd', 'otp'],
        auth_time: authTime,
      }),
    );
    expect([...token.scopes]).toEqual(['openid', 'orders:read']);
    expect(token.permissions.has('orders:write')).toBe(true);
    expect(token.roles.has('support')).toBe(true);
    expect(token.groups.has('eu')).toBe(true);
    expect(token.orgId).toBe('org_1');
    expect(token.amr).toEqual(['pwd', 'otp']);
    expect(token.authTime?.getTime()).toBe(authTime * 1000);
    expect(Object.isFrozen(token.claims)).toBe(true);
    expect(String(token)).toBe('AccessToken(person user:usr_123)');
    expect(JSON.stringify(token.principal)).toBe('"user:usr_123"');
  });
});

describe('requirements on a token', () => {
  async function token(claims: Record<string, unknown>) {
    const { t, verifier } = await setup();
    return verifier.verify(await t.sign(claims));
  }

  it('permissions are all-of, any-permission and roles are any-of, scopes all-of', async () => {
    const tok = await token({ permissions: ['a', 'b'], roles: ['r'], scope: 'x y' });
    expect(() => tok.requirePermission('a', 'b')).not.toThrow();
    expect(() => tok.requirePermission('a', 'c')).toThrow(
      expect.objectContaining({ name: 'InsufficientPermission', required: ['a', 'c'] }),
    );
    expect(() => tok.requireAnyPermission('c', 'b')).not.toThrow();
    expect(() => tok.requireAnyPermission('c', 'd')).toThrow(
      expect.objectContaining({ name: 'InsufficientPermission' }),
    );
    expect(() => tok.requireRole('q', 'r')).not.toThrow();
    expect(() => tok.requireRole('q')).toThrow(expect.objectContaining({ name: 'InsufficientPermission' }));
    expect(() => tok.requireScope('x', 'y')).not.toThrow();
    expect(() => tok.requireScope('x', 'z')).toThrow(
      expect.objectContaining({ name: 'InsufficientScope', required: ['x', 'z'] }),
    );
    expect(() => tok.requirePermission()).toThrow(expect.objectContaining({ name: 'ConfigurationError' }));
  });

  it('requires an acr and a recent sign-in', async () => {
    const now = Date.now();
    const tok = await token({ acr: 'urn:authfi:acr:mfa', auth_time: Math.floor(now / 1000) - 600 });
    expect(() => tok.requireAcr(['urn:authfi:acr:mfa'])).not.toThrow();
    expect(() => tok.requireAcr(['urn:authfi:acr:passkey'])).toThrow(
      expect.objectContaining({ name: 'InsufficientAuthentication' }),
    );
    expect(() => tok.requireAcr(['urn:authfi:acr:mfa'], { maxAgeSeconds: 300, nowMs: now })).toThrow(
      expect.objectContaining({ maxAge: 300, acrValues: ['urn:authfi:acr:mfa'] }),
    );
    expect(() => tok.requireAcr(['urn:authfi:acr:mfa'], { maxAgeSeconds: 900, nowMs: now })).not.toThrow();
    const noTime = await token({ acr: 'urn:authfi:acr:mfa' });
    expect(() => noTime.requireAcr(['urn:authfi:acr:mfa'], { maxAgeSeconds: 900 })).toThrow();
  });

  it('requires an agent', async () => {
    const person = await token({});
    expect(() => person.requireAgent()).toThrow(expect.objectContaining({ code: 'token_no_agent' }));
    const delegated = await token({ sub: 'user:u', act: { sub: 'agent:agt_1' } });
    expect(() => delegated.requireAgent()).not.toThrow();
  });
});

describe('verifyRequest', () => {
  it('reads the Bearer and DPoP schemes from a Fetch Request or the parts', async () => {
    const { t, verifier } = await setup();
    const raw = await t.sign();
    const req = new Request('https://api.example.com/orders', {
      headers: { authorization: `bearer ${raw}` },
    });
    await expect(verifier.verifyRequest(req)).resolves.toBeDefined();
    expect(
      await refusal(
        verifier.verifyRequest({ authorization: `DPoP ${raw}`, dpop: 'p', method: 'GET', url: 'u' }),
      ),
    ).toBe('token_dpop_unbound');
    const bound = await t.sign({ cnf: { jkt: 'x' } });
    expect(await refusal(verifier.verifyRequest({ authorization: `DPoP ${bound}` }))).toBe(
      'token_dpop_unsupported',
    );
    expect(await refusal(verifier.verifyRequest({ authorization: null }))).toBe('token_missing');
    expect(await refusal(verifier.verifyRequest({ authorization: `Basic abc` }))).toBe('token_missing');
  });

  it('parses the scheme case-insensitively', () => {
    expect(parseAuthorization('dpop abc')).toEqual({ scheme: 'DPoP', raw: 'abc' });
    expect(parseAuthorization('  Bearer   abc  ')).toEqual({ scheme: 'Bearer', raw: 'abc' });
    expect(() => parseAuthorization('Bearer a b')).toThrow();
    expect(() => decodeUnverified('a.b.c')).toThrow();
  });
});

describe('MultiIssuerVerifier', () => {
  async function two() {
    const acme = await TestIssuer.create('https://acme.authfi.io');
    const globex = await TestIssuer.create('https://globex.authfi.io');
    const fetchBoth: typeof fetch = (input, init) => {
      const url = new Request(input, init).url;
      return (url.startsWith('https://acme') ? acme : globex).fake.fetch(input, init);
    };
    const a = new AuthFI({ issuer: acme.issuer, fetch: fetchBoth });
    const g = new AuthFI({ issuer: globex.issuer, fetch: fetchBoth });
    return { acme, globex, a, g };
  }

  it('picks the issuer from the list and pins each to its tenant', async () => {
    const { acme, globex, a, g } = await two();
    const multi = new MultiIssuerVerifier({
      [acme.issuer]: { verifier: a.verifier({ audience: API }), tenantId: TENANT },
      [globex.issuer]: { verifier: g.verifier({ audience: API }), tenantId: 'globex-tenant' },
    });
    expect((await multi.verify(await acme.sign())).issuer).toBe(acme.issuer);
    expect((await multi.verify(await globex.sign({ tenant_id: 'globex-tenant' }))).issuer).toBe(
      globex.issuer,
    );
    expect(await refusal(multi.verify(await globex.sign()))).toBe('token_tenant_not_issuers');
    const stranger = await TestIssuer.create('https://stranger.authfi.io');
    expect(await refusal(multi.verify(await stranger.sign()))).toBe('token_issuer_not_accepted');
    await expect(
      multi.verifyRequest({ authorization: `Bearer ${await acme.sign()}` }),
    ).resolves.toBeDefined();
    expect(await refusal(multi.verifyRequest({ authorization: 'Basic x' }))).toBe('token_missing');
    expect((await multi.verify(new Secret(await acme.sign()))).tenantId).toBe(TENANT);
  });

  it('refuses a misfiled verifier, a missing tenant, a tenant that disagrees, and no issuers', async () => {
    const { acme, a } = await two();
    expect(
      () =>
        new MultiIssuerVerifier({
          'https://other.authfi.io': { verifier: a.verifier({ audience: API }), tenantId: TENANT },
        }),
    ).toThrow('verifies');
    expect(
      () =>
        new MultiIssuerVerifier({ [acme.issuer]: { verifier: a.verifier({ audience: API }), tenantId: '' } }),
    ).toThrow('tenant');
    expect(
      () =>
        new MultiIssuerVerifier({
          [acme.issuer]: { verifier: a.verifier({ audience: API, expectedTenantId: 'x' }), tenantId: TENANT },
        }),
    ).toThrow('another tenant');
    expect(() => new MultiIssuerVerifier({})).toThrow('at least one');
    expect(
      () => new MultiIssuerVerifier({ [acme.issuer]: { verifier: {} as TokenVerifier, tenantId: TENANT } }),
    ).toThrow('no TokenVerifier');
  });
});
