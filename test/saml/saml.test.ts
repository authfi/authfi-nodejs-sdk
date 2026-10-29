// SAML sign-in for a standard app: the project's metadata, the redirect, and every refusal the assertion
// must meet (unsigned, wrong signer, wrong audience, wrong recipient, wrong request, expired, replayed, wrapped).

import { beforeAll, describe, expect, it } from 'vitest';
import { ConfigurationError, DiscoveryError } from '../../src/core/errors.js';
import { AuthFI } from '../../src/core/project.js';
import {
  InMemoryReplayStore,
  parseIdpMetadata,
  PendingSamlSignIn,
  SamlAssertionRefused,
  SamlServiceProvider,
  type SamlServiceProviderOptions,
} from '../../src/saml/index.js';
import { FakeFetch } from '../support/fake-fetch.js';
import { ACS, BASE, ENTITY, FakeIdp, makeSigner, SP_ENTITY } from '../support/fake-saml-idp.js';

let idp: FakeIdp;
beforeAll(async () => {
  idp = await FakeIdp.create();
});

function provider(options: Partial<SamlServiceProviderOptions> = {}): SamlServiceProvider {
  return new SamlServiceProvider(parseIdpMetadata(idp.metadata(), ENTITY), {
    spEntityId: SP_ENTITY,
    acsUrl: ACS,
    ...options,
  });
}

async function refused(run: Promise<unknown>, code: string): Promise<void> {
  const error = await run.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(SamlAssertionRefused);
  expect((error as SamlAssertionRefused).code).toBe(code);
  expect((error as SamlAssertionRefused).status).toBe(401);
}

describe('signing in', () => {
  it('redirects to the project with a request id', async () => {
    const pending = await provider().startSignIn('/dashboard');
    const url = new URL(pending.url);
    expect(`${url.origin}${url.pathname}`).toBe(idp.ssoUrl);
    expect(url.searchParams.get('SAMLRequest')).toBeTruthy();
    expect(url.searchParams.get('RelayState')).toBe('/dashboard');
    expect(pending.requestId).toMatch(/^_[0-9a-f]{32}$/);
    expect(pending.relayState).toBe('/dashboard');
  });

  it('puts the request id in the AuthnRequest it sends', async () => {
    const pending = await provider().startSignIn();
    const { inflateRawSync } = await import('node:zlib');
    const xml = inflateRawSync(
      Buffer.from(new URL(pending.url).searchParams.get('SAMLRequest') ?? '', 'base64'),
    ).toString();
    expect(xml).toContain(`ID="${pending.requestId}"`);
    expect(xml).toContain(SP_ENTITY);
    expect(xml).toContain(ACS);
  });

  it('accepts a signed assertion for this app and maps the person', async () => {
    const sp = provider();
    const pending = await sp.startSignIn('/dashboard');
    const now = Date.now();
    const signedIn = await sp.finishSignIn(idp.response({ now, inResponseTo: pending.requestId }), pending);
    const { user } = signedIn;
    expect(user.sub).toBe('ada@example.com');
    expect(user.email).toBe('ada@example.com');
    expect(user.emailVerified).toBeUndefined();
    expect(user.name).toBe('Ada L');
    expect(user.groups).toEqual(['staff']);
    expect(user.roles).toEqual(['admin']);
    expect(user.acr).toBe('urn:authfi:acr:pwd');
    expect(user.amr).toEqual(['saml']);
    expect(Math.abs((user.authTime?.getTime() ?? 0) - (now - 5000))).toBeLessThan(2000);
    expect(signedIn.sessionIndex).toBe('_s1');
    expect(signedIn.relayState).toBe('/dashboard');
    expect(signedIn.assertionId).toMatch(/^_a/);
    expect(user.claims.saml_attributes).toEqual({ groups: ['staff'], roles: ['admin'], name: ['Ada L'] });
  });

  it('reads the attribute names it is given', async () => {
    const sp = provider({ attributes: { email: ['work_email'], groups: ['teams'] } });
    const pending = await sp.startSignIn();
    const response = idp.response({
      now: Date.now(),
      inResponseTo: pending.requestId,
      attributes: { work_email: ['a@corp.example'], teams: ['x', 'y'] },
      nameId: 'u1',
      nameFormat: 'urn:x:persistent',
    });
    const { user } = await sp.finishSignIn(response, pending);
    expect([user.sub, user.email, user.groups]).toEqual(['u1', 'a@corp.example', ['x', 'y']]);
  });

  it('does not take a persistent NameID for an email', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const response = idp.response({
      now: Date.now(),
      inResponseTo: pending.requestId,
      nameId: 'user@looks.like',
      nameFormat: 'urn:x:persistent',
      attributes: {},
    });
    const { user } = await sp.finishSignIn(response, pending);
    expect(user.sub).toBe('user@looks.like');
    expect(user.email).toBeUndefined();
  });

  it('keeps an attribute named like an object member as data', async () => {
    const sp = provider({ attributes: { name: ['constructor'] } });
    const pending = await sp.startSignIn();
    const response = idp.response({
      now: Date.now(),
      inResponseTo: pending.requestId,
      attributes: { constructor: ['Ada'], __proto__: ['x'] },
    });
    const { user } = await sp.finishSignIn(response, pending);
    expect(user.name).toBe('Ada');
  });
});

describe('refusals', () => {
  async function attempt(
    options: Partial<Parameters<FakeIdp['response']>[0]>,
    code: string,
    sp = provider(),
  ): Promise<void> {
    const pending = await sp.startSignIn();
    const response = idp.response({ now: Date.now(), inResponseTo: pending.requestId, ...options });
    await refused(sp.finishSignIn(response, pending), code);
  }

  it('refuses an unsigned assertion', () => attempt({ sign: 'none' }, 'saml_signature_invalid'));
  it('refuses a signed response around an unsigned assertion', () =>
    attempt({ sign: 'response' }, 'saml_signature_invalid'));
  it('refuses an assertion signed by a key not in the metadata', async () => {
    await attempt({ signer: await makeSigner('attacker') }, 'saml_signature_invalid');
  });
  it('refuses an assertion changed after signing', () => attempt({ tamper: true }, 'saml_signature_invalid'));
  it('refuses a second unsigned assertion beside a signed one', () =>
    attempt({ wrap: true }, 'saml_assertion_count'));
  it('refuses an assertion for another audience', () =>
    attempt({ audience: 'https://other.example/saml' }, 'saml_audience_mismatch'));
  it('refuses an assertion for another recipient', () =>
    attempt({ recipient: 'https://evil.example/saml/acs', destination: ACS }, 'saml_recipient_mismatch'));
  it('refuses an assertion from another issuer', () =>
    attempt({ issuer: 'https://evil.authfi.io/saml/metadata' }, 'saml_issuer_mismatch'));
  it('refuses an assertion answering another request', () =>
    attempt({ inResponseTo: '_someone_elses_request' }, 'saml_in_response_to_mismatch'));
  it('refuses an assertion that answers no request when one was started', () =>
    attempt({ inResponseTo: undefined }, 'saml_in_response_to_mismatch'));
  it.each(['signature', 'digest', 'both'] as const)('refuses an SHA-1 %s', (weak) =>
    attempt({ weak }, 'saml_algorithm_rejected'),
  );
  it('refuses an attribute named twice', () =>
    attempt({ duplicateAttribute: true }, 'saml_attribute_duplicated'));
  it('refuses a failed status', () =>
    attempt(
      { status: 'urn:oasis:names:tc:SAML:2.0:status:Responder', bare: true },
      'saml_status_not_success',
    ));

  it('refuses an expired assertion', () => {
    const now = Date.now();
    return attempt(
      { now: now - 7_200_000, notBefore: now - 7_300_000, notOnOrAfter: now - 7_000_000 },
      'saml_assertion_expired',
    );
  });

  it('refuses an assertion expired inside the library skew, by this provider leeway', () => {
    const now = Date.now();
    return attempt(
      {
        now: now - 400_000,
        notBefore: now - 500_000,
        notOnOrAfter: now - 120_000,
        confirmNotOnOrAfter: now + 300_000,
      },
      'saml_assertion_expired',
      provider({ leewayMs: 10_000 }),
    );
  });

  it('refuses an assertion not yet valid by this provider leeway', () => {
    const now = Date.now();
    return attempt(
      { notBefore: now + 120_000, notOnOrAfter: now + 600_000 },
      'saml_assertion_not_yet_valid',
      provider({ leewayMs: 10_000 }),
    );
  });

  it('refuses a confirmation that expired', () => {
    const now = Date.now();
    return attempt(
      { confirmNotOnOrAfter: now - 120_000 },
      'saml_assertion_expired',
      provider({ leewayMs: 10_000 }),
    );
  });

  it('accepts an assertion once', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const response = idp.response({ now: Date.now(), inResponseTo: pending.requestId });
    await sp.finishSignIn(response, pending);
    await refused(sp.finishSignIn(response, pending), 'saml_assertion_replayed');
  });

  it('refuses a second assertion for one request', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const now = Date.now();
    await sp.finishSignIn(idp.response({ now, inResponseTo: pending.requestId }), pending);
    await refused(
      sp.finishSignIn(idp.response({ now, inResponseTo: pending.requestId }), pending),
      'saml_assertion_replayed',
    );
  });

  it('refuses a replay at a second provider sharing the store', async () => {
    const store = new InMemoryReplayStore();
    const first = provider({ replayStore: store });
    const second = provider({ replayStore: store });
    const pending = await first.startSignIn();
    const response = idp.response({ now: Date.now(), inResponseTo: pending.requestId });
    await first.finishSignIn(response, pending);
    await refused(second.finishSignIn(response, pending), 'saml_assertion_replayed');
  });

  it('does not remember a failed response as used', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const now = Date.now();
    const forged = idp.response({
      now,
      inResponseTo: pending.requestId,
      assertionId: '_same',
      signer: await makeSigner('x'),
    });
    await refused(sp.finishSignIn(forged, pending), 'saml_signature_invalid');
    const real = idp.response({ now, inResponseTo: pending.requestId, assertionId: '_same' });
    expect((await sp.finishSignIn(real, pending)).assertionId).toBe('_same');
  });

  it('refuses a response with a DTD', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const response = idp.response({ now: Date.now(), inResponseTo: pending.requestId, doctype: true });
    await refused(sp.finishSignIn(response, pending), 'saml_xml_invalid');
  });

  it.each([
    ['empty', ''],
    ['not base64', '!!not base64!!'],
    ['too large', 'A'.repeat(1024 * 1024 + 4)],
  ])('refuses a response that is %s', async (_name, junk) => {
    const sp = provider();
    await refused(sp.finishSignIn(junk, await sp.startSignIn()), 'saml_xml_invalid');
  });

  it('refuses base64 that is not a SAML response', async () => {
    const sp = provider();
    const pending = await sp.startSignIn();
    const error = await sp
      .finishSignIn(Buffer.from('not xml').toString('base64'), pending)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SamlAssertionRefused);
  });

  it('refuses a response when no sign-in was started', () =>
    refused(
      provider().finishSignIn(idp.response({ now: Date.now(), inResponseTo: undefined }), undefined),
      'saml_unsolicited',
    ));

  it('refuses a pending sign-in that is too old', async () => {
    let now = Date.now();
    const sp = provider({ now: () => now });
    const pending = await sp.startSignIn();
    const response = idp.response({ now, inResponseTo: pending.requestId });
    now += 601_000;
    await refused(sp.finishSignIn(response, pending), 'saml_pending_expired');
  });
});

describe('IdP-initiated', () => {
  it('is accepted only when allowed', async () => {
    const sp = provider({ allowIdpInitiated: true });
    const signedIn = await sp.finishSignIn(
      idp.response({ now: Date.now(), inResponseTo: undefined }),
      undefined,
    );
    expect(signedIn.user.sub).toBe('ada@example.com');
    expect(signedIn.relayState).toBeUndefined();
  });

  it('is still signed and single-use', async () => {
    const sp = provider({ allowIdpInitiated: true });
    await refused(
      sp.finishSignIn(idp.response({ now: Date.now(), inResponseTo: undefined, sign: 'none' }), undefined),
      'saml_signature_invalid',
    );
    const response = idp.response({ now: Date.now(), inResponseTo: undefined });
    await sp.finishSignIn(response, undefined);
    await refused(sp.finishSignIn(response, undefined), 'saml_assertion_replayed');
  });

  it('cannot use a response that answers a request without that request', async () => {
    const sp = provider({ allowIdpInitiated: true });
    await refused(
      sp.finishSignIn(idp.response({ now: Date.now(), inResponseTo: '_r1' }), undefined),
      'saml_in_response_to_mismatch',
    );
  });
});

describe('the pending sign-in and the replay store', () => {
  it('round-trips a pending sign-in', async () => {
    const pending = await provider().startSignIn('/x');
    const back = PendingSamlSignIn.load(pending.dump());
    expect([back.url, back.requestId, back.relayState, back.expiresAt]).toEqual([
      pending.url,
      pending.requestId,
      pending.relayState,
      pending.expiresAt,
    ]);
    expect(String(pending)).toBe(`PendingSamlSignIn(${idp.ssoUrl})`);
  });

  it.each([
    '',
    'nope',
    '[]',
    'null',
    '{}',
    '{"id":"","rs":null,"exp":1,"url":"u"}',
    '{"id":"a","rs":3,"exp":1,"url":"u"}',
    '{"id":"a","rs":null,"exp":"1","url":"u"}',
    '{"id":"a","rs":null,"exp":1,"url":5}',
  ])('refuses %j as a pending sign-in', (text) => {
    expect(() => PendingSamlSignIn.load(text)).toThrowError(
      expect.objectContaining({ code: 'saml_pending_malformed' }) as Error,
    );
  });

  it('refuses rather than forgets a live entry', () => {
    const store = new InMemoryReplayStore(2);
    expect(store.remember('a', 100, 0)).toBe(true);
    expect(store.remember('b', 100, 0)).toBe(true);
    expect(() => store.remember('c', 100, 0)).toThrowError(
      expect.objectContaining({ code: 'saml_replay_store_full' }) as Error,
    );
    expect(store.remember('c', 300, 150)).toBe(true);
    expect(store.remember('c', 300, 160)).toBe(false);
    expect(store.remember('a', 400, 200)).toBe(true);
  });
});

describe('configuration', () => {
  it.each<[string, Partial<SamlServiceProviderOptions>]>([
    ['http acsUrl', { acsUrl: 'http://app.example.com/acs' }],
    ['not a URL', { acsUrl: 'nope' }],
    ['blank spEntityId', { spEntityId: ' ' }],
    ['leeway too big', { leewayMs: 300_001 }],
    ['negative leeway', { leewayMs: -1 }],
  ])('refuses %s', (_name, options) => {
    expect(() => provider(options)).toThrow(ConfigurationError);
  });

  it('allows a loopback acsUrl over http for development', async () => {
    const sp = provider({ acsUrl: 'http://localhost:8000/saml/acs' });
    expect((await sp.startSignIn()).requestId).toBeTruthy();
  });

  it('exposes the identity provider', () => {
    expect(provider().idp.entityId).toBe(ENTITY);
  });
});

describe('metadata', () => {
  it('lets only the first certificate of a key descriptor sign', async () => {
    const other = await makeSigner('custody');
    const parsed = parseIdpMetadata(idp.metadata({ extraCerts: [other.certB64] }), ENTITY);
    expect(parsed.signingCerts).toEqual([idp.signer.certB64]);
    const sp = new SamlServiceProvider(parsed, { spEntityId: SP_ENTITY, acsUrl: ACS });
    const pending = await sp.startSignIn();
    const forged = idp.response({ now: Date.now(), inResponseTo: pending.requestId, signer: other });
    await refused(sp.finishSignIn(forged, pending), 'saml_signature_invalid');
  });

  it.each([
    ['not xml', 'not xml'],
    ['another element', '<a/>'],
    [
      'no identity provider role',
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${ENTITY}"/>`,
    ],
  ])('refuses metadata that is %s', (_name, xml) => {
    expect(() => parseIdpMetadata(xml, ENTITY)).toThrow(DiscoveryError);
  });

  it('refuses metadata of another entity', () => {
    expect(() =>
      parseIdpMetadata(idp.metadata({ entityId: 'https://evil.authfi.io/saml/metadata' }), ENTITY),
    ).toThrowError(/not this project's/);
  });

  it('refuses metadata with a DTD', () => {
    expect(() => parseIdpMetadata(idp.metadata({ doctype: true }), ENTITY)).toThrowError(/DTD/);
  });

  it('refuses metadata without a signing key or sign-on URL', () => {
    expect(() => parseIdpMetadata(idp.metadata({ use: 'encryption' }), ENTITY)).toThrowError(
      /no signing certificate/,
    );
    expect(() =>
      parseIdpMetadata(idp.metadata({ binding: 'urn:x:artifact' }).replace(idp.ssoUrl, 'ftp://x'), ENTITY),
    ).toThrowError(/no sign-on URL/);
  });

  it('reads the metadata from the project saml route', async () => {
    const fake = new FakeFetch();
    fake.on('GET', `${BASE}/saml/metadata`, () => new Response(idp.metadata(), { status: 200 }));
    const af = new AuthFI({ issuer: BASE, fetch: fake.fetch });
    const sp = await SamlServiceProvider.fromProject(af, { spEntityId: SP_ENTITY, acsUrl: ACS });
    expect(sp.idp.entityId).toBe(ENTITY);
    expect(fake.to(`${BASE}/saml/metadata`)).toHaveLength(1);
    const pending = await sp.startSignIn();
    const signedIn = await sp.finishSignIn(
      idp.response({ now: Date.now(), inResponseTo: pending.requestId }),
      pending,
    );
    expect(signedIn.user.sub).toBe('ada@example.com');
  });

  it('refuses metadata that is not the project', async () => {
    const fake = new FakeFetch();
    fake.on(
      'GET',
      `${BASE}/saml/metadata`,
      () => new Response(idp.metadata({ entityId: 'https://evil.authfi.io/saml/metadata' }), { status: 200 }),
    );
    const af = new AuthFI({ issuer: BASE, fetch: fake.fetch });
    await expect(SamlServiceProvider.fromProject(af, { spEntityId: SP_ENTITY, acsUrl: ACS })).rejects.toThrow(
      DiscoveryError,
    );
  });

  it('reports a metadata route that fails', async () => {
    const fake = new FakeFetch();
    fake.on('GET', `${BASE}/saml/metadata`, () => new Response('', { status: 404 }));
    const af = new AuthFI({ issuer: BASE, fetch: fake.fetch });
    await expect(
      SamlServiceProvider.fromProject(af, { spEntityId: SP_ENTITY, acsUrl: ACS }),
    ).rejects.toMatchObject({
      status: 404,
    });
  });
});
