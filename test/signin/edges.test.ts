// Sign-in against refusing and unusual answers: each one a typed error, never a value.

import { describe, expect, it } from 'vitest';
import { isAuthFIError } from '../../src/core/errors.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { MemoryTokenStore, TokenSet } from '../../src/core/token-set.js';
import { json } from '../support/fake-fetch.js';
import { CLIENT_ID, CLIENT_SECRET, FakeIdP, REDIRECT } from '../support/fake-idp.js';
import { unsignedJwt } from '../support/issuer.js';

const STATE_KEY = new Secret(Buffer.alloc(32, 7).toString('base64'));

async function setup(extra: Record<string, unknown> = {}) {
  const idp = await FakeIdP.create();
  idp.t.metadataExtra = extra;
  const af = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch, retries: 0 });
  const web = af.webApp({
    clientId: CLIENT_ID,
    clientSecret: new Secret(CLIENT_SECRET),
    redirectUri: REDIRECT,
    stateKey: STATE_KEY,
    authMethod: 'client_secret_post',
    stepUpAcrValues: ['urn:authfi:acr:mfa'],
  });
  return { idp, af, web, fake: idp.t.fake };
}

describe('callbacks in every shape', () => {
  it('takes the URL, a URL object, its query, its parameters', async () => {
    const { web, idp } = await setup();
    for (const shape of [
      (u: string) => u,
      (u: string) => new URL(u).searchParams,
      (u: string) => Object.fromEntries(new URL(u).searchParams),
      (u: string) => new URL(u).search.slice(1),
    ]) {
      const pending = await web.startSignIn();
      expect((await web.finishSignIn(shape(idp.approve(pending.url)), pending)).user.sub).toBe('usr_ada');
    }
  });

  it('refuses a callback for a sign-in that lapsed', async () => {
    const { web, idp } = await setup();
    const pending = await web.startSignIn();
    const clock = {
      now: () => Date.now() + 11 * 60_000,
      monotonic: () => performance.now(),
      sleep: async () => undefined,
    };
    const later = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch, clock }).webApp({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      stateKey: STATE_KEY,
    });
    await expect(later.finishSignIn(idp.approve(pending.url), pending)).rejects.toThrow('expired');
    expect(String(pending)).toBe(`PendingSignIn(${idp.issuer}/oauth/authorize)`);
    expect(pending.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });
});

describe('the token endpoint asks for a step-up', () => {
  it("carries the app's configured acr", async () => {
    const { web, idp, fake } = await setup();
    fake.on('POST', `${idp.issuer}/oauth/token`, () =>
      json(
        { error: 'insufficient_user_authentication', error_description: 'x (acr: urn:authfi:acr:mfa)' },
        401,
      ),
    );
    const pending = await web.startSignIn();
    await expect(web.finishSignIn(idp.approve(pending.url), pending)).rejects.toMatchObject({
      name: 'StepUpRequired',
      acrValues: ['urn:authfi:acr:mfa'],
    });
  });
});

describe('ID tokens that must be refused', () => {
  async function withIdToken(make: (t: FakeIdP, nonce: string) => Promise<string> | string) {
    const { web, idp, fake } = await setup();
    const pending = await web.startSignIn();
    const callback = idp.approve(pending.url);
    fake.on('POST', `${idp.issuer}/oauth/token`, async () =>
      json({
        access_token: await idp.t.sign(),
        token_type: 'Bearer',
        expires_in: 900,
        id_token: await make(idp, pending.remembered.nonce),
      }),
    );
    return web.finishSignIn(callback, pending);
  }
  const base = (nonce: string) => ({
    sub: 'usr_ada',
    aud: CLIENT_ID,
    nonce,
    tenant_id: undefined,
    client_id: undefined,
  });

  it.each([
    [
      'typ at+jwt',
      (t: FakeIdP, n: string) => t.t.sign(base(n), { header: { typ: 'at+jwt' } }),
      'id_token_not_id_token',
    ],
    [
      'no typ',
      (t: FakeIdP, n: string) => t.t.sign(base(n), { header: { typ: undefined } }),
      'id_token_not_id_token',
    ],
    [
      'typ jwt in lower case',
      (t: FakeIdP, n: string) => t.t.sign(base(n), { header: { typ: 'jwt' } }),
      'id_token_not_id_token',
    ],
    [
      'no kid',
      (_t: FakeIdP, n: string) => unsignedJwt({ alg: 'RS256', typ: 'JWT' }, base(n)),
      'id_token_key_unknown',
    ],
    [
      'an unknown kid',
      (_t: FakeIdP, n: string) => unsignedJwt({ alg: 'RS256', typ: 'JWT', kid: 'nope' }, base(n)),
      'id_token_key_unknown',
    ],
    [
      'alg none',
      (_t: FakeIdP, n: string) => unsignedJwt({ alg: 'none', typ: 'JWT', kid: 'rsa-1' }, base(n)),
      'id_token_alg_refused',
    ],
    [
      'a bad signature',
      (_t: FakeIdP, n: string) => unsignedJwt({ alg: 'RS256', typ: 'JWT', kid: 'rsa-1' }, base(n), 'AAAA'),
      'id_token_signature_invalid',
    ],
    [
      'no exp',
      (t: FakeIdP, n: string) => t.t.sign({ ...base(n), exp: undefined }, { header: { typ: 'JWT' } }),
      'id_token_claims_invalid',
    ],
    [
      'no iat',
      (t: FakeIdP, n: string) => t.t.sign({ ...base(n), iat: undefined }, { header: { typ: 'JWT' } }),
      'id_token_claims_invalid',
    ],
    [
      'an azp naming another app, with one audience',
      (t: FakeIdP, n: string) => t.t.sign({ ...base(n), azp: 'app_other' }, { header: { typ: 'JWT' } }),
      'id_token_audience_mismatch',
    ],
    [
      'a token over 16 KiB',
      (t: FakeIdP, n: string) =>
        t.t.sign({ ...base(n), padding: 'x'.repeat(16 * 1024) }, { header: { typ: 'JWT' } }),
      'id_token_malformed',
    ],
    [
      'iat in the future',
      (t: FakeIdP, n: string) =>
        t.t.sign({ ...base(n), iat: Math.floor(Date.now() / 1000) + 600 }, { header: { typ: 'JWT' } }),
      'id_token_claims_invalid',
    ],
    [
      'no sub',
      (t: FakeIdP, n: string) => t.t.sign({ ...base(n), sub: undefined }, { header: { typ: 'JWT' } }),
      'id_token_claims_invalid',
    ],
  ])('refuses %s as an InvalidIdToken, never an access-token refusal', async (_what, make, code) => {
    const refused = withIdToken(make);
    await expect(refused).rejects.toMatchObject({ code, name: 'InvalidIdToken' });
    await expect(refused).rejects.toSatisfy((e: unknown) => !isAuthFIError(e, 'InvalidToken'));
  });

  it('accepts one without at_hash, and reads a sparse token', async () => {
    const signed = await withIdToken((t, n) => t.t.sign({ ...base(n) }, { header: { typ: 'JWT' } }));
    expect(signed.user).toMatchObject({
      sub: 'usr_ada',
      email: undefined,
      acr: undefined,
      authTime: undefined,
      amr: [],
      groups: [],
    });
  });

  it('checks at_hash with SHA-512 for an EdDSA ID token', async () => {
    const { web, idp, fake } = await setup({ id_token_signing_alg_values_supported: ['EdDSA'] });
    const pending = await web.startSignIn();
    const callback = idp.approve(pending.url);
    const access = await idp.t.sign();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(access)));
    const atHash = Buffer.from(digest.subarray(0, 32)).toString('base64url');
    fake.on('POST', `${idp.issuer}/oauth/token`, async () =>
      json({
        access_token: access,
        expires_in: 900,
        id_token: await idp.t.sign(
          { ...base(pending.remembered.nonce), at_hash: atHash },
          { alg: 'EdDSA', header: { typ: 'JWT' } },
        ),
      }),
    );
    expect((await web.finishSignIn(callback, pending)).user.sub).toBe('usr_ada');
  });
});

describe('what a project may not offer', () => {
  it('no authorization, userinfo, revocation or end-session endpoint', async () => {
    const { web, idp } = await setup({ authorization_endpoint: undefined, userinfo_endpoint: undefined });
    await expect(web.startSignIn()).rejects.toMatchObject({
      name: 'NotSupportedError',
      feature: 'authorization_code',
    });
    const tokens = new TokenSet({ accessToken: new Secret(await idp.t.sign()), expiresAt: new Date() });
    await expect(web.userinfo(tokens)).rejects.toMatchObject({ feature: 'userinfo' });
    idp.t.metadataExtra = { revocation_endpoint: undefined };
    const fresh = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch }).webApp({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      stateKey: STATE_KEY,
    });
    await expect(
      fresh.signOut(
        new TokenSet({
          accessToken: tokens.accessToken,
          refreshToken: new Secret('r'),
          expiresAt: new Date(),
        }),
      ),
    ).rejects.toMatchObject({ feature: 'revocation' });
    await expect(fresh.signOut(tokens)).rejects.toMatchObject({ feature: 'revocation' }); // no refresh token: the access token
    idp.t.metadataExtra = { end_session_endpoint: undefined };
    const other = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch }).webApp({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      stateKey: STATE_KEY,
    });
    await expect(other.signOut(tokens)).rejects.toMatchObject({ feature: 'end_session' });
    expect(idp.revoked).toEqual([]); // nothing was revoked by a sign-out that could not finish
  });

  it('userinfo refusals, and a sign-out of a person with no refresh token', async () => {
    const { web, idp, fake } = await setup();
    const tokens = new TokenSet({ accessToken: new Secret('opaque'), expiresAt: new Date() });
    await expect(web.userinfo(tokens)).rejects.toMatchObject({ code: 'invalid_token' });
    fake.on('GET', `${idp.issuer}/oauth/userinfo`, () => json({ name: 'x' }));
    await expect(web.userinfo(tokens)).rejects.toMatchObject({ code: 'response_invalid' });
    fake.on('GET', `${idp.issuer}/oauth/userinfo`, () => json({ sub: 's' }));
    expect(await web.userinfo(tokens)).toMatchObject({
      sub: 's',
      email: undefined,
      emailVerified: undefined,
      name: undefined,
    });
    expect(await web.signOut(tokens)).toBe(`${idp.issuer}/oauth/logout?client_id=${CLIENT_ID}`);
    expect(idp.revoked).toEqual(['opaque']); // the access token, under its own hint
    expect(idp.revokeHints).toEqual(['access_token']);
  });
});

describe('a session when another worker refreshes first', () => {
  it('uses what the other worker stored, and reports a session signed out meanwhile', async () => {
    const { web, idp } = await setup();
    const pending = await web.startSignIn();
    const { tokens } = await web.finishSignIn(idp.approve(pending.url), pending);
    const stale = new TokenSet({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() - 1000),
    });
    const winner = new TokenSet({
      accessToken: new Secret('winner-token'),
      refreshToken: new Secret('w'),
      expiresAt: new Date(Date.now() + 900_000),
    });
    let loads = 0;
    const store = {
      load: async () => (++loads === 1 ? stale : winner),
      compareAndSet: async () => false,
      delete: async () => undefined,
    };
    expect(await (await web.session(stale, { key: 'sid', store })).token()).toBe('winner-token');
    const again = await web.startSignIn();
    const second = (await web.finishSignIn(idp.approve(again.url), again)).tokens;
    const stale2 = new TokenSet({
      accessToken: second.accessToken,
      refreshToken: second.refreshToken,
      expiresAt: new Date(Date.now() - 1000),
    });
    let calls = 0;
    const gone = { ...store, load: async () => (++calls === 1 ? stale2 : undefined) };
    await expect((await web.session(stale2, { key: 'sid', store: gone })).token()).rejects.toThrow(
      'signed out',
    );
    expect(new MemoryTokenStore()).toBeInstanceOf(MemoryTokenStore);
  });
});
