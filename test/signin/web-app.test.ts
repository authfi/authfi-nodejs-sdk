import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { MemoryTokenStore } from '../../src/core/token-set.js';
import { CLIENT_ID, CLIENT_SECRET, FakeIdP, REDIRECT } from '../support/fake-idp.js';
import { json } from '../support/fake-fetch.js';

const STATE_KEY = new Secret(Buffer.alloc(32, 7).toString('base64'));

async function setup(options: { publicClient?: boolean; stepUp?: string[] } = {}) {
  const idp = await FakeIdP.create();
  const af = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch, retries: 0 });
  const web = af.webApp({
    clientId: CLIENT_ID,
    ...(options.publicClient === true ? {} : { clientSecret: new Secret(CLIENT_SECRET) }),
    redirectUri: REDIRECT,
    stateKey: STATE_KEY,
    ...(options.stepUp === undefined ? {} : { stepUpAcrValues: options.stepUp }),
  });
  return { idp, af, web, fake: idp.t.fake };
}

describe('starting a sign-in', () => {
  it('builds the authorize URL with PKCE S256, a fresh state and nonce, and what was asked', async () => {
    const { web, idp } = await setup();
    const pending = await web.startSignIn({
      acrValues: ['urn:authfi:acr:mfa'],
      maxAge: 300,
      loginHint: 'ada@example.com',
      prompt: 'login',
    });
    const u = new URL(pending.url);
    expect(u.origin + u.pathname).toBe(`${idp.issuer}/oauth/authorize`);
    expect(Object.fromEntries(u.searchParams)).toMatchObject({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      scope: 'openid profile email',
      code_challenge_method: 'S256',
      acr_values: 'urn:authfi:acr:mfa',
      max_age: '300',
      login_hint: 'ada@example.com',
      prompt: 'login',
    });
    for (const p of ['state', 'nonce', 'code_challenge'])
      expect(u.searchParams.get(p)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const other = await web.startSignIn();
    expect(new URL(other.url).searchParams.get('state')).not.toBe(u.searchParams.get('state'));
  });

  it('refuses silent sign-in, which the platform does not build', async () => {
    const { web } = await setup();
    await expect(web.startSignIn({ prompt: 'none' as 'login' })).rejects.toMatchObject({
      name: 'NotSupportedError',
      feature: 'prompt_none',
    });
  });

  it('refuses bad settings', async () => {
    const { af } = await setup();
    expect(() => af.webApp({ clientId: '', redirectUri: REDIRECT, stateKey: STATE_KEY })).toThrow('clientId');
    expect(() => af.webApp({ clientId: 'a', redirectUri: 'callback', stateKey: STATE_KEY })).toThrow(
      'redirectUri',
    );
    expect(() =>
      af.webApp({ clientId: 'a', redirectUri: 'http://app.example.com/cb', stateKey: STATE_KEY }),
    ).toThrow('https');
    expect(() =>
      af.webApp({
        clientId: 'a',
        redirectUri: REDIRECT,
        stateKey: STATE_KEY,
        clientSecret: 's' as unknown as Secret,
      }),
    ).toThrow('Secret');
    const shortKey = af.webApp({ clientId: 'a', redirectUri: REDIRECT, stateKey: new Secret('c2hvcnQ=') });
    await expect(shortKey.startSignIn()).rejects.toThrow('must be 32 bytes');
    const notB64 = af.webApp({ clientId: 'a', redirectUri: REDIRECT, stateKey: new Secret('!!!') });
    await expect(notB64.startSignIn()).rejects.toThrow('not base64');
  });
});

describe('the pending sign-in', () => {
  it('is encrypted: neither the verifier, the state nor the nonce is readable', async () => {
    const { web } = await setup();
    const pending = await web.startSignIn();
    const blob = await pending.dump();
    const { state, nonce, verifier } = pending.remembered;
    for (const value of [state, nonce, verifier.reveal()]) {
      expect(blob).not.toContain(value);
      expect(inspect(pending)).not.toContain(value);
      expect(JSON.stringify(pending)).not.toContain(value);
    }
    const back = await web.loadPending(blob);
    expect(back.remembered.state).toBe(state);
    expect(back.url).toBe(pending.url);
  });

  it('refuses a blob that is altered, expired, or from another app or key', async () => {
    const { web, af, idp } = await setup();
    const blob = await (await web.startSignIn()).dump();
    const flipped = `${blob.slice(0, -2)}${blob.endsWith('A') ? 'B' : 'A'}${blob.slice(-1)}`;
    const refused = (code: string) => ({ name: 'InvalidPendingSignIn', code });
    await expect(web.loadPending(flipped)).rejects.toMatchObject(refused('pending_sign_in_tampered'));
    await expect(web.loadPending('v1.!!!')).rejects.toMatchObject(refused('pending_sign_in_malformed'));
    await expect(web.loadPending('nonsense')).rejects.toMatchObject(refused('pending_sign_in_malformed'));
    const otherApp = af.webApp({ clientId: 'app_other', redirectUri: REDIRECT, stateKey: STATE_KEY });
    await expect(otherApp.loadPending(blob)).rejects.toMatchObject(refused('pending_sign_in_tampered'));
    const otherKey = af.webApp({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      stateKey: new Secret(Buffer.alloc(32, 9).toString('base64')),
    });
    await expect(otherKey.loadPending(blob)).rejects.toMatchObject(refused('pending_sign_in_tampered'));
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
    await expect(later.loadPending(blob)).rejects.toMatchObject(refused('pending_sign_in_expired'));
  });

  it('compares the callback iss exactly: a trailing slash is another issuer (RFC 9207)', async () => {
    const { web, idp, fake } = await setup();
    const pending = await web.startSignIn();
    await expect(
      web.finishSignIn(idp.approve(pending.url, { iss: `${idp.issuer}/` }), pending),
    ).rejects.toMatchObject({ name: 'InvalidCallback', code: 'callback_iss_mismatch' });
    expect(fake.to(`${idp.issuer}/oauth/token`)).toHaveLength(0);
  });
});

describe('finishing a sign-in', () => {
  it('exchanges the code with the verifier and returns verified tokens and the person', async () => {
    const { web, idp, fake } = await setup();
    const pending = await web.loadPending(await (await web.startSignIn()).dump());
    const { tokens, user } = await web.finishSignIn(idp.approve(pending.url), pending);
    expect(user).toMatchObject({
      sub: 'usr_ada',
      email: 'ada@example.com',
      emailVerified: true,
      acr: 'urn:authfi:acr:mfa',
    });
    expect(tokens.refreshToken).toBeDefined();
    expect(JSON.stringify(tokens)).not.toContain('eyJ');
    const form = new URLSearchParams(fake.to(`${idp.issuer}/oauth/token`)[0]!.body);
    expect(form.get('redirect_uri')).toBe(REDIRECT);
    expect(form.get('code_verifier')).toBe(pending.remembered.verifier.reveal());
  });

  it('works for a public client with PKCE alone', async () => {
    const { web, idp, fake } = await setup({ publicClient: true });
    const pending = await web.startSignIn();
    await web.finishSignIn(new URL(idp.approve(pending.url)), pending);
    const req = fake.to(`${idp.issuer}/oauth/token`)[0]!;
    expect(req.headers.get('authorization')).toBeNull();
    expect(new URLSearchParams(req.body).get('client_id')).toBe(CLIENT_ID);
  });

  it.each([
    ['no iss', { iss: null }, 'callback_iss_missing'],
    ['another iss', { iss: 'https://evil.authfi.io' }, 'callback_iss_mismatch'],
    ['another state', { state: 'forged' }, 'callback_state_mismatch'],
    ['no state', { state: null }, 'callback_state_mismatch'],
    ['no code', { code: null }, 'callback_code_missing'],
  ])('refuses a callback with %s', async (_what, overrides, code) => {
    const { web, idp, fake } = await setup();
    const pending = await web.startSignIn();
    await expect(web.finishSignIn(idp.approve(pending.url, overrides), pending)).rejects.toMatchObject({
      code,
    });
    expect(fake.to(`${idp.issuer}/oauth/token`)).toHaveLength(0);
  });

  it('maps an error callback, and a step-up the person did not meet', async () => {
    const { web, idp } = await setup({ stepUp: ['urn:authfi:acr:passkey'] });
    const pending = await web.startSignIn();
    await expect(
      web.finishSignIn(
        idp.approve(pending.url, { code: null, error: 'access_denied', error_description: 'no' }),
        pending,
      ),
    ).rejects.toMatchObject({
      name: 'OAuthError',
      code: 'access_denied',
    });
    await expect(
      web.finishSignIn(
        idp.approve(pending.url, { code: null, error: 'unmet_authentication_requirements' }),
        pending,
      ),
    ).rejects.toMatchObject({
      name: 'StepUpRequired',
      acrValues: ['urn:authfi:acr:passkey'],
    });
  });

  it('a code is redeemed once: a second finish is refused and nothing retried', async () => {
    const { web, idp, fake } = await setup();
    const pending = await web.startSignIn();
    const callback = idp.approve(pending.url);
    await web.finishSignIn(callback, pending);
    await expect(web.finishSignIn(callback, pending)).rejects.toMatchObject({ code: 'invalid_grant' });
    expect(fake.to(`${idp.issuer}/oauth/token`)).toHaveLength(2);
  });

  it('checks the ID token: nonce, audience, at_hash, alg, acr and max_age', async () => {
    const cases: [Record<string, unknown>, string, Record<string, unknown>?][] = [
      [{ nonce: 'other' }, 'id_token_nonce_mismatch'],
      [{ aud: 'app_other' }, 'id_token_audience_mismatch'],
      [{ aud: [CLIENT_ID, 'app_other'] }, 'id_token_audience_mismatch'],
      [{ at_hash: 'AAAA' }, 'id_token_at_hash_mismatch'],
      [{ iss: 'https://evil.authfi.io' }, 'id_token_issuer_mismatch'],
      [{ exp: Math.floor(Date.now() / 1000) - 600 }, 'id_token_expired'],
    ];
    for (const [claims, code] of cases) {
      const { web, idp } = await setup();
      idp.idTokenClaims = claims;
      const pending = await web.startSignIn();
      await expect(web.finishSignIn(idp.approve(pending.url), pending)).rejects.toMatchObject({ code });
    }
    const { web, idp } = await setup();
    idp.acr = 'urn:authfi:acr:1fa';
    const asked = await web.startSignIn({ acrValues: ['urn:authfi:acr:mfa'] });
    await expect(web.finishSignIn(idp.approve(asked.url), asked)).rejects.toMatchObject({
      name: 'StepUpRequired',
      acrValues: ['urn:authfi:acr:mfa'],
    });
    idp.authTime = Math.floor(Date.now() / 1000) - 3600;
    const fresh = await web.startSignIn({ maxAge: 300 });
    await expect(web.finishSignIn(idp.approve(fresh.url), fresh)).rejects.toMatchObject({
      name: 'StepUpRequired',
      maxAge: 300,
    });
    idp.authTime = Math.floor(Date.now() / 1000);
    idp.idTokenClaims = { azp: CLIENT_ID, aud: [CLIENT_ID, 'other'] };
    const multi = await web.startSignIn();
    expect((await web.finishSignIn(idp.approve(multi.url), multi)).user.sub).toBe('usr_ada');
  });

  it('refuses an ID token signed with an algorithm discovery does not list for ID tokens', async () => {
    const { web, idp } = await setup();
    idp.t.metadataExtra = { id_token_signing_alg_values_supported: ['ES256'] };
    const pending = await web.startSignIn();
    await expect(web.finishSignIn(idp.approve(pending.url), pending)).rejects.toMatchObject({
      code: 'id_token_alg_refused',
    });
  });

  it('needs an ID token', async () => {
    const { web, idp } = await setup();
    idp.omitIdToken = true;
    const pending = await web.startSignIn();
    await expect(web.finishSignIn(idp.approve(pending.url), pending)).rejects.toThrow('openid');
  });
});

describe('after sign-in', () => {
  async function signedIn() {
    const s = await setup();
    const pending = await s.web.startSignIn();
    const { tokens } = await s.web.finishSignIn(s.idp.approve(pending.url), pending);
    return { ...s, tokens };
  }

  it('refreshes once for concurrent callers, rotating the refresh token', async () => {
    const { web, tokens, idp, fake } = await signedIn();
    const [a, b] = await Promise.all([web.refresh(tokens), web.refresh(tokens)]);
    expect(a).toBe(b);
    expect(a.refreshToken?.reveal()).not.toBe(tokens.refreshToken?.reveal());
    expect(a.idToken).toBe(tokens.idToken);
    expect(fake.to(`${idp.issuer}/oauth/token`).filter((r) => r.body.includes('refresh_token'))).toHaveLength(
      1,
    );
    await expect(web.refresh(tokens)).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('a session refreshes through the store with compare-and-set, so two workers spend one refresh token', async () => {
    const { web, tokens, idp, af } = await signedIn();
    const clock = {
      now: () => Date.now() + 14.5 * 60_000,
      monotonic: () => performance.now(),
      sleep: async () => undefined,
    };
    const later = new AuthFI({ issuer: idp.issuer, fetch: idp.t.fake.fetch, clock }).webApp({
      clientId: CLIENT_ID,
      clientSecret: new Secret(CLIENT_SECRET),
      redirectUri: REDIRECT,
      stateKey: STATE_KEY,
    });
    const store = new MemoryTokenStore();
    await store.compareAndSet('sid-1', undefined, tokens);
    const fresh = af
      .webApp({
        clientId: CLIENT_ID,
        clientSecret: new Secret(CLIENT_SECRET),
        redirectUri: REDIRECT,
        stateKey: STATE_KEY,
      })
      .session({ key: 'sid-1', store });
    expect(await fresh.token()).toBe(tokens.accessToken.reveal());
    const w1 = later.session({ key: 'sid-1', store });
    const w2 = later.session({ key: 'sid-1', store });
    const [t1, t2] = await Promise.all([w1.token(), w2.token()]);
    expect(t1).toBe(t2);
    expect(t1).not.toBe(tokens.accessToken.reveal());
    expect([...idp.families.values()].every((f) => !f.revoked)).toBe(true);
    await expect(later.session({ key: 'nope', store }).token()).rejects.toThrow('the person must sign in again');
    expect(() => web.session({ key: '', store })).toThrow('key is required');
    const toApi = web.session({ key: 'sid-1', store, sendTo: ['https://api.example.com'] });
    expect(toApi.sendTo).toEqual(['https://api.example.com']);
    await expect(fresh.headers('GET', 'https://api.example.com')).rejects.toThrow('refusing to send');
  });

  it('reads userinfo', async () => {
    const { web, tokens } = await signedIn();
    expect(await web.userinfo(tokens)).toMatchObject({
      sub: 'usr_ada',
      email: 'ada@example.com',
      name: 'Ada',
    });
  });

  it('signs out by revoking the refresh token first, then returns the end-session URL', async () => {
    const { web, tokens, idp, fake } = await signedIn();
    const url = await web.signOut(tokens, {
      postLogoutRedirectUri: 'https://app.example.com/bye',
      state: 's1',
    });
    expect(idp.revoked).toEqual([tokens.refreshToken?.reveal()]);
    const revoke = fake.to(`${idp.issuer}/oauth/token/revoke`)[0]!;
    expect(new URLSearchParams(revoke.body).get('token_type_hint')).toBe('refresh_token');
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
      client_id: CLIENT_ID,
      post_logout_redirect_uri: 'https://app.example.com/bye',
      state: 's1',
    });
    await expect(web.refresh(tokens)).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('reports a refused revocation, and refreshing a set with no refresh token', async () => {
    const { web, tokens, idp, fake } = await signedIn();
    fake.on('POST', `${idp.issuer}/oauth/token/revoke`, () => json({ error: 'invalid_client' }, 401));
    await expect(web.signOut(tokens)).rejects.toMatchObject({ code: 'invalid_client' });
    const { TokenSet } = await import('../../src/core/token-set.js');
    await expect(
      web.refresh(new TokenSet({ accessToken: tokens.accessToken, expiresAt: new Date() })),
    ).rejects.toThrow('no refresh token');
    expect(String(web)).toBe(`WebApp(${CLIENT_ID} -> ${REDIRECT})`);
    expect(inspect(web)).not.toContain(CLIENT_SECRET);
  });
});
