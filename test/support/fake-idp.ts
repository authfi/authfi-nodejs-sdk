// A fake identity service for people's sign-in, as identity serves it on main: the code flow with
// PKCE (S256, single-use codes, redirect_uri bound), refresh tokens that rotate on every use and
// revoke the whole family when a spent one is reused, revocation, userinfo and the end-session URL.

import { createHash, randomBytes } from 'node:crypto';
import { base64url } from '../../src/core/bytes.js';
import { json, type Recorded } from './fake-fetch.js';
import { TestIssuer } from './issuer.js';

export const CLIENT_ID = 'app_web';
export const CLIENT_SECRET = 'web-s3cret';
export const REDIRECT = 'https://app.example.com/callback';

interface CodeGrant {
  challenge: string;
  redirectUri: string;
  nonce: string;
  acr: string;
  used: boolean;
}

export class FakeIdP {
  readonly codes = new Map<string, CodeGrant>();
  readonly families = new Map<string, { current: string; revoked: boolean }>();
  readonly revoked: string[] = [];
  acr = 'urn:authfi:acr:mfa';
  authTime = Math.floor(Date.now() / 1000) - 30;
  omitIdToken = false;
  idTokenClaims: Record<string, unknown> = {};

  private constructor(readonly t: TestIssuer) {}

  static async create(): Promise<FakeIdP> {
    const idp = new FakeIdP(await TestIssuer.create());
    idp.serve();
    return idp;
  }

  get issuer(): string {
    return this.t.issuer;
  }

  /** What the sign-in app does: the person signs in, and the browser comes back with a code. */
  approve(authorizeUrl: string, overrides: Record<string, string | null> = {}): string {
    const u = new URL(authorizeUrl);
    const code = base64url(randomBytes(16));
    this.codes.set(code, {
      challenge: u.searchParams.get('code_challenge') ?? '',
      redirectUri: u.searchParams.get('redirect_uri') ?? '',
      nonce: u.searchParams.get('nonce') ?? '',
      acr: this.acr,
      used: false,
    });
    const back = new URL(u.searchParams.get('redirect_uri') ?? REDIRECT);
    const params: Record<string, string | null> = {
      code,
      state: u.searchParams.get('state'),
      iss: this.issuer,
      ...overrides,
    };
    for (const [k, v] of Object.entries(params)) if (v !== null) back.searchParams.set(k, v);
    return back.toString();
  }

  #clientOk(r: Recorded, form: URLSearchParams): boolean {
    const basic = r.headers.get('authorization');
    if (basic?.startsWith('Basic ')) return atob(basic.slice(6)) === `${CLIENT_ID}:${CLIENT_SECRET}`;
    if (form.has('client_secret'))
      return form.get('client_id') === CLIENT_ID && form.get('client_secret') === CLIENT_SECRET;
    return form.get('client_id') === CLIENT_ID;
  }

  async #tokens(nonce: string, acr: string, family: string) {
    const access = await this.t.sign({
      sub: 'usr_ada',
      client_id: CLIENT_ID,
      aud: [CLIENT_ID],
      scope: 'openid profile email',
    });
    const refresh = base64url(randomBytes(24));
    this.families.set(family, { current: refresh, revoked: false });
    const atHash = base64url(createHash('sha256').update(access).digest().subarray(0, 16));
    const id = await this.t.sign(
      {
        sub: 'usr_ada',
        aud: CLIENT_ID,
        nonce,
        at_hash: atHash,
        acr,
        auth_time: this.authTime,
        email: 'ada@example.com',
        email_verified: true,
        name: 'Ada',
        tenant_id: undefined,
        client_id: undefined,
        ...this.idTokenClaims,
      },
      { header: { typ: 'JWT' } },
    );
    return {
      access_token: access,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refresh,
      ...(this.omitIdToken ? {} : { id_token: id }),
      scope: 'openid profile email',
    };
  }

  serve(): void {
    const { fake } = this.t;
    fake.on('POST', `${this.issuer}/oauth/token`, async (r) => {
      const form = new URLSearchParams(r.body);
      if (!this.#clientOk(r, form)) return json({ error: 'invalid_client' }, 401);
      if (form.get('grant_type') === 'authorization_code') {
        const grant = this.codes.get(form.get('code') ?? '');
        if (grant === undefined || grant.used)
          return json({ error: 'invalid_grant', error_description: 'code unknown or used' }, 400);
        grant.used = true;
        if (grant.redirectUri !== form.get('redirect_uri'))
          return json({ error: 'invalid_grant', error_description: 'redirect_uri' }, 400);
        const verifier = form.get('code_verifier') ?? '';
        if (base64url(createHash('sha256').update(verifier).digest()) !== grant.challenge)
          return json({ error: 'invalid_grant', error_description: 'pkce' }, 400);
        return json(await this.#tokens(grant.nonce, grant.acr, base64url(randomBytes(8))));
      }
      if (form.get('grant_type') === 'refresh_token') {
        const token = form.get('refresh_token');
        const family = [...this.families.values()].find((f) => f.current === token && !f.revoked);
        if (family !== undefined) {
          family.current = base64url(randomBytes(24));
          const access = await this.t.sign({ sub: 'usr_ada', client_id: CLIENT_ID, aud: [CLIENT_ID] });
          return json({
            access_token: access,
            token_type: 'Bearer',
            expires_in: 900,
            refresh_token: family.current,
            scope: 'openid profile email',
          });
        }
        // A spent or unknown refresh token: reuse detection revokes the families.
        for (const f of this.families.values()) f.revoked = true;
        return json({ error: 'invalid_grant', error_description: 'refresh token reused' }, 400);
      }
      return json({ error: 'unsupported_grant_type' }, 400);
    });
    fake.on('POST', `${this.issuer}/oauth/token/revoke`, (r) => {
      const form = new URLSearchParams(r.body);
      if (!this.#clientOk(r, form)) return json({ error: 'invalid_client' }, 401);
      const token = form.get('token') ?? '';
      this.revoked.push(token);
      for (const f of this.families.values()) if (f.current === token) f.revoked = true;
      return new Response(null, { status: 200 });
    });
    fake.on('GET', `${this.issuer}/oauth/userinfo`, (r) =>
      r.headers.get('authorization')?.startsWith('Bearer eyJ')
        ? json({ sub: 'usr_ada', email: 'ada@example.com', email_verified: true, name: 'Ada' })
        : json({ error: 'invalid_token' }, 401, { 'www-authenticate': 'Bearer error="invalid_token"' }),
    );
  }
}
