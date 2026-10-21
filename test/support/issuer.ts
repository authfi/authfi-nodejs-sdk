// A test issuer: real keys of the three types the platform publishes, its discovery document and key
// set served through a FakeFetch, and a signer for tokens of any shape.

import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import type { Clock } from '../../src/core/clock.js';
import { FakeFetch, json } from './fake-fetch.js';

export const ISSUER = 'https://acme.authfi.io';
export const TENANT = '4e46e0c4-ec26-48e1-b5bb-04a1ec3ff358';
export const API = 'api_orders';

export type Alg = 'RS256' | 'EdDSA' | 'ES256';

interface KeyPair {
  readonly kid: string;
  readonly alg: Alg;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JWK;
}

export async function keyPair(alg: Alg, kid: string): Promise<KeyPair> {
  const pair =
    alg === 'EdDSA'
      ? await generateKeyPair('Ed25519', { extractable: true })
      : await generateKeyPair(alg, { extractable: true });
  const publicJwk = { ...(await exportJWK(pair.publicKey)), kid, alg, use: 'sig' };
  return { kid, alg, privateKey: pair.privateKey, publicJwk };
}

/** A clock whose sleeps resolve at once and whose time can be moved. */
export class TestClock implements Clock {
  wall = Date.UTC(2026, 9, 20, 12, 0, 0);
  mono = 1_000_000;
  readonly sleeps: number[] = [];
  now(): number {
    return this.wall;
  }
  monotonic(): number {
    return this.mono;
  }
  sleep(ms: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(signal.reason);
    this.sleeps.push(ms);
    this.advance(ms);
    return Promise.resolve();
  }
  advance(ms: number): void {
    this.wall += ms;
    this.mono += ms;
  }
}

export class TestIssuer {
  readonly fake = new FakeFetch();
  readonly keys: KeyPair[] = [];
  metadataExtra: Record<string, unknown> = {};
  jwksMaxAge = 300;

  private constructor(readonly issuer: string) {}

  static async create(issuer = ISSUER): Promise<TestIssuer> {
    const t = new TestIssuer(issuer);
    t.keys.push(
      await keyPair('RS256', 'rsa-1'),
      await keyPair('EdDSA', 'okp-1'),
      await keyPair('ES256', 'ec-1'),
    );
    t.serve();
    return t;
  }

  metadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      userinfo_endpoint: `${this.issuer}/oauth/userinfo`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      revocation_endpoint: `${this.issuer}/oauth/token/revoke`,
      end_session_endpoint: `${this.issuer}/oauth/logout`,
      backchannel_authentication_endpoint: `${this.issuer}/apis/regional/v1/ai/auth/backchannel-authorize`,
      grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:token-exchange',
        'urn:openid:params:grant-type:ciba',
      ],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'none',
        'private_key_jwt',
      ],
      token_endpoint_auth_signing_alg_values_supported: ['EdDSA', 'ES256', 'PS256'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
      acr_values_supported: ['urn:authfi:acr:1fa', 'urn:authfi:acr:mfa'],
      ...this.metadataExtra,
    };
  }

  serve(): void {
    this.fake.on('GET', `${this.issuer}/.well-known/openid-configuration`, () =>
      json(this.metadata(), 200, { 'cache-control': 'public, max-age=3600' }),
    );
    this.fake.on('GET', `${this.issuer}/.well-known/jwks.json`, () =>
      json({ keys: this.keys.map((k) => k.publicJwk) }, 200, {
        'cache-control': `public, max-age=${this.jwksMaxAge}`,
      }),
    );
  }

  key(alg: Alg): KeyPair {
    const k = this.keys.find((x) => x.alg === alg);
    if (k === undefined) throw new Error(`no ${alg} key`);
    return k;
  }

  /** Signs a token. Defaults make a valid person's access token (T1) for API. */
  async sign(
    claims: Record<string, unknown> = {},
    options: { alg?: Alg; header?: Record<string, unknown>; nowSeconds?: number } = {},
  ): Promise<string> {
    const alg = options.alg ?? 'RS256';
    const key = this.key(alg);
    const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    const body = {
      iss: this.issuer,
      sub: 'usr_123',
      aud: [API],
      exp: now + 900,
      iat: now,
      tenant_id: TENANT,
      client_id: API,
      jti: `jti-${Math.random().toString(36).slice(2)}`,
      ...claims,
    };
    for (const [k, v] of Object.entries(body))
      if (v === undefined) delete (body as Record<string, unknown>)[k];
    return new SignJWT(body)
      .setProtectedHeader({ alg, typ: 'at+jwt', kid: key.kid, ...options.header })
      .sign(key.privateKey);
  }
}

/** A JWT with an arbitrary header and payload and a meaningless signature. */
export function unsignedJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  sig = 'c2ln',
): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64(header)}.${b64(payload)}.${sig}`;
}
