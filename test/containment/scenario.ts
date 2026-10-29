// Shared fixture for the containment tests: a project issuer, a PKI (root, intermediate, leaf) whose
// leaf certifies the token signing key, a key set, a DPoP key, and builders for tokens, proofs and
// requests. `scenario()` wires one valid world; a test changes one thing and expects one refusal.

import {
  createHash,
  createHmac,
  constants,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from 'node:crypto';
import assert from 'node:assert/strict';
import { AuthFI, type AuthFIOptions } from '../../src/core/project.js';
import type { Clock } from '../../src/core/clock.js';
import { requestCredentials, type ExpressRequest } from '../../src/express/index.js';
import type { Logger } from '../../src/core/logger.js';
import { AccessToken } from '../../src/verify/access-token.js';
import type { TokenVerifier, VerifierOptions } from '../../src/verify/verifier.js';
import { buildCert, KU, PEN_POLICY, type CertSpec } from './certs.js';

export const T0 = Date.parse('2026-10-26T12:00:00Z');
export const DAY = 86_400_000;
export const ISSUER = 'https://acme.authfi.io';
export const AUD = 'orders-api';
export const PUBLIC = 'https://api.example.com';

export const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString('base64url');
export const sha256 = (b: Uint8Array | string): Buffer => createHash('sha256').update(b).digest();
export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export const ec = (): KeyPair => generateKeyPairSync('ec', { namedCurve: 'P-256' });
export const ed = (): KeyPair => generateKeyPairSync('ed25519');
export const rsa = (bits = 2048): KeyPair => generateKeyPairSync('rsa', { modulusLength: bits });

/** Signs a compact JWS with node:crypto. `payload` may be a ready segment string. */
export function signJWS(
  header: Record<string, unknown>,
  payload: Record<string, unknown> | string,
  privateKey: KeyObject | string | null,
  alg = 'ES256',
): string {
  const h = b64u(JSON.stringify(header));
  const p = typeof payload === 'string' ? payload : b64u(JSON.stringify(payload));
  const data = Buffer.from(`${h}.${p}`);
  let sig: Buffer;
  if (alg === 'ES256')
    sig = sign('sha256', data, { key: privateKey as KeyObject, dsaEncoding: 'ieee-p1363' });
  else if (alg === 'EdDSA') sig = sign(null, data, privateKey as KeyObject);
  else if (alg === 'RS256') sig = sign('sha256', data, privateKey as KeyObject);
  else if (alg === 'PS256')
    sig = sign('sha256', data, {
      key: privateKey as KeyObject,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
  else if (alg === 'HS256')
    sig = createHmac('sha256', privateKey as string)
      .update(data)
      .digest();
  else sig = Buffer.alloc(0);
  return `${h}.${p}.${b64u(sig)}`;
}

/** The RFC 7638 thumbprint of a public key. */
export function thumbprint(publicKey: KeyObject): string {
  const j = publicKey.export({ format: 'jwk' });
  const m =
    j.kty === 'EC'
      ? { crv: j.crv, kty: j.kty, x: j.x, y: j.y }
      : j.kty === 'OKP'
        ? { crv: j.crv, kty: j.kty, x: j.x }
        : { e: j.e, kty: j.kty, n: j.n };
  return b64u(sha256(JSON.stringify(m)));
}

export interface PkiOptions {
  tokenKey?: KeyPair;
  rootKey?: KeyPair;
  interKey?: KeyPair;
  leafCertifies?: KeyObject;
  omitRoot?: boolean;
  rootPolicies?: string[];
  root?: Partial<CertSpec>;
  inter?: Partial<CertSpec>;
  extraInter?: Partial<CertSpec>;
  leaf?: Partial<CertSpec>;
}

/** root -> intermediate -> leaf. Every option is a single fault knob. */
export function makePKI(o: PkiOptions = {}) {
  const root = o.rootKey ?? ec();
  const inter = o.interKey ?? ec();
  const tokenKey = o.tokenKey ?? ec();
  const valid = { notBefore: T0 - 30 * DAY, notAfter: T0 + 300 * DAY };
  const rootDer = buildCert({
    subject: 'Test Root',
    issuer: 'Test Root',
    subjectKey: root.publicKey,
    signerKey: root.privateKey,
    ...valid,
    ca: true,
    keyUsage: KU.keyCertSign | KU.cRLSign,
    policies: o.rootPolicies,
    ...o.root,
  });
  const interDer = buildCert({
    subject: 'Test Intermediate',
    issuer: 'Test Root',
    subjectKey: inter.publicKey,
    signerKey: root.privateKey,
    ...valid,
    ca: true,
    keyUsage: KU.keyCertSign | KU.cRLSign,
    policies: [PEN_POLICY],
    ...o.inter,
  });
  let leafIssuer = 'Test Intermediate';
  let leafSigner = inter.privateKey;
  const mid: Buffer[] = [];
  if (o.extraInter) {
    // a second intermediate between the first and the leaf
    const inter2 = ec();
    mid.push(
      buildCert({
        subject: 'Test Intermediate 2',
        issuer: 'Test Intermediate',
        subjectKey: inter2.publicKey,
        signerKey: inter.privateKey,
        ...valid,
        ca: true,
        keyUsage: KU.keyCertSign | KU.cRLSign,
        policies: [PEN_POLICY],
        ...o.extraInter,
      }),
    );
    leafIssuer = 'Test Intermediate 2';
    leafSigner = inter2.privateKey;
  }
  const leafDer = buildCert({
    subject: 'Test Leaf',
    issuer: leafIssuer,
    subjectKey: o.leafCertifies ?? tokenKey.publicKey,
    signerKey: leafSigner,
    ...valid,
    ca: false,
    keyUsage: KU.digitalSignature,
    policies: [PEN_POLICY],
    ...o.leaf,
  });
  const x5c = [leafDer, ...mid, interDer, ...(o.omitRoot === true ? [] : [rootDer])].map((d) =>
    d.toString('base64'),
  );
  return {
    root,
    inter,
    tokenKey,
    rootDer,
    interDer,
    leafDer,
    x5c,
    rootPin: sha256(root.publicKey.export({ type: 'spki', format: 'der' })).toString('hex'),
    leafThumb: b64u(sha256(leafDer)),
  };
}
export type Pki = ReturnType<typeof makePKI>;

export function jwkOf(publicKey: KeyObject, kid: string, extra: Record<string, unknown> = {}) {
  return { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', ...extra };
}

export function pemOf(der: Buffer): string {
  const body =
    der
      .toString('base64')
      .match(/.{1,64}/g)
      ?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

/** A request in the shape Node gives an Express handler. */
export interface FakeRequest extends ExpressRequest {
  method: string;
  originalUrl: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  rawHeaders?: string[];
}

export interface RequestSpec {
  scheme?: string;
  proofs?: string[];
  proof?: ProofSpec;
  method?: string;
  url?: string;
  headers?: Record<string, string | string[] | undefined>;
}

export interface ProofSpec {
  pair?: KeyPair;
  jwk?: unknown;
  alg?: string;
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
  raw?: string;
}

/** What a scenario is built from. Old option names are kept: a test reads as the guarantee it proves. */
export interface ScenarioOptions {
  pki?: PkiOptions;
  noX5c?: boolean;
  x5cFn?: (pki: Pki) => string[];
  jwksX5t?: string;
  keyExtra?: Record<string, unknown>;
  dpopKey?: KeyPair;
  jwks?: { keys: Record<string, unknown>[] };
  jwksFetch?: (url: string) => Promise<Response>;
  config?: ClientConfig;
  configFn?: (pki: Pki) => ClientConfig;
}

export interface ClientConfig extends Partial<Omit<VerifierOptions, 'audience' | 'rootCerts'>> {
  rootCerts?: string[];
  issuer?: string;
  audience?: string | string[];
  logger?: Partial<Logger>;
  /** Clock leeway in seconds. */
  leeway?: number;
  /** Not a VerifierOptions field: the second argument of the AuthFI constructor. */
  af?: Partial<AuthFIOptions>;
  /** A clock function in epoch ms; defaults to the scenario's. */
  now?: () => number;
}

export interface Client {
  af: AuthFI;
  verifier: TokenVerifier;
  verifyRequest(req: FakeRequest): Promise<Record<string, unknown>>;
  verifyToken(token: string): Promise<Record<string, unknown>>;
  access(req: FakeRequest): Promise<AccessToken>;
}

const full = (part: Partial<Logger> | undefined): Logger => ({
  debug: part?.debug ?? (() => undefined),
  info: part?.info ?? (() => undefined),
  warn: part?.warn ?? (() => undefined),
  error: part?.error ?? (() => undefined),
});

export function scenario(o: ScenarioOptions = {}) {
  const clock = { t: T0 };
  const sdkClock: Clock = {
    now: () => clock.t,
    monotonic: () => clock.t,
    sleep: () => Promise.resolve(),
  };
  const pki = makePKI(o.pki);
  const kid = 'k1';
  const keyExtra = o.noX5c
    ? {}
    : {
        x5c: o.x5cFn ? o.x5cFn(pki) : pki.x5c,
        'x5t#S256': o.jwksX5t ?? pki.leafThumb,
        ...o.keyExtra,
      };
  const keyType = pki.tokenKey.privateKey.asymmetricKeyType;
  const tokenAlg = keyType === 'rsa' ? 'RS256' : keyType === 'ed25519' ? 'EdDSA' : 'ES256';
  const jwks: { keys: Record<string, unknown>[] } = o.jwks ?? {
    keys: [jwkOf(pki.tokenKey.publicKey, kid, { alg: tokenAlg, ...keyExtra })],
  };
  const dpop = o.dpopKey ?? ed();
  const dpopJwk = dpop.publicKey.export({ format: 'jwk' });
  const fetches: string[] = [];
  const fetchOpts: (RequestInit | undefined)[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    fetches.push(url);
    fetchOpts.push(init);
    if (url.endsWith('/.well-known/openid-configuration')) {
      const origin = new URL(url).origin;
      return new Response(
        JSON.stringify({
          issuer: origin,
          token_endpoint: `${origin}/oauth/token`,
          jwks_uri: `${origin}/.well-known/jwks.json`,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (o.jwksFetch) return o.jwksFetch(url);
    return new Response(JSON.stringify(jwks), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'max-age=300' },
    });
  };
  const config: ClientConfig = {
    issuer: ISSUER,
    audience: AUD,
    publicUrl: PUBLIC,
    rootPins: [pki.rootPin],
    ...o.config,
    ...(o.configFn ? o.configFn(pki) : {}),
  };

  /** Builds an SDK client the way a server would, from `config` plus overrides. */
  function build(overrides: ClientConfig = {}): Client {
    const c = { ...config, ...overrides };
    const af = new AuthFI({
      issuer: c.issuer ?? ISSUER,
      fetch: fetchImpl,
      clock: c.now ? { ...sdkClock, now: c.now, monotonic: c.now } : sdkClock,
      logger: full(c.logger),
      leewayMs: c.leeway === undefined ? undefined : c.leeway * 1000,
      ...c.af,
    });
    const { issuer: _i, audience, logger: _l, leeway: _w, af: _a, now: _n, ...rest } = c;
    const verifier = af.verifier({
      audience: audience ?? AUD,
      ...(rest as Partial<VerifierOptions>),
      rootCerts: rest.rootCerts,
    });
    const access = (req: FakeRequest): Promise<AccessToken> =>
      verifier.verifyRequest(requestCredentials(req));
    return {
      af,
      verifier,
      access,
      verifyRequest: async (req) => ({ ...(await access(req)).claims }),
      verifyToken: async (token) => ({ ...(await verifier.verify(token)).claims }),
    };
  }

  const s = {
    clock,
    sdkClock,
    pki,
    kid,
    jwks,
    dpop,
    dpopJwk,
    fetches,
    fetchOpts,
    fetchImpl,
    config,
    build,
    client: undefined as unknown as Client,
    claims: undefined as unknown as (extra?: Record<string, unknown>) => Record<string, unknown>,
    agentClaims: undefined as unknown as (extra?: Record<string, unknown>) => Record<string, unknown>,
    token: undefined as unknown as (
      claims: Record<string, unknown> | string,
      header?: Record<string, unknown>,
      key?: KeyObject,
      alg?: string,
    ) => string,
    agentToken: undefined as unknown as (
      extra?: Record<string, unknown>,
      header?: Record<string, unknown>,
    ) => string,
    proof: undefined as unknown as (token: string, p?: ProofSpec) => string,
    request: undefined as unknown as (token: string | null, o2?: RequestSpec) => FakeRequest,
  };
  s.client = build();

  const sec = (): number => Math.floor(clock.t / 1000);
  s.claims = (extra = {}) => {
    const c: Record<string, unknown> = {
      iss: ISSUER,
      aud: AUD,
      sub: 'usr_1',
      tenant_id: 'tnt_1',
      iat: sec(),
      exp: sec() + 600,
      ...extra,
    };
    for (const k of Object.keys(c)) if (c[k] === undefined) delete c[k];
    return c;
  };
  s.agentClaims = (extra = {}) =>
    s.claims({ sub: 'agt_1', client_id: 'agt_1', cnf: { jkt: thumbprint(dpop.publicKey) }, ...extra });
  s.token = (claims, header = {}, key = pki.tokenKey.privateKey, alg = tokenAlg) => {
    const h: Record<string, unknown> = {
      alg,
      typ: 'at+jwt',
      kid,
      ...(o.noX5c ? {} : { 'x5t#S256': pki.leafThumb }),
      ...header,
    };
    for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
    return signJWS(h, claims, key, alg);
  };
  s.agentToken = (extra = {}, header = {}) => s.token(s.agentClaims(extra), header);

  let jtiN = 0;
  s.proof = (token, p = {}) => {
    const key = p.pair ? p.pair.privateKey : dpop.privateKey;
    const jwk = p.jwk !== undefined ? p.jwk : p.pair ? p.pair.publicKey.export({ format: 'jwk' }) : dpopJwk;
    const alg = p.alg ?? 'EdDSA';
    const claims: Record<string, unknown> = {
      jti: `jti-${String(++jtiN)}-${randomBytes(4).toString('hex')}`,
      htm: 'GET',
      htu: `${PUBLIC}/orders`,
      iat: sec(),
      ath: b64u(sha256(token)),
      ...p.claims,
    };
    for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
    return signJWS({ typ: 'dpop+jwt', alg, jwk, ...p.header }, p.raw ?? claims, key, alg);
  };
  // request builds a request object; the authorization scheme and proofs are parameters.
  s.request = (token, o2 = {}) => {
    const headers: Record<string, string | string[] | undefined> = { host: 'api.example.com', ...o2.headers };
    const raw = ['Host', 'api.example.com'];
    const scheme = o2.scheme ?? 'DPoP';
    if (token !== null) {
      headers.authorization = `${scheme} ${token}`;
      raw.push('Authorization', headers.authorization);
    }
    const proofs = o2.proofs ?? [s.proof(token ?? '', o2.proof)];
    if (proofs.length === 1) headers.dpop = proofs[0];
    else if (proofs.length > 1) headers.dpop = proofs.join(', ');
    for (const p of proofs) raw.push('DPoP', p);
    return {
      method: o2.method ?? 'GET',
      originalUrl: o2.url ?? '/orders',
      url: o2.url ?? '/orders',
      headers,
      rawHeaders: raw,
    };
  };
  return s;
}
export type Scenario = ReturnType<typeof scenario>;

/** Asserts the promise rejects with an SDK error carrying `code`; returns the error. */
export async function rejectsWith(
  promise: Promise<unknown>,
  code: string,
): Promise<Error & Record<string, unknown>> {
  let err: unknown;
  try {
    await promise;
  } catch (e) {
    err = e;
  }
  assert.ok(err, `expected refusal ${code}, got success`);
  const e = err as Error & { code?: string };
  assert.equal(e.code, code, `expected ${code}, got ${String(e.code)}: ${e.message}`);
  return err as Error & Record<string, unknown>;
}
