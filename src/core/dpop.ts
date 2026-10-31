import { base64url, fromBase64url, randomBytes, sha256, utf8, fromUtf8 } from './bytes.js';
import type { Clock } from './clock.js';
import { OAuthError } from './errors.js';
import type { Secret } from './secret.js';
import { originOf } from './urls.js';

interface KeyMaterial {
  readonly key: CryptoKey;
  readonly publicJwk: JsonWebKey;
  readonly thumbprint: string;
}

// One key per process (the instance key of release 1): made on first use, held in memory, and
// non-extractable, so nothing can read it back. A worker thread has its own module and so its own key;
// a forked process has its own. A key two processes share is bound to neither.
let processKey: Promise<KeyMaterial> | undefined;

async function makeKey(): Promise<KeyMaterial> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const { kty, crv, x, y } = jwk;
  const publicJwk = { kty, crv, x, y } as JsonWebKey;
  return { key: pair.privateKey, publicJwk, thumbprint: await ecThumbprint(publicJwk) };
}

/** The RFC 7638 thumbprint of an EC P-256 public key, which a bound token names in `cnf.jkt`. */
export async function ecThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
  return base64url(await sha256(utf8(canonical)));
}

/** The RFC 7638 thumbprint of a public JWK this SDK can make (EC P-256, or OKP Ed25519), else undefined. */
export async function jwkThumbprint(jwk: unknown): Promise<string | undefined> {
  if (typeof jwk !== 'object' || jwk === null) return undefined;
  const j = jwk as Record<string, unknown>;
  const str = (n: string): string | undefined => (typeof j[n] === 'string' ? j[n] : undefined);
  if (j.kty === 'EC' && str('crv') !== undefined && str('x') !== undefined && str('y') !== undefined) {
    return base64url(
      await sha256(
        utf8(
          `{"crv":${JSON.stringify(j.crv)},"kty":"EC","x":${JSON.stringify(j.x)},"y":${JSON.stringify(j.y)}}`,
        ),
      ),
    );
  }
  if (j.kty === 'OKP' && str('crv') !== undefined && str('x') !== undefined) {
    return base64url(
      await sha256(utf8(`{"crv":${JSON.stringify(j.crv)},"kty":"OKP","x":${JSON.stringify(j.x)}}`)),
    );
  }
  return undefined;
}

/**
 * Signs RFC 9449 DPoP proofs with the process's one ES256 key (the instance key). The private key is
 * generated non-extractable, so nothing can read it back. A signer is made per project (its own clock
 * and its own server nonces) over the one key.
 */
export class DPoPSigner {
  readonly #material: KeyMaterial;
  readonly #clock: Clock;
  readonly #nonces = new Map<string, string>();

  private constructor(material: KeyMaterial, clock: Clock) {
    this.#material = material;
    this.#clock = clock;
  }

  /** A signer over this process's key, made on first use. */
  static async create(clock: Clock): Promise<DPoPSigner> {
    processKey ??= makeKey();
    return new DPoPSigner(await processKey, clock);
  }

  /** The public key every proof carries. */
  get publicJwk(): JsonWebKey {
    return { ...this.#material.publicJwk };
  }

  /** The RFC 7638 thumbprint of the key. A bound token names it as `cnf.jkt`. */
  get thumbprint(): string {
    return this.#material.thumbprint;
  }

  /** The algorithm the key signs with. */
  readonly alg = 'ES256';

  async #sign(header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> {
    const input = `${base64url(utf8(JSON.stringify(header)))}.${base64url(utf8(JSON.stringify(payload)))}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.#material.key, utf8(input));
    return `${input}.${base64url(new Uint8Array(sig))}`;
  }

  /**
   * A proof for one attempt: `htm`, `htu` without query or fragment, `iat`, a fresh `jti`, `ath`
   * when an access token goes with it, and the origin's last nonce.
   */
  async proof(method: string, url: string, accessToken?: Secret): Promise<string> {
    const u = new URL(url);
    const payload: Record<string, unknown> = {
      htm: method.toUpperCase(),
      htu: `${u.origin}${u.pathname}`,
      iat: Math.floor(this.#clock.now() / 1000),
      jti: base64url(randomBytes(16)),
    };
    if (accessToken !== undefined) payload.ath = base64url(await sha256(utf8(accessToken.reveal())));
    const nonce = this.#nonces.get(u.origin);
    if (nonce !== undefined) payload.nonce = nonce;
    return this.#sign({ typ: 'dpop+jwt', alg: 'ES256', jwk: this.#material.publicJwk }, payload);
  }

  /**
   * A compact JWS of `claims` with this key and `typ` in the header, for the proofs an instance signs
   * (the attestation request's proof, the attestation PoP). It carries no `jwk`: the verifier holds
   * the key from the attestation.
   */
  signJwt(claims: Readonly<Record<string, unknown>>, typ: string): Promise<string> {
    return this.#sign({ typ, alg: 'ES256' }, { ...claims });
  }

  /** Keeps the `DPoP-Nonce` an origin answered, for the next proof to it. Returns whether one was answered. */
  rememberNonce(url: string, headers: Headers): boolean {
    const nonce = headers.get('dpop-nonce');
    const origin = originOf(url);
    if (nonce === null || origin === undefined) return false;
    this.#nonces.set(origin, nonce);
    return true;
  }

  /** The nonce an origin last answered, for tests and logs. */
  nonceFor(url: string): string | undefined {
    const origin = originOf(url);
    return origin === undefined ? undefined : this.#nonces.get(origin);
  }

  /** The key and thumbprint only. */
  toString(): string {
    return `DPoPSigner(ES256 ${this.thumbprint})`;
  }

  toJSON(): { alg: 'ES256'; thumbprint: string } {
    return { alg: 'ES256', thumbprint: this.thumbprint };
  }
}

/** Whether an answer asks for a DPoP nonce (RFC 9449 §8, §9). */
export function asksForNonce(status: number, headers: Headers, body: string): boolean {
  if (status !== 400 && status !== 401) return false;
  if (headers.get('dpop-nonce') === null) return false;
  return (
    (headers.get('www-authenticate') ?? '').includes('use_dpop_nonce') ||
    /"error"\s*:\s*"use_dpop_nonce"/.test(body)
  );
}

/** The `cnf.jkt` an access token names, read without verifying (the client's own token), or undefined. */
export function boundThumbprint(jwt: string): string | undefined {
  try {
    const part = jwt.split('.')[1] ?? '';
    const payload = JSON.parse(fromUtf8(fromBase64url(part))) as { cnf?: { jkt?: unknown } };
    return typeof payload.cnf?.jkt === 'string' ? payload.cnf.jkt : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether a token answer is bound to `signer`'s key: `token_type` DPoP and `cnf.jkt` the key's
 * thumbprint. An answer that is Bearer is not bound (false); a DPoP answer bound to another key is an
 * error, because nobody here can use it.
 */
export function isBoundTo(tokenType: string, accessToken: Secret, signer: DPoPSigner): boolean {
  if (tokenType.toLowerCase() !== 'dpop') return false;
  if (boundThumbprint(accessToken.reveal()) !== signer.thumbprint) {
    throw new OAuthError(
      'dpop_binding_mismatch',
      'the token endpoint bound the token to a key this process does not hold',
      { status: 200 },
    );
  }
  return true;
}
