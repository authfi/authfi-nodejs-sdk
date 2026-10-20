import { base64url, randomBytes, sha256, utf8 } from './bytes.js';
import type { Clock } from './clock.js';
import type { Secret } from './secret.js';
import { originOf } from './urls.js';

/**
 * Signs RFC 9449 DPoP proofs with one ES256 key per process (the run key of release 1). The private
 * key is generated non-extractable, so nothing can read it back. Not public until mandates (M1) use
 * it; the transport already sends a fresh proof per attempt and retries once on `use_dpop_nonce`.
 */
export class DPoPSigner {
  readonly #key: CryptoKey;
  readonly #publicJwk: JsonWebKey;
  readonly #clock: Clock;
  readonly #nonces = new Map<string, string>();

  private constructor(key: CryptoKey, publicJwk: JsonWebKey, clock: Clock) {
    this.#key = key;
    this.#publicJwk = publicJwk;
    this.#clock = clock;
  }

  /** Generates the process's key pair. */
  static async create(clock: Clock): Promise<DPoPSigner> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const { kty, crv, x, y } = jwk;
    return new DPoPSigner(pair.privateKey, { kty, crv, x, y } as JsonWebKey, clock);
  }

  /** The public key every proof carries. */
  get publicJwk(): JsonWebKey {
    return { ...this.#publicJwk };
  }

  /**
   * A proof for one attempt: `htm`, `htu` without query or fragment, `iat`, a fresh `jti`, `ath`
   * when an access token goes with it, and the origin's last nonce.
   */
  async proof(method: string, url: string, accessToken?: Secret): Promise<string> {
    const u = new URL(url);
    const htu = `${u.origin}${u.pathname}`;
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: this.#publicJwk };
    const payload: Record<string, unknown> = {
      htm: method.toUpperCase(),
      htu,
      iat: Math.floor(this.#clock.now() / 1000),
      jti: base64url(randomBytes(16)),
    };
    if (accessToken !== undefined) payload.ath = base64url(await sha256(utf8(accessToken.reveal())));
    const nonce = this.#nonces.get(u.origin);
    if (nonce !== undefined) payload.nonce = nonce;
    const input = `${base64url(utf8(JSON.stringify(header)))}.${base64url(utf8(JSON.stringify(payload)))}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.#key, utf8(input));
    return `${input}.${base64url(new Uint8Array(sig))}`;
  }

  /** Keeps the `DPoP-Nonce` an origin answered, for the next proof to it. Returns whether one was answered. */
  rememberNonce(url: string, headers: Headers): boolean {
    const nonce = headers.get('dpop-nonce');
    const origin = originOf(url);
    if (nonce === null || origin === undefined) return false;
    this.#nonces.set(origin, nonce);
    return true;
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
