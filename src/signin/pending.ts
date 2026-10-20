import { base64url, constantTimeEqual, fromBase64url, fromUtf8, randomBytes, utf8 } from '../core/bytes.js';
import { ConfigurationError, InvalidPendingSignIn } from '../core/errors.js';
import { isSecret, Secret } from '../core/secret.js';

/** How long a pending sign-in may wait for its callback. */
export const PENDING_LIFETIME_MS = 10 * 60_000;
const VERSION = 'v1';

/** What a sign-in needs to remember between the redirect and the callback. */
export interface PendingState {
  readonly verifier: Secret;
  readonly state: string;
  readonly nonce: string;
  readonly acrValues: readonly string[];
  readonly maxAge: number | undefined;
  /** Epoch milliseconds. */
  readonly expiresAt: number;
}

const INSPECT = Symbol.for('nodejs.util.inspect.custom');

/**
 * A sign-in between the redirect and the callback: the authorization URL to send the browser to,
 * and the PKCE verifier, `state` and `nonce` the callback is checked against.
 *
 * It must not reach the browser readable (a signed cookie is readable by its holder), so
 * {@link PendingSignIn.dump} encrypts it: store the blob in a cookie or a server-side session, and
 * restore it with `webApp.loadPending(blob)`.
 */
export class PendingSignIn {
  /** Where to redirect the browser. */
  readonly url: string;
  readonly #state: PendingState;
  readonly #key: CryptoKey;
  readonly #aad: Uint8Array<ArrayBuffer>;

  /** Built by `webApp.startSignIn()` and `webApp.loadPending()`. */
  constructor(url: string, state: PendingState, key: CryptoKey, aad: Uint8Array<ArrayBuffer>) {
    this.url = url;
    this.#state = state;
    this.#key = key;
    this.#aad = aad;
  }

  /** The remembered values. Internal to the SDK: the callback check reads them. */
  get remembered(): PendingState {
    return this.#state;
  }

  /** When this sign-in lapses. */
  get expiresAt(): Date {
    return new Date(this.#state.expiresAt);
  }

  /**
   * An opaque blob to store until the callback: AES-256-GCM under the app's `stateKey`, bound to the
   * client and redirect URI, expiring with the sign-in.
   */
  async dump(): Promise<string> {
    const plain = utf8(
      JSON.stringify({
        u: this.url,
        v: this.#state.verifier.reveal(),
        s: this.#state.state,
        n: this.#state.nonce,
        a: this.#state.acrValues,
        m: this.#state.maxAge,
        e: this.#state.expiresAt,
      }),
    );
    const iv = randomBytes(12);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: this.#aad }, this.#key, plain),
    );
    const out = new Uint8Array(iv.length + sealed.length);
    out.set(iv);
    out.set(sealed, iv.length);
    return `${VERSION}.${base64url(out)}`;
  }

  /** The URL only. */
  toString(): string {
    return `PendingSignIn(${this.url.split('?')[0] ?? ''})`;
  }

  toJSON(): { kind: 'pending_sign_in'; expires_at: string } {
    return { kind: 'pending_sign_in', expires_at: new Date(this.#state.expiresAt).toISOString() };
  }

  [INSPECT](): string {
    return this.toString();
  }

  /** Restores a pending sign-in from its blob; refuses one that is expired, from another client or altered. */
  static async load(
    blob: string,
    options: { key: CryptoKey; aad: Uint8Array<ArrayBuffer>; nowMs: number },
  ): Promise<PendingSignIn> {
    const [version, body] = typeof blob === 'string' ? blob.split('.') : [];
    if (version !== VERSION || body === undefined)
      throw new InvalidPendingSignIn(
        'pending_sign_in_malformed',
        'the pending sign-in is not one this SDK wrote',
      );
    let raw: Uint8Array<ArrayBuffer>;
    try {
      raw = fromBase64url(body);
    } catch {
      throw new InvalidPendingSignIn(
        'pending_sign_in_malformed',
        'the pending sign-in is not one this SDK wrote',
      );
    }
    let plain: Uint8Array;
    try {
      plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: raw.subarray(0, 12), additionalData: options.aad },
          options.key,
          raw.subarray(12),
        ),
      );
    } catch {
      throw new InvalidPendingSignIn(
        'pending_sign_in_tampered',
        'the pending sign-in was altered, or belongs to another app or key',
      );
    }
    const d = JSON.parse(fromUtf8(plain)) as {
      u: string;
      v: string;
      s: string;
      n: string;
      a: string[];
      m?: number;
      e: number;
    };
    if (d.e <= options.nowMs)
      throw new InvalidPendingSignIn('pending_sign_in_expired', 'the pending sign-in expired: start again');
    return new PendingSignIn(
      d.u,
      { verifier: new Secret(d.v), state: d.s, nonce: d.n, acrValues: d.a, maxAge: d.m, expiresAt: d.e },
      options.key,
      options.aad,
    );
  }
}

/** Imports the app's `stateKey` (32 random bytes, base64 or base64url) as an AES-256-GCM key. */
export async function importStateKey(stateKey: Secret): Promise<CryptoKey> {
  const how =
    'make one with: node -e "console.log(crypto.getRandomValues(Buffer.alloc(32)).toString(\'base64\'))"';
  if (!isSecret(stateKey))
    throw new ConfigurationError(`stateKey must be a Secret holding 32 random bytes in base64; ${how}`);
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = fromBase64url(
      stateKey.reveal().trim().replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    );
  } catch {
    throw new ConfigurationError(`stateKey is not base64; ${how}`);
  }
  if (bytes.length !== 32)
    throw new ConfigurationError(`stateKey must be 32 bytes, not ${bytes.length}; ${how}`);
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Whether two strings are equal, in time that depends only on their lengths. */
export function sameString(a: string, b: string): boolean {
  return constantTimeEqual(utf8(a), utf8(b));
}
