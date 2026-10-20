import type { TokenResponse } from './oauth.js';
import { Secret } from './secret.js';

const INSPECT = Symbol.for('nodejs.util.inspect.custom');

/** The plain form of a {@link TokenSet}, for a {@link TokenStore} that persists it. Holds tokens in clear. */
export interface StoredTokenSet {
  readonly access_token: string;
  readonly refresh_token?: string | undefined;
  readonly id_token?: string | undefined;
  /** Epoch milliseconds. */
  readonly expires_at: number;
  readonly scope: readonly string[];
}

/**
 * The tokens a person's sign-in or refresh returned. Every token is a {@link Secret}; the set
 * prints and serialises as `{ kind, expires_at }` only.
 */
export class TokenSet {
  readonly accessToken: Secret;
  readonly refreshToken: Secret | undefined;
  readonly idToken: Secret | undefined;
  readonly expiresAt: Date;
  readonly scope: readonly string[];

  constructor(init: {
    accessToken: Secret;
    refreshToken?: Secret | undefined;
    idToken?: Secret | undefined;
    expiresAt: Date;
    scope?: readonly string[] | undefined;
  }) {
    this.accessToken = init.accessToken;
    this.refreshToken = init.refreshToken;
    this.idToken = init.idToken;
    this.expiresAt = init.expiresAt;
    this.scope = Object.freeze([...(init.scope ?? [])]);
    Object.freeze(this);
  }

  /** Builds a set from a token endpoint answer. */
  static fromResponse(res: TokenResponse): TokenSet {
    return new TokenSet({
      accessToken: res.accessToken,
      refreshToken: res.refreshToken,
      idToken: res.idToken,
      expiresAt: new Date(res.expiresAt),
      scope: res.scope,
    });
  }

  /** Rebuilds a set a {@link TokenStore} persisted with {@link TokenSet.revealForStorage}. */
  static fromStorage(stored: StoredTokenSet): TokenSet {
    return new TokenSet({
      accessToken: new Secret(stored.access_token),
      refreshToken: stored.refresh_token === undefined ? undefined : new Secret(stored.refresh_token),
      idToken: stored.id_token === undefined ? undefined : new Secret(stored.id_token),
      expiresAt: new Date(stored.expires_at),
      scope: stored.scope,
    });
  }

  /** The tokens in clear, for a store that persists them (encrypt at rest). A reveal point. */
  revealForStorage(): StoredTokenSet {
    return {
      access_token: this.accessToken.reveal(),
      refresh_token: this.refreshToken?.reveal(),
      id_token: this.idToken?.reveal(),
      expires_at: this.expiresAt.getTime(),
      scope: this.scope,
    };
  }

  /** Whether the access token expires within `skewMs` of `nowMs`. */
  expiresWithin(skewMs: number, nowMs: number = Date.now()): boolean {
    return this.expiresAt.getTime() - skewMs <= nowMs;
  }

  toJSON(): { kind: 'token_set'; expires_at: string } {
    return { kind: 'token_set', expires_at: this.expiresAt.toISOString() };
  }

  toString(): string {
    return `TokenSet(expires_at=${this.expiresAt.toISOString()})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

/**
 * Where a person's tokens live between requests, keyed by the app (a session id, a user id). A
 * refresh replaces the set with {@link TokenStore.compareAndSet}, so two workers refreshing the same
 * set cannot both write: the refresh token rotates on every use, and reusing a spent one revokes
 * the whole family.
 */
export interface TokenStore {
  /** The set stored under `key`, or undefined. */
  load(key: string): Promise<TokenSet | undefined>;
  /**
   * Stores `next` under `key` only if the stored set is still `expected` (by its refresh token, or
   * absent when `expected` is undefined). Returns whether it stored.
   */
  compareAndSet(key: string, expected: TokenSet | undefined, next: TokenSet): Promise<boolean>;
  /** Removes the set stored under `key`. */
  delete(key: string): Promise<void>;
}

function sameSet(a: TokenSet | undefined, b: TokenSet | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  if (a === b) return true;
  const ra = a.refreshToken ?? a.accessToken;
  const rb = b.refreshToken ?? b.accessToken;
  return ra.equals(rb);
}

/**
 * A {@link TokenStore} in this process's memory. It is correct for one process only: with several
 * workers or pods, use a shared store whose `compareAndSet` is atomic.
 */
export class MemoryTokenStore implements TokenStore {
  readonly #sets = new Map<string, TokenSet>();

  load(key: string): Promise<TokenSet | undefined> {
    return Promise.resolve(this.#sets.get(key));
  }

  compareAndSet(key: string, expected: TokenSet | undefined, next: TokenSet): Promise<boolean> {
    if (!sameSet(this.#sets.get(key), expected)) return Promise.resolve(false);
    this.#sets.set(key, next);
    return Promise.resolve(true);
  }

  delete(key: string): Promise<void> {
    this.#sets.delete(key);
    return Promise.resolve();
  }
}
