import { SingleFlight } from '../core/cache.js';
import { ConsentExpired } from '../core/errors.js';
import type { TokenResponse } from '../core/oauth.js';
import type { Core } from '../core/project.js';
import type { Secret } from '../core/secret.js';
import { BaseTokenSource, type TokenOptions } from '../core/token-source.js';
import { principalsOf, type Principal } from '../verify/access-token.js';
import { decodeUnverified } from '../verify/verifier.js';

/** How a delegated token was obtained: CIBA (the person approved on their own device) or token exchange. */
export type DelegationRoute = 'ciba' | 'exchange';

/** Where a delegated token may be sent and how it renews; internal to the SDK. */
export interface DelegatedInit {
  readonly core: Core;
  readonly via: DelegationRoute;
  readonly response: TokenResponse;
  /** The exact origins, or undefined for AuthFI's own (the issuer and the API origin). */
  readonly sendTo: readonly string[] | undefined;
  readonly ownOrigins: () => readonly string[];
  readonly refreshSkewMs: number;
  /** Exchanges again (token exchange only); undefined for CIBA, which only the person can renew. */
  readonly renew: ((signal?: AbortSignal) => Promise<TokenResponse>) | undefined;
}

/**
 * A token an agent holds for a person: its subject is the person and its actor the agent. A
 * {@link TokenSource}, so it goes wherever the agent's own token goes, under the same origin guard.
 *
 * - From token exchange (`via: 'exchange'`) it renews by exchanging again while the person's token
 *   lives, and raises {@link ConsentExpired} after.
 * - From CIBA (`via: 'ciba'`) it never renews: only the person can consent again. It raises
 *   {@link ConsentExpired} a little before expiry, so no call is made on a token about to die.
 *
 * It never prints, serialises or clones its token, and a checkpoint should store an id, never it.
 */
export class DelegatedToken extends BaseTokenSource {
  /** The person the token is for; undefined only for a token the client cannot read. */
  readonly subject: Principal | undefined;
  /** The agent acting for them. */
  readonly actor: Principal | undefined;
  readonly via: DelegationRoute;
  readonly #core: Core;
  readonly #sendTo: readonly string[] | undefined;
  readonly #ownOrigins: () => readonly string[];
  readonly #skew: number;
  readonly #renew: DelegatedInit['renew'];
  readonly #flight = new SingleFlight<0, TokenResponse>();
  #token: Secret;
  #expiresAt: number;
  #scopes: ReadonlySet<string>;

  /** Built by the agent's CIBA and exchange calls. */
  constructor(init: DelegatedInit) {
    super(init.core.fetch);
    this.#core = init.core;
    this.via = init.via;
    this.#sendTo = init.sendTo;
    this.#ownOrigins = init.ownOrigins;
    this.#skew = init.refreshSkewMs;
    this.#renew = init.renew;
    this.#token = init.response.accessToken;
    this.#expiresAt = init.response.expiresAt;
    this.#scopes = new Set(init.response.scope);
    let claims: Record<string, unknown> | undefined;
    try {
      claims = decodeUnverified(init.response.accessToken.reveal()).payload;
    } catch {
      // An opaque token: its subject is unknown to the client, which needs only to send it.
    }
    const parties = claims === undefined ? undefined : principalsOf(claims);
    this.subject = parties?.principal;
    this.actor = parties?.actor;
    if (this.#scopes.size === 0 && typeof claims?.scope === 'string')
      this.#scopes = new Set(claims.scope.split(' ').filter(Boolean));
  }

  /** The origins the token may go to. */
  get sendTo(): readonly string[] {
    return this.#sendTo ?? this.#ownOrigins();
  }

  /** The scopes the token carries: the person's approval intersected with the agent's capabilities. */
  get scopes(): ReadonlySet<string> {
    return this.#scopes;
  }

  /** When the current token expires. */
  get expiresAt(): Date {
    return new Date(this.#expiresAt);
  }

  protected override async ready(signal?: AbortSignal): Promise<void> {
    if (this.#sendTo === undefined) await this.#core.metadata({ signal });
  }

  /** The current token, renewed by exchanging again when it can be; else {@link ConsentExpired}. */
  async token(options: TokenOptions = {}): Promise<string> {
    const now = this.#core.clock.now();
    if (options.force !== true && now < this.#expiresAt - this.#skew) return this.#token.reveal();
    const renew = this.#renew;
    if (renew === undefined) {
      throw new ConsentExpired(
        'expired_token',
        'this token was approved by the person once and is about to expire; ask them again',
      );
    }
    const res = await this.#flight.run(0, () => renew(options.signal));
    this.#token = res.accessToken;
    this.#expiresAt = res.expiresAt;
    if (res.scope.length > 0) this.#scopes = new Set(res.scope);
    return res.accessToken.reveal();
  }

  /** The route and expiry only. */
  override toString(): string {
    return `DelegatedToken(${this.subject?.toString() ?? 'unknown'} by ${this.actor?.toString() ?? 'unknown'} via ${this.via})`;
  }

  toJSON(): { kind: 'delegated_token'; via: DelegationRoute; expires_at: string } {
    return { kind: 'delegated_token', via: this.via, expires_at: new Date(this.#expiresAt).toISOString() };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
