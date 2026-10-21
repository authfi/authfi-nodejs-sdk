import { SingleFlight } from '../core/cache.js';
import { ConfigurationError } from '../core/errors.js';
import { GRANT, requestToken, type ClientAuth, type TokenResponse } from '../core/oauth.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { isSecret, type Secret } from '../core/secret.js';
import { BaseTokenSource, checkSendTo, type TokenOptions } from '../core/token-source.js';

/** How `af.clientCredentials()` is configured. */
export interface ClientCredentialsOptions {
  readonly clientId: string;
  readonly clientSecret: Secret;
  /**
   * The client id of the API the token is for. Without it the token's audience is this client
   * itself, which no API should accept; the SDK warns once.
   */
  readonly resource?: string | undefined;
  /** The exact `https` origins of that API. Required with `resource`; the token goes nowhere else. */
  readonly sendTo?: readonly string[] | undefined;
  /** Scopes to ask for. The platform copies them into the token unchecked; authorize on permissions. */
  readonly scope?: readonly string[] | undefined;
  /** `client_secret_basic` (default) or `client_secret_post`. */
  readonly authMethod?: 'client_secret_basic' | 'client_secret_post' | undefined;
}

/**
 * A machine client's token (OAuth client credentials), cached per (resource, scope) and renewed at
 * two thirds of its lifetime. Concurrent callers share one request. Made by `af.clientCredentials()`.
 *
 * @example
 * const m2m = af.clientCredentials({
 *   clientId: 'app_…', clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET!),
 *   resource: 'api_orders', sendTo: ['https://api.example.com'],
 * });
 * const res = await m2m.fetch('https://api.example.com/orders');
 */
export class ClientCredentials extends BaseTokenSource {
  readonly clientId: string;
  readonly resource: string | undefined;
  readonly scope: readonly string[];
  readonly #af: AuthFI;
  readonly #core: Core;
  readonly #auth: ClientAuth;
  readonly #sendTo: readonly string[];
  readonly #flight = new SingleFlight<0, TokenResponse>();
  #cached: { token: Secret; renewAt: number; expiresAt: number } | undefined;

  /** Use `af.clientCredentials()`. */
  constructor(af: AuthFI, options: ClientCredentialsOptions, internal: { quiet?: boolean } = {}) {
    const core = coreOf(af);
    super(core.fetch);
    this.#af = af;
    this.#core = core;
    if (typeof options.clientId !== 'string' || options.clientId === '')
      throw new ConfigurationError('clientId is required');
    if (!isSecret(options.clientSecret)) {
      throw new ConfigurationError(
        'clientSecret must be a Secret: new Secret(process.env.AUTHFI_CLIENT_SECRET)',
      );
    }
    const method: unknown = options.authMethod ?? 'client_secret_basic';
    if (method !== 'client_secret_basic' && method !== 'client_secret_post') {
      throw new ConfigurationError(
        `authMethod must be client_secret_basic or client_secret_post, not ${String(method)}: a machine ` +
          'client authenticates with its secret (an agent authenticates with its key, af.agent())',
      );
    }
    this.clientId = options.clientId;
    this.resource = options.resource;
    this.scope = Object.freeze([...(options.scope ?? [])]);
    this.#auth = {
      method,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
    };
    const sendTo = checkSendTo(options.sendTo ?? []);
    if (options.resource !== undefined && sendTo.length === 0) {
      throw new ConfigurationError(
        `sendTo is required with resource ${options.resource}: the exact https origin(s) of that API, where the token may go`,
      );
    }
    if (options.resource === undefined && sendTo.length > 0) {
      throw new ConfigurationError(
        'sendTo names an API, but there is no resource: the token would be for this client itself',
      );
    }
    this.#sendTo = sendTo;
    if (options.resource === undefined && internal.quiet !== true) {
      core.warnOnce(
        `cc-no-resource:${options.clientId}`,
        "a client-credentials token without resource names this client as its audience, which no API should accept; set resource to the API's client id",
        { client_id: options.clientId },
      );
    }
  }

  /**
   * The origins the token may go to: the API's (`sendTo`), or, for a token with no resource, the
   * project's own (the management routes). Before discovery has run, the issuer's.
   */
  get sendTo(): readonly string[] {
    if (this.#sendTo.length > 0) return this.#sendTo;
    return [...new Set([new URL(this.#af.issuer).origin, this.#af.apiOrigin])];
  }

  /** Learns the project's API origin before the first origin check of a token with no resource. */
  protected override async ready(signal?: AbortSignal): Promise<void> {
    if (this.#sendTo.length === 0) await this.#core.metadata({ signal });
  }

  /** A current token: cached, renewed at two thirds of its lifetime, minted once for concurrent callers. */
  async token(options: TokenOptions = {}): Promise<string> {
    const now = this.#core.clock.now();
    const cached = this.#cached;
    if (options.force !== true && cached !== undefined && now < cached.renewAt) return cached.token.reveal();
    const res = await this.#flight.run(0, () => this.#mint(), options.signal);
    const lifetime = Math.max(0, res.expiresAt - now);
    this.#cached = { token: res.accessToken, renewAt: now + (lifetime * 2) / 3, expiresAt: res.expiresAt };
    return res.accessToken.reveal();
  }

  /** The shared mint belongs to no caller, so it takes no caller's signal. */
  async #mint(): Promise<TokenResponse> {
    const meta = await this.#core.metadata();
    return requestToken(
      this.#core.transport,
      {
        tokenEndpoint: meta.token_endpoint,
        params: {
          grant_type: GRANT.clientCredentials,
          resource: this.resource,
          scope: this.scope.length > 0 ? this.scope.join(' ') : undefined,
        },
        auth: this.#auth,
        retry: 'safe',
      },
      () => this.#core.clock.now(),
    );
  }

  /** The client id and resource; never the secret or a token. */
  override toString(): string {
    return `ClientCredentials(${this.clientId}${this.resource === undefined ? '' : ` for ${this.resource}`})`;
  }

  toJSON(): { clientId: string; resource: string | undefined } {
    return { clientId: this.clientId, resource: this.resource };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
