import { CachedDocument } from './cache.js';
import { systemClock, type Clock } from './clock.js';
import { ConfigurationError } from './errors.js';
import { KeySet } from './jwks.js';
import { consoleLogger, redactingLogger, warnOnce, type LogFields, type Logger } from './logger.js';
import { loadMetadata, type ServerMetadata } from './metadata.js';
import { runtimeUserAgent, Transport, type OpenTelemetryApi } from './transport.js';
import { checkIssuer, checkOrigin, originOf } from './urls.js';
import { SDK_VERSION } from './version.js';

/** Settings for one AuthFI project. Only `issuer` is required; everything else is read from discovery. */
export interface AuthFIOptions {
  /** The project's issuer: `https://<slug>.authfi.io`, or its custom domain. No trailing slash. */
  issuer: string;
  /**
   * The origin of the project's machine APIs (`/apis/...`), for a custom-domain issuer whose APIs
   * stay on the slug host. Without it, the origin of the metadata's
   * `backchannel_authentication_endpoint` is used when present, and the issuer otherwise.
   */
  apiOrigin?: string | undefined;
  /**
   * Timeouts in milliseconds: one per attempt (default 15 000) and one per logical call, retries
   * included (default 30 000). `fetch` has no connect or read phase, so there are no such settings.
   */
  timeout?: { attemptMs?: number | undefined; totalMs?: number | undefined } | undefined;
  /** Retries per call, for the requests that may be retried (default 2). */
  retries?: number | undefined;
  /** Clock leeway when checking token times, in milliseconds (default 60 000; 0 to 300 000). */
  leewayMs?: number | undefined;
  /** The `fetch` to send requests with (a proxy, a test double). Defaults to the global one. */
  fetch?: typeof fetch | undefined;
  /** Where the SDK logs. Defaults to warnings and errors on the console. */
  logger?: Logger | undefined;
  /** Appended to the User-Agent, for example `my-app/1.4`. */
  userAgentSuffix?: string | undefined;
  /**
   * The `@opentelemetry/api` module, to send the active trace as `traceparent`. Without it the SDK
   * sends a fresh, unsampled `traceparent` on each call.
   */
  otel?: OpenTelemetryApi | undefined;
  /** The clock, for tests. */
  clock?: Clock | undefined;
}

/** The project's shared machinery, which every area reaches through {@link coreOf}. */
export interface Core {
  readonly issuer: string;
  readonly transport: Transport;
  readonly logger: Logger;
  readonly clock: Clock;
  readonly leewayMs: number;
  readonly fetch: typeof fetch;
  readonly keys: KeySet;
  metadata(options?: {
    refresh?: boolean | undefined;
    signal?: AbortSignal | undefined;
  }): Promise<ServerMetadata>;
  /** The origin of the project's machine APIs, resolved from discovery when not configured. */
  apiOrigin(signal?: AbortSignal): Promise<string>;
  /** The origins AuthFI's own credentials may go to: the issuer's and the API origin. */
  ownOrigins(signal?: AbortSignal): Promise<readonly string[]>;
  warnOnce(key: string, message: string, fields?: LogFields): void;
}

const cores = new WeakMap<AuthFI, Core>();

/** The core of a project. Internal to the SDK. */
export function coreOf(af: AuthFI): Core {
  const core = cores.get(af);
  if (core === undefined) throw new ConfigurationError('not an AuthFI project built by this SDK');
  return core;
}

function positive(value: number | undefined, fallback: number, what: string): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0)
    throw new ConfigurationError(`${what} must be a positive number of milliseconds`);
  return value;
}

/**
 * One AuthFI project: its issuer, discovery, keys and one HTTP transport. Build one per issuer and
 * process and share it; it owns the caches, so a second instance doubles the fetches. Every area is
 * made from it: `af.verifier()`, `af.clientCredentials()`, `af.agent()`, `af.webApp()`.
 *
 * @example
 * const af = new AuthFI({ issuer: 'https://acme.authfi.io' });
 */
export class AuthFI {
  /** The project's issuer. */
  readonly issuer: string;
  readonly #configuredApiOrigin: string | undefined;
  #learnedApiOrigin: string | undefined;

  constructor(options: AuthFIOptions) {
    const issuer = checkIssuer(options.issuer);
    this.issuer = issuer;
    this.#configuredApiOrigin =
      options.apiOrigin === undefined ? undefined : checkOrigin(options.apiOrigin, 'apiOrigin');
    const attemptMs = positive(options.timeout?.attemptMs, 15_000, 'timeout.attemptMs');
    const totalMs = positive(options.timeout?.totalMs, 30_000, 'timeout.totalMs');
    const retries = options.retries ?? 2;
    if (!Number.isInteger(retries) || retries < 0 || retries > 10)
      throw new ConfigurationError('retries must be an integer from 0 to 10');
    const leewayMs = options.leewayMs ?? 60_000;
    if (!Number.isFinite(leewayMs) || leewayMs < 0 || leewayMs > 300_000) {
      throw new ConfigurationError('leewayMs must be from 0 to 300000');
    }
    const fetchFn = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    const logger = redactingLogger(options.logger ?? consoleLogger);
    const clock = options.clock ?? systemClock;
    const { userAgent, browser } = runtimeUserAgent(SDK_VERSION, options.userAgentSuffix);
    const transport = new Transport({
      fetch: fetchFn,
      attemptMs,
      totalMs,
      retries,
      logger,
      clock,
      userAgent,
      browser,
      otel: options.otel,
    });
    const metadataDoc = new CachedDocument(() => loadMetadata(transport, issuer), clock);
    const warned = new Set<string>();
    const metadata: Core['metadata'] = async (opts = {}) => {
      const doc = await metadataDoc.get(opts);
      this.#learnApiOrigin(doc);
      return doc;
    };
    const apiOrigin = async (signal?: AbortSignal): Promise<string> => {
      if (this.#configuredApiOrigin !== undefined) return this.#configuredApiOrigin;
      await metadata({ signal });
      return this.apiOrigin;
    };
    cores.set(this, {
      issuer,
      transport,
      logger,
      clock,
      leewayMs,
      fetch: fetchFn,
      keys: new KeySet(transport, async () => (await metadata()).jwks_uri, clock, logger),
      metadata,
      apiOrigin,
      ownOrigins: async (signal) => [...new Set([new URL(issuer).origin, await apiOrigin(signal)])],
      warnOnce: (key, message, fields) => {
        warnOnce(logger, warned, key, message, fields);
      },
    });
  }

  /**
   * A project from the environment: `AUTHFI_ISSUER` and, when set, `AUTHFI_API_ORIGIN`. `env`
   * defaults to `process.env` where there is one.
   */
  static fromEnv(
    env?: Readonly<Record<string, string | undefined>>,
    overrides: Partial<AuthFIOptions> = {},
  ): AuthFI {
    const source =
      env ?? (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {};
    const issuer = overrides.issuer ?? source.AUTHFI_ISSUER;
    if (issuer === undefined || issuer === '') {
      throw new ConfigurationError(
        'AUTHFI_ISSUER is not set: set it to the project issuer, such as https://<slug>.authfi.io',
      );
    }
    const apiOrigin =
      overrides.apiOrigin ?? (source.AUTHFI_API_ORIGIN === '' ? undefined : source.AUTHFI_API_ORIGIN);
    return new AuthFI({ ...overrides, issuer, apiOrigin });
  }

  /**
   * The origin of the project's machine APIs: the configured `apiOrigin`, else the one learned from
   * discovery, else the issuer's origin (before discovery has been read).
   */
  get apiOrigin(): string {
    return this.#configuredApiOrigin ?? this.#learnedApiOrigin ?? new URL(this.issuer).origin;
  }

  /** The issuer's metadata, cached for its `max-age`. `refresh` fetches it again. */
  metadata(options: { refresh?: boolean; signal?: AbortSignal } = {}): Promise<ServerMetadata> {
    return coreOf(this).metadata(options);
  }

  #learnApiOrigin(doc: ServerMetadata): void {
    if (this.#learnedApiOrigin !== undefined) return;
    const ciba = doc.backchannel_authentication_endpoint;
    this.#learnedApiOrigin =
      (typeof ciba === 'string' ? originOf(ciba) : undefined) ?? new URL(this.issuer).origin;
  }

  /** The issuer only; nothing secret. */
  toString(): string {
    return `AuthFI(${this.issuer})`;
  }

  toJSON(): { issuer: string } {
    return { issuer: this.issuer };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
