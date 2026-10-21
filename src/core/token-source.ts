import { ConfigurationError } from './errors.js';
import { checkOrigin, originOf } from './urls.js';

/** Options for {@link TokenSource.token}. */
export interface TokenOptions {
  /** Mint or renew even when the cached token is still fresh. */
  readonly force?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
}

/**
 * A credential: a machine client's token, an agent's own token, a token held for a person, and in
 * release 1 a mandate. Framework adapters, the gateway helpers and the management client take any
 * TokenSource, which is where the people side and the agent side of the SDK meet.
 *
 * {@link TokenSource.token} and {@link TokenSource.headers} are the two places a credential leaves
 * its `Secret`. Call them inside the request path and keep no reference to the result.
 */
export interface TokenSource {
  /** The exact origins this credential may be sent to. Every other origin is refused. */
  readonly sendTo: readonly string[];
  /** A current access token, minted or renewed as needed. A reveal point. */
  token(options?: TokenOptions): Promise<string>;
  /** The `Authorization` header for one request to `url`. A reveal point; refuses an origin not in {@link sendTo}. */
  headers(method: string, url: string | URL): Promise<Record<string, string>>;
  /**
   * A `fetch` that attaches the credential to each request, refuses any origin not in
   * {@link sendTo}, and refuses to follow redirects.
   */
  readonly fetch: typeof fetch;
}

/** Checks each `sendTo` value is an exact `https` (or loopback `http`) origin, and returns their normal forms. */
export function checkSendTo(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values.map((v) => checkOrigin(v, 'sendTo')))]);
}

/** Refuses a URL whose origin is not one of `allowed`. */
export function requireAllowedOrigin(url: string | URL, allowed: readonly string[]): void {
  const origin = originOf(url);
  if (origin === undefined || !allowed.includes(origin)) {
    throw new ConfigurationError(
      `refusing to send this credential to ${origin ?? String(url)}: it may go only to ${allowed.join(', ') || 'no origin'} (sendTo)`,
    );
  }
}

/**
 * The shared half of every TokenSource the SDK makes: `headers()` and `fetch` on top of `token()`,
 * both guarded by the source's origins. A third-party credential may extend it too.
 */
export abstract class BaseTokenSource implements TokenSource {
  abstract readonly sendTo: readonly string[];
  readonly #baseFetch: typeof fetch;

  /** @param baseFetch the `fetch` requests go through (the project's, by default the global one). */
  protected constructor(baseFetch: typeof fetch) {
    this.#baseFetch = baseFetch;
  }

  abstract token(options?: TokenOptions): Promise<string>;

  async headers(_method: string, url: string | URL): Promise<Record<string, string>> {
    requireAllowedOrigin(url, this.sendTo);
    return { authorization: `Bearer ${await this.token()}` };
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    requireAllowedOrigin(request.url, this.sendTo);
    const headers = new Headers(request.headers);
    headers.set('authorization', `Bearer ${await this.token({ signal: request.signal })}`);
    return this.#baseFetch(new Request(request, { headers, redirect: 'error' }));
  };
}
