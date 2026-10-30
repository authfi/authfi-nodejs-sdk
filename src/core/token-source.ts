import { asksForNonce, type DPoPSigner } from './dpop.js';
import { ConfigurationError } from './errors.js';
import { Secret } from './secret.js';
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
  /**
   * The headers for one request to `url`: `Authorization: Bearer <token>`, or for a token bound to a
   * key, `Authorization: DPoP <token>` and a `DPoP` proof made for this request. A reveal point;
   * refuses an origin not in {@link sendTo}.
   */
  headers(method: string, url: string | URL): Promise<Record<string, string>>;
  /**
   * The key the current token is bound to (DPoP, RFC 9449), once a token has been minted; undefined
   * for a Bearer token. A caller that sends the request itself answers a server nonce with it.
   */
  readonly dpop?: DPoPSigner | undefined;
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

  /**
   * Runs before the origin check, for a source whose origins come from discovery (a token for
   * AuthFI's own APIs). The default does nothing.
   */
  protected ready(_signal?: AbortSignal): Promise<void> {
    return Promise.resolve();
  }

  /** The key the current token is bound to; undefined (Bearer) unless a source binds its tokens. */
  get dpop(): DPoPSigner | undefined {
    return undefined;
  }

  async headers(method: string, url: string | URL): Promise<Record<string, string>> {
    await this.ready();
    requireAllowedOrigin(url, this.sendTo);
    return credentialHeaders(await this.token(), this.dpop, method, url);
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    await this.ready(request.signal);
    requireAllowedOrigin(request.url, this.sendTo);
    const token = await this.token({ signal: request.signal });
    const key = this.dpop;
    const again = key === undefined ? undefined : request.clone();
    const send = async (r: Request): Promise<Response> => {
      const headers = new Headers(r.headers);
      for (const [k, v] of Object.entries(await credentialHeaders(token, key, r.method, r.url)))
        headers.set(k, v);
      return this.#baseFetch(new Request(r, { headers, redirect: 'error' }));
    };
    const res = await send(request);
    if (key !== undefined && again !== undefined && (await learnNonce(key, request.url, res))) {
      return send(again);
    }
    return res;
  };
}

/**
 * `Authorization` (and `DPoP`) for one request: a proof of `key` over the method, URL and token when the
 * token is bound to it, else Bearer. A proof is good once, so each request makes its own.
 */
export async function credentialHeaders(
  token: string,
  key: DPoPSigner | undefined,
  method: string,
  url: string | URL,
): Promise<Record<string, string>> {
  if (key === undefined) return { authorization: `Bearer ${token}` };
  return { authorization: `DPoP ${token}`, dpop: await key.proof(method, String(url), new Secret(token)) };
}

/**
 * Keeps the nonce a server asked for (RFC 9449 §8) and says whether it did: the caller then sends the
 * request once more with a new proof. The answer is left unread.
 */
export async function learnNonce(key: DPoPSigner, url: string, res: Response): Promise<boolean> {
  if ((res.status !== 400 && res.status !== 401) || res.headers.get('dpop-nonce') === null) return false;
  const body = await res.clone().text();
  if (!asksForNonce(res.status, res.headers, body)) return false;
  await res.body?.cancel();
  return key.rememberNonce(url, res.headers);
}
