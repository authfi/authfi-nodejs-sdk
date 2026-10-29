import { ConfigurationError, TransportError } from '../core/errors.js';
import { apiErrorOf, dataOf } from '../core/oauth.js';
import type { Core } from '../core/project.js';
import { isSecret, type Secret } from '../core/secret.js';
import type { TokenSource } from '../core/token-source.js';
import { contextOf, type HttpResponse } from '../core/transport.js';

/** The canonical path of the regional plane on a project origin. */
const PREFIX = '/apis/regional/v1';

/** What an admin call sends and expects. */
export interface AdminCall {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** The path under `/apis/regional/v1`, with every id already encoded by {@link segment}. */
  readonly path: string;
  readonly query?: Readonly<Record<string, string | number | undefined>> | undefined;
  readonly body?: Readonly<Record<string, unknown>> | undefined;
  /** The statuses that mean success; any other 2xx is a contract change and is raised. */
  readonly ok: readonly number[];
  /** `safe` for a read or a replace that gives the same result twice; `unsafe` for a call that may create or remove. */
  readonly retry: 'safe' | 'unsafe';
  readonly signal?: AbortSignal | undefined;
}

/** Options every admin call takes. */
export interface CallOptions {
  readonly signal?: AbortSignal | undefined;
}

/** A path segment: encoded, so an id can never add a segment or a query. A colon stays readable. */
export function segment(value: string, what: string): string {
  if (typeof value !== 'string' || value === '') throw new ConfigurationError(`${what} is required`);
  return encodeURIComponent(value).replaceAll('%3A', ':');
}

/**
 * The one HTTP seam of the admin client: the project's API origin, the credential's headers (refused
 * for an origin outside its `sendTo`), the SDK transport, and the platform's refusals as `APIError`.
 */
export class AdminHttp {
  readonly #core: Core;
  readonly #credential: TokenSource | Secret;

  constructor(core: Core, credential: TokenSource | Secret) {
    if (!isSecret(credential) && typeof (credential as Partial<TokenSource>).headers !== 'function') {
      throw new ConfigurationError(
        'the admin client needs a credential: a TokenSource such as af.clientCredentials(), or a token in a Secret',
      );
    }
    this.#core = core;
    this.#credential = credential;
  }

  async call(spec: AdminCall): Promise<HttpResponse> {
    const origin = await this.#core.apiOrigin(spec.signal);
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(spec.query ?? {})) {
      if (value !== undefined && value !== '') params.set(key, String(value));
    }
    const query = params.size === 0 ? '' : `?${params.toString()}`;
    const url = `${origin}${PREFIX}${spec.path}${query}`;
    const auth = isSecret(this.#credential)
      ? { authorization: `Bearer ${this.#credential.reveal()}` }
      : await this.#credential.headers(spec.method, url);
    const res = await this.#core.transport.send({
      method: spec.method,
      url,
      retry: spec.retry,
      signal: spec.signal,
      headers: spec.body === undefined ? auth : { ...auth, 'content-type': 'application/json' },
      ...(spec.body === undefined ? {} : { body: JSON.stringify(spec.body) }),
    });
    if (res.status >= 400) throw apiErrorOf(res);
    if (!spec.ok.includes(res.status)) {
      throw new TransportError(
        'response_invalid',
        `${spec.method} ${url} answered HTTP ${String(res.status)}, not ${spec.ok.join(' or ')}`,
        { ...contextOf(res), retryable: false },
      );
    }
    return res;
  }

  /** The `data` of a success answer, which must be an object. */
  async object(spec: AdminCall): Promise<Record<string, unknown>> {
    const res = await this.call(spec);
    return objectOf(dataOf(res), res);
  }

  /** The `data` of a success answer, which must be an array of objects. */
  async array(spec: AdminCall): Promise<Record<string, unknown>[]> {
    const res = await this.call(spec);
    return arrayOf(dataOf(res), res);
  }

  /** The cursor page the platform's list routes answer: `{ data: { data: [...], next_cursor, has_more } }`. */
  async page(spec: AdminCall): Promise<{ items: Record<string, unknown>[]; nextCursor: string | undefined }> {
    const res = await this.call(spec);
    const page = objectOf(dataOf(res), res);
    const next = page.next_cursor;
    return {
      items: arrayOf(page.data, res),
      nextCursor: typeof next === 'string' && next !== '' ? next : undefined,
    };
  }
}

function invalid(res: HttpResponse, what: string): TransportError {
  return new TransportError('response_invalid', `${res.url} answered ${what}`, {
    ...contextOf(res),
    retryable: false,
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function objectOf(value: unknown, res: HttpResponse): Record<string, unknown> {
  if (!isObject(value)) throw invalid(res, 'data that is not an object');
  return value;
}

function arrayOf(value: unknown, res: HttpResponse): Record<string, unknown>[] {
  if (!Array.isArray(value) || !value.every(isObject))
    throw invalid(res, 'data that is not a list of objects');
  return value;
}

/** Fields whose value is the tenant's own JSON and keeps its keys as written. */
const OPAQUE = new Set(['attributes']);

const snake = (key: string): string => key.replaceAll(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
const camel = (key: string): string => key.replaceAll(/_([a-z])/g, (_, c: string) => c.toUpperCase());

/** A request's top-level keys in the platform's spelling. `undefined` members are left out. */
export function toWire(input: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) out[snake(key)] = value;
  }
  return out;
}

/** An answer's top-level keys in camelCase; the tenant's `attributes` object is left as written. */
// The caller names the model the platform's JSON is read as; the shape is the platform's contract.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
export function fromWire<T>(input: Record<string, unknown>): T {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) out[OPAQUE.has(key) ? key : camel(key)] = value;
  return out as T;
}

/** One page of a list. */
export interface Page<T> {
  readonly items: readonly T[];
  /** Pass as `cursor` for the next page; undefined on the last. */
  readonly nextCursor: string | undefined;
  readonly hasMore: boolean;
}

/** Options for a paginated list. */
export interface ListOptions extends CallOptions {
  /** Page size. The platform applies its default and its maximum. */
  readonly limit?: number | undefined;
  /** The `nextCursor` of the previous page. */
  readonly cursor?: string | undefined;
}

/** Every item of a list, fetching pages as the loop asks for them. */
export async function* eachItem<T>(
  fetchPage: (cursor: string | undefined) => Promise<Page<T>>,
  start?: string,
): AsyncGenerator<T, void, undefined> {
  const seen = new Set<string>();
  let cursor = start;
  for (;;) {
    const page = await fetchPage(cursor);
    yield* page.items;
    if (!page.hasMore || page.nextCursor === undefined) return;
    if (seen.has(page.nextCursor) || page.nextCursor === cursor) {
      throw new TransportError(
        'response_invalid',
        'the platform answered a cursor it had already answered; stopping rather than looping',
        { retryable: false },
      );
    }
    seen.add(page.nextCursor);
    cursor = page.nextCursor;
  }
}

/** Builds a {@link Page} from the platform's page. */
export function pageOf<T>(
  raw: {
    items: Record<string, unknown>[];
    nextCursor: string | undefined;
  },
  map: (item: Record<string, unknown>) => T,
): Page<T> {
  return {
    items: raw.items.map(map),
    nextCursor: raw.nextCursor,
    hasMore: raw.nextCursor !== undefined,
  };
}
