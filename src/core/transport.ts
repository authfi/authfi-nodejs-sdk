import type { Clock } from './clock.js';
import { fromUtf8 } from './bytes.js';
import { asksForNonce, type DPoPSigner } from './dpop.js';
import { TransportError, type ErrorContext } from './errors.js';
import { freshTraceparent, isValidRequestId, requestId as newRequestId, traceIdOf } from './ids.js';
import { warnOnce, type Logger } from './logger.js';
import type { Secret } from './secret.js';
import { originOf } from './urls.js';

/**
 * How a request may be retried (design §1.2).
 *
 * - `safe`: reads, the client-credentials and agent mints (a fresh assertion per attempt), and any
 *   request carrying an `Idempotency-Key`. Retried on a network failure, 429, 502, 503 and 504.
 * - `unsafe`: a request that may have created state once sent (a code redeemed, a refresh, a CIBA
 *   request, an approval opened, a token exchange, a write without an `Idempotency-Key`). `fetch`
 *   raises the same error for a refused connection and for a failure after the body left, so a
 *   network error is never retried; only 429, and 503 with `Retry-After`, which the platform answers
 *   before doing anything.
 */
export type RetryClass = 'safe' | 'unsafe';

/** The minimal OpenTelemetry API the transport uses to propagate the active trace. */
export interface OpenTelemetryApi {
  readonly context: { active(): unknown };
  readonly propagation: {
    inject(context: unknown, carrier: Record<string, string>, setter?: unknown): void;
  };
}

/** A request body the transport sends as is. */
export type RequestBody = string | URLSearchParams;

/** What one attempt sends, built fresh per attempt by {@link HttpRequest.prepare}. */
export interface PreparedAttempt {
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: RequestBody;
}

/** One logical call. */
export interface HttpRequest {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly url: string;
  readonly retry: RetryClass;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: RequestBody;
  /**
   * Builds the headers and body of each attempt, so a signed value (a client assertion, a DPoP
   * proof) is fresh on every attempt. Its result is merged over {@link headers} and {@link body}.
   */
  readonly prepare?: (attempt: number) => Promise<PreparedAttempt>;
  /** The largest body read, in bytes. Defaults to 1 MiB. */
  readonly maxBytes?: number;
  readonly signal?: AbortSignal | undefined;
  /** The caller's request id; replaced (and logged at debug) when outside the platform's alphabet. */
  readonly requestId?: string | undefined;
  /** Sent as `Idempotency-Key`; makes the request safe to retry. */
  readonly idempotencyKey?: string | undefined;
  /** Signs a fresh DPoP proof per attempt, bound to `accessToken` when one goes with the request. */
  readonly dpop?: { readonly signer: DPoPSigner; readonly accessToken?: Secret | undefined } | undefined;
}

/** The answer to a logical call, after any retries. */
export interface HttpResponse {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Uint8Array;
  readonly url: string;
  /** The answered `X-Request-Id`, or the one sent. */
  readonly requestId: string;
  readonly platformRequestId: string | undefined;
  readonly runId: string | undefined;
  /** A header this request sent whose absence the answer shows (see {@link Transport}). */
  readonly droppedHeader: string | undefined;
}

/** Transport settings. */
export interface TransportSettings {
  readonly fetch: typeof fetch;
  readonly attemptMs: number;
  readonly totalMs: number;
  readonly retries: number;
  readonly logger: Logger;
  readonly clock: Clock;
  readonly userAgent: string | undefined;
  readonly browser: boolean;
  readonly otel: OpenTelemetryApi | undefined;
}

/** The largest JSON answer read, by default. */
export const MAX_JSON_BYTES = 1024 * 1024;
/** The largest discovery document or key set read. */
export const MAX_DOCUMENT_BYTES = 256 * 1024;
const BACKOFF_BASE_MS = 200;
const BACKOFF_CAP_MS = 2000;

/** The error context of an answer, for an error built from it. */
export function contextOf(res: HttpResponse): ErrorContext {
  return {
    status: res.status,
    requestId: res.requestId,
    platformRequestId: res.platformRequestId,
    runId: res.runId,
    droppedHeader: res.droppedHeader,
  };
}

/** The answer's body as text. */
export function textOf(res: HttpResponse): string {
  try {
    return fromUtf8(res.body);
  } catch {
    throw new TransportError('response_invalid', `${res.url} answered a body that is not UTF-8`, {
      ...contextOf(res),
      retryable: false,
    });
  }
}

/** The answer's body as JSON, or a `response_invalid` error. */
export function jsonOf(res: HttpResponse): unknown {
  const text = textOf(res);
  try {
    return text === '' ? undefined : (JSON.parse(text) as unknown);
  } catch {
    throw new TransportError(
      'response_invalid',
      `${res.url} answered HTTP ${String(res.status)} with a body that is not JSON`,
      {
        ...contextOf(res),
        retryable: false,
      },
    );
  }
}

function retryAfterMs(headers: Headers, now: number): number | undefined {
  const value = headers.get('retry-after');
  if (value === null) return undefined;
  if (/^\d+$/.test(value.trim())) return Number(value.trim()) * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}

function statusRetryable(status: number, retry: RetryClass, headers: Headers): boolean {
  if (status === 429) return true;
  if (retry === 'safe') return status === 502 || status === 503 || status === 504;
  return status === 503 && headers.get('retry-after') !== null;
}

async function readCapped(
  res: Response,
  max: number,
  url: string,
  context: ErrorContext,
): Promise<Uint8Array> {
  const tooLarge = (): TransportError =>
    new TransportError('response_too_large', `${url} answered more than ${String(max)} bytes`, {
      ...context,
      retryable: false,
    });
  const declared = Number(res.headers.get('content-length') ?? NaN);
  if (declared > max) {
    await res.body?.cancel();
    throw tooLarge();
  }
  if (res.body === null) return new Uint8Array();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/**
 * The SDK's one HTTP client: timeouts per attempt and per call, the retry table, request and trace
 * ids, the User-Agent, no redirects, capped bodies, and the platform's deprecation headers.
 *
 * The public edge forwards a fixed header set. When a request carried a header and the answer is
 * what that header's absence causes, the answer carries `droppedHeader` and the logger warns once per
 * origin, naming the header: a `DPoP` challenge to a request that sent a proof, `EMDT013` to a request
 * that sent an `Idempotency-Key`, or a `traceparent` answered with another trace id.
 */
export class Transport {
  readonly #settings: TransportSettings;
  readonly #warned = new Set<string>();

  constructor(settings: TransportSettings) {
    this.#settings = settings;
  }

  /** Sends one logical call, retrying it as its class allows. */
  async send(req: HttpRequest): Promise<HttpResponse> {
    const { clock, attemptMs, totalMs, retries, logger } = this.#settings;
    const id = this.#requestId(req.requestId);
    const retry: RetryClass = req.idempotencyKey === undefined ? req.retry : 'safe';
    const deadline = clock.monotonic() + totalMs;
    const traceparent = this.#traceparent();

    let nonceRetried = false;
    for (let attempt = 0; ; attempt++) {
      const remaining = deadline - clock.monotonic();
      if (remaining <= 0) {
        throw new TransportError(
          'timeout',
          `${req.method} ${req.url} did not finish within ${String(totalMs)} ms`,
          {
            requestId: id,
            retryable: retry === 'safe',
          },
        );
      }
      const prepared = req.prepare === undefined ? {} : await req.prepare(attempt);
      const headers = this.#headers(req, prepared, id, traceparent);
      if (req.dpop !== undefined)
        headers.set('dpop', await req.dpop.signer.proof(req.method, req.url, req.dpop.accessToken));
      const body = prepared.body ?? req.body;
      const timeout = AbortSignal.timeout(Math.min(attemptMs, remaining));
      const signal = req.signal === undefined ? timeout : AbortSignal.any([timeout, req.signal]);

      let res: Response;
      try {
        res = await this.#settings.fetch(req.url, {
          method: req.method,
          headers,
          ...(body === undefined ? {} : { body }),
          redirect: 'manual',
          signal,
        });
      } catch (cause) {
        if (req.signal?.aborted) throw req.signal.reason;
        const timedOut = timeout.aborted;
        const error = new TransportError(
          timedOut ? 'timeout' : 'network_error',
          timedOut
            ? `${req.method} ${req.url} timed out after ${String(Math.min(attemptMs, remaining))} ms`
            : `${req.method} ${req.url} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
          { requestId: id, retryable: retry === 'safe', cause },
        );
        const wait =
          retry === 'safe' && attempt < retries
            ? this.#waitBeforeRetry(attempt, undefined, deadline)
            : undefined;
        if (wait === undefined) throw error;
        logger.debug('retrying after a transport failure', {
          url: req.url,
          request_id: id,
          attempt,
          code: error.code,
        });
        await clock.sleep(wait, req.signal);
        continue;
      }

      const context: ErrorContext = { status: res.status, requestId: res.headers.get('x-request-id') ?? id };
      if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
        await res.body?.cancel();
        throw new TransportError(
          'redirect_refused',
          `${req.method} ${req.url} answered a redirect, which the SDK never follows`,
          {
            ...context,
            retryable: false,
          },
        );
      }
      const wait =
        statusRetryable(res.status, retry, res.headers) && attempt < retries
          ? this.#waitBeforeRetry(attempt, retryAfterMs(res.headers, clock.now()), deadline)
          : undefined;
      if (wait !== undefined) {
        await res.body?.cancel();
        logger.debug('retrying after a retryable answer', {
          url: req.url,
          request_id: id,
          attempt,
          status: res.status,
        });
        await clock.sleep(wait, req.signal);
        continue;
      }
      let bytes: Uint8Array;
      try {
        bytes = await readCapped(res, req.maxBytes ?? MAX_JSON_BYTES, req.url, context);
      } catch (cause) {
        if (req.signal?.aborted) throw req.signal.reason;
        if (cause instanceof TransportError) throw cause;
        throw new TransportError('network_error', `${req.method} ${req.url}: the answer was cut off`, {
          ...context,
          retryable: false,
          cause,
        });
      }
      // One more attempt with the server's nonce (RFC 9449 §8); it does not count as a retry.
      if (req.dpop !== undefined && !nonceRetried && asksForNonce(res.status, res.headers, safeText(bytes))) {
        nonceRetried = req.dpop.signer.rememberNonce(req.url, res.headers);
        attempt--;
        continue;
      }
      return this.#finish(req, res, bytes, id, headers);
    }
  }

  #requestId(given: string | undefined): string {
    if (given === undefined) return newRequestId();
    if (isValidRequestId(given)) return given;
    const id = newRequestId();
    this.#settings.logger.debug('replaced a request id the platform would not keep', {
      given_length: given.length,
      request_id: id,
    });
    return id;
  }

  /**
   * The trace headers for a request the SDK does not send itself (a framework's call through the
   * gateway): the active OpenTelemetry trace when the project was given the API, else a fresh one.
   */
  traceHeaders(): Record<string, string> {
    return this.#traceparent();
  }

  #traceparent(): Record<string, string> {
    const { otel, browser } = this.#settings;
    // The edge's CORS allow-list does not admit traceparent yet, so a browser would fail the preflight.
    if (browser) return {};
    if (otel !== undefined) {
      const carrier: Record<string, string> = {};
      otel.propagation.inject(otel.context.active(), carrier);
      if (carrier.traceparent !== undefined) return carrier;
    }
    return { traceparent: freshTraceparent() };
  }

  #headers(req: HttpRequest, prepared: PreparedAttempt, id: string, trace: Record<string, string>): Headers {
    const headers = new Headers({ accept: 'application/json' });
    for (const [k, v] of Object.entries(req.headers ?? {})) headers.set(k, v);
    for (const [k, v] of Object.entries(prepared.headers ?? {})) headers.set(k, v);
    headers.set('x-request-id', id);
    if (this.#settings.userAgent !== undefined) headers.set('user-agent', this.#settings.userAgent);
    for (const [k, v] of Object.entries(trace)) headers.set(k, v);
    if (req.idempotencyKey !== undefined) headers.set('idempotency-key', req.idempotencyKey);
    return headers;
  }

  /** How long to wait before the next attempt (Retry-After, else full-jitter backoff), or undefined when it would pass the deadline. */
  #waitBeforeRetry(attempt: number, after: number | undefined, deadline: number): number | undefined {
    const wait = after ?? Math.random() * Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
    return this.#settings.clock.monotonic() + wait >= deadline ? undefined : wait;
  }

  #finish(req: HttpRequest, res: Response, body: Uint8Array, id: string, sent: Headers): HttpResponse {
    const answer: HttpResponse = {
      status: res.status,
      headers: res.headers,
      body,
      url: req.url,
      requestId: res.headers.get('x-request-id') ?? id,
      platformRequestId: res.headers.get('authfi-request-id') ?? undefined,
      runId: res.headers.get('authfi-run-id') ?? undefined,
      droppedHeader: this.#dropped(req, res, body, sent),
    };
    this.#deprecation(req.url, res.headers);
    return answer;
  }

  #dropped(req: HttpRequest, res: Response, body: Uint8Array, sent: Headers): string | undefined {
    const origin = originOf(req.url) ?? req.url;
    const report = (header: string): string => {
      warnOnce(
        this.#settings.logger,
        this.#warned,
        `dropped:${origin}:${header}`,
        `${origin} answered as if the ${header} header never arrived: an edge or proxy on the path removed it`,
        { header, origin },
      );
      return header;
    };
    const sentTrace = traceIdOf(sent.get('traceparent'));
    const answeredTrace = traceIdOf(res.headers.get('traceparent'));
    if (sentTrace !== undefined && answeredTrace !== undefined && sentTrace !== answeredTrace)
      report('traceparent');
    if (
      res.status === 401 &&
      sent.has('dpop') &&
      /^dpop\b/i.test(res.headers.get('www-authenticate') ?? '')
    ) {
      return report('DPoP');
    }
    if (
      res.status >= 400 &&
      sent.has('idempotency-key') &&
      /"(?:code|error)"\s*:\s*"EMDT013"/.test(safeText(body))
    ) {
      return report('Idempotency-Key');
    }
    return undefined;
  }

  #deprecation(url: string, headers: Headers): void {
    const deprecation = headers.get('deprecation');
    const sunset = headers.get('sunset');
    if (deprecation === null && sunset === null) return;
    const key = url.split('?')[0] ?? url;
    const successor = /<([^>]+)>\s*;\s*rel="?successor-version"?/i.exec(headers.get('link') ?? '')?.[1];
    warnOnce(
      this.#settings.logger,
      this.#warned,
      `deprecated:${key}`,
      `${key} is deprecated by the platform`,
      {
        url: key,
        ...(deprecation === null ? {} : { deprecation }),
        ...(sunset === null ? {} : { sunset }),
        ...(successor === undefined ? {} : { successor }),
      },
    );
  }
}

function safeText(body: Uint8Array): string {
  try {
    return fromUtf8(body);
  } catch {
    return '';
  }
}

/** The User-Agent the transport sends in this runtime, or undefined in a browser (which cannot set one). */
export function runtimeUserAgent(
  sdkVersion: string,
  suffix?: string,
): { userAgent: string | undefined; browser: boolean } {
  const g = globalThis as { EdgeRuntime?: unknown; document?: unknown; navigator?: { userAgent?: string } };
  if (g.document !== undefined) return { userAgent: undefined, browser: true };
  let runtime = 'unknown';
  if (typeof g.EdgeRuntime === 'string') runtime = 'edge-runtime';
  else {
    const m = /^(Node\.js|Deno|Bun|Cloudflare-Workers)(?:\/(\S+))?/.exec(g.navigator?.userAgent ?? '');
    if (m?.[1] !== undefined)
      runtime = `${m[1].toLowerCase().replace('.js', '')}${m[2] === undefined ? '' : ` ${m[2]}`}`;
  }
  const ua = `authfi-node/${sdkVersion} (${runtime})${suffix === undefined ? '' : ` ${suffix}`}`;
  return { userAgent: ua, browser: false };
}
