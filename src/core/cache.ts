import type { Clock } from './clock.js';

/** Resolves as `promise` does, or rejects with the signal's reason when it aborts first. */
export function raceSignal<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) {
    // The caller is gone, but the promise may still reject later; that rejection has no other reader.
    promise.catch(() => undefined);
    return Promise.reject(signal.reason as Error);
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      reject(signal.reason as Error);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

/**
 * Concurrent callers asking for the same key share one in-flight call. A failure is not kept: the
 * next caller starts a new call.
 *
 * The shared call belongs to no caller, so it runs without any caller's `AbortSignal` (the
 * transport's own timeouts still apply), and each caller's `signal` ends that caller's wait only.
 * Handing the first caller's signal to the shared call would let that caller's abort reject every
 * other caller, and abandon a refresh whose rotated token the platform has already issued.
 */
export class SingleFlight<K, V> {
  readonly #inflight = new Map<K, Promise<V>>();

  /**
   * Runs `fn` for `key` unless a call for it is in flight, in which case its result is shared.
   * `signal` stops this caller waiting; it never reaches `fn` or the other callers.
   */
  run(key: K, fn: () => Promise<V>, signal?: AbortSignal): Promise<V> {
    let shared = this.#inflight.get(key);
    if (shared === undefined) {
      shared = fn().finally(() => {
        this.#inflight.delete(key);
      });
      this.#inflight.set(key, shared);
    }
    return raceSignal(shared, signal);
  }
}

/** A loaded document and how long it may be kept, from its `Cache-Control`. */
export interface Loaded<T> {
  readonly value: T;
  readonly maxAgeMs: number | undefined;
}

/** The TTL of a document whose answer gives no `max-age`. */
export const DEFAULT_TTL_MS = 300_000;
const MIN_TTL_MS = 60_000;
const MAX_TTL_MS = 86_400_000;

/** The `max-age` of a `Cache-Control` header in milliseconds; `no-store` and `no-cache` count as 0. */
export function maxAgeOf(cacheControl: string | null): number | undefined {
  if (cacheControl === null) return undefined;
  if (/\bno-(store|cache)\b/i.test(cacheControl)) return 0;
  const m = /\bmax-age\s*=\s*(\d+)/i.exec(cacheControl);
  return m?.[1] === undefined ? undefined : Number(m[1]) * 1000;
}

/** After a failed refresh, how long to wait before trying again while a stale value is still served. */
const STALE_RETRY_MS = 15_000;

/**
 * A document fetched once and kept for its TTL: the answer's `max-age`, clamped to 60 s to 24 h,
 * 300 s when it gives none. Concurrent readers share one fetch, and a failed fetch is never cached.
 *
 * With `staleGraceMs`, a document whose refresh fails is still served for that long past its TTL, and
 * the refresh is retried at most every 15 s: an outage of the issuer's key endpoint does not take every
 * request down with it. With `failureBackoffMs`, a failed load with nothing to serve is remembered for
 * that long, so a flood of requests does not become a flood of fetches against a failing endpoint.
 */
export class CachedDocument<T> {
  readonly #load: () => Promise<Loaded<T>>;
  readonly #clock: Clock;
  readonly #flight = new SingleFlight<0, T>();
  readonly #staleGraceMs: number;
  readonly #failureBackoffMs: number;
  #value: T | undefined;
  #expiresAt = 0;
  #retryAt = 0;
  #failure: { readonly error: Error; readonly until: number } | undefined;

  constructor(
    load: () => Promise<Loaded<T>>,
    clock: Clock,
    options: { staleGraceMs?: number; failureBackoffMs?: number } = {},
  ) {
    this.#load = load;
    this.#clock = clock;
    this.#staleGraceMs = options.staleGraceMs ?? 0;
    this.#failureBackoffMs = options.failureBackoffMs ?? 0;
  }

  /** The document, fetched when absent, expired or when `refresh` is set. */
  get(options: { refresh?: boolean | undefined; signal?: AbortSignal | undefined } = {}): Promise<T> {
    if (options.refresh !== true && this.#value !== undefined && this.#clock.monotonic() < this.#expiresAt) {
      return Promise.resolve(this.#value);
    }
    if (
      options.refresh !== true &&
      this.#value !== undefined &&
      this.#clock.monotonic() < this.#retryAt &&
      this.#clock.monotonic() < this.#expiresAt + this.#staleGraceMs
    ) {
      return Promise.resolve(this.#value);
    }
    if (this.#failure !== undefined && this.#clock.monotonic() < this.#failure.until) {
      return Promise.reject(this.#failure.error);
    }
    return this.#flight.run(
      0,
      async () => {
        let loaded: Loaded<T>;
        try {
          loaded = await this.#load();
        } catch (e) {
          const now = this.#clock.monotonic();
          if (this.#value !== undefined && now < this.#expiresAt + this.#staleGraceMs) {
            this.#retryAt = now + STALE_RETRY_MS;
            return this.#value;
          }
          if (this.#failureBackoffMs > 0)
            this.#failure = {
              error: e instanceof Error ? e : new Error(String(e)),
              until: now + this.#failureBackoffMs,
            };
          throw e;
        }
        this.#retryAt = 0;
        this.#failure = undefined;
        const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, loaded.maxAgeMs ?? DEFAULT_TTL_MS));
        this.#value = loaded.value;
        this.#expiresAt = this.#clock.monotonic() + ttl;
        return loaded.value;
      },
      options.signal,
    );
  }

  /** The cached value, without fetching; undefined before the first successful fetch. */
  peek(): T | undefined {
    return this.#value;
  }
}
