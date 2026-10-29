/**
 * The time the SDK reads. Deadlines and backoff use {@link Clock.monotonic}; only token times
 * (`exp`, `iat`, `nbf`) use {@link Clock.now}. Tests inject one; programs never need to.
 */
export interface Clock {
  /** Wall-clock time in milliseconds since the epoch. */
  now(): number;
  /** A monotonic time in milliseconds, for measuring intervals. */
  monotonic(): number;
  /** Resolves after `ms`, or rejects with the signal's reason when it aborts first. */
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

/** Sleeps on `setTimeout`, cancellable by a signal. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason as Error);
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason as Error);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** The clock of the running system. */
export const systemClock: Clock = {
  now: () => Date.now(),
  monotonic: () => performance.now(),
  sleep,
};
