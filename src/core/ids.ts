import { randomBytes } from './bytes.js';

// Request ids join an SDK call to the platform's records. The gateway keeps a caller's id only when
// it is 1-128 characters of [A-Za-z0-9._:-] (mcp callref); any other id is silently dropped, so the
// SDK generates ids inside that alphabet and replaces a caller's id that is outside it.

const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Whether the platform keeps `id` as a request id. */
export function isValidRequestId(id: string): boolean {
  return REQUEST_ID.test(id);
}

function ulid(nowMs: number): string {
  let time = '';
  let t = Math.floor(nowMs);
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD.charAt(t % 32) + time;
    t = Math.floor(t / 32);
  }
  const random = randomBytes(16);
  let rand = '';
  for (let i = 0; i < 16; i++) rand += CROCKFORD.charAt((random[i] ?? 0) % 32);
  return time + rand;
}

/**
 * A fresh request id: `afr-` and a ULID, inside the alphabet the platform keeps. Sent as
 * `X-Request-Id`, the same on every retry of one call.
 */
export function requestId(): string {
  return `afr-${ulid(Date.now())}`;
}

/**
 * A fresh `Idempotency-Key`: a UUIDv7 (RFC 9562), time-ordered. A request that carries one may be
 * retried, because the platform answers the second copy with the first one's result.
 */
export function idempotencyKey(): string {
  const bytes = randomBytes(16);
  const ms = Date.now();
  for (let i = 0; i < 6; i++) bytes[i] = Math.floor(ms / 2 ** (8 * (5 - i))) & 0xff;
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** A W3C `traceparent` for a call with no active trace: fresh ids, sampled flag off. */
export function freshTraceparent(): string {
  const hex = (n: number): string =>
    Array.from(randomBytes(n), (b) => b.toString(16).padStart(2, '0')).join('');
  return `00-${hex(16)}-${hex(8)}-00`;
}

/** The trace id inside a `traceparent`, or undefined when it is not one. */
export function traceIdOf(traceparent: string | null | undefined): string | undefined {
  const m = /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/.exec(traceparent?.trim() ?? '');
  return m?.[1];
}
