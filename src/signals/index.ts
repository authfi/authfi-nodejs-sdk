/**
 * Revocation signals: stop an agent's tokens the moment AuthFI withdraws it.
 *
 * Access tokens verify offline, so a revoked, suspended or deleted agent keeps working at your API
 * until its token expires, unless AuthFI tells you. AuthFI transmits a signed Shared Signals event
 * (RFC 8935 push) for this. {@link createReceiver} takes it, {@link createRevocationStore} remembers
 * it, and a verifier built with `revocations: store` refuses the withdrawn subject's earlier tokens.
 *
 * @example
 * import { AuthFI } from '@authfi/sdk';
 * import { createReceiver, createRevocationStore } from '@authfi/sdk/signals';
 *
 * const af = AuthFI.fromEnv();
 * const revocations = createRevocationStore({ tokenLifetimeSeconds: 86_400 });
 * const verifier = af.verifier({ audience: 'api_orders', publicUrl: 'https://api.example.com', revocations });
 * app.post('/ssf/push', createReceiver(af, { revocations, audience: 'my-stream' }));
 *
 * @packageDocumentation
 */

import { compactVerify } from 'jose';
import { constantTimeEqual, fromBase64urlStrict, fromUtf8, sha256, utf8 } from '../core/bytes.js';
import { ConfigurationError } from '../core/errors.js';
import { coreOf, type AuthFI } from '../core/project.js';
import type { RevocationStore } from '../verify/verifier.js';

const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_SUBJECT_LENGTH = 512;
const MAX_JTI_LENGTH = 256;
const MAX_NUMERIC_DATE = 253_402_300_799; // 9999-12-31T23:59:59Z
const EVICT_FRACTION = 10;
const SET_TYP = 'secevent+jwt';
const SET_CONTENT_TYPE = 'application/secevent+jwt';
const LEEWAY_SECONDS = 60;
const MAX_SET_BYTES = 16 * 1024;
const REGISTER_TIMEOUT_MS = 10_000;

/** The event types a receiver acts on. */
export const EVENTS = Object.freeze({
  SESSION_REVOKED: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  TOKEN_CLAIMS_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
  ACCOUNT_PURGED: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  CREDENTIAL_COMPROMISE: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
});
const REVOKING = new Set<string>([
  EVENTS.SESSION_REVOKED,
  EVENTS.ACCOUNT_PURGED,
  EVENTS.CREDENTIAL_COMPROMISE,
]);

/** What {@link createRevocationStore} is configured with. */
export interface RevocationStoreOptions {
  /** The most subjects remembered (default 100 000). */
  readonly maxEntries?: number | undefined;
  /** The longest token lifetime to cover, in seconds (default 86 400): a revocation is forgotten after it. */
  readonly tokenLifetimeSeconds?: number | undefined;
  /** The clock in epoch milliseconds, for tests. */
  readonly clock?: (() => number) | undefined;
}

/** A bounded memory of withdrawn subjects: see {@link createRevocationStore}. */
export interface MemoryRevocationStore extends RevocationStore {
  /**
   * Records that tokens of `subject` issued at or before `at` (Unix seconds) are dead. A later call
   * with an earlier time changes nothing. Returns how many other subjects were dropped to make room;
   * zero in normal operation. `ref` is the decision's reference: the `jti` of the event that withdrew
   * the subject, carried by the refusal.
   */
  revoke(subject: string, at: number, ref?: string): number;
  /**
   * Whether a token of `subject` issued at `issuedAt` is revoked. An unknown issue time counts as
   * older than every revocation: it cannot be shown to be newer.
   */
  isRevoked(subject: string, issuedAt: number | undefined): boolean;
  /** Subjects remembered, expired ones included until they are next swept. */
  readonly size: number;
  /** The most subjects the store remembers. */
  readonly maxEntries: number;
}

function seconds(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

interface Entry {
  readonly at: number;
  readonly ref: string;
}

/**
 * A bounded map from subject to the time before which its tokens are dead. A revocation means:
 * tokens of this subject issued at or before the event's `iat` are refused. A token issued after it is
 * fine, which is why a resumed agent needs no "lift": its new token is newer.
 *
 * When it is full it drops the oldest revocations and raises a floor: every token issued at or before
 * the newest dropped revocation is then refused whatever its subject. A full store costs some holders
 * a new token and never lets a revoked one through. It lives in memory: a restart empties it.
 */
export function createRevocationStore(options: RevocationStoreOptions = {}): MemoryRevocationStore {
  const requestedMax = options.maxEntries ?? 0;
  const max = Number.isInteger(requestedMax) && requestedMax > 0 ? requestedMax : DEFAULT_MAX_ENTRIES;
  const requestedLife = options.tokenLifetimeSeconds ?? 0;
  const life = requestedLife > 0 ? Math.floor(requestedLife) : DEFAULT_TOKEN_LIFETIME_SECONDS;
  const clock = options.clock ?? Date.now;
  const notBefore = new Map<string, Entry>();
  let floor = 0;
  let floorRef = '';
  const nowSeconds = (): number => Math.floor(clock() / 1000);

  function makeRoom(now: number): number {
    for (const [subject, entry] of notBefore) {
      if (entry.at + life <= now) notBefore.delete(subject);
    }
    if (notBefore.size < max) return 0;
    const oldest = [...notBefore.entries()].sort((a, b) => a[1].at - b[1].at);
    const n = Math.min(Math.floor(max / EVICT_FRACTION) + 1, oldest.length);
    for (const [subject] of oldest.slice(0, n)) notBefore.delete(subject);
    const newest = oldest[n - 1];
    if (newest !== undefined && newest[1].at > floor) {
      floor = newest[1].at;
      floorRef = newest[1].ref;
    }
    return n;
  }

  const store: MemoryRevocationStore = {
    revoke(subject, at, ref = '') {
      const t = seconds(at);
      if (typeof subject !== 'string' || subject === '' || t === null) return 0;
      const now = nowSeconds();
      if (t + life <= now) return 0; // every token this could refuse has already expired
      const current = notBefore.get(subject);
      if (current !== undefined) {
        if (t > current.at) notBefore.set(subject, { at: t, ref });
        return 0;
      }
      const dropped = notBefore.size >= max ? makeRoom(now) : 0;
      notBefore.set(subject, { at: t, ref });
      return dropped;
    },
    isRevoked(subject, issuedAt) {
      return store.find(subject, issuedAt ?? Number.NaN) !== null;
    },
    find(subject, issuedAt) {
      const now = nowSeconds();
      const iat = seconds(issuedAt) === null ? Number.NEGATIVE_INFINITY : issuedAt;
      if (floor !== 0 && floor + life > now && iat <= floor) return { ref: floorRef };
      const entry = notBefore.get(subject);
      if (entry === undefined || entry.at + life <= now) return null;
      return iat <= entry.at ? { ref: entry.ref } : null;
    },
    get size() {
      return notBefore.size;
    },
    get maxEntries() {
      return max;
    },
    get tokenLifetimeSeconds() {
      return life;
    },
  };
  return store;
}

/** A bounded set of recently accepted `jti` values. */
export class SeenSet {
  readonly #seen = new Map<string, number>(); // jti -> expiry in Unix seconds; insertion order is expiry order
  readonly #max: number;
  readonly #lifeSeconds: number;
  readonly #clock: () => number;

  constructor(max: number, lifeSeconds: number, clock: () => number) {
    this.#max = max;
    this.#lifeSeconds = lifeSeconds;
    this.#clock = clock;
  }

  /** Records `jti`; false when it was already there. The oldest id is forgotten when full. */
  claim(jti: string): boolean {
    const now = Math.floor(this.#clock() / 1000);
    for (const [id, expires] of this.#seen) {
      if (expires > now) break;
      this.#seen.delete(id);
    }
    if (this.#seen.has(jti)) return false;
    if (this.#seen.size >= this.#max) {
      const oldest = this.#seen.keys().next();
      if (oldest.done !== true) this.#seen.delete(oldest.value);
    }
    this.#seen.set(jti, now + this.#lifeSeconds);
    return true;
  }
}

/** What the receiver hands `onSignal` for each event it acted on. */
export interface Signal {
  /** The event type URI. */
  readonly event: string;
  /** The subject the event is about, such as `agent:agt_42`. */
  readonly subject: string;
  /** The `jti` of the event. */
  readonly jti: string;
  /** The event's `iat`, in Unix seconds. */
  readonly issuedAt: number;
  /** Whether the event revoked the subject. */
  readonly revoked: boolean;
  /** Whether the event is a `token-claims-change` with `resumed: true`. */
  readonly resumed: boolean;
}

/** How to build a receiver. */
export interface ReceiverOptions {
  /** Where revocations are recorded; give the same store to the verifier. */
  readonly revocations: MemoryRevocationStore;
  /** The audience the stream was registered with. Events for another stream are refused. */
  readonly audience: string;
  /** The bearer AuthFI sends on each push, when the stream was registered with one. Without it no bearer is required. */
  readonly authToken?: string | undefined;
  /** Called for each event acted on, after it was recorded. A throw is logged and the revocation stands. */
  readonly onSignal?: ((signal: Signal) => void | Promise<void>) | undefined;
}

/** The parts of a Node `IncomingMessage` (or Express request) the receiver reads. */
export interface PushRequest {
  readonly method?: string | undefined;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /** A body a parser already read: a string or a byte array is taken as the raw SET. */
  readonly body?: unknown;
  readonly readableEnded?: boolean | undefined;
  on(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
  on(event: 'error', listener: (error: unknown) => void): unknown;
}

/** The parts of a Node `ServerResponse` (or Express response) the receiver writes. */
export interface PushResponse {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

class SetError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SetError';
    this.code = code;
  }
}

type Failure = readonly [status: number, err: string, description: string];

function trimSlash(value: unknown): string {
  return typeof value === 'string' ? value.trim().replace(/\/+$/, '') : '';
}

function validDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_NUMERIC_DATE;
}

function mediaType(header: string | string[] | undefined): string {
  const value = Array.isArray(header) ? (header[0] ?? '') : (header ?? '');
  return (value.split(';')[0] ?? '').trim().toLowerCase();
}

function subjectOf(subId: unknown, issuer: string): string | null {
  if (typeof subId !== 'object' || subId === null) return null;
  const id = subId as Record<string, unknown>;
  let subject: unknown = null;
  if (id.format === 'opaque') subject = id.id;
  else if (id.format === 'iss_sub' && trimSlash(id.iss) === issuer) subject = id.sub;
  if (typeof subject !== 'string' || subject === '' || subject.length > MAX_SUBJECT_LENGTH) return null;
  return subject;
}

/** Maps a JWS-layer failure to RFC 8935 §2.4. A key set that cannot be read is a 503. */
function mapSetError(err: unknown): Failure {
  switch ((err as { code?: unknown } | undefined)?.code) {
    case 'key_set_unavailable':
      return [503, 'temporarily_unavailable', "the issuer's keys could not be read"];
    case 'unknown_key':
      // The key may be one the issuer rotated in since the last (throttled) fetch. A 400 is final
      // for the transmitter and would lose this revocation, so ask for a retry.
      return [503, 'temporarily_unavailable', "the signing key is not in the issuer's key set (yet)"];
    case 'bad_signature':
      return [400, 'authentication_failed', 'the signature does not verify'];
    case 'alg_not_allowed':
    case 'alg_key_mismatch':
    case 'kid_required':
    case 'crit_not_supported':
      return [400, 'invalid_key', 'the key or algorithm of the SET is not accepted'];
    case 'malformed':
    case 'typ_invalid':
      return [400, 'invalid_request', `the SET is not a well-formed ${SET_TYP}`];
    default:
      return [503, 'temporarily_unavailable', 'the SET could not be checked now'];
  }
}

function readBody(req: PushRequest): Promise<string> {
  if (typeof req.body === 'string') return Promise.resolve(req.body);
  if (req.body instanceof Uint8Array) return Promise.resolve(fromUtf8(req.body));
  // A body parser already consumed the stream and left something that is not the raw SET: there is
  // nothing left to read, and waiting for 'end' would hang the request. A parser that skipped this
  // content type may leave req.body = {} with the stream unread, which is read below.
  if (req.readableEnded === true) return Promise.reject(new Error('body already consumed'));
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    let failed = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        if (!failed) reject(new Error('too large'));
        failed = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      const all = new Uint8Array(size);
      let at = 0;
      for (const c of chunks) {
        all.set(c, at);
        at += c.length;
      }
      try {
        resolve(fromUtf8(all));
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
    req.on('error', (e) => {
      reject(e instanceof Error ? e : new Error(String(e)));
    });
  });
}

function checkStore(store: unknown): asserts store is MemoryRevocationStore {
  const s = store as Partial<MemoryRevocationStore> | undefined;
  if (
    s === undefined ||
    typeof s.revoke !== 'function' ||
    typeof s.isRevoked !== 'function' ||
    !((s.tokenLifetimeSeconds ?? 0) > 0) ||
    !Number.isInteger(s.maxEntries) ||
    (s.maxEntries ?? 0) < 1
  ) {
    throw new ConfigurationError('revocations must be a store from createRevocationStore()');
  }
}

/**
 * Builds the handler for the Shared Signals push (RFC 8935), `(req, res)`, which works as an Express
 * route and in a plain `http.createServer`. It reads the body itself (or `req.body` when a parser made
 * it a string or byte array) and answers:
 *
 * - `202` accepted (also for a retry of an event already applied, and for one older than any token it
 *   could affect: applied once, or not at all);
 * - `400 {"err", "description"}` refused for good (`invalid_request`, `invalid_key`, `invalid_issuer`,
 *   `invalid_audience`, `authentication_failed`): nothing is recorded;
 * - `503` for anything that can heal, because the transmitter treats a 400 as final and stops the
 *   stream: a key not in the key set yet, a key set that cannot be read, an `iat` ahead of this clock;
 * - `401` without the bearer when `authToken` is set; `405` for any method but POST.
 *
 * Throws now, not at the first request, if it cannot work.
 */
export function createReceiver(
  af: AuthFI,
  options: ReceiverOptions,
): (req: PushRequest, res: PushResponse) => Promise<void> {
  const core = coreOf(af);
  const issuer = af.issuer;
  const { revocations: store, audience } = options;
  checkStore(store);
  if (typeof audience !== 'string' || audience.trim() === '')
    throw new ConfigurationError(
      'createReceiver needs audience: the audience your stream was registered with',
    );
  if (options.authToken !== undefined && (typeof options.authToken !== 'string' || options.authToken === ''))
    throw new ConfigurationError('authToken must be a non-empty string, or left out to not require a bearer');
  const expectedBearer = options.authToken === undefined ? undefined : sha256(utf8(options.authToken));
  const onSignal = options.onSignal;
  const life = store.tokenLifetimeSeconds;
  const clock = (): number => core.clock.now();
  const seen = new SeenSet(store.maxEntries, life, clock);
  const logger = core.logger;
  const warn = (msg: string, fields?: Record<string, unknown>): void => {
    logger.warn(`receiver: ${msg}`, fields);
  };

  async function verifySet(token: string): Promise<Record<string, unknown>> {
    if (token.length > MAX_SET_BYTES || utf8(token).length > MAX_SET_BYTES)
      throw new SetError('malformed', 'the token is not a bounded string');
    const parts = token.split('.');
    const [head, body, tail] = parts;
    if (parts.length !== 3 || !head || !body || !tail)
      throw new SetError('malformed', 'a token is three dot-separated parts');
    const header = jsonOf(head);
    if (header === undefined) throw new SetError('malformed', 'the token header is not valid');
    const { alg } = header;
    if (typeof alg !== 'string' || !['RS256', 'PS256', 'ES256', 'EdDSA'].includes(alg))
      throw new SetError('alg_not_allowed', 'the algorithm of the token is not accepted');
    if (header.crit !== undefined && header.crit !== null)
      throw new SetError('crit_not_supported', 'critical header extensions are not supported');
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : '';
    if (typ !== SET_TYP)
      throw new SetError('typ_invalid', `the token is not of the expected type (typ must be ${SET_TYP})`);
    if (typeof header.kid !== 'string' || header.kid === '')
      throw new SetError('kid_required', 'the token names no signing key');
    if (fromBase64urlStrict(tail) === undefined)
      throw new SetError('malformed', 'the token signature is not valid');
    let published;
    try {
      published = await core.keys.lookup(header.kid);
    } catch {
      throw new SetError('key_set_unavailable', 'failed to fetch the key set');
    }
    if (published === undefined) throw new SetError('unknown_key', 'unknown signing key');
    if (!published.algs.some((a) => a === alg))
      throw new SetError('alg_key_mismatch', 'the algorithm of the token does not match its signing key');
    try {
      const { key } = await core.keys.key(header.kid, alg);
      await compactVerify(token, key, { algorithms: [alg] });
    } catch {
      throw new SetError('bad_signature', 'invalid signature');
    }
    const payload = jsonOf(body);
    if (payload === undefined) throw new SetError('malformed', 'the token payload is not valid');
    return payload;
  }

  function jsonOf(segment: string): Record<string, unknown> | undefined {
    const bytes = fromBase64urlStrict(segment);
    if (bytes === undefined) return undefined;
    try {
      const value: unknown = JSON.parse(fromUtf8(bytes));
      return typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
    } catch {
      return undefined;
    }
  }

  async function apply(
    claims: Record<string, unknown>,
    events: Record<string, Record<string, unknown>>,
    subject: string,
    iat: number,
  ): Promise<void> {
    const jti = claims.jti as string;
    for (const [event, detail] of Object.entries(events)) {
      let resumed = false;
      let revoked = false;
      if (REVOKING.has(event)) {
        revoked = true;
        const dropped = store.revoke(subject, iat, jti);
        if (dropped > 0)
          warn('revocation store is full; the oldest revocations were folded into a floor', { dropped });
      } else if (event === EVENTS.TOKEN_CLAIMS_CHANGE) {
        resumed = detail.resumed === true;
      } else {
        logger.info('receiver: SET event ignored: not an event this receiver acts on', { event });
        continue;
      }
      logger.info('receiver: SET accepted', { event, subject, jti });
      if (onSignal !== undefined) {
        try {
          await onSignal({ event, subject, jti, issuedAt: iat, revoked, resumed });
        } catch {
          warn('onSignal threw; the revocation stands', { event });
        }
      }
    }
  }

  /** Runs every check; returns null when accepted, else the failure to answer. */
  async function accept(token: string): Promise<Failure | null> {
    let payload: Record<string, unknown>;
    try {
      payload = await verifySet(token);
    } catch (e) {
      return mapSetError(e);
    }
    if (trimSlash(payload.iss) !== issuer)
      return [400, 'invalid_issuer', 'the SET was not issued by this project'];
    const aud: unknown[] = Array.isArray(payload.aud) ? (payload.aud as unknown[]) : [payload.aud];
    if (!aud.includes(audience)) return [400, 'invalid_audience', 'the SET is not for this stream'];
    const { jti, iat } = payload;
    if (typeof jti !== 'string' || jti === '' || jti.length > MAX_JTI_LENGTH)
      return [400, 'invalid_request', 'the SET has no usable jti'];
    const now = Math.floor(clock() / 1000);
    if (!validDate(iat)) return [400, 'invalid_request', 'the SET has no usable iat'];
    if (iat > now + LEEWAY_SECONDS) {
      // Not a refusal of the SET: this clock is behind the transmitter's. A 400 is final for the
      // transmitter and disables the stream, so ask for a retry instead.
      return [503, 'temporarily_unavailable', "the SET is dated ahead of this server's clock"];
    }
    if (payload.exp !== undefined && (!validDate(payload.exp) || now >= payload.exp + LEEWAY_SECONDS))
      return [400, 'invalid_request', 'the SET has expired'];
    const subject = subjectOf(payload.sub_id, issuer);
    if (subject === null) return [400, 'invalid_request', 'the SET names no usable subject'];
    const events = payload.events;
    if (
      typeof events !== 'object' ||
      events === null ||
      Array.isArray(events) ||
      Object.keys(events).length === 0
    )
      return [400, 'invalid_request', 'the SET carries no events'];
    for (const detail of Object.values(events)) {
      if (typeof detail !== 'object' || detail === null || Array.isArray(detail))
        return [400, 'invalid_request', 'an event of the SET is not an object'];
    }
    if (now >= iat + life) {
      // Every token this could refuse has expired: accepted so the transmitter does not take it for
      // a failure, and not applied.
      logger.info('receiver: SET ignored: older than any token it could affect', { jti });
      return null;
    }
    if (!seen.claim(jti)) return null; // a retry of a SET already applied: accepted again, applied once
    await apply(payload, events as Record<string, Record<string, unknown>>, subject, iat);
    return null;
  }

  async function bearerOk(req: PushRequest): Promise<boolean> {
    const header = req.headers.authorization;
    const value = Array.isArray(header) ? (header[0] ?? '') : (header ?? '');
    const match = /^bearer\s+(\S+)$/i.exec(value.trim());
    if (match?.[1] === undefined || expectedBearer === undefined) return false;
    return constantTimeEqual(await sha256(utf8(match[1])), await expectedBearer);
  }

  function write(
    res: PushResponse,
    status: number,
    body: string,
    headers: Record<string, string> = {},
  ): void {
    res.statusCode = status;
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.end(body);
  }

  function refuse(res: PushResponse, status: number, err: string, description: string): void {
    warn('SET refused', { code: err, reason: description });
    write(res, status, JSON.stringify({ err, description }), {
      'Content-Type': 'application/json',
      ...(status === 503 ? { 'Retry-After': '5' } : {}),
    });
  }

  return async function receiver(req, res) {
    try {
      if (req.method !== 'POST') {
        write(res, 405, JSON.stringify({ error: 'method_not_allowed' }), {
          Allow: 'POST',
          'Content-Type': 'application/json',
        });
        return;
      }
      if (expectedBearer !== undefined && !(await bearerOk(req))) {
        warn('push refused', { code: 'bearer' });
        write(res, 401, JSON.stringify({ error: 'unauthorized' }), {
          'WWW-Authenticate': 'Bearer error="invalid_token"',
          'Content-Type': 'application/json',
        });
        return;
      }
      if (mediaType(req.headers['content-type']) !== SET_CONTENT_TYPE) {
        refuse(res, 400, 'invalid_request', `the content type must be ${SET_CONTENT_TYPE}`);
        return;
      }
      let body: string;
      try {
        body = await readBody(req);
      } catch {
        refuse(res, 400, 'invalid_request', 'the body could not be read or is too large');
        return;
      }
      const failure = await accept(body.trim());
      if (failure !== null) {
        refuse(res, failure[0], failure[1], failure[2]);
        return;
      }
      res.statusCode = 202;
      res.end();
    } catch (e) {
      warn('SET could not be processed', { reason: e instanceof Error ? e.message : String(e) });
      write(
        res,
        503,
        JSON.stringify({ err: 'temporarily_unavailable', description: 'the SET could not be processed now' }),
        { 'Content-Type': 'application/json', 'Retry-After': '5' },
      );
    }
  };
}

/** What {@link registerStream} registers. */
export interface StreamRequest {
  /** The audience events for this stream carry. */
  readonly audience: string;
  /** The https URL of your receiver. */
  readonly endpointUrl: string;
  /** The bearer AuthFI should send with each push; give the same to {@link ReceiverOptions.authToken}. */
  readonly authToken?: string | undefined;
  /** The event types to ask for; default is the transmitter's choice. */
  readonly events?: readonly string[] | undefined;
}

/** A registered stream. */
export interface Stream {
  readonly id: string;
  readonly audience: string;
  readonly endpointUrl: string;
  readonly status: string;
  readonly events: readonly string[];
}

/**
 * Registers a push stream with the project's transmitter: reads the issuer's
 * `/.well-known/ssf-configuration` and posts the registration to the `configuration_endpoint` it
 * names. That endpoint must sit on the issuer's own host, because the bearer is a credential and a
 * discovery document must not be able to redirect it; no redirect is followed with it.
 *
 * @param bearer A credential allowed to register streams.
 */
export async function registerStream(af: AuthFI, bearer: string, request: StreamRequest): Promise<Stream> {
  const { fetch: doFetch } = coreOf(af);
  const issuer = af.issuer;
  if (typeof bearer !== 'string' || bearer === '')
    throw new ConfigurationError('registerStream needs the bearer token that may register streams');
  const { audience, endpointUrl, authToken, events } = request;
  if (typeof audience !== 'string' || audience.trim() === '')
    throw new ConfigurationError('audience is required');
  let endpoint: URL;
  try {
    endpoint = new URL(endpointUrl);
  } catch {
    throw new ConfigurationError('endpointUrl must be an https URL');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username !== '' || endpoint.password !== '')
    throw new ConfigurationError('endpointUrl must be an https URL');
  const secrets = [bearer, authToken].filter((s): s is string => s !== undefined && s !== '');
  const scrub = (text: string): string => secrets.reduce((out, s) => out.split(s).join('[redacted]'), text);

  const metaRes = await doFetch(`${issuer}/.well-known/ssf-configuration`, {
    redirect: 'error',
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(REGISTER_TIMEOUT_MS),
  });
  if (!metaRes.ok) throw new Error(`stream discovery failed (${String(metaRes.status)})`);
  const meta = (await metaRes.json()) as { issuer?: unknown; configuration_endpoint?: unknown };
  if (trimSlash(meta.issuer) !== issuer)
    throw new Error('stream discovery: the metadata names another issuer');
  const base = new URL(issuer);
  let target: URL;
  try {
    target = new URL(String(meta.configuration_endpoint));
  } catch {
    throw new Error('stream discovery: configuration_endpoint is missing or invalid');
  }
  if (
    target.protocol !== base.protocol ||
    target.host !== base.host ||
    target.username !== '' ||
    target.password !== '' ||
    target.hash !== ''
  ) {
    throw new Error("stream discovery: configuration_endpoint is not on the issuer's host");
  }

  const body: Record<string, unknown> = { audience, endpoint_url: endpoint.toString() };
  if (authToken !== undefined && authToken !== '') body.auth_token = authToken;
  if (events !== undefined && events.length > 0) body.events_requested = events;
  const res = await doFetch(target.toString(), {
    method: 'POST',
    redirect: 'error',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${bearer}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REGISTER_TIMEOUT_MS),
  });
  const text = (await res.text()).slice(0, 65_536);
  if (!res.ok) throw new Error(`stream registration refused (${String(res.status)}): ${scrub(text)}`);
  let parsed: { data?: Record<string, unknown> } | null;
  try {
    parsed = JSON.parse(text) as { data?: Record<string, unknown> } | null;
  } catch {
    parsed = null;
  }
  const stream = parsed?.data;
  if (stream === undefined || typeof stream.id !== 'string' || stream.id === '')
    throw new Error('stream registration: the reply holds no stream');
  return {
    id: stream.id,
    audience: String(stream.audience),
    endpointUrl: String(stream.endpoint_url),
    status: String(stream.status),
    events: Array.isArray(stream.events_requested) ? (stream.events_requested as string[]) : [],
  };
}
