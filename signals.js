'use strict';

/**
 * Shared Signals push receiver (RFC 8935) and the revocation store behind it.
 *
 * A revocation means: tokens of this subject issued at or before the SET's `iat` are dead. A token
 * issued after it is fine, which is why a resumed agent needs no "lift": its new token is newer.
 */

const crypto = require('crypto');

const DEFAULT_MAX_ENTRIES = 100000;
const DEFAULT_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_SUBJECT_LENGTH = 512;
const MAX_JTI_LENGTH = 256;
const MAX_NUMERIC_DATE = 253402300799; // 9999-12-31T23:59:59Z
const EVICT_FRACTION = 10;
const SET_TYP = 'secevent+jwt';
const SET_CONTENT_TYPE = 'application/secevent+jwt';

const EVENTS = Object.freeze({
  SESSION_REVOKED: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  TOKEN_CLAIMS_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
  ACCOUNT_PURGED: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  CREDENTIAL_COMPROMISE: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
});
const REVOKING = new Set([EVENTS.SESSION_REVOKED, EVENTS.ACCOUNT_PURGED, EVENTS.CREDENTIAL_COMPROMISE]);

/** A failure of the JWS layer, with a stable code the receiver maps to RFC 8935. */
class JwsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'JwsError';
    this.code = code;
  }
}

function toSeconds(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * A bounded map from subject to the time before which its tokens are dead.
 *
 * When it is full it drops the oldest revocations and raises a floor: every token issued at or
 * before the newest dropped revocation is then refused whatever its subject. A full store costs
 * some holders a new token and never lets a revoked one through.
 */
function createRevocationStore(options = {}) {
  const max = Number.isInteger(options.maxEntries) && options.maxEntries > 0 ? options.maxEntries : DEFAULT_MAX_ENTRIES;
  const life = options.tokenLifetimeSeconds > 0 ? Math.floor(options.tokenLifetimeSeconds) : DEFAULT_TOKEN_LIFETIME_SECONDS;
  const clock = typeof options.clock === 'function' ? options.clock : Date.now;
  const notBefore = new Map();
  let floor = 0;
  let floorRef = '';

  const nowSeconds = () => Math.floor(clock() / 1000);

  function makeRoom(now) {
    for (const [subject, entry] of notBefore) {
      if (entry.at + life <= now) notBefore.delete(subject);
    }
    if (notBefore.size < max) return 0;
    const oldest = [...notBefore.entries()].sort((a, b) => a[1].at - b[1].at);
    const n = Math.min(Math.floor(max / EVICT_FRACTION) + 1, oldest.length);
    for (let i = 0; i < n; i++) notBefore.delete(oldest[i][0]);
    if (oldest[n - 1][1].at > floor) {
      floor = oldest[n - 1][1].at;
      floorRef = oldest[n - 1][1].ref;
    }
    return n;
  }

  const store = {
    /**
     * Records that tokens of `subject` issued at or before `at` (Unix seconds) are dead. A later
     * call with an earlier time changes nothing. Returns how many other subjects were dropped to
     * make room; zero in normal operation. `ref` is the reference of the decision, the jti of the
     * SET that withdrew the subject; a token refused because of it carries it as `error.ref`.
     */
    revoke(subject, at, ref = '') {
      const t = toSeconds(at);
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

    /**
     * Whether a token of `subject` issued at `issuedAt` (Unix seconds) is revoked. An unknown
     * issue time counts as older than every revocation: it is revoked whenever the subject has a
     * live one, because it cannot be shown to be newer.
     */
    isRevoked(subject, issuedAt) {
      return store.find(subject, issuedAt) !== null;
    },

    /** Like isRevoked, but returns { ref } of the revocation that applies, or null. */
    find(subject, issuedAt) {
      const now = nowSeconds();
      const iat = toSeconds(issuedAt) === null ? -Infinity : issuedAt;
      if (floor !== 0 && floor + life > now && iat <= floor) return { ref: floorRef };
      const entry = notBefore.get(subject);
      if (entry === undefined || entry.at + life <= now) return null;
      return iat <= entry.at ? { ref: entry.ref } : null;
    },

    /** Subjects remembered, expired ones included until they are next swept. */
    get size() {
      return notBefore.size;
    },

    /** The most subjects the store remembers. */
    get maxEntries() {
      return max;
    },

    /** The lifetime a revocation is remembered for, in seconds. */
    get tokenLifetimeSeconds() {
      return life;
    },
  };
  return store;
}

/** A bounded set of recently accepted jti values. */
function createSeenSet(max, lifeSeconds, clock) {
  const seen = new Map(); // jti -> expiry in Unix seconds; insertion order is expiry order
  return {
    /** Records jti; false when it was already there. The oldest id is forgotten when full. */
    claim(jti) {
      const now = Math.floor(clock() / 1000);
      for (const [id, expires] of seen) {
        if (expires > now) break;
        seen.delete(id);
      }
      if (seen.has(jti)) return false;
      if (seen.size >= max) seen.delete(seen.keys().next().value);
      seen.set(jti, now + lifeSeconds);
      return true;
    },
    get size() {
      return seen.size;
    },
  };
}

function refuseWith(res, status, err, description) {
  const body = JSON.stringify({ err, description });
  if (status === 503) res.setHeader('Retry-After', '5');
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(body);
}

function readBody(req) {
  if (typeof req.body === 'string') return Promise.resolve(req.body);
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body.toString('utf8'));
  // A body parser already consumed the stream and left something that is not the raw SET: there is
  // nothing left to read, and waiting for 'end' would hang the request. A parser that skipped this
  // content type may leave req.body = {} with the stream unread, which is read below.
  if (req.readableEnded) return Promise.reject(new Error('body already consumed'));
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function mediaType(header) {
  return String(header || '').split(';')[0].trim().toLowerCase();
}

function digest(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function subjectOf(subId, issuer) {
  if (!subId || typeof subId !== 'object') return null;
  let subject = null;
  if (subId.format === 'opaque') subject = subId.id;
  else if (subId.format === 'iss_sub' && trimSlash(subId.iss) === issuer) subject = subId.sub;
  if (typeof subject !== 'string' || subject === '' || subject.length > MAX_SUBJECT_LENGTH) return null;
  return subject;
}

/** An https issuer, or http on a loopback host for local development. */
function checkIssuer(issuer) {
  let u;
  try {
    u = new URL(issuer);
  } catch (e) {
    throw new Error('authfi: issuer must be an absolute URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.search || u.hash || u.username || u.password || !(u.protocol === 'https:' || (u.protocol === 'http:' && loopback))) {
    throw new Error('authfi: issuer must be an https URL without query, fragment or credentials');
  }
}

function trimSlash(value) {
  return typeof value === 'string' ? value.trim().replace(/\/+$/, '') : '';
}

function validDate(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_NUMERIC_DATE;
}

/** Maps a JWS-layer failure to RFC 8935 section 2.4. A key set that cannot be read is a 503. */
function mapJwsError(err) {
  switch (err && err.code) {
    case 'key_set_unavailable':
      return [503, 'temporarily_unavailable', 'the issuer\'s keys could not be read'];
    case 'unknown_key':
      // The key may be one the issuer rotated in since the last (throttled) fetch. A 400 is final
      // for the transmitter and would lose this revocation, so ask for a retry.
      return [503, 'temporarily_unavailable', 'the signing key is not in the issuer\'s key set (yet)'];
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

/**
 * Builds the receiver handler. `deps` supplies what the client already owns: the issuer, the
 * store, the JWS verifier over the issuer's key set, the clock and a logger.
 */
function createReceiver(deps, config) {
  const { issuer, store, verifyJws, clock, logger } = deps;
  if (!issuer) throw new Error('authfi: receiver needs the issuer option (the project issuer, for example https://acme.authfi.io)');
  checkIssuer(issuer);
  if (!store) throw new Error('authfi: receiver needs the revocations option (a store from authfi.createRevocationStore())');
  if (!config || typeof config.audience !== 'string' || config.audience.trim() === '') {
    throw new Error('authfi: receiver needs audience: the audience your stream was registered with');
  }
  if (typeof store.revoke !== 'function' || typeof store.isRevoked !== 'function' ||
      !(store.tokenLifetimeSeconds > 0) || !Number.isInteger(store.maxEntries) || store.maxEntries < 1) {
    throw new Error('authfi: revocations must be a store from authfi.createRevocationStore()');
  }
  if (config.authToken !== undefined && (typeof config.authToken !== 'string' || config.authToken === '')) {
    throw new Error('authfi: authToken must be a non-empty string, or left out to not require a bearer');
  }
  const audience = config.audience;
  const pushToken = config.authToken === undefined ? null : digest(config.authToken);
  const onSignal = typeof config.onSignal === 'function' ? config.onSignal : null;
  const leewaySeconds = 60;
  const life = store.tokenLifetimeSeconds;
  const seen = createSeenSet(store.maxEntries, life, clock);

  const warn = (msg, fields) => logger.warn(`authfi: receiver: ${msg}`, fields);

  function bearerOk(req) {
    const match = /^bearer\s+(\S+)$/i.exec(String(req.headers.authorization || '').trim());
    if (!match) return false;
    return crypto.timingSafeEqual(digest(match[1]), pushToken);
  }

  function refuse(res, status, err, description) {
    warn('SET refused', { code: err, reason: description });
    refuseWith(res, status, err, description);
  }

  async function runHook(signal) {
    if (!onSignal) return;
    try {
      await onSignal(signal);
    } catch (e) {
      warn('onSignal threw; the revocation stands', { event: signal.event });
    }
  }

  async function apply(claims, subject, iat) {
    for (const [event, detail] of Object.entries(claims.events)) {
      const signal = { event, subject, jti: claims.jti, issuedAt: iat, revoked: false, resumed: false };
      if (REVOKING.has(event)) {
        signal.revoked = true;
        const dropped = store.revoke(subject, iat, claims.jti);
        if (dropped > 0) warn('revocation store is full; the oldest revocations were folded into a floor', { dropped });
      } else if (event === EVENTS.TOKEN_CLAIMS_CHANGE) {
        signal.resumed = detail.resumed === true;
      } else {
        logger.info('authfi: receiver: SET event ignored: not an event this receiver acts on', { event });
        continue;
      }
      logger.info('authfi: receiver: SET accepted', { event, subject, jti: claims.jti });
      await runHook(signal);
    }
  }

  /** Runs every check; returns null when accepted, else [status, code, description]. */
  async function accept(token) {
    let payload;
    try {
      payload = await verifyJws(token, SET_TYP);
    } catch (e) {
      return mapJwsError(e);
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return [400, 'invalid_request', 'the SET payload is not a JSON object'];
    }
    if (trimSlash(payload.iss) !== issuer) return [400, 'invalid_issuer', 'the SET was not issued by this project'];
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(audience)) return [400, 'invalid_audience', 'the SET is not for this stream'];
    if (typeof payload.jti !== 'string' || payload.jti === '' || payload.jti.length > MAX_JTI_LENGTH) {
      return [400, 'invalid_request', 'the SET has no usable jti'];
    }
    const now = Math.floor(clock() / 1000);
    if (!validDate(payload.iat)) return [400, 'invalid_request', 'the SET has no usable iat'];
    if (payload.iat > now + leewaySeconds) {
      // Not a refusal of the SET: this clock is behind the transmitter's. A 400 is final for the
      // transmitter and disables the stream, so ask for a retry instead.
      return [503, 'temporarily_unavailable', 'the SET is dated ahead of this server\'s clock'];
    }
    if (payload.exp !== undefined && (!validDate(payload.exp) || now >= payload.exp + leewaySeconds)) {
      return [400, 'invalid_request', 'the SET has expired'];
    }
    const subject = subjectOf(payload.sub_id, issuer);
    if (subject === null) return [400, 'invalid_request', 'the SET names no usable subject'];
    const events = payload.events;
    if (!events || typeof events !== 'object' || Array.isArray(events) || Object.keys(events).length === 0) {
      return [400, 'invalid_request', 'the SET carries no events'];
    }
    for (const detail of Object.values(events)) {
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) {
        return [400, 'invalid_request', 'an event of the SET is not an object'];
      }
    }
    if (now >= payload.iat + life) {
      // Every token this could refuse has expired: accepted so the transmitter does not take it for
      // a failure, and not applied.
      logger.info('authfi: receiver: SET ignored: older than any token it could affect', { jti: payload.jti });
      return null;
    }
    if (!seen.claim(payload.jti)) return null; // a retry of a SET already applied: accepted again, applied once
    await apply(payload, subject, payload.iat);
    return null;
  }

  /** (req, res) handler: mount it with app.post(path, receiver) or inside http.createServer. */
  return async function receiver(req, res) {
    try {
      if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        res.statusCode = 405;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'method_not_allowed' }));
        return;
      }
      if (pushToken && !bearerOk(req)) {
        warn('push refused', { code: 'bearer' });
        res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      if (mediaType(req.headers['content-type']) !== SET_CONTENT_TYPE) {
        refuse(res, 400, 'invalid_request', `the content type must be ${SET_CONTENT_TYPE}`);
        return;
      }
      let body;
      try {
        body = await readBody(req);
      } catch (e) {
        refuse(res, 400, 'invalid_request', 'the body could not be read or is too large');
        return;
      }
      const failure = await accept(body.trim());
      if (failure) {
        refuse(res, failure[0], failure[1], failure[2]);
        return;
      }
      res.statusCode = 202;
      res.end();
    } catch (e) {
      warn('SET could not be processed', { reason: e && e.message });
      refuseWith(res, 503, 'temporarily_unavailable', 'the SET could not be processed now');
    }
  };
}

/**
 * Registers a push stream with the project's transmitter: reads the issuer's
 * /.well-known/ssf-configuration and posts the registration to the configuration_endpoint it
 * names. That endpoint must sit on the issuer's own host, because the bearer is a credential and a
 * discovery document must not be able to redirect it.
 */
async function registerStream(issuer, bearer, request, fetchImpl) {
  if (!issuer) throw new Error('authfi: registerStream needs the issuer option');
  checkIssuer(issuer);
  if (typeof bearer !== 'string' || bearer === '') throw new Error('authfi: registerStream needs the bearer token that may register streams');
  const { audience, endpointUrl, authToken, events } = request || {};
  if (typeof audience !== 'string' || audience.trim() === '') throw new Error('authfi: audience is required');
  let endpoint;
  try {
    endpoint = new URL(endpointUrl);
  } catch (e) {
    throw new Error('authfi: endpointUrl must be an https URL');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) {
    throw new Error('authfi: endpointUrl must be an https URL');
  }
  const secrets = [bearer, authToken].filter(Boolean);
  const scrub = (text) => secrets.reduce((out, s) => out.split(s).join('[redacted]'), String(text));

  const metaRes = await fetchImpl(`${issuer}/.well-known/ssf-configuration`, { redirect: 'error', headers: { Accept: 'application/json' } });
  if (!metaRes.ok) throw new Error(`authfi: stream discovery failed (${metaRes.status})`);
  const meta = await metaRes.json();
  if (trimSlash(meta.issuer) !== issuer) throw new Error('authfi: stream discovery: the metadata names another issuer');
  const base = new URL(issuer);
  let target;
  try {
    target = new URL(meta.configuration_endpoint);
  } catch (e) {
    throw new Error('authfi: stream discovery: configuration_endpoint is missing or invalid');
  }
  if (target.protocol !== base.protocol || target.host !== base.host || target.username || target.password || target.hash) {
    throw new Error('authfi: stream discovery: configuration_endpoint is not on the issuer\'s host');
  }

  const body = { audience, endpoint_url: endpoint.toString() };
  if (authToken) body.auth_token = authToken;
  if (Array.isArray(events) && events.length > 0) body.events_requested = events;
  const res = await fetchImpl(target.toString(), {
    method: 'POST',
    redirect: 'error',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
  const text = (await res.text()).slice(0, 65536);
  if (!res.ok) throw new Error(`authfi: stream registration refused (${res.status}): ${scrub(text)}`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    parsed = null;
  }
  const stream = parsed && parsed.data;
  if (!stream || !stream.id) throw new Error('authfi: stream registration: the reply holds no stream');
  return {
    id: stream.id,
    audience: stream.audience,
    endpointUrl: stream.endpoint_url,
    status: stream.status,
    events: stream.events_requested || [],
  };
}

module.exports = {
  EVENTS,
  JwsError,
  createRevocationStore,
  createReceiver,
  createSeenSet,
  registerStream,
  DEFAULT_MAX_ENTRIES,
  SET_TYP,
};
