'use strict';
const crypto = require('node:crypto');
const { refuse } = require('./errors');

const MAX_BYTES = 1 << 20;
const MAX_KEYS = 100;
const MIN_REFETCH_MS = 15 * 1000;
const STALE_GRACE_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10 * 1000;
const MIN_RSA_BITS = 2048;

// parseKey turns one JWKS entry into a verification key, or null when it is not usable. A key
// that does not parse is skipped and never fatal to the others. The algorithms a key may verify
// are bound to its kty and crv, so the algorithm in a token can never choose the key type.
function parseKey(k) {
  if (!k || typeof k !== 'object' || typeof k.kid !== 'string' || k.kid === '') return null;
  if (k.use !== undefined && k.use !== 'sig') return null;
  try {
    let algs;
    let material;
    if (k.kty === 'RSA') {
      algs = ['RS256', 'PS256'];
      if (k.alg !== undefined) {
        if (!algs.includes(k.alg)) return null;
        algs = [k.alg];
      }
      material = { kty: 'RSA', n: k.n, e: k.e };
    } else if (k.kty === 'EC' && k.crv === 'P-256') {
      if (k.alg !== undefined && k.alg !== 'ES256') return null;
      algs = ['ES256'];
      material = { kty: 'EC', crv: 'P-256', x: k.x, y: k.y };
    } else if (k.kty === 'OKP' && k.crv === 'Ed25519') {
      if (k.alg !== undefined && k.alg !== 'EdDSA') return null;
      algs = ['EdDSA'];
      material = { kty: 'OKP', crv: 'Ed25519', x: k.x };
    } else return null;
    const pub = crypto.createPublicKey({ key: material, format: 'jwk' });
    if (k.kty === 'RSA' && !(pub.asymmetricKeyDetails.modulusLength >= MIN_RSA_BITS)) return null;
    return {
      kid: k.kid, pub, algs, spki: pub.export({ type: 'spki', format: 'der' }), x5c: k.x5c, x5t: k['x5t#S256'],
    };
  } catch {
    return null;
  }
}

// createKeySet caches the issuer's JWKS. The URL is the project issuer's own, never one named by a
// token. An unknown kid refetches at most every 15 s; on a failed refresh a key stays usable for
// an hour past its ttl, and not longer.
function createKeySet({ url, ttlMs, fetchFn, now }) {
  let keys = new Map();
  let fetched = -Infinity;
  let attempted = -Infinity;
  let failure = null;
  let flight = null;

  const stale = (kid) => (keys.has(kid) && now() - fetched < ttlMs + STALE_GRACE_MS ? keys.get(kid) : null);
  const noKey = () => refuse('token_unknown_key', 'the key set of the issuer has no such key');

  async function download() {
    let res;
    try {
      res = await (fetchFn || globalThis.fetch)(url, {
        headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      throw refuse('jwks_unavailable', 'the key set of the issuer could not be fetched');
    }
    if (!res || !res.ok) throw refuse('jwks_unavailable', 'the key set of the issuer answered an error');
    let doc;
    try {
      if (typeof res.text === 'function') {
        const text = await res.text();
        if (text.length > MAX_BYTES) throw new Error('too large');
        doc = JSON.parse(text);
      } else doc = await res.json();
    } catch {
      throw refuse('jwks_unavailable', 'the key set of the issuer could not be read');
    }
    if (!doc || !Array.isArray(doc.keys)) throw refuse('jwks_unavailable', 'the issuer key set is not a JWKS document');
    const next = new Map();
    for (const raw of doc.keys.slice(0, MAX_KEYS)) {
      const k = parseKey(raw);
      if (k && !next.has(k.kid)) next.set(k.kid, k);
    }
    if (next.size === 0) throw refuse('jwks_unavailable', 'the key set of the issuer holds no usable key');
    return next;
  }

  function start() {
    attempted = now();
    flight = download().then(
      (next) => { keys = next; fetched = now(); failure = null; },
      (err) => { failure = err; },
    ).finally(() => { flight = null; });
    return flight;
  }

  async function get(kid) {
    if (keys.has(kid) && now() - fetched < ttlMs) return keys.get(kid);
    if (!flight) {
      if (now() - attempted < MIN_REFETCH_MS) {
        const k = stale(kid);
        if (k) return k;
        throw failure || noKey();
      }
      start();
    }
    await flight;
    if (failure) {
      const k = stale(kid);
      if (k) return k;
      throw failure;
    }
    const k = keys.get(kid);
    if (!k) throw noKey();
    return k;
  }

  async function refresh() {
    if (!flight) start();
    await flight;
    if (failure) throw failure;
  }

  return { get, refresh };
}

module.exports = { createKeySet, parseKey };
