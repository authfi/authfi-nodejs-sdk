'use strict';
const crypto = require('node:crypto');
const { refuse } = require('./errors');
const { b64uDecode, parseObject, b64u, sha256, verifySignature, thumbprint } = require('./jws');

const MAX_PROOF_BYTES = 8 * 1024;
const MAX_AGE_S = 60;
const MAX_FUTURE_S = 5;
const NONCE_WINDOW_MS = 60 * 1000;
const PROOF_ALGS = ['EdDSA', 'ES256', 'PS256'];
const MIN_RSA_BITS = 2048;

// countHeader counts how many times a header was sent. A comma in a DPoP value counts as a second
// proof: a JWS holds none, and Node joins repeated unknown headers with a comma.
function countHeader(req, name) {
  let n = 0;
  if (Array.isArray(req.rawHeaders)) {
    for (let i = 0; i < req.rawHeaders.length; i += 2) if (String(req.rawHeaders[i]).toLowerCase() === name) n++;
  }
  const v = req.headers && req.headers[name];
  if (Array.isArray(v)) n = Math.max(n, v.length);
  else if (typeof v === 'string') n = Math.max(n, v.includes(',') ? 2 : 1);
  return n;
}

function headerValue(req, name) {
  const v = req.headers && req.headers[name];
  return typeof v === 'string' ? v : null;
}

// importProofKey builds a public KeyObject from the proof's embedded JWK, binding kty and crv to
// the algorithm. A JWK with a private member is refused.
function importProofKey(alg, jwk) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) throw refuse('dpop_malformed', 'the proof has no embedded key');
  for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if (jwk[m] !== undefined) throw refuse('dpop_malformed', 'the embedded key is not a public key');
  }
  let material;
  if (alg === 'EdDSA') {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') throw refuse('dpop_alg', 'the algorithm does not fit the embedded key');
    material = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  } else if (alg === 'ES256') {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw refuse('dpop_alg', 'the algorithm does not fit the embedded key');
    material = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  } else {
    if (jwk.kty !== 'RSA') throw refuse('dpop_alg', 'the algorithm does not fit the embedded key');
    material = { kty: 'RSA', n: jwk.n, e: jwk.e };
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: material, format: 'jwk' });
  } catch {
    throw refuse('dpop_malformed', 'the embedded key is not valid');
  }
  if (alg === 'PS256' && !(key.asymmetricKeyDetails.modulusLength >= MIN_RSA_BITS)) throw refuse('dpop_alg', 'the embedded RSA key is too small');
  return key;
}

function nonceFor(nonceKey, window) {
  return b64u(crypto.createHmac('sha256', nonceKey).update(`authfi-dpop-nonce-v1:${window}`).digest().subarray(0, 16));
}
const currentNonce = (nonceKey, nowMs) => nonceFor(nonceKey, Math.floor(nowMs / NONCE_WINDOW_MS));

function nonceValid(nonceKey, nowMs, given) {
  if (typeof given !== 'string') return false;
  const w = Math.floor(nowMs / NONCE_WINDOW_MS);
  const g = Buffer.from(given);
  let ok = false;
  for (const win of [w, w - 1]) {
    const want = Buffer.from(nonceFor(nonceKey, win));
    if (want.length === g.length && crypto.timingSafeEqual(want, g)) ok = true;
  }
  return ok;
}

const HTU = /^(https?:\/\/[^/?#\s]+)(\/[^?#\s]*)?$/i;

// expectedURL is the request's own public URL as [origin, path]. The origin comes from the
// configured publicUrl, or from forwarding headers only when trustForwarded is set and no publicUrl is. The Host
// header is never used: a client sets it.
function expectedURL(req, cfg) {
  let origin = cfg.publicOrigin;
  // A configured publicUrl always wins. Forwarded headers are used only without one, and then
  // the LAST entry counts: it is what the trusted proxy appended, the earlier ones came from the client.
  if (!origin && cfg.trustForwarded) {
    const last = (n) => { const v = headerValue(req, n); return v ? v.split(',').pop().trim() : ''; };
    const proto = last('x-forwarded-proto').toLowerCase();
    const host = last('x-forwarded-host');
    if (proto && host) {
      if (!['http', 'https'].includes(proto) || !/^[A-Za-z0-9.\-:[\]]+$/.test(host)) throw refuse('dpop_url', 'the forwarded address is not valid');
      try { origin = new URL(`${proto}://${host}`).origin; } catch { throw refuse('dpop_url', 'the forwarded address is not valid'); }
    }
  }
  if (!origin) throw refuse('dpop_url', 'the public address of this server is not known');
  const target = String(req.originalUrl || req.url || '');
  const path = target.split(/[?#]/)[0];
  if (!path.startsWith('/') || path.startsWith('//')) throw refuse('dpop_url', 'the request target is not an absolute path');
  return [origin, path];
}

function matchesHtu(htu, [origin, path]) {
  if (typeof htu !== 'string') return false;
  const m = HTU.exec(htu);
  if (!m) return false;
  let o;
  try { o = new URL(m[1]).origin; } catch { return false; }
  return o === origin && (m[2] || '/') === path;
}

// validateProof checks a DPoP proof (RFC 9449) for an access token. It returns what the replay
// guard needs and records nothing: the caller records the jti only after every other check.
function validateProof(req, token, jkt, cfg, nowMs) {
  const n = countHeader(req, 'dpop');
  if (n === 0) throw refuse('dpop_missing', 'a DPoP proof is required');
  if (n > 1) throw refuse('dpop_multiple', 'exactly one DPoP proof is allowed');
  const proof = headerValue(req, 'dpop');
  if (proof === null) throw refuse('dpop_malformed', 'the DPoP header is not valid');
  if (proof.length > MAX_PROOF_BYTES) throw refuse('dpop_malformed', 'the proof is too large');
  const parts = proof.split('.');
  if (parts.length !== 3) throw refuse('dpop_malformed', 'a proof is three dot-separated parts');

  let header;
  try { header = parseObject(parts[0]); } catch { throw refuse('dpop_malformed', 'the proof header is not valid'); }
  if (header.typ !== 'dpop+jwt') throw refuse('dpop_type', 'the proof typ must be dpop+jwt');
  if (header.crit !== undefined) throw refuse('dpop_malformed', 'the proof carries critical header extensions');
  if (!PROOF_ALGS.includes(header.alg)) throw refuse('dpop_alg', 'the proof algorithm is not accepted');
  const key = importProofKey(header.alg, header.jwk);

  let sig;
  try { sig = b64uDecode(parts[2]); } catch { throw refuse('dpop_malformed', 'the proof signature is not valid'); }
  if (!verifySignature(header.alg, key, Buffer.from(`${parts[0]}.${parts[1]}`), sig)) throw refuse('dpop_signature', 'the proof signature does not verify');

  let claims;
  try { claims = parseObject(parts[1]); } catch { throw refuse('dpop_malformed', 'the proof payload is not valid'); }
  if (typeof claims.jti !== 'string' || claims.jti === '' || claims.jti.length > 256) throw refuse('dpop_malformed', 'the proof has no usable jti');
  if (claims.htm !== req.method) throw refuse('dpop_method', 'the proof is for another HTTP method');
  if (!matchesHtu(claims.htu, expectedURL(req, cfg))) throw refuse('dpop_url', 'the proof is for another URL');
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) throw refuse('dpop_iat', 'the proof has no issue time');
  const age = nowMs / 1000 - claims.iat;
  if (age > MAX_AGE_S || age < -MAX_FUTURE_S) throw refuse('dpop_iat', 'the proof is not fresh');
  if (typeof claims.ath !== 'string' || claims.ath !== b64u(sha256(token))) throw refuse('dpop_ath', 'the proof is not for this access token');
  if (thumbprint(key) !== jkt) throw refuse('dpop_key_mismatch', 'the proof key is not the key the token is bound to');
  if (cfg.nonceKey && !nonceValid(cfg.nonceKey, nowMs, claims.nonce)) {
    const e = refuse('dpop_nonce', 'a current server nonce is required');
    e.dpopNonce = currentNonce(cfg.nonceKey, nowMs);
    throw e;
  }
  return { thumb: jkt, jti: claims.jti, iat: claims.iat };
}

// memoryReplayGuard is the default replay guard: bounded, in process memory. A deployment with
// more than one replica needs a shared store behind the same interface. record answers true (new),
// false (already seen) or 'full' (a cap was reached: the proof is neither accepted nor called a replay).
// One key (thumbprint) may hold at most perKeyMax entries, so one agent cannot fill the guard for all.
// Expired entries are swept at most once a second, not only when the guard is full.
function memoryReplayGuard(max, now, perKeyMax = 1000) {
  const seen = new Map();
  const perKey = new Map();
  let nextSweep = 0;
  const thumbOf = (k) => k.slice(0, k.indexOf(':'));
  const drop = (k) => {
    seen.delete(k);
    const th = thumbOf(k);
    const n = (perKey.get(th) || 1) - 1;
    if (n <= 0) perKey.delete(th); else perKey.set(th, n);
  };
  return {
    record(key, expiresAtMs) {
      const t = now();
      if (t >= nextSweep) {
        for (const [k, exp] of seen) if (exp <= t) drop(k);
        nextSweep = t + 1000;
      }
      if (seen.has(key)) return false;
      const th = thumbOf(key);
      if (seen.size >= max || (perKey.get(th) || 0) >= perKeyMax) return 'full';
      seen.set(key, expiresAtMs);
      perKey.set(th, (perKey.get(th) || 0) + 1);
      return true;
    },
  };
}

module.exports = { validateProof, memoryReplayGuard, currentNonce, MAX_AGE_S, MAX_FUTURE_S };
