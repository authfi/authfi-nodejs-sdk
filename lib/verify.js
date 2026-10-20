'use strict';

// Verifies an access token an AuthFI project issued: a person's (RS256), an agent's own token or
// a token an agent holds for a person (EdDSA), with the keys the project publishes at its
// jwks_uri. The token must name this issuer and this API, and must carry an expiry.

const { createDiscovery } = require('./discovery');
const { JoseError, parseCompact, verificationKey, verifySignature } = require('./jose');

class TokenError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TokenError';
    this.code = code;
  }
}

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
    this.code = 'not_configured';
  }
}

// A JWKS is refetched for an unknown kid (the issuer rotated its keys) at most this often, so a
// stream of tokens with made-up kids cannot turn into a stream of JWKS fetches.
const UNKNOWN_KID_REFETCH_MS = 30000;

function audiences(audience) {
  const list = (Array.isArray(audience) ? audience : [audience]).filter((a) => typeof a === 'string' && a.trim());
  return list.map((a) => a.trim());
}

/**
 * Creates a verifier for one issuer and one API.
 *
 * `audience` is the API's audience: one value or a list of accepted values. The token's `aud`
 * (a string or a list) must contain one of them. For an agent's token that is the `resource` it
 * asked for, by default `<issuer>/mcp`; for a person's token it is the client id of the app.
 */
function createVerifier({ issuer, audience, fetch: fetchFn, jwksTtlMs = 300000, discoveryTtlMs = 3600000, clockToleranceSec = 30, discovery }) {
  const disco = discovery || createDiscovery({ issuer, fetch: fetchFn, ttlMs: discoveryTtlMs });
  const accepted = audiences(audience);
  if (accepted.length === 0) {
    throw new ConfigError('audience is required to verify tokens: set it to the audience your API accepts');
  }
  let jwks = null;
  let jwksAt = 0;
  let jwksInflight = null;

  async function loadJWKS() {
    const meta = await disco.metadata();
    if (!meta.jwks_uri) throw new TokenError('jwks_unavailable', `Issuer ${disco.issuer} publishes no jwks_uri`);
    const doFetch = fetchFn || globalThis.fetch;
    let res;
    try {
      res = await doFetch(meta.jwks_uri, { headers: { accept: 'application/json' } });
    } catch (e) {
      throw new TokenError('jwks_unavailable', `Failed to fetch JWKS: ${e.message}`);
    }
    if (!res.ok) throw new TokenError('jwks_unavailable', `Failed to fetch JWKS: HTTP ${res.status}`);
    const doc = await res.json().catch(() => null);
    if (!doc || !Array.isArray(doc.keys)) throw new TokenError('jwks_unavailable', 'JWKS has no keys');
    return doc;
  }

  async function keySet({ force = false } = {}) {
    if (!force && jwks && Date.now() - jwksAt < jwksTtlMs) return jwks;
    if (!jwksInflight) {
      jwksInflight = loadJWKS()
        .then((doc) => {
          jwks = doc;
          jwksAt = Date.now();
          return doc;
        })
        .finally(() => {
          jwksInflight = null;
        });
    }
    return jwksInflight;
  }

  async function keyFor(kid) {
    if (!kid || typeof kid !== 'string') throw new TokenError('kid_missing', 'Token header has no kid');
    let set = await keySet();
    let jwk = set.keys.find((k) => k.kid === kid);
    if (!jwk && Date.now() - jwksAt >= UNKNOWN_KID_REFETCH_MS) {
      set = await keySet({ force: true });
      jwk = set.keys.find((k) => k.kid === kid);
    }
    if (!jwk) throw new TokenError('kid_unknown', 'Unknown signing key');
    return jwk;
  }

  async function verify(token) {
    let parsed;
    try {
      parsed = parseCompact(token);
    } catch (e) {
      throw new TokenError(e.code || 'token_malformed', e.message);
    }
    const { header, payload, signingInput, signature } = parsed;

    const jwk = await keyFor(header.kid);
    let key;
    try {
      key = verificationKey(jwk);
    } catch (e) {
      throw new TokenError(e instanceof JoseError ? e.code : 'key_unusable', e.message);
    }
    // The key decides the algorithm; the header only has to agree with it.
    if (header.alg !== key.alg) {
      throw new TokenError('alg_mismatch', `Token alg ${header.alg} is not ${key.alg}, the algorithm of key ${header.kid}`);
    }
    if (!verifySignature(key.alg, key.key, signingInput, signature)) {
      throw new TokenError('signature_invalid', 'Invalid signature');
    }

    // Claims only after the signature: before it they are attacker-controlled bytes.
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number') throw new TokenError('exp_missing', 'Token has no exp');
    if (payload.exp + clockToleranceSec <= now) throw new TokenError('token_expired', 'Token expired');
    if (typeof payload.nbf === 'number' && payload.nbf - clockToleranceSec > now) {
      throw new TokenError('token_not_yet_valid', 'Token is not valid yet');
    }
    if (payload.iss !== disco.issuer) {
      throw new TokenError('issuer_mismatch', `Token issuer ${JSON.stringify(payload.iss)} is not ${disco.issuer}`);
    }
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.some((a) => typeof a === 'string' && accepted.includes(a))) {
      throw new TokenError('audience_mismatch', 'Token is not for this audience');
    }
    return payload;
  }

  /** Fetches the issuer's metadata and keys ahead of the first request. */
  async function warm() {
    await keySet();
  }

  return { issuer: disco.issuer, audience: accepted, verify, warm };
}

module.exports = { createVerifier, TokenError, ConfigError };
