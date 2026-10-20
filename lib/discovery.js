'use strict';

// Reads a project's authorization-server metadata (RFC 8414), falling back to OpenID discovery.
//
// Every endpoint the SDK calls comes from this document, so nothing is hard-coded: the token
// endpoint, the JWKS and the CIBA endpoint move with the project's origin, a custom domain
// included. The document must name the issuer it was fetched for (RFC 8414 §3.3); one that names
// another is refused, because its keys and endpoints would be another issuer's.

const WELL_KNOWN = ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'];

class DiscoveryError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'DiscoveryError';
    this.code = 'discovery_failed';
    this.status = status;
  }
}

/** Trims trailing slashes and refuses anything that is not an https (or loopback http) origin URL. */
function normalizeIssuer(issuer) {
  if (!issuer || typeof issuer !== 'string') throw new DiscoveryError('issuer is required');
  const trimmed = issuer.trim().replace(/\/+$/, '');
  let u;
  try {
    u = new URL(trimmed);
  } catch {
    throw new DiscoveryError(`issuer ${JSON.stringify(issuer)} is not a URL`);
  }
  const loopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) {
    throw new DiscoveryError(`issuer ${trimmed} must be https`);
  }
  if (u.search || u.hash) throw new DiscoveryError(`issuer ${trimmed} must not carry a query or fragment`);
  return trimmed;
}

/**
 * Creates a cached reader of one issuer's metadata. A failed read is never cached: the next call
 * tries again, so a transient outage does not pin the SDK to "no configuration".
 */
function createDiscovery({ issuer, fetch: fetchFn, ttlMs = 3600000 }) {
  const iss = normalizeIssuer(issuer);
  let cached = null;
  let cachedAt = 0;
  let inflight = null;

  async function load() {
    const doFetch = fetchFn || globalThis.fetch;
    let lastStatus = 0;
    for (const path of WELL_KNOWN) {
      const url = iss + path;
      let res;
      try {
        res = await doFetch(url, { headers: { accept: 'application/json' } });
      } catch (e) {
        throw new DiscoveryError(`Discovery at ${url} failed: ${e.message}`);
      }
      if (res.status === 404) {
        lastStatus = 404;
        continue;
      }
      if (!res.ok) throw new DiscoveryError(`Discovery at ${url} answered HTTP ${res.status}`, res.status);
      let doc;
      try {
        doc = await res.json();
      } catch {
        throw new DiscoveryError(`Discovery at ${url} did not answer JSON`, res.status);
      }
      if (!doc || typeof doc !== 'object') throw new DiscoveryError(`Discovery at ${url} did not answer an object`);
      if (doc.issuer !== iss) {
        throw new DiscoveryError(`Discovery at ${url} names issuer ${JSON.stringify(doc.issuer)}, not ${iss}`);
      }
      return doc;
    }
    throw new DiscoveryError(`No discovery document at ${iss}`, lastStatus);
  }

  /** The metadata, fetched once per ttl. `force` refetches. */
  async function metadata({ force = false } = {}) {
    if (!force && cached && Date.now() - cachedAt < ttlMs) return cached;
    if (!inflight) {
      inflight = load()
        .then((doc) => {
          cached = doc;
          cachedAt = Date.now();
          return doc;
        })
        .finally(() => {
          inflight = null;
        });
    }
    return inflight;
  }

  return { issuer: iss, metadata };
}

module.exports = { createDiscovery, normalizeIssuer, DiscoveryError };
