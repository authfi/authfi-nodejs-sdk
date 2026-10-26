'use strict';
const crypto = require('node:crypto');
const { refuse } = require('./errors');
const { parseCertificate } = require('./der');
const { b64u, sha256 } = require('./jws');

// AuthFI Root CA R1, by the SHA-256 of its SubjectPublicKeyInfo. Compiled in: a root is never
// taken from the JWKS, the token or the network.
const DEFAULT_ROOT_PINS = ['b060083465bf0e9239a37f12a5e294a8c219f6b7d81563f4509c984b83ca6332'];
// The AuthFI private enterprise number policy arcs: .1.1 and .1.2.
const PEN_POLICIES = new Set(['1.3.6.1.4.1.67322.1.1', '1.3.6.1.4.1.67322.1.2']);

const MAX_CERTS = 6;
const MAX_CERT_BYTES = 16 * 1024;
const CACHE_MS = 10 * 60 * 1000;
const CACHE_MAX = 256;

const notProven = (m) => refuse('chain_not_proven', m);
const policyErr = (m) => refuse('chain_policy', m);
const pinErr = (m) => refuse('chain_pin', m);

const spkiOf = (cert) => cert.publicKey.export({ type: 'spki', format: 'der' });
const pinOf = (cert) => sha256(spkiOf(cert)).toString('hex');

function validity(cert) {
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  if (Number.isNaN(from) || Number.isNaN(to)) throw notProven('a certificate has no readable validity');
  return { from, to };
}

function decodeCert(b64) {
  if (typeof b64 !== 'string') throw notProven('x5c holds a value that is not base64');
  const der = Buffer.from(b64, 'base64');
  // The re-encoded form must equal the input: Node's decoder skips what it does not know.
  if (der.length === 0 || der.length > MAX_CERT_BYTES || der.toString('base64') !== b64) throw notProven('x5c holds a certificate that is not valid');
  return der;
}

function isSelfSigned(cert) {
  try {
    return cert.issuer === cert.subject && cert.verify(cert.publicKey);
  } catch {
    return false;
  }
}

function issuedBy(cert, issuer) {
  try {
    return cert.issuer === issuer.subject && cert.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

// createChain returns prove(key, headerX5t): it shows that the JWKS key the token was verified
// with is certified by a chain that reaches a pinned AuthFI root, with the right policy.
// pins is a list of lower-case hex SPKI SHA-256 values; roots are optional X509Certificate roots
// for chains whose JWKS x5c does not carry the root.
function createChain({ pins, roots, now }) {
  const pinSet = new Set(pins);
  const cache = new Map();

  function prove(key, headerX5t) {
    const t = now();
    if (typeof headerX5t !== 'string' || typeof key.x5t !== 'string') throw notProven('the token or its key carries no x5t#S256');
    if (!Array.isArray(key.x5c) || key.x5c.length === 0 || key.x5c.length > MAX_CERTS) throw notProven('the signing key carries no usable x5c chain');

    const cacheKey = sha256(key.x5c.join('\n')).toString('hex');
    const hit = cache.get(cacheKey);
    // A cached chain is still checked on every call: in date, and for the same key and thumbprint.
    if (hit && t < hit.until && t >= hit.notBefore && t <= hit.notAfter
      && hit.thumb === headerX5t && hit.thumb === key.x5t && hit.spki.equals(key.spki)) return;

    const ders = key.x5c.map(decodeCert);
    let certs;
    let meta;
    try {
      certs = ders.map((d) => new crypto.X509Certificate(d));
      meta = ders.map((d) => parseCertificate(d));
    } catch {
      throw notProven('a certificate in x5c could not be read');
    }
    if (meta.some((m) => m.unknownCritical)) throw notProven('a certificate carries a critical extension this SDK does not understand');

    const thumb = b64u(sha256(ders[0]));
    if (thumb !== headerX5t || thumb !== key.x5t) throw notProven('x5t#S256 does not name the leaf certificate');
    if (!spkiOf(certs[0]).equals(key.spki)) throw notProven('the leaf certificate does not certify the signing key');

    let notBefore = -Infinity;
    let notAfter = Infinity;
    for (const c of certs) {
      const v = validity(c);
      if (t < v.from || t > v.to) throw notProven('a certificate in the chain is not valid now');
      notBefore = Math.max(notBefore, v.from);
      notAfter = Math.min(notAfter, v.to);
    }

    // Signatures: each certificate is issued by the next; a self-signed one ends the chain.
    let rootIdx = -1;
    for (let i = 0; i < certs.length; i++) {
      if (isSelfSigned(certs[i])) {
        if (i === 0 || i !== certs.length - 1) throw notProven('the chain is not leaf-first, root-last');
        rootIdx = i;
        break;
      }
      if (i < certs.length - 1 && !issuedBy(certs[i], certs[i + 1])) throw notProven('a certificate is not issued by the next one in x5c');
    }

    let root;
    let caBelowRoot;
    if (rootIdx >= 0) {
      root = certs[rootIdx];
      caBelowRoot = rootIdx - 1;
    } else {
      const top = certs[certs.length - 1];
      root = roots.find((r) => pinSet.has(pinOf(r)) && issuedBy(top, r));
      if (!root) throw pinErr('the chain does not reach a pinned root');
      const v = validity(root);
      if (t < v.from || t > v.to) throw notProven('the root is not valid now');
      notBefore = Math.max(notBefore, v.from);
      notAfter = Math.min(notAfter, v.to);
      caBelowRoot = certs.length - 1;
    }
    if (!pinSet.has(pinOf(root))) throw pinErr('the root of the chain is not pinned');

    // Policy: leaf, then every CA between the leaf and the root.
    const leaf = meta[0];
    if (leaf.isCA) throw policyErr('the leaf certificate is a CA');
    if (!leaf.digitalSignature) throw policyErr('the leaf certificate is not for digital signatures');
    if (!leaf.policies.some((p) => PEN_POLICIES.has(p))) throw policyErr('the leaf certificate states no AuthFI policy');
    const caEnd = rootIdx >= 0 ? rootIdx : certs.length;
    for (let i = 1; i < caEnd; i++) {
      const m = meta[i];
      if (!m.isCA) throw policyErr('a certificate between the leaf and the root is not a CA');
      if (m.keyUsage !== null && !m.keyCertSign) throw policyErr('a CA certificate may not sign certificates');
      if (!m.policies.some((p) => PEN_POLICIES.has(p))) throw policyErr('a CA certificate states no AuthFI policy');
      if (m.pathLen !== undefined && i - 1 > m.pathLen) throw policyErr('a CA path length is exceeded');
    }
    const rootMeta = rootIdx >= 0 ? meta[rootIdx] : parseRoot(root);
    if (rootMeta.pathLen !== undefined && caBelowRoot > rootMeta.pathLen) throw policyErr('the root path length is exceeded');

    if (cache.size >= CACHE_MAX) cache.clear();
    cache.set(cacheKey, { until: t + CACHE_MS, notBefore, notAfter, thumb, spki: key.spki });
  }

  return { prove };
}

function parseRoot(root) {
  try {
    return parseCertificate(root.raw);
  } catch {
    throw notProven('the root certificate could not be read');
  }
}

module.exports = { createChain, DEFAULT_ROOT_PINS, PEN_POLICIES };
