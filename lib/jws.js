'use strict';
const crypto = require('node:crypto');

const B64URL = /^[A-Za-z0-9_-]*$/;

// b64uDecode decodes base64url strictly: the alphabet only (no padding, no line breaks) and a
// canonical form, so two different strings never stand for one value.
function b64uDecode(s) {
  if (typeof s !== 'string' || !B64URL.test(s) || s.length % 4 === 1) throw new Error('not base64url');
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) throw new Error('not canonical');
  return buf;
}

// parseObject decodes a JWS segment into a plain JSON object.
function parseObject(seg) {
  const v = JSON.parse(b64uDecode(seg).toString('utf8'));
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
  return v;
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

// verifySignature checks a JWS signature with node:crypto. The key type is checked by the caller
// against the algorithm; an ES256 signature is raw r||s (IEEE P1363), 64 bytes.
function verifySignature(alg, key, signed, sig) {
  try {
    switch (alg) {
      case 'RS256':
        return crypto.verify('sha256', signed, key, sig);
      case 'PS256':
        return crypto.verify('sha256', signed, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
      case 'ES256':
        return sig.length === 64 && crypto.verify('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, sig);
      case 'EdDSA':
        return sig.length === 64 && crypto.verify(null, signed, key, sig);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

// thumbprint is the RFC 7638 JWK thumbprint (SHA-256, base64url) of a public KeyObject.
function thumbprint(publicKey) {
  const j = publicKey.export({ format: 'jwk' });
  let m;
  if (j.kty === 'EC') m = { crv: j.crv, kty: j.kty, x: j.x, y: j.y };
  else if (j.kty === 'OKP') m = { crv: j.crv, kty: j.kty, x: j.x };
  else if (j.kty === 'RSA') m = { e: j.e, kty: j.kty, n: j.n };
  else throw new Error('unsupported key');
  return b64u(sha256(JSON.stringify(m)));
}

module.exports = { b64uDecode, parseObject, b64u, sha256, verifySignature, thumbprint };
