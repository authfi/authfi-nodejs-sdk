'use strict';

// Compact JWS parsing and verification with the algorithm pinned by the key, never by the token.
//
// A token header names an algorithm, but the verifier decides it: the key the kid selects implies
// one algorithm, and a header that names any other is refused. That closes alg confusion (an RSA
// public key used as an HMAC secret) and "none".

const crypto = require('crypto');

/** The algorithms an AuthFI issuer signs tokens with, and the only ones verified here. */
const VERIFY_ALGORITHMS = Object.freeze(['RS256', 'PS256', 'ES256', 'EdDSA']);

const MIN_RSA_BITS = 2048;

class JoseError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'JoseError';
    this.code = code;
  }
}

function b64uDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new JoseError('token_malformed', 'Malformed token');
  }
  return Buffer.from(s, 'base64url');
}

function b64uJSON(s) {
  try {
    const v = JSON.parse(b64uDecode(s).toString('utf8'));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    return v;
  } catch (e) {
    if (e instanceof JoseError) throw e;
    throw new JoseError('token_malformed', 'Malformed token');
  }
}

/** Splits a compact JWS into its decoded header and payload, without verifying anything. */
function parseCompact(token) {
  if (typeof token !== 'string') throw new JoseError('token_malformed', 'Malformed token');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new JoseError('token_malformed', 'Malformed token');
  }
  return {
    header: b64uJSON(parts[0]),
    payload: b64uJSON(parts[1]),
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    signature: b64uDecode(parts[2]),
  };
}

/**
 * The one algorithm a published (issuer) JWK verifies. The JWK's own `alg` decides it when present
 * and must agree with the key type; without one, the key type decides (an RSA key without `alg`
 * is RS256, the algorithm AuthFI signs user tokens with). Returns the algorithm and a KeyObject.
 */
function verificationKey(jwk) {
  if (!jwk || typeof jwk !== 'object') throw new JoseError('key_unusable', 'Signing key is not a JWK');
  if (jwk.d || jwk.p || jwk.q || jwk.dp || jwk.dq || jwk.qi) {
    throw new JoseError('key_unusable', 'Published key carries a private component');
  }
  if (jwk.use && jwk.use !== 'sig') throw new JoseError('key_unusable', `Key use is ${jwk.use}, not sig`);

  let alg;
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') alg = 'EdDSA';
  else if (jwk.kty === 'EC' && jwk.crv === 'P-256') alg = 'ES256';
  else if (jwk.kty === 'RSA') alg = jwk.alg === 'PS256' ? 'PS256' : 'RS256';
  else throw new JoseError('key_unusable', `Unsupported key type ${jwk.kty}/${jwk.crv || '-'}`);
  if (jwk.alg && jwk.alg !== alg) {
    throw new JoseError('key_unusable', `Key alg ${jwk.alg} does not match its type ${jwk.kty}`);
  }

  let key;
  try {
    key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch (e) {
    throw new JoseError('key_unusable', `Signing key is unusable: ${e.message}`);
  }
  if (alg === 'RS256' || alg === 'PS256') {
    const bits = key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength;
    if (!bits || bits < MIN_RSA_BITS) throw new JoseError('key_unusable', 'RSA signing key is shorter than 2048 bits');
  }
  return { alg, key };
}

/** Verifies a signature with the algorithm the key implies. */
function verifySignature(alg, key, data, signature) {
  switch (alg) {
    case 'EdDSA':
      return crypto.verify(null, data, key, signature);
    case 'ES256':
      return signature.length === 64 && crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
    case 'RS256':
      return crypto.verify('sha256', data, key, signature);
    case 'PS256':
      return crypto.verify('sha256', data, {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      }, signature);
    default:
      return false;
  }
}

module.exports = {
  VERIFY_ALGORITHMS,
  JoseError,
  parseCompact,
  verificationKey,
  verifySignature,
};
