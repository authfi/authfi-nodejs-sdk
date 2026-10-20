'use strict';

// Compact JWS parsing and verification with the algorithm pinned by the key, never by the token.
//
// A token header names an algorithm, but the verifier decides it: the key the kid selects implies
// one algorithm, and a header that names any other is refused. That closes alg confusion (an RSA
// public key used as an HMAC secret) and "none".

const crypto = require('crypto');

/** The algorithms an AuthFI issuer signs tokens with, and the only ones verified here. */
const VERIFY_ALGORITHMS = Object.freeze(['RS256', 'PS256', 'ES256', 'EdDSA']);

/**
 * The algorithms an agent key may sign with, as the platform's key rules define them: the key type
 * decides, Ed25519 -> EdDSA, P-256 -> ES256, RSA -> PS256. RS256 is not offered for a client key.
 */
const SIGNING_ALGORITHMS = Object.freeze(['EdDSA', 'ES256', 'PS256']);

const MIN_RSA_BITS = 2048;
const MAX_RSA_BITS = 4096;
const RSA_EXPONENT = 65537n;

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

function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * The algorithm a private KeyObject signs with as an agent key, or a JoseError saying why the key
 * cannot be one. Mirrors the platform's checks, so a key refused here would be refused there.
 */
function signingAlgorithm(key) {
  if (!key || key.type !== 'private') throw new JoseError('key_unusable', 'An agent key must be a private key');
  const type = key.asymmetricKeyType;
  const details = key.asymmetricKeyDetails || {};
  if (type === 'ed25519') return 'EdDSA';
  if (type === 'ec') {
    if (details.namedCurve !== 'prime256v1') {
      throw new JoseError('key_unusable', `An EC agent key must be P-256, but this one is ${details.namedCurve}`);
    }
    return 'ES256';
  }
  if (type === 'rsa') {
    if (details.modulusLength < MIN_RSA_BITS || details.modulusLength > MAX_RSA_BITS) {
      throw new JoseError('key_unusable', `An RSA agent key must be 2048 to 4096 bits, but this one is ${details.modulusLength}`);
    }
    if (details.publicExponent !== RSA_EXPONENT) {
      throw new JoseError('key_unusable', 'An RSA agent key must use the public exponent 65537');
    }
    return 'PS256';
  }
  throw new JoseError('key_unusable', `An agent key must be Ed25519, P-256 or RSA, but this one is ${type}`);
}

/** Signs data with the algorithm the key implies. */
function signWith(alg, key, data) {
  switch (alg) {
    case 'EdDSA':
      return crypto.sign(null, data, key);
    case 'ES256':
      return crypto.sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
    case 'PS256':
      return crypto.sign('sha256', data, {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });
    default:
      throw new JoseError('key_unusable', `Cannot sign ${alg}`);
  }
}

/** Builds and signs a compact JWS. */
function signCompact(header, payload, alg, key) {
  const input = `${b64uEncode(JSON.stringify(header))}.${b64uEncode(JSON.stringify(payload))}`;
  return `${input}.${b64uEncode(signWith(alg, key, Buffer.from(input, 'ascii')))}`;
}

/** The RFC 7638 thumbprint of a public JWK. */
function thumbprint(jwk) {
  const members = { OKP: ['crv', 'kty', 'x'], EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'] }[jwk.kty];
  if (!members) throw new JoseError('key_unusable', `No thumbprint for key type ${jwk.kty}`);
  const canonical = `{${members.map((m) => `${JSON.stringify(m)}:${JSON.stringify(jwk[m])}`).join(',')}}`;
  return b64uEncode(crypto.createHash('sha256').update(canonical).digest());
}

module.exports = {
  VERIFY_ALGORITHMS,
  SIGNING_ALGORITHMS,
  b64uEncode,
  signingAlgorithm,
  signCompact,
  thumbprint,
  JoseError,
  parseCompact,
  verificationKey,
  verifySignature,
};
