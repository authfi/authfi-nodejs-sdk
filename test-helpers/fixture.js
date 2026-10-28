'use strict';
// Shared test fixture: a project issuer, a PKI (root, intermediate, leaf) whose leaf certifies the
// token signing key, a JWKS, a DPoP key, and builders for tokens, proofs and requests.
const crypto = require('node:crypto');
const authfi = require('../index');
const { buildCert, KU, PEN_POLICY } = require('./certs');

const T0 = Date.parse('2026-10-26T12:00:00Z');
const DAY = 86400000;
const ISSUER = 'https://acme.authfi.io';
const AUD = 'orders-api';
const PUBLIC = 'https://api.example.com';

const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const ec = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ed = () => crypto.generateKeyPairSync('ed25519');

function signJWS(header, payload, privateKey, alg = 'ES256') {
  const h = b64u(JSON.stringify(header));
  const p = typeof payload === 'string' ? payload : b64u(JSON.stringify(payload));
  const data = Buffer.from(`${h}.${p}`);
  let sig;
  if (alg === 'ES256') sig = crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  else if (alg === 'EdDSA') sig = crypto.sign(null, data, privateKey);
  else if (alg === 'RS256') sig = crypto.sign('sha256', data, privateKey);
  else if (alg === 'PS256') sig = crypto.sign('sha256', data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  else if (alg === 'HS256') sig = crypto.createHmac('sha256', privateKey).update(data).digest();
  else sig = Buffer.alloc(0);
  return `${h}.${p}.${b64u(sig)}`;
}

function thumbprint(publicKey) {
  const j = publicKey.export({ format: 'jwk' });
  const m = j.kty === 'EC' ? { crv: j.crv, kty: j.kty, x: j.x, y: j.y }
    : j.kty === 'OKP' ? { crv: j.crv, kty: j.kty, x: j.x }
      : { e: j.e, kty: j.kty, n: j.n };
  return b64u(sha256(JSON.stringify(m)));
}

// makePKI builds root -> intermediate -> leaf. Every option is a single fault knob.
function makePKI(o = {}) {
  const root = ec(); const inter = ec();
  const tokenKey = o.tokenKey || ec();
  const valid = { notBefore: T0 - 30 * DAY, notAfter: T0 + 300 * DAY };
  const rootDer = buildCert({
    subject: 'Test Root', issuer: 'Test Root', subjectKey: root.publicKey, signerKey: root.privateKey,
    ...valid, ca: true, keyUsage: KU.keyCertSign | KU.cRLSign, policies: o.rootPolicies, ...o.root,
  });
  const interDer = buildCert({
    subject: 'Test Intermediate', issuer: 'Test Root', subjectKey: inter.publicKey, signerKey: root.privateKey,
    ...valid, ca: true, keyUsage: KU.keyCertSign | KU.cRLSign, policies: [PEN_POLICY], ...o.inter,
  });
  let leafIssuer = 'Test Intermediate';
  let leafSigner = inter.privateKey;
  const mid = [];
  if (o.extraInter) { // a second intermediate between the first and the leaf
    const inter2 = ec();
    mid.push(buildCert({
      subject: 'Test Intermediate 2', issuer: 'Test Intermediate', subjectKey: inter2.publicKey, signerKey: inter.privateKey,
      ...valid, ca: true, keyUsage: KU.keyCertSign | KU.cRLSign, policies: [PEN_POLICY], ...o.extraInter,
    }));
    leafIssuer = 'Test Intermediate 2';
    leafSigner = inter2.privateKey;
  }
  const leafDer = buildCert({
    subject: 'Test Leaf', issuer: leafIssuer, subjectKey: o.leafCertifies || tokenKey.publicKey,
    signerKey: leafSigner, ...valid, ca: false, keyUsage: KU.digitalSignature, policies: [PEN_POLICY], ...o.leaf,
  });
  const x5c = [leafDer, ...mid, interDer, ...(o.omitRoot ? [] : [rootDer])].map((d) => d.toString('base64'));
  return {
    root, inter, tokenKey, rootDer, interDer, leafDer, x5c,
    rootPin: sha256(root.publicKey.export({ type: 'spki', format: 'der' })).toString('hex'),
    leafThumb: b64u(sha256(leafDer)),
  };
}

function jwkOf(publicKey, kid, extra = {}) {
  return { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', ...extra };
}

// scenario wires one valid world. Tests change one thing and expect one refusal.
function scenario(o = {}) {
  const clock = { t: T0 };
  const pki = makePKI(o.pki);
  const kid = 'k1';
  const keyExtra = o.noX5c ? {} : { x5c: o.x5cFn ? o.x5cFn(pki) : pki.x5c, 'x5t#S256': o.jwksX5t || pki.leafThumb, ...o.keyExtra };
  const tokenAlg = 'ES256';
  const jwks = { keys: [jwkOf(pki.tokenKey.publicKey, kid, { alg: tokenAlg, ...keyExtra })] };
  const dpop = o.dpopKey || ed();
  const dpopJwk = dpop.publicKey.export({ format: 'jwk' });
  const fetches = [];
  const fetchOpts = [];
  const fetchImpl = async (url, opts) => {
    fetches.push(String(url));
    fetchOpts.push(opts);
    return new Response(JSON.stringify(o.jwks || jwks), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const config = {
    issuer: ISSUER, audience: AUD, publicUrl: PUBLIC, fetch: fetchImpl, now: () => clock.t,
    rootPins: [pki.rootPin], ...o.config, ...(o.configFn ? o.configFn(pki) : {}),
  };
  const client = authfi({ tenant: 'acme', apiKey: 'sk_test', ...config });
  const s = { clock, pki, kid, jwks, dpop, dpopJwk, fetches, fetchOpts, client, config };

  const sec = () => Math.floor(clock.t / 1000);
  s.claims = (extra = {}) => ({
    iss: ISSUER, aud: AUD, sub: 'usr_1', tenant_id: 'tnt_1', iat: sec(), exp: sec() + 600, ...extra,
  });
  s.agentClaims = (extra = {}) => s.claims({
    sub: 'agt_1', client_id: 'agt_1', cnf: { jkt: thumbprint(dpop.publicKey) }, ...extra,
  });
  s.token = (claims, header = {}, key = pki.tokenKey.privateKey, alg = tokenAlg) => signJWS(
    { alg, typ: 'at+jwt', kid, ...(o.noX5c ? {} : { 'x5t#S256': pki.leafThumb }), ...header }, claims, key, alg,
  );
  s.agentToken = (extra = {}, header = {}) => s.token(s.agentClaims(extra), header);

  let jtiN = 0;
  s.proof = (token, p = {}) => {
    const key = p.pair ? p.pair.privateKey : dpop.privateKey;
    const jwk = p.jwk !== undefined ? p.jwk : (p.pair ? p.pair.publicKey.export({ format: 'jwk' }) : dpopJwk);
    const alg = p.alg || 'EdDSA';
    const claims = {
      jti: `jti-${++jtiN}-${crypto.randomBytes(4).toString('hex')}`, htm: 'GET', htu: `${PUBLIC}/orders`,
      iat: sec(), ath: b64u(sha256(token)), ...p.claims,
    };
    for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
    return signJWS({ typ: 'dpop+jwt', alg, jwk, ...p.header }, p.raw || claims, key, alg);
  };
  // request builds a request object; the authorization scheme and proofs are parameters.
  s.request = (token, o2 = {}) => {
    const headers = { host: 'api.example.com', ...o2.headers };
    const raw = ['Host', 'api.example.com'];
    const scheme = o2.scheme || 'DPoP';
    if (token !== null) { headers.authorization = `${scheme} ${token}`; raw.push('Authorization', headers.authorization); }
    const proofs = o2.proofs === undefined ? [s.proof(token, o2.proof)] : o2.proofs;
    if (proofs.length === 1) headers.dpop = proofs[0];
    else if (proofs.length > 1) headers.dpop = proofs.join(', ');
    for (const p of proofs) raw.push('DPoP', p);
    return { method: o2.method || 'GET', originalUrl: o2.url || '/orders', url: o2.url || '/orders', headers, rawHeaders: raw };
  };
  return s;
}

async function rejectsWith(promise, code, assert) {
  let err;
  try { await promise; } catch (e) { err = e; }
  assert.ok(err, `expected refusal ${code}, got success`);
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
  return err;
}

module.exports = { scenario, makePKI, signJWS, thumbprint, jwkOf, rejectsWith, b64u, sha256, ec, ed, T0, DAY, ISSUER, AUD, PUBLIC };
