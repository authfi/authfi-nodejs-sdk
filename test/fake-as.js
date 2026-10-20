'use strict';

// A fake AuthFI authorization server for agent tests. It checks a client assertion the way the
// platform does (the kernel's clientassertion package): the kid selects a registered key, the
// key's type decides the algorithm and the header must agree, iss and sub name the client, aud is
// the token endpoint or the issuer, the lifetime is at most five minutes plus skew, and a jti is
// single-use. Signatures are checked with node:crypto directly, not with the SDK's code.

const crypto = require('crypto');

const ISSUER = 'https://acme.authfi.io';
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const BACKCHANNEL = `${ISSUER}/apis/regional/v1/ai/auth/backchannel-authorize`;
const TX = 'urn:ietf:params:oauth:grant-type:token-exchange';
const CIBA = 'urn:openid:params:grant-type:ciba';

function decode(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function algOfJwk(jwk) {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  if (jwk.kty === 'RSA') return 'PS256';
  return null;
}

function verifySig(alg, jwk, input, sig) {
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  if (alg === 'EdDSA') return crypto.verify(null, input, key, sig);
  if (alg === 'ES256') return crypto.verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, sig);
  return crypto.verify('sha256', input, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
}

function fakeAS({ metadata = {}, docIssuer = ISSUER } = {}) {
  const as = {
    clients: new Map(), // client_id -> [public JWK]
    seen: new Set(),
    requests: [],
    assertions: [],
    ciba: new Map(), // auth_req_id -> {status, polls}
    pollScript: [], // errors to answer CIBA polls with, in order, before the token
    exchangeAllowed: true,
    tokenTtl: 900,
    minted: 0,
    omitExpiresIn: false,
    headers: {},
    other: null, // answers any other URL, for tests of what the SDK sends to a gateway
  };

  const json = (status, body) => new Response(JSON.stringify(as.omitExpiresIn ? { ...body, expires_in: undefined } : body), {
    status,
    headers: { 'content-type': 'application/json', ...as.headers },
  });
  const oauthErr = (status, error, desc) => json(status, { error, error_description: desc });

  function checkAssertion(form) {
    if (form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return 'assertion_type_unsupported';
    const parts = String(form.get('client_assertion') || '').split('.');
    if (parts.length !== 3) return 'assertion_malformed';
    const header = decode(parts[0]);
    const claims = decode(parts[1]);
    as.assertions.push({ header, claims });
    const keys = as.clients.get(form.get('client_id')) || [];
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return 'assertion_kid_unknown';
    if (header.alg !== algOfJwk(jwk)) return 'assertion_alg_mismatch';
    if (!verifySig(header.alg, jwk, Buffer.from(`${parts[0]}.${parts[1]}`), Buffer.from(parts[2], 'base64url'))) return 'assertion_signature_invalid';
    if (claims.iss !== form.get('client_id') || claims.sub !== form.get('client_id')) return 'assertion_client_mismatch';
    if (![TOKEN_ENDPOINT, ISSUER].includes(claims.aud)) return 'assertion_audience_invalid';
    const now = Math.floor(Date.now() / 1000);
    if (!claims.exp || claims.exp + 60 <= now) return 'assertion_expired';
    if (claims.exp - (claims.iat || now) > 360) return 'assertion_lifetime_exceeded';
    if (!claims.jti) return 'assertion_jti_missing';
    if (as.seen.has(claims.jti)) return 'assertion_replayed';
    as.seen.add(claims.jti);
    return null;
  }

  function token(sub, extra = {}) {
    as.minted += 1;
    const claims = { iss: ISSUER, sub, aud: extra.aud || `${ISSUER}/mcp`, n: as.minted, exp: Math.floor(Date.now() / 1000) + as.tokenTtl, ...extra };
    return `${Buffer.from('{"alg":"EdDSA"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;
  }

  as.fetch = async (input, init = {}) => {
    const url = String(typeof input === 'string' ? input : input.url);
    const form = new URLSearchParams(init.body || '');
    as.requests.push({ url, form, headers: new Headers(init.headers) });
    if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
      return json(200, {
        issuer: docIssuer,
        token_endpoint: TOKEN_ENDPOINT,
        backchannel_authentication_endpoint: BACKCHANNEL,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        grant_types_supported: ['client_credentials', TX, CIBA],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'private_key_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['EdDSA', 'ES256', 'PS256'],
        ...metadata,
      });
    }
    if (url === BACKCHANNEL) {
      const bad = checkAssertion(form);
      if (bad) return oauthErr(401, 'invalid_client', bad);
      const id = crypto.randomUUID();
      as.ciba.set(id, { client: form.get('client_id'), loginHint: form.get('login_hint') });
      return json(200, { auth_req_id: id, expires_in: 300, interval: 2 });
    }
    if (url === TOKEN_ENDPOINT) {
      const grant = form.get('grant_type');
      if (grant === TX) {
        if (form.get('client_id') || form.get('client_assertion')) return oauthErr(400, 'unsupported_grant_type', 'agent service serves client_credentials and CIBA only');
        if (!as.exchangeAllowed) return oauthErr(403, 'access_denied', 'the actor may not act for this subject');
        const actor = decode(String(form.get('actor_token')).split('.')[1]).sub;
        const subject = decode(String(form.get('subject_token')).split('.')[1]).sub;
        return json(200, {
          access_token: token(subject, { act: { sub: actor }, aud: form.get('resource') || `${ISSUER}/mcp` }),
          token_type: 'Bearer', expires_in: as.tokenTtl, scope: form.get('scope') || '',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        });
      }
      const bad = checkAssertion(form);
      if (bad) return oauthErr(401, 'invalid_client', bad);
      if (grant === 'client_credentials') {
        const extra = form.get('resource') ? { aud: form.get('resource') } : {};
        return json(200, { access_token: token(form.get('client_id'), extra), token_type: 'Bearer', expires_in: as.tokenTtl, capabilities: ['mcp:read'] });
      }
      if (grant === CIBA) {
        const req = as.ciba.get(form.get('auth_req_id'));
        if (!req) return oauthErr(400, 'invalid_grant', 'unknown auth_req_id');
        const next = as.pollScript.shift();
        if (next) return oauthErr(400, next, next);
        return json(200, { access_token: token(`user:${req.loginHint}`, { act: { sub: `agent:${req.client}` } }), token_type: 'Bearer', expires_in: as.tokenTtl });
      }
      return oauthErr(400, 'unsupported_grant_type', grant);
    }
    if (as.other) return as.other(url, init);
    return json(404, { error: 'not_found' });
  };

  as.register = (clientId, key) => {
    const list = as.clients.get(clientId) || [];
    list.push(key.publicJwk());
    as.clients.set(clientId, list);
  };
  as.tokenRequests = () => as.requests.filter((r) => r.url === TOKEN_ENDPOINT);
  return as;
}

module.exports = { fakeAS, ISSUER, TOKEN_ENDPOINT, BACKCHANNEL, TX, CIBA, decode };
