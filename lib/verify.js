'use strict';
const { refuse } = require('./errors');
const { b64uDecode, parseObject, verifySignature } = require('./jws');

const MAX_TOKEN_BYTES = 16 * 1024;
const DEFAULT_LEEWAY_S = 60;
const MAX_LEEWAY_S = 300;
const MAX_NUMERIC_DATE = 253402300799; // 9999-12-31T23:59:59Z
const ALGS = ['RS256', 'PS256', 'ES256', 'EdDSA'];

// AuthFI's own client ids: a token minted for one of them is for AuthFI, not for a customer's API.
const FIRST_PARTY_AUDIENCES = new Set(['authfi-console', 'authfi-workspace']);

const trimSlash = (s) => String(s || '').replace(/\/+$/, '');

function isLoopback(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

// checkConfig validates what verification depends on. The factory runs it once and keeps the
// result, so every verification fails closed with it. It returns { error } or { value }.
function checkConfig(cfg) {
  const bad = (m) => ({ error: refuse('sdk_not_configured', m) });
  if (typeof cfg.issuer !== 'string' || cfg.issuer === '') return bad('issuer is required: the project issuer, for example https://acme.authfi.io');
  let url;
  try { url = new URL(cfg.issuer); } catch { return bad('issuer is not a URL'); }
  if (!(url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url.hostname)))) return bad('issuer must be an https URL');
  if (url.search || url.hash || url.username || url.password) return bad('issuer must not carry a query, fragment or credentials');
  const aud = typeof cfg.audience === 'string' ? [cfg.audience] : cfg.audience;
  if (!Array.isArray(aud) || aud.length === 0) return bad('audience is required: the client id of your API. There is no way to skip the audience check');
  const issuer = trimSlash(cfg.issuer);
  const api = trimSlash(cfg.apiUrl);
  for (const a of aud) {
    if (typeof a !== 'string' || a.trim() === '') return bad('audience holds an empty value');
    if (a === issuer || a.startsWith(`${issuer}/`) || (api && (a === api || a.startsWith(`${api}/`))) || FIRST_PARTY_AUDIENCES.has(a)) {
      return bad('audience is an AuthFI audience; mint the token with resource=<the client id of your API> and verify that audience');
    }
  }
  let leeway = DEFAULT_LEEWAY_S;
  if (cfg.leeway !== undefined) {
    if (typeof cfg.leeway !== 'number' || !(cfg.leeway >= 0) || cfg.leeway > MAX_LEEWAY_S) return bad('leeway is a number of seconds, 0 to 300');
    leeway = cfg.leeway;
  }
  if (cfg.tenantId !== undefined && (typeof cfg.tenantId !== 'string' || cfg.tenantId === '')) return bad('tenantId must be a non-empty string');
  return { value: { issuer, audience: aud, leewayMs: leeway * 1000, tenantId: cfg.tenantId } };
}

function numericDate(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= MAX_NUMERIC_DATE;
}

// createVerifier verifies an access token against the project issuer. Every rule fails closed.
function createVerifier({ conf, keySet, now }) {
  async function verifyJWT(token) {
    if (typeof token !== 'string') throw refuse('token_malformed', 'a token is a string');
    if (token.length > MAX_TOKEN_BYTES) throw refuse('token_too_large', `the token is larger than ${MAX_TOKEN_BYTES} bytes`);
    const parts = token.split('.');
    if (parts.length !== 3) throw refuse('token_malformed', 'a token is three dot-separated parts');
    let header;
    try { header = parseObject(parts[0]); } catch { throw refuse('token_malformed', 'the token header is not valid'); }
    if (!ALGS.includes(header.alg)) throw refuse('token_alg_not_allowed', 'the algorithm of the token is not accepted');
    if (header.crit !== undefined && header.crit !== null) throw refuse('token_crit_not_supported', 'the token carries critical header extensions this SDK does not understand');
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : '';
    if (typ !== 'at+jwt') throw refuse('token_typ_invalid', 'the token is not an access token (typ must be at+jwt)');
    if (typeof header.kid !== 'string' || header.kid === '') throw refuse('token_kid_required', 'the token names no signing key');
    let sig;
    try { sig = b64uDecode(parts[2]); } catch { throw refuse('token_malformed', 'the token signature is not valid'); }
    if (sig.length === 0) throw refuse('token_malformed', 'the token signature is not valid');

    const key = await keySet.get(header.kid); // only ever the issuer's own key set
    if (!key.algs.includes(header.alg)) throw refuse('token_alg_key_mismatch', 'the algorithm of the token does not match its signing key');
    if (!verifySignature(header.alg, key.pub, Buffer.from(`${parts[0]}.${parts[1]}`), sig)) throw refuse('token_signature_invalid', 'the token signature does not verify');

    let claims;
    try { claims = parseObject(parts[1]); } catch { throw refuse('token_malformed', 'the token payload is not valid'); }
    checkClaims(claims);
    return { claims, header, key };
  }

  function checkClaims(c) {
    const t = now();
    if (typeof c.iss !== 'string' || trimSlash(c.iss) !== conf.issuer) throw refuse('token_issuer_mismatch', 'the token was not issued by this project');
    if (!numericDate(c.exp)) throw refuse('token_exp_required', 'the token has no valid expiry');
    if (t >= c.exp * 1000 + conf.leewayMs) throw refuse('token_expired', 'the token has expired');
    for (const f of ['nbf', 'iat']) {
      if (c[f] === undefined) continue;
      if (!numericDate(c[f])) throw refuse('token_malformed', `the ${f} claim is not valid`);
      if (t + conf.leewayMs < c[f] * 1000) throw refuse('token_not_yet_valid', `the token ${f} is in the future`);
    }
    const have = typeof c.aud === 'string' ? [c.aud] : Array.isArray(c.aud) ? c.aud : [];
    if (!have.some((a) => typeof a === 'string' && a !== '' && conf.audience.includes(a))) throw refuse('token_audience_mismatch', 'the token is not for this API');
    if (typeof c.sub !== 'string' || c.sub === '') throw refuse('token_sub_required', 'the token has no subject');
    if (typeof c.tenant_id !== 'string' || c.tenant_id === '') throw refuse('token_tenant_required', 'the token names no tenant');
    if (conf.tenantId !== undefined && c.tenant_id !== conf.tenantId) throw refuse('token_tenant_not_issuers', 'the token belongs to another tenant');
    if (c.act !== undefined && c.act !== null) {
      if (typeof c.act !== 'object' || Array.isArray(c.act)) throw refuse('token_malformed', 'the act claim is not valid');
      if (c.act.act !== undefined && c.act.act !== null) throw refuse('token_act_chain_unsupported', 'a delegation chain is not supported');
    }
  }

  return { verifyJWT };
}

module.exports = { checkConfig, createVerifier };
