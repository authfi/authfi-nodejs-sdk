/**
 * AuthFI Node.js SDK
 *
 * Usage:
 *   const authfi = require('@authfi/sdk');
 *
 *   const auth = authfi({
 *     issuer: 'https://acme.authfi.io',          // the project issuer
 *     audience: 'client-id-of-your-api',         // required: the API this server is
 *     publicUrl: 'https://api.example.com',      // origin clients call, for DPoP htu
 *     tenant: 'acme',
 *     apiKey: 'sk_live_...',
 *     apiUrl: 'https://api.authfi.io',
 *     autoSync: true,                            // auto-register permissions on startup
 *   });
 *
 *   // Express middleware: verifies the token (and, for agents, the DPoP proof and the key chain)
 *   app.get('/api/users', auth.require('read:users'), (req, res) => {
 *     console.log(req.user); // verified claims
 *   });
 *
 *   // Outside Express, verify a request directly
 *   const claims = await auth.verifyRequest(req);
 *
 *   // Start server: triggers permission sync
 *   auth.start().then(() => app.listen(3000));
 */

const { AuthFIError, refuse } = require('./lib/errors');
const { checkConfig, createVerifier } = require('./lib/verify');
const { createKeySet } = require('./lib/jwks');
const { createChain, DEFAULT_ROOT_PINS } = require('./lib/chain');
const { validateProof, memoryReplayGuard, currentNonce, MAX_AGE_S, MAX_FUTURE_S } = require('./lib/dpop');
const { parseObject, b64uDecode, verifySignature } = require('./lib/jws');
const { JwsError, createRevocationStore, createReceiver, registerStream } = require('./signals');

const crypto = require('crypto');

const MODES = ['enforce', 'watch', 'off'];
const REPLAY_DEFAULT_MAX = 100000;
const REPLAY_PER_KEY_DEFAULT = 1000;
const PIN_FORMAT = /^[0-9a-f]{64}$/;

const isAgentClaims = (c) => (typeof c.sub === 'string' && c.sub.startsWith('agt_'))
  || (typeof c.client_id === 'string' && c.client_id.startsWith('agt_'))
  || (c.act !== undefined && c.act !== null);

function authfi(config) {
  const {
    tenant,
    apiKey,
    apiUrl = 'https://api.authfi.io',
    applicationId,
    clientSecret,       // required for cloud identity
    autoSync = true,
    jwksRefreshInterval = 300000, // 5 min
    agentTokens = 'enforce',
    publicUrl,
    trustForwarded = false,
    replayGuard,
    nonceKey,
    rootPins,
    rootCerts,
    logger,
    fetch: fetchOverride,
    now: nowOverride,
    clock,              // milliseconds, the same as now
    jwksUrl,
    revocations,        // a store from authfi.createRevocationStore(); makes verification refuse revoked tokens
  } = config;

  const now = typeof nowOverride === 'function' ? nowOverride : typeof clock === 'function' ? clock : Date.now;
  const log = (level, msg, fields) => {
    try { if (logger && typeof logger[level] === 'function') logger[level](msg, fields); } catch { /* a logger must never break a request */ }
  };

  // The edge dispatch is api.authfi.io/<slug>/<path> — the SLUG COMES FIRST. Two shapes,
  // deliberately named apart: root-level protocol paths hang off tenantBase; API routes add /v1.
  const tenantBase = `${apiUrl}/${tenant}`;
  const managePath = `${tenantBase}/v1`;
  const authPath = `${tenantBase}/v1`;
  const registeredPermissions = new Set();

  // --- Verification set-up. Anything wrong here fails every verification closed. ---

  const checked = checkConfig({ ...config, apiUrl });
  const baseErr = checked.error
    || (MODES.includes(agentTokens) ? null : refuse('sdk_not_configured', 'agentTokens is enforce, watch or off'));
  // The project issuer as given, without a trailing slash. The revocation receiver needs it and the key set,
  // not the audience, so its key set is built whenever an issuer is named.
  const issuer = typeof config.issuer === 'string' ? config.issuer.trim().replace(/\/+$/, '') : '';
  const keySet = issuer === '' ? null : createKeySet({
    url: jwksUrl || `${issuer}/.well-known/jwks.json`,
    ttlMs: jwksRefreshInterval,
    fetchFn: fetchOverride,
    now,
  });
  const verifier = baseErr ? null : createVerifier({ conf: checked.value, keySet, now });

  // Proof set-up (publicUrl, nonceKey), checked when a proof is first needed.
  let proofCfg;
  function getProofCfg() {
    if (proofCfg) return proofCfg;
    let publicOrigin;
    if (publicUrl !== undefined) {
      let u;
      try { u = new URL(publicUrl); } catch { throw refuse('sdk_not_configured', 'publicUrl is not a URL'); }
      if (!['https:', 'http:'].includes(u.protocol) || (u.pathname !== '/' && u.pathname !== '') || u.search || u.hash) {
        throw refuse('sdk_not_configured', 'publicUrl is the origin only, for example https://api.example.com');
      }
      publicOrigin = u.origin;
    }
    if (!publicOrigin && !trustForwarded) {
      throw refuse('sdk_not_configured', 'publicUrl is required to check DPoP proofs (or set trustForwarded behind a trusted proxy)');
    }
    let key;
    if (nonceKey !== undefined) {
      key = Buffer.isBuffer(nonceKey) ? nonceKey : typeof nonceKey === 'string' ? Buffer.from(nonceKey) : null;
      if (!key || key.length < 16) throw refuse('sdk_not_configured', 'nonceKey must be at least 16 bytes');
    }
    const guard = replayGuard || memoryReplayGuard(config.replayMax || REPLAY_DEFAULT_MAX, now, config.replayPerKey || REPLAY_PER_KEY_DEFAULT);
    if (typeof guard.record !== 'function') throw refuse('sdk_not_configured', 'replayGuard needs a record(key, expiresAtMs) method');
    proofCfg = { publicOrigin, trustForwarded: trustForwarded === true, nonceKey: key, guard };
    return proofCfg;
  }

  // Chain set-up (pins, extra roots), checked when a chain is first needed.
  let chain;
  function getChain() {
    if (chain) return chain;
    const pins = rootPins === undefined ? DEFAULT_ROOT_PINS : rootPins;
    if (!Array.isArray(pins) || pins.length === 0 || !pins.every((p) => typeof p === 'string' && PIN_FORMAT.test(p))) {
      throw refuse('sdk_not_configured', 'rootPins is a list of lower-case hex SHA-256 values of root public keys');
    }
    const roots = [];
    for (const pem of rootCerts || []) {
      try { roots.push(new crypto.X509Certificate(pem)); } catch { throw refuse('sdk_not_configured', 'rootCerts holds a certificate that is not valid PEM'); }
    }
    chain = createChain({ pins, roots, now });
    return chain;
  }

  // --- Revocation ---

  // checkRevoked refuses a token whose subject, or any actor in its delegation chain, was revoked after
  // it was issued. It runs before a proof is checked, so a withdrawn agent is answered token_revoked
  // wherever its token is presented, and it reads nothing but the claims.
  function checkRevoked(claims) {
    if (!revocations) return;
    // The store forgets a revocation once the longest token it was told about has expired; a longer-lived
    // token would outlive its revocation, so it is refused rather than trusted.
    if (!Number.isFinite(claims.iat) || !Number.isFinite(claims.exp)) {
      throw refuse('token_iat_exp_required', 'the token has no issue or expiry time, which revocation needs');
    }
    if (claims.exp - claims.iat > revocations.tokenLifetimeSeconds) {
      throw refuse('revocation_store_misconfigured', 'the revocation store tokenLifetimeSeconds is shorter than this token lifetime; raise it');
    }
    const subjects = [claims.sub];
    for (let act = claims.act, depth = 0; act && typeof act === 'object' && depth < 16; act = act.act, depth += 1) subjects.push(act.sub);
    for (const subject of subjects) {
      const hit = revocations.find(subject, claims.iat);
      if (hit) {
        const err = refuse('token_revoked', hit.ref ? `the token was revoked (ref ${hit.ref})` : 'the token was revoked');
        err.ref = hit.ref;
        throw err;
      }
    }
  }

  // --- Verification ---

  let offWarned = false;
  function warnOff() {
    if (offWarned) return;
    offWarned = true;
    log('warn', 'authfi: agentTokens is off, so agent tokens are accepted without proof of possession or key chain', {});
  }

  // verifyToken checks a person's access token. An agent token carries a key binding that only a
  // request can prove, so it is refused here with agent_token_needs_request.
  async function verifyToken(token) {
    if (baseErr) throw baseErr;
    const { claims } = await verifier.verifyJWT(token);
    checkRevoked(claims);
    if (isAgentClaims(claims)) {
      if (agentTokens === 'enforce') throw refuse('agent_token_needs_request', 'an agent token is verified with verifyRequest, which checks its proof and key chain');
      if (agentTokens === 'off') warnOff();
      else log('warn', 'authfi: agent token would be refused by verifyToken', { code: 'agent_token_needs_request' });
    }
    if (claims.cnf !== undefined && claims.cnf !== null) throw refuse('token_dpop_proof_required', 'the token is bound to a key and needs a DPoP proof; use verifyRequest');
    return claims;
  }

  function readAuthorization(req) {
    const headers = (req && req.headers) || {};
    if (Array.isArray(req.rawHeaders)) {
      let n = 0;
      for (let i = 0; i < req.rawHeaders.length; i += 2) if (String(req.rawHeaders[i]).toLowerCase() === 'authorization') n++;
      if (n > 1) throw refuse('missing_authorization', 'exactly one Authorization header is allowed');
    }
    const m = typeof headers.authorization === 'string' ? /^(Bearer|DPoP) +(\S+)$/i.exec(headers.authorization) : null;
    if (!m) throw refuse('missing_authorization', 'an Authorization header with a Bearer or DPoP token is required');
    return { scheme: m[1].toLowerCase(), token: m[2] };
  }

  // verifyRequest verifies the token of an HTTP request and, where the token is bound to a key,
  // the DPoP proof of that request. Agent tokens also have to prove the chain of their signing key.
  async function verifyRequest(req) {
    if (baseErr) throw baseErr;
    const { scheme, token } = readAuthorization(req || {});
    const { claims, header, key } = await verifier.verifyJWT(token);
    checkRevoked(claims);
    const agent = isAgentClaims(claims);
    const bound = claims.cnf !== undefined && claims.cnf !== null;
    const checkAgent = agent && agentTokens !== 'off';
    if (!bound && !checkAgent) {
      if (scheme === 'dpop') throw refuse('dpop_key_mismatch', 'the token is not bound to a key; present it as Bearer');
      if (agent) warnOff();
      return claims;
    }
    const run = async () => {
      const jkt = bound && claims.cnf && typeof claims.cnf === 'object' ? claims.cnf.jkt : undefined;
      if (typeof jkt !== 'string' || jkt === '') throw refuse('dpop_key_mismatch', 'the token carries no key binding (cnf.jkt)');
      if (scheme !== 'dpop') throw refuse('dpop_missing', 'a bound token must be presented with the DPoP scheme');
      const pc = getProofCfg();
      const proof = validateProof(req, token, jkt, pc, now());
      if (checkAgent) getChain().prove(key, header['x5t#S256']);
      // Single use: recorded only after every other check has passed.
      let outcome = false;
      try {
        outcome = await pc.guard.record(`${proof.thumb}:${proof.jti}`, proof.iat * 1000 + (MAX_AGE_S + MAX_FUTURE_S + 60) * 1000);
      } catch { outcome = false; }
      if (outcome === 'full') throw refuse('dpop_replay_guard_full', 'the replay guard is full; retry later');
      if (outcome !== true) throw refuse('dpop_replayed', 'the proof was already used');
    };
    if (agent && agentTokens === 'watch') {
      try {
        await run();
      } catch (err) {
        if (!(err instanceof AuthFIError)) throw err;
        log('warn', 'authfi: agent token would be refused', { code: err.code });
      }
      return claims;
    }
    await run();
    return claims;
  }

  // --- JWKS prefetch ---

  async function fetchJWKS() {
    if (baseErr) throw baseErr;
    await keySet.refresh();
  }

  // --- Permission registration ---

  function registerPermission(name, description) {
    registeredPermissions.add(JSON.stringify({ name, description }));
  }

  async function syncPermissions() {
    if (registeredPermissions.size === 0) return;

    const permissions = [...registeredPermissions].map(p => JSON.parse(p));
    const body = { permissions };
    if (applicationId) body.application_id = applicationId;

    const res = await fetch(`${managePath}/permissions/sync`, {
      method: 'PUT',
      headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error('[authfi] Permission sync failed:', err.error || res.status);
      return;
    }

    const data = await res.json();
    console.log(`[authfi] Synced ${data.synced} permissions (${data.total} total)`);
  }


  // --- Middleware ---

  const STATUS_BY_CODE = { jwks_unavailable: 503, dpop_replay_guard_full: 503, sdk_not_configured: 500, revocation_store_misconfigured: 500 };
  const PROOF_CHALLENGE = 'algs="EdDSA ES256 PS256"';

  // respond answers a refusal with its stable code and nothing from the token or the proof.
  function respond(res, err) {
    if (!(err instanceof AuthFIError)) {
      log('warn', 'authfi: unexpected verification failure', {});
      return res.status(500).json({ error: 'sdk_internal' });
    }
    const status = STATUS_BY_CODE[err.code] || 401;
    if (err.code === 'dpop_replay_guard_full' && typeof res.setHeader === 'function') res.setHeader('Retry-After', '5');
    if (status === 401 && typeof res.setHeader === 'function') {
      let challenge;
      if (err.code === 'dpop_nonce') {
        res.setHeader('DPoP-Nonce', err.dpopNonce);
        challenge = `DPoP error="use_dpop_nonce", ${PROOF_CHALLENGE}`;
      } else if (err.code === 'missing_authorization') challenge = `Bearer realm="authfi", DPoP ${PROOF_CHALLENGE}`;
      else if (err.code.startsWith('dpop_')) challenge = `DPoP error="invalid_dpop_proof", ${PROOF_CHALLENGE}`;
      else challenge = `DPoP error="invalid_token", ${PROOF_CHALLENGE}`;
      res.setHeader('WWW-Authenticate', challenge);
    }
    return res.status(status).json({ error: err.code });
  }

  // announceNonce offers the current server nonce on every response when nonces are on.
  function announceNonce(res) {
    if (nonceKey === undefined || baseErr || typeof res.setHeader !== 'function') return;
    try {
      const pc = getProofCfg();
      if (pc.nonceKey) res.setHeader('DPoP-Nonce', currentNonce(pc.nonceKey, now()));
    } catch { /* a configuration problem is reported when a proof is checked */ }
  }

  /**
   * Express middleware that verifies the request (token, and DPoP proof and key chain for agents)
   * and checks required permissions. All specified permissions must be present in the token.
   */
  function require(...permissions) {
    // Register permissions for auto-sync
    for (const p of permissions) {
      registerPermission(p, null);
    }

    return async (req, res, next) => {
      try {
        announceNonce(res);
        const claims = await verifyRequest(req);
        req.user = claims;

        // Check permissions
        const userPerms = Array.isArray(claims.permissions) ? claims.permissions : [];
        for (const required of permissions) {
          if (!userPerms.includes(required)) {
            return res.status(403).json({
              error: 'Insufficient permissions',
              required: permissions,
              missing: permissions.filter(p => !userPerms.includes(p)),
            });
          }
        }

        next();
      } catch (err) {
        return respond(res, err);
      }
    };
  }

  /**
   * Express middleware that checks for specific roles (ANY match).
   */
  function requireRole(...roles) {
    return async (req, res, next) => {
      try {
        announceNonce(res);
        const claims = await verifyRequest(req);
        req.user = claims;

        const userRoles = Array.isArray(claims.roles) ? claims.roles : [];
        if (!roles.some(r => userRoles.includes(r))) {
          return res.status(403).json({
            error: 'Insufficient role',
            required: roles,
          });
        }

        next();
      } catch (err) {
        return respond(res, err);
      }
    };
  }

  /**
   * Express middleware that only verifies the request (no permission check).
   */
  function authenticate() {
    return async (req, res, next) => {
      try {
        announceNonce(res);
        req.user = await verifyRequest(req);
        next();
      } catch (err) {
        return respond(res, err);
      }
    };
  }

  // --- Startup ---

  async function start() {
    // Pre-fetch JWKS
    if (!baseErr) await fetchJWKS().catch(err => console.warn('[authfi] JWKS fetch failed:', err.code || 'error'));

    // Sync permissions
    if (autoSync) {
      await syncPermissions().catch(err => console.warn('[authfi] Sync failed:', err.message));
    }
  }

  // --- Cloud Identity ---

  /**
   * Get cloud provider credentials using AuthFI identity.
   * Requires the user to be authenticated (pass their JWT).
   *
   * @param {string} userToken - The user's AuthFI JWT
   * @param {string} provider - 'aws' | 'gcp' | 'azure'
   * @param {object} options - Provider-specific options
   * @returns {object} Cloud credentials (short-lived)
   *
   * Usage:
   *   const creds = await auth.cloud.credentials(userToken, 'aws', { roleArn: 'arn:...' });
   *   // Use creds.access_key_id, creds.secret_access_key, creds.session_token
   */
  const cloud = {
    /**
     * Get cloud provider credentials using AuthFI identity.
     * Requires applicationId + clientSecret in config.
     *
     * @param {string} userToken - The user's AuthFI JWT
     * @param {string} provider - 'aws' | 'gcp' | 'azure'
     * @param {object} options - Provider-specific options
     * @returns {object} Cloud credentials (short-lived)
     */
    credentials: async (userToken, provider, options = {}) => {
      if (!applicationId || !clientSecret) {
        throw new Error('applicationId and clientSecret required for cloud credentials');
      }
      const res = await fetch(`${authPath}/credentials`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userToken}`,
          'X-Client-ID': applicationId,
          'X-Client-Secret': clientSecret,
        },
        body: JSON.stringify({
          provider,
          role_arn: options.roleArn || options.role_arn,
          project: options.project,
          scope: options.scope,
          ttl: options.ttl || 900,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Cloud credentials failed: ${res.status}`);
      }
      return res.json();
    },

    /**
     * Get a raw OIDC token for manual federation.
     * Requires applicationId + clientSecret in config.
     */
    token: async (userToken, audience, ttl = 900) => {
      if (!applicationId || !clientSecret) {
        throw new Error('applicationId and clientSecret required for cloud token');
      }
      const res = await fetch(`${authPath}/credentials/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userToken}`,
          'X-Client-ID': applicationId,
          'X-Client-Secret': clientSecret,
        },
        body: JSON.stringify({ audience, ttl }),
      });
      if (!res.ok) throw new Error('Failed to get OIDC token');
      return res.json();
    },
  };

  // --- Revocation signals ---

  // verifyJws checks a Security Event Token's structure and signature against the issuer's key set, with
  // the same rules as an access token, and returns its payload. It throws JwsError with the codes the
  // receiver maps to RFC 8935 answers.
  async function verifyJws(token, wantTyp) {
    if (!keySet) throw new JwsError('key_set_unavailable', 'no issuer is configured');
    if (typeof token !== 'string' || token.length > 16 * 1024) throw new JwsError('malformed', 'the token is not a bounded string');
    const parts = token.split('.');
    if (parts.length !== 3) throw new JwsError('malformed', 'a token is three dot-separated parts');
    let header;
    try { header = parseObject(parts[0]); } catch { throw new JwsError('malformed', 'the token header is not valid'); }
    if (!['RS256', 'PS256', 'ES256', 'EdDSA'].includes(header.alg)) throw new JwsError('alg_not_allowed', 'the algorithm of the token is not accepted');
    if (header.crit !== undefined && header.crit !== null) throw new JwsError('crit_not_supported', 'critical header extensions are not supported');
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : '';
    if (typ !== wantTyp) throw new JwsError('typ_invalid', `the token is not of the expected type (typ must be ${wantTyp})`);
    if (typeof header.kid !== 'string' || header.kid === '') throw new JwsError('kid_required', 'the token names no signing key');
    let sig;
    try { sig = b64uDecode(parts[2]); } catch { throw new JwsError('malformed', 'the token signature is not valid'); }
    let key;
    try {
      key = await keySet.get(header.kid);
    } catch (err) {
      if (err && err.code === 'token_unknown_key') throw new JwsError('unknown_key', 'Unknown signing key');
      throw new JwsError('key_set_unavailable', 'Failed to fetch JWKS');
    }
    if (!key.algs.includes(header.alg)) throw new JwsError('alg_key_mismatch', 'the algorithm of the token does not match its signing key');
    if (!verifySignature(header.alg, key.pub, Buffer.from(`${parts[0]}.${parts[1]}`), sig)) throw new JwsError('bad_signature', 'Invalid signature');
    try { return parseObject(parts[1]); } catch { throw new JwsError('malformed', 'the token payload is not valid'); }
  }

  const receiverLogger = { info: (m, f) => log('info', m, f), warn: (m, f) => log('warn', m, f) };

  /**
   * Express-compatible handler for the Shared Signals push delivery (RFC 8935). Mount it at the https
   * endpoint registered with the stream: app.post('/ssf/push', auth.receiver({ audience })). Needs the
   * issuer and revocations options. Throws now, not at the first request, if it cannot work.
   */
  function receiver(receiverConfig) {
    return createReceiver({ issuer, store: revocations, verifyJws, clock: now, logger: receiverLogger }, receiverConfig);
  }

  /** Registers a push stream with the project's transmitter. See registerStream in signals.js. */
  function registerStreamFor(bearer, request) {
    const doFetch = fetchOverride || ((...args) => fetch(...args));
    return registerStream(issuer, bearer, request, doFetch);
  }

  return {
    require,
    requireRole,
    authenticate,
    verifyToken,
    verifyRequest,
    receiver,
    registerStream: registerStreamFor,
    start,
    registerPermission,
    syncPermissions,
    cloud,
  };
}

module.exports = authfi;
module.exports.AuthFIError = AuthFIError;
module.exports.DEFAULT_ROOT_PINS = DEFAULT_ROOT_PINS;
module.exports.createRevocationStore = createRevocationStore;
