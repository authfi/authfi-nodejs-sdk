/**
 * AuthFI Node.js SDK
 *
 * Usage:
 *   const authfi = require('@authfi/node');
 *
 *   const auth = authfi({
 *     tenant: 'acme',
 *     apiKey: 'sk_live_...',
 *     apiUrl: 'https://api.authfi.io',
 *     applicationId: 'client-id-of-your-app',   // optional: scope permissions to this app
 *     autoSync: true,                            // auto-register permissions on startup
 *   });
 *
 *   // Express middleware — validates JWT + checks permissions
 *   app.get('/api/users', auth.require('read:users'), (req, res) => {
 *     console.log(req.user); // decoded JWT claims
 *   });
 *
 *   // Check multiple permissions (ALL required)
 *   app.delete('/api/users/:id', auth.require('read:users', 'delete:users'), handler);
 *
 *   // Check role instead
 *   app.get('/admin', auth.requireRole('admin'), handler);
 *
 *   // Start server — triggers permission sync
 *   auth.start().then(() => app.listen(3000));
 */

const crypto = require('crypto');
const { JwsError, createRevocationStore, createReceiver, registerStream } = require('./signals');

const JWKS_MIN_REFETCH_MS = 15000;
const MAX_TOKEN_BYTES = 16 * 1024;
const ALLOWED_ALGS = new Set(['RS256', 'PS256', 'ES256', 'EdDSA']);
const B64URL = /^[A-Za-z0-9_-]+$/;
const noopLogger = { info() {}, warn() {} };

/** Whether this JWK may verify `alg`: the key type, curve and its own alg all have to agree. */
function keyAllows(jwk, alg) {
  if (!jwk || (jwk.use && jwk.use !== 'sig')) return false;
  if (jwk.alg && jwk.alg !== alg) return false;
  switch (jwk.kty) {
    case 'RSA':
      return (alg === 'RS256' || alg === 'PS256') && typeof jwk.n === 'string' && Buffer.from(jwk.n, 'base64url').length * 8 >= 2048;
    case 'EC':
      return alg === 'ES256' && jwk.crv === 'P-256';
    case 'OKP':
      return alg === 'EdDSA' && jwk.crv === 'Ed25519';
    default:
      return false;
  }
}

function checkSignature(alg, jwk, signedData, signature) {
  let key;
  try {
    key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch (e) {
    return false;
  }
  const data = Buffer.from(signedData);
  switch (alg) {
    case 'RS256':
      return crypto.verify('sha256', data, key, signature);
    case 'PS256':
      return crypto.verify('sha256', data, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
    case 'ES256':
      return signature.length === 64 && crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
    case 'EdDSA':
      return crypto.verify(null, data, key, signature);
    default:
      return false;
  }
}

function decodeJsonSegment(segment) {
  if (!B64URL.test(segment)) throw new Error('not base64url');
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

module.exports = function authfi(config) {
  const {
    tenant,
    apiKey,
    apiUrl = 'https://api.authfi.io',
    applicationId,
    clientSecret,       // required for cloud identity
    autoSync = true,
    jwksRefreshInterval = 300000, // 5 min
    issuer: issuerOption,   // the project issuer, e.g. https://acme.authfi.io; needed by receiver()
    revocations,            // a store from authfi.createRevocationStore(); makes verifyToken refuse revoked tokens
    logger = noopLogger,    // { info, warn }: receives receiver events, never a token
    clock = Date.now,       // milliseconds; tests only
  } = config;
  const issuer = typeof issuerOption === 'string' ? issuerOption.trim().replace(/\/+$/, '') : '';

  // The edge dispatch is api.authfi.io/<slug>/<path> — the SLUG COMES FIRST. Every path here had
  // the slug and the version transposed, so every URL 404'd against a real deployment, the JWKS
  // fetch among them.
  //
  // Two shapes, deliberately named apart: root-level protocol paths (JWKS, OIDC discovery,
  // /oauth/*) hang off tenantBase; API routes add /v1. Conflating them is how a straight
  // transposition still leaves JWKS broken.
  const tenantBase = `${apiUrl}/${tenant}`;
  // No /manage/ prefix exists on the platform; those routes are /v1/* like the rest.
  const managePath = `${tenantBase}/v1`;
  const authPath = `${tenantBase}/v1`;
  const registeredPermissions = new Set();
  const jwksUrl = `${issuer || tenantBase}/.well-known/jwks.json`;
  let jwksCache = null;
  let jwksCacheTime = 0;
  let jwksFlight = null;
  let jwksAttempted = 0;

  // --- JWKS ---

  async function fetchJWKS(force = false) {
    const now = clock();
    if (jwksCache && !force && now - jwksCacheTime < jwksRefreshInterval) return jwksCache;
    // One fetch at a time: a burst of requests waits for the same answer.
    if (jwksFlight) return jwksFlight;
    jwksAttempted = now;
    jwksFlight = (async () => {
      try {
        const res = await fetch(jwksUrl);
        if (!res.ok) throw new Error('Failed to fetch JWKS');
        const doc = await res.json();
        if (!doc || !Array.isArray(doc.keys)) throw new Error('Failed to fetch JWKS');
        jwksCache = doc;
        jwksCacheTime = clock();
        return jwksCache;
      } finally {
        jwksFlight = null;
      }
    })();
    return jwksFlight;
  }

  /** The issuer's key named by kid. An unknown kid costs at most one refetch per 15 seconds. */
  async function getKey(kid) {
    let jwks;
    try {
      jwks = await fetchJWKS();
    } catch (e) {
      throw new JwsError('key_set_unavailable', 'Failed to fetch JWKS');
    }
    let key = jwks.keys.find((k) => k && k.kid === kid);
    if (!key && clock() - jwksAttempted >= JWKS_MIN_REFETCH_MS) {
      try {
        jwks = await fetchJWKS(true);
        key = jwks.keys.find((k) => k && k.kid === kid);
      } catch (e) {
        throw new JwsError('key_set_unavailable', 'Failed to fetch JWKS');
      }
    }
    if (!key) throw new JwsError('unknown_key', 'Unknown signing key');
    return key;
  }

  /**
   * Checks the structure and signature of a compact JWS against the issuer's key set and returns
   * the decoded payload: size, three parts, an allowed alg, no critical extensions, the media type
   * wantTyp, a kid, and a signature by that key under an alg it may use. Reads nothing from the
   * payload. Throws JwsError with a stable code.
   */
  async function verifyJws(token, wantTyp) {
    if (typeof token !== 'string' || token.length > MAX_TOKEN_BYTES) throw new JwsError('malformed', 'the token is not a bounded string');
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((p) => p === '')) throw new JwsError('malformed', 'a token is three dot-separated parts');
    let header;
    try {
      header = decodeJsonSegment(parts[0]);
    } catch (e) {
      throw new JwsError('malformed', 'the token header is not valid');
    }
    if (!header || typeof header !== 'object' || Array.isArray(header)) throw new JwsError('malformed', 'the token header is not valid');
    if (!ALLOWED_ALGS.has(header.alg)) throw new JwsError('alg_not_allowed', 'the algorithm of the token is not accepted');
    if (header.crit !== undefined && header.crit !== null) throw new JwsError('crit_not_supported', 'critical header extensions are not supported');
    const typ = String(header.typ || '').toLowerCase().replace(/^application\//, '');
    if (typ !== wantTyp) throw new JwsError('typ_invalid', `the token is not of the expected type (typ must be ${wantTyp})`);
    if (typeof header.kid !== 'string' || header.kid === '') throw new JwsError('kid_required', 'the token names no signing key');
    if (!B64URL.test(parts[2])) throw new JwsError('malformed', 'the token signature is not valid');
    const key = await getKey(header.kid);
    if (!keyAllows(key, header.alg)) throw new JwsError('alg_key_mismatch', 'the algorithm of the token does not match its signing key');
    const signature = Buffer.from(parts[2], 'base64url');
    if (!checkSignature(header.alg, key, `${parts[0]}.${parts[1]}`, signature)) throw new JwsError('bad_signature', 'Invalid signature');
    try {
      return decodeJsonSegment(parts[1]);
    } catch (e) {
      throw new JwsError('malformed', 'the token payload is not valid');
    }
  }

  async function verifyToken(token) {
    // Decode header to get kid
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    // Check expiry
    if (payload.exp && payload.exp < clock() / 1000) {
      throw new Error('Token expired');
    }

    // Only the algorithms the issuer signs with; a Security Event Token is never an access token.
    if (!ALLOWED_ALGS.has(header.alg)) {
      throw new Error('Unsupported algorithm: ' + header.alg);
    }
    if (String(header.typ || '').toLowerCase().includes('secevent')) {
      throw new Error('Not an access token');
    }

    // Fetch JWKS and find matching key
    const key = await getKey(header.kid);
    if (!keyAllows(key, header.alg)) throw new Error('Unsupported algorithm: ' + header.alg);

    // Verify signature using Node.js crypto
    const signature = Buffer.from(signatureB64, 'base64url');
    if (!checkSignature(header.alg, key, `${headerB64}.${payloadB64}`, signature)) throw new Error('Invalid signature');

    // A subject (or the actor on a delegated token) revoked after this token was issued.
    if (revocations) {
      const actor = payload.act && typeof payload.act === 'object' ? payload.act.sub : undefined;
      if (revocations.isRevoked(payload.sub, payload.iat) || (actor && revocations.isRevoked(actor, payload.iat))) {
        const err = new Error('Token revoked');
        err.code = 'token_revoked';
        throw err;
      }
    }

    return payload;
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

  /**
   * Express middleware that validates JWT and checks required permissions.
   * All specified permissions must be present in the token.
   */
  function require(...permissions) {
    // Register permissions for auto-sync
    for (const p of permissions) {
      registerPermission(p, null);
    }

    return async (req, res, next) => {
      try {
        const token = extractBearer(req);
        if (!token) return res.status(401).json({ error: 'Missing authorization' });

        const claims = await verifyToken(token);
        req.user = claims;

        // Check permissions
        const userPerms = claims.permissions || [];
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
        return res.status(401).json({ error: err.message });
      }
    };
  }

  /**
   * Express middleware that checks for specific roles (ANY match).
   */
  function requireRole(...roles) {
    return async (req, res, next) => {
      try {
        const token = extractBearer(req);
        if (!token) return res.status(401).json({ error: 'Missing authorization' });

        const claims = await verifyToken(token);
        req.user = claims;

        const userRoles = claims.roles || [];
        if (!roles.some(r => userRoles.includes(r))) {
          return res.status(403).json({
            error: 'Insufficient role',
            required: roles,
          });
        }

        next();
      } catch (err) {
        return res.status(401).json({ error: err.message });
      }
    };
  }

  /**
   * Express middleware that only validates the JWT (no permission check).
   */
  function authenticate() {
    return async (req, res, next) => {
      try {
        const token = extractBearer(req);
        if (!token) return res.status(401).json({ error: 'Missing authorization' });
        req.user = await verifyToken(token);
        next();
      } catch (err) {
        return res.status(401).json({ error: err.message });
      }
    };
  }

  function extractBearer(req) {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer ')) return auth.slice(7);
    return null;
  }

  // --- Startup ---

  async function start() {
    // Pre-fetch JWKS
    await fetchJWKS().catch(err => console.warn('[authfi] JWKS fetch failed:', err.message));

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

  /**
   * Express-compatible handler for the Shared Signals push delivery (RFC 8935). Mount it at the
   * https endpoint registered with the stream: app.post('/ssf/push', auth.receiver({ audience })).
   * Needs the issuer and revocations options. Throws now, not at the first request, if it cannot work.
   */
  function receiver(receiverConfig) {
    return createReceiver({ issuer, store: revocations, verifyJws, clock, logger }, receiverConfig);
  }

  /** Registers a push stream with the project's transmitter. See registerStream in signals.js. */
  function registerStreamFor(bearer, request) {
    return registerStream(issuer, bearer, request, (...args) => fetch(...args));
  }

  return {
    require,
    requireRole,
    authenticate,
    verifyToken,
    receiver,
    registerStream: registerStreamFor,
    start,
    registerPermission,
    syncPermissions,
    cloud,
  };
};

module.exports.createRevocationStore = createRevocationStore;
