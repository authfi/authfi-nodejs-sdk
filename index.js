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

module.exports = function authfi(config) {
  const {
    tenant,
    apiKey,
    apiUrl = 'https://api.authfi.io',
    applicationId,
    clientSecret,       // required for cloud identity
    autoSync = true,
    jwksRefreshInterval = 300000, // 5 min
  } = config;

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
  let jwksCache = null;
  let jwksCacheTime = 0;

  // --- JWKS ---

  async function fetchJWKS() {
    const now = Date.now();
    if (jwksCache && now - jwksCacheTime < jwksRefreshInterval) return jwksCache;

    const res = await fetch(`${tenantBase}/.well-known/jwks.json`);
    if (!res.ok) throw new Error('Failed to fetch JWKS');
    jwksCache = await res.json();
    jwksCacheTime = now;
    return jwksCache;
  }

  async function verifyToken(token) {
    // Decode header to get kid
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    // Check expiry
    if (payload.exp && payload.exp < Date.now() / 1000) {
      throw new Error('Token expired');
    }

    // Enforce RS256 algorithm
    if (header.alg !== 'RS256') {
      throw new Error('Unsupported algorithm: ' + header.alg);
    }

    // Fetch JWKS and find matching key
    const jwks = await fetchJWKS();
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) throw new Error('Unknown signing key');

    // Verify signature using Node.js crypto
    const publicKey = crypto.createPublicKey({ key, format: 'jwk' });
    const signedData = `${headerB64}.${payloadB64}`;
    const signature = Buffer.from(signatureB64, 'base64url');
    const valid = crypto.verify('sha256', Buffer.from(signedData), publicKey, signature);
    if (!valid) throw new Error('Invalid signature');

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

  return {
    require,
    requireRole,
    authenticate,
    verifyToken,
    start,
    registerPermission,
    syncPermissions,
    cloud,
  };
};
