/**
 * AuthFI Node.js SDK
 *
 * Usage:
 *   const authfi = require('@authfi/sdk');
 *
 *   const auth = authfi({
 *     issuer: 'https://acme.authfi.io',            // the project's origin, which is its issuer
 *     audience: 'https://api.acme.com',            // what this API accepts in a token's aud
 *     apiKey: 'sk_live_...',                       // only for permission sync
 *     applicationId: 'client-id-of-your-app',      // optional: scope permissions to this app
 *     autoSync: true,                              // auto-register permissions on startup
 *   });
 *
 *   // Express middleware — validates the token + checks permissions
 *   app.get('/api/users', auth.require('read:users'), (req, res) => {
 *     console.log(req.user); // verified token claims
 *   });
 *
 *   // Check multiple permissions (ALL required)
 *   app.delete('/api/users/:id', auth.require('read:users', 'delete:users'), handler);
 *
 *   // Check role instead
 *   app.get('/admin', auth.requireRole('admin'), handler);
 *
 *   // Start server — fetches the issuer's keys and triggers permission sync
 *   auth.start().then(() => app.listen(3000));
 */

const { createVerifier, TokenError, ConfigError } = require('./lib/verify');

module.exports = function authfi(config) {
  const {
    tenant,
    apiKey,
    apiUrl = 'https://api.authfi.io',
    // The project's own origin, which is also its issuer. Pass it for a custom domain or a
    // self-hosted deployment; otherwise it is https://<tenant>.<baseDomain>.
    issuer,
    // The zone projects live under: authfi.io in production. A domain is never hard-coded into
    // an issuer, so both levels are configurable.
    baseDomain = 'authfi.io',
    // The audience this API accepts: a string or a list. Required to verify tokens.
    audience,
    applicationId,
    clientSecret,       // required for cloud identity
    autoSync = true,
    jwksRefreshInterval = 300000, // 5 min
    clockTolerance = 30, // seconds
    fetch: fetchFn,
  } = config;

  // Permission sync and cloud credentials still address api.authfi.io; token verification reads
  // everything from the project issuer's own discovery document.
  const tenantBase = `${apiUrl}/${tenant}`;
  // No /manage/ prefix exists on the platform; those routes are /v1/* like the rest.
  const managePath = `${tenantBase}/v1`;
  const authPath = `${tenantBase}/v1`;
  const registeredPermissions = new Set();

  // --- Token verification ---

  let verifier = null;
  function getVerifier() {
    if (verifier) return verifier;
    const iss = issuer || (tenant ? `https://${tenant}.${baseDomain}` : null);
    if (!iss) throw new ConfigError('issuer (or tenant) is required to verify tokens');
    try {
      verifier = createVerifier({
        issuer: iss,
        audience,
        fetch: fetchFn,
        jwksTtlMs: jwksRefreshInterval,
        clockToleranceSec: clockTolerance,
      });
    } catch (e) {
      // A bad issuer or a missing audience is a construction-time fact, so it is configuration.
      throw e instanceof ConfigError ? e : new ConfigError(e.message);
    }
    return verifier;
  }

  /**
   * Verifies an access token from this project and returns its claims. The algorithm comes from
   * the issuer's key, never from the token; iss must be the issuer, aud must contain `audience`,
   * and exp is required.
   */
  async function verifyToken(token) {
    return getVerifier().verify(token);
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
        return refuse(res, err);
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
        return refuse(res, err);
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
        return refuse(res, err);
      }
    };
  }

  // A misconfigured SDK is the server's fault, not the caller's: 500, not 401.
  function refuse(res, err) {
    if (err instanceof ConfigError) {
      console.error('[authfi] token verification is not configured:', err.message);
      return res.status(500).json({ error: 'Authentication is not configured' });
    }
    return res.status(401).json({ error: err.message, code: err.code });
  }

  function extractBearer(req) {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer ')) return auth.slice(7);
    return null;
  }

  // --- Startup ---

  async function start() {
    // Pre-fetch the issuer's metadata and keys, when this service verifies tokens.
    if (audience) {
      await Promise.resolve()
        .then(() => getVerifier().warm())
        .catch(err => console.warn('[authfi] JWKS fetch failed:', err.message));
    }

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

module.exports.TokenError = TokenError;
module.exports.ConfigError = ConfigError;

// Agent identity: an agent's own key, token, CIBA and token exchange.
const agent = require('./lib/agent');
module.exports.AgentKey = agent.AgentKey;
module.exports.AgentAuth = agent.AgentAuth;
module.exports.AgentAuthError = agent.AgentAuthError;
module.exports.DelegatedToken = agent.DelegatedToken;
