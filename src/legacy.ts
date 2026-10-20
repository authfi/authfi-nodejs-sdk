import { ConfigurationError, NotSupportedError } from './core/errors.js';
import { consoleLogger, type Logger } from './core/logger.js';
import { AuthFI } from './core/project.js';
import { protect, type ExpressRequest, type ExpressResponse, type NextFunction } from './express/index.js';
import type { AccessToken } from './verify/access-token.js';
import type { TokenVerifier } from './verify/verifier.js';

/** The settings of the 0.1 factory. */
export interface LegacyConfig {
  /** The issuer. Takes precedence over `tenant`. */
  readonly issuer?: string;
  /** The project slug; the issuer becomes `https://<tenant>.<baseDomain>`. */
  readonly tenant?: string;
  /** The base domain for `tenant` (default `authfi.io`). */
  readonly baseDomain?: string;
  /** The audiences `verifyToken` and the middleware accept. Required to verify anything. */
  readonly audience?: string | readonly string[];
  /** Ignored: the platform issues no such key. */
  readonly apiKey?: string;
  /** Ignored: endpoints come from the issuer's discovery. */
  readonly apiUrl?: string;
  /** Ignored. */
  readonly applicationId?: string;
  /** Ignored. */
  readonly clientSecret?: string;
  /** Ignored: permission sync does not exist on the platform. */
  readonly autoSync?: boolean;
  /** Ignored: the key set is cached for its own max-age. */
  readonly jwksRefreshInterval?: number;
  readonly fetch?: typeof fetch;
  readonly logger?: Logger;
}

type Middleware = (
  req: ExpressRequest & { user?: Record<string, unknown> },
  res: ExpressResponse,
  next: NextFunction,
) => void;

/** The object the 0.1 factory returns, rebuilt on the 0.2 core. */
export interface LegacyClient {
  /** @deprecated Use `protect(verifier, { permissions })` from `@authfi/sdk/express`. */
  require(...permissions: string[]): Middleware;
  /** @deprecated Use `protect(verifier, { roles })` from `@authfi/sdk/express`. */
  requireRole(...roles: string[]): Middleware;
  /** @deprecated Use `protect(verifier)` from `@authfi/sdk/express`. */
  authenticate(): Middleware;
  /** @deprecated Use `af.verifier({ audience }).verify(token)`. Returns the verified claims. */
  verifyToken(token: string): Promise<Readonly<Record<string, unknown>>>;
  /** @deprecated Fetches discovery and the key set ahead of the first request; nothing else. */
  start(): Promise<void>;
  /** @deprecated Permission sync does not exist on the platform; throws `NotSupportedError`. */
  registerPermission(name: string, description?: string): never;
  /** @deprecated Permission sync does not exist on the platform; throws `NotSupportedError`. */
  syncPermissions(): Promise<never>;
  /** @deprecated The cloud credential route is not open to applications; agents use the gateway. */
  readonly cloud: {
    credentials(...args: unknown[]): Promise<never>;
    token(...args: unknown[]): Promise<never>;
  };
}

const warned = new Set<string>();

function deprecated(logger: Logger, symbol: string, instead: string): void {
  if (warned.has(symbol)) return;
  warned.add(symbol);
  logger.warn(`${symbol} is deprecated and is removed in 1.0: ${instead}`);
}

/**
 * The 0.1 factory, kept for one minor version and rebuilt on the 0.2 core: strict verification
 * (an audience is required), errors answered by code, and the dead calls refused.
 *
 * @deprecated Use `new AuthFI({ issuer })`, `af.verifier({ audience })` and `@authfi/sdk/express`.
 */
export default function authfi(config: LegacyConfig): LegacyClient {
  const logger = config.logger ?? consoleLogger;
  deprecated(logger, 'authfi()', 'use new AuthFI({ issuer }) and af.verifier({ audience })');
  let issuer = config.issuer;
  if (issuer === undefined) {
    if (config.tenant === undefined)
      throw new ConfigurationError('issuer is required: https://<slug>.authfi.io');
    issuer = `https://${config.tenant}.${config.baseDomain ?? 'authfi.io'}`;
    logger.warn(`authfi(): the issuer was built from tenant as ${issuer}; pass issuer instead`);
  }
  for (const key of [
    'apiKey',
    'apiUrl',
    'applicationId',
    'clientSecret',
    'autoSync',
    'jwksRefreshInterval',
  ] as const) {
    if (config[key] !== undefined) logger.warn(`authfi(): ${key} is ignored in 0.2 and is removed in 1.0`);
  }
  const af = new AuthFI({ issuer, fetch: config.fetch, logger });
  let verifier: TokenVerifier | undefined;
  const verifierOf = (): TokenVerifier => {
    if (config.audience === undefined) {
      throw new ConfigurationError(
        "authfi(): audience is required to verify tokens: your API's client id (or your front end's), as audience: ['api_…']",
      );
    }
    verifier ??= af.verifier({ audience: config.audience });
    return verifier;
  };
  const middleware = (requirements: { permissions?: string[]; roles?: string[] }): Middleware => {
    const guard = protect(verifierOf(), { ...requirements, logger });
    return (req, res, next) => {
      guard(req, res, (err?: unknown) => {
        // 0.1 put the claims on req.user; keep it for one minor alongside req.authfi.
        const token: AccessToken | undefined = req.authfi;
        if (err === undefined && token !== undefined) req.user = token.claims;
        next(err);
      });
    };
  };
  const notSupported = (feature: string, message: string): never => {
    throw new NotSupportedError(feature, message);
  };
  return {
    require: (...permissions) => {
      deprecated(logger, 'require()', "use protect(verifier, { permissions }) from '@authfi/sdk/express'");
      return middleware({ permissions });
    },
    requireRole: (...roles) => {
      deprecated(logger, 'requireRole()', "use protect(verifier, { roles }) from '@authfi/sdk/express'");
      return middleware({ roles });
    },
    authenticate: () => {
      deprecated(logger, 'authenticate()', "use protect(verifier) from '@authfi/sdk/express'");
      return middleware({});
    },
    verifyToken: async (token) => {
      deprecated(logger, 'verifyToken()', 'use af.verifier({ audience }).verify(token)');
      return (await verifierOf().verify(token)).claims;
    },
    start: async () => {
      await af.metadata();
    },
    registerPermission: () =>
      notSupported(
        'permission_sync',
        'Permissions are managed in the console; there is no permission sync to register with',
      ),
    syncPermissions: () =>
      Promise.reject(
        new NotSupportedError(
          'permission_sync',
          'Permissions are managed in the console; there is no permission sync',
        ),
      ),
    cloud: {
      credentials: () =>
        Promise.reject(
          new NotSupportedError(
            'cloud_credentials',
            'Cloud credentials are issued to agents through the gateway: agent.gateway().cloudCredentials()',
          ),
        ),
      token: () =>
        Promise.reject(
          new NotSupportedError(
            'cloud_credentials',
            'Cloud credentials are issued to agents through the gateway: agent.gateway().cloudCredentials()',
          ),
        ),
    },
  };
}
