import { systemClock, type Clock } from './core/clock.js';
import { ConfigurationError, NotSupportedError } from './core/errors.js';
import { consoleLogger, type Logger } from './core/logger.js';
import { AuthFI } from './core/project.js';
import {
  protect,
  requestCredentials,
  type ExpressRequest,
  type ExpressResponse,
  type NextFunction,
} from './express/index.js';
import {
  createReceiver,
  createRevocationStore,
  registerStream,
  type MemoryRevocationStore,
  type PushRequest,
  type PushResponse,
  type ReceiverOptions,
  type Stream,
  type StreamRequest,
} from './signals/index.js';
import type { AccessToken } from './verify/access-token.js';
import { DEFAULT_ROOT_PINS } from './verify/chain.js';
import type { ReplayGuard } from './verify/dpop-proof.js';
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
  /** How an agent's token is treated: `enforce` (default), `watch` or `off`. See `VerifierOptions.agentTokens`. */
  readonly agentTokens?: 'enforce' | 'watch' | 'off';
  /** The origin clients call this API at; required to check any DPoP proof. */
  readonly publicUrl?: string;
  /** Take the origin for a proof's `htu` from the forwarding headers when no `publicUrl` is set. */
  readonly trustForwarded?: boolean;
  /** Where single-use proof ids are recorded; share one across replicas. */
  readonly replayGuard?: ReplayGuard;
  /** At least 16 bytes: proofs must then carry the server nonce. */
  readonly nonceKey?: string | Uint8Array;
  /** Hex SHA-256 pins of the trusted roots; defaults to AuthFI Root CA R1. */
  readonly rootPins?: readonly string[];
  /** PEM roots to complete a chain whose `x5c` omits its root. */
  readonly rootCerts?: readonly string[];
  /** The tenant the issuer belongs to. */
  readonly tenantId?: string;
  /** Clock leeway in seconds, 0 to 300 (default 60). */
  readonly leeway?: number;
  /** A store from `createRevocationStore()`: verification then refuses revoked tokens. */
  readonly revocations?: MemoryRevocationStore;
  /** The clock in epoch milliseconds, for tests (`now` is the same). */
  readonly clock?: () => number;
  readonly now?: () => number;
  /** Ignored: the key set is read from the issuer's discovery document. */
  readonly jwksUrl?: string;
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
  /** @deprecated Use `af.verifier({ audience }).verify(token)`. Returns the verified claims; refuses an agent's token. */
  verifyToken(token: string): Promise<Readonly<Record<string, unknown>>>;
  /** @deprecated Use `af.verifier({ audience }).verifyRequest(request)`. Returns the verified claims. */
  verifyRequest(req: ExpressRequest): Promise<Readonly<Record<string, unknown>>>;
  /** @deprecated Use `createReceiver(af, options)` from `@authfi/sdk/signals`. */
  receiver(
    options: Omit<ReceiverOptions, 'revocations'>,
  ): (req: PushRequest, res: PushResponse) => Promise<void>;
  /** @deprecated Use `registerStream(af, bearer, request)` from `@authfi/sdk/signals`. */
  registerStream(bearer: string, request: StreamRequest): Promise<Stream>;
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

const seconds = (value: number | undefined): number | undefined =>
  value === undefined ? undefined : value * 1000;

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
    'jwksUrl',
  ] as const) {
    if (config[key] !== undefined) logger.warn(`authfi(): ${key} is ignored in 0.2 and is removed in 1.0`);
  }
  const now = config.now ?? config.clock;
  const clock: Clock | undefined = now === undefined ? undefined : { ...systemClock, now };
  const af = new AuthFI({ issuer, fetch: config.fetch, logger, clock, leewayMs: seconds(config.leeway) });
  let verifier: TokenVerifier | undefined;
  const verifierOf = (): TokenVerifier => {
    if (config.audience === undefined) {
      throw new ConfigurationError(
        "authfi(): audience is required to verify tokens: your API's client id (or your front end's), as audience: ['api_…']",
      );
    }
    verifier ??= af.verifier({
      audience: config.audience,
      expectedTenantId: config.tenantId,
      leewayMs: seconds(config.leeway),
      agentTokens: config.agentTokens,
      publicUrl: config.publicUrl,
      trustForwarded: config.trustForwarded,
      replayGuard: config.replayGuard,
      nonceKey: config.nonceKey,
      rootPins: config.rootPins,
      rootCerts: config.rootCerts,
      revocations: config.revocations,
    });
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
    verifyRequest: async (req) => (await verifierOf().verifyRequest(requestCredentials(req))).claims,
    receiver: (options) => {
      deprecated(logger, 'receiver()', "use createReceiver(af, options) from '@authfi/sdk/signals'");
      if (config.revocations === undefined)
        throw new ConfigurationError(
          'receiver needs the revocations option (a store from authfi.createRevocationStore())',
        );
      return createReceiver(af, { ...options, revocations: config.revocations });
    },
    registerStream: (bearer, request) => {
      deprecated(
        logger,
        'registerStream()',
        "use registerStream(af, bearer, request) from '@authfi/sdk/signals'",
      );
      return registerStream(af, bearer, request);
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

// 0.1 exposed these on the factory function: keep them there for the same one minor.
/* eslint-disable @typescript-eslint/no-deprecated */
authfi.createRevocationStore = createRevocationStore;
authfi.DEFAULT_ROOT_PINS = DEFAULT_ROOT_PINS;
