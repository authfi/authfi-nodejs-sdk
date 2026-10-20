import { RequestHandler } from 'express';

interface AuthFIConfig {
  /** The project slug. Used to build the issuer when `issuer` is not given. */
  tenant?: string;
  /** Only permission sync uses it. */
  apiKey?: string;
  /** The base for permission sync and cloud credentials. Token verification never uses it. */
  apiUrl?: string;
  /** The project's own origin, which is its issuer. Defaults to `https://<tenant>.<baseDomain>`. */
  issuer?: string;
  /** The zone projects live under. Defaults to `authfi.io`. */
  baseDomain?: string;
  /** The audience this API accepts in a token's `aud`. Required to verify tokens. */
  audience?: string | string[];
  applicationId?: string;
  clientSecret?: string;
  autoSync?: boolean;
  /** How long the issuer's JWKS is cached, in milliseconds. */
  jwksRefreshInterval?: number;
  /** Clock skew tolerated on exp and nbf, in seconds. Defaults to 30. */
  clockTolerance?: number;
  /** The fetch used for discovery and keys. Defaults to the global fetch. */
  fetch?: typeof fetch;
}

interface Claims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  /** RFC 8693 actor: on a token an agent holds for a person, the agent. */
  act?: { sub: string; [claim: string]: unknown };
  client_id?: string;
  scope?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  roles?: string[];
  permissions?: string[];
  tenant_id?: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  iat?: number;
  [claim: string]: unknown;
}

/** Why a token was refused. `code` is stable; the message may change. */
declare class TokenError extends Error {
  code:
    | 'token_malformed' | 'kid_missing' | 'kid_unknown' | 'key_unusable' | 'alg_mismatch'
    | 'signature_invalid' | 'exp_missing' | 'token_expired' | 'token_not_yet_valid'
    | 'issuer_mismatch' | 'audience_mismatch' | 'jwks_unavailable';
}

/** The SDK is missing configuration it needs (an issuer or an audience). */
declare class ConfigError extends Error {
  code: 'not_configured';
}

interface AuthFIClient {
  require(...permissions: string[]): RequestHandler;
  requireRole(...roles: string[]): RequestHandler;
  authenticate(): RequestHandler;
  verifyToken(token: string): Promise<Claims>;
  start(): Promise<void>;
  registerPermission(name: string, description?: string): void;
  syncPermissions(): Promise<void>;
}

declare function authfi(config: AuthFIConfig): AuthFIClient;
declare namespace authfi {
  export { AuthFIConfig, AuthFIClient, Claims, TokenError, ConfigError };
}
export = authfi;

declare global {
  namespace Express {
    interface Request {
      user?: Claims;
    }
  }
}
