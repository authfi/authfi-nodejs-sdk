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

/** A refusal from an AuthFI endpoint. Branch on `error`, the OAuth error code. */
declare class AgentAuthError extends Error {
  /** The OAuth error code (invalid_client, access_denied, expired_token, ...), or null when the server sent none. */
  error: string | null;
  description: string | null;
  status: number;
}

type AgentAlg = 'EdDSA' | 'ES256' | 'PS256';

/** An agent's signing key: Ed25519 (EdDSA), P-256 (ES256) or RSA 2048-4096 (PS256). */
declare class AgentKey {
  constructor(privateKey: import('crypto').KeyObject, kid: string);
  readonly alg: AgentAlg;
  readonly kid: string;
  /** Generates a key; its kid defaults to the RFC 7638 thumbprint. */
  static generate(alg?: AgentAlg, options?: { kid?: string }): AgentKey;
  static fromPem(pem: string | Buffer, options: { kid: string }): AgentKey;
  static fromJwk(jwk: string | Record<string, unknown>, options?: { kid?: string }): AgentKey;
  static fromFile(path: string, options?: { kid?: string }): AgentKey;
  /** The public JWK to register. */
  publicJwk(): Record<string, string>;
  thumbprint(): string;
  privatePem(): string;
  /** An RFC 7523 client assertion: aud = the token endpoint, fresh jti, at most 300 s. */
  clientAssertion(agentId: string, audience: string, options?: { lifetime?: number }): string;
}

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** A token an agent holds for a person: sub is the person, act.sub the agent. */
declare class DelegatedToken {
  readonly accessToken: string;
  expiresAt: number;
  scope: string | null;
  /** The token's claims, decoded and NOT verified. */
  claims: Claims;
  /** The current token; a token from a token exchange is renewed by exchanging again. */
  token(): Promise<string>;
  /** A fetch that sends this token to the project's origin. */
  fetch: Fetch;
}

interface AgentAuthConfig {
  /** The project's origin. Required: there is no default. */
  issuer: string;
  agentId: string;
  key: AgentKey;
  /** The RFC 8707 resource the agent's own token is for. */
  resource?: string;
  fetch?: Fetch;
  /** Seconds before expiry at which a token is renewed. Defaults to 60. */
  refreshSkew?: number;
  /** Origins besides the issuer's that `fetch` may send the token to. */
  allowedOrigins?: string[];
  /** Called once per endpoint that answers with a Deprecation header. */
  onDeprecation?: (info: { url: string; deprecation: string; link: string | null; sunset: string | null }) => void;
}

interface CibaApproval {
  auth_req_id: string;
  expires_in: number;
  interval?: number;
  [field: string]: unknown;
}

/** An agent's identity at one AuthFI project. */
declare class AgentAuth {
  constructor(config: AgentAuthConfig);
  /** AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KEY_FILE (or AUTHFI_AGENT_PRIVATE_KEY), AUTHFI_AGENT_KID, AUTHFI_AGENT_RESOURCE. */
  static fromEnv(env?: Record<string, string | undefined>, overrides?: Partial<AgentAuthConfig>): AgentAuth;
  readonly issuer: string;
  readonly agentId: string;
  /** A fetch that sends the agent's own token, renewed as needed, to the project's origin. */
  fetch: Fetch;
  metadata(): Promise<Record<string, unknown>>;
  /** The agent's own token (client credentials, private_key_jwt), cached and renewed before expiry. */
  token(options?: { resource?: string; force?: boolean }): Promise<string>;
  capabilities(options?: { resource?: string }): Promise<string[]>;
  authHeader(options?: { resource?: string }): Promise<{ Authorization: string }>;
  /** Asks a person to let the agent act for them (OpenID CIBA). */
  requestUserApproval(request: { loginHint: string; bindingMessage?: string; scope?: string; requestedExpiry?: number }): Promise<CibaApproval>;
  /** Waits, without blocking, for the person's decision. */
  awaitUserToken(approval: CibaApproval | string, options?: { timeout?: number; signal?: AbortSignal; resource?: string }): Promise<DelegatedToken>;
  tokenAsUser(request: { loginHint: string; bindingMessage?: string; scope?: string; requestedExpiry?: number; timeout?: number; signal?: AbortSignal; resource?: string }): Promise<DelegatedToken>;
  /** RFC 8693: exchanges a person's token for one the agent holds for them. */
  exchangeToken(request: { subjectToken: string; subjectTokenType?: string; resource?: string; scope?: string }): Promise<DelegatedToken>;
}

declare function authfi(config: AuthFIConfig): AuthFIClient;
declare namespace authfi {
  export {
    AuthFIConfig, AuthFIClient, Claims, TokenError, ConfigError,
    AgentKey, AgentAuth, AgentAuthError, DelegatedToken, AgentAuthConfig, AgentAlg, CibaApproval,
  };
}
export = authfi;

declare global {
  namespace Express {
    interface Request {
      user?: Claims;
    }
  }
}
