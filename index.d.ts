import { RequestHandler } from 'express';
import { IncomingMessage, ServerResponse } from 'node:http';

/** Stable refusal codes. Read them from `AuthFIError.code`. */
type RefusalCode =
  | 'sdk_not_configured' | 'missing_authorization' | 'agent_token_needs_request' | 'jwks_unavailable'
  | 'token_malformed' | 'token_too_large' | 'token_alg_not_allowed' | 'token_kid_required'
  | 'token_crit_not_supported' | 'token_typ_invalid' | 'token_unknown_key' | 'token_alg_key_mismatch'
  | 'token_signature_invalid' | 'token_issuer_mismatch' | 'token_audience_mismatch' | 'token_expired'
  | 'token_exp_required' | 'token_not_yet_valid' | 'token_sub_required' | 'token_tenant_required'
  | 'token_tenant_not_issuers' | 'token_dpop_proof_required' | 'token_act_chain_unsupported'
  | 'dpop_missing' | 'dpop_multiple' | 'dpop_malformed' | 'dpop_type' | 'dpop_alg' | 'dpop_signature'
  | 'dpop_replay_guard_full' | 'dpop_method' | 'dpop_url' | 'dpop_iat' | 'dpop_ath' | 'dpop_replayed' | 'dpop_key_mismatch' | 'dpop_nonce'
  | 'chain_not_proven' | 'chain_policy' | 'chain_pin'
  | 'token_revoked' | 'token_iat_exp_required' | 'revocation_store_misconfigured';

/**
 * Single-use store for DPoP proofs. `record` returns true when the key was new and is now
 * recorded, false when it was already seen. An error or any other value refuses the proof.
 * The default is a bounded in-memory store: with more than one replica, supply a shared store.
 */
interface ReplayGuard {
  record(key: string, expiresAtMs: number): boolean | 'full' | Promise<boolean | 'full'>;
}

interface AuthFIConfig {
  /** The project issuer, for example https://acme.authfi.io. Required to verify tokens. */
  issuer?: string;
  /** The client id of your API (string or list). Required to verify tokens; AuthFI's own audiences are refused. */
  audience?: string | string[];
  /** Refuse tokens of any other tenant_id. */
  tenantId?: string;
  /** Override the key set URL (default `${issuer}/.well-known/jwks.json`). */
  jwksUrl?: string;
  /** Clock leeway in seconds, 0 to 300 (default 60). */
  leeway?: number;

  /** `enforce` (default): agent tokens need a DPoP proof and a proven key chain. `watch`: log the code and allow. `off`: explicit, logged once. */
  agentTokens?: 'enforce' | 'watch' | 'off';
  /** The origin clients call, for the DPoP `htu` check, for example https://api.example.com. Origin only. */
  publicUrl?: string;
  /** Build `htu` from X-Forwarded-Proto and X-Forwarded-Host. Only behind a proxy that sets them. Default false. */
  trustForwarded?: boolean;
  /** Replay store for DPoP proofs. Default: bounded in memory (one replica). */
  replayGuard?: ReplayGuard;
  /** At least 16 bytes. Turns on server nonces (RFC 9449 section 8). */
  nonceKey?: string | Buffer;
  /** Hex SHA-256 values of trusted root public keys (SPKI). Replaces the built-in AuthFI Root CA R1 pin. */
  rootPins?: string[];
  /** PEM roots to complete a chain whose JWKS x5c omits the root. A root counts only when its key is pinned. */
  rootCerts?: string[];
  /** `warn`, `info` and `debug` receive refusal codes and receiver events only, never a token. */
  logger?: { warn?: (msg: string, fields?: object) => void; info?: (msg: string, fields?: object) => void; debug?: (msg: string, fields?: object) => void };
  /** Makes verification refuse a token whose subject (or actor) was revoked after it was issued. */
  revocations?: RevocationStore;

  tenant?: string;
  apiKey?: string;
  apiUrl?: string;
  applicationId?: string;
  clientSecret?: string;
  autoSync?: boolean;
  jwksRefreshInterval?: number;
}

interface RevocationStoreOptions {
  /** Most subjects remembered. Default 100000. */
  maxEntries?: number;
  /** At least the longest lifetime of any token you accept, in seconds. Default 86400. */
  tokenLifetimeSeconds?: number;
}

interface RevocationStore {
  /** Tokens of `subject` issued at or before `notBefore` (Unix seconds) are dead. Returns how many other subjects were dropped to make room. */
  revoke(subject: string, notBefore: number, ref?: string): number;
  /** Like isRevoked, but returns the reference (the jti of the revoking SET) of the revocation that applies, or null. */
  find(subject: string, issuedAt?: number): { ref: string } | null;
  /** Whether a token of `subject` issued at `issuedAt` (Unix seconds) is revoked. An unknown issue time counts as older than every revocation. */
  isRevoked(subject: string, issuedAt?: number): boolean;
  readonly size: number;
  readonly maxEntries: number;
  readonly tokenLifetimeSeconds: number;
}

interface Signal {
  event: string;
  subject: string;
  jti: string;
  /** The iat of the SET, in Unix seconds. */
  issuedAt: number;
  /** The event withdrew the subject's access; the store now refuses its tokens issued at or before issuedAt. */
  revoked: boolean;
  /** A token-claims-change event saying the subject was resumed. Lifts nothing. */
  resumed: boolean;
}

interface ReceiverConfig {
  /** The audience your stream was registered with. */
  audience: string;
  /** The bearer the transmitter presents on every push, when you registered one. */
  authToken?: string;
  onSignal?(signal: Signal): void | Promise<void>;
}

interface StreamRequest {
  audience: string;
  endpointUrl: string;
  authToken?: string;
  events?: string[];
}

interface Stream {
  id: string;
  audience: string;
  endpointUrl: string;
  status: string;
  events: string[];
}

interface Claims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  roles?: string[];
  permissions?: string[];
  tenant_id: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  iat?: number;
  exp: number;
  iss: string;
  aud?: string | string[];
  client_id?: string;
  cnf?: { jkt?: string };
  act?: { sub?: string };
  [claim: string]: unknown;
}

interface AuthFIClient {
  require(...permissions: string[]): RequestHandler;
  requireRole(...roles: string[]): RequestHandler;
  authenticate(): RequestHandler;
  /** Verify a request: the token, and for agent or key-bound tokens the DPoP proof of this request and the key chain. */
  verifyRequest(req: Pick<IncomingMessage, 'method' | 'headers' | 'rawHeaders'> & { url?: string; originalUrl?: string }): Promise<Claims>;
  /** Verify a person's access token. Refuses an agent token with `agent_token_needs_request`. */
  verifyToken(token: string): Promise<Claims>;
  start(): Promise<void>;
  registerPermission(name: string, description?: string): void;
  syncPermissions(): Promise<void>;
  /** Handler for the Shared Signals push delivery (RFC 8935). Throws now if it cannot work. */
  receiver(config: ReceiverConfig): (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  registerStream(bearer: string, request: StreamRequest): Promise<Stream>;
  cloud: {
    credentials(userToken: string, provider: 'aws' | 'gcp' | 'azure', options?: Record<string, unknown>): Promise<Record<string, unknown>>;
    token(userToken: string, audience: string, ttl?: number): Promise<Record<string, unknown>>;
  };
}

declare function authfi(config: AuthFIConfig): AuthFIClient;
declare namespace authfi {
  /** A refusal. Its message never holds a token, a proof, a signature or a claim value. */
  class AuthFIError extends Error {
    readonly code: RefusalCode;
    /** Set on `dpop_nonce`: the nonce the client should put in its next proof. */
    readonly dpopNonce?: string;
  }
  /** SHA-256 of the AuthFI Root CA R1 public key (SPKI), hex. */
  const DEFAULT_ROOT_PINS: string[];
  function createRevocationStore(options?: RevocationStoreOptions): RevocationStore;
}
export = authfi;

declare global {
  namespace Express {
    interface Request {
      user?: Claims;
    }
  }
}
