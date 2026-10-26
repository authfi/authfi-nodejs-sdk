import { RequestHandler } from 'express';
import { IncomingMessage, ServerResponse } from 'http';

interface AuthFIConfig {
  tenant: string;
  apiKey: string;
  apiUrl?: string;
  applicationId?: string;
  autoSync?: boolean;
  jwksRefreshInterval?: number;
  /** The project issuer, for example https://acme.authfi.io. Needed by receiver() and registerStream(); when set, keys are read from its key set. */
  issuer?: string;
  /** Makes verifyToken refuse a token whose subject (or actor) was revoked after it was issued. */
  revocations?: RevocationStore;
  /** Receives receiver events. Never a token. */
  logger?: { info(message: string, fields?: object): void; warn(message: string, fields?: object): void };
}

interface RevocationStoreOptions {
  /** Most subjects remembered. Default 100000. */
  maxEntries?: number;
  /** At least the longest lifetime of any token you accept, in seconds. Default 86400. */
  tokenLifetimeSeconds?: number;
}

interface RevocationStore {
  /** Tokens of `subject` issued at or before `notBefore` (Unix seconds) are dead. Returns how many other subjects were dropped to make room. */
  revoke(subject: string, notBefore: number): number;
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
  email: string;
  email_verified: boolean;
  name: string;
  roles: string[];
  permissions: string[];
  tenant_id: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  iat: number;
  exp: number;
  iss: string;
}

interface AuthFIClient {
  require(...permissions: string[]): RequestHandler;
  requireRole(...roles: string[]): RequestHandler;
  authenticate(): RequestHandler;
  verifyToken(token: string): Promise<Claims>;
  start(): Promise<void>;
  registerPermission(name: string, description?: string): void;
  syncPermissions(): Promise<void>;
  /** Handler for the Shared Signals push delivery (RFC 8935). Throws now if it cannot work. */
  receiver(config: ReceiverConfig): (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  registerStream(bearer: string, request: StreamRequest): Promise<Stream>;
}

declare function authfi(config: AuthFIConfig): AuthFIClient;
declare namespace authfi {
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
