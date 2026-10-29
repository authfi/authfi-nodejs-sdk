import type { KernelTokenCode } from './codes.js';

/**
 * The OAuth 2.0 error codes the platform answers with (RFC 6749 §5.2, RFC 8693, OpenID CIBA,
 * RFC 9470), as they appear in `error`.
 */
export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_target'
  | 'access_denied'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'insufficient_user_authentication';

/** The codes this SDK raises itself, for failures that never reached the platform. */
export type SdkErrorCode =
  | 'configuration_invalid'
  | 'network_error'
  | 'timeout'
  | 'redirect_refused'
  | 'response_too_large'
  | 'response_invalid'
  | 'discovery_failed'
  | 'issuer_mismatch'
  | 'not_supported'
  | 'token_act_chain_unsupported'
  | 'insufficient_permission'
  | 'insufficient_scope'
  | 'gateway_token_refused'
  | 'callback_iss_missing'
  | 'callback_iss_mismatch'
  | 'callback_state_mismatch'
  | 'callback_code_missing'
  | 'pending_sign_in_malformed'
  | 'pending_sign_in_tampered'
  | 'pending_sign_in_expired'
  | 'id_token_missing'
  | 'id_token_malformed'
  | 'id_token_alg_refused'
  | 'id_token_not_id_token'
  | 'id_token_key_unknown'
  | 'id_token_signature_invalid'
  | 'id_token_issuer_mismatch'
  | 'id_token_audience_mismatch'
  | 'id_token_claims_invalid'
  | 'id_token_expired'
  | 'id_token_nonce_mismatch'
  | 'id_token_at_hash_mismatch'
  | 'callback_parameter_repeated'
  | 'id_token_subject_changed'
  | 'userinfo_subject_mismatch'
  | 'wait_timeout';

/** Every code this SDK knows by name. */
export type KnownCode = KernelTokenCode | OAuthErrorCode | SdkErrorCode;

/**
 * A code an error carries. It is open: the platform's code families (`EMODEL…`, `EMDT…`, `ETOOL…`)
 * grow without an SDK release, so a `switch` on it needs a `default` arm.
 */
export type ErrorCode = KnownCode | (string & {});

const BRAND = Symbol.for('authfi.error');

/** Where an error came from on the wire, when it came from an answer. */
export interface ErrorContext {
  /** The HTTP status of the answer. */
  readonly status?: number | undefined;
  /** The `X-Request-Id` the platform answered with (or the one sent, when no answer came). */
  readonly requestId?: string | undefined;
  /** The platform's `AuthFI-Request-Id`, when it answered one. */
  readonly platformRequestId?: string | undefined;
  /** The platform's `AuthFI-Run-Id`, when it answered one. */
  readonly runId?: string | undefined;
  /** A header this request sent that an edge on the path removed (see the transport docs). */
  readonly droppedHeader?: string | undefined;
  /** The underlying error. */
  readonly cause?: unknown;
}

/**
 * The base of every error the SDK raises. Branch on {@link AuthFIError.code}, never on the
 * message.
 *
 * A package loaded as both ESM and CommonJS can hold two copies of this class, which breaks
 * `instanceof`. {@link isAuthFIError} checks a brand instead, and is the documented test.
 */
export class AuthFIError extends Error {
  override readonly name: string = 'AuthFIError';
  /** The stable code: a kernel code, an OAuth error, or one of the SDK's own. */
  readonly code: ErrorCode;
  /** The HTTP status, when the error came from an answer. */
  readonly status: number | undefined;
  /** The request id of the call that failed. */
  readonly requestId: string | undefined;
  /** The platform's `AuthFI-Request-Id`, when it answered one. */
  readonly platformRequestId: string | undefined;
  /** The platform's `AuthFI-Run-Id`, when it answered one. */
  readonly runId: string | undefined;
  /** A header an edge on the path removed, when that is what this answer shows. */
  readonly droppedHeader: string | undefined;

  constructor(code: ErrorCode, message: string, context: ErrorContext = {}) {
    super(message, context.cause === undefined ? undefined : { cause: context.cause });
    Object.defineProperty(this, BRAND, { value: true });
    this.code = code;
    this.status = context.status;
    this.requestId = context.requestId;
    this.platformRequestId = context.platformRequestId;
    this.runId = context.runId;
    this.droppedHeader = context.droppedHeader;
  }
}

/** A setting is wrong. Raised before anything is sent; it never carries an HTTP status. */
export class ConfigurationError extends AuthFIError {
  override readonly name: string = 'ConfigurationError';
  constructor(message: string) {
    super('configuration_invalid', message);
  }
}

/** A request did not get a usable answer: timeout, connection, redirect or an oversized body. */
export class TransportError extends AuthFIError {
  override readonly name: string = 'TransportError';
  /** Whether the same request may succeed when sent again. */
  readonly retryable: boolean;
  constructor(code: ErrorCode, message: string, context: ErrorContext & { retryable: boolean }) {
    super(code, message, context);
    this.retryable = context.retryable;
  }
}

/** The issuer's discovery document could not be used: it is missing, names another issuer, or lacks a field. */
export class DiscoveryError extends AuthFIError {
  override readonly name: string = 'DiscoveryError';
}

/** An OAuth endpoint refused the request (RFC 6749 §5.2). `code` is its `error`. */
export class OAuthError extends AuthFIError {
  override readonly name: string = 'OAuthError';
  /** The answer's `error_description`, for a log line. Never branch on it. */
  readonly description: string | undefined;
  constructor(code: ErrorCode, description: string | undefined, context: ErrorContext = {}) {
    super(code, description ? `${code}: ${description}` : code, context);
    this.description = description;
  }
}

/** The person must sign in again with a stronger method (`insufficient_user_authentication`). */
export class StepUpRequired extends OAuthError {
  override readonly name: string = 'StepUpRequired';
  /** The `acr` values to ask for when signing in again, when known. */
  readonly acrValues: readonly string[];
  /** The `max_age` to ask for, in seconds, when known. */
  readonly maxAge: number | undefined;
  constructor(
    description: string | undefined,
    context: ErrorContext & { acrValues?: readonly string[]; maxAge?: number | undefined } = {},
  ) {
    super('insufficient_user_authentication', description, context);
    this.acrValues = context.acrValues ?? [];
    this.maxAge = context.maxAge;
  }
}

/** The person said no to a CIBA request (`access_denied`). */
export class ConsentDenied extends OAuthError {
  override readonly name: string = 'ConsentDenied';
}

/** The person's consent is no longer valid: a CIBA request expired, or a delegated token outlived it. */
export class ConsentExpired extends OAuthError {
  override readonly name: string = 'ConsentExpired';
}

/**
 * The caller's own `timeoutMs` ran out while waiting for a person; what was waited on is still open.
 * This is the SDK's answer, never the server's: `authorization_pending` is the server saying the
 * person has not decided yet, and a request that really ran out is {@link ConsentExpired}.
 */
export class WaitTimeout extends AuthFIError {
  override readonly name: string = 'WaitTimeout';
  /** What is still open and can be waited on again, when it has an id of its own (an approval's). */
  readonly pendingId: string | undefined;
  constructor(message: string, pendingId?: string) {
    super('wait_timeout', message);
    this.pendingId = pendingId;
  }
}

/** The platform could not decide now (503, for example Actions failing closed). Safe to try later. */
export class TemporarilyUnavailable extends OAuthError {
  override readonly name: string = 'TemporarilyUnavailable';
  /** Always true: the same request may succeed later. */
  readonly retryable = true;
}

/** An AuthFI API (`/apis/...`, the gateways) refused the request. `code` is the platform's code. */
export class APIError extends AuthFIError {
  override readonly name: string = 'APIError';
  /** The answer's `error_description`, for a log line. Never branch on it. */
  readonly description: string | undefined;
  constructor(code: ErrorCode, description: string | undefined, context: ErrorContext = {}) {
    super(code, description ? `${code}: ${description}` : code, context);
    this.description = description;
  }
}

/** The verifier refused a token. `code` is the kernel's refusal code; it belongs in logs, not on the wire. */
export class InvalidToken extends AuthFIError {
  override readonly name: string = 'InvalidToken';
}

/** The token lacks a permission or role the call needs. `required` names what was asked for. */
export class InsufficientPermission extends InvalidToken {
  override readonly name: string = 'InsufficientPermission';
  /** What the check required. */
  readonly required: readonly string[];
  constructor(required: readonly string[], message: string) {
    super('insufficient_permission', message);
    this.required = required;
  }
}

/** The token lacks a scope the call needs. `required` names what was asked for. */
export class InsufficientScope extends InvalidToken {
  override readonly name: string = 'InsufficientScope';
  /** The scopes the check required. */
  readonly required: readonly string[];
  constructor(required: readonly string[], message: string) {
    super('insufficient_scope', message);
    this.required = required;
  }
}

/** The person signed in with too weak a method, or too long ago (RFC 9470). */
export class InsufficientAuthentication extends InvalidToken {
  override readonly name: string = 'InsufficientAuthentication';
  /** The acceptable `acr` values. */
  readonly acrValues: readonly string[];
  /** The maximum age of the sign-in, in seconds, when one was required. */
  readonly maxAge: number | undefined;
  constructor(acrValues: readonly string[], maxAge: number | undefined, message: string) {
    super('insufficient_user_authentication', message);
    this.acrValues = acrValues;
    this.maxAge = maxAge;
  }
}

/** The gateway refused the token itself (HTTP 401): missing, expired, revoked or for another audience. Ends the run. */
export class GatewayTokenRefused extends AuthFIError {
  override readonly name: string = 'GatewayTokenRefused';
  constructor(message: string, context: ErrorContext = {}) {
    super('gateway_token_refused', message, context);
  }
}

/** This project does not offer the feature to this kind of client. `feature` names it. */
export class NotSupportedError extends AuthFIError {
  override readonly name: string = 'NotSupportedError';
  /** The feature that is not offered. */
  readonly feature: string;
  constructor(feature: string, message: string, context: ErrorContext = {}) {
    super('not_supported', message, context);
    this.feature = feature;
  }
}

/**
 * A sign-in callback refused before its code was used: `callback_iss_missing`,
 * `callback_iss_mismatch` (RFC 9207, a mix-up), `callback_state_mismatch` or `callback_code_missing`.
 * The same codes as the Python SDK's `InvalidCallback`.
 */
export class InvalidCallback extends AuthFIError {
  override readonly name: string = 'InvalidCallback';
  constructor(
    code:
      | 'callback_iss_missing'
      | 'callback_iss_mismatch'
      | 'callback_state_mismatch'
      | 'callback_code_missing'
      | 'callback_parameter_repeated',
    message: string,
  ) {
    super(code, message, { status: 400 });
  }
}

/**
 * An ID token refused at sign-in: `id_token_*` (`id_token_nonce_mismatch`,
 * `id_token_audience_mismatch`, ...). It is not an {@link InvalidToken}: an access-token refusal is
 * an API's 401, and a failed sign-in is not. The same codes as the Python SDK's `InvalidIdToken`.
 */
export class InvalidIdToken extends AuthFIError {
  override readonly name: string = 'InvalidIdToken';
  constructor(code: string, message: string) {
    super(code, message, { status: 401 });
  }
}

/**
 * A pending sign-in that could not be restored: `pending_sign_in_malformed` (not one this SDK
 * wrote), `pending_sign_in_tampered` (altered, or another app's or key's) or
 * `pending_sign_in_expired`. Start the sign-in again.
 */
export class InvalidPendingSignIn extends AuthFIError {
  override readonly name: string = 'InvalidPendingSignIn';
  constructor(
    code: 'pending_sign_in_malformed' | 'pending_sign_in_tampered' | 'pending_sign_in_expired',
    message: string,
  ) {
    super(code, message, { status: 400 });
  }
}

/** The error classes by name, for {@link isAuthFIError}'s second argument. */
export interface AuthFIErrorKinds {
  AuthFIError: AuthFIError;
  ConfigurationError: ConfigurationError;
  TransportError: TransportError;
  DiscoveryError: DiscoveryError;
  OAuthError: OAuthError;
  StepUpRequired: StepUpRequired;
  ConsentDenied: ConsentDenied;
  ConsentExpired: ConsentExpired;
  TemporarilyUnavailable: TemporarilyUnavailable;
  WaitTimeout: WaitTimeout;
  APIError: APIError;
  InvalidToken: InvalidToken;
  InsufficientPermission: InsufficientPermission;
  InsufficientScope: InsufficientScope;
  InsufficientAuthentication: InsufficientAuthentication;
  GatewayTokenRefused: GatewayTokenRefused;
  NotSupportedError: NotSupportedError;
  InvalidCallback: InvalidCallback;
  InvalidIdToken: InvalidIdToken;
  InvalidPendingSignIn: InvalidPendingSignIn;
}

const PARENTS: Readonly<Record<string, string>> = {
  ConfigurationError: 'AuthFIError',
  TransportError: 'AuthFIError',
  DiscoveryError: 'AuthFIError',
  OAuthError: 'AuthFIError',
  StepUpRequired: 'OAuthError',
  ConsentDenied: 'OAuthError',
  ConsentExpired: 'OAuthError',
  TemporarilyUnavailable: 'OAuthError',
  WaitTimeout: 'AuthFIError',
  APIError: 'AuthFIError',
  InvalidToken: 'AuthFIError',
  InsufficientPermission: 'InvalidToken',
  InsufficientScope: 'InvalidToken',
  InsufficientAuthentication: 'InvalidToken',
  GatewayTokenRefused: 'AuthFIError',
  NotSupportedError: 'AuthFIError',
  InvalidCallback: 'AuthFIError',
  InvalidIdToken: 'AuthFIError',
  InvalidPendingSignIn: 'AuthFIError',
};

/**
 * Whether `e` is an error this SDK raised, optionally of one kind (or a kind derived from it). It
 * checks a brand, so it holds across the ESM and CommonJS copies of the package.
 *
 * @example
 * if (isAuthFIError(e, 'InvalidToken')) log.warn({ code: e.code }, 'token refused');
 */
export function isAuthFIError(e: unknown): e is AuthFIError;
export function isAuthFIError<K extends keyof AuthFIErrorKinds>(
  e: unknown,
  kind: K,
): e is AuthFIErrorKinds[K];
export function isAuthFIError(e: unknown, kind?: keyof AuthFIErrorKinds): boolean {
  if (typeof e !== 'object' || e === null || (e as Record<symbol, unknown>)[BRAND] !== true) return false;
  if (kind === undefined || kind === 'AuthFIError') return true;
  let name: string | undefined = (e as Error).name;
  while (name !== undefined) {
    if (name === kind) return true;
    name = PARENTS[name];
  }
  return false;
}
