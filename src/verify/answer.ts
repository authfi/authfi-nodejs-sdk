import {
  ConfigurationError,
  isAuthFIError,
  type AuthFIError,
  type InsufficientAuthentication,
  type InsufficientScope,
} from '../core/errors.js';
import type { AccessToken } from './access-token.js';
import { PROOF_ALGORITHMS } from './dpop-proof.js';
import type { Scheme } from './verifier.js';

/** What an API answers a refused request: status, headers and JSON body. */
export interface RefusalAnswer {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Readonly<Record<string, string>>;
}

/** How an adapter answers refusals. */
export interface AnswerOptions {
  /**
   * The URL of your API's protected-resource metadata (RFC 9728), sent in the 401 challenge so a
   * client can find the authorization server.
   */
  readonly resourceMetadata?: string | undefined;
  /**
   * Put the precise refusal code (`token_expired`, `token_audience_mismatch`, …) in the body as
   * `code`. Off by default: the platform keeps one opaque answer so a caller cannot tell a wrong key
   * from a wrong audience or a wrong account. Turn it on only for an internal API.
   */
  readonly exposeRefusalCode?: boolean | undefined;
}

const OPAQUE = 'The access token is not valid.';
const OPAQUE_PROOF = 'The DPoP proof is not valid.';

function quote(value: string): string {
  return `"${value.replace(/["\\]/g, '')}"`;
}

function challenge(scheme: Scheme, params: Readonly<Record<string, string | number | undefined>>): string {
  const parts = Object.entries(params).flatMap(([k, v]) =>
    v === undefined ? [] : [`${k}=${typeof v === 'number' ? String(v) : quote(v)}`],
  );
  return parts.length === 0 ? scheme : `${scheme} ${parts.join(', ')}`;
}

/**
 * The answer to a refused request, the same in every adapter (design §1.4):
 *
 * - no credential: 401, a `Bearer` challenge with no `error` (RFC 6750 §3.1);
 * - any other token refusal: 401 `invalid_token` with one fixed description;
 * - a missing scope: 403 `insufficient_scope`, naming the scopes;
 * - a missing permission or role: 403 `forbidden`, naming nothing;
 * - too weak a sign-in: 401 `insufficient_user_authentication` with `acr_values` (RFC 9470);
 * - the issuer's keys or discovery unreachable (`TransportError`, `DiscoveryError`,
 *   `TemporarilyUnavailable`): 503 with `Retry-After`, because the caller's token may be fine;
 * - anything else, a misconfiguration or a bug: 500 `internal_error` with no `Retry-After`, because
 *   a well-behaved client must not retry a programming error.
 *
 * The precise code is never on the wire unless `exposeRefusalCode` is set.
 */
export function refusalAnswer(
  error: unknown,
  scheme: Scheme = 'Bearer',
  options: AnswerOptions = {},
): RefusalAnswer {
  const rm = options.resourceMetadata;
  const withCode = (body: Record<string, string>, e: AuthFIError): Record<string, string> =>
    options.exposeRefusalCode === true ? { ...body, code: e.code } : body;

  if (isAuthFIError(error, 'InsufficientScope')) {
    const e: InsufficientScope = error;
    return {
      status: 403,
      headers: {
        'www-authenticate': challenge('Bearer', { error: 'insufficient_scope', scope: e.required.join(' ') }),
      },
      body: withCode({ error: 'insufficient_scope' }, e),
    };
  }
  if (isAuthFIError(error, 'InsufficientPermission')) {
    return { status: 403, headers: {}, body: withCode({ error: 'forbidden' }, error) };
  }
  if (isAuthFIError(error, 'InsufficientAuthentication')) {
    const e: InsufficientAuthentication = error;
    return {
      status: 401,
      headers: {
        'www-authenticate': challenge('Bearer', {
          error: 'insufficient_user_authentication',
          acr_values: e.acrValues.join(' '),
          max_age: e.maxAge,
          resource_metadata: rm,
        }),
      },
      body: withCode({ error: 'insufficient_user_authentication' }, e),
    };
  }
  if (isAuthFIError(error, 'DPoPNonceRequired')) {
    return {
      status: 401,
      headers: {
        'www-authenticate': challenge('DPoP', {
          error: 'use_dpop_nonce',
          algs: PROOF_ALGORITHMS.join(' '),
          resource_metadata: rm,
        }),
        'dpop-nonce': error.nonce,
      },
      body: withCode({ error: 'use_dpop_nonce' }, error),
    };
  }
  if (isAuthFIError(error, 'InvalidToken') && error.code === 'dpop_replay_check_unavailable') {
    // The proof may be fine: the guard that makes it single-use cannot answer now. Retry.
    return {
      status: 503,
      headers: { 'retry-after': '5' },
      body: withCode({ error: 'service_unavailable' }, error),
    };
  }
  if (isAuthFIError(error, 'InvalidToken') && error.code.startsWith('dpop_proof_')) {
    return {
      status: 401,
      headers: {
        'www-authenticate': challenge('DPoP', {
          error: 'invalid_dpop_proof',
          error_description: OPAQUE_PROOF,
          algs: PROOF_ALGORITHMS.join(' '),
          resource_metadata: rm,
        }),
      },
      body: withCode({ error: 'invalid_dpop_proof', error_description: OPAQUE_PROOF }, error),
    };
  }
  if (isAuthFIError(error, 'InvalidToken')) {
    if (error.code === 'token_missing') {
      return {
        status: 401,
        headers: { 'www-authenticate': challenge('Bearer', { resource_metadata: rm }) },
        body: withCode({ error: 'unauthorized' }, error),
      };
    }
    return {
      status: 401,
      headers: {
        'www-authenticate': challenge(scheme, {
          error: 'invalid_token',
          error_description: OPAQUE,
          resource_metadata: rm,
        }),
      },
      body: withCode({ error: 'invalid_token', error_description: OPAQUE }, error),
    };
  }
  if (
    isAuthFIError(error, 'TransportError') ||
    isAuthFIError(error, 'DiscoveryError') ||
    isAuthFIError(error, 'TemporarilyUnavailable')
  ) {
    return { status: 503, headers: { 'retry-after': '5' }, body: { error: 'service_unavailable' } };
  }
  return { status: 500, headers: {}, body: { error: 'internal_error' } };
}

/**
 * What a route requires of a token. Kinds combine with AND; within a kind:
 * `permissions` and `scopes` need all, `anyPermission` and `roles` need one.
 */
export interface Requirements {
  /** The token must have **all** of these permissions. */
  readonly permissions?: readonly string[] | undefined;
  /** The token must have **at least one** of these permissions. */
  readonly anyPermission?: readonly string[] | undefined;
  /** The token must have **at least one** of these roles. */
  readonly roles?: readonly string[] | undefined;
  /** The token must have **all** of these scopes (meaningful for agent tokens and your own scopes). */
  readonly scopes?: readonly string[] | undefined;
}

/** Refuses an empty requirement list at setup, so it never reads as "no requirement". */
export function checkRequirements(req: Requirements): void {
  for (const [name, list] of Object.entries(req)) {
    if (list !== undefined && Array.isArray(list) && list.length === 0) {
      throw new ConfigurationError(`${name} is empty: list at least one name, or leave it out`);
    }
  }
}

/** Applies every requirement to a verified token; throws the first that fails. */
export function applyRequirements(token: AccessToken, req: Requirements): void {
  if (req.permissions !== undefined) token.requirePermission(...req.permissions);
  if (req.anyPermission !== undefined) token.requireAnyPermission(...req.anyPermission);
  if (req.roles !== undefined) token.requireRole(...req.roles);
  if (req.scopes !== undefined) token.requireScope(...req.scopes);
}
