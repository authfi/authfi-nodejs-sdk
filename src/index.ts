/**
 * The AuthFI SDK: one core (the project's issuer, discovery, keys, one HTTP transport, typed errors
 * and secrets) under every area: verifying tokens, machine clients, AI agents, and people signing in.
 *
 * @packageDocumentation
 */

export { AuthFI, type AuthFIOptions } from './core/project.js';
export type { ServerMetadata } from './core/metadata.js';
export { Secret } from './core/secret.js';
export { BaseTokenSource, type TokenOptions, type TokenSource } from './core/token-source.js';
export { MemoryTokenStore, TokenSet, type StoredTokenSet, type TokenStore } from './core/token-set.js';
export { idempotencyKey, requestId } from './core/ids.js';
export type { Logger, LogFields } from './core/logger.js';
export type { Clock } from './core/clock.js';
export type { OpenTelemetryApi } from './core/transport.js';
export { KERNEL_CODES_REF, KERNEL_TOKEN_CODES, type KernelTokenCode } from './core/codes.js';
export {
  APIError,
  AuthFIError,
  ConfigurationError,
  ConsentDenied,
  ConsentExpired,
  DiscoveryError,
  GatewayTokenRefused,
  InsufficientAuthentication,
  InsufficientPermission,
  InsufficientScope,
  InvalidToken,
  isAuthFIError,
  NotSupportedError,
  OAuthError,
  StepUpRequired,
  TemporarilyUnavailable,
  TransportError,
  type AuthFIErrorKinds,
  type ErrorCode,
  type ErrorContext,
  type KnownCode,
  type OAuthErrorCode,
  type SdkErrorCode,
} from './core/errors.js';
export { AccessToken, Principal, type PrincipalKind, type TokenKind } from './verify/access-token.js';
export {
  loggerOf,
  MultiIssuerVerifier,
  TokenVerifier,
  type RequestCredentials,
  type Scheme,
  type TrustedIssuer,
  type Verifier,
  type VerifierOptions,
} from './verify/verifier.js';
export {
  applyRequirements,
  checkRequirements,
  refusalAnswer,
  type AnswerOptions,
  type RefusalAnswer,
  type Requirements,
} from './verify/answer.js';
export type { CheckRequest, CheckResult } from './verify/check.js';
export { ClientCredentials, type ClientCredentialsOptions } from './machine/client-credentials.js';
// The 0.1 factory, deprecated and kept for one minor version.
// eslint-disable-next-line @typescript-eslint/no-deprecated
export { default, type LegacyClient, type LegacyConfig } from './legacy.js';
export { AgentKey, type AgentAlgorithm, type Signer } from './agents/agent-key.js';
export {
  AgentAuth,
  type ActionDecision,
  type AgentOptions,
  type Approval,
  type CibaRequest,
  type TransactionToken,
} from './agents/agent.js';
export { DelegatedToken, type DelegationRoute } from './agents/delegated.js';
export {
  APPROVAL_ARGUMENT,
  Gateway,
  type CloudCredential,
  type CloudCredentialOutcome,
  type ToolOutcome,
  type ToolResult,
} from './gateway/gateway.js';
