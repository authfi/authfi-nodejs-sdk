import { compactVerify } from 'jose';
import { fromBase64url, fromUtf8, utf8 } from '../core/bytes.js';
import { ConfigurationError, InvalidToken, isAuthFIError, TokenRevoked } from '../core/errors.js';
import type { Logger } from '../core/logger.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { isSecret, type Secret } from '../core/secret.js';
import { checkOrigin, isAtOrUnder, originOf } from '../core/urls.js';
import { AccessToken } from './access-token.js';
import { certificatesFromPem, ChainProver, DEFAULT_ROOT_PINS } from './chain.js';
import type { Certificate } from './der.js';
import {
  MAX_AGE_SECONDS,
  MAX_FUTURE_SECONDS,
  memoryReplayGuard,
  NonceIssuer,
  validateProof,
  type ProofConfig,
  type ReplayGuard,
} from './dpop-proof.js';

/** How an `af.verifier()` is configured. */
export interface VerifierOptions {
  /**
   * The audiences your API accepts: its own client id (for machine and agent tokens minted with
   * `resource`), and the client ids of the front ends that call it (a person's token names the app
   * they signed in to). Required; there is no "skip". AuthFI's own audiences are refused.
   */
  readonly audience: string | readonly string[];
  /**
   * The tenant the issuer belongs to. Recommended: without it the verifier accepts whatever
   * `tenant_id` the issuer's key signed. A server that trusts several issuers must pin each one (see
   * {@link MultiIssuerVerifier}).
   */
  readonly expectedTenantId?: string | undefined;
  /** Clock leeway for `exp`, `nbf` and `iat`, 0 to 300 000 ms. Defaults to the project's. */
  readonly leewayMs?: number | undefined;
  /**
   * What to do with an agent's token (a `sub` or `client_id` starting `agt_`, or an `act` claim):
   * `enforce` (the default) accepts it only with a valid DPoP proof and a signing key proven by an AuthFI
   * certificate chain; `watch` accepts it and logs what `enforce` would refuse; `off` skips both checks.
   */
  readonly agentTokens?: 'enforce' | 'watch' | 'off' | undefined;
  /**
   * The origin clients call this API at, such as `https://api.example.com`. A DPoP proof's `htu` is
   * checked against it plus the request path. Required to check any proof, unless `trustForwarded`.
   */
  readonly publicUrl?: string | undefined;
  /**
   * Take the origin for `htu` from the last `X-Forwarded-Proto` and `X-Forwarded-Host` entries when
   * no `publicUrl` is set. Only behind a proxy you control that overwrites both.
   */
  readonly trustForwarded?: boolean | undefined;
  /** Where single-use proof ids are recorded. The default is in this process; with replicas, share one. */
  readonly replayGuard?: ReplayGuard | undefined;
  /** At most this many proof ids in the default guard (default 100 000). */
  readonly replayMax?: number | undefined;
  /** At most this many proof ids per key in the default guard (default 1000). */
  readonly replayPerKey?: number | undefined;
  /** At least 16 bytes. When set, a proof must carry the server nonce (RFC 9449 �8), handed out by `serverNonce()`. */
  readonly nonceKey?: string | Uint8Array | undefined;
  /** SHA-256 of the SubjectPublicKeyInfo of each trusted root, lower-case hex. Defaults to AuthFI Root CA R1. */
  readonly rootPins?: readonly string[] | undefined;
  /** PEM roots to complete a chain whose `x5c` does not carry its root; each must still match a pin. */
  readonly rootCerts?: readonly string[] | undefined;
  /** Tokens of withdrawn subjects are refused. Fill it with `receiver()` from `@authfi/sdk/signals`. */
  readonly revocations?: RevocationStore | undefined;
}

/** What a verifier asks of a revocation store: see `createRevocationStore` in `@authfi/sdk/signals`. */
export interface RevocationStore {
  /** The revocation that applies to a token of `subject` issued at `issuedAt` (Unix seconds), or null. */
  find(subject: string, issuedAt: number): { readonly ref: string } | null;
  /** How long a revocation is remembered, in seconds: the longest token lifetime the store covers. */
  readonly tokenLifetimeSeconds: number;
}

/** The parts of a request a verifier reads. */
export interface RequestCredentials {
  /** The `Authorization` header: `Bearer …` or `DPoP …` (case-insensitive scheme). */
  readonly authorization?: string | null | undefined;
  /** The `DPoP` proof header. */
  readonly dpop?: string | null | undefined;
  /** The request method, for the proof's `htm`. */
  readonly method?: string | undefined;
  /** The request URL or path (a path may carry a query), for the proof's `htu`. */
  readonly url?: string | undefined;
  /**
   * How many `Authorization` and `DPoP` headers the request carried, when the server joined or dropped
   * duplicates: more than one of either is refused.
   */
  readonly headerCounts?: { readonly authorization?: number; readonly dpop?: number } | undefined;
  /** The raw `X-Forwarded-Proto` and `X-Forwarded-Host` values, read only with `trustForwarded`. */
  readonly forwarded?:
    { readonly proto?: string | undefined; readonly host?: string | undefined } | undefined;
}

/** Anything that verifies a request: a {@link TokenVerifier} or a {@link MultiIssuerVerifier}. */
export interface Verifier {
  verify(raw: string | Secret, options?: { signal?: AbortSignal }): Promise<AccessToken>;
  verifyRequest(input: Request | RequestCredentials): Promise<AccessToken>;
  /** The current DPoP server nonce to offer on responses, when the verifier requires nonces. */
  serverNonce?(): Promise<string | undefined>;
}

/** The scheme a credential arrived under. */
export type Scheme = 'Bearer' | 'DPoP';

const ALLOWED_ALGS = new Set(['RS256', 'ES256', 'EdDSA']);
const MAX_NUMERIC_DATE = 253_402_300_799; // 9999-12-31T23:59:59Z
const REPLAY_DEFAULT_MAX = 100_000;
const PIN_FORMAT = /^[0-9a-f]{64}$/;
const MAX_TOKEN_BYTES = 16 * 1024;
/** First-party clients whose tokens must never be accepted by a customer API. */
const FIRST_PARTY = new Set(['authfi-console', 'authfi-workspace']);

const LOGGER = Symbol.for('authfi.logger');

/**
 * The logger of the project a verifier belongs to, for an adapter's log lines. It is kept under a
 * registered symbol, so it is found across the ESM and CommonJS copies of the package.
 */
export function loggerOf(verifier: object): Logger | undefined {
  return (verifier as Record<symbol, Logger | undefined>)[LOGGER];
}

function setLogger(verifier: object, logger: Logger): void {
  Object.defineProperty(verifier, LOGGER, { value: logger });
}

function decodeJson(part: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(fromUtf8(fromBase64url(part)));
  } catch {
    throw new InvalidToken('token_malformed', 'the token is not a compact JWS');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InvalidToken('token_malformed', 'the token is not a compact JWS');
  }
  return value as Record<string, unknown>;
}

/** The decoded header and payload of a compact JWS, unverified. */
export function decodeUnverified(raw: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  // Bytes, not UTF-16 units: a code unit is at least one UTF-8 byte, so the length alone can
  // refuse early, and the encoded size decides the rest.
  if (raw.length > MAX_TOKEN_BYTES || utf8(raw).length > MAX_TOKEN_BYTES)
    throw new InvalidToken('token_malformed', 'the token is longer than 16 KiB');
  const parts = raw.split('.');
  if (parts.length === 5)
    throw new InvalidToken('token_malformed', 'the token is encrypted (JWE), not a signed access token');
  if (parts.length !== 3 || parts.some((p) => p === ''))
    throw new InvalidToken('token_malformed', 'the token is not a compact JWS');
  const [header, payload] = parts as [string, string, string];
  return { header: decodeJson(header), payload: decodeJson(payload) };
}

/** Splits an `Authorization` header into its scheme and credential, or refuses it as `token_missing`. */
export function parseAuthorization(header: string | null | undefined): { scheme: Scheme; raw: string } {
  const m = /^\s*(Bearer|DPoP)\s+(\S+)\s*$/i.exec(header ?? '');
  if (m?.[1] === undefined || m[2] === undefined)
    throw new InvalidToken('token_missing', 'no Bearer or DPoP credential in the request');
  return { scheme: m[1].toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer', raw: m[2] };
}

function numericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_NUMERIC_DATE;
}

/** Whether the claims name an agent: an `agt_` subject or client id, or an actor. */
function isAgentClaims(claims: Record<string, unknown>): boolean {
  return (
    (typeof claims.sub === 'string' && claims.sub.startsWith('agt_')) ||
    (typeof claims.client_id === 'string' && claims.client_id.startsWith('agt_')) ||
    (claims.act !== undefined && claims.act !== null)
  );
}

function audiences(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function isAccessTokenType(typ: unknown): boolean {
  if (typeof typ !== 'string') return false;
  const t = typ.toLowerCase();
  return t === 'at+jwt' || t === 'application/at+jwt';
}

/**
 * The brand {@link isTokenVerifier} reads. A package loaded as both ESM and CommonJS holds two
 * copies of this class, so `instanceof` is false for the other copy's verifiers.
 */
const VERIFIER_BRAND = Symbol.for('authfi.token-verifier');

/** Whether `value` is a {@link TokenVerifier}, from this copy of the SDK or another. */
export function isTokenVerifier(value: unknown): value is TokenVerifier {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<symbol, unknown>)[VERIFIER_BRAND] === true &&
    typeof (value as { verifyAs?: unknown }).verifyAs === 'function'
  );
}

/**
 * Verifies the access tokens one issuer mints for your API: people's, machine clients', agents' and
 * delegated tokens, with the rules of design §1.8. Made by `af.verifier({ audience })`.
 *
 * A refusal is an {@link InvalidToken} whose `code` is the kernel's refusal code. The code belongs
 * in your logs; on the wire, answer the one opaque `invalid_token` (the adapters do).
 */
export class TokenVerifier implements Verifier {
  /** The brand {@link isTokenVerifier} reads. */
  readonly [VERIFIER_BRAND] = true;
  readonly issuer: string;
  readonly audience: readonly string[];
  readonly expectedTenantId: string | undefined;
  readonly #core: Core;
  readonly #leewaySeconds: number;
  readonly #agentTokens: 'enforce' | 'watch' | 'off';
  readonly #publicOrigin: string | undefined;
  readonly #trustForwarded: boolean;
  readonly #nonces: NonceIssuer | undefined;
  readonly #guard: ReplayGuard;
  readonly #chain: ChainProver;
  readonly #revocations: RevocationStore | undefined;
  #apiOriginChecked = false;

  /** Use `af.verifier()`. */
  constructor(af: AuthFI, options: VerifierOptions) {
    this.#core = coreOf(af);
    this.issuer = af.issuer;
    const list = (typeof options.audience === 'string' ? [options.audience] : [...options.audience]).map(
      (a) => a.trim(),
    );
    if (list.length === 0 || list.some((a) => a === '')) {
      throw new ConfigurationError(
        "audience is required: your API's client id, and the client ids of the front ends that call it",
      );
    }
    for (const a of list) refuseOwnAudience(a, [af.issuer, af.apiOrigin]);
    this.audience = Object.freeze(list);
    if (options.expectedTenantId?.trim() === '') {
      throw new ConfigurationError('expectedTenantId must not be empty');
    }
    this.expectedTenantId = options.expectedTenantId;
    const leewayMs = options.leewayMs ?? this.#core.leewayMs;
    if (!Number.isFinite(leewayMs) || leewayMs < 0 || leewayMs > 300_000)
      throw new ConfigurationError('leewayMs must be from 0 to 300000');
    this.#leewaySeconds = leewayMs / 1000;
    const mode: string = options.agentTokens ?? 'enforce';
    if (mode !== 'enforce' && mode !== 'watch' && mode !== 'off')
      throw new ConfigurationError('agentTokens is enforce, watch or off');
    this.#agentTokens = mode;
    this.#publicOrigin =
      options.publicUrl === undefined ? undefined : checkOrigin(options.publicUrl, 'publicUrl');
    this.#trustForwarded = options.trustForwarded === true;
    const nonceSecret = typeof options.nonceKey === 'string' ? utf8(options.nonceKey) : options.nonceKey;
    if (nonceSecret !== undefined && nonceSecret.length < 16)
      throw new ConfigurationError('nonceKey must be at least 16 bytes');
    this.#nonces = nonceSecret === undefined ? undefined : new NonceIssuer(Uint8Array.from(nonceSecret));
    const now = (): number => this.#core.clock.now();
    this.#guard =
      options.replayGuard ??
      memoryReplayGuard(options.replayMax ?? REPLAY_DEFAULT_MAX, now, options.replayPerKey);
    if (typeof (this.#guard as { record?: unknown }).record !== 'function')
      throw new ConfigurationError('replayGuard needs a record(key, expiresAtMs) method');
    const pins = options.rootPins ?? DEFAULT_ROOT_PINS;
    if (
      !Array.isArray(pins) ||
      pins.length === 0 ||
      !pins.every((p: unknown) => typeof p === 'string' && PIN_FORMAT.test(p))
    )
      throw new ConfigurationError('rootPins is a list of lower-case hex SHA-256 values of root public keys');
    const roots: Certificate[] = [];
    for (const pem of options.rootCerts ?? []) {
      try {
        roots.push(...certificatesFromPem(pem));
      } catch {
        throw new ConfigurationError('rootCerts holds a certificate that is not valid PEM');
      }
    }
    this.#chain = new ChainProver({ pins, roots, clock: this.#core.clock });
    this.#revocations = options.revocations;
    setLogger(this, this.#core.logger);
  }

  /** The current DPoP server nonce to put in a `DPoP-Nonce` header, or undefined when `nonceKey` is not set. */
  serverNonce(): Promise<string | undefined> {
    return this.#nonces === undefined
      ? Promise.resolve(undefined)
      : this.#nonces.current(this.#core.clock.now());
  }

  /**
   * Verifies a token presented under the Bearer scheme, with no request: a person's or a machine
   * client's. An agent's token carries a key binding only a request can prove, so it is refused here
   * as `agent_token_needs_request` (use {@link TokenVerifier.verifyRequest}).
   */
  verify(raw: string | Secret, options: { signal?: AbortSignal } = {}): Promise<AccessToken> {
    const value = isSecret(raw) ? raw.reveal() : raw;
    return this.verifyAs(value, 'Bearer', this.expectedTenantId, options.signal);
  }

  /**
   * Verifies the credential of a request: its `Authorization` header (`Bearer` or `DPoP`), and, for
   * a token bound to a key and for every agent's token, the DPoP proof, method and URL, and the
   * certificate chain of the signing key. Takes a Fetch API `Request`, or the parts.
   */
  verifyRequest(input: Request | RequestCredentials): Promise<AccessToken> {
    const credentials = credentialsOf(input);
    let parsed: { scheme: Scheme; raw: string };
    try {
      if ((credentials.headerCounts?.authorization ?? 0) > 1)
        throw new InvalidToken('token_missing', 'exactly one Authorization header is allowed');
      parsed = parseAuthorization(credentials.authorization);
    } catch (e) {
      return Promise.reject(e as Error);
    }
    return this.verifyAs(parsed.raw, parsed.scheme, this.expectedTenantId, undefined, credentials);
  }

  /** Verifies under a scheme, with a tenant pin. Internal to the SDK (the multi-issuer verifier pins). */
  async verifyAs(
    raw: string,
    scheme: Scheme,
    tenantPin: string | undefined,
    signal?: AbortSignal,
    request?: RequestCredentials,
  ): Promise<AccessToken> {
    if (raw === '') throw new InvalidToken('token_missing', 'no token');
    const { header, payload } = decodeUnverified(raw);

    const alg = header.alg;
    if (typeof alg !== 'string' || !ALLOWED_ALGS.has(alg)) {
      throw new InvalidToken('token_signature_invalid', `the algorithm ${JSON.stringify(alg)} is refused`);
    }
    if (!isAccessTokenType(header.typ)) {
      throw new InvalidToken(
        'token_not_access_token',
        `the token type ${JSON.stringify(header.typ)} is not at+jwt`,
      );
    }
    if (header.crit !== undefined)
      throw new InvalidToken(
        'token_claims_invalid',
        'the token names critical header parameters the SDK does not understand',
      );
    if (typeof header.kid !== 'string' || header.kid === '')
      throw new InvalidToken('token_key_unknown', 'the token names no key');

    await this.#checkLearnedApiOrigin(signal);
    const { key, published } = await this.#core.keys.key(header.kid, alg, signal);
    try {
      await compactVerify(raw, key, { algorithms: [alg] });
    } catch {
      throw new InvalidToken('token_signature_invalid', 'the signature does not verify');
    }

    // The claims are read only after the signature: before it they are anyone's bytes.
    const now = this.#core.clock.now() / 1000;
    const leeway = this.#leewaySeconds;
    if (payload.iss !== this.issuer) {
      throw new InvalidToken(
        'token_issuer_not_accepted',
        `the token's issuer ${JSON.stringify(payload.iss)} is not ${this.issuer}`,
      );
    }
    if (!numericDate(payload.exp))
      throw new InvalidToken('token_claims_invalid', 'the token has no valid exp');
    if (payload.exp + leeway <= now) throw new InvalidToken('token_expired', 'the token has expired');
    for (const name of ['nbf', 'iat'] as const) {
      if (payload[name] !== undefined && !numericDate(payload[name]))
        throw new InvalidToken('token_claims_invalid', `the ${name} claim is not valid`);
    }
    if (typeof payload.nbf === 'number' && payload.nbf - leeway > now)
      throw new InvalidToken('token_claims_invalid', 'the token is not valid yet (nbf)');
    if (typeof payload.iat === 'number' && payload.iat - leeway > now)
      throw new InvalidToken('token_claims_invalid', 'the token was issued in the future (iat)');
    const aud = audiences(payload.aud);
    if (!aud.some((a) => this.audience.includes(a)))
      throw new InvalidToken('token_audience_mismatch', 'the token is not for this API');
    if (typeof payload.sub !== 'string' || payload.sub === '')
      throw new InvalidToken('token_claims_invalid', 'the token has no sub');
    if (typeof payload.tenant_id !== 'string' || payload.tenant_id === '')
      throw new InvalidToken('token_no_tenant', 'the token names no tenant');
    if (tenantPin !== undefined && payload.tenant_id !== tenantPin) {
      throw new InvalidToken(
        'token_tenant_not_issuers',
        `the token's tenant is not the tenant ${this.issuer} belongs to`,
      );
    }

    const agent = isAgentClaims(payload);
    const bound = (payload.cnf !== undefined && payload.cnf !== null) || payload.authfi_mandate !== undefined;
    // A bound token presented as Bearer is refused before its actor chain is looked at. Watching an
    // agent's token (a request only) logs what enforcing would refuse, and accepts.
    const watching = agent && this.#agentTokens === 'watch' && request !== undefined;
    // Without a request, an agent's token is refused for needing one, whatever else it carries.
    const needsRequest = agent && this.#agentTokens === 'enforce' && request === undefined;
    if (bound && scheme === 'Bearer' && !watching && !needsRequest)
      throw new InvalidToken(
        'token_dpop_proof_required',
        request === undefined
          ? 'the token is bound to a key and needs a DPoP proof; use verifyRequest'
          : 'a sender-constrained token was presented as Bearer',
      );

    const act: unknown = payload.act;
    if (
      act !== undefined &&
      (typeof act !== 'object' || act === null || typeof (act as { sub?: unknown }).sub !== 'string')
    ) {
      throw new InvalidToken('token_claims_invalid', 'the act claim is not an object with a sub');
    }
    if (act !== undefined && (act as { act?: unknown }).act !== undefined)
      throw new InvalidToken('token_act_chain_unsupported', 'a chain of actors (nested act) is not accepted');

    // Revocation runs before the proof, so a withdrawn agent is answered `token_revoked` wherever its
    // token is presented, and it reads nothing but the claims.
    this.#checkRevoked(payload);

    if (request === undefined) {
      // No request to prove anything with: a person's or a machine client's Bearer token only.
      if (agent) {
        if (this.#agentTokens === 'enforce')
          throw new InvalidToken(
            'agent_token_needs_request',
            "an agent's token is verified with verifyRequest, which checks its proof and key chain",
          );
        this.#noteUnchecked();
      }
      return new AccessToken(payload, aud);
    }

    const checkAgent = agent && this.#agentTokens !== 'off';
    if (!bound && !checkAgent) {
      if (scheme === 'DPoP')
        throw new InvalidToken('token_dpop_unbound', 'the DPoP scheme was used with a token bound to no key');
      if (agent) this.#noteUnchecked();
      return new AccessToken(payload, aud);
    }
    const prove = async (): Promise<void> => {
      const cnf = payload.cnf as { jkt?: unknown } | null | undefined;
      const jkt = bound && typeof cnf === 'object' && cnf !== null ? cnf.jkt : undefined;
      if (typeof jkt !== 'string' || jkt === '')
        throw new InvalidToken('dpop_proof_key_mismatch', 'the token carries no key binding (cnf.jkt)');
      if (scheme !== 'DPoP')
        throw new InvalidToken(
          'token_dpop_proof_required',
          'a sender-constrained token was presented as Bearer',
        );
      const proof = await validateProof(request, raw, jkt, this.#proofConfig(), this.#core.clock.now());
      if (checkAgent) await this.#chain.prove(published, header['x5t#S256']);
      // Single use: recorded only after every other check has passed.
      let outcome: boolean | 'full' = false;
      let unavailable = false;
      try {
        outcome = await this.#guard.record(
          `${proof.thumbprint}:${proof.jti}`,
          (proof.iat + MAX_AGE_SECONDS + MAX_FUTURE_SECONDS + 60) * 1000,
        );
      } catch {
        unavailable = true;
      }
      if (unavailable || outcome === 'full')
        throw new InvalidToken(
          'dpop_replay_check_unavailable',
          'the replay guard cannot record the proof now',
        );
      if (!outcome) throw new InvalidToken('dpop_proof_replayed', 'the proof was already used');
    };
    if (agent && this.#agentTokens === 'watch') {
      try {
        await prove();
      } catch (e) {
        if (!(e instanceof InvalidToken) && !isAuthFIError(e, 'ConfigurationError')) throw e;
        this.#core.logger.warn('an agent token would be refused', { code: (e as { code?: string }).code });
      }
      return new AccessToken(payload, aud);
    }
    await prove();
    return new AccessToken(payload, aud);
  }

  #noteUnchecked(): void {
    if (this.#agentTokens === 'off') {
      this.#core.warnOnce(
        'agent-tokens-off',
        'agentTokens is off, so agent tokens are accepted without proof of possession or key chain',
      );
    } else {
      this.#core.logger.warn('an agent token would be refused', { code: 'agent_token_needs_request' });
    }
  }

  #proofConfig(): ProofConfig {
    if (this.#publicOrigin === undefined && !this.#trustForwarded) {
      throw new ConfigurationError(
        'publicUrl is required to check DPoP proofs (or set trustForwarded behind a trusted proxy)',
      );
    }
    return {
      publicOrigin: this.#publicOrigin,
      trustForwarded: this.#trustForwarded,
      nonces: this.#nonces,
      guard: this.#guard,
    };
  }

  /**
   * Refuses a token whose subject, or any actor in its delegation chain, was revoked after it was
   * issued. The store forgets a revocation once the longest token it was told about has expired, so
   * a token that lives longer would outlive its revocation: it is refused as a misconfiguration.
   */
  #checkRevoked(claims: Record<string, unknown>): void {
    const store = this.#revocations;
    if (store === undefined) return;
    const { iat, exp } = claims;
    if (
      typeof iat !== 'number' ||
      typeof exp !== 'number' ||
      !Number.isFinite(iat) ||
      !Number.isFinite(exp)
    ) {
      throw new InvalidToken(
        'token_iat_exp_required',
        'the token has no issue or expiry time, which revocation needs',
      );
    }
    if (exp - iat > store.tokenLifetimeSeconds) {
      throw new ConfigurationError(
        'the revocation store tokenLifetimeSeconds is shorter than this token lifetime; raise it',
      );
    }
    // A chain of actors is refused before this runs, so the subject and at most one actor remain.
    const subjects = [claims.sub as string];
    const actor = (claims.act as { sub?: string } | undefined)?.sub;
    if (actor !== undefined) subjects.push(actor);
    for (const subject of subjects) {
      const hit = store.find(subject, iat);
      if (hit !== null) {
        throw new TokenRevoked(
          hit.ref,
          hit.ref === '' ? 'the token was revoked' : `the token was revoked (ref ${hit.ref})`,
        );
      }
    }
  }

  /** Refuses, once discovery taught the API origin, an audience under it (design §1.8 item 6). */
  async #checkLearnedApiOrigin(signal?: AbortSignal): Promise<void> {
    if (this.#apiOriginChecked) return;
    const apiOrigin = await this.#core.apiOrigin(signal);
    for (const a of this.audience) refuseOwnAudience(a, [apiOrigin]);
    this.#apiOriginChecked = true;
  }
}

/**
 * Refuses an audience that is AuthFI's own: the issuer, the API origin, any URL under either (the
 * gateway's `<issuer>/mcp` among them), or a first-party client. Accepting one would let a token
 * minted for the gateway, or for the console, be replayed at your API.
 */
function refuseOwnAudience(audience: string, own: readonly string[]): void {
  const fix = "mint the token with resource=<your API's client id> and verify that audience";
  if (FIRST_PARTY.has(audience)) {
    throw new ConfigurationError(
      `the audience ${audience} is an AuthFI first-party client, which no API may accept: ${fix}`,
    );
  }
  for (const base of own) {
    const origin = originOf(base);
    if (isAtOrUnder(audience, base) || (origin !== undefined && isAtOrUnder(audience, origin))) {
      throw new ConfigurationError(
        `the audience ${audience} is AuthFI's own (${base}), which no API may accept: ${fix}`,
      );
    }
  }
}

function header(
  input: Request | RequestCredentials,
  name: 'authorization' | 'dpop',
): string | null | undefined {
  return input instanceof Request ? input.headers.get(name) : input[name];
}

function credentialsOf(input: Request | RequestCredentials): RequestCredentials {
  return {
    authorization: header(input, 'authorization'),
    dpop: header(input, 'dpop'),
    method: input.method,
    url: input.url,
    headerCounts: input instanceof Request ? undefined : input.headerCounts,
    forwarded:
      input instanceof Request
        ? {
            proto: input.headers.get('x-forwarded-proto') ?? undefined,
            host: input.headers.get('x-forwarded-host') ?? undefined,
          }
        : input.forwarded,
  };
}

/** One trusted issuer of a {@link MultiIssuerVerifier}: its verifier and the tenant it belongs to. */
export interface TrustedIssuer {
  readonly verifier: TokenVerifier;
  readonly tenantId: string;
}

/**
 * Verifies tokens from several projects. It picks the verifier by the token's (unverified) `iss`,
 * from the list only, and pins each issuer to its tenant, as the platform does: a token whose
 * `tenant_id` is not the tenant held for its issuer is refused `token_tenant_not_issuers`. It never
 * accepts "any *.authfi.io".
 *
 * @example
 * const verifier = new MultiIssuerVerifier({
 *   'https://acme.authfi.io': { verifier: acme.verifier({ audience: 'api_orders' }), tenantId: '4e46e0c4-…' },
 * });
 */
export class MultiIssuerVerifier implements Verifier {
  readonly #issuers: ReadonlyMap<string, TrustedIssuer>;

  constructor(issuers: Readonly<Record<string, TrustedIssuer>>) {
    const map = new Map<string, TrustedIssuer>();
    for (const [issuer, entry] of Object.entries(issuers)) {
      if (!isTokenVerifier(entry.verifier))
        throw new ConfigurationError(`the entry for ${issuer} has no TokenVerifier`);
      if (entry.verifier.issuer !== issuer) {
        throw new ConfigurationError(`the verifier filed under ${issuer} verifies ${entry.verifier.issuer}`);
      }
      if (typeof entry.tenantId !== 'string' || entry.tenantId.trim() === '') {
        throw new ConfigurationError(
          `the tenant of ${issuer} is required: each issuer is pinned to its tenant`,
        );
      }
      if (
        entry.verifier.expectedTenantId !== undefined &&
        entry.verifier.expectedTenantId !== entry.tenantId
      ) {
        throw new ConfigurationError(
          `the verifier for ${issuer} expects another tenant than the one given beside it`,
        );
      }
      map.set(issuer, entry);
      const logger = loggerOf(entry.verifier);
      if (logger !== undefined && loggerOf(this) === undefined) setLogger(this, logger);
    }
    if (map.size === 0) throw new ConfigurationError('a MultiIssuerVerifier needs at least one issuer');
    this.#issuers = map;
  }

  /** Verifies a token presented under the Bearer scheme. */
  verify(raw: string | Secret, options: { signal?: AbortSignal } = {}): Promise<AccessToken> {
    const value = isSecret(raw) ? raw.reveal() : raw;
    return this.#verify(value, 'Bearer', options.signal);
  }

  /** Verifies the credential of a request (see {@link TokenVerifier.verifyRequest}). */
  verifyRequest(input: Request | RequestCredentials): Promise<AccessToken> {
    try {
      const credentials = credentialsOf(input);
      if ((credentials.headerCounts?.authorization ?? 0) > 1)
        throw new InvalidToken('token_missing', 'exactly one Authorization header is allowed');
      const { scheme, raw } = parseAuthorization(credentials.authorization);
      return this.#verify(raw, scheme, undefined, credentials);
    } catch (e) {
      return Promise.reject(e as Error);
    }
  }

  async #verify(
    raw: string,
    scheme: Scheme,
    signal?: AbortSignal,
    request?: RequestCredentials,
  ): Promise<AccessToken> {
    const { payload } = decodeUnverified(raw);
    const entry = typeof payload.iss === 'string' ? this.#issuers.get(payload.iss) : undefined;
    if (entry === undefined)
      throw new InvalidToken('token_issuer_not_accepted', 'the token was not issued by a trusted issuer');
    return entry.verifier.verifyAs(raw, scheme, entry.tenantId, signal, request);
  }
}
