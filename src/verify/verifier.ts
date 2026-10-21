import { compactVerify } from 'jose';
import { fromBase64url, fromUtf8, utf8 } from '../core/bytes.js';
import { ConfigurationError, InvalidToken } from '../core/errors.js';
import type { Logger } from '../core/logger.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { isSecret, type Secret } from '../core/secret.js';
import { isAtOrUnder, originOf } from '../core/urls.js';
import { AccessToken } from './access-token.js';

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
}

/** The parts of a request a verifier reads. */
export interface RequestCredentials {
  /** The `Authorization` header: `Bearer …` or `DPoP …` (case-insensitive scheme). */
  readonly authorization?: string | null | undefined;
  /** The `DPoP` proof header. */
  readonly dpop?: string | null | undefined;
  /** The request method, for the proof's `htm`. */
  readonly method?: string | undefined;
  /** The full request URL, for the proof's `htu`. */
  readonly url?: string | undefined;
}

/** Anything that verifies a request: a {@link TokenVerifier} or a {@link MultiIssuerVerifier}. */
export interface Verifier {
  verify(raw: string | Secret, options?: { signal?: AbortSignal }): Promise<AccessToken>;
  verifyRequest(input: Request | RequestCredentials): Promise<AccessToken>;
}

/** The scheme a credential arrived under. */
export type Scheme = 'Bearer' | 'DPoP';

const ALLOWED_ALGS = new Set(['RS256', 'ES256', 'EdDSA']);
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
  return { header: decodeJson(parts[0] ?? ''), payload: decodeJson(parts[1] ?? '') };
}

/** Splits an `Authorization` header into its scheme and credential, or refuses it as `token_missing`. */
export function parseAuthorization(header: string | null | undefined): { scheme: Scheme; raw: string } {
  const m = /^\s*(Bearer|DPoP)\s+(\S+)\s*$/i.exec(header ?? '');
  if (m?.[1] === undefined || m[2] === undefined)
    throw new InvalidToken('token_missing', 'no Bearer or DPoP credential in the request');
  return { scheme: m[1].toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer', raw: m[2] };
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
    setLogger(this, this.#core.logger);
  }

  /** Verifies a token presented under the Bearer scheme. */
  verify(raw: string | Secret, options: { signal?: AbortSignal } = {}): Promise<AccessToken> {
    const value = isSecret(raw) ? raw.reveal() : raw;
    return this.verifyAs(value, 'Bearer', this.expectedTenantId, options.signal);
  }

  /**
   * Verifies the credential of a request: its `Authorization` header (`Bearer` or `DPoP`), and the
   * DPoP proof, method and URL a bound token needs. Takes a Fetch API `Request`, or the four parts.
   */
  verifyRequest(input: Request | RequestCredentials): Promise<AccessToken> {
    const { authorization } = credentialsOf(input);
    let parsed: { scheme: Scheme; raw: string };
    try {
      parsed = parseAuthorization(authorization);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    return this.verifyAs(parsed.raw, parsed.scheme, this.expectedTenantId);
  }

  /** Verifies under a scheme, with a tenant pin. Internal to the SDK (the multi-issuer verifier pins). */
  async verifyAs(
    raw: string,
    scheme: Scheme,
    tenantPin: string | undefined,
    signal?: AbortSignal,
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
    const { key } = await this.#core.keys.key(header.kid, alg, signal);
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
    if (typeof payload.exp !== 'number')
      throw new InvalidToken('token_claims_invalid', 'the token has no exp');
    if (payload.exp + leeway <= now) throw new InvalidToken('token_expired', 'the token has expired');
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

    const bound = payload.cnf !== undefined || payload.authfi_mandate !== undefined;
    if (bound && scheme === 'Bearer')
      throw new InvalidToken(
        'token_dpop_proof_required',
        'a sender-constrained token was presented as Bearer',
      );
    if (bound)
      throw new InvalidToken('token_dpop_unsupported', 'this verifier does not check DPoP proofs yet');
    if (scheme === 'DPoP')
      throw new InvalidToken('token_dpop_unbound', 'the DPoP scheme was used with a token bound to no key');

    const act: unknown = payload.act;
    if (
      act !== undefined &&
      (typeof act !== 'object' || act === null || typeof (act as { sub?: unknown }).sub !== 'string')
    ) {
      throw new InvalidToken('token_claims_invalid', 'the act claim is not an object with a sub');
    }
    if (act !== undefined && (act as { act?: unknown }).act !== undefined)
      throw new InvalidToken('token_act_chain_unsupported', 'a chain of actors (nested act) is not accepted');

    return new AccessToken(payload, aud);
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
      const { scheme, raw } = parseAuthorization(credentialsOf(input).authorization);
      return this.#verify(raw, scheme);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
  }

  async #verify(raw: string, scheme: Scheme, signal?: AbortSignal): Promise<AccessToken> {
    const { payload } = decodeUnverified(raw);
    const entry = typeof payload.iss === 'string' ? this.#issuers.get(payload.iss) : undefined;
    if (entry === undefined)
      throw new InvalidToken('token_issuer_not_accepted', 'the token was not issued by a trusted issuer');
    return entry.verifier.verifyAs(raw, scheme, entry.tenantId, signal);
  }
}
