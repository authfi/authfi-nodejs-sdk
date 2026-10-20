import { compactVerify } from 'jose';
import { base64url, sha256, utf8 } from '../core/bytes.js';
import { InvalidToken, StepUpRequired } from '../core/errors.js';
import type { Core } from '../core/project.js';
import type { Secret } from '../core/secret.js';
import { decodeUnverified } from '../verify/verifier.js';
import { sameString } from './pending.js';

/** The claims of a verified ID token: who signed in, and how. */
export interface IdTokenClaims {
  readonly sub: string;
  readonly email: string | undefined;
  readonly emailVerified: boolean | undefined;
  readonly name: string | undefined;
  readonly acr: string | undefined;
  readonly amr: readonly string[];
  readonly authTime: Date | undefined;
  readonly sid: string | undefined;
  readonly groups: readonly string[];
  readonly roles: readonly string[];
  /** Every claim, read-only. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/** What the ID token is checked against. */
export interface IdTokenExpectations {
  readonly clientId: string;
  readonly nonce: string;
  readonly accessToken: Secret;
  readonly acrValues: readonly string[];
  readonly maxAge: number | undefined;
}

const ALLOWED = new Set(['RS256', 'ES256', 'EdDSA']);

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/**
 * Verifies an ID token (design §1.8): the algorithm is one discovery lists for ID tokens and the
 * key's own, `typ` is JWT, `iss` is the issuer, `aud` names the app (with `azp` when it names
 * several), the `nonce` matches in constant time, `at_hash` matches the access token, and the
 * sign-in meets the `acr` and `max_age` asked for (else {@link StepUpRequired}). It is never an
 * access-token verifier.
 */
export async function verifyIdToken(
  core: Core,
  raw: Secret,
  expect: IdTokenExpectations,
): Promise<IdTokenClaims> {
  const token = raw.reveal();
  const { header, payload } = decodeUnverified(token);
  const meta = await core.metadata();
  const advertised = meta.id_token_signing_alg_values_supported ?? ['RS256'];
  const alg = header.alg;
  if (typeof alg !== 'string' || !ALLOWED.has(alg) || !advertised.includes(alg)) {
    throw new InvalidToken(
      'token_signature_invalid',
      `the ID token's algorithm ${JSON.stringify(alg)} is not one the issuer signs ID tokens with`,
    );
  }
  if (typeof header.typ === 'string' && header.typ.toUpperCase() !== 'JWT') {
    throw new InvalidToken('token_claims_invalid', `the ID token's type ${header.typ} is not JWT`);
  }
  if (typeof header.kid !== 'string' || header.kid === '')
    throw new InvalidToken('token_key_unknown', 'the ID token names no key');
  const { key } = await core.keys.key(header.kid, alg);
  try {
    await compactVerify(token, key, { algorithms: [alg] });
  } catch {
    throw new InvalidToken('token_signature_invalid', "the ID token's signature does not verify");
  }

  const now = core.clock.now() / 1000;
  const leeway = core.leewayMs / 1000;
  if (payload.iss !== core.issuer)
    throw new InvalidToken('token_issuer_not_accepted', 'the ID token is from another issuer');
  const aud = typeof payload.aud === 'string' ? [payload.aud] : strings(payload.aud);
  if (!aud.includes(expect.clientId))
    throw new InvalidToken('token_audience_mismatch', 'the ID token is for another app');
  if (aud.length > 1 && payload.azp !== expect.clientId)
    throw new InvalidToken('token_audience_mismatch', "the ID token's azp is not this app");
  if (typeof payload.exp !== 'number')
    throw new InvalidToken('token_claims_invalid', 'the ID token has no exp');
  if (payload.exp + leeway <= now) throw new InvalidToken('token_expired', 'the ID token has expired');
  if (typeof payload.iat === 'number' && payload.iat - leeway > now)
    throw new InvalidToken('token_claims_invalid', 'the ID token was issued in the future');
  if (typeof payload.sub !== 'string' || payload.sub === '')
    throw new InvalidToken('token_claims_invalid', 'the ID token has no sub');
  if (typeof payload.nonce !== 'string' || !sameString(payload.nonce, expect.nonce)) {
    throw new InvalidToken('token_claims_invalid', "the ID token's nonce is not this sign-in's");
  }
  if (typeof payload.at_hash === 'string') {
    const digest =
      alg === 'EdDSA'
        ? new Uint8Array(await crypto.subtle.digest('SHA-512', utf8(expect.accessToken.reveal())))
        : await sha256(utf8(expect.accessToken.reveal()));
    if (!sameString(payload.at_hash, base64url(digest.subarray(0, digest.length / 2)))) {
      throw new InvalidToken(
        'token_claims_invalid',
        "the ID token's at_hash does not match the access token",
      );
    }
  }
  const authTime = typeof payload.auth_time === 'number' ? payload.auth_time : undefined;
  if (expect.maxAge !== undefined && (authTime === undefined || now - authTime > expect.maxAge + leeway)) {
    throw new StepUpRequired('the sign-in is older than the max_age asked for', {
      acrValues: expect.acrValues,
      maxAge: expect.maxAge,
    });
  }
  const acr = typeof payload.acr === 'string' ? payload.acr : undefined;
  if (expect.acrValues.length > 0 && (acr === undefined || !expect.acrValues.includes(acr))) {
    throw new StepUpRequired('the person signed in with a weaker method than the acr asked for', {
      acrValues: expect.acrValues,
      maxAge: expect.maxAge,
    });
  }
  return Object.freeze({
    sub: payload.sub,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    emailVerified: typeof payload.email_verified === 'boolean' ? payload.email_verified : undefined,
    name: typeof payload.name === 'string' ? payload.name : undefined,
    acr,
    amr: Object.freeze(strings(payload.amr)),
    authTime: authTime === undefined ? undefined : new Date(authTime * 1000),
    sid: typeof payload.sid === 'string' ? payload.sid : undefined,
    groups: Object.freeze(strings(payload.groups)),
    roles: Object.freeze(strings(payload.roles)),
    claims: Object.freeze({ ...payload }),
  });
}
