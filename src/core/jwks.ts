import { importJWK, type JWK } from 'jose';
import { CachedDocument, maxAgeOf, type Loaded } from './cache.js';
import type { Clock } from './clock.js';
import { fromBase64url } from './bytes.js';
import { DiscoveryError, InvalidToken } from './errors.js';
import type { Logger } from './logger.js';
import { contextOf, jsonOf, MAX_DOCUMENT_BYTES, type Transport } from './transport.js';

/** The algorithms the SDK verifies issuer signatures with. */
export type VerifyAlgorithm = 'RS256' | 'ES256' | 'EdDSA';

/** A published key the verifier may use: its kid and the one algorithm it verifies. */
interface UsableKey {
  readonly kid: string;
  readonly alg: VerifyAlgorithm;
  readonly jwk: JWK;
}

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'] as const;
const MIN_RSA_BITS = 2048;

/** A key whose kid the token names is not published, after the rate-limited refetch. */
export const UNKNOWN_KID_REFETCH_MS = 30_000;

/** The algorithm a key's type implies, or undefined for a type the SDK does not verify. */
function algorithmOfType(jwk: JWK): VerifyAlgorithm | undefined {
  if (jwk.kty === 'RSA') return 'RS256';
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  return undefined;
}

/**
 * Why a published key is refused, or undefined when it may be used. A key is used for signatures
 * only, has no private member, has an `alg` that agrees with its type, and (RSA) at least 2048 bits.
 */
export function refusalOf(jwk: JWK): string | undefined {
  if (typeof jwk.kid !== 'string' || jwk.kid === '') return 'it has no kid';
  if (jwk.use !== undefined && jwk.use !== 'sig') return `its use is ${jwk.use}`;
  if (PRIVATE_MEMBERS.some((m) => (jwk as Record<string, unknown>)[m] !== undefined))
    return 'it carries a private member';
  const implied = algorithmOfType(jwk);
  if (implied === undefined) return `its type ${jwk.kty ?? '-'}/${jwk.crv ?? '-'} is not verified by the SDK`;
  if (jwk.alg !== undefined && jwk.alg !== implied)
    return `its alg ${jwk.alg} disagrees with its type ${jwk.kty}`;
  if (jwk.kty === 'RSA') {
    let bits: number;
    try {
      const n = fromBase64url(jwk.n ?? '');
      let i = 0;
      while (i < n.length && n[i] === 0) i++;
      bits = (n.length - i) * 8;
    } catch {
      return 'its modulus is not base64url';
    }
    if (bits < MIN_RSA_BITS) return `its modulus is ${String(bits)} bits, under ${String(MIN_RSA_BITS)}`;
  }
  return undefined;
}

/**
 * The issuer's published keys, read from the metadata's `jwks_uri` (never built from the issuer),
 * cached for the answer's `max-age`. A kid not in the set triggers one refetch, at most once per
 * 30 seconds per issuer, so a stream of invented kids cannot turn every request into a fetch.
 */
export class KeySet {
  readonly #doc: CachedDocument<ReadonlyMap<string, UsableKey>>;
  readonly #clock: Clock;
  readonly #imported = new Map<string, Promise<CryptoKey>>();
  #lastUnknownRefetch = Number.NEGATIVE_INFINITY;

  constructor(transport: Transport, jwksUri: () => Promise<string>, clock: Clock, logger: Logger) {
    this.#clock = clock;
    this.#doc = new CachedDocument(async () => loadKeys(transport, await jwksUri(), logger), clock);
  }

  /**
   * The verification key for `kid`, with the one algorithm it verifies. Refuses (as `InvalidToken`)
   * an unknown kid, and a header `alg` that is not the key's.
   */
  async key(
    kid: string,
    alg: string,
    signal?: AbortSignal,
  ): Promise<{ key: CryptoKey; alg: VerifyAlgorithm }> {
    let keys = await this.#doc.get({ signal });
    let found = keys.get(kid);
    if (found === undefined && this.#clock.monotonic() - this.#lastUnknownRefetch >= UNKNOWN_KID_REFETCH_MS) {
      this.#lastUnknownRefetch = this.#clock.monotonic();
      keys = await this.#doc.get({ refresh: true, signal });
      found = keys.get(kid);
    }
    if (found === undefined)
      throw new InvalidToken('token_key_unknown', `the issuer publishes no usable key ${kid}`);
    if (alg !== found.alg) {
      throw new InvalidToken(
        'token_signature_invalid',
        `the token's alg ${alg} is not ${found.alg}, the algorithm of key ${kid}`,
      );
    }
    const cacheKey = `${kid}\u0000${JSON.stringify(found.jwk)}`;
    let imported = this.#imported.get(cacheKey);
    if (imported === undefined) {
      imported = importJWK(found.jwk, found.alg).then((k) => k as CryptoKey);
      imported.catch(() => this.#imported.delete(cacheKey));
      this.#imported.set(cacheKey, imported);
    }
    return { key: await imported, alg: found.alg };
  }
}

async function loadKeys(
  transport: Transport,
  url: string,
  logger: Logger,
): Promise<Loaded<ReadonlyMap<string, UsableKey>>> {
  const res = await transport.send({ method: 'GET', url, retry: 'safe', maxBytes: MAX_DOCUMENT_BYTES });
  if (res.status !== 200) {
    throw new DiscoveryError(
      'discovery_failed',
      `the key set at ${url} answered HTTP ${String(res.status)}`,
      contextOf(res),
    );
  }
  const doc = jsonOf(res) as { keys?: unknown } | undefined;
  if (typeof doc !== 'object' || !Array.isArray(doc.keys)) {
    throw new DiscoveryError('discovery_failed', `the key set at ${url} has no keys array`, contextOf(res));
  }
  const keys = new Map<string, UsableKey>();
  for (const raw of doc.keys as unknown[]) {
    if (typeof raw !== 'object' || raw === null) continue;
    const jwk = raw as JWK;
    const refusal = refusalOf(jwk);
    if (refusal !== undefined) {
      logger.warn('ignored a published key', {
        jwks_uri: url,
        kid: typeof jwk.kid === 'string' ? jwk.kid : undefined,
        reason: refusal,
      });
      continue;
    }
    const alg = algorithmOfType(jwk);
    if (alg !== undefined && typeof jwk.kid === 'string') keys.set(jwk.kid, { kid: jwk.kid, alg, jwk });
  }
  return { value: keys, maxAgeMs: maxAgeOf(res.headers.get('cache-control')) };
}
