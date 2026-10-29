import { base64url, constantTimeEqual, fromBase64urlStrict, fromUtf8, sha256, utf8 } from '../core/bytes.js';
import { DPoPNonceRequired, InvalidToken } from '../core/errors.js';

const MAX_PROOF_BYTES = 8 * 1024;
/** How old a proof's `iat` may be, in seconds. */
export const MAX_AGE_SECONDS = 60;
/** How far ahead of this server's clock a proof's `iat` may be, in seconds. */
export const MAX_FUTURE_SECONDS = 5;
const NONCE_WINDOW_MS = 60 * 1000;
const MAX_JTI_LENGTH = 256;
const MIN_RSA_BITS = 2048;
const PROOF_ALGS = ['EdDSA', 'ES256', 'PS256'] as const;
type ProofAlg = (typeof PROOF_ALGS)[number];
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/** The algorithms a DPoP proof may be signed with, for a `WWW-Authenticate: DPoP algs="…"` challenge. */
export const PROOF_ALGORITHMS: readonly string[] = PROOF_ALGS;

const refuse = (code: string, message: string): InvalidToken => new InvalidToken(code, message);

/**
 * Remembers proof ids so each is used once. `record` answers `true` (new), `false` (already seen) or
 * `'full'` (a cap was reached: the proof is neither accepted nor called a replay). With more than one
 * replica, supply a guard over a shared store.
 */
export interface ReplayGuard {
  /** Records `key` until `expiresAtMs`. */
  record(key: string, expiresAtMs: number): boolean | 'full' | Promise<boolean | 'full'>;
}

/**
 * The default replay guard: bounded, in process memory. One key (a thumbprint) may hold at most
 * `perKeyMax` entries, so one agent cannot fill the guard for all. Expired entries are swept at most
 * once a second.
 */
export function memoryReplayGuard(max: number, now: () => number, perKeyMax = 1000): ReplayGuard {
  const seen = new Map<string, number>();
  const perKey = new Map<string, number>();
  let nextSweep = 0;
  const thumbOf = (k: string): string => k.slice(0, k.indexOf(':'));
  const drop = (k: string): void => {
    seen.delete(k);
    const th = thumbOf(k);
    const n = (perKey.get(th) ?? 1) - 1;
    if (n <= 0) perKey.delete(th);
    else perKey.set(th, n);
  };
  return {
    record(key, expiresAtMs) {
      const t = now();
      if (t >= nextSweep) {
        for (const [k, exp] of seen) if (exp <= t) drop(k);
        nextSweep = t + 1000;
      }
      if (seen.has(key)) return false;
      const th = thumbOf(key);
      if (seen.size >= max || (perKey.get(th) ?? 0) >= perKeyMax) return 'full';
      seen.set(key, expiresAtMs);
      perKey.set(th, (perKey.get(th) ?? 0) + 1);
      return true;
    },
  };
}

/** Issues and checks server nonces (RFC 9449 §8): an HMAC of the current minute, valid for two minutes. */
export class NonceIssuer {
  readonly #secret: Uint8Array<ArrayBuffer>;
  #key: Promise<CryptoKey> | undefined;

  constructor(secret: Uint8Array<ArrayBuffer>) {
    this.#secret = secret;
  }

  async #nonceFor(window: number): Promise<string> {
    this.#key ??= crypto.subtle.importKey('raw', this.#secret, { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ]);
    const mac = await crypto.subtle.sign(
      'HMAC',
      await this.#key,
      utf8(`authfi-dpop-nonce-v1:${String(window)}`),
    );
    return base64url(new Uint8Array(mac).subarray(0, 16));
  }

  /** The nonce to hand out now. */
  current(nowMs: number): Promise<string> {
    return this.#nonceFor(Math.floor(nowMs / NONCE_WINDOW_MS));
  }

  /** Whether `given` is the current nonce or the one before it. */
  async valid(nowMs: number, given: unknown): Promise<boolean> {
    if (typeof given !== 'string') return false;
    const w = Math.floor(nowMs / NONCE_WINDOW_MS);
    const got = utf8(given);
    let ok = false;
    for (const win of [w, w - 1]) {
      if (constantTimeEqual(utf8(await this.#nonceFor(win)), got)) ok = true;
    }
    return ok;
  }
}

/** What proof checking needs beyond the request: where this server is, the nonce issuer, the replay guard. */
export interface ProofConfig {
  /** The origin clients call, from the `publicUrl` option; wins over forwarded headers. */
  readonly publicOrigin: string | undefined;
  /** Whether to take the origin from `X-Forwarded-Proto` and `-Host` when no `publicOrigin` is set. */
  readonly trustForwarded: boolean;
  readonly nonces: NonceIssuer | undefined;
  readonly guard: ReplayGuard;
}

/** The parts of a request a proof is checked against. */
export interface ProofRequest {
  /** The `DPoP` header value; several proofs arrive comma-joined. */
  readonly dpop?: string | null | undefined;
  /** How many `DPoP` headers the request carried, when the adapter knows (more than one is refused). */
  readonly headerCounts?: { readonly dpop?: number } | undefined;
  readonly method?: string | undefined;
  /** The request target: a path with an optional query, or a full URL. */
  readonly url?: string | undefined;
  /** The raw `X-Forwarded-Proto` and `X-Forwarded-Host` values, read only with `trustForwarded`. */
  readonly forwarded?:
    { readonly proto?: string | undefined; readonly host?: string | undefined } | undefined;
}

function strictJson(segment: string): Record<string, unknown> | undefined {
  const bytes = fromBase64urlStrict(segment);
  if (bytes === undefined) return undefined;
  try {
    const value: unknown = JSON.parse(fromUtf8(bytes));
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function bitsOf(n: unknown): number {
  const bytes = typeof n === 'string' ? fromBase64urlStrict(n) : undefined;
  if (bytes === undefined) return 0;
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  return (bytes.length - i) * 8;
}

interface ProofKey {
  readonly key: CryptoKey;
  readonly thumbprint: string;
}

/**
 * Imports the proof's embedded public key, binding `kty` and `crv` to the algorithm, and returns it
 * with its RFC 7638 thumbprint. A key with a private member, or an RSA key under 2048 bits, is refused.
 */
async function importProofKey(alg: ProofAlg, jwk: unknown): Promise<ProofKey> {
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk))
    throw refuse('dpop_proof_key_invalid', 'the proof has no embedded key');
  const j = jwk as Record<string, unknown>;
  if (PRIVATE_MEMBERS.some((m) => j[m] !== undefined))
    throw refuse('dpop_proof_key_invalid', 'the embedded key is not a public key');
  let material: Record<string, string>;
  let algorithm: Parameters<SubtleCrypto['importKey']>[2];
  const text = (v: unknown): string => (typeof v === 'string' ? v : '');
  if (alg === 'EdDSA') {
    if (j.kty !== 'OKP' || j.crv !== 'Ed25519')
      throw refuse('dpop_proof_alg_mismatch', 'the algorithm does not fit the embedded key');
    // RFC 7638 orders the members alphabetically: crv, kty, x.
    material = { crv: 'Ed25519', kty: 'OKP', x: text(j.x) };
    algorithm = { name: 'Ed25519' };
  } else if (alg === 'ES256') {
    if (j.kty !== 'EC' || j.crv !== 'P-256')
      throw refuse('dpop_proof_alg_mismatch', 'the algorithm does not fit the embedded key');
    material = { crv: 'P-256', kty: 'EC', x: text(j.x), y: text(j.y) };
    algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  } else {
    if (j.kty !== 'RSA')
      throw refuse('dpop_proof_alg_mismatch', 'the algorithm does not fit the embedded key');
    material = { e: text(j.e), kty: 'RSA', n: text(j.n) };
    algorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
    if (bitsOf(j.n) < MIN_RSA_BITS)
      throw refuse('dpop_proof_alg_mismatch', 'the embedded RSA key is too small');
  }
  const coordinates = Object.entries(material).filter(([k]) => k !== 'kty' && k !== 'crv');
  if (coordinates.some(([, v]) => fromBase64urlStrict(v) === undefined))
    throw refuse('dpop_proof_key_invalid', 'the embedded key is not valid');
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('jwk', material as JsonWebKey, algorithm, false, ['verify']);
  } catch {
    throw refuse('dpop_proof_key_invalid', 'the embedded key is not valid');
  }
  const thumbprint = base64url(await sha256(utf8(JSON.stringify(material))));
  return { key, thumbprint };
}

async function proofSignatureValid(
  alg: ProofAlg,
  key: CryptoKey,
  signed: string,
  signature: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const algorithm =
    alg === 'EdDSA'
      ? { name: 'Ed25519' }
      : alg === 'ES256'
        ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSA-PSS', saltLength: 32 };
  try {
    return await crypto.subtle.verify(algorithm, key, signature, utf8(signed));
  } catch {
    return false;
  }
}

const HTU = /^(https?:\/\/[^/?#\s]+)(\/[^?#\s]*)?$/i;

function lastEntry(value: string | undefined): string {
  return value === undefined ? '' : (value.split(',').pop() ?? '').trim();
}

/**
 * The request's own public URL as `[origin, path]`. The origin comes from the configured
 * `publicOrigin`, or from the forwarding headers only when `trustForwarded` is set and no origin is
 * configured. The `Host` header is never used: a client sets it.
 */
function expectedUrl(req: ProofRequest, cfg: ProofConfig): [string, string] {
  let origin = cfg.publicOrigin;
  // A configured origin always wins. Forwarded headers are used only without one, and then the LAST
  // entry counts: it is what the trusted proxy appended; the earlier ones came from the client.
  if (origin === undefined && cfg.trustForwarded) {
    const proto = lastEntry(req.forwarded?.proto).toLowerCase();
    const host = lastEntry(req.forwarded?.host);
    if (proto !== '' && host !== '') {
      if (!['http', 'https'].includes(proto) || !/^[A-Za-z0-9.\-:[\]]+$/.test(host))
        throw refuse('dpop_proof_htu_mismatch', 'the forwarded address is not valid');
      try {
        origin = new URL(`${proto}://${host}`).origin;
      } catch {
        throw refuse('dpop_proof_htu_mismatch', 'the forwarded address is not valid');
      }
    }
  }
  if (origin === undefined)
    throw refuse('dpop_proof_htu_mismatch', 'the public address of this server is not known');
  let target = req.url ?? '';
  if (/^https?:\/\//i.test(target)) {
    try {
      target = new URL(target).pathname;
    } catch {
      throw refuse('dpop_proof_htu_mismatch', 'the request target is not valid');
    }
  }
  const path = target.replace(/[?#][\s\S]*$/, '');
  if (!path.startsWith('/') || path.startsWith('//'))
    throw refuse('dpop_proof_htu_mismatch', 'the request target is not an absolute path');
  return [origin, path];
}

function matchesHtu(htu: unknown, [origin, path]: [string, string]): boolean {
  if (typeof htu !== 'string') return false;
  const m = HTU.exec(htu);
  if (m?.[1] === undefined) return false;
  let o: string;
  try {
    o = new URL(m[1]).origin;
  } catch {
    return false;
  }
  return o === origin && (m[2] ?? '/') === path;
}

/** What the replay guard records once the whole request is accepted. */
export interface ValidProof {
  readonly thumbprint: string;
  readonly jti: string;
  readonly iat: number;
}

/**
 * Checks a DPoP proof (RFC 9449) for an access token: exactly one proof; `typ dpop+jwt`; EdDSA,
 * ES256 or PS256 bound to the embedded key's type; a valid signature; `jti`; `htm` and `htu` equal to
 * this request; `iat` fresh; `ath` the token's hash; the key's RFC 7638 thumbprint equal to `jkt`;
 * and, when nonces are on, a current server nonce. It records nothing: the caller records the `jti`
 * only after every other check has passed.
 */
export async function validateProof(
  req: ProofRequest,
  token: string,
  jkt: string,
  cfg: ProofConfig,
  nowMs: number,
): Promise<ValidProof> {
  const proof = req.dpop ?? '';
  const count = Math.max(req.headerCounts?.dpop ?? 0, proof === '' ? 0 : proof.includes(',') ? 2 : 1);
  if (count === 0) throw refuse('dpop_proof_missing', 'a DPoP proof is required');
  if (count > 1) throw refuse('dpop_proof_multiple', 'exactly one DPoP proof is allowed');
  if (proof.length > MAX_PROOF_BYTES) throw refuse('dpop_proof_malformed', 'the proof is too large');
  const parts = proof.split('.');
  const [head, body, tail] = parts;
  if (parts.length !== 3 || head === undefined || body === undefined || tail === undefined)
    throw refuse('dpop_proof_malformed', 'a proof is three dot-separated parts');

  const header = strictJson(head);
  if (header === undefined) throw refuse('dpop_proof_malformed', 'the proof header is not valid');
  if (header.typ !== 'dpop+jwt') throw refuse('dpop_proof_type_invalid', 'the proof typ must be dpop+jwt');
  if (header.crit !== undefined)
    throw refuse('dpop_proof_malformed', 'the proof carries critical header extensions');
  const alg = PROOF_ALGS.find((a) => a === header.alg);
  if (alg === undefined) throw refuse('dpop_proof_alg_mismatch', 'the proof algorithm is not accepted');
  const { key, thumbprint } = await importProofKey(alg, header.jwk);

  const signature = fromBase64urlStrict(tail);
  if (signature === undefined) throw refuse('dpop_proof_malformed', 'the proof signature is not valid');
  if (!(await proofSignatureValid(alg, key, `${head}.${body}`, signature)))
    throw refuse('dpop_proof_signature_invalid', 'the proof signature does not verify');

  const claims = strictJson(body);
  if (claims === undefined) throw refuse('dpop_proof_malformed', 'the proof payload is not valid');
  const { jti } = claims;
  if (typeof jti !== 'string' || jti === '' || jti.length > MAX_JTI_LENGTH)
    throw refuse('dpop_proof_jti_missing', 'the proof has no usable jti');
  if (claims.htm !== req.method)
    throw refuse('dpop_proof_htm_mismatch', 'the proof is for another HTTP method');
  if (!matchesHtu(claims.htu, expectedUrl(req, cfg)))
    throw refuse('dpop_proof_htu_mismatch', 'the proof is for another URL');
  const { iat } = claims;
  if (typeof iat !== 'number' || !Number.isFinite(iat))
    throw refuse('dpop_proof_iat_invalid', 'the proof has no issue time');
  const age = nowMs / 1000 - iat;
  if (age > MAX_AGE_SECONDS || age < -MAX_FUTURE_SECONDS)
    throw refuse('dpop_proof_iat_invalid', 'the proof is not fresh');
  if (typeof claims.ath !== 'string' || claims.ath !== base64url(await sha256(utf8(token))))
    throw refuse('dpop_proof_ath_mismatch', 'the proof is not for this access token');
  if (thumbprint !== jkt)
    throw refuse('dpop_proof_key_mismatch', 'the proof key is not the key the token is bound to');
  if (cfg.nonces !== undefined && !(await cfg.nonces.valid(nowMs, claims.nonce)))
    throw new DPoPNonceRequired(await cfg.nonces.current(nowMs), 'a current server nonce is required');
  return { thumbprint, jti, iat };
}
