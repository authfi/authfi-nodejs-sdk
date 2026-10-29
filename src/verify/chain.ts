import { base64url, constantTimeEqual, fromBase64, sha256 } from '../core/bytes.js';
import type { Clock } from '../core/clock.js';
import { InvalidToken } from '../core/errors.js';
import type { UsableKey } from '../core/jwks.js';
import { ecdsaDerToRaw, parseCertificate, signatureOID, spkiAlgorithm, type Certificate } from './der.js';

/**
 * AuthFI Root CA R1, by the SHA-256 of its SubjectPublicKeyInfo. Compiled in: a root is never taken
 * from the key set, the token or the network.
 */
export const DEFAULT_ROOT_PINS: readonly string[] = [
  'b060083465bf0e9239a37f12a5e294a8c219f6b7d81563f4509c984b83ca6332',
];

/** The AuthFI private enterprise number policy arcs: `.1.1` and `.1.2`. */
const PEN_POLICIES = new Set(['1.3.6.1.4.1.67322.1.1', '1.3.6.1.4.1.67322.1.2']);

const MAX_CERTS = 6;
const MAX_CERT_BYTES = 16 * 1024;
const CACHE_MS = 10 * 60 * 1000;
const CACHE_MAX = 256;

const notProven = (message: string): InvalidToken => new InvalidToken('chain_not_proven', message);
const policyError = (message: string): InvalidToken => new InvalidToken('chain_policy', message);
const pinError = (message: string): InvalidToken => new InvalidToken('chain_pin', message);

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function same(a: Uint8Array, b: Uint8Array): boolean {
  return constantTimeEqual(a, b);
}

/** Parses a PEM certificate bundle to certificates; throws `RangeError` for text that holds none. */
export function certificatesFromPem(pem: string): Certificate[] {
  const blocks = [
    ...pem.matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----/g),
  ];
  if (blocks.length === 0) throw new RangeError('no certificate in the PEM');
  return blocks.map((m) => {
    const der = fromBase64((m[1] ?? '').replace(/\s+/g, ''));
    if (der === undefined) throw new RangeError('the PEM body is not base64');
    return parseCertificate(der);
  });
}

const HASHES: Readonly<Record<string, string>> = {
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.113549.1.1.11': 'SHA-256',
  '1.2.840.113549.1.1.12': 'SHA-384',
  '1.2.840.113549.1.1.13': 'SHA-512',
};
const CURVES: Readonly<Record<string, { name: string; size: number }>> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
  '1.3.132.0.34': { name: 'P-384', size: 48 },
};

/** Whether `cert`'s signature verifies under `issuer`'s key. Anything the SDK does not understand is false. */
async function signedBy(cert: Certificate, issuer: Certificate): Promise<boolean> {
  try {
    const oid = signatureOID(cert.signatureAlgorithm);
    const key = spkiAlgorithm(issuer.spki);
    const tbs = cert.tbs as Uint8Array<ArrayBuffer>;
    const sig = cert.signature as Uint8Array<ArrayBuffer>;
    const spki = issuer.spki as Uint8Array<ArrayBuffer>;
    const hash = HASHES[oid];
    if (oid === '1.3.101.112' && key.oid === '1.3.101.112') {
      const k = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, k, sig, tbs);
    }
    if (hash !== undefined && key.oid === '1.2.840.10045.2.1' && oid.startsWith('1.2.840.10045.4.3.')) {
      const curve = CURVES[key.curve];
      if (curve === undefined) return false;
      const k = await crypto.subtle.importKey(
        'spki',
        spki,
        { name: 'ECDSA', namedCurve: curve.name },
        false,
        ['verify'],
      );
      const raw = ecdsaDerToRaw(sig, curve.size);
      return await crypto.subtle.verify({ name: 'ECDSA', hash }, k, raw, tbs);
    }
    if (hash !== undefined && key.oid === '1.2.840.113549.1.1.1' && oid.startsWith('1.2.840.113549.1.1.')) {
      const k = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, [
        'verify',
      ]);
      return await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, k, sig, tbs);
    }
    return false;
  } catch {
    return false;
  }
}

async function selfSigned(cert: Certificate): Promise<boolean> {
  return same(cert.issuer, cert.subject) && (await signedBy(cert, cert));
}

async function issued(cert: Certificate, by: Certificate): Promise<boolean> {
  return same(cert.issuer, by.subject) && (await signedBy(cert, by));
}

const SPKI_OF_KEY = new WeakMap<object, Promise<Uint8Array | undefined>>();

/** The SubjectPublicKeyInfo DER of a published key, or undefined for a key that cannot be imported. */
function spkiOf(key: UsableKey): Promise<Uint8Array | undefined> {
  let spki = SPKI_OF_KEY.get(key);
  if (spki === undefined) {
    spki = spkiOfJwk(key.jwk);
    SPKI_OF_KEY.set(key, spki);
  }
  return spki;
}

async function spkiOfJwk(jwk: Record<string, unknown>): Promise<Uint8Array | undefined> {
  try {
    const kty = jwk.kty;
    let algorithm: Parameters<SubtleCrypto['importKey']>[2];
    let material: JsonWebKey;
    if (kty === 'RSA') {
      algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      material = { kty: 'RSA', n: jwk.n as string, e: jwk.e as string };
    } else if (kty === 'EC') {
      algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
      material = { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string };
    } else if (kty === 'OKP') {
      algorithm = { name: 'Ed25519' };
      material = { kty: 'OKP', crv: 'Ed25519', x: jwk.x as string };
    } else return undefined;
    const key = await crypto.subtle.importKey('jwk', material, algorithm, true, ['verify']);
    return new Uint8Array(await crypto.subtle.exportKey('spki', key));
  } catch {
    return undefined;
  }
}

interface Proven {
  readonly until: number;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly thumbprint: string;
  readonly spki: Uint8Array;
}

/** What a {@link ChainProver} is built from. */
export interface ChainOptions {
  /** Lower-case hex SHA-256 values of the SubjectPublicKeyInfo of the roots to trust. */
  readonly pins: readonly string[];
  /** Roots to complete a chain whose `x5c` does not carry its root; each must still match a pin. */
  readonly roots: readonly Certificate[];
  readonly clock: Clock;
}

/**
 * Shows that the JWKS key a token was verified with is certified by a chain that reaches a pinned
 * AuthFI root with AuthFI's certificate policy. The leaf (`x5c[0]`) must certify the key, the
 * `x5t#S256` of the token header and of the key must be the leaf's thumbprint, every certificate
 * must be valid now and signed by the next, the root must be pinned, and the leaf and every CA
 * between must state the policy. A proven chain is cached, and the cache is re-checked for date and
 * key on every call.
 */
export class ChainProver {
  readonly #pins: ReadonlySet<string>;
  readonly #roots: readonly Certificate[];
  readonly #clock: Clock;
  readonly #cache = new Map<string, Proven>();

  constructor(options: ChainOptions) {
    this.#pins = new Set(options.pins);
    this.#roots = options.roots;
    this.#clock = options.clock;
  }

  /** Throws `InvalidToken` (`chain_not_proven`, `chain_policy` or `chain_pin`) unless the chain proves `key`. */
  async prove(key: UsableKey, headerX5t: unknown): Promise<void> {
    const jwk = key.jwk as Record<string, unknown>;
    const keyX5t = jwk['x5t#S256'];
    const x5c = jwk.x5c;
    if (typeof headerX5t !== 'string' || typeof keyX5t !== 'string')
      throw notProven('the token or its key carries no x5t#S256');
    if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > MAX_CERTS)
      throw notProven('the signing key carries no usable x5c chain');

    const t = this.#clock.now();
    const cacheKey = toHex(await sha256(new TextEncoder().encode(x5c.map(String).join('\n'))));
    const keySpki = await spkiOf(key);
    const hit = this.#cache.get(cacheKey);
    // A cached chain is still checked on every call: in date, and for the same key and thumbprint.
    if (
      hit !== undefined &&
      keySpki !== undefined &&
      t < hit.until &&
      t >= hit.notBefore &&
      t <= hit.notAfter &&
      hit.thumbprint === headerX5t &&
      hit.thumbprint === keyX5t &&
      same(hit.spki, keySpki)
    )
      return;

    const ders = x5c.map((entry): Uint8Array => {
      const der = typeof entry === 'string' ? fromBase64(entry) : undefined;
      if (der === undefined || der.length === 0 || der.length > MAX_CERT_BYTES)
        throw notProven('x5c holds a certificate that is not valid');
      return der;
    });
    let certs: Certificate[];
    try {
      certs = ders.map((d) => parseCertificate(d));
    } catch {
      throw notProven('a certificate in x5c could not be read');
    }
    if (certs.some((c) => c.unknownCritical))
      throw notProven('a certificate carries a critical extension this SDK does not understand');

    // x5c holds at least one certificate, so both exist.
    const leafCert = certs[0] as Certificate;
    const leafDer = ders[0] as Uint8Array;
    const thumbprint = base64url(await sha256(leafDer as Uint8Array<ArrayBuffer>));
    if (thumbprint !== headerX5t || thumbprint !== keyX5t)
      throw notProven('x5t#S256 does not name the leaf certificate');
    if (keySpki === undefined || !same(leafCert.spki, keySpki))
      throw notProven('the leaf certificate does not certify the signing key');

    let notBefore = Number.NEGATIVE_INFINITY;
    let notAfter = Number.POSITIVE_INFINITY;
    for (const c of certs) {
      if (t < c.notBefore || t > c.notAfter) throw notProven('a certificate in the chain is not valid now');
      notBefore = Math.max(notBefore, c.notBefore);
      notAfter = Math.min(notAfter, c.notAfter);
    }

    // Signatures: each certificate is issued by the next; a self-signed one ends the chain.
    let rootIndex = -1;
    for (const [i, cert] of certs.entries()) {
      if (await selfSigned(cert)) {
        if (i === 0 || i !== certs.length - 1) throw notProven('the chain is not leaf-first, root-last');
        rootIndex = i;
        break;
      }
      const next = certs[i + 1];
      if (next !== undefined && !(await issued(cert, next)))
        throw notProven('a certificate is not issued by the next one in x5c');
    }

    let root: Certificate | undefined;
    let caBelowRoot: number;
    if (rootIndex >= 0) {
      root = certs[rootIndex];
      caBelowRoot = rootIndex - 1;
    } else {
      const top = certs[certs.length - 1];
      for (const candidate of this.#roots) {
        if (
          top !== undefined &&
          this.#pins.has(await this.#pinOf(candidate)) &&
          (await issued(top, candidate))
        ) {
          root = candidate;
          break;
        }
      }
      if (root === undefined) throw pinError('the chain does not reach a pinned root');
      if (t < root.notBefore || t > root.notAfter) throw notProven('the root is not valid now');
      notBefore = Math.max(notBefore, root.notBefore);
      notAfter = Math.min(notAfter, root.notAfter);
      caBelowRoot = certs.length - 1;
    }
    if (root === undefined || !this.#pins.has(await this.#pinOf(root)))
      throw pinError('the root of the chain is not pinned');

    // Policy: the leaf, then every CA between the leaf and the root.
    if (leafCert.isCA) throw policyError('the leaf certificate is a CA');
    if (!leafCert.digitalSignature) throw policyError('the leaf certificate is not for digital signatures');
    if (!leafCert.policies.some((p) => PEN_POLICIES.has(p)))
      throw policyError('the leaf certificate states no AuthFI policy');
    const caEnd = rootIndex >= 0 ? rootIndex : certs.length;
    for (let i = 1; i < caEnd; i++) {
      const m = certs[i] as Certificate;
      if (!m.isCA) throw policyError('a certificate between the leaf and the root is not a CA');
      if (m.keyUsage !== null && !m.keyCertSign)
        throw policyError('a CA certificate may not sign certificates');
      if (!m.policies.some((p) => PEN_POLICIES.has(p)))
        throw policyError('a CA certificate states no AuthFI policy');
      if (m.pathLen !== undefined && i - 1 > m.pathLen) throw policyError('a CA path length is exceeded');
    }
    if (root.pathLen !== undefined && caBelowRoot > root.pathLen)
      throw policyError('the root path length is exceeded');

    if (this.#cache.size >= CACHE_MAX) this.#cache.clear();
    this.#cache.set(cacheKey, { until: t + CACHE_MS, notBefore, notAfter, thumbprint, spki: keySpki });
  }

  async #pinOf(cert: Certificate): Promise<string> {
    return toHex(await sha256(cert.spki as Uint8Array<ArrayBuffer>));
  }
}
