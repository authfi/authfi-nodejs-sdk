import {
  calculateJwkThumbprint,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importJWK,
  importPKCS8,
  type JWK,
} from 'jose';
import { fromBase64url } from '../core/bytes.js';
import { ConfigurationError } from '../core/errors.js';
import { Secret } from '../core/secret.js';

/** The algorithms an agent key signs with. The key type decides: Ed25519, P-256 or RSA (PSS). */
export type AgentAlgorithm = 'EdDSA' | 'ES256' | 'PS256';

/**
 * Something that signs as the agent: a key file today; a cloud KMS, PKCS#11 or TPM later. The
 * private key never needs to leave it.
 */
export interface Signer {
  /** The key id registered with the public key. */
  readonly kid: string;
  readonly alg: AgentAlgorithm;
  /** Signs bytes; the signature is in the JWS form for `alg`. */
  sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>;
  /** The public key, to register in the console. Never carries a private member. */
  publicJwk(): JsonWebKey;
}

const PUBLIC_MEMBERS = ['kty', 'crv', 'x', 'y', 'n', 'e'] as const;
const RSA_BITS = 3072;
const MIN_RSA_BITS = 2048;
const MAX_RSA_BITS = 4096;
/** Exports a generated key for `writeAgentKey`. Not part of the public API. */
export const EXPORT_PKCS8 = Symbol.for('authfi.agentKey.exportPkcs8');

const SIGN_PARAMS: Record<AgentAlgorithm, AlgorithmIdentifier | RsaPssParams | EcdsaParams> = {
  EdDSA: { name: 'Ed25519' },
  ES256: { name: 'ECDSA', hash: 'SHA-256' },
  PS256: { name: 'RSA-PSS', saltLength: 32 },
};

function publicOf(
  jwk: JWK,
  kid: string,
  alg: AgentAlgorithm,
): JsonWebKey & { kid: string; alg: string; use: string } {
  const out: Record<string, string> = {};
  for (const m of PUBLIC_MEMBERS) {
    const v = (jwk as Record<string, unknown>)[m];
    if (typeof v === 'string') out[m] = v;
  }
  return { ...out, kid, alg, use: 'sig' };
}

/** The algorithm a key's type implies, checked as the platform checks a registered key. */
function algorithmOf(jwk: JWK): AgentAlgorithm {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'EC') {
    if (jwk.crv !== 'P-256')
      throw new ConfigurationError(`an EC agent key must be P-256, not ${jwk.crv ?? 'unknown'}`);
    return 'ES256';
  }
  if (jwk.kty === 'RSA') {
    const bits = (() => {
      try {
        const n = fromBase64url(jwk.n ?? '');
        let i = 0;
        while (i < n.length && n[i] === 0) i++;
        return (n.length - i) * 8;
      } catch {
        return 0;
      }
    })();
    if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) {
      throw new ConfigurationError(`an RSA agent key must be 2048 to 4096 bits, not ${bits}`);
    }
    if (jwk.e !== 'AQAB') throw new ConfigurationError('an RSA agent key must use the public exponent 65537');
    return 'PS256';
  }
  throw new ConfigurationError(`an agent key must be Ed25519, P-256 or RSA, not ${jwk.kty ?? 'unknown'}`);
}

// PKCS#8 algorithm identifiers, as DER: the OID tag, length and value.
const OID = {
  ed25519: [0x06, 0x03, 0x2b, 0x65, 0x70],
  ecPublicKey: [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
  rsaEncryption: [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
  rsaPss: [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
};

function contains(haystack: Uint8Array, needle: readonly number[]): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

function pemAlgorithm(pem: string): AgentAlgorithm {
  const label = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(pem)?.[1];
  if (label === 'ENCRYPTED PRIVATE KEY')
    throw new ConfigurationError('an encrypted private key is not supported: decrypt it into a 0600 file');
  if (label === 'EC PRIVATE KEY' || label === 'RSA PRIVATE KEY') {
    throw new ConfigurationError(
      `the agent key is a ${label}; convert it to PKCS#8 with: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.p8.pem`,
    );
  }
  if (label !== 'PRIVATE KEY') {
    throw new ConfigurationError(
      label === undefined
        ? 'the agent key is not a PEM private key'
        : `the agent key must be a PKCS#8 PRIVATE KEY, not a ${label}`,
    );
  }
  const body = pem.replace(/-----[A-Z0-9 ]+-----/g, '').replace(/\s+/g, '');
  let der: Uint8Array;
  try {
    der = fromBase64url(body.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  } catch {
    throw new ConfigurationError('the agent key PEM is not valid base64');
  }
  if (contains(der, OID.ed25519)) return 'EdDSA';
  if (contains(der, OID.ecPublicKey)) return 'ES256';
  if (contains(der, OID.rsaEncryption) || contains(der, OID.rsaPss)) return 'PS256';
  throw new ConfigurationError('the agent key must be Ed25519, P-256 or RSA');
}

/**
 * An agent's signing key: Ed25519 (EdDSA, the default), P-256 (ES256) or RSA (PS256, 3072 bits when
 * generated). The private key is held as a non-extractable Web Crypto key; no method returns it as a
 * value. `writeAgentKey` in `@authfi/sdk/node` writes a generated key to a 0600 file, once.
 *
 * Register the public half in the console (`publicJwk()`, `thumbprint()`). The SDK never uploads a
 * private key.
 */
export class AgentKey implements Signer {
  readonly kid: string;
  readonly alg: AgentAlgorithm;
  readonly #privateKey: CryptoKey;
  readonly #publicJwk: JsonWebKey & { kid: string; alg: string; use: string };
  readonly #exportable: CryptoKey | undefined;

  private constructor(
    privateKey: CryptoKey,
    publicJwk: JWK,
    kid: string,
    alg: AgentAlgorithm,
    exportable?: CryptoKey,
  ) {
    if (typeof kid !== 'string' || kid.trim() === '')
      throw new ConfigurationError('kid is required: the key id registered with the public key');
    this.kid = kid.trim();
    this.alg = alg;
    this.#privateKey = privateKey;
    this.#publicJwk = publicOf(publicJwk, this.kid, alg);
    this.#exportable = exportable;
  }

  /** Generates a key. Its kid defaults to the RFC 7638 thumbprint of the public key. */
  static async generate(alg: AgentAlgorithm = 'EdDSA', options: { kid?: string } = {}): Promise<AgentKey> {
    if (!(alg in SIGN_PARAMS))
      throw new ConfigurationError(`cannot generate ${alg}: use EdDSA, ES256 or PS256`);
    const pair =
      alg === 'EdDSA'
        ? await generateKeyPair('Ed25519', { extractable: true })
        : await generateKeyPair(alg, { extractable: true, modulusLength: RSA_BITS });
    const pub = await exportJWK(pair.publicKey);
    const kid = options.kid ?? (await calculateJwkThumbprint(pub, 'sha256'));
    return new AgentKey(pair.privateKey, pub, kid, alg, pair.privateKey);
  }

  /** Loads a PKCS#8 PEM private key. The kid is the one registered with its public key. */
  static async fromPem(pem: string | Secret, options: { kid: string }): Promise<AgentKey> {
    const text = pem instanceof Secret ? pem.reveal() : pem;
    if (typeof text !== 'string') throw new ConfigurationError('the agent key PEM must be a string');
    const alg = pemAlgorithm(text);
    let full: JWK;
    try {
      full = await exportJWK(await importPKCS8(text, alg, { extractable: true }));
    } catch (e) {
      throw new ConfigurationError(
        `the agent key is not a usable ${alg} private key: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    return AgentKey.#fromFullJwk(full, alg, options.kid);
  }

  /** Loads a private JWK. Its own `kid` is used unless one is given. */
  static async fromJwk(
    jwk: JsonWebKey & { kid?: string },
    options: { kid?: string } = {},
  ): Promise<AgentKey> {
    if (typeof jwk !== 'object' || typeof jwk.d !== 'string') {
      throw new ConfigurationError(
        'this JWK has no private member: signing needs the private key the agent holds',
      );
    }
    const alg = algorithmOf(jwk);
    return AgentKey.#fromFullJwk(jwk, alg, options.kid ?? jwk.kid ?? '');
  }

  static async #fromFullJwk(full: JWK, alg: AgentAlgorithm, kid: string): Promise<AgentKey> {
    algorithmOf(full);
    const privateKey = (await importJWK({ ...full, alg }, alg, { extractable: false })) as CryptoKey;
    return new AgentKey(privateKey, full, kid, alg);
  }

  /** The public JWK to register in the console: `kid`, `alg`, `use` and the public members only. */
  publicJwk(): JsonWebKey & { kid: string; alg: string; use: string } {
    return { ...this.#publicJwk };
  }

  /** The RFC 7638 thumbprint of the public key. */
  thumbprint(): Promise<string> {
    return calculateJwkThumbprint(this.#publicJwk, 'sha256');
  }

  /** Signs bytes with the key. */
  async sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    return new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS[this.alg], this.#privateKey, data));
  }

  /** A generated key's PKCS#8 PEM, for `writeAgentKey` only. A loaded key is already in a file. */
  async [EXPORT_PKCS8](): Promise<Secret> {
    if (this.#exportable === undefined) {
      throw new ConfigurationError(
        'only a key made by AgentKey.generate() can be written; this one was loaded and is already stored',
      );
    }
    return new Secret(await exportPKCS8(this.#exportable));
  }

  /** The kid and algorithm only. */
  toString(): string {
    return `AgentKey(${this.alg} ${this.kid})`;
  }

  toJSON(): { kid: string; alg: string } {
    return { kid: this.kid, alg: this.alg };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
