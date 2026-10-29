import { constantTimeEqual, utf8 } from './bytes.js';
import { ConfigurationError } from './errors.js';

const INSPECT = Symbol.for('nodejs.util.inspect.custom');
const REDACTED = 'Secret(***)';
/**
 * The brand {@link isSecret} reads. A package loaded as both ESM and CommonJS holds two copies of
 * this class, so `instanceof Secret` is false for the other copy's secrets; the brand is shared.
 */
const BRAND = Symbol.for('authfi.secret');

/**
 * A value that must not leave the process by accident: a client secret, a token, an assertion, a
 * private key, a webhook secret.
 *
 * It prints, inspects, stringifies and serialises as a redacted placeholder. The value is in a
 * `#private` field, so `Object.entries`, spread, `JSON.stringify` and `structuredClone` see nothing.
 * {@link Secret.reveal} is the one way to read it, and that name shows up in review.
 *
 * @example
 * const clientSecret = new Secret(process.env.AUTHFI_CLIENT_SECRET ?? '');
 */
export class Secret {
  readonly #value: string;

  constructor(value: string) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new ConfigurationError('a Secret needs a non-empty string value');
    }
    this.#value = value;
  }

  /** The value. Read it only where it goes onto the wire. */
  reveal(): string {
    return this.#value;
  }

  /** Compares with another secret in constant time. */
  equals(other: Secret): boolean {
    return constantTimeEqual(utf8(this.#value), utf8(other.reveal()));
  }

  /** The redacted form. */
  toString(): string {
    return REDACTED;
  }

  /** The redacted form, so `JSON.stringify` never carries the value. */
  toJSON(): { kind: 'secret' } {
    return { kind: 'secret' };
  }

  /** The redacted form for Node's `util.inspect` and `console.log`. */
  [INSPECT](): string {
    return REDACTED;
  }

  /** The brand {@link isSecret} reads. It carries no part of the value. */
  readonly [BRAND] = true;
}

/**
 * Whether `value` is a {@link Secret}, from this copy of the SDK or another (ESM and CommonJS).
 * The SDK checks this, never `instanceof`.
 */
export function isSecret(value: unknown): value is Secret {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<symbol, unknown>)[BRAND] === true &&
    typeof (value as { reveal?: unknown }).reveal === 'function'
  );
}

/** Wraps a string in a {@link Secret}, or passes a Secret through. */
export function toSecret(value: string | Secret): Secret {
  return isSecret(value) ? value : new Secret(value);
}
