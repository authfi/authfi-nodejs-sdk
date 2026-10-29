// Byte helpers on Web APIs only (no Buffer), so the core runs in Node, edge runtimes and browsers.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/** UTF-8 bytes of a string. */
export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(s);
}

/** A string from UTF-8 bytes; throws on invalid UTF-8. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** `n` cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 with padding (RFC 4648 §4), as HTTP Basic needs. */
export function base64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out +=
      B64.charAt((n >> 18) & 63) +
      B64.charAt((n >> 12) & 63) +
      B64.charAt((n >> 6) & 63) +
      B64.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += `${B64.charAt((n >> 18) & 63)}${B64.charAt((n >> 12) & 63)}==`;
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += `${B64.charAt((n >> 18) & 63)}${B64.charAt((n >> 12) & 63)}${B64.charAt((n >> 6) & 63)}=`;
  }
  return out;
}

/** base64url without padding (RFC 4648 §5), as JOSE uses. */
export function base64url(bytes: Uint8Array): string {
  return base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url without padding; throws on any character outside the alphabet. */
export function fromBase64url(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new TypeError('not base64url');
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const out = new Uint8Array(Math.floor((std.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of std) {
    value = (value << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

/** Compares two byte strings in time that depends only on their lengths. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** SHA-256 of bytes, through Web Crypto. */
export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Decodes standard base64 with padding, or returns undefined unless the input is exactly the
 * canonical encoding of what it decodes to (no whitespace, no stray bits, no other alphabet).
 */
export function fromBase64(s: string): Uint8Array<ArrayBuffer> | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return undefined;
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return base64(out) === s ? out : undefined;
}

/** Decodes base64url, or returns undefined unless the input is the canonical encoding of what it decodes to. */
export function fromBase64urlStrict(s: string): Uint8Array<ArrayBuffer> | undefined {
  try {
    const out = fromBase64url(s);
    return base64url(out) === s ? out : undefined;
  } catch {
    return undefined;
  }
}
