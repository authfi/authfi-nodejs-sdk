import { ConfigurationError } from './errors.js';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

function parse(value: string, what: string): URL {
  if (typeof value !== 'string' || value.trim() === '') throw new ConfigurationError(`${what} is required`);
  try {
    return new URL(value);
  } catch {
    throw new ConfigurationError(`${what} ${JSON.stringify(value)} is not a URL`);
  }
}

/** Whether a URL's host is the loopback interface, where plain http is allowed. */
export function isLoopback(url: URL): boolean {
  return LOOPBACK.has(url.hostname);
}

/** Refuses a URL that is not `https`, or `http` to loopback; the one rule for every address the SDK sends to. */
export function requireSecureScheme(url: URL, what: string, value: string): void {
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:' && isLoopback(url)) return;
  throw new ConfigurationError(`${what} ${value} must be https (plain http is allowed for loopback only)`);
}

/**
 * Checks an issuer: `https` (or loopback `http`), no credentials, query, fragment or trailing slash.
 * Returns it unchanged, because the discovery document must name exactly this string (RFC 8414 §3.3).
 */
export function checkIssuer(value: string): string {
  const url = parse(value, 'issuer');
  requireSecureScheme(url, 'issuer', value);
  if (url.username || url.password)
    throw new ConfigurationError(`issuer ${value} must not carry credentials`);
  if (url.search || url.hash || value.includes('?') || value.includes('#')) {
    throw new ConfigurationError(`issuer ${value} must not carry a query or fragment`);
  }
  if (value.endsWith('/')) {
    throw new ConfigurationError(
      `issuer ${value} must not end with a slash: use ${value.replace(/\/+$/, '')}`,
    );
  }
  return value;
}

/**
 * Checks an exact origin (scheme, host and port; no path, query or fragment) and returns its
 * normal form. Used for `apiOrigin` and every `sendTo` value.
 */
export function checkOrigin(value: string, what: string): string {
  const url = parse(value, what);
  requireSecureScheme(url, what, value);
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new ConfigurationError(
      `${what} ${value} must be an origin only (scheme, host and port), such as ${url.origin}`,
    );
  }
  return url.origin;
}

/** The origin of a URL string, or undefined when it does not parse. */
export function originOf(value: string | URL): string | undefined {
  try {
    return new URL(value).origin;
  } catch {
    return undefined;
  }
}

/** Whether `url` is `base` or a URL under it (path-segment aware). */
export function isAtOrUnder(url: string, base: string): boolean {
  if (url === base) return true;
  const b = base.endsWith('/') ? base : `${base}/`;
  return url.startsWith(b);
}
