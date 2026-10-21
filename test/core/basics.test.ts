import fc from 'fast-check';
import { inspect } from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import { base64, base64url, constantTimeEqual, fromBase64url, utf8 } from '../../src/core/bytes.js';
import { raceSignal, SingleFlight, maxAgeOf, CachedDocument } from '../../src/core/cache.js';
import { KERNEL_TOKEN_CODES } from '../../src/core/codes.js';
import {
  AuthFIError,
  ConfigurationError,
  ConsentDenied,
  InsufficientPermission,
  InvalidToken,
  isAuthFIError,
  OAuthError,
  StepUpRequired,
  TransportError,
} from '../../src/core/errors.js';
import {
  freshTraceparent,
  idempotencyKey,
  isValidRequestId,
  requestId,
  traceIdOf,
} from '../../src/core/ids.js';
import { redact, redactingLogger, type Logger } from '../../src/core/logger.js';
import { isSecret, Secret, toSecret } from '../../src/core/secret.js';
import { MemoryTokenStore, TokenSet } from '../../src/core/token-set.js';
import { checkIssuer, checkOrigin, isAtOrUnder, originOf } from '../../src/core/urls.js';
import { TestClock } from '../support/issuer.js';

const MARKER = 'sk-MARKER-7f3a9c';

/** Every way a value could leave the process by accident (design §6.1, the secret-leak suite). */
function exposures(value: unknown): string[] {
  const out = [
    inspect(value, { depth: 10, showHidden: true }),
    String(value),
    String(value),
    JSON.stringify(value),
  ];
  out.push(JSON.stringify(Object.entries(value as object)));
  out.push(JSON.stringify({ ...(value as object) }));
  try {
    out.push(inspect(structuredClone(value), { depth: 10 }));
  } catch (e) {
    out.push(String(e));
  }
  return out;
}

describe('Secret', () => {
  it('never shows its value', () => {
    const s = new Secret(MARKER);
    for (const text of exposures(s)) expect(text).not.toContain(MARKER);
    expect(s.reveal()).toBe(MARKER);
  });

  it('refuses an empty value', () => {
    expect(() => new Secret('')).toThrow(ConfigurationError);
  });

  it('compares in constant time', () => {
    expect(new Secret('abc').equals(new Secret('abc'))).toBe(true);
    expect(new Secret('abc').equals(new Secret('abd'))).toBe(false);
    expect(new Secret('abc').equals(new Secret('abcd'))).toBe(false);
  });

  it("is recognised by its brand, so another copy of the SDK's Secret passes", () => {
    const s = new Secret('x');
    expect(isSecret(s)).toBe(true);
    // A Secret from the other build (ESM beside CommonJS) is another class with the same brand.
    const otherCopy: unknown = { [Symbol.for('authfi.secret')]: true, reveal: () => 'x' };
    expect(otherCopy instanceof Secret).toBe(false);
    expect(isSecret(otherCopy)).toBe(true);
    expect(toSecret(otherCopy as Secret)).toBe(otherCopy);
    expect(isSecret({ reveal: () => 'x' })).toBe(false);
    expect(isSecret('x')).toBe(false);
    expect(isSecret(null)).toBe(false);
  });

  it('wraps a string and passes a Secret through', () => {
    const s = new Secret('x');
    expect(toSecret(s)).toBe(s);
    expect(toSecret('y').reveal()).toBe('y');
  });
});

describe('TokenSet', () => {
  const set = new TokenSet({
    accessToken: new Secret(`${MARKER}-a`),
    refreshToken: new Secret(`${MARKER}-r`),
    idToken: new Secret(`${MARKER}-i`),
    expiresAt: new Date('2026-10-20T12:15:00Z'),
    scope: ['openid'],
  });

  it('never shows a token', () => {
    for (const text of exposures(set)) expect(text).not.toContain(MARKER);
    expect(JSON.parse(JSON.stringify(set))).toEqual({
      kind: 'token_set',
      expires_at: '2026-10-20T12:15:00.000Z',
    });
  });

  it('round-trips through storage', () => {
    const back = TokenSet.fromStorage(set.revealForStorage());
    expect(back.accessToken.reveal()).toBe(`${MARKER}-a`);
    expect(back.refreshToken?.reveal()).toBe(`${MARKER}-r`);
    expect(back.expiresAt.getTime()).toBe(set.expiresAt.getTime());
    expect(back.expiresWithin(60_000, Date.parse('2026-10-20T12:14:30Z'))).toBe(true);
    expect(back.expiresWithin(60_000, Date.parse('2026-10-20T12:00:00Z'))).toBe(false);
  });

  it('a memory store writes only over the set it expected', async () => {
    const store = new MemoryTokenStore();
    expect(await store.compareAndSet('k', undefined, set)).toBe(true);
    const next = new TokenSet({
      accessToken: new Secret('a2'),
      refreshToken: new Secret('r2'),
      expiresAt: new Date(),
    });
    expect(await store.compareAndSet('k', undefined, next)).toBe(false);
    expect(await store.compareAndSet('k', TokenSet.fromStorage(set.revealForStorage()), next)).toBe(true);
    expect(await store.compareAndSet('k', set, next)).toBe(false);
    expect((await store.load('k'))?.accessToken.reveal()).toBe('a2');
    await store.delete('k');
    expect(await store.load('k')).toBeUndefined();
  });
});

describe('errors', () => {
  it('brands every error so a dual-package copy is still recognised', () => {
    const e = new InsufficientPermission(['a'], 'no');
    expect(isAuthFIError(e)).toBe(true);
    expect(isAuthFIError(e, 'InvalidToken')).toBe(true);
    expect(isAuthFIError(e, 'InsufficientPermission')).toBe(true);
    expect(isAuthFIError(e, 'OAuthError')).toBe(false);
    expect(isAuthFIError(new Error('x'))).toBe(false);
    expect(isAuthFIError(null)).toBe(false);
    // A copy from the other module format: a plain object with the same brand and name.
    const copy = Object.assign(new Error('x'), {
      name: 'StepUpRequired',
      [Symbol.for('authfi.error')]: true,
    });
    expect(isAuthFIError(copy, 'OAuthError')).toBe(true);
  });

  it('carries names, codes and context', () => {
    const e = new StepUpRequired('needs mfa', {
      status: 401,
      requestId: 'r1',
      acrValues: ['urn:authfi:acr:mfa'],
    });
    expect(e).toBeInstanceOf(OAuthError);
    expect(e).toBeInstanceOf(AuthFIError);
    expect(e.name).toBe('StepUpRequired');
    expect(e.code).toBe('insufficient_user_authentication');
    expect(e.status).toBe(401);
    expect(e.requestId).toBe('r1');
    expect(e.acrValues).toEqual(['urn:authfi:acr:mfa']);
    expect(new ConsentDenied('access_denied', undefined).message).toBe('access_denied');
    expect(new ConfigurationError('bad').status).toBeUndefined();
    expect(new InvalidToken('token_expired', 'expired').code).toBe('token_expired');
    const t = new TransportError('timeout', 't', { retryable: true, cause: new Error('c') });
    expect(t.retryable).toBe(true);
    expect((t.cause as Error).message).toBe('c');
  });

  it('carries the kernel codes of the pinned tag', () => {
    expect(KERNEL_TOKEN_CODES).toContain('token_signature_invalid');
    expect(KERNEL_TOKEN_CODES).toContain('dpop_proof_replayed');
    expect(KERNEL_TOKEN_CODES).not.toContain('token_alg_not_allowed');
  });
});

describe('ids', () => {
  it('request ids stay inside the alphabet the platform keeps', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 50 }), () => {
        const id = requestId();
        return isValidRequestId(id) && /^afr-[0-9A-HJKMNP-TV-Z]{26}$/.test(id);
      }),
    );
  });

  it('the request id check matches the gateway rule', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 140 }), (s) => {
        const expected = s.length >= 1 && s.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(s);
        return isValidRequestId(s) === expected;
      }),
    );
  });

  it('idempotency keys are UUIDv7 and unique', () => {
    const keys = new Set(Array.from({ length: 200 }, () => idempotencyKey()));
    expect(keys.size).toBe(200);
    for (const k of keys)
      expect(k).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('traceparent values parse', () => {
    const tp = freshTraceparent();
    expect(traceIdOf(tp)).toHaveLength(32);
    expect(traceIdOf('nonsense')).toBeUndefined();
    expect(traceIdOf(null)).toBeUndefined();
  });
});

describe('bytes', () => {
  it('base64 and base64url agree with the platform encoders', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        const b64 = btoa(String.fromCharCode(...bytes));
        return (
          base64(bytes) === b64 &&
          base64url(bytes) === b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        );
      }),
    );
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) =>
        constantTimeEqual(fromBase64url(base64url(bytes)), bytes),
      ),
    );
  });

  it('refuses characters outside base64url', () => {
    expect(() => fromBase64url('ab+c')).toThrow();
    expect(() => fromBase64url('a')).toThrow();
  });

  it('compares lengths too', () => {
    expect(constantTimeEqual(utf8('ab'), utf8('abc'))).toBe(false);
  });
});

describe('urls', () => {
  it('accepts an https issuer and loopback http', () => {
    expect(checkIssuer('https://acme.authfi.io')).toBe('https://acme.authfi.io');
    expect(checkIssuer('http://localhost:8080')).toBe('http://localhost:8080');
    expect(checkIssuer('http://127.0.0.1:1')).toBe('http://127.0.0.1:1');
    expect(checkIssuer('http://[::1]:1')).toBe('http://[::1]:1');
  });

  it.each([
    ['', 'required'],
    ['acme', 'not a URL'],
    ['http://acme.authfi.io', 'must be https'],
    ['https://acme.authfi.io/', 'must not end with a slash'],
    ['https://acme.authfi.io?x=1', 'query or fragment'],
    ['https://acme.authfi.io#f', 'query or fragment'],
    ['https://u:p@acme.authfi.io', 'credentials'],
  ])('refuses the issuer %j', (value, why) => {
    expect(() => checkIssuer(value)).toThrow(why);
  });

  it('normalises an exact origin and refuses anything more', () => {
    expect(checkOrigin('https://api.example.com', 'sendTo')).toBe('https://api.example.com');
    expect(checkOrigin('https://api.example.com/', 'sendTo')).toBe('https://api.example.com');
    expect(checkOrigin('https://API.example.com:443', 'sendTo')).toBe('https://api.example.com');
    expect(() => checkOrigin('https://api.example.com/v1', 'sendTo')).toThrow('origin only');
    expect(() => checkOrigin('http://api.example.com', 'sendTo')).toThrow('https');
    expect(() => checkOrigin('https://api.example.com?x', 'sendTo')).toThrow('origin only');
  });

  it('tells a URL under a base', () => {
    expect(isAtOrUnder('https://a.io/mcp', 'https://a.io')).toBe(true);
    expect(isAtOrUnder('https://a.io', 'https://a.io')).toBe(true);
    expect(isAtOrUnder('https://a.iox', 'https://a.io')).toBe(false);
    expect(originOf('not a url')).toBeUndefined();
  });
});

describe('logging', () => {
  it('redacts JWT-shaped values and Bearer credentials in messages and fields', () => {
    const lines: unknown[] = [];
    const inner: Logger = {
      debug: (m, f) => lines.push(m, f),
      info: (m, f) => lines.push(m, f),
      warn: (m, f) => lines.push(m, f),
      error: (m) => lines.push(m),
    };
    const log = redactingLogger(inner);
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    log.warn(`token ${jwt}`, { header: `Bearer ${MARKER}`, nested: { list: [`DPoP ${MARKER}`] } });
    log.error('plain');
    log.debug('d');
    log.info('i', { n: 1 });
    expect(JSON.stringify(lines)).not.toContain(MARKER);
    expect(JSON.stringify(lines)).not.toContain(jwt);
    expect(redact('Bearer abc.def')).toBe('Bearer [redacted]');
  });
});

describe('caches', () => {
  it('SingleFlight shares one call and forgets a failure', async () => {
    const flight = new SingleFlight<string, number>();
    let calls = 0;
    const slow = () =>
      new Promise<number>((r) => {
        calls += 1;
        setTimeout(() => r(calls), 5);
      });
    const [a, b] = await Promise.all([flight.run('k', slow), flight.run('k', slow)]);
    expect([a, b, calls]).toEqual([1, 1, 1]);
    await expect(flight.run('k', () => Promise.reject(new Error('x')))).rejects.toThrow('x');
    expect(await flight.run('k', slow)).toBe(2);
  });

  it("one caller's abort ends that caller's wait and no one else's", async () => {
    const flight = new SingleFlight<string, string>();
    const seen: (AbortSignal | undefined)[] = [];
    let release: (v: string) => void = () => undefined;
    const call = (signal?: AbortSignal) => {
      seen.push(signal);
      return new Promise<string>((r) => {
        release = r;
      });
    };
    const a = new AbortController();
    const first = flight.run('k', () => call(), a.signal);
    const second = flight.run('k', () => call());
    const reason = new Error('caller A gave up');
    a.abort(reason);
    await expect(first).rejects.toBe(reason);
    release('minted');
    expect(await second).toBe('minted');
    expect(seen).toEqual([undefined]); // one call, made with no caller's signal
  });

  it('a caller whose signal is already aborted leaves no unhandled rejection when the shared call fails', async () => {
    const flight = new SingleFlight<string, number>();
    const unhandled: unknown[] = [];
    const onUnhandled = (e: unknown): void => {
      unhandled.push(e);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const gone = flight.run(
        'k',
        () => new Promise<number>((_, rej) => setTimeout(() => rej(new Error('boom')), 5)),
        AbortSignal.abort(new Error('early')),
      );
      await expect(gone).rejects.toThrow('early');
      await new Promise((r) => setTimeout(r, 30));
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('a call that outlives the caller that started it still finishes for the others', async () => {
    const flight = new SingleFlight<string, number>();
    let calls = 0;
    const slow = () =>
      new Promise<number>((r) => {
        calls += 1;
        setTimeout(() => r(calls), 5);
      });
    const a = new AbortController();
    const early = flight.run('k', slow, a.signal);
    const late = flight.run('k', slow);
    a.abort();
    await expect(early).rejects.toBeDefined();
    expect(await late).toBe(1);
    expect(calls).toBe(1);
  });

  it('raceSignal rejects on abort and passes a value through', async () => {
    const c = new AbortController();
    const p = raceSignal(new Promise(() => undefined), c.signal);
    c.abort(new Error('stop'));
    await expect(p).rejects.toThrow('stop');
    expect(await raceSignal(Promise.resolve(3), new AbortController().signal)).toBe(3);
    await expect(raceSignal(Promise.reject(new Error('e')), new AbortController().signal)).rejects.toThrow(
      'e',
    );
    await expect(raceSignal(Promise.resolve(1), AbortSignal.abort(new Error('pre')))).rejects.toThrow('pre');
  });

  it('reads max-age', () => {
    expect(maxAgeOf('public, max-age=300')).toBe(300_000);
    expect(maxAgeOf('no-store')).toBe(0);
    expect(maxAgeOf(null)).toBeUndefined();
    expect(maxAgeOf('public')).toBeUndefined();
  });

  it('keeps a document for its clamped TTL and never caches a failure', async () => {
    const clock = new TestClock();
    let n = 0;
    let fail = false;
    const doc = new CachedDocument(async () => {
      n += 1;
      if (fail) throw new Error('down');
      return { value: n, maxAgeMs: 10 };
    }, clock);
    expect(await doc.get()).toBe(1);
    clock.advance(30_000);
    expect(await doc.get()).toBe(1); // 10 ms is clamped up to 60 s
    clock.advance(31_000);
    fail = true;
    await expect(doc.get()).rejects.toThrow('down');
    fail = false;
    expect(await doc.get()).toBe(3);
    expect(doc.peek()).toBe(3);
    expect(await doc.get({ refresh: true })).toBe(4);
  });
});

describe('the system clock and the console logger', () => {
  it('sleeps, and cancels a sleep', async () => {
    const { systemClock, sleep } = await import('../../src/core/clock.js');
    const before = systemClock.monotonic();
    await systemClock.sleep(5);
    expect(systemClock.monotonic() - before).toBeGreaterThanOrEqual(4);
    expect(Math.abs(systemClock.now() - Date.now())).toBeLessThan(50);
    const c = new AbortController();
    const p = sleep(10_000, c.signal);
    c.abort(new Error('cancelled'));
    await expect(p).rejects.toThrow('cancelled');
    await expect(sleep(1, AbortSignal.abort(new Error('already')))).rejects.toThrow('already');
  });

  it('writes warnings and errors with a prefix, and drops debug and info', async () => {
    const { consoleLogger } = await import('../../src/core/logger.js');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    consoleLogger.warn('w', { a: 1 });
    consoleLogger.warn('w2');
    consoleLogger.error('e', { b: 2 });
    consoleLogger.error('e2');
    consoleLogger.debug('d');
    consoleLogger.info('i');
    expect(warn.mock.calls).toEqual([['[authfi] w', { a: 1 }], ['[authfi] w2']]);
    expect(error.mock.calls).toEqual([['[authfi] e', { b: 2 }], ['[authfi] e2']]);
    warn.mockRestore();
    error.mockRestore();
  });
});
