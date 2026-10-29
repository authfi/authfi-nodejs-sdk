import { jwtVerify, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { DPoPSigner } from '../../src/core/dpop.js';
import { isAuthFIError } from '../../src/core/errors.js';
import type { Logger } from '../../src/core/logger.js';
import { Secret } from '../../src/core/secret.js';
import { runtimeUserAgent, Transport, type RetryClass } from '../../src/core/transport.js';
import { FakeFetch, hang, json, networkError } from '../support/fake-fetch.js';
import { TestClock } from '../support/issuer.js';

const URL1 = 'https://acme.authfi.io/oauth/token';

function logger(): Logger & { warns: string[]; debugs: string[] } {
  const warns: string[] = [];
  const debugs: string[] = [];
  return {
    warns,
    debugs,
    debug: (m) => debugs.push(m),
    info: () => undefined,
    warn: (m) => warns.push(m),
    error: () => undefined,
  };
}

function transport(fake: FakeFetch, overrides: Partial<ConstructorParameters<typeof Transport>[0]> = {}) {
  const log = logger();
  const clock = new TestClock();
  const t = new Transport({
    fetch: fake.fetch,
    attemptMs: 15_000,
    totalMs: 30_000,
    retries: 2,
    logger: log,
    clock,
    userAgent: 'authfi-node/test (node 22)',
    browser: false,
    otel: undefined,
    ...overrides,
  });
  return { t, log, clock };
}

type Scenario = 'refused' | 'reset' | '429' | '503-retry-after' | '503' | '502';

function answer(scenario: Scenario): Response | Promise<Response> {
  switch (scenario) {
    case 'refused':
    case 'reset':
      return networkError();
    case '429':
      return json({ error: 'rate_limited' }, 429, { 'retry-after': '1' });
    case '503-retry-after':
      return json({ error: 'temporarily_unavailable' }, 503, { 'retry-after': '2' });
    case '503':
      return json({ error: 'temporarily_unavailable' }, 503);
    case '502':
      return new Response('bad gateway', { status: 502 });
  }
}

// The retry table of design §1.2: which answers each request class retries.
const TABLE: Record<RetryClass, Record<Scenario, boolean>> = {
  safe: { refused: true, reset: true, '429': true, '503-retry-after': true, '503': true, '502': true },
  unsafe: { refused: false, reset: false, '429': true, '503-retry-after': true, '503': false, '502': false },
};

describe('the retry table', () => {
  for (const retry of ['safe', 'unsafe'] as const) {
    for (const scenario of Object.keys(TABLE[retry]) as Scenario[]) {
      const retried = TABLE[retry][scenario];
      it(`${retried ? 'retries' : 'does not retry'} a ${retry} request on ${scenario}`, async () => {
        const fake = new FakeFetch().on('POST', URL1, (_r, n) =>
          n === 1 ? answer(scenario) : json({ ok: true }),
        );
        const { t } = transport(fake);
        const send = t.send({ method: 'POST', url: URL1, retry, body: 'a=b' });
        if (retried) {
          const res = await send;
          expect(res.status).toBe(200);
          expect(fake.requests).toHaveLength(2);
        } else if (scenario === 'refused' || scenario === 'reset') {
          await expect(send).rejects.toMatchObject({ code: 'network_error', retryable: false });
          expect(fake.requests).toHaveLength(1);
        } else {
          const res = await send;
          expect(res.status).not.toBe(200);
          expect(fake.requests).toHaveLength(1);
        }
      });
    }
  }

  it('an Idempotency-Key makes an unsafe request safe to retry, and is sent on every attempt', async () => {
    const fake = new FakeFetch().on('POST', URL1, (_r, n) => (n === 1 ? networkError() : json({ ok: true })));
    const { t } = transport(fake);
    const res = await t.send({ method: 'POST', url: URL1, retry: 'unsafe', idempotencyKey: 'k-1' });
    expect(res.status).toBe(200);
    expect(fake.requests.map((r) => r.headers.get('idempotency-key'))).toEqual(['k-1', 'k-1']);
  });

  it('stops after the configured number of retries and returns the last answer', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => new Response('x', { status: 503 }));
    const { t } = transport(fake, { retries: 2 });
    const res = await t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(res.status).toBe(503);
    expect(new TextDecoder().decode(res.body)).toBe('x');
    expect(fake.requests).toHaveLength(3);
  });

  it('honours Retry-After, and does not retry when it would pass the deadline', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}, 429, { 'retry-after': '120' }));
    const { t, clock } = transport(fake);
    const res = await t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(res.status).toBe(429);
    expect(fake.requests).toHaveLength(1);
    expect(clock.sleeps).toEqual([]);
  });

  it('waits the Retry-After it was given', async () => {
    const fake = new FakeFetch().on('GET', URL1, (_r, n) =>
      n === 1 ? json({}, 429, { 'retry-after': '3' }) : json({}),
    );
    const { t, clock } = transport(fake);
    await t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(clock.sleeps).toEqual([3000]);
  });

  it('builds each attempt fresh through prepare', async () => {
    const fake = new FakeFetch().on('POST', URL1, (_r, n) => (n === 1 ? networkError() : json({})));
    const { t } = transport(fake);
    const prepare = vi.fn(async (attempt: number) => ({ body: `attempt=${attempt}` }));
    await t.send({ method: 'POST', url: URL1, retry: 'safe', prepare });
    expect(fake.requests.map((r) => r.body)).toEqual(['attempt=0', 'attempt=1']);
  });
});

describe('timeouts', () => {
  it('ends an attempt after attemptMs and reports a timeout', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => hang());
    const { t } = transport(fake, { attemptMs: 30, retries: 0 });
    await expect(t.send({ method: 'GET', url: URL1, retry: 'safe' })).rejects.toMatchObject({
      name: 'TransportError',
      code: 'timeout',
    });
  });

  it('retries a safe request that timed out', async () => {
    const fake = new FakeFetch().on('GET', URL1, (_r, n) => (n === 1 ? hang() : json({ ok: 1 })));
    const { t } = transport(fake, { attemptMs: 30 });
    expect((await t.send({ method: 'GET', url: URL1, retry: 'safe' })).status).toBe(200);
  });

  it('never retries an unsafe request that timed out', async () => {
    const fake = new FakeFetch().on('POST', URL1, () => hang());
    const { t } = transport(fake, { attemptMs: 30 });
    await expect(t.send({ method: 'POST', url: URL1, retry: 'unsafe' })).rejects.toMatchObject({
      code: 'timeout',
    });
    expect(fake.requests).toHaveLength(1);
  });

  it('stops at the total deadline', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}, 503));
    const { t, clock } = transport(fake, { totalMs: 1000 });
    const original = clock.sleep.bind(clock);
    clock.sleep = (ms, signal) => {
      clock.advance(5000);
      return original(ms, signal);
    };
    const err = await t.send({ method: 'GET', url: URL1, retry: 'safe' }).catch((e: unknown) => e);
    expect(isAuthFIError(err, 'TransportError') && err.code).toBe('timeout');
    expect(fake.requests).toHaveLength(1);
  });

  it('passes the caller abort reason through', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => hang());
    const { t } = transport(fake);
    const controller = new AbortController();
    const p = t.send({ method: 'GET', url: URL1, retry: 'safe', signal: controller.signal });
    controller.abort(new Error('caller gave up'));
    await expect(p).rejects.toThrow('caller gave up');
  });
});

describe('the scheme', () => {
  it.each(['http://example.com/', 'http://acme.authfi.io/oauth/token', 'ftp://example.com/', 'not a url'])(
    'refuses to send to %s, before any request leaves',
    async (url) => {
      const fake = new FakeFetch();
      const { t } = transport(fake);
      await expect(t.send({ method: 'POST', url, retry: 'unsafe' })).rejects.toMatchObject({
        name: 'ConfigurationError',
      });
      expect(fake.requests).toHaveLength(0);
    },
  );

  it('sends plain http to loopback, for local development', async () => {
    const fake = new FakeFetch().on('GET', 'http://127.0.0.1:8080/x', () => json({ ok: true }));
    const { t } = transport(fake);
    expect((await t.send({ method: 'GET', url: 'http://127.0.0.1:8080/x', retry: 'safe' })).status).toBe(200);
  });
});

describe('answers', () => {
  it('refuses a redirect', async () => {
    const fake = new FakeFetch().on(
      'GET',
      URL1,
      () => new Response(null, { status: 302, headers: { location: 'https://evil.example' } }),
    );
    const { t } = transport(fake);
    await expect(t.send({ method: 'GET', url: URL1, retry: 'safe' })).rejects.toMatchObject({
      code: 'redirect_refused',
    });
    expect(fake.requests).toHaveLength(1);
  });

  it('refuses a body over the cap, declared or streamed', async () => {
    const big = 'x'.repeat(2048);
    const declared = new FakeFetch().on(
      'GET',
      URL1,
      () => new Response(big, { headers: { 'content-length': '2048' } }),
    );
    await expect(
      transport(declared).t.send({ method: 'GET', url: URL1, retry: 'safe', maxBytes: 1024 }),
    ).rejects.toMatchObject({
      code: 'response_too_large',
    });
    const streamed = new FakeFetch().on('GET', URL1, () => new Response(new Blob([big]).stream()));
    await expect(
      transport(streamed).t.send({ method: 'GET', url: URL1, retry: 'safe', maxBytes: 1024 }),
    ).rejects.toMatchObject({
      code: 'response_too_large',
    });
  });

  it('keeps the answered request ids', async () => {
    const fake = new FakeFetch().on('GET', URL1, () =>
      json({}, 200, { 'x-request-id': 'srv-1', 'authfi-request-id': 'arq-1', 'authfi-run-id': 'run-1' }),
    );
    const res = await transport(fake).t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(res).toMatchObject({ requestId: 'srv-1', platformRequestId: 'arq-1', runId: 'run-1' });
  });

  it('warns once per URL when the platform deprecates it', async () => {
    const fake = new FakeFetch().on('GET', URL1, () =>
      json({}, 200, {
        deprecation: '@1760000000',
        link: '<https://acme.authfi.io/oauth/token2>; rel="successor-version"',
      }),
    );
    const { t, log } = transport(fake);
    await t.send({ method: 'GET', url: URL1, retry: 'safe' });
    await t.send({ method: 'GET', url: `${URL1}?x=1`, retry: 'safe' });
    expect(log.warns).toEqual([`${URL1} is deprecated by the platform`]);
  });
});

describe('headers', () => {
  it('sends one X-Request-Id per logical call, the same on every retry', async () => {
    const fake = new FakeFetch().on('GET', URL1, (_r, n) => (n < 3 ? networkError() : json({})));
    await transport(fake).t.send({ method: 'GET', url: URL1, retry: 'safe' });
    const ids = fake.requests.map((r) => r.headers.get('x-request-id'));
    expect(new Set(ids).size).toBe(1);
    expect(ids[0]).toMatch(/^afr-[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("keeps a caller's valid id and replaces one the platform would drop", async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}));
    const { t, log } = transport(fake);
    await t.send({ method: 'GET', url: URL1, retry: 'safe', requestId: 'run_42.step:1-a' });
    await t.send({ method: 'GET', url: URL1, retry: 'safe', requestId: 'has space' });
    expect(fake.requests[0]!.headers.get('x-request-id')).toBe('run_42.step:1-a');
    expect(fake.requests[1]!.headers.get('x-request-id')).toMatch(/^afr-/);
    expect(log.debugs).toContain('replaced a request id the platform would not keep');
  });

  it('sends the User-Agent and a fresh unsampled traceparent', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}));
    await transport(fake).t.send({ method: 'GET', url: URL1, retry: 'safe' });
    const h = fake.requests[0]!.headers;
    expect(h.get('user-agent')).toBe('authfi-node/test (node 22)');
    expect(h.get('traceparent')).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-00$/);
  });

  it('propagates the active OpenTelemetry trace when given the API', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}));
    const otel = {
      context: { active: () => 'ctx' },
      propagation: {
        inject: (_c: unknown, carrier: Record<string, string>) => {
          carrier.traceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
        },
      },
    };
    await transport(fake, { otel }).t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(fake.requests[0]!.headers.get('traceparent')).toBe(
      '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
    );
  });

  it('sends neither User-Agent nor traceparent from a browser, which the edge CORS would refuse', async () => {
    const fake = new FakeFetch().on('GET', URL1, () => json({}));
    await transport(fake, { browser: true, userAgent: undefined }).t.send({
      method: 'GET',
      url: URL1,
      retry: 'safe',
    });
    expect(fake.requests[0]!.headers.has('traceparent')).toBe(false);
    expect(fake.requests[0]!.headers.has('user-agent')).toBe(false);
  });
});

describe('dropped headers', () => {
  it('names DPoP when a request that carried a proof is challenged for one', async () => {
    const signer = await DPoPSigner.create(new TestClock());
    const fake = new FakeFetch().on('GET', URL1, () =>
      json({ error: 'invalid_token' }, 401, { 'www-authenticate': 'DPoP error="invalid_token"' }),
    );
    const { t, log } = transport(fake);
    const res = await t.send({ method: 'GET', url: URL1, retry: 'safe', dpop: { signer } });
    expect(res.droppedHeader).toBe('DPoP');
    await t.send({ method: 'GET', url: URL1, retry: 'safe', dpop: { signer } });
    expect(log.warns.filter((w) => w.includes('DPoP'))).toHaveLength(1);
  });

  it('names Idempotency-Key when the platform answers EMDT013', async () => {
    const fake = new FakeFetch().on('POST', URL1, () => json({ error: 'EMDT013' }, 400));
    const res = await transport(fake).t.send({
      method: 'POST',
      url: URL1,
      retry: 'unsafe',
      idempotencyKey: 'k',
    });
    expect(res.droppedHeader).toBe('Idempotency-Key');
  });

  it('warns when the answer carries another trace id', async () => {
    const fake = new FakeFetch().on('GET', URL1, () =>
      json({}, 200, { traceparent: '00-11111111111111111111111111111111-2222222222222222-01' }),
    );
    const { t, log } = transport(fake);
    const res = await t.send({ method: 'GET', url: URL1, retry: 'safe' });
    expect(res.droppedHeader).toBeUndefined();
    expect(log.warns.some((w) => w.includes('traceparent'))).toBe(true);
  });

  it('reports nothing when the headers arrived', async () => {
    const fake = new FakeFetch().on('POST', URL1, (r) =>
      json({}, 200, { traceparent: r.headers.get('traceparent')! }),
    );
    const { t, log } = transport(fake);
    const res = await t.send({ method: 'POST', url: URL1, retry: 'unsafe', idempotencyKey: 'k' });
    expect(res.droppedHeader).toBeUndefined();
    expect(log.warns).toEqual([]);
  });
});

describe('DPoP', () => {
  it('sends a fresh proof per attempt, bound to the token, and retries once with the server nonce', async () => {
    const clock = new TestClock();
    const signer = await DPoPSigner.create(clock);
    const fake = new FakeFetch().on('POST', URL1, (_r, n) =>
      n === 1
        ? json({ error: 'use_dpop_nonce' }, 400, { 'dpop-nonce': 'n-1' })
        : n === 2
          ? networkError()
          : json({ ok: true }),
    );
    const { t } = transport(fake, { clock });
    const token = new Secret('at-123');
    const res = await t.send({
      method: 'POST',
      url: `${URL1}?q=1#f`,
      retry: 'safe',
      dpop: { signer, accessToken: token },
    });
    expect(res.status).toBe(200);
    const proofs = fake.requests.map((r) => r.headers.get('dpop')!);
    expect(proofs).toHaveLength(3);
    expect(new Set(proofs).size).toBe(3);
    const key = await importJWK(decodeProtectedHeader(proofs[2]!).jwk as JWK, 'ES256');
    const { payload, protectedHeader } = await jwtVerify(proofs[2]!, key, {
      currentDate: new Date(clock.now()),
    });
    expect(protectedHeader.typ).toBe('dpop+jwt');
    expect(payload).toMatchObject({ htm: 'POST', htu: URL1, nonce: 'n-1' });
    expect(typeof payload.ath).toBe('string');
    const first = (await jwtVerify(proofs[0]!, key, { currentDate: new Date(clock.now()) })).payload;
    expect(first.nonce).toBeUndefined();
    expect(first.jti).not.toBe(payload.jti);
  });

  it('does not loop on a second nonce challenge', async () => {
    const signer = await DPoPSigner.create(new TestClock());
    const fake = new FakeFetch().on('GET', URL1, () =>
      json({ error: 'use_dpop_nonce' }, 401, {
        'dpop-nonce': 'n',
        'www-authenticate': 'DPoP error="use_dpop_nonce"',
      }),
    );
    const res = await transport(fake).t.send({ method: 'GET', url: URL1, retry: 'safe', dpop: { signer } });
    expect(res.status).toBe(401);
    expect(fake.requests).toHaveLength(2);
  });
});

describe('runtimeUserAgent', () => {
  it('names the runtime and version, with the suffix', () => {
    const { userAgent, browser } = runtimeUserAgent('1.2.3', 'my-app/1');
    expect(browser).toBe(false);
    expect(userAgent).toMatch(/^authfi-node\/1\.2\.3 \(node \d+\) my-app\/1$/);
  });

  it('sends none from a browser', () => {
    const g = globalThis as { document?: unknown };
    g.document = {};
    try {
      expect(runtimeUserAgent('1.2.3')).toEqual({ userAgent: undefined, browser: true });
    } finally {
      delete g.document;
    }
  });
});
