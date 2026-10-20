import express from 'express';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { KERNEL_TOKEN_CODES } from '../../src/core/codes.js';
import {
  DiscoveryError,
  InvalidToken,
  TemporarilyUnavailable,
  TransportError,
} from '../../src/core/errors.js';
import type { Logger } from '../../src/core/logger.js';
import { AuthFI } from '../../src/core/project.js';
import { authfiErrorHandler, protect, type ProtectOptions } from '../../src/express/index.js';
import type { Verifier } from '../../src/verify/verifier.js';
import { GUARD_CASES } from '../support/guard-cases.js';
import { API, TestIssuer } from '../support/issuer.js';

const servers: { close(): void }[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

function capture(): Logger & {
  lines: { level: string; message: string; fields: Record<string, unknown> | undefined }[];
} {
  const lines: { level: string; message: string; fields: Record<string, unknown> | undefined }[] = [];
  const at = (level: string) => (message: string, fields?: Record<string, unknown>) => {
    lines.push({ level, message, fields });
  };
  return { lines, debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') };
}

async function serve(
  verifier: Verifier,
  options: ProtectOptions = {},
  extra?: (app: express.Express) => void,
): Promise<string> {
  const app = express();
  app.get('/orders', protect(verifier, options), (req, res) => {
    res.json({ principal: req.authfi?.principal.toString() ?? null });
  });
  extra?.(app);
  app.use(authfiErrorHandler({ logger: options.logger, exposeRefusalCode: options.exposeRefusalCode }));
  const server = app.listen(0);
  servers.push(server);
  await new Promise((r) => server.once('listening', r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function setup() {
  const t = await TestIssuer.create();
  const log = capture();
  const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch, logger: log });
  return { t, log, verifier: af.verifier({ audience: API }) };
}

async function call(base: string, path: string, headers: Record<string, string> = {}) {
  const res = await fetch(base + path, { headers });
  return {
    status: res.status,
    challenge: res.headers.get('www-authenticate'),
    body: await res.text(),
    headers: res.headers,
  };
}

/** A verifier that refuses with a chosen code, to exercise every code on the wire. */
function refusing(code: string): Verifier {
  return {
    verify: () => Promise.reject(new InvalidToken(code, `refused ${code}`)),
    verifyRequest: () => Promise.reject(new InvalidToken(code, `refused ${code}`)),
  };
}

describe('protect', () => {
  it('lets a valid token through and sets req.authfi', async () => {
    const { t, verifier } = await setup();
    const base = await serve(verifier);
    const res = await call(base, '/orders', { authorization: `Bearer ${await t.sign()}` });
    expect(res).toMatchObject({ status: 200, body: JSON.stringify({ principal: 'user:usr_123' }) });
  });

  it('answers no credential with a bare Bearer challenge and no error (RFC 6750 §3.1)', async () => {
    const { verifier } = await setup();
    const base = await serve(verifier, {
      resourceMetadata: 'https://api.example.com/.well-known/oauth-protected-resource',
    });
    const res = await call(base, '/orders', { 'x-request-id': 'req-1' });
    expect(res.status).toBe(401);
    expect(res.challenge).toBe(
      'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
    );
    expect(JSON.parse(res.body)).toEqual({ error: 'unauthorized' });
    expect(res.headers.get('x-request-id')).toBe('req-1');
  });

  it("echoes and logs the caller's X-Request-Id only when the platform would accept it", async () => {
    const { verifier, log } = await setup();
    const base = await serve(verifier, { logger: log });
    const forged = 'x	level=error msg=forged';
    for (const given of [forged, 'a'.repeat(129), 'has space', '<script>']) {
      const res = await call(base, '/orders', { 'x-request-id': given });
      expect(res.status).toBe(401);
      expect(res.headers.get('x-request-id')).toBeNull();
    }
    expect(JSON.stringify(log.lines)).not.toContain('forged');
    expect(log.lines.every((l) => l.fields?.request_id === undefined)).toBe(true);
    const ok = await call(base, '/orders', { 'x-request-id': 'req-1.a:b_c-d' });
    expect(ok.headers.get('x-request-id')).toBe('req-1.a:b_c-d');
    expect(log.lines.at(-1)?.fields?.request_id).toBe('req-1.a:b_c-d');
  });

  it('answers every token refusal the same, byte for byte, and logs the code only', async () => {
    const answers = new Set<string>();
    const codes: string[] = KERNEL_TOKEN_CODES.filter((c) => c.startsWith('token_') && c !== 'token_missing');
    for (const code of [...codes, 'token_act_chain_unsupported']) {
      const log = capture();
      const base = await serve(refusing(code), { logger: log });
      const res = await call(base, '/orders', { authorization: 'Bearer x.y.z' });
      answers.add(JSON.stringify([res.status, res.challenge, res.body]));
      expect(res.body).not.toContain(code);
      expect(log.lines.at(-1)?.fields?.code).toBe(code);
    }
    expect([...answers]).toEqual([
      JSON.stringify([
        401,
        'Bearer error="invalid_token", error_description="The access token is not valid."',
        JSON.stringify({ error: 'invalid_token', error_description: 'The access token is not valid.' }),
      ]),
    ]);
  });

  it('answers a DPoP-scheme refusal with a DPoP challenge', async () => {
    const base = await serve(refusing('token_dpop_unbound'));
    const res = await call(base, '/orders', { authorization: 'DPoP x.y.z' });
    expect(res.challenge).toMatch(/^DPoP error="invalid_token"/);
  });

  it('puts the code in the body only when the API opts in', async () => {
    const base = await serve(refusing('token_expired'), { exposeRefusalCode: true });
    const res = await call(base, '/orders', { authorization: 'Bearer x.y.z' });
    expect(JSON.parse(res.body)).toEqual({
      error: 'invalid_token',
      error_description: 'The access token is not valid.',
      code: 'token_expired',
    });
  });

  it('never logs the token', async () => {
    const { t, log, verifier } = await setup();
    const raw = await t.sign({ aud: ['other'] });
    const base = await serve(verifier, { logger: log });
    await call(base, '/orders', { authorization: `Bearer ${raw}` });
    expect(JSON.stringify(log.lines)).not.toContain(raw.split('.')[2]);
    expect(log.lines.at(-1)?.fields?.code).toBe('token_audience_mismatch');
  });

  for (const c of GUARD_CASES) {
    it(`guard: ${c.name} -> ${c.status}`, async () => {
      const { t, verifier } = await setup();
      const base = await serve(verifier, c.requirements);
      const res = await call(base, '/orders', { authorization: `Bearer ${await t.sign(c.claims)}` });
      expect(res.status).toBe(c.status);
      if (c.status === 403) {
        const scope =
          c.requirements.scopes !== undefined &&
          !(c.requirements.permissions ?? []).length &&
          !(c.requirements.roles ?? []).length;
        expect(JSON.parse(res.body)).toEqual(
          scope ? { error: 'insufficient_scope' } : { error: 'forbidden' },
        );
        if (scope)
          expect(res.challenge).toBe(
            `Bearer error="insufficient_scope", scope="${c.requirements.scopes.join(' ')}"`,
          );
        else expect(res.challenge).toBeNull();
      }
    });
  }

  it('refuses an empty requirement list at setup', async () => {
    const { verifier } = await setup();
    expect(() => protect(verifier, { permissions: [] })).toThrow('permissions is empty');
    expect(() => protect(verifier, { roles: [] })).toThrow('roles is empty');
  });

  it('lets an optional route through without a credential, but not with a bad one', async () => {
    const { verifier } = await setup();
    const base = await serve(verifier, { optional: true });
    expect(await call(base, '/orders')).toMatchObject({
      status: 200,
      body: JSON.stringify({ principal: null }),
    });
    expect((await call(base, '/orders', { authorization: 'Bearer x.y.z' })).status).toBe(401);
  });

  it('answers 503 when the issuer keys cannot be fetched, and logs it as an error', async () => {
    const t = await TestIssuer.create();
    const log = capture();
    t.fake.on('GET', `${t.issuer}/.well-known/jwks.json`, () => new Response('down', { status: 500 }));
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch, logger: log, retries: 0 });
    const base = await serve(af.verifier({ audience: API }));
    const res = await call(base, '/orders', { authorization: `Bearer ${await t.sign()}` });
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toEqual({ error: 'service_unavailable' });
    expect(log.lines.some((l) => l.level === 'error')).toBe(true);
  });
});

describe('a failure that is not a refusal', () => {
  /** A verifier that throws what a bug or an outage would, to see what the client gets and what is logged. */
  function failing(error: unknown): Verifier {
    return { verify: () => Promise.reject(error), verifyRequest: () => Promise.reject(error) };
  }

  it('answers a bug 500 with no Retry-After, and logs its message, stack and cause', async () => {
    const log = capture();
    const bug = new TypeError("cannot read properties of undefined (reading 'keys')", {
      cause: new Error('the real cause'),
    });
    const base = await serve(failing(bug), { logger: log });
    const res = await call(base, '/orders', { authorization: 'Bearer x.y.z' });
    expect(res.status).toBe(500);
    expect(res.headers.get('retry-after')).toBeNull();
    expect(JSON.parse(res.body)).toEqual({ error: 'internal_error' });
    const line = log.lines.find((l) => l.level === 'error');
    expect(line?.fields?.error).toContain("reading 'keys'");
    expect(String(line?.fields?.stack)).toContain('TypeError');
    expect(line?.fields?.cause).toBe('the real cause');
  });

  it.each([
    ['a transport failure', new TransportError('network_error', 'connection refused', { retryable: true })],
    ['a discovery failure', new DiscoveryError('discovery_failed', 'no document')],
    ['the platform failing closed', new TemporarilyUnavailable('temporarily_unavailable', 'later')],
  ])('answers %s 503 with Retry-After, and logs why', async (_name, error) => {
    const log = capture();
    const base = await serve(failing(error), { logger: log });
    const res = await call(base, '/orders', { authorization: 'Bearer x.y.z' });
    expect(res.status).toBe(503);
    expect(res.headers.get('retry-after')).toBe('5');
    expect(JSON.parse(res.body)).toEqual({ error: 'service_unavailable' });
    expect(log.lines.find((l) => l.level === 'error')?.fields?.error).toBe(error.message);
  });
});

describe('the URL a DPoP proof is checked against', () => {
  function recording(): { verifier: Verifier; urls: (string | undefined)[] } {
    const urls: (string | undefined)[] = [];
    const verifier: Verifier = {
      verify: () => Promise.reject(new Error('unused')),
      verifyRequest: (input) => {
        urls.push('url' in input ? input.url : undefined);
        return Promise.reject(new InvalidToken('token_missing', 'x'));
      },
    };
    return { verifier, urls };
  }

  it('is built from publicUrl, not from a Host header the client chose', async () => {
    const { verifier, urls } = recording();
    const base = await serve(verifier, { publicUrl: 'https://api.example.com' });
    await call(base, '/orders?x=1', { host: 'attacker.example' });
    expect(urls).toEqual(['https://api.example.com/orders?x=1']);
  });

  it('falls back to the Host header only when publicUrl is not given', async () => {
    const { verifier, urls } = recording();
    const base = await serve(verifier);
    await call(base, '/orders');
    expect(urls[0]).toBe(`${base}/orders`);
  });

  it('must be an origin', () => {
    const { verifier } = recording();
    expect(() => protect(verifier, { publicUrl: 'https://api.example.com/path' })).toThrow('origin only');
    expect(() => protect(verifier, { publicUrl: 'http://api.example.com' })).toThrow('https');
  });
});

describe('authfiErrorHandler', () => {
  it('answers a refusal thrown by a handler, and passes other errors on', async () => {
    const { t, verifier } = await setup();
    const base = await serve(verifier, {}, (app) => {
      app.get('/step-up', protect(verifier), (req) => {
        req.authfi?.requireAcr(['urn:authfi:acr:mfa'], { maxAgeSeconds: 300 });
      });
      app.get('/perm', protect(verifier), (req) => {
        req.authfi?.requirePermission('orders:refund');
      });
      app.get('/boom', () => {
        throw new Error('not ours');
      });
    });
    const auth = { authorization: `Bearer ${await t.sign()}` };
    const stepUp = await call(base, '/step-up', auth);
    expect(stepUp.status).toBe(401);
    expect(stepUp.challenge).toBe(
      'Bearer error="insufficient_user_authentication", acr_values="urn:authfi:acr:mfa", max_age=300',
    );
    const perm = await call(base, '/perm', auth);
    expect(perm).toMatchObject({ status: 403, body: JSON.stringify({ error: 'forbidden' }) });
    expect(perm.body).not.toContain('orders:refund');
    expect((await call(base, '/boom', auth)).status).toBe(500);
  });
});

describe('the request URL', () => {
  it('verifies a request that carries no host', async () => {
    const seen: (string | undefined)[] = [];
    const verifier: Verifier = {
      verify: () => Promise.reject(new Error('unused')),
      verifyRequest: (input) => {
        seen.push((input as { url?: string }).url);
        return Promise.reject(new InvalidToken('token_expired', 'x'));
      },
    };
    const mw = protect(verifier);
    await new Promise<void>((resolve) => {
      const res = {
        status() {
          return this;
        },
        set() {
          return this;
        },
        json() {
          resolve();
          return this;
        },
      };
      mw({ headers: { authorization: 'Bearer a.b.c' }, method: 'GET' }, res, () => resolve());
    });
    expect(seen).toEqual([undefined]);
  });
});
