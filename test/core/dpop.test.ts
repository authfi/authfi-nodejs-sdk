import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Mandate, mandateDetailsOf } from '../../src/agents/mandate.js';
import { InstanceAuth, InstanceSigner } from '../../src/agents/instance.js';
import {
  asksForNonce,
  boundThumbprint,
  DPoPSigner,
  ecThumbprint,
  isBoundTo,
  jwkThumbprint,
} from '../../src/core/dpop.js';
import { Secret } from '../../src/core/secret.js';
import { learnNonce } from '../../src/core/token-source.js';
import { TestClock, unsignedJwt } from '../support/issuer.js';
import { call, person, platform } from '../support/platform-setup.js';
import type { TokenResponse } from '../../src/core/oauth.js';
import { AuthFI } from '../../src/core/project.js';

describe('the process key', () => {
  it('is one key for every signer in the process, named by its RFC 7638 thumbprint', async () => {
    const a = await DPoPSigner.create(new TestClock());
    const b = await DPoPSigner.create(new TestClock());
    expect(a.thumbprint).toBe(b.thumbprint);
    expect(a.thumbprint).toBe(await calculateJwkThumbprint(a.publicJwk as never));
    expect(a.thumbprint).toBe(await ecThumbprint(a.publicJwk));
    expect(a.publicJwk).not.toHaveProperty('d');
    expect(a.alg).toBe('ES256');
    expect(String(a)).toBe(`DPoPSigner(ES256 ${a.thumbprint})`);
    expect(JSON.stringify(a)).toBe(JSON.stringify({ alg: 'ES256', thumbprint: a.thumbprint }));
  });

  it('signs a proof with its own nonce per origin, and a JWT of the type asked for', async () => {
    const signer = await DPoPSigner.create(new TestClock());
    const url = 'https://nonce-test.example/a/b?q=1#f';
    expect(signer.nonceFor(url)).toBeUndefined();
    expect(signer.rememberNonce(url, new Headers())).toBe(false);
    expect(signer.rememberNonce('not a url', new Headers({ 'dpop-nonce': 'x' }))).toBe(false);
    expect(signer.nonceFor('not a url')).toBeUndefined();
    expect(signer.rememberNonce(url, new Headers({ 'dpop-nonce': 'n1' }))).toBe(true);
    expect(signer.nonceFor('https://nonce-test.example/other')).toBe('n1');
    const claims = decodeJwt(await signer.proof('post', url, new Secret('tok')));
    expect(claims).toMatchObject({ htm: 'POST', htu: 'https://nonce-test.example/a/b', nonce: 'n1' });
    expect(claims.ath).toBeDefined();
    const jwt = await signer.signJwt({ a: 1 }, 'my+jwt');
    expect(decodeProtectedHeader(jwt)).toEqual({ typ: 'my+jwt', alg: 'ES256' });
  });
});

describe('thumbprints and what a token is bound to', () => {
  it('reads the RFC 8037 Ed25519 example, and an EC key the same as the signer does', async () => {
    expect(
      await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }),
    ).toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
    const signer = await DPoPSigner.create(new TestClock());
    expect(await jwkThumbprint(signer.publicJwk)).toBe(signer.thumbprint);
  });

  it('knows no thumbprint for a key it cannot make', async () => {
    expect(await jwkThumbprint(null)).toBeUndefined();
    expect(await jwkThumbprint('x')).toBeUndefined();
    expect(await jwkThumbprint({ kty: 'RSA', n: 'a', e: 'b' })).toBeUndefined();
    expect(await jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'a' })).toBeUndefined();
    expect(await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519' })).toBeUndefined();
  });

  it('reads cnf.jkt without trusting the token, and says nothing of a token that is not one', () => {
    expect(boundThumbprint(unsignedJwt({}, { cnf: { jkt: 'abc' } }))).toBe('abc');
    expect(boundThumbprint(unsignedJwt({}, { cnf: {} }))).toBeUndefined();
    expect(boundThumbprint('opaque')).toBeUndefined();
    expect(boundThumbprint('a.%%%.c')).toBeUndefined();
  });

  it('calls an answer bound only when it says DPoP and names this key; Bearer is not bound, another key is an error', async () => {
    const signer = await DPoPSigner.create(new TestClock());
    const mine = new Secret(unsignedJwt({}, { cnf: { jkt: signer.thumbprint } }));
    const other = new Secret(unsignedJwt({}, { cnf: { jkt: 'other' } }));
    expect(isBoundTo('DPoP', mine, signer)).toBe(true);
    expect(isBoundTo('dpop', mine, signer)).toBe(true);
    expect(isBoundTo('Bearer', mine, signer)).toBe(false);
    expect(() => isBoundTo('DPoP', other, signer)).toThrow(/key this process does not hold/);
    expect(() => isBoundTo('DPoP', new Secret('opaque'), signer)).toThrow(/key this process does not hold/);
  });

  it('asks for a nonce only on a 400 or 401 that carries one and says use_dpop_nonce', () => {
    const h = (o: Record<string, string>) => new Headers(o);
    expect(
      asksForNonce(401, h({ 'dpop-nonce': 'n', 'www-authenticate': 'DPoP error="use_dpop_nonce"' }), ''),
    ).toBe(true);
    expect(asksForNonce(400, h({ 'dpop-nonce': 'n' }), '{"error": "use_dpop_nonce"}')).toBe(true);
    expect(asksForNonce(401, h({ 'www-authenticate': 'DPoP error="use_dpop_nonce"' }), '')).toBe(false);
    expect(asksForNonce(403, h({ 'dpop-nonce': 'n' }), '{"error":"use_dpop_nonce"}')).toBe(false);
    expect(asksForNonce(401, h({ 'dpop-nonce': 'n' }), '{"error":"invalid_token"}')).toBe(false);
  });

  it('keeps a nonce only from an answer that asked for it', async () => {
    const signer = await DPoPSigner.create(new TestClock());
    const url = 'https://learn.example/x';
    const plain = new Response('{"error":"invalid_token"}', { status: 401, headers: { 'dpop-nonce': 'z' } });
    expect(await learnNonce(signer, url, plain)).toBe(false);
    expect(await learnNonce(signer, url, new Response('ok'))).toBe(false);
    const asked = new Response('{"error":"use_dpop_nonce"}', { status: 400, headers: { 'dpop-nonce': 'z' } });
    expect(await learnNonce(signer, url, asked)).toBe(true);
    expect(signer.nonceFor(url)).toBe('z');
  });
});

describe('a bound credential used as a fetch', () => {
  it("answers the server's nonce once, with a new proof, and keeps the body", async () => {
    const { agent, p } = await platform();
    p.nonce = { gateway: 'fn' };
    const res = await agent.fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    const sent = p.t.fake.to(`${p.issuer}/mcp`);
    expect(sent).toHaveLength(2);
    expect(sent[1]!.body).toBe(sent[0]!.body);
    expect(sent.map((r) => r.headers.get('authorization')?.split(' ')[0])).toEqual(['DPoP', 'DPoP']);
  });

  it("does not answer twice, and refuses an origin that is not AuthFI's", async () => {
    const { agent, p } = await platform();
    p.nonce = { gateway: 'a' };
    p.rotate = true;
    const res = await agent.fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(401);
    expect(p.t.fake.to(`${p.issuer}/mcp`)).toHaveLength(2);
    await expect(agent.fetch('https://attacker.example/steal')).rejects.toThrow(
      /refusing to send this credential/,
    );
  });

  it('sends a mandate, a delegated token and a customer-resource token the way each is bound', async () => {
    const s = await platform();
    const mandate = await s.agent.mandate('support.refund', { subjectToken: await person(s.p, s.clock) });
    s.p.nonce = { gateway: 'mn' };
    expect(
      (await mandate.fetch(`${s.p.issuer}/mcp`, { method: 'POST', body: call('billing__refund') })).status,
    ).toBe(200);
    expect(s.p.calls.at(-1)!.mandate).toBe('mnd_1');
    expect(s.p.t.fake.to(`${s.p.issuer}/mcp`).at(-1)!.headers.get('authorization')).toMatch(/^DPoP /);
  });
});

describe('a mandate from its answer', () => {
  const response = (details: unknown): TokenResponse =>
    ({
      accessToken: new Secret('t'),
      expiresAt: 1_900_000_000_000,
      extra: details === undefined ? {} : { authorization_details: details },
    }) as unknown as TokenResponse;

  it('reads a bare entry with defaults, ignores other entries, and refuses an answer without its entry', () => {
    expect(mandateDetailsOf(response([{ type: 'authfi_mandate' }]))).toEqual({
      mandateId: '',
      template: '',
      tools: [],
      budgets: {},
      expiresAt: undefined,
    });
    expect(
      mandateDetailsOf(
        response([
          { type: 'other' },
          'text',
          null,
          {
            type: 'authfi_mandate',
            mandate_id: 'm',
            tools: ['a', 1],
            budgets: { spend: 5, bad: 'x', frac: 1.5 },
            expires_at: 'soon',
          },
        ]),
      ),
    ).toMatchObject({ mandateId: 'm', tools: ['a'], budgets: { spend: 5 }, expiresAt: 'soon' });
    for (const none of [undefined, [], 'x', [{ type: 'other' }]]) {
      expect(() => mandateDetailsOf(response(none))).toThrow(/without its authorization_details/);
    }
  });

  it('shows when it runs out, prints without its token, and is a disposable', async () => {
    const s = await platform();
    const mandate = await s.agent.mandate('support.refund', { subjectToken: await person(s.p, s.clock) });
    expect(mandate.expiresAt.getTime()).toBe(s.clock.now() + s.p.tokenLifetime * 1000);
    expect(mandate.toJSON()).toEqual({ kind: 'mandate', mandateId: 'mnd_1', template: 'support.refund@3' });
    expect(String(mandate)).toBe('Mandate(mnd_1, support.refund@3)');
    expect(
      (mandate as unknown as Record<symbol, () => string>)[Symbol.for('nodejs.util.inspect.custom')]!(),
    ).toBe('Mandate(mnd_1, support.refund@3)');
    expect(mandate).toBeInstanceOf(Mandate);
    mandate[Symbol.dispose]();
    await expect(mandate.token()).rejects.toThrow(/closed/);
  });
});

describe('the instance credential', () => {
  it('has no key to sign an assertion with, and says what to do instead', async () => {
    const signer = new InstanceSigner();
    await expect(signer.sign()).rejects.toMatchObject({ feature: 'instance_assertion' });
    expect(signer.publicJwk()).toEqual({});
    expect(signer).toMatchObject({ kid: 'instance', alg: 'ES256' });
  });

  it('is not made without an approved configuration or with a malformed one', () => {
    const af = new AuthFI({ issuer: 'https://acme.authfi.io' });
    const evidence = { kind: 'k8s' as const, token: () => Promise.resolve('t') };
    for (const config of [
      { version: 0, digest: `sha256:${'a'.repeat(64)}` },
      { version: 1.5, digest: `sha256:${'a'.repeat(64)}` },
      { version: 1, digest: 'md5:abc' },
      { version: '1' as never, digest: `sha256:${'a'.repeat(64)}` },
    ]) {
      expect(() => new InstanceAuth(af, { agentId: 'agt_1', evidence, config })).toThrow(
        /approved configuration/,
      );
    }
    expect(
      new InstanceAuth(af, {
        agentId: 'agt_1',
        evidence,
        config: { version: 1, digest: `sha256:${'a'.repeat(64)}` },
      }).instanceId,
    ).toBeUndefined();
  });
});

describe('where the one-level rule is tracked', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('tracks nothing where the runtime has no AsyncLocalStorage, and the work still runs', async () => {
    vi.resetModules();
    vi.stubGlobal('process', { ...process, getBuiltinModule: () => undefined });
    const none = await import('../../src/agents/scope.js');
    expect(() => none.refuseNested()).not.toThrow();
    expect(none.runInMandate(() => 'ran')).toBe('ran');
    vi.resetModules();
    vi.stubGlobal('process', {
      ...process,
      getBuiltinModule: () => {
        throw new Error('no such module');
      },
    });
    const broken = await import('../../src/agents/scope.js');
    expect(broken.runInMandate(() => 'ran')).toBe('ran');
  });
});
