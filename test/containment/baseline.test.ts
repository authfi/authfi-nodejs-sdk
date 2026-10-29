// Containment track A, baseline: every token is verified strictly. Ported from the 0.1 JavaScript
// suite (test.js) onto the TypeScript verifier, with the kernel's refusal codes. Each refusal has a
// control that passes. The matrix in test/verify/verifier.test.ts holds the rest of the rules.

import assert from 'node:assert/strict';

import { describe, expect, it } from 'vitest';
import { DiscoveryError, TransportError, isAuthFIError } from '../../src/core/errors.js';
import {
  AUD,
  ISSUER,
  T0,
  b64u,
  ec,
  ed,
  rejectsWith,
  rsa,
  scenario,
  signJWS,
  type ClientConfig,
  type Scenario,
  type ScenarioOptions,
} from './scenario.js';

const nowSec = (s: Scenario): number => Math.floor(s.clock.t / 1000);
const bearer = (s: Scenario, t: string) => s.request(t, { scheme: 'Bearer', proofs: [] });

// refuse: the control (a good token on the same client) verifies, then the broken one is refused.
async function refuse(code: string, make: (s: Scenario) => string, cfg?: ScenarioOptions) {
  const s = scenario(cfg);
  assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1', 'control leg');
  const bad = make(s);
  const err = await rejectsWith(s.client.verifyToken(bad), code);
  assert.ok(!err.message.includes(bad), 'the message must not hold the token');
  return err;
}

describe('configuration fails closed', () => {
  const cases: Record<string, ClientConfig> = {
    'empty audience': { audience: [] },
    'blank audience value': { audience: ['  '] },
    'the issuer as audience': { audience: ISSUER },
    'a path of the issuer as audience': { audience: `${ISSUER}/api` },
    'the AuthFI console as audience': { audience: 'authfi-console' },
    'the AuthFI workspace as audience': { audience: ['api', 'authfi-workspace'] },
    'the gateway as audience': { audience: `${ISSUER}/mcp` },
    'an issuer with a query': { issuer: `${ISSUER}?x=1` },
    'a plain http issuer': { issuer: 'http://acme.authfi.io' },
    'an issuer that is not a URL': { issuer: 'acme' },
    'leeway above 300 s': { leeway: 301 },
  };
  for (const [name, cfg] of Object.entries(cases)) {
    it(`refuses to build a verifier: ${name}`, () => {
      const good = scenario();
      expect(() => good.build({ audience: [], ...cfg })).toThrow();
      assert.equal(good.client.verifier.audience[0], AUD);
    });
  }
  it('http is allowed for a loopback issuer (local development)', async () => {
    const s = scenario({ config: { issuer: 'http://localhost:8080' } });
    const t = s.token(s.claims({ iss: 'http://localhost:8080' }));
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
  });
  it('the audience may not name the API origin', () => {
    const s = scenario();
    expect(() => s.build({ audience: `${ISSUER}/apis/regional/v1` })).toThrow(/AuthFI's own/);
  });
});

describe('baseline verification', () => {
  it('accepts a valid access token and returns its claims', async () => {
    const s = scenario();
    const claims = await s.client.verifyToken(
      s.token(s.claims({ roles: ['admin'], permissions: ['read:users'] })),
    );
    assert.equal(claims.sub, 'usr_1');
    assert.deepEqual(claims.roles, ['admin']);
  });
  it('accepts an RS256 token on an RSA key and an EdDSA token on an Ed25519 key', async () => {
    for (const kind of ['rsa', 'ed']) {
      const pair = kind === 'rsa' ? rsa() : ed();
      const alg = kind === 'rsa' ? 'RS256' : 'EdDSA';
      const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' };
      const s = scenario({ jwks: { keys: [jwk] } });
      const t = signJWS({ alg, typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, alg);
      assert.equal((await s.client.verifyToken(t)).sub, 'usr_1', alg);
    }
  });
  it('accepts the typ application/at+jwt, an array audience and a tenant match', async () => {
    const s = scenario({ config: { expectedTenantId: 'tnt_1' } });
    const t = s.token(s.claims({ aud: ['x', AUD] }), { typ: 'application/at+jwt' });
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
  });
  it('token_malformed: not three parts', () => refuse('token_malformed', () => 'a.b'));
  it('token_malformed: four parts', () => refuse('token_malformed', (s) => `${s.token(s.claims())}.x`));
  it('token_malformed: an empty token', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyToken(''), 'token_missing');
  });
  it('token_malformed: header or payload that is not JSON, or JSON that is not an object', async () => {
    await refuse('token_malformed', () => `${b64u('nope')}.${b64u('{}')}.${b64u('x')}`);
    await refuse('token_malformed', (s) => s.token(b64u('[1]')));
  });
  it('token_malformed: padded base64 and a newline', async () => {
    await refuse('token_malformed', (s) => {
      const [h, p, g] = s.token(s.claims()).split('.');
      return `${h}=.${p}.${g}`;
    });
    await refuse('token_malformed', (s) => {
      const [h, p, g] = s.token(s.claims()).split('.');
      return `${h}\n.${p}.${g}`;
    });
  });
  it('a signature with non-canonical trailing bits does not verify', async () => {
    const s = scenario();
    const [h, p, g] = s.token(s.claims()).split('.');
    const bad = `${h}.${p}.${(g ?? '').slice(0, -1)}B`;
    await rejectsWith(s.client.verifyToken(bad), 'token_malformed');
  });
  it('token_malformed: an empty signature', () =>
    refuse('token_malformed', (s) => {
      const [h, p] = s.token(s.claims()).split('.');
      return `${h}.${p}.`;
    }));
  it('token_too_large: over 16 KiB', () =>
    refuse('token_malformed', (s) => s.token(s.claims({ pad: 'x'.repeat(17_000) }))));
  it('token_alg_not_allowed: none, with or without a signature', async () => {
    await refuse('token_malformed', (s) =>
      signJWS({ alg: 'none', typ: 'at+jwt', kid: 'k1' }, s.claims(), null, 'none'),
    );
    await refuse('token_signature_invalid', (s) => {
      const [h, p] = signJWS({ alg: 'none', typ: 'at+jwt', kid: 'k1' }, s.claims(), null, 'none').split('.');
      return `${h}.${p}.${b64u('junk')}`;
    });
  });
  it('token_alg_not_allowed: HS256 signed with the public key as the secret', async () => {
    const pair = rsa();
    const pem = pair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };
    const s = scenario({ jwks: { keys: [jwk] } });
    const t = signJWS({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pem, 'HS256');
    await rejectsWith(s.client.verifyToken(t), 'token_signature_invalid');
    const t2 = signJWS({ alg: 'RS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, 'RS256');
    assert.equal((await s.client.verifyToken(t2)).sub, 'usr_1');
  });
  it('token_alg_not_allowed: HS512, RS512, ES384, a lower-case alg and an empty one', async () => {
    for (const alg of ['HS512', 'RS512', 'ES384', 'es256', '']) {
      await refuse('token_signature_invalid', (s) => s.token(s.claims(), { alg }));
    }
  });
  it('token_alg_key_mismatch: an RS256 token against an EC key (algorithm confusion)', () =>
    refuse('token_key_unknown', (s) => s.token(s.claims(), { alg: 'RS256' })));
  it('token_alg_key_mismatch: a key pinned to ES256 by its alg refuses PS256', () =>
    refuse('token_signature_invalid', (s) => s.token(s.claims(), { alg: 'PS256' })));
  it('token_alg_key_mismatch: an RSA key whose alg is RS256 refuses PS256', async () => {
    const pair = rsa();
    const s = scenario({
      jwks: { keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] },
    });
    const t = signJWS({ alg: 'PS256', typ: 'at+jwt', kid: 'k1' }, s.claims(), pair.privateKey, 'PS256');
    await expect(s.client.verifyToken(t)).rejects.toMatchObject({ name: 'InvalidToken' });
  });
  it('token_kid_required: no kid', () =>
    refuse('token_key_unknown', (s) => s.token(s.claims(), { kid: undefined })));
  it('token_crit_not_supported: a crit header', () =>
    refuse('token_claims_invalid', (s) => s.token(s.claims(), { crit: ['exp'] })));
  it('token_typ_invalid: an ID token, a plain JWT, a missing typ, a proof type', async () => {
    await refuse('token_not_access_token', (s) => s.token(s.claims(), { typ: 'JWT' }));
    await refuse('token_not_access_token', (s) => s.token(s.claims(), { typ: 'id+jwt' }));
    await refuse('token_not_access_token', (s) => s.token(s.claims(), { typ: undefined }));
    await refuse('token_not_access_token', (s) => s.token(s.claims(), { typ: 'dpop+jwt' }));
  });
  it('token_unknown_key: a kid the issuer never published', () =>
    refuse('token_key_unknown', (s) => s.token(s.claims(), { kid: 'nope' })));
  it('token_unknown_key: keys never come from the token (embedded jwk and jku are ignored)', async () => {
    const attacker = ec();
    await refuse('token_key_unknown', (s) =>
      s.token(
        s.claims(),
        { kid: 'evil', jwk: attacker.publicKey.export({ format: 'jwk' }), jku: 'https://evil.example/jwks' },
        attacker.privateKey,
      ),
    );
  });
  it('token_signature_invalid: signed by another key, and a tampered payload', async () => {
    await refuse('token_signature_invalid', (s) => s.token(s.claims(), {}, ec().privateKey));
    await refuse('token_signature_invalid', (s) => {
      const [h, , g] = s.token(s.claims()).split('.');
      return `${h}.${b64u(JSON.stringify(s.claims({ sub: 'usr_2' })))}.${g}`;
    });
  });
  it('token_issuer_mismatch', async () => {
    await refuse('token_issuer_not_accepted', (s) => s.token(s.claims({ iss: 'https://other.authfi.io' })));
    await refuse('token_issuer_not_accepted', (s) => s.token(s.claims({ iss: undefined })));
  });
  it('token_audience_mismatch: wrong, missing and empty audiences', async () => {
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: 'other-api' })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: undefined })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: [] })));
    await refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: [5, null] })));
  });
  it('token_audience_mismatch: a token minted for the AuthFI console is not accepted by an API', () =>
    refuse('token_audience_mismatch', (s) => s.token(s.claims({ aud: 'authfi-console' }))));
  it('token_expired: past exp, even with the leeway', () =>
    refuse('token_expired', (s) => s.token(s.claims({ exp: nowSec(s) - 61 }))));
  it('the leeway lets a token that expired 30 s ago through, and leeway 0 does not', async () => {
    const s = scenario();
    assert.equal((await s.client.verifyToken(s.token(s.claims({ exp: nowSec(s) - 30 })))).sub, 'usr_1');
    const strict = scenario({ config: { leeway: 0 } });
    await rejectsWith(
      strict.client.verifyToken(strict.token(strict.claims({ exp: nowSec(strict) - 1 }))),
      'token_expired',
    );
  });
  it('token_exp_required: no exp, or one that is not a date', async () => {
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ exp: undefined })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ exp: '9999999999' })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ exp: -1 })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ exp: 1e20 })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ exp: 253_402_300_800 })));
  });
  it('token_not_yet_valid: nbf and iat in the future', async () => {
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ nbf: nowSec(s) + 120 })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ iat: nowSec(s) + 120 })));
  });
  it('token_malformed: nbf or iat that is not a valid date', async () => {
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ nbf: 'later' })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ iat: -5 })));
  });
  it('token_malformed: an act claim that is not an object', async () => {
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ act: 'someone' })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ act: [1] })));
    await refuse('token_claims_invalid', (s) => s.token(s.claims({ act: null })));
  });
  it('token_sub_required', () =>
    refuse('token_claims_invalid', (s) => s.token(s.claims({ sub: undefined }))));
  it('token_tenant_required', () =>
    refuse('token_no_tenant', (s) => s.token(s.claims({ tenant_id: undefined }))));
  it('token_tenant_not_issuers: tenant_id differs from the configured tenant', async () => {
    const s = scenario({ config: { expectedTenantId: 'tnt_1' } });
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).tenant_id, 'tnt_1');
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims({ tenant_id: 'tnt_2' }))),
      'token_tenant_not_issuers',
    );
  });
});

describe('the key set', () => {
  it('is fetched from the issuer origin and cached', async () => {
    const s = scenario();
    await s.client.verifyToken(s.token(s.claims()));
    await s.client.verifyToken(s.token(s.claims()));
    assert.deepEqual(
      s.fetches.filter((u) => u.endsWith('/jwks.json')),
      [`${ISSUER}/.well-known/jwks.json`],
    );
    const call = s.fetchOpts.find((_, i) => s.fetches[i]?.endsWith('/jwks.json'));
    assert.equal(call?.redirect, 'manual', 'a redirect from the key set URL must not be followed');
    assert.ok(call?.signal, 'the fetch has a timeout');
  });
  it('an unknown kid refetches at most once every 30 s', async () => {
    const s = scenario();
    await s.client.verifyToken(s.token(s.claims()));
    const hits = (): number => s.fetches.filter((u) => u.endsWith('/jwks.json')).length;
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'n1' })), 'token_key_unknown');
    const afterFirst = hits();
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'n2' })), 'token_key_unknown');
    assert.equal(hits(), afterFirst, 'forged-kid traffic inside the interval must not refetch');
    s.clock.t += 40_000;
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }), { kid: 'n1' })),
      'token_key_unknown',
    );
    assert.equal(hits(), afterFirst + 1);
  });
  it('jwks_unavailable: the fetch fails, answers 500, is not JSON, is too large, or holds no key', async () => {
    const body = JSON.stringify(scenario().jwks);
    const fetches: (() => Promise<Response>)[] = [
      () => Promise.reject(new Error('down')),
      () => Promise.resolve(new Response('x', { status: 500 })),
      () => Promise.resolve(new Response(body, { status: 500 })), // a good document under an error status is not trusted
      () => Promise.resolve(new Response(body + ' '.repeat(1_100_000), { status: 200 })), // valid JSON, only the size is wrong
      () => Promise.resolve(new Response('not json', { status: 200 })),
    ];
    for (const jwksFetch of fetches) {
      const s = scenario({ jwksFetch });
      const err = await s.client.verifyToken(s.token(s.claims())).then(
        () => undefined,
        (e: unknown) => e,
      );
      assert.ok(
        isAuthFIError(err, 'DiscoveryError') || isAuthFIError(err, 'TransportError'),
        `unexpected ${String(err)}`,
      );
    }
    // an empty key set is a valid document that publishes nothing: no key is unknown, not unavailable
    const s = scenario({ jwksFetch: () => Promise.resolve(new Response('{"keys":[]}', { status: 200 })) });
    await rejectsWith(s.client.verifyToken(s.token(s.claims())), 'token_key_unknown');
  });
  it('serves a stale key for a while when a refresh fails, and not forever', async () => {
    let down = false;
    const s = scenario({
      jwksFetch: () => {
        if (down) return Promise.reject(new Error('down'));
        return Promise.resolve(
          new Response(JSON.stringify(s.jwks), { status: 200, headers: { 'cache-control': 'max-age=300' } }),
        );
      },
    });
    await s.client.verifyToken(s.token(s.claims()));
    down = true;
    s.clock.t += 10 * 60 * 1000;
    const t = s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }));
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
    // a failed refresh is retried after a pause, not on every request
    const hits = s.fetches.length;
    assert.equal((await s.client.verifyToken(t)).sub, 'usr_1');
    assert.equal(s.fetches.length, hits);
    s.clock.t += 2 * 3600 * 1000;
    const t2 = s.token(s.claims({ iat: nowSec(s), exp: nowSec(s) + 600 }));
    const err = await s.client.verifyToken(t2).then(
      () => undefined,
      (e: unknown) => e,
    );
    assert.ok(err instanceof TransportError || err instanceof DiscoveryError, String(err));
  });
  it('with a duplicated kid the first key wins', async () => {
    const attacker = ec();
    const s = scenario();
    s.jwks.keys.push({
      ...attacker.publicKey.export({ format: 'jwk' }),
      kid: 'k1',
      use: 'sig',
      alg: 'ES256',
    });
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1');
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims(), {}, attacker.privateKey)),
      'token_signature_invalid',
    );
  });
  it('reads at most 100 keys of a key set', async () => {
    const fill = Array.from({ length: 100 }, (_, i) => ({
      ...ec().publicKey.export({ format: 'jwk' }),
      kid: `f${String(i)}`,
      use: 'sig',
    }));
    const late = ec();
    const lateJwk = { ...late.publicKey.export({ format: 'jwk' }), kid: 'late', use: 'sig' };
    const s = scenario({ jwks: { keys: [...fill, lateJwk] } });
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims(), { kid: 'late' }, late.privateKey)),
      'token_key_unknown',
    );
    const s2 = scenario({ jwks: { keys: [...fill.slice(1), lateJwk] } });
    assert.equal(
      (await s2.client.verifyToken(s2.token(s2.claims(), { kid: 'late' }, late.privateKey))).sub,
      'usr_1',
    );
  });
  it('stops reading a key set body at the cap instead of buffering it', async () => {
    let pulls = 0;
    const chunk = new Uint8Array(256 * 1024).fill(32);
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        pulls++;
        if (pulls > 400) c.close();
        else c.enqueue(chunk);
      },
    });
    const s = scenario({ jwksFetch: () => Promise.resolve(new Response(stream, { status: 200 })) });
    await expect(s.client.verifyToken(s.token(s.claims()))).rejects.toMatchObject({ name: 'TransportError' });
    assert.ok(pulls < 20, `read ${String(pulls)} chunks`);
  });
  it('ignores a key with use=enc, a small RSA key and a key that does not parse', async () => {
    const small = rsa(1024);
    const enc = ec();
    const s = scenario();
    s.jwks.keys.push({ ...small.publicKey.export({ format: 'jwk' }), kid: 'small', use: 'sig' });
    s.jwks.keys.push({ ...enc.publicKey.export({ format: 'jwk' }), kid: 'enc', use: 'enc' });
    s.jwks.keys.push({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA', kid: 'junk' });
    s.jwks.keys.push({
      ...enc.publicKey.export({ format: 'jwk' }),
      kid: 'wrongalg',
      use: 'sig',
      alg: 'RS256',
    });
    const r = rsa();
    s.jwks.keys.push({ ...r.publicKey.export({ format: 'jwk' }), kid: 'rsaec', use: 'sig', alg: 'ES256' });
    s.jwks.keys.push({ kty: 'oct', k: 'AAAA', kid: 'secret', use: 'sig' });
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1');
    await rejectsWith(
      s.client.verifyToken(
        signJWS({ alg: 'RS256', typ: 'at+jwt', kid: 'small' }, s.claims(), small.privateKey, 'RS256'),
      ),
      'token_key_unknown',
    );
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims(), { kid: 'enc' }, enc.privateKey)),
      'token_key_unknown',
    );
    await rejectsWith(s.client.verifyToken(s.token(s.claims(), { kid: 'junk' })), 'token_key_unknown');
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims(), { kid: 'wrongalg', alg: 'RS256' }, enc.privateKey)),
      'token_key_unknown',
    );
    await rejectsWith(
      s.client.verifyToken(
        signJWS({ alg: 'RS256', typ: 'at+jwt', kid: 'rsaec' }, s.claims(), r.privateKey, 'RS256'),
      ),
      'token_key_unknown',
    );
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims(), { kid: 'secret', alg: 'RS256' })),
      'token_key_unknown',
    );
  });
});

describe('verifyRequest on a person token', () => {
  it('accepts a Bearer token and returns the claims', async () => {
    const s = scenario();
    assert.equal((await s.client.verifyRequest(bearer(s, s.token(s.claims())))).sub, 'usr_1');
  });
  it('missing_authorization: no header, wrong scheme, two Authorization values', async () => {
    const s = scenario();
    const t = s.token(s.claims());
    assert.equal((await s.client.verifyRequest(bearer(s, t))).sub, 'usr_1');
    const r1 = bearer(s, t);
    delete r1.headers.authorization;
    r1.rawHeaders = [];
    await rejectsWith(s.client.verifyRequest(r1), 'token_missing');
    await rejectsWith(s.client.verifyRequest(s.request(t, { scheme: 'Basic', proofs: [] })), 'token_missing');
    const r3 = bearer(s, t);
    r3.rawHeaders?.push('Authorization', `Bearer ${t}`);
    await rejectsWith(s.client.verifyRequest(r3), 'token_missing');
  });
});

describe('the clock', () => {
  it('uses the scenario clock for exp, so a token that was valid at T0 is expired a day later', async () => {
    const s = scenario();
    const t = s.token(s.claims());
    assert.equal(s.clock.t, T0);
    await s.client.verifyToken(t);
    s.clock.t += 86_400_000;
    await rejectsWith(s.client.verifyToken(t), 'token_expired');
  });
});
