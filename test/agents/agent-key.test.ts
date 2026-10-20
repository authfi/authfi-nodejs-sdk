import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { inspect } from 'node:util';
import { compactVerify, importJWK, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { AgentKey, EXPORT_PKCS8 } from '../../src/agents/agent-key.js';
import { clientAssertion, MAX_ASSERTION_SECONDS } from '../../src/agents/assertion.js';
import { Secret } from '../../src/core/secret.js';
import { TestClock } from '../support/issuer.js';

describe('AgentKey', () => {
  for (const alg of ['EdDSA', 'ES256', 'PS256'] as const) {
    it(`generates an ${alg} key that signs what its public JWK verifies`, async () => {
      const key = await AgentKey.generate(alg);
      expect(key.alg).toBe(alg);
      expect(key.kid).toBe(await key.thumbprint());
      const jwk = key.publicJwk();
      expect(jwk).toMatchObject({ kid: key.kid, alg, use: 'sig' });
      for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(jwk).not.toHaveProperty(m);
      const assertion = await clientAssertion(
        key,
        'agt_1',
        'https://acme.authfi.io/oauth/token',
        new TestClock(),
      );
      const pub = await importJWK(jwk as JWK, alg);
      const { protectedHeader } = await compactVerify(assertion.reveal(), pub);
      expect(protectedHeader).toEqual({ alg, typ: 'JWT', kid: key.kid });
    });
  }

  it('makes RSA keys of 3072 bits', async () => {
    const key = await AgentKey.generate('PS256');
    expect(atob((key.publicJwk().n ?? '').replace(/-/g, '+').replace(/_/g, '/')).length).toBe(384);
  });

  it('loads PKCS#8 PEM keys of each type, and private JWKs', async () => {
    const pairs: [string, KeyObject, string][] = [
      ['ed25519', generateKeyPairSync('ed25519').privateKey, 'EdDSA'],
      ['ec', generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, 'ES256'],
      ['rsa', generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey, 'PS256'],
    ];
    for (const [type, privateKey, alg] of pairs) {
      const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      const key = await AgentKey.fromPem(new Secret(pem), { kid: `k-${type}` });
      expect([key.alg, key.kid]).toEqual([alg, `k-${type}`]);
      const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
      const fromJwk = await AgentKey.fromJwk({ ...jwk, kid: 'jwk-kid' });
      expect([fromJwk.alg, fromJwk.kid]).toEqual([alg, 'jwk-kid']);
      expect(fromJwk.publicJwk().x ?? fromJwk.publicJwk().n).toBe(key.publicJwk().x ?? key.publicJwk().n);
    }
  });

  it('refuses keys the platform would refuse', async () => {
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    await expect(
      AgentKey.fromJwk(p384.export({ format: 'jwk' }) as JsonWebKey, { kid: 'k' }),
    ).rejects.toThrow('P-256');
    const rsa1024 = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    await expect(
      AgentKey.fromJwk(rsa1024.export({ format: 'jwk' }) as JsonWebKey, { kid: 'k' }),
    ).rejects.toThrow('2048 to 4096');
    const rsa3 = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 3 }).privateKey;
    await expect(
      AgentKey.fromJwk(rsa3.export({ format: 'jwk' }) as JsonWebKey, { kid: 'k' }),
    ).rejects.toThrow('65537');
    await expect(AgentKey.fromJwk({ kty: 'OKP', crv: 'Ed25519', x: 'a' }, { kid: 'k' })).rejects.toThrow(
      'no private member',
    );
    await expect(AgentKey.fromJwk({ kty: 'oct', k: 'x', d: 'x' }, { kid: 'k' })).rejects.toThrow(
      'Ed25519, P-256 or RSA',
    );
    const sec1 = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      .privateKey.export({ type: 'sec1', format: 'pem' })
      .toString();
    await expect(AgentKey.fromPem(sec1, { kid: 'k' })).rejects.toThrow('openssl pkcs8 -topk8');
    await expect(
      AgentKey.fromPem('-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----', {
        kid: 'k',
      }),
    ).rejects.toThrow('encrypted');
    await expect(
      AgentKey.fromPem('-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----', { kid: 'k' }),
    ).rejects.toThrow('PKCS#8');
    await expect(AgentKey.fromPem('not a pem', { kid: 'k' })).rejects.toThrow('not a PEM');
    const ed = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    await expect(AgentKey.fromPem(ed, { kid: '' })).rejects.toThrow('kid is required');
    await expect(AgentKey.generate('RS256' as 'PS256')).rejects.toThrow('cannot generate');
  });

  it('never shows its private key, and exports only a generated key', async () => {
    const generated = await AgentKey.generate();
    const pem = await generated[EXPORT_PKCS8]();
    const ed = generateKeyPairSync('ed25519').privateKey;
    const loaded = await AgentKey.fromPem(ed.export({ type: 'pkcs8', format: 'pem' }).toString(), {
      kid: 'k',
    });
    await expect(loaded[EXPORT_PKCS8]()).rejects.toThrow('only a key made by AgentKey.generate()');
    const body = pem.reveal().split('\n')[1]!;
    for (const text of [
      inspect(generated, { showHidden: true }),
      String(generated),
      JSON.stringify(generated),
      JSON.stringify(Object.entries(generated)),
    ]) {
      expect(text).not.toContain(body);
      expect(text).not.toContain('"d"');
    }
    expect(JSON.parse(JSON.stringify(generated))).toEqual({ kid: generated.kid, alg: 'EdDSA' });
  });
});

describe('the client assertion', () => {
  it('is five minutes long, names the agent and the audience, and has a fresh jti every time', async () => {
    const key = await AgentKey.generate();
    const clock = new TestClock();
    const a = await clientAssertion(key, 'agt_1', 'https://acme.authfi.io/oauth/token', clock);
    const b = await clientAssertion(key, 'agt_1', 'https://acme.authfi.io/oauth/token', clock);
    const decode = (s: Secret) =>
      JSON.parse(atob(s.reveal().split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<
        string,
        unknown
      >;
    const pa = decode(a);
    expect(pa).toMatchObject({
      iss: 'agt_1',
      sub: 'agt_1',
      aud: 'https://acme.authfi.io/oauth/token',
      iat: clock.now() / 1000,
    });
    expect((pa.exp as number) - (pa.iat as number)).toBe(MAX_ASSERTION_SECONDS);
    expect(pa.jti).not.toBe(decode(b).jti);
    expect(String(a)).toBe('Secret(***)');
  });
});

describe('keys the SDK cannot use', () => {
  it('names the problem', async () => {
    await expect(AgentKey.fromJwk({ kty: 'RSA', n: 'a+b', e: 'AQAB', d: 'x' }, { kid: 'k' })).rejects.toThrow(
      '2048 to 4096',
    );
    await expect(
      AgentKey.fromPem('-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----', { kid: 'k' }),
    ).rejects.toThrow('not valid base64');
    const x25519 = generateKeyPairSync('x25519')
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();
    await expect(AgentKey.fromPem(x25519, { kid: 'k' })).rejects.toThrow('Ed25519, P-256 or RSA');
    const ed = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const lines = ed.split('\n');
    const truncated = [lines[0], lines[1]!.slice(0, 40), lines.at(-2)].join('\n');
    await expect(AgentKey.fromPem(truncated, { kid: 'k' })).rejects.toThrow('not a usable EdDSA private key');
    await expect(AgentKey.fromPem(42 as unknown as string, { kid: 'k' })).rejects.toThrow('must be a string');
  });
});
