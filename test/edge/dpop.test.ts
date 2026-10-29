// DPoP proof checking, nonces and Shared Signals SET verification in the edge runtime: Web Crypto only.
// The certificate chain proof is exercised in Node (test/containment/chain.test.ts), where the test
// certificates are built.

import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { base64url, sha256, utf8 } from '../../src/core/bytes.js';
import { AuthFI } from '../../src/core/project.js';
import { createRevocationStore } from '../../src/signals/index.js';
import { API, ISSUER, TestClock, TestIssuer } from '../support/issuer.js';

const API_URL = 'https://api.example.com';

async function proofFor(token: string, jwk: unknown, key: CryptoKey, claims: Record<string, unknown> = {}) {
  return new SignJWT({
    htm: 'GET',
    htu: `${API_URL}/orders`,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: base64url(await sha256(utf8(token))),
    ...claims,
  })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: jwk as never })
    .sign(key);
}

describe('DPoP in the edge runtime', () => {
  it('accepts a bound token with its proof, refuses a replay, and hands out a nonce', async () => {
    const t = await TestIssuer.create();
    const clock = new TestClock();
    clock.wall = Date.now();
    const af = new AuthFI({ issuer: ISSUER, fetch: t.fake.fetch, clock });
    const verifier = af.verifier({
      audience: API,
      publicUrl: API_URL,
      nonceKey: 'n'.repeat(32),
      revocations: createRevocationStore({ clock: () => clock.now() }),
    });
    const pair = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(pair.publicKey);
    const token = await t.sign({ cnf: { jkt: await calculateJwkThumbprint(jwk, 'sha256') } });
    const nonce = await verifier.serverNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{16,}$/);
    const request = (proof: string) => ({
      authorization: `DPoP ${token}`,
      dpop: proof,
      method: 'GET',
      url: '/orders',
    });
    // no nonce: refused with the one to send back
    await expect(
      verifier.verifyRequest(request(await proofFor(token, jwk, pair.privateKey))),
    ).rejects.toMatchObject({
      code: 'dpop_proof_nonce_invalid',
      nonce,
    });
    const good = await proofFor(token, jwk, pair.privateKey, { nonce });
    await expect(verifier.verifyRequest(request(good))).resolves.toBeDefined();
    await expect(verifier.verifyRequest(request(good))).rejects.toMatchObject({
      code: 'dpop_proof_replayed',
    });
  });
});
