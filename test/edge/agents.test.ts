// The agent's key and assertion in the edge runtime: generation and signing with Web Crypto only.
import { compactVerify, importJWK, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { clientAssertion } from '../../src/agents/assertion.js';
import { TestClock } from '../support/issuer.js';

describe('agent keys in the edge runtime', () => {
  for (const alg of ['EdDSA', 'ES256', 'PS256'] as const) {
    it(`generates an ${alg} key and signs an assertion its public key verifies`, async () => {
      const key = await AgentKey.generate(alg);
      const assertion = await clientAssertion(
        key,
        'agt_1',
        'https://acme.authfi.io/oauth/token',
        new TestClock(),
      );
      const pub = await importJWK(key.publicJwk() as JWK, alg);
      expect((await compactVerify(assertion.reveal(), pub)).protectedHeader.alg).toBe(alg);
    });
  }
});
