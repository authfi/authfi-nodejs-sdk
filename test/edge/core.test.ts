// Runs in the edge-runtime environment (Vercel's EdgeVM): Web APIs only, no Node built-ins. Each
// runtime verifies an EdDSA and an RS256 signature with the keys the core imports, so "EdDSA
// everywhere" is measured here rather than assumed.

import { compactVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { AuthFI, coreOf } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { TestIssuer } from '../support/issuer.js';

describe('the core in an edge runtime', () => {
  it('runs without Node globals', () => {
    expect(typeof (globalThis as { EdgeRuntime?: unknown }).EdgeRuntime).toBe('string');
  });

  for (const alg of ['EdDSA', 'RS256', 'ES256'] as const) {
    it(`imports the published ${alg} key and verifies a signature with it`, async () => {
      const t = await TestIssuer.create();
      const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch });
      const token = await t.sign({}, { alg });
      const { key } = await coreOf(af).keys.key(t.key(alg).kid, alg);
      const { protectedHeader } = await compactVerify(token, key, { algorithms: [alg] });
      expect(protectedHeader.alg).toBe(alg);
      expect(t.fake.requests[0]?.headers.get('user-agent')).toMatch(/^authfi-node\/\S+ \(edge-runtime\)$/);
    });
  }

  it('keeps secrets out of JSON', () => {
    expect(JSON.stringify({ s: new Secret('marker') })).not.toContain('marker');
  });
});
