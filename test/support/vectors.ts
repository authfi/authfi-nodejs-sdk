// Runs the conformance vectors (conformance/vectors.json) through the verifier, in whichever runtime
// the test file runs in.

import { expect, it } from 'vitest';
import doc from '../../conformance/vectors.json' with { type: 'json' };
import { AuthFI } from '../../src/core/project.js';
import { TestClock } from './issuer.js';

interface Vector {
  name: string;
  token: string;
  expect:
    | {
        valid: true;
        principal: string;
        token_kind: string;
        actor: string | null;
        client_id?: string;
        scopes?: string[];
      }
    | { valid: false; code: string };
}

export function runVectors(): void {
  const clock = new TestClock();
  clock.wall = doc.now * 1000;
  const fetchDocs: typeof fetch = async (input) => {
    const url = new Request(input).url;
    const body = url.endsWith('/jwks.json')
      ? doc.jwks
      : {
          issuer: doc.issuer,
          token_endpoint: `${doc.issuer}/oauth/token`,
          jwks_uri: `${doc.issuer}/.well-known/jwks.json`,
        };
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  };
  const af = new AuthFI({ issuer: doc.issuer, fetch: fetchDocs, clock, leewayMs: doc.leeway_seconds * 1000 });
  const verifier = af.verifier({ audience: doc.audience, expectedTenantId: doc.tenant_id });

  for (const v of doc.vectors as Vector[]) {
    it(`vector: ${v.name}`, async () => {
      if (v.expect.valid) {
        const token = await verifier.verify(v.token);
        expect(token.principal.toString()).toBe(v.expect.principal);
        expect(token.tokenKind).toBe(v.expect.token_kind);
        expect(token.actor?.toString() ?? null).toBe(v.expect.actor);
        if (v.expect.client_id !== undefined) expect(token.clientId).toBe(v.expect.client_id);
        if (v.expect.scopes !== undefined)
          expect([...token.scopes].sort()).toEqual([...v.expect.scopes].sort());
      } else {
        await expect(verifier.verify(v.token)).rejects.toMatchObject({ code: v.expect.code });
      }
    });
  }
}
