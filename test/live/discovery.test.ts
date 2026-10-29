// Live against a real project (platform-beta in CI). Needs no credential: discovery, the key set, and
// the verifier's refusals of tokens the project never issued. Skipped unless AUTHFI_LIVE_ISSUER is set.

import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import { coreOf } from '../../src/core/project.js';
import { unsignedJwt } from '../support/issuer.js';

const issuer = process.env.AUTHFI_LIVE_ISSUER;

describe.skipIf(issuer === undefined)('live: discovery and keys', () => {
  const af = new AuthFI({ issuer: issuer ?? 'https://unset.invalid' });

  it('reads the discovery document and learns the API origin', async () => {
    const meta = await af.metadata();
    expect(meta.issuer).toBe(issuer);
    expect(meta.token_endpoint).toBe(`${issuer}/oauth/token`);
    expect(af.apiOrigin).toBe(new URL(meta.backchannel_authentication_endpoint ?? issuer!).origin);
  });

  it('imports the published Ed25519 and RSA keys', async () => {
    const meta = await af.metadata();
    const jwks = (await (await fetch(meta.jwks_uri)).json()) as {
      keys: { kid: string; kty: string; alg?: string }[];
    };
    for (const k of jwks.keys) {
      const alg = k.kty === 'OKP' ? 'EdDSA' : k.kty === 'EC' ? 'ES256' : 'RS256';
      expect((await coreOf(af).keys.key(k.kid, alg)).alg).toBe(alg);
    }
  });

  it('refuses a token signed with a published kid but no valid signature', async () => {
    const verifier = af.verifier({ audience: 'api_live_probe' });
    const meta = await af.metadata();
    const jwks = (await (await fetch(meta.jwks_uri)).json()) as { keys: { kid: string; kty: string }[] };
    const rsa = jwks.keys.find((k) => k.kty === 'RSA')!;
    const forged = unsignedJwt(
      { alg: 'RS256', typ: 'at+jwt', kid: rsa.kid },
      { iss: issuer, sub: 'x', aud: 'api_live_probe', exp: 9e9, tenant_id: 't' },
      'AAAA',
    );
    await expect(verifier.verify(forged)).rejects.toMatchObject({ code: 'token_signature_invalid' });
    await expect(
      verifier.verify(unsignedJwt({ alg: 'RS256', typ: 'at+jwt', kid: 'invented' }, {})),
    ).rejects.toMatchObject({ code: 'token_key_unknown' });
  });
});
