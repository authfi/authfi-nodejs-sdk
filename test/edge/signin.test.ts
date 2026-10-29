// The pending sign-in's encryption and PKCE in the edge runtime: Web Crypto only.
import { describe, expect, it } from 'vitest';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { TestIssuer } from '../support/issuer.js';

describe('sign-in in the edge runtime', () => {
  it('starts a sign-in and round-trips its encrypted pending state', async () => {
    const t = await TestIssuer.create();
    const af = new AuthFI({ issuer: t.issuer, fetch: t.fake.fetch });
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const web = af.webApp({
      clientId: 'app_web',
      redirectUri: 'https://app.example.com/cb',
      stateKey: new Secret(key),
    });
    const pending = await web.startSignIn();
    const back = await web.loadPending(await pending.dump());
    expect(back.remembered.state).toBe(pending.remembered.state);
    expect(new URL(pending.url).searchParams.get('code_challenge_method')).toBe('S256');
  });
});
