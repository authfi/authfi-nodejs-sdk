import { AuthFI, coreOf } from '../../src/core/project.js';
import { requestToken, type TokenResponse } from '../../src/core/oauth.js';
import { Secret } from '../../src/core/secret.js';
import { TestClock, type TestIssuer } from './issuer.js';

/** One client-credentials request against a test issuer, through the real core. */
export async function requireToken(
  t: TestIssuer,
  options: { retries?: number } = {},
): Promise<TokenResponse> {
  const af = new AuthFI({
    issuer: t.issuer,
    fetch: t.fake.fetch,
    clock: new TestClock(),
    retries: options.retries ?? 2,
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  const meta = await af.metadata();
  return requestToken(
    coreOf(af).transport,
    {
      tokenEndpoint: meta.token_endpoint,
      params: { grant_type: 'client_credentials' },
      auth: { method: 'client_secret_basic', clientId: 'm2m', clientSecret: new Secret('s') },
      retry: 'unsafe',
    },
    () => Date.now(),
  );
}
