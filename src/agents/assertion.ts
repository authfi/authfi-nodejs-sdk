import { base64url, randomBytes, utf8 } from '../core/bytes.js';
import type { Clock } from '../core/clock.js';
import { Secret } from '../core/secret.js';
import type { Signer } from './agent-key.js';

/** The platform refuses an assertion that claims to live longer than five minutes. */
export const MAX_ASSERTION_SECONDS = 300;

/**
 * One RFC 7523 client assertion: `iss` and `sub` are the agent, `aud` the token endpoint, a fresh
 * `jti`, and five minutes of life. Built per attempt, so a retry never reuses a `jti`. `confirmation`
 * is a `cnf` claim (`{ jkt }`) naming the DPoP key that will hold what the assertion asks for, as a
 * mandate's start does.
 */
export async function clientAssertion(
  signer: Signer,
  agentId: string,
  audience: string,
  clock: Clock,
  confirmation?: { readonly jkt: string },
): Promise<Secret> {
  const iat = Math.floor(clock.now() / 1000);
  const header = { alg: signer.alg, typ: 'JWT', kid: signer.kid };
  const payload = {
    iss: agentId,
    sub: agentId,
    aud: audience,
    jti: base64url(randomBytes(18)),
    iat,
    exp: iat + MAX_ASSERTION_SECONDS,
    ...(confirmation === undefined ? {} : { cnf: { jkt: confirmation.jkt } }),
  };
  const input = `${base64url(utf8(JSON.stringify(header)))}.${base64url(utf8(JSON.stringify(payload)))}`;
  const signature = await signer.sign(utf8(input));
  return new Secret(`${input}.${base64url(signature)}`);
}
