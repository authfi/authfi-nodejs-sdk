// B3 on a live np project, from the SDK: what a registered agent gets right and what the platform refuses.
// Skipped unless set (a probe project on np, never production):
//
//   AUTHFI_B3_ISSUER   https://probe-c1.np.authfi.io
//   AUTHFI_B3_AGENT_ID the registered agent, agt_…
//   AUTHFI_B3_KEY_FILE its private key (PEM)         AUTHFI_B3_KID the key id registered with it
//   AUTHFI_B3_OUT      optional: where to write the result as JSON
//
// Each refusal is paired with a control that is admitted, so a refusal is the rule and not a dead endpoint:
//   mint      the agent's token is bound to its run key
//   proved    tools/list with the proof is admitted (control)
//   bearer    the same bound token sent as Bearer is refused
//   noproof   `Authorization: DPoP` with no proof is refused
//   replay    a proof sent twice is admitted once
//   htu, htm, ath   a proof for another URL, method or token is refused
//   nonce     informational: identity asks for a nonce once DPOP_NONCE_KEY is set
// No token, key or proof is printed.

import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { asksForNonce } from '../../src/core/dpop.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';

const ISSUER = process.env.AUTHFI_B3_ISSUER?.replace(/\/+$/, '');
const host = ISSUER === undefined ? '' : new URL(ISSUER).hostname;
const live = ISSUER !== undefined && host.endsWith('.np.authfi.io') && ISSUER.startsWith('https://');
const env = (name: string): string => process.env[name] ?? '';

describe.skipIf(!live)('live on np: B3 from the SDK', () => {
  it('admits the proved call and refuses each broken one', async () => {
    const mcp = `${ISSUER}/mcp`;
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
    const mints: { nonceInProof: boolean }[] = [];
    const af = new AuthFI({
      issuer: ISSUER ?? '',
      fetch: (input, init) => {
        if (
          new URL(typeof input === 'string' || input instanceof URL ? input : input.url).pathname ===
          '/oauth/token'
        ) {
          const proof = new Headers(init?.headers).get('dpop') ?? '';
          const claims = JSON.parse(Buffer.from(proof.split('.')[1] ?? 'e30', 'base64url').toString()) as {
            nonce?: unknown;
          };
          mints.push({ nonceInProof: claims.nonce !== undefined });
        }
        return fetch(input, init);
      },
    });
    const key = await AgentKey.fromPem(readFileSync(env('AUTHFI_B3_KEY_FILE'), 'utf8'), {
      kid: env('AUTHFI_B3_KID'),
    });
    const agent = af.agent({ agentId: env('AUTHFI_B3_AGENT_ID'), key });
    const legs: Record<string, { want: string; got: string; ok: boolean }> = {};
    const leg = (name: string, want: string, got: string, ok: boolean): void => {
      legs[name] = { want, got, ok };
    };

    const token = await agent.token();
    const signer = agent.dpop;
    leg(
      'mint',
      'a token bound to the run key',
      signer === undefined ? 'bearer' : 'bound',
      signer !== undefined,
    );
    if (signer === undefined) throw new Error('the token is not bound: nothing to check');

    const post = (headers: Record<string, string>): Promise<Response> =>
      fetch(mcp, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
    const secret = new Secret(token);
    const proof = (method = 'POST', url = mcp, tok = secret): Promise<string> =>
      signer.proof(method, url, tok);
    const dpop = (p: string | undefined): Record<string, string> => ({
      authorization: `DPoP ${token}`,
      ...(p === undefined ? {} : { dpop: p }),
    });
    /** Send once; a nonce challenge is answered once, as the SDK does. */
    const settle = async (make: () => Promise<Record<string, string>>): Promise<Response> => {
      let res = await post(await make());
      if (
        asksForNonce(res.status, res.headers, await res.clone().text()) &&
        signer.rememberNonce(mcp, res.headers)
      ) {
        res = await post(await make());
      }
      return res;
    };

    const control = await settle(async () => dpop(await proof()));
    leg('proved', '200', String(control.status), control.status === 200);
    for (const [name, headers] of Object.entries({
      bearer: { authorization: `Bearer ${token}` },
      noproof: dpop(undefined),
    })) {
      const r = await post(headers);
      leg(name, '401', String(r.status), r.status === 401);
    }
    const replayed = await proof();
    const first = await post(dpop(replayed));
    const second = await post(dpop(replayed));
    leg('replay', 'admitted once', `${first.status} then ${second.status}`, second.status === 401);
    const wrongToken = new Secret(token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA'));
    for (const [name, make] of Object.entries({
      htu: () => proof('POST', `${ISSUER}/mcp/other`),
      htm: () => proof('GET'),
      ath: () => proof('POST', mcp, wrongToken),
    })) {
      const r = await settle(async () => dpop(await make()));
      leg(name, '401', String(r.status), r.status === 401);
    }
    const asked = mints.length > 1 && mints.some((m) => m.nonceInProof);
    leg(
      'nonce',
      'informational: asked once DPOP_NONCE_KEY is set (B3, by 14 Nov)',
      asked ? 'asked and answered' : 'not asked',
      true,
    );

    const out = process.env.AUTHFI_B3_OUT;
    const ok = Object.values(legs).every((l) => l.ok);
    if (out !== undefined && out !== '') {
      writeFileSync(
        out,
        JSON.stringify({ issuer: ISSUER, agent: env('AUTHFI_B3_AGENT_ID'), ok, legs }, null, 2),
      );
    }
    expect(Object.entries(legs).filter(([, l]) => !l.ok)).toEqual([]);
  }, 60_000);
});
