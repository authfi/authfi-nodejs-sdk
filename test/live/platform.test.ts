// Live against a real project, as an administrator through the console API. Skipped unless set:
//
//   AUTHFI_LIVE_ISSUER                 the project, e.g. https://platform-beta.authfi.io
//   AUTHFI_LIVE_CONSOLE_TOKEN_FILE     a console token of a probe administrator (never a real person)
//   AUTHFI_LIVE_PERSON_DIR             optional: a directory shared with the harness, which plays the
//                                      sign-in page for the probe person in the people's sign-in leg
//
// It registers one agent and one web app, and removes them, and the delegation it grants, whatever
// the outcome. No token, key or secret is printed.

import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { compactVerify, decodeJwt, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import type { AgentAuth } from '../../src/agents/agent.js';
import { isAuthFIError } from '../../src/core/errors.js';
import { AuthFI, coreOf } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';

const ISSUER = process.env.AUTHFI_LIVE_ISSUER;
const TOKEN_FILE = process.env.AUTHFI_LIVE_CONSOLE_TOKEN_FILE;
const PERSON_DIR = process.env.AUTHFI_LIVE_PERSON_DIR;
const live = ISSUER !== undefined && TOKEN_FILE !== undefined;
const RUN = Math.random().toString(16).slice(2, 8);
const read = (path: string) => readFileSync(path, 'utf8').trim();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function gql<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(`${ISSUER}/graphql`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${read(TOKEN_FILE!)}` },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await res.json()) as { data?: T; errors?: unknown };
  if (!res.ok || body.errors !== undefined)
    throw new Error(`console API ${res.status}: ${JSON.stringify(body.errors ?? body).slice(0, 300)}`);
  return body.data as T;
}

describe.skipIf(!live)('live: agents, the gateway and people on a real project', () => {
  const af = new AuthFI({ issuer: ISSUER ?? 'https://unset.invalid', userAgentSuffix: `sdk-live/${RUN}` });
  let me: { id: string; email: string };
  let agentId = '';
  let key: AgentKey;
  let agent: AgentAuth;
  const cleanups: (() => Promise<unknown>)[] = [];

  beforeAll(async () => {
    me = (await gql<{ me: { id: string; email: string } }>('{ me { id email } }')).me;
    key = await AgentKey.generate('EdDSA', { kid: `sdk-live-${RUN}` });
    const out = await gql<{ registerAgent: { id: string } }>(
      'mutation($i:RegisterAgentInput!){ registerAgent(input:$i){ id } }',
      {
        i: {
          name: `sdk-live-${RUN}`,
          type: 'delegated',
          publicJwk: JSON.stringify(key.publicJwk()),
          jwkKid: key.kid,
          ownerUserId: me.id,
        },
      },
    );
    agentId = out.registerAgent.id;
    cleanups.push(() => gql('mutation($id:ID!){ deleteAgent(id:$id) }', { id: agentId }));
    agent = af.agent({ agentId, key });
  }, 60_000);

  afterAll(async () => {
    for (const c of cleanups.reverse())
      await c().catch((e: unknown) => console.error('cleanup:', (e as Error).message));
  }, 60_000);

  it("mints the agent's own token with its key, and the token verifies under the issuer's EdDSA key", async () => {
    const token = await agent.token();
    const header = decodeProtectedHeader(token);
    expect(header.alg).toBe('EdDSA');
    const { key: pub } = await coreOf(af).keys.key(String(header.kid), 'EdDSA');
    await compactVerify(token, pub, { algorithms: ['EdDSA'] });
    const claims = decodeJwt(token);
    expect(claims).toMatchObject({ iss: ISSUER, sub: agentId });
    expect(claims.tenant_id).toBeTypeOf('string');
    expect(await agent.token()).toBe(token);
    console.log(
      `  agent token ok: aud=${JSON.stringify(claims.aud)} capabilities=${[...(await agent.capabilities())].length}`,
    );
  });

  it('a key the project never registered is refused as invalid_client', async () => {
    const impostor = af.agent({ agentId, key: await AgentKey.generate('EdDSA', { kid: key.kid }) });
    await expect(impostor.token()).rejects.toMatchObject({ name: 'OAuthError', code: 'invalid_client' });
  });

  it('the gateway lists tools and answers an ungranted call as a refusal value, not an exception', async () => {
    const gateway = agent.gateway();
    const rpc = async (body: unknown) =>
      (await (
        await gateway.fetch(gateway.mcpUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
          body: JSON.stringify(body),
        })
      ).json()) as {
        result?: { tools?: { name: string; _meta?: Record<string, unknown> }[] } & Record<string, unknown>;
      };
    const list = await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const tools = list.result?.tools ?? [];
    console.log(
      `  tools/list: ${tools.length} tools; scopes ${tools
        .slice(0, 3)
        .map((t) => gateway.scopeOf(t))
        .join(', ')}`,
    );
    if (tools.length === 0) return;
    const call = await rpc({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: tools[0]!.name, arguments: {} },
    });
    const outcome = gateway.readResult(call.result);
    console.log(
      `  tools/call ${tools[0]!.name}: ${outcome.kind}${outcome.kind === 'refused' ? ` (${String(outcome.error)}, ${String(outcome.code)})` : ''}`,
    );
    expect(outcome.kind).not.toBe('allowed');
  });

  it('a cloud credential for a role the agent is not granted is refused with a code', async () => {
    const out = await agent
      .gateway()
      .cloudCredentials({ account: `sdk-live-${RUN}`, role: 'none' })
      .catch((e: unknown) => e);
    console.log(
      `  cloud credentials: ${isAuthFIError(out) ? `${out.name} ${String(out.code)} (${String(out.status)})` : JSON.stringify(out)}`,
    );
    expect(isAuthFIError(out) ? out.name : (out as { kind: string }).kind).toMatch(
      /APIError|approval_required/,
    );
  });

  it('token exchange: refused without a delegation, then sub is the person and act.sub the agent', async () => {
    const personToken = new Secret(read(TOKEN_FILE!));
    await expect(agent.exchange(personToken)).rejects.toMatchObject({ code: 'access_denied' });
    const sub = String(decodeJwt(personToken.reveal()).sub);
    const person = sub.startsWith('user:') ? sub : `user:${sub}`;
    await gql('mutation($a:ID!,$o:String!){ grantXaaDelegation(agentId:$a, object:$o) }', {
      a: agentId,
      o: person,
    });
    cleanups.push(() =>
      gql('mutation($a:ID!,$o:String!){ revokeXaaDelegation(agentId:$a, object:$o) }', {
        a: agentId,
        o: person,
      }),
    );
    let delegated;
    for (let i = 0; i < 5 && delegated === undefined; i++) {
      await sleep(1500);
      delegated = await agent
        .exchange(personToken)
        .catch((e: unknown) =>
          isAuthFIError(e) && e.code === 'access_denied' ? undefined : Promise.reject(e as Error),
        );
    }
    expect(delegated?.via).toBe('exchange');
    expect(delegated?.actor?.toString()).toMatch(new RegExp(`${agentId}$`));
    expect(delegated?.subject?.toString()).toBe(person);
  });

  async function decide(bindingMessage: string, decision: 'APPROVE' | 'DENY'): Promise<boolean> {
    for (let i = 0; i < 20; i++) {
      await sleep(1500);
      const reqs = (
        await gql<{ myAgentRequests: { authReqId: string; agentId: string; bindingMessage: string }[] }>(
          '{ myAgentRequests { authReqId agentId bindingMessage } }',
        )
      ).myAgentRequests;
      const mine = reqs.find((r) => r.agentId === agentId && r.bindingMessage === bindingMessage);
      if (mine !== undefined) {
        await gql(
          'mutation($id:ID!,$d:ApprovalDecision!){ decideMyAgentRequest(authReqId:$id, decision:$d){ status } }',
          { id: mine.authReqId, d: decision },
        );
        return true;
      }
    }
    return false;
  }

  it('CIBA: the person approves on their own channel, and the agent holds a token naming both', async () => {
    const bindingMessage = `SDK live ${RUN}: let the test agent act for you`;
    const request = await agent.requestUserToken({
      loginHint: me.email,
      bindingMessage,
      expiresInSeconds: 300,
    });
    const waiting = agent.awaitUserToken(request, { timeoutMs: 120_000 });
    expect(await decide(bindingMessage, 'APPROVE')).toBe(true);
    const token = await waiting;
    expect(token.via).toBe('ciba');
    expect(token.actor?.toString()).toBe(`agent:${agentId}`);
    expect(token.subject?.kind).toBe('user');
  }, 180_000);

  it('CIBA: a person who says no is ConsentDenied, not a timeout', async () => {
    const bindingMessage = `SDK live ${RUN}: deny this one`;
    const request = await agent.requestUserToken({
      loginHint: me.email,
      bindingMessage,
      expiresInSeconds: 300,
    });
    const waiting = agent.awaitUserToken(request, { timeoutMs: 120_000 });
    expect(await decide(bindingMessage, 'DENY')).toBe(true);
    await expect(waiting).rejects.toMatchObject({ name: 'ConsentDenied' });
  }, 180_000);

  it('an approval opens once; its status is NotSupportedError until the project opens it to agents', async () => {
    const approval = await agent.requestApproval(`sdk-live-${RUN}.check`, {
      context: { run: RUN },
      expiresInSeconds: 60,
    });
    expect(approval.status).toBe('pending');
    const status = await agent.approval(approval.id).catch((e: unknown) => e);
    console.log(
      `  approval ${approval.status}; status read: ${isAuthFIError(status) ? `${status.name} ${(status as { feature?: string }).feature ?? status.code}` : (status as { status: string }).status}`,
    );
    expect(
      isAuthFIError(status, 'NotSupportedError') || (status as { status?: string }).status === 'pending',
    ).toBe(true);
  });

  it('the action gate answers with a typed decision or a coded refusal', async () => {
    const out = await agent
      .transactionToken(`sdk-live-${RUN}.read`, { resource: 'sdk-live', context: { n: 1 } })
      .then((txn) => agent.authorizeAction(txn))
      .catch((e: unknown) => e);
    console.log(
      `  action gate: ${isAuthFIError(out) ? `${out.name} ${String(out.code)}` : JSON.stringify(out)}`,
    );
    expect(isAuthFIError(out) ? out.name : (out as { decision: string }).decision).toMatch(
      /APIError|allow|deny|approval_required/,
    );
  });

  describe.skipIf(PERSON_DIR === undefined)("a person's sign-in to a web app", () => {
    it('signs in with PKCE, verifies the ID token, refreshes, and signs out with the refresh token revoked', async () => {
      const redirectUri = `https://sdk-live-${RUN}.example.com/callback`;
      const created = await gql<{
        createApplication: { application: { id: string; clientId: string }; clientSecret: string };
      }>(
        'mutation($i:CreateApplicationInput!){ createApplication(input:$i){ application { id clientId } clientSecret } }',
        { i: { name: `sdk-live-${RUN}`, type: 'web', redirectUris: [redirectUri] } },
      );
      const app = created.createApplication;
      cleanups.push(() => gql('mutation($id:ID!){ deleteApplication(id:$id) }', { id: app.application.id }));
      const stateKey = new Secret(btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))));
      const web = af.webApp({
        clientId: app.application.clientId,
        clientSecret: new Secret(app.clientSecret),
        redirectUri,
        stateKey,
      });
      const pending = await web.loadPending(await (await web.startSignIn()).dump());

      // The sign-in page's part, played by the harness: the probe person signs in to this app and
      // the browser comes back with a code.
      const request = `${PERSON_DIR!}/authorize-request`;
      const answer = `${PERSON_DIR!}/sign-in-callback`;
      writeFileSync(request, JSON.stringify({ url: pending.url }), { mode: 0o600 });
      let callback = '';
      for (let i = 0; i < 60 && callback === ''; i++) {
        await sleep(1000);
        if (existsSync(answer)) callback = read(answer);
      }
      rmSync(answer, { force: true });
      expect(callback, 'the harness answered no callback').not.toBe('');

      const { tokens, user } = await web.finishSignIn(callback, pending);
      expect(user.sub).toBeTypeOf('string');
      expect(tokens.refreshToken).toBeDefined();
      const refreshed = await web.refresh(tokens);
      expect(refreshed.refreshToken?.reveal()).not.toBe(tokens.refreshToken?.reveal());
      expect((await web.userinfo(refreshed)).sub).toBe(user.sub);
      const end = await web.signOut(refreshed);
      expect(end).toContain('/oauth/logout');
      await expect(web.refresh(refreshed)).rejects.toMatchObject({ code: 'invalid_grant' });
      // The spent token from before the refresh is refused too (rotation).
      await expect(web.refresh(tokens)).rejects.toMatchObject({ code: 'invalid_grant' });
      console.log(
        `  sign-in ok: sub=${user.sub.slice(0, 6)}… acr=${String(user.acr)}; refresh rotated; sign-out revoked the refresh token`,
      );
    }, 120_000);
  });
});
