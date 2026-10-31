// A model call through the AI gateway proves the key its token is bound to, whichever adapter makes it.
//
// The platform stand-in enforces the gateway's model proof check (MCP_MODEL_PROOF_CHECK=enforce, EMODEL020): a model
// call whose token is bound to nothing is refused. It also demands a DPoP nonce, as the gateway does in production.

import { describe, expect, it } from 'vitest';
import { RunGateway } from '../../src/adapters/shared.js';
import { Secret } from '../../src/core/secret.js';
import { createMastra } from '../../src/mastra/index.js';
import { createVercelAI } from '../../src/vercel-ai/index.js';
import { AGENT } from '../support/fake-platform.js';
import { platform } from '../support/platform-setup.js';

const SECRET = new Secret('s'.repeat(32));

const MESSAGES = JSON.stringify({
  model: 'claude-haiku-5-5',
  max_tokens: 16,
  messages: [{ role: 'user', content: 'hi' }],
});

async function setup() {
  const s = await platform();
  s.p.modelProof = true;
  s.p.nonce = { gateway: 'gn' };
  return s;
}

/** The scheme and proof of every request the gateway saw on one path. */
function seen(s: Awaited<ReturnType<typeof setup>>, path: string) {
  return s.p.t.fake
    .to(`${s.p.issuer}${path}`)
    .map((r) => ({ scheme: r.headers.get('authorization')?.split(' ')[0], proof: r.headers.get('dpop') }));
}

async function post(f: typeof fetch, url: string): Promise<Response> {
  return f(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: MESSAGES });
}

describe('a model call proves the key', () => {
  it('on the Anthropic route, with a proof made for the request, answering the nonce once', async () => {
    const s = await setup();
    const run = new RunGateway({ source: s.agent, logger: { debug() {}, info() {}, warn() {}, error() {} } });
    const { baseURL, fetch } = run.anthropic();

    const res = await post(fetch, `${baseURL}/v1/messages`);

    expect(res.status).toBe(200);
    const sent = seen(s, '/mcp/v1/messages');
    expect(sent).toHaveLength(2); // the nonce challenge, then the call with the nonce
    expect(sent.every((r) => r.scheme === 'DPoP' && r.proof?.startsWith('eyJ'))).toBe(true);
    expect(s.p.unprovenModelCalls).toEqual([]);
    expect(s.p.refusals.filter((x) => !x.includes('nonce'))).toEqual([]);
  });

  it("answers the nonce on a run's very first call, before any token was minted", async () => {
    const s = await setup();
    const run = new RunGateway({ source: s.agent, logger: { debug() {}, info() {}, warn() {}, error() {} } });
    expect(s.agent.dpop).toBeUndefined(); // nothing minted yet: the key is not known until the first token

    const res = await post(run.anthropic().fetch, `${run.gateway.mcpUrl}/v1/messages`);

    expect(res.status).toBe(200);
    expect(seen(s, '/mcp/v1/messages')).toHaveLength(2);
  });

  it('on the OpenAI routes, chat completions and responses', async () => {
    const s = await setup();
    const run = new RunGateway({ source: s.agent, logger: { debug() {}, info() {}, warn() {}, error() {} } });
    const { baseURL, fetch } = run.openai();

    expect((await post(fetch, `${baseURL}/chat/completions`)).status).toBe(200);
    expect((await post(fetch, `${baseURL}/responses`)).status).toBe(200);

    for (const path of ['/mcp/v1/chat/completions', '/mcp/v1/responses']) {
      const sent = seen(s, path);
      expect(sent.length).toBeGreaterThan(0);
      expect(sent.every((r) => r.scheme === 'DPoP' && r.proof?.startsWith('eyJ'))).toBe(true);
    }
    expect(s.p.unprovenModelCalls).toEqual([]);
  });

  it("through the Mastra and Vercel AI adapters' model settings", async () => {
    const s = await setup();
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const mastra = createMastra({ source: s.agent, logger });
    const vercel = createVercelAI({ source: s.agent, logger, approvalSecret: SECRET });

    const openai = mastra.openai();
    expect((await post(openai.fetch, `${openai.baseURL}/chat/completions`)).status).toBe(200);
    const anthropic = vercel.anthropic();
    expect((await post(anthropic.fetch, `${anthropic.baseURL}/messages`)).status).toBe(200);

    expect(s.p.unprovenModelCalls).toEqual([]);
    for (const path of ['/mcp/v1/chat/completions', '/mcp/v1/messages']) {
      expect(seen(s, path).every((r) => r.scheme === 'DPoP' && r.proof !== null)).toBe(true);
    }
  });

  it('is refused for a token bound to nothing, and the SDK says so once (the control leg)', async () => {
    const s = await setup();
    const agent = s.af.agent({ agentId: AGENT, key: s.key, dpop: false });
    const run = new RunGateway({ source: agent, logger: { debug() {}, info() {}, warn() {}, error() {} } });
    const { baseURL, fetch } = run.anthropic();

    for (let i = 0; i < 2; i++) {
      const res = await post(fetch, `${baseURL}/v1/messages`);
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe('EMODEL020');
    }

    expect(s.p.unprovenModelCalls).toEqual(['/mcp/v1/messages', '/mcp/v1/messages']);
    expect(seen(s, '/mcp/v1/messages').every((r) => r.scheme === 'Bearer' && r.proof === null)).toBe(true);
    expect(s.warns.filter((w) => w.includes('MCP_MODEL_PROOF_CHECK'))).toHaveLength(1);
  });

  it('says nothing for a proven call, nor for a tool call that carries no proof', async () => {
    const s = await setup();
    const run = new RunGateway({ source: s.agent, logger: { debug() {}, info() {}, warn() {}, error() {} } });
    const { baseURL, fetch } = run.anthropic();
    await post(fetch, `${baseURL}/v1/messages`);

    const bearer = s.af.agent({ agentId: AGENT, key: s.key, dpop: false });
    const tools = await bearer.gateway().fetch(`${s.p.issuer}/mcp`, {
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(tools.status).toBe(200);

    expect(s.warns.filter((w) => w.includes('MCP_MODEL_PROOF_CHECK'))).toEqual([]);
  });
});
