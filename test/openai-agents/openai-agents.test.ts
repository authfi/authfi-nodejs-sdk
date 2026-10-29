// The OpenAI Agents JS adapter, driven through the real `@openai/agents` runner and
// `MCPServerStreamableHttp` against the fake gateway, with a scripted model: what the model is
// told, what the gateway receives, and that only AuthFI's decision lets a held call run.

import {
  Agent,
  MCPServerStreamableHttp,
  run,
  setTracingDisabled,
  Usage,
  type Model,
  type ModelRequest,
  type ModelResponse,
} from '@openai/agents';
import { beforeAll, describe, expect, it } from 'vitest';
import { createOpenAIAgents, HOLD_MESSAGE } from '../../src/openai-agents/index.js';
import { setupGateway } from '../support/adapter-setup.js';
import { CONTENTS, QUESTION, STRUCTURE } from '../support/fake-gateway.js';

beforeAll(() => setTracingDisabled(true));

/** Calls `tool` once with `args`, then repeats whatever the tool said. */
class ScriptedModel implements Model {
  readonly sawByModel: string[] = [];
  constructor(
    private readonly tool: string,
    private readonly args: Record<string, unknown>,
  ) {}

  getResponse(request: ModelRequest): Promise<ModelResponse> {
    const items = Array.isArray(request.input) ? request.input : [];
    const result = items.find((i) => i.type === 'function_call_result');
    this.sawByModel.push(JSON.stringify(items));
    if (result !== undefined) {
      const out = JSON.stringify((result as { output?: unknown }).output);
      return Promise.resolve({
        usage: new Usage(),
        responseId: 'r2',
        output: [
          {
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: `Tool said: ${out}` }],
          },
        ],
      });
    }
    return Promise.resolve({
      usage: new Usage(),
      responseId: 'r1',
      output: [
        {
          type: 'function_call',
          callId: 'call_1',
          name: this.tool,
          arguments: JSON.stringify(this.args),
          status: 'completed',
        },
      ],
    });
  }

  // eslint-disable-next-line require-yield
  async *getStreamedResponse(): AsyncIterable<never> {
    throw new Error('not streamed in these tests');
  }
}

async function setup(tool: string, args: Record<string, unknown> = { repoName: 'pallets/itsdangerous' }) {
  const s = await setupGateway();
  const authfi = createOpenAIAgents({
    source: s.agent,
    pollIntervalMs: 100,
    logger: s.logger,
    runId: 'run-1',
  });
  const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
  await server.connect();
  const model = new ScriptedModel(tool, args);
  const agent = new Agent({ name: 'a', instructions: 'x', model, tools: await authfi.tools(server) });
  return { ...s, authfi, server, model, agent };
}
type Setup = Awaited<ReturnType<typeof setup>>;

async function untilHold(t: Setup) {
  const result = await run(t.agent, 'Read the wiki of pallets/itsdangerous.');
  expect(result.interruptions).toHaveLength(1);
  return result;
}

describe('the tools', () => {
  it('keep the gateway names and send the credential, the run request ids and no API key', async () => {
    const t = await setup(STRUCTURE);
    expect(t.agent.tools.map((x) => x.name).sort()).toEqual([CONTENTS, QUESTION, STRUCTURE].sort());
    const result = await run(t.agent, 'go');
    expect(String(result.finalOutput)).toContain('1 Overview');
    const calls = t.gw.toolCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.authorization).toMatch(/^Bearer /);
    expect(calls[0]!.apiKey).toBeNull();
    expect(calls[0]!.requestId).toMatch(/^run-1\.\d+$/);
    expect(t.authfi.enrichSpan()).toEqual({ 'authfi.agent_id': 'agt_test1', 'authfi.run_id': 'run-1' });
  });

  it('answer a refusal as the tool result, and the run goes on', async () => {
    const t = await setup(QUESTION);
    const result = await run(t.agent, 'go');
    expect(String(result.finalOutput)).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('end the run when AuthFI refuses the token itself, and never run the tool', async () => {
    const t = await setup(STRUCTURE);
    t.gw.revoked = true;
    await expect(run(t.agent, 'go')).rejects.toThrow(/gateway refused the token/);
    expect(t.gw.executed).toHaveLength(0);
  });
});

describe('a held call', () => {
  it('interrupts the run through needsApproval, with the gateway call made once', async () => {
    const t = await setup(CONTENTS);
    await untilHold(t);
    expect(t.gw.pending()).toHaveLength(1);
    expect(t.authfi.pendingApprovals()).toHaveLength(1);
    expect(t.gw.executed).toHaveLength(0);
    expect(t.gw.toolCalls()).toHaveLength(1);
  });

  it('runs once when AuthFI approves, with one approval opened and the hold text never given to the model', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    const decisions = await t.authfi.awaitApprovals(held.state);
    expect([...decisions.values()]).toEqual(['approved']);
    const done = await run(t.agent, held.state);
    expect(String(done.finalOutput)).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    expect(t.model.sawByModel.join()).not.toContain('Waiting for approval');
  });

  it('is refused when AuthFI denies it: nothing runs and the model is told so', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    t.gw.decide(t.gw.pending()[0]!, 'denied');
    expect([...(await t.authfi.awaitApprovals(held.state)).values()]).toEqual(['denied']);
    const done = await run(t.agent, held.state);
    expect(t.gw.executed).toHaveLength(0);
    expect(String(done.finalOutput)).toMatch(/did not approve|Refused/);
  });

  it('is never run by an app that approves before AuthFI did', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    for (const item of held.state.getInterruptions()) held.state.approve(item);
    const done = await run(t.agent, held.state);
    expect(t.gw.executed).toHaveLength(0);
    expect(JSON.stringify(done.finalOutput)).toContain(HOLD_MESSAGE.slice(0, 20));
    expect(t.gw.approvals.size).toBe(1);
  });

  it('rejects, never approves, a call still undecided at the timeout', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    const decisions = await t.authfi.awaitApprovals(held.state, {
      timeoutMs: 450,
      sleep: () => Promise.resolve(),
    });
    expect([...decisions.values()]).toEqual(['pending']);
    const done = await run(t.agent, held.state);
    expect(t.gw.executed).toHaveLength(0);
    expect(String(done.finalOutput)).toContain('not been approved');
  });
});

describe('the clients the adapter builds', () => {
  it('point an OpenAI client at the project, with a placeholder key replaced by the credential', async () => {
    const t = await setup(STRUCTURE);
    expect(t.authfi.openai()).toMatchObject({ baseURL: `${t.as.issuer}/mcp/v1`, apiKey: 'authfi' });
    expect(t.authfi.mcpServerOptions('x')).toMatchObject({ name: 'x', url: `${t.as.issuer}/mcp` });
  });

  it('take only a connected MCP server that can return full results', async () => {
    const t = await setup(STRUCTURE);
    await expect(t.authfi.tools({ listTools: () => Promise.resolve([]) })).rejects.toThrow(
      /connected MCPServerStreamableHttp/,
    );
  });
});
