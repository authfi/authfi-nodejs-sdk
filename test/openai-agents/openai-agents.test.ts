// The OpenAI Agents JS adapter, driven through the real `@openai/agents` runner and
// `MCPServerStreamableHttp` against the fake gateway, with a scripted model: what the model is
// told, what the gateway receives, and that only AuthFI's decision lets a held call run.

import {
  Agent,
  MCPServerStreamableHttp,
  run,
  RunState,
  setTracingDisabled,
  Usage,
  type Model,
  type ModelRequest,
  type ModelResponse,
} from '@openai/agents';
import { beforeAll, describe, expect, it } from 'vitest';
import { ApprovalPollRefused, ConfigurationError, GatewayTokenRefused } from '../../src/core/errors.js';
import { createOpenAIAgents, HOLD_MESSAGE, type OpenAIAgentsOptions } from '../../src/openai-agents/index.js';
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

async function setup(
  tool: string,
  args: Record<string, unknown> = { repoName: 'pallets/itsdangerous' },
  options: Partial<OpenAIAgentsOptions> = {},
) {
  const s = await setupGateway();
  const authfi = createOpenAIAgents({
    source: s.agent,
    pollIntervalMs: 100,
    logger: s.logger,
    runId: 'run-1',
    ...options,
  });
  const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
  await server.connect();
  const model = new ScriptedModel(tool, args);
  const agent = new Agent({ name: 'a', instructions: 'x', model, tools: await authfi.tools(server) });
  return { ...s, auth: s.agent, authfi, server, model, agent };
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

describe('waiting for AuthFI inside the tool', () => {
  it('continues by itself when AuthFI approves: no interruption, the call made once with the approval', async () => {
    const t = await setup(CONTENTS, undefined, { waitInTool: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 300);
    const result = await run(t.agent, 'go');
    expect(result.interruptions ?? []).toHaveLength(0);
    expect(String(result.finalOutput)).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    expect(t.model.sawByModel.join()).not.toContain('Waiting for approval');
  });

  it('tells the model plainly, and runs nothing, when AuthFI denies', async () => {
    const t = await setup(CONTENTS, undefined, { waitInTool: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'denied'), 300);
    const result = await run(t.agent, 'go');
    expect(String(result.finalOutput)).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('answers "waiting", never a run, when nobody decides before the timeout', async () => {
    const t = await setup(CONTENTS, undefined, { waitInTool: true, approvalTimeoutMs: 450 });
    const result = await run(t.agent, 'go');
    expect(String(result.finalOutput)).toContain('waiting for a person');
    expect(t.gw.executed).toHaveLength(0);
  });
});

describe('polling the approval route with the agent own token', () => {
  it('asks the gateway twice, not once per interval, and releases the call once approved', async () => {
    const t = await setup(CONTENTS, undefined, { waitInTool: true, approvalPoll: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 450);
    const result = await run(t.agent, 'go');
    expect(String(result.finalOutput)).toContain('1 Overview');
    expect(t.as.approvalPolls).toBeGreaterThanOrEqual(3);
    expect(t.gw.toolCalls()).toHaveLength(2); // the hold, then the release
    expect(t.gw.executed).toHaveLength(1);
  });

  it('is refused for a token held for a person', async () => {
    const s = await setupGateway();
    expect(() =>
      createOpenAIAgents({ source: { gateway: () => s.agent.gateway() }, approvalPoll: true }),
    ).toThrow(ConfigurationError);
  });

  it.each([
    ['forbidden', 403],
    ['unknown', 404],
  ] as const)('ends at once with a distinct error when the route answers %s', async (kind, status) => {
    const t = await setup(CONTENTS, undefined, { approvalPoll: true, approvalTimeoutMs: 60_000 });
    const held = await untilHold(t);
    if (kind === 'forbidden') t.gw.approvalRoute = 'forbidden';
    else t.gw.approvals.clear();
    const began = Date.now();
    await expect(t.authfi.awaitApprovals(held.state)).rejects.toMatchObject({
      name: 'ApprovalPollRefused',
      status,
    });
    expect(Date.now() - began).toBeLessThan(2000);
  });

  it('ends at once when the agent is revoked while the approval is polled (401)', async () => {
    const t = await setup(CONTENTS, undefined, { approvalPoll: true, approvalTimeoutMs: 60_000 });
    const held = await untilHold(t);
    t.gw.revoked = true;
    await expect(t.authfi.awaitApprovals(held.state)).rejects.toBeInstanceOf(ApprovalPollRefused);
  });
});

describe('a revoked agent while a person is being waited on', () => {
  it('ends the wait at once with GatewayTokenRefused, not at the timeout', async () => {
    const t = await setup(CONTENTS, undefined, { approvalTimeoutMs: 60_000 });
    const held = await untilHold(t);
    t.gw.revoked = true;
    const began = Date.now();
    await expect(t.authfi.awaitApprovals(held.state)).rejects.toBeInstanceOf(GatewayTokenRefused);
    expect(Date.now() - began).toBeLessThan(2000);
    expect(t.gw.executed).toHaveLength(0);
  });
});

describe('a restarted process', () => {
  async function restarted(t: Setup, state: string, pending: unknown) {
    const authfi = createOpenAIAgents({
      source: t.auth,
      pollIntervalMs: 100,
      logger: t.logger,
      runId: 'run-2',
    });
    const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
    await server.connect();
    const agent = new Agent({
      name: 'a',
      instructions: 'x',
      model: t.model,
      tools: await authfi.tools(server),
    });
    // What the app kept beside the saved RunState, through JSON as a database would.
    authfi.restorePending(JSON.parse(JSON.stringify(pending)) as never);
    return { authfi, agent, state: await RunState.fromString(agent, state) };
  }

  it('resumes the saved run with the approval id and opens no second approval; the id is never in the model input', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    const saved = held.state.toString();
    const pending = t.authfi.pendingApprovals();
    const approvalId = pending[0]!.approvalId;
    const next = await restarted(t, saved, pending);
    t.gw.decide(approvalId, 'approved');
    expect([...(await next.authfi.awaitApprovals(next.state)).values()]).toEqual(['approved']);
    const done = await run(next.agent, next.state);
    expect(String(done.finalOutput)).toContain('1 Overview');
    expect(t.gw.approvals.size).toBe(1);
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.toolCalls().at(-1)!.args).toMatchObject({ _authfi_approval_id: approvalId });
    expect(t.model.sawByModel.join()).not.toContain(approvalId);
    expect(saved).not.toContain(approvalId);
  });

  it('is told, structurally, to raise the call again when the gateway binds the approval to another run', async () => {
    const t = await setup(CONTENTS);
    const held = await untilHold(t);
    const saved = held.state.toString();
    const pending = t.authfi.pendingApprovals();
    const next = await restarted(t, saved, pending);
    t.gw.decide(pending[0]!.approvalId, 'approved');
    t.gw.otherRun = true;
    expect([...(await next.authfi.awaitApprovals(next.state)).values()]).toEqual(['raise_again']);
    const done = await run(next.agent, next.state);
    expect(t.gw.executed).toHaveLength(0);
    expect(String(done.finalOutput)).toMatch(/another run|Raise the call again/);
  });
});
