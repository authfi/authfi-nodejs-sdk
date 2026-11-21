// The Mastra adapter, driven through the real `@mastra/mcp` MCPClient against the fake gateway:
// what a tool answers, what the gateway receives, and that only AuthFI's decision lets a held
// call run. The approval functions are called as Mastra's tool-call step calls them.

import { Mastra } from '@mastra/core';
import { Agent } from '@mastra/core/agent';
import { InMemoryStore } from '@mastra/core/storage';
import { MCPClient } from '@mastra/mcp';
import { simulateReadableStream } from 'ai';
import { MockLanguageModelV4 } from 'ai/test';
import { describe, expect, it } from 'vitest';
import { ApprovalPollRefused, GatewayTokenRefused } from '../../src/core/errors.js';
import { createMastra, HOLD_MESSAGE, type MastraOptions } from '../../src/mastra/index.js';
import { setupGateway } from '../support/adapter-setup.js';
import { CONTENTS, QUESTION, STRUCTURE } from '../support/fake-gateway.js';

interface MastraTool {
  execute(input: unknown, context?: unknown): Promise<{ content?: { text?: string }[]; isError?: boolean }>;
  needsApprovalFn?(input: unknown, ctx?: unknown): Promise<boolean>;
  requireApproval?: boolean;
}

async function setup(options: Partial<MastraOptions> = {}) {
  const s = await setupGateway();
  const authfi = createMastra({
    source: s.agent,
    pollIntervalMs: 100,
    logger: s.logger,
    runId: 'run-1',
    ...options,
  });
  const mcp = new MCPClient({ id: `t-${Math.random()}`, servers: { authfi: authfi.mcpServer() } });
  const tools = authfi.tools(await mcp.listTools()) as Record<string, MastraTool>;
  return { ...s, authfi, mcp, tools };
}
type Setup = Awaited<ReturnType<typeof setup>>;

const ARGS = { repoName: 'pallets/itsdangerous' };
const name = (tool: string) => `authfi_${tool}`;
const said = (r: { content?: { text?: string }[] }): string => (r.content ?? []).map((c) => c.text).join('');

/** What Mastra's tool-call step does with a tool: ask whether it needs approval, then run it. */
async function step(t: Setup, tool: string, toolCallId = 'call_1') {
  const mt = t.tools[name(tool)]!;
  const ctx = { toolCallId };
  const approval = await mt.needsApprovalFn!(ARGS, ctx);
  return { approval, run: () => mt.execute(ARGS, ctx) };
}

describe('the tools', () => {
  it('keep Mastra names and send the credential, the run request ids and no API key', async () => {
    const t = await setup();
    expect(Object.keys(t.tools).sort()).toEqual([name(CONTENTS), name(QUESTION), name(STRUCTURE)].sort());
    const s = await step(t, STRUCTURE);
    expect(s.approval).toBe(false);
    expect(said(await s.run())).toContain('1 Overview');
    const calls = t.gw.toolCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.authorization).toMatch(/^Bearer /);
    expect(calls[0]!.apiKey).toBeNull();
    expect(calls[0]!.requestId).toMatch(/^run-1\.\d+$/);
    expect(t.authfi.enrichSpan()).toEqual({ 'authfi.agent_id': 'agt_test1', 'authfi.run_id': 'run-1' });
    await t.mcp.disconnect();
  });

  it('answer a refusal as the tool result, not an exception', async () => {
    const t = await setup();
    const s = await step(t, QUESTION);
    expect(s.approval).toBe(false);
    const r = await s.run();
    expect(r.isError).toBe(true);
    expect(said(r)).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
    await t.mcp.disconnect();
  });

  it('end the run when AuthFI refuses the token itself', async () => {
    const t = await setup();
    t.gw.revoked = true;
    await expect(t.tools[name(STRUCTURE)]!.execute(ARGS, { toolCallId: 'c' })).rejects.toThrow(
      /refused the token/,
    );
    await t.mcp.disconnect();
  });

  it('send every tool through approval, so none is skipped by an allow rule', async () => {
    const t = await setup();
    for (const tool of Object.values(t.tools)) expect(tool.requireApproval).toBe(true);
    await t.mcp.disconnect();
  });
});

describe('a held call', () => {
  it('asks Mastra for approval, with the gateway call made once', async () => {
    const t = await setup();
    const s = await step(t, CONTENTS);
    expect(s.approval).toBe(true);
    expect(t.gw.pending()).toHaveLength(1);
    expect(t.authfi.pendingApprovals()).toHaveLength(1);
    expect(t.gw.executed).toHaveLength(0);
    await t.mcp.disconnect();
  });

  it('runs once when AuthFI approves, with one approval opened and the hold text never given to the model', async () => {
    const t = await setup();
    const s = await step(t, CONTENTS);
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    expect([...(await t.authfi.awaitApprovals()).values()]).toEqual(['approved']);
    const r = await s.run();
    expect(said(r)).toContain('1 Overview');
    expect(said(r)).not.toContain('Waiting for approval');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    await t.mcp.disconnect();
  });

  it('is refused when AuthFI denies it: nothing runs', async () => {
    const t = await setup();
    const s = await step(t, CONTENTS);
    t.gw.decide(t.gw.pending()[0]!, 'denied');
    expect([...(await t.authfi.awaitApprovals()).values()]).toEqual(['denied']);
    expect(said(await s.run())).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
    await t.mcp.disconnect();
  });

  it('is never run by an app that approves before AuthFI did', async () => {
    const t = await setup();
    const s = await step(t, CONTENTS);
    const r = await s.run(); // Mastra runs the tool once the app approved
    expect(said(r)).toBe(HOLD_MESSAGE);
    expect(t.gw.executed).toHaveLength(0);
    expect(t.gw.approvals.size).toBe(1);
    await t.mcp.disconnect();
  });

  it('stops waiting at the timeout without answering for AuthFI', async () => {
    const t = await setup();
    await step(t, CONTENTS);
    const decisions = await t.authfi.awaitApprovals({ timeoutMs: 450, sleep: () => Promise.resolve() });
    expect([...decisions.values()]).toEqual(['pending']);
    expect(t.gw.executed).toHaveLength(0);
    await t.mcp.disconnect();
  });

  it('keeps two calls with the same arguments apart when Mastra names them', async () => {
    const t = await setup();
    await step(t, CONTENTS, 'call_1');
    await step(t, CONTENTS, 'call_2');
    expect(t.gw.approvals.size).toBe(2);
    await t.mcp.disconnect();
  });
});

describe('the settings', () => {
  it('point an OpenAI-compatible model at the project and refuse AuthFI-less origins', async () => {
    const t = await setup();
    expect(t.authfi.openai()).toMatchObject({ baseURL: `${t.as.issuer}/mcp/v1`, apiKey: 'authfi' });
    await expect(t.authfi.fetch('https://example.com/mcp')).rejects.toThrow();
    expect(() => t.authfi.tools(null as never)).toThrow(/mcp.listTools/);
    expect(() => t.authfi.tools({ x: {} })).toThrow(/no execute function/);
    await t.mcp.disconnect();
  });
});

/** A model that calls `tool` once, then says "done". */
function scriptedModel(tool: string) {
  let n = 0;
  const usage = {
    inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
    outputTokens: { total: 1, text: 1, reasoning: 0 },
  };
  const stop = { unified: 'stop', raw: 'stop' };
  return new MockLanguageModelV4({
    doGenerate: () => {
      n++;
      return Promise.resolve(
        (n === 1
          ? {
              content: [
                { type: 'tool-call', toolCallId: 'call_1', toolName: tool, input: JSON.stringify(ARGS) },
              ],
              finishReason: { unified: 'tool-calls', raw: 'tool_calls' },
              usage,
              warnings: [],
            }
          : { content: [{ type: 'text', text: 'done' }], finishReason: stop, usage, warnings: [] }) as never,
      );
    },
    doStream: () =>
      Promise.resolve({
        stream: simulateReadableStream({
          chunks: [
            { type: 'stream-start', warnings: [] },
            { type: 'text-start', id: 't' },
            { type: 'text-delta', id: 't', delta: 'done' },
            { type: 'text-end', id: 't' },
            { type: 'finish', finishReason: stop, usage },
          ] as never,
        }),
      }),
  });
}

async function agentSetup(tool: string) {
  const t = await setup();
  const agent = new Agent({
    id: 'a',
    name: 'a',
    instructions: 'x',
    model: scriptedModel(name(tool)),
    tools: t.tools as never,
  });
  new Mastra({ agents: { a: agent }, storage: new InMemoryStore() });
  return { ...t, agent };
}

async function finish(stream: unknown): Promise<string> {
  return (await (stream as { getFullOutput(): Promise<{ text: string }> }).getFullOutput()).text;
}

describe('in a Mastra agent', () => {
  it('runs an allowed tool through the agent once', async () => {
    const t = await agentSetup(STRUCTURE);
    const out = await t.agent.generate('go');
    expect(out.text).toBe('done');
    expect(t.gw.executed).toHaveLength(1);
    await t.mcp.disconnect();
  });

  it('suspends a held call for approval, and runs it once after AuthFI approved', async () => {
    const t = await agentSetup(CONTENTS);
    const out = await t.agent.generate('go');
    expect(out.finishReason).toBe('suspended');
    expect(t.gw.executed).toHaveLength(0);
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    await t.authfi.awaitApprovals();
    expect(await finish(await t.agent.approveToolCall({ runId: out.runId } as never))).toBe('done');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    await t.mcp.disconnect();
  });

  it('does not run a call the app approved before AuthFI did', async () => {
    const t = await agentSetup(CONTENTS);
    const out = await t.agent.generate('go');
    await finish(await t.agent.approveToolCall({ runId: out.runId } as never));
    expect(t.gw.executed).toHaveLength(0);
    expect(t.gw.approvals.size).toBe(1);
    await t.mcp.disconnect();
  });
});

describe('waiting for AuthFI inside the tool', () => {
  it('continues by itself when AuthFI approves: no approval is asked of the app, the call runs once', async () => {
    const t = await setup({ waitInTool: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 300);
    const s = await step(t, CONTENTS);
    expect(s.approval).toBe(false);
    expect(said(await s.run())).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    await t.mcp.disconnect();
  });

  it('answers the refusal when AuthFI denies, and "waiting" when nobody decides in time', async () => {
    const t = await setup({ waitInTool: true, approvalTimeoutMs: 450 });
    const s = await step(t, CONTENTS);
    expect(said(await s.run())).toBe(HOLD_MESSAGE);
    const t2 = await setup({ waitInTool: true });
    setTimeout(() => t2.gw.decide(t2.gw.pending()[0]!, 'denied'), 300);
    const d = await step(t2, CONTENTS);
    expect(said(await d.run())).toContain('Refused');
    expect(t.gw.executed.length + t2.gw.executed.length).toBe(0);
    await t.mcp.disconnect();
    await t2.mcp.disconnect();
  });

  it('polls the approval route with the agent own token and asks the gateway only to release the call', async () => {
    const t = await setup({ waitInTool: true, approvalPoll: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 450);
    const s = await step(t, CONTENTS);
    expect(said(await s.run())).toContain('1 Overview');
    expect(t.as.approvalPolls).toBeGreaterThanOrEqual(3);
    expect(t.gw.toolCalls()).toHaveLength(2);
    await t.mcp.disconnect();
  });
});

describe('a revoked agent while a person is being waited on', () => {
  it('ends the wait at once with GatewayTokenRefused, or ApprovalPollRefused when the approval route is polled', async () => {
    const t = await setup({ approvalTimeoutMs: 60_000 });
    await step(t, CONTENTS);
    t.gw.revoked = true;
    await expect(t.authfi.awaitApprovals()).rejects.toBeInstanceOf(GatewayTokenRefused);
    const p = await setup({ approvalTimeoutMs: 60_000, approvalPoll: true });
    await step(p, CONTENTS);
    p.gw.revoked = true;
    await expect(p.authfi.awaitApprovals()).rejects.toBeInstanceOf(ApprovalPollRefused);
    await t.mcp.disconnect();
    await p.mcp.disconnect();
  });
});

describe('a restarted process', () => {
  async function restarted(t: Setup) {
    const authfi = createMastra({ source: t.agent, pollIntervalMs: 100, logger: t.logger, runId: 'run-2' });
    const mcp = new MCPClient({ id: `t-${Math.random()}`, servers: { authfi: authfi.mcpServer() } });
    const tools = authfi.tools(await mcp.listTools()) as Record<string, MastraTool>;
    // What the app kept beside Mastra's suspended run, through JSON as a database would.
    authfi.restorePending(JSON.parse(JSON.stringify(t.authfi.pendingApprovals())) as never);
    return { authfi, tools, mcp };
  }

  it('resumes the suspended call with the approval id and opens no second approval', async () => {
    const t = await setup();
    await step(t, CONTENTS);
    const approvalId = t.gw.pending()[0]!;
    const next = await restarted(t);
    t.gw.decide(approvalId, 'approved');
    expect([...(await next.authfi.awaitApprovals()).values()]).toEqual(['approved']);
    const resumed = await next.tools[name(CONTENTS)]!.needsApprovalFn!(ARGS, { toolCallId: 'call_1' });
    expect(resumed).toBe(false);
    const r = await next.tools[name(CONTENTS)]!.execute(ARGS, { toolCallId: 'call_1' });
    expect(said(r)).toContain('1 Overview');
    expect(t.gw.approvals.size).toBe(1);
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.toolCalls().at(-1)!.args).toMatchObject({ _authfi_approval_id: approvalId });
    await t.mcp.disconnect();
    await next.mcp.disconnect();
  });

  it('is told, structurally, to raise the call again when the gateway binds the approval to another run', async () => {
    const t = await setup();
    await step(t, CONTENTS);
    const next = await restarted(t);
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    t.gw.otherRun = true;
    expect([...(await next.authfi.awaitApprovals()).values()]).toEqual(['raise_again']);
    const r = await next.tools[name(CONTENTS)]!.execute(ARGS, { toolCallId: 'call_1' });
    expect(said(r)).toContain('Raise the call again');
    expect(t.gw.executed).toHaveLength(0);
    await t.mcp.disconnect();
    await next.mcp.disconnect();
  });
});
