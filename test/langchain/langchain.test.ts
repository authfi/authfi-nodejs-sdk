// The LangChain.js adapter, driven through the real MCP client, `@langchain/mcp-adapters` and
// LangGraph (a `ToolNode` with a checkpointer) against the fake gateway: what the model sees, what
// the gateway receives, and that only AuthFI's decision lets a held call run.

import { AIMessage, type BaseMessage, type ToolMessage } from '@langchain/core/messages';
import { Command, END, MemorySaver, MessagesAnnotation, START, StateGraph } from '@langchain/langgraph';
import { ToolNode } from '@langchain/langgraph/prebuilt';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { describe, expect, it, vi } from 'vitest';
import { GatewayTokenRefused } from '../../src/core/errors.js';
import {
  createLangChain,
  HOLD_MESSAGE,
  type ApprovalInterrupt,
  type LangChainOptions,
} from '../../src/langchain/index.js';
import { setupGateway } from '../support/adapter-setup.js';
import { CONTENTS, QUESTION, STRUCTURE } from '../support/fake-gateway.js';

async function setup(
  options: Partial<LangChainOptions> & { toolNode?: boolean } = {},
  saver = new MemorySaver(),
) {
  const s = await setupGateway();
  const authfi = createLangChain({
    source: s.agent,
    pollIntervalMs: 100,
    logger: s.logger,
    runId: 'run-1',
    ...options,
  });
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(authfi.mcpUrl), authfi.transportOptions()));
  const tools = await authfi.tools(client);
  const graph = new StateGraph(MessagesAnnotation)
    .addNode('tools', options.toolNode === true ? authfi.toolNode(tools) : new ToolNode(tools))
    .addEdge(START, 'tools')
    .addEdge('tools', END)
    .compile({ checkpointer: saver });
  let n = 0;
  const config = () => ({ configurable: { thread_id: `t${String(++n)}` } });
  return { ...s, authfi, client, tools, graph, config, saver };
}
type Setup = Awaited<ReturnType<typeof setup>>;

const call = (name: string, id = 'call_1', repoName = 'pallets/itsdangerous') =>
  new AIMessage({ content: '', tool_calls: [{ id, name, args: { repoName }, type: 'tool_call' }] });

const text = (m: BaseMessage | undefined): string =>
  typeof m?.content === 'string' ? m.content : JSON.stringify(m?.content);

async function untilHold(t: Setup) {
  const config = t.config();
  const out = await t.graph.invoke({ messages: [call(CONTENTS)] }, config);
  const interrupts = (out as { __interrupt__?: { value: ApprovalInterrupt }[] }).__interrupt__;
  expect(interrupts).toHaveLength(1);
  return { config, interrupt: interrupts![0]!.value };
}

describe('the tools', () => {
  it('keep the gateway names and send the credential, the run request ids and no API key', async () => {
    const t = await setup();
    expect(t.tools.map((x) => x.name).sort()).toEqual([CONTENTS, QUESTION, STRUCTURE].sort());
    const out = await t.graph.invoke({ messages: [call(STRUCTURE)] }, t.config());
    expect(text(out.messages.at(-1))).toContain('1 Overview');
    const calls = t.gw.toolCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.authorization).toMatch(/^Bearer /);
    expect(calls[0]!.apiKey).toBeNull();
    expect(calls[0]!.requestId).toMatch(/^run-1\.\d+$/);
    expect(calls[0]!.traceparent).toMatch(/^00-/);
    expect(t.authfi.enrichSpan()).toEqual({ 'authfi.agent_id': 'agt_test1', 'authfi.run_id': 'run-1' });
  });

  it('ask the gateway again when the same question comes in a later step', async () => {
    const t = await setup();
    await t.graph.invoke({ messages: [call(STRUCTURE, 'call_1')] }, t.config());
    await t.graph.invoke({ messages: [call(STRUCTURE, 'call_2')] }, t.config());
    expect(t.gw.executed).toHaveLength(2);
  });

  it('answer a refusal as the tool result, and the run goes on', async () => {
    const t = await setup();
    const out = await t.graph.invoke({ messages: [call(QUESTION)] }, t.config());
    const last = out.messages.at(-1) as ToolMessage;
    expect(last.status).toBe('error');
    expect(text(last)).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('report a refused token as a tool error naming the cause, and never run the tool', async () => {
    const t = await setup();
    t.gw.revoked = true;
    const out = await t.graph.invoke({ messages: [call(STRUCTURE)] }, t.config());
    const last = out.messages.at(-1) as ToolMessage;
    expect(last.status).toBe('error');
    expect(text(last)).toContain('the gateway refused the token');
    expect(t.gw.executed).toHaveLength(0);
  });
});

describe('a held call', () => {
  it('pauses the graph with interrupt() and names the approval, not the hold text', async () => {
    const t = await setup();
    const { interrupt } = await untilHold(t);
    expect(interrupt.type).toBe('authfi.approval');
    expect(interrupt.tool).toBe(CONTENTS);
    expect(t.gw.pending()).toEqual([interrupt.approvalId]);
    expect(t.authfi.pendingApprovals()).toHaveLength(1);
    expect(t.gw.executed).toHaveLength(0);
  });

  it('runs once when AuthFI approves, with one approval opened', async () => {
    const t = await setup();
    const { config, interrupt } = await untilHold(t);
    t.gw.decide(interrupt.approvalId, 'approved');
    const decisions = await t.authfi.awaitApprovals();
    expect([...decisions.values()]).toEqual(['approved']);
    const out = await t.graph.invoke(new Command({ resume: true }), config);
    expect(text(out.messages.at(-1))).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
    expect(JSON.stringify(out.messages)).not.toContain('Waiting for approval');
  });

  it('is refused when AuthFI denies it: nothing runs and the model is told so', async () => {
    const t = await setup();
    const { config, interrupt } = await untilHold(t);
    t.gw.decide(interrupt.approvalId, 'denied');
    expect([...(await t.authfi.awaitApprovals()).values()]).toEqual(['denied']);
    const out = await t.graph.invoke(new Command({ resume: true }), config);
    expect(text(out.messages.at(-1))).toContain('Refused');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('is never run by an app that resumes before AuthFI decided', async () => {
    const t = await setup();
    const { config } = await untilHold(t);
    const out = await t.graph.invoke(new Command({ resume: true }), config);
    expect(text(out.messages.at(-1))).toBe(HOLD_MESSAGE);
    expect(t.gw.executed).toHaveLength(0);
    expect(t.gw.approvals.size).toBe(1);
  });

  it('sends the same question once when it is asked twice in one step', async () => {
    const t = await setup();
    const two = new AIMessage({
      content: '',
      tool_calls: [
        { id: 'call_1', name: CONTENTS, args: { repoName: 'x' }, type: 'tool_call' },
        { id: 'call_2', name: CONTENTS, args: { repoName: 'x' }, type: 'tool_call' },
      ],
    });
    await t.graph.invoke({ messages: [two] }, t.config());
    expect(t.gw.approvals.size).toBe(1);
    expect(t.gw.executed).toHaveLength(0);
  });

  it('does not run the other tools of the same step again when the graph resumes', async () => {
    const t = await setup();
    const config = t.config();
    const two = new AIMessage({
      content: '',
      tool_calls: [
        { id: 'call_1', name: STRUCTURE, args: { repoName: 'x' }, type: 'tool_call' },
        { id: 'call_2', name: CONTENTS, args: { repoName: 'x' }, type: 'tool_call' },
      ],
    });
    await t.graph.invoke({ messages: [two] }, config);
    await vi.waitFor(() => expect(t.authfi.pendingApprovals()).toHaveLength(1));
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    await t.authfi.awaitApprovals();
    const out = await t.graph.invoke(new Command({ resume: true }), config);
    expect(out.messages.filter((m) => m.type === 'tool')).toHaveLength(2);
    expect(t.gw.executed.map((e) => e.tool).sort()).toEqual(
      ['deepwiki.read_wiki_contents', 'deepwiki.read_wiki_structure'].sort(),
    );
  });

  it('stops waiting at the timeout without answering for AuthFI', async () => {
    const t = await setup();
    await untilHold(t);
    const sleeps: number[] = [];
    const decisions = await t.authfi.awaitApprovals({
      timeoutMs: 450,
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    });
    expect([...decisions.values()]).toEqual(['pending']);
    expect(sleeps.length).toBeGreaterThan(0);
    expect(t.gw.executed).toHaveLength(0);
  });
});

describe('the clients the adapter builds', () => {
  it('point a model provider at the project, with a placeholder key replaced by the credential', async () => {
    const t = await setup();
    expect(t.authfi.openai()).toMatchObject({ baseURL: `${t.as.issuer}/mcp/v1`, apiKey: 'authfi' });
    expect(t.authfi.anthropic()).toMatchObject({ baseURL: `${t.as.issuer}/mcp`, authToken: 'authfi' });
    const res = await t.authfi.anthropic().fetch(`${t.as.issuer}/mcp/v1/messages`, {
      method: 'POST',
      body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'hi' }] }),
      headers: { 'x-api-key': 'authfi', 'content-type': 'application/json' },
    });
    expect(res.status).toBe(200);
    const req = t.gw.modelRequests.at(-1)!;
    expect(req.authorization).toMatch(/^Bearer /);
    expect(req.apiKey).toBeNull();
    expect(req.requestId).toMatch(/^run-1\.\d+$/);
  });

  it('refuse to send the credential outside AuthFI', async () => {
    const t = await setup();
    await expect(t.authfi.fetch('https://example.com/mcp')).rejects.toThrow();
  });
});

describe('waiting for AuthFI inside the tool', () => {
  it('continues by itself when AuthFI approves: no interrupt, one approval, one run', async () => {
    const t = await setup({ waitInTool: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 300);
    const out = await t.graph.invoke({ messages: [call(CONTENTS)] }, t.config());
    expect((out as { __interrupt__?: unknown }).__interrupt__).toBeUndefined();
    expect(text(out.messages.at(-1))).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.gw.approvals.size).toBe(1);
  });

  it('answers the model the refusal when AuthFI denies, and "waiting" when nobody decides in time', async () => {
    const t = await setup({ waitInTool: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'denied'), 300);
    const out = await t.graph.invoke({ messages: [call(CONTENTS)] }, t.config());
    expect(text(out.messages.at(-1))).toContain('Refused');
    const slow = await setup({ waitInTool: true, approvalTimeoutMs: 450 });
    const waiting = await slow.graph.invoke({ messages: [call(CONTENTS)] }, slow.config());
    expect(text(waiting.messages.at(-1))).toBe(HOLD_MESSAGE);
    expect(t.gw.executed.length + slow.gw.executed.length).toBe(0);
  });

  it('polls the approval route with the agent own token and asks the gateway only to release the call', async () => {
    const t = await setup({ waitInTool: true, approvalPoll: true });
    setTimeout(() => t.gw.decide(t.gw.pending()[0]!, 'approved'), 450);
    const out = await t.graph.invoke({ messages: [call(CONTENTS)] }, t.config());
    expect(text(out.messages.at(-1))).toContain('1 Overview');
    expect(t.as.approvalPolls).toBeGreaterThanOrEqual(3);
    expect(t.gw.toolCalls()).toHaveLength(2);
  });
});

describe('a revoked agent', () => {
  it('ends the run through authfi.toolNode, where a plain ToolNode would hand the model an error', async () => {
    const t = await setup({ toolNode: true });
    t.gw.revoked = true;
    await expect(t.graph.invoke({ messages: [call(STRUCTURE)] }, t.config())).rejects.toBeInstanceOf(
      GatewayTokenRefused,
    );
    expect(t.authfi.ended).toBeInstanceOf(GatewayTokenRefused);
    expect(t.gw.executed).toHaveLength(0);
  });

  it('lets the model read every other tool error through authfi.toolNode', async () => {
    const t = await setup({ toolNode: true });
    const out = await t.graph.invoke({ messages: [call(QUESTION)] }, t.config());
    expect(text(out.messages.at(-1))).toContain('Refused');
    expect(t.authfi.ended).toBeUndefined();
  });

  it('ends the wait for a person at once, not at the timeout, when revoked mid-wait', async () => {
    const t = await setup({ approvalTimeoutMs: 60_000 });
    await untilHold(t);
    t.gw.revoked = true;
    const began = Date.now();
    await expect(t.authfi.awaitApprovals()).rejects.toBeInstanceOf(GatewayTokenRefused);
    expect(Date.now() - began).toBeLessThan(2000);
  });
});

describe('a restarted process', () => {
  async function restart(t: Setup) {
    // A new adapter, MCP client and compiled graph over the same durable checkpointer.
    const next = await setup({ runId: 'run-2' }, t.saver);
    const state = await next.graph.getState({ configurable: { thread_id: 't1' } });
    next.authfi.adoptInterrupts(state.tasks.flatMap((task) => task.interrupts.map((i) => i.value)));
    return next;
  }

  it('resumes from the checkpoint with the approval id and opens no second approval; the id is not in the messages', async () => {
    const t = await setup();
    const { config, interrupt } = await untilHold(t);
    const next = await restart(t);
    // Same gateway, as one platform serves both processes.
    next.gw.approvals.clear();
    for (const [id, a] of t.gw.approvals) next.gw.approvals.set(id, a);
    t.gw.decide(interrupt.approvalId, 'approved');
    expect([...(await next.authfi.awaitApprovals()).values()]).toEqual(['approved']);
    const out = await next.graph.invoke(new Command({ resume: true }), config);
    expect(text(out.messages.at(-1))).toContain('1 Overview');
    expect(next.gw.executed).toHaveLength(1);
    expect(next.gw.toolCalls().at(-1)!.args).toMatchObject({ _authfi_approval_id: interrupt.approvalId });
    expect(JSON.stringify(out.messages)).not.toContain(interrupt.approvalId);
  });

  it('is told, structurally, to raise the call again when the gateway binds the approval to another run', async () => {
    const t = await setup();
    const { config, interrupt } = await untilHold(t);
    const next = await restart(t);
    next.gw.approvals.clear();
    for (const [id, a] of t.gw.approvals) next.gw.approvals.set(id, a);
    t.gw.decide(interrupt.approvalId, 'approved');
    next.gw.otherRun = true;
    expect([...(await next.authfi.awaitApprovals()).values()]).toEqual(['raise_again']);
    const out = await next.graph.invoke(new Command({ resume: true }), config);
    expect(text(out.messages.at(-1))).toContain('Raise the call again');
    expect(next.gw.executed).toHaveLength(0);
  });
});
