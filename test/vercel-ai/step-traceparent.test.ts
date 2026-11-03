// Every gateway call names the step that made it (authfi/authfi#303): driven through the real `ai`,
// `@ai-sdk/otel` and the SDK's own step export, with no context manager and no propagator registered
// by the test, as an app that only calls `exportSteps()` has. The `traceparent` the fake gateway
// received must be the trace id and span id of a span the exporter was handed.

import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import * as otel from '@opentelemetry/api';
import type { ReadableSpan } from '@opentelemetry/sdk-trace-base';
import { generateText, jsonSchema, stepCountIs, tool, type ToolSet } from 'ai';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { AuthFISpanExporter } from '../../src/otel/index.js';
import { createVercelAI } from '../../src/vercel-ai/index.js';
import { AGENT_ID, FakeAS } from '../support/fake-as.js';
import { FakeGateway, STRUCTURE } from '../support/fake-gateway.js';

const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const FRESH = /^00-[0-9a-f]{32}-[0-9a-f]{16}-00$/;

afterEach(() => {
  vi.restoreAllMocks();
});

/** The project is given the API and the adapter is not: the adapter reads it from the credential. */
async function setup() {
  const key = await AgentKey.generate('ES256');
  const as = await FakeAS.create(key);
  const gw = new FakeGateway(as);
  const logger = { debug() {}, info() {}, warn() {}, error() {} };
  const af = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch, logger, otel });
  const authfi = createVercelAI({
    source: af.agent({ agentId: AGENT_ID, key }),
    approvalSecret: new Secret('s'.repeat(32)),
    pollIntervalMs: 100,
    logger,
  });
  as.t.fake.on('POST', `${as.issuer}/otlp/v1/traces`, () => new Response(new Uint8Array(), { status: 200 }));
  const exported: ReadableSpan[] = [];
  // eslint-disable-next-line @typescript-eslint/unbound-method -- called with its receiver below
  const real = AuthFISpanExporter.prototype.export;
  vi.spyOn(AuthFISpanExporter.prototype, 'export').mockImplementation(function (
    this: AuthFISpanExporter,
    spans,
    done,
  ) {
    exported.push(...spans);
    real.call(this, spans, done);
  });
  const steps = await authfi.exportSteps({ scheduleDelayMs: 60_000 });
  const client = await createMCPClient({ transport: authfi.mcpTransport() });
  const tools = authfi.tools(await client.tools());
  const model = createAnthropic(authfi.anthropic())('claude-test');
  // The initialize and tools/list calls above had no step; only what a run sends is checked.
  gw.mcpRequests.length = 0;
  const finish = async () => {
    // The batch is sent from inside a step, as when the timer was started by the step that ended a span.
    await steps.tracer.startActiveSpan('flushing step', async (span) => {
      await steps.forceFlush();
      span.end();
    });
    await steps.shutdown();
    await client.close();
  };
  return { gw, authfi, as, exported, tools, model, finish };
}

type Setup = Awaited<ReturnType<typeof setup>>;

function spanOf(exported: ReadableSpan[], traceparent: string | null): ReadableSpan | undefined {
  const m = TRACEPARENT.exec(traceparent ?? '');
  if (m === null) return undefined;
  return exported.find((s) => s.spanContext().traceId === m[1] && s.spanContext().spanId === m[2]);
}

function run(t: Setup, tools: ToolSet, withApprovals: boolean) {
  return generateText({
    model: t.model,
    tools,
    messages: [{ role: 'user', content: 'go' }],
    stopWhen: stepCountIs(3),
    maxRetries: 0,
    telemetry: { isEnabled: true },
    ...(withApprovals ? t.authfi.approvals() : {}),
  } as never);
}

describe('the traceparent of a gateway call is the step that made it', () => {
  it('a tool call carries its execute_tool span, and each model call its own chat span', async () => {
    const t = await setup();
    await run(t, { [STRUCTURE]: t.tools[STRUCTURE]! }, false);
    await t.finish();
    const [call] = t.gw.toolCalls();
    expect(t.gw.toolCalls()).toHaveLength(1);
    expect(spanOf(t.exported, call!.traceparent)?.name).toBe(`execute_tool ${STRUCTURE}`);
    expect(t.gw.modelRequests).toHaveLength(2);
    const chats = t.gw.modelRequests.map((m) => spanOf(t.exported, m.traceparent));
    expect(chats.map((s) => s?.name)).toEqual(['chat claude-test', 'chat claude-test']);
    expect(new Set(chats.map((s) => s!.spanContext().spanId)).size).toBe(2);
  });

  it('with toolApproval the call is made before the tool span exists: it names the model call that asked for it', async () => {
    const t = await setup();
    await run(t, { [STRUCTURE]: t.tools[STRUCTURE]! }, true);
    await t.finish();
    expect(t.gw.toolCalls()).toHaveLength(1);
    const asked = spanOf(t.exported, t.gw.toolCalls()[0]!.traceparent);
    expect(asked?.name).toBe('chat claude-test');
    // The chat span that asked is the first model call's, not the one that read the answer.
    expect(asked?.spanContext().spanId).toBe(TRACEPARENT.exec(t.gw.modelRequests[0]!.traceparent ?? '')![2]);
  });

  it("a sub-agent's call names the sub-agent's tool span, below the parent's tool span", async () => {
    const t = await setup();
    const ask = tool({
      description: 'ask the researcher',
      inputSchema: jsonSchema<{ repoName: string }>({
        type: 'object',
        properties: { repoName: { type: 'string' } },
        required: ['repoName'],
      }),
      execute: async () => {
        const inner = await run(t, { [STRUCTURE]: t.tools[STRUCTURE]! }, false);
        return inner.text;
      },
    });
    await run(t, { ask }, false);
    await t.finish();
    const [call] = t.gw.toolCalls();
    const toolSpan = spanOf(t.exported, call!.traceparent);
    expect(toolSpan?.name).toBe(`execute_tool ${STRUCTURE}`);
    const names: string[] = [];
    for (let id = toolSpan!.parentSpanContext?.spanId; id !== undefined;) {
      const s = t.exported.find((x) => x.spanContext().spanId === id);
      if (s === undefined) break;
      names.push(s.name);
      id = s.parentSpanContext?.spanId;
    }
    expect(names).toContain('execute_tool ask');
    expect(names.indexOf('execute_tool ask')).toBeGreaterThan(names.indexOf('invoke_agent claude-test'));
  });

  it('with no step active the call carries a fresh unsampled traceparent, and is still allowed', async () => {
    const t = await setup();
    const gateway = t.authfi.mcpTransport();
    const res = await gateway.fetch(gateway.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list' }),
    });
    expect(res.status).toBe(200);
    await t.finish();
    const sent = t.gw.mcpRequests.at(-1)!.traceparent;
    expect(sent).toMatch(FRESH);
    expect(spanOf(t.exported, sent)).toBeUndefined();
  });

  it("the step export's own posts are not a step's calls", async () => {
    const t = await setup();
    await run(t, { [STRUCTURE]: t.tools[STRUCTURE]! }, false);
    await t.finish();
    const posts = t.as.t.fake.to(`${t.as.issuer}/otlp/v1/traces`);
    expect(posts.length).toBeGreaterThan(0);
    for (const p of posts) expect(p.headers.get('traceparent')).toMatch(FRESH);
  });
});
