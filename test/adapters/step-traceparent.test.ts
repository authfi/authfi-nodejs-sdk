// Every framework adapter's `fetch` sends the step running when the call is made (authfi/authfi#303): the
// OpenAI Agents and Mastra adapters hand a framework the run's `fetch`, and a model or MCP call made inside a
// step must carry that step's trace id and span id. With no step active the value is fresh and unsampled.
import * as otel from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { BasicTracerProvider } from '@opentelemetry/sdk-trace-base';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { RunGateway } from '../../src/adapters/shared.js';
import { AuthFI } from '../../src/core/project.js';
import { createMastra } from '../../src/mastra/index.js';
import { createOpenAIAgents } from '../../src/openai-agents/index.js';
import { AGENT_ID, FakeAS } from '../support/fake-as.js';
import { FakeGateway } from '../support/fake-gateway.js';

const FRESH = /^00-[0-9a-f]{32}-[0-9a-f]{16}-00$/;
const manager = new AsyncLocalStorageContextManager();

beforeAll(() => {
  manager.enable();
  otel.context.setGlobalContextManager(manager);
  otel.trace.setGlobalTracerProvider(new BasicTracerProvider());
});
afterAll(() => {
  manager.disable();
  otel.context.disable();
  otel.trace.disable();
});

async function setup() {
  const key = await AgentKey.generate('ES256');
  const as = await FakeAS.create(key);
  const gw = new FakeGateway(as);
  const logger = { debug() {}, info() {}, warn() {}, error() {} };
  const af = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch, logger, otel });
  const options = { source: af.agent({ agentId: AGENT_ID, key }), pollIntervalMs: 100, logger };
  return { gw, as, options, mcpUrl: `${as.issuer}/mcp` };
}

const listTools = (fetchFn: typeof fetch, url: string) =>
  fetchFn(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });

describe('a call through an adapter names the step that made it', () => {
  it.each([
    ['the shared run gateway', (o: Awaited<ReturnType<typeof setup>>['options']) => new RunGateway(o).fetch],
    [
      'the OpenAI Agents adapter',
      (o: Awaited<ReturnType<typeof setup>>['options']) => createOpenAIAgents(o).fetch,
    ],
    ['the Mastra adapter', (o: Awaited<ReturnType<typeof setup>>['options']) => createMastra(o).fetch],
  ])('%s', async (_name, make) => {
    const t = await setup();
    const fetchFn = make(t.options);
    const tracer = otel.trace.getTracer('step-test');
    let stepped = '';
    await tracer.startActiveSpan('execute_tool', async (span) => {
      const { traceId, spanId } = span.spanContext();
      stepped = `00-${traceId}-${spanId}-01`;
      await listTools(fetchFn, t.mcpUrl);
      span.end();
    });
    await listTools(fetchFn, t.mcpUrl); // no step active

    const sent = t.gw.mcpRequests.filter((r) => r.method === 'tools/list').map((r) => r.traceparent);
    expect(sent).toHaveLength(2);
    expect(sent[0]).toBe(stepped);
    expect(sent[1]).toMatch(FRESH);
  });
});
