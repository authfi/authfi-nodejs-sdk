import * as otel from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { W3CTraceContextPropagator } from '@opentelemetry/core';
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from '@opentelemetry/sdk-trace-base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { decisionAttributes, recordDecision } from '../../src/gateway/decision-span.js';
import type { ToolOutcome } from '../../src/gateway/gateway.js';
import { LangSmithProcessor, REDACTED, redactSpan, runTypeOf } from '../../src/otel/langsmith.js';
import { registerAuthFITelemetry } from '../../src/otel/index.js';
import { call, person, platform } from '../support/platform-setup.js';

let exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;
let manager: AsyncLocalStorageContextManager;

beforeEach(() => {
  exporter = new InMemorySpanExporter();
  manager = new AsyncLocalStorageContextManager().enable();
  otel.context.setGlobalContextManager(manager);
  otel.propagation.setGlobalPropagator(new W3CTraceContextPropagator());
  provider = new BasicTracerProvider({
    spanProcessors: [
      new LangSmithProcessor({ authfi_agent_id: 'agt_1', authfi_run_id: 'run-1' }),
      new SimpleSpanProcessor(exporter),
    ],
  });
});
afterEach(async () => {
  await provider.shutdown();
  otel.context.disable();
  otel.propagation.disable();
  otel.trace.disable();
});

const tracer = () => provider.getTracer('test');
const finished = (name: string): ReadableSpan => exporter.getFinishedSpans().find((s) => s.name === name)!;

describe("LangSmith's OpenTelemetry mapping", () => {
  it('sets the run type, the trace name on the root only, and the AuthFI metadata', () => {
    const root = tracer().startSpan('refund-agent');
    const ctx = otel.trace.setSpan(otel.context.active(), root);
    const child = tracer().startSpan('chat claude', { attributes: { 'gen_ai.operation.name': 'chat' } }, ctx);
    child.end();
    root.end();
    expect(finished('refund-agent').attributes).toMatchObject({
      'langsmith.span.kind': 'chain',
      'langsmith.trace.name': 'refund-agent',
      'langsmith.metadata.authfi_agent_id': 'agt_1',
      'langsmith.metadata.authfi_run_id': 'run-1',
    });
    const llm = finished('chat claude');
    expect(llm.attributes['langsmith.span.kind']).toBe('llm');
    expect(llm.attributes['langsmith.trace.name']).toBeUndefined();
  });

  it('keeps what the framework already said', () => {
    const span = tracer().startSpan('mine', {
      attributes: {
        'langsmith.span.kind': 'retriever',
        'langsmith.trace.name': 'named',
        'langsmith.metadata.authfi_run_id': 'theirs',
      },
    });
    span.end();
    expect(finished('mine').attributes).toMatchObject({
      'langsmith.span.kind': 'retriever',
      'langsmith.trace.name': 'named',
      'langsmith.metadata.authfi_run_id': 'theirs',
    });
  });

  it('maps gen_ai operations to the run types LangSmith reads', () => {
    for (const [operation, expected] of Object.entries({
      chat: 'llm',
      embeddings: 'embedding',
      execute_tool: 'tool',
      retrieval: 'retriever',
      invoke_agent: 'chain',
    })) {
      expect(runTypeOf({ 'gen_ai.operation.name': operation })).toBe(expected);
    }
    expect(runTypeOf({ 'gen_ai.tool.name': 'x' })).toBe('tool');
    expect(runTypeOf({})).toBe('chain');
    expect(runTypeOf({ 'gen_ai.operation.name': 'unheard-of' })).toBe('chain');
  });
});

describe('no secret is ever in a span', () => {
  const JWT = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ3RfMSJ9.c2lnbmF0dXJl';

  it('redacts secret-shaped values and credential-named attributes, in attributes, events, names and status', () => {
    const span = tracer().startSpan(`call with ${JWT}`);
    span.setAttributes({
      'http.request.header.authorization': 'DPoP abcdefghijklmnop',
      'tool.note': `used Bearer abcdefgh12345678 and sk-abcdefghijklmnopqrstuv and AKIAABCDEFGHIJKLMNOP`,
      'gen_ai.usage.input_tokens': 12,
      'safe.list': ['plain', JWT],
      client_secret: 'plain-but-named',
      'my.api_key': 'x',
      'github.token': 'ghp_abcdefghijklmnopqrstuvwxyz',
    });
    span.addEvent('log', { body: JWT, authorization: 'Basic dXNlcjpwYXNzd29yZA==' });
    span.setStatus({ code: otel.SpanStatusCode.ERROR, message: `failed: ${JWT}` });
    span.end();
    const out = redactSpan(finished(`call with ${JWT}`));
    const text = JSON.stringify({ a: out.attributes, e: out.events, n: out.name, s: out.status });
    expect(text).not.toContain('eyJ');
    expect(text).not.toMatch(/abcdefgh12345678|sk-abcdef|AKIAABCDEF|dXNlcjpwYXNzd29yZA|ghp_|plain-but-named/);
    expect(out.attributes['gen_ai.usage.input_tokens']).toBe(12);
    expect(out.attributes.client_secret).toBe(REDACTED);
    expect(out.attributes['safe.list']).toEqual(['plain', REDACTED]);
    expect(out.name).toContain(REDACTED);
    expect(out.status.message).toContain(REDACTED);
    // the span's own methods and fields still work through the copy
    expect(out.spanContext().traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(out.startTime).toBeDefined();
  });

  it('hands back the same span when it is clean', () => {
    const span = tracer().startSpan('clean', { attributes: { a: 'b' } });
    span.end();
    const clean = finished('clean');
    expect(redactSpan(clean)).toBe(clean);
  });

  it('keeps the real agent token out of what the exporter sends, with content capture on and off', async () => {
    for (const capture of [false, true]) {
      const { agent, p } = await platform();
      const bodies: Uint8Array[] = [];
      p.t.fake.on('POST', `${p.issuer}/otlp/v1/traces`, async (r) => {
        bodies.push(new TextEncoder().encode(r.body));
        return new Response(new Uint8Array(), { headers: { 'content-type': 'application/x-protobuf' } });
      });
      const token = await agent.token();
      const telemetry = registerAuthFITelemetry({
        source: agent,
        global: false,
        captureContent: capture,
        scheduleDelayMs: 60_000,
      });
      const span = telemetry.tracer.startSpan('step');
      span.setAttribute('http.request.header.authorization', `DPoP ${token}`);
      span.setAttribute('gen_ai.tool.call.arguments', `{"t":"${token}"}`);
      span.setAttribute('note', `leaked ${token}`);
      span.end();
      await telemetry.forceFlush();
      await telemetry.shutdown();
      expect(bodies).toHaveLength(1);
      const sent = new TextDecoder().decode(bodies[0]);
      expect(sent).not.toContain(token);
      expect(sent).not.toContain('eyJ');
      expect(sent).toContain('langsmith.span.kind');
      expect(sent).toContain('langsmith.metadata.authfi_agent_id');
      // the export itself went out as DPoP
      expect(p.t.fake.to(`${p.issuer}/otlp/v1/traces`)[0]!.headers.get('authorization')).toMatch(/^DPoP /);
    }
  });
});

describe('a gateway decision is a child span in LangSmith words', () => {
  const refused: ToolOutcome = {
    kind: 'refused',
    result: {
      isError: true,
      _meta: {
        'io.authfi/decision': { decision_id: 'dec_1', rule: 'rule_9', grant: 'grant_2', mandate_id: 'mnd_1' },
      },
    },
    reason: 'outside the mandate',
    code: 'EMDT005',
    error: undefined,
    requiredScope: 'mcp:billing.refund',
    why: 'outside_mandate',
    nextStep: 'x',
    modelText: 'x',
  };

  it('names the outcome, the rule or grant that decided, the decision and the mandate', () => {
    expect(decisionAttributes(refused, { tool: 'admin__delete' })).toEqual({
      'langsmith.span.kind': 'tool',
      'gen_ai.tool.name': 'admin__delete',
      'authfi.decision.outcome': 'deny',
      'authfi.decision.code': 'EMDT005',
      'authfi.decision.reason': 'outside the mandate',
      'authfi.decision.required_scope': 'mcp:billing.refund',
      'authfi.decision.why': 'outside_mandate',
      'authfi.decision.id': 'dec_1',
      'authfi.decision.rule': 'rule_9',
      'authfi.decision.grant': 'grant_2',
      'authfi.mandate.id': 'mnd_1',
    });
    expect(
      decisionAttributes(
        { kind: 'allowed', result: {} },
        { decisionId: 'd', mandateId: 'm', rule: 'r', grant: 'g' },
      ),
    ).toMatchObject({
      'authfi.decision.outcome': 'allow',
      'authfi.decision.id': 'd',
      'authfi.mandate.id': 'm',
      'authfi.decision.rule': 'r',
      'authfi.decision.grant': 'g',
    });
    expect(
      decisionAttributes({ kind: 'approval_required', approvalId: 'apr', code: 'approval_required' }),
    ).toMatchObject({
      'authfi.decision.outcome': 'needs_approval',
      'authfi.decision.approval_id': 'apr',
    });
  });

  it('is recorded as a finished tool child of the step that made the call, with nothing the tool said', async () => {
    const { agent, p, af } = await platform({ otel });
    p.t.fake.on('POST', `${p.issuer}/mcp`, () =>
      Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          isError: true,
          content: [{ type: 'text', text: 'SECRET TOOL ANSWER' }],
          _meta: {
            'io.authfi/refusal': { code: 'EMDT005', reason: 'outside' },
            'io.authfi/decision': { mandate_id: 'mnd_1' },
          },
        },
      }),
    );
    expect(af).toBeDefined();
    otel.trace.setGlobalTracerProvider(provider);
    const step = tracer().startSpan('step');
    await otel.context.with(otel.trace.setSpan(otel.context.active(), step), async () => {
      const res = await agent
        .gateway()
        .fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('admin__delete') });
      const outcome = agent.gateway().readResult(((await res.json()) as { result: unknown }).result);
      expect(outcome.kind).toBe('refused');
    });
    step.end();
    const decision = finished('authfi.decision');
    expect(decision.parentSpanContext?.spanId).toBe(step.spanContext().spanId);
    expect(decision.spanContext().traceId).toBe(step.spanContext().traceId);
    expect(decision.attributes).toMatchObject({
      'langsmith.span.kind': 'tool',
      'authfi.decision.outcome': 'deny',
      'authfi.decision.code': 'EMDT005',
      'authfi.mandate.id': 'mnd_1',
    });
    expect(JSON.stringify(decision.attributes)).not.toContain('SECRET TOOL ANSWER');
  });

  it('does nothing outside a span, without the API, or when the tracer fails', async () => {
    const { agent } = await platform({ otel });
    agent.gateway().readResult({ content: [] });
    expect(exporter.getFinishedSpans()).toHaveLength(0);
    const plain = await platform();
    plain.agent.gateway().readResult({ content: [] });
    recordDecision(undefined, { kind: 'allowed', result: {} });
    const broken = {
      ...otel,
      trace: {
        getActiveSpan: () => ({ spanContext: () => ({ traceId: 'a'.repeat(32) }) }),
        getTracer: () => {
          throw new Error('no tracer');
        },
      },
    };
    expect(() => recordDecision(broken as never, { kind: 'allowed', result: {} })).not.toThrow();
    const span = tracer().startSpan('s');
    otel.context.with(otel.trace.setSpan(otel.context.active(), span), () => {
      expect(() => recordDecision(broken as never, { kind: 'allowed', result: {} })).not.toThrow();
    });
    span.end();
    expect(await person(plain.p, plain.clock)).toBeDefined();
  });
});
