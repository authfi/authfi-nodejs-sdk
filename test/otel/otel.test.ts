import * as otel from '@opentelemetry/api';
import { afterEach, describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import {
  AuthFISpanExporter,
  isContentAttribute,
  registerAuthFITelemetry,
  type AuthFITelemetry,
} from '../../src/otel/index.js';
import { json } from '../support/fake-fetch.js';
import { AGENT_ID, FakeAS } from '../support/fake-as.js';

const logs: { warn: string[] } = { warn: [] };
const logger = { debug() {}, info() {}, warn: (m: string) => logs.warn.push(m), error() {} };
let live: AuthFITelemetry | undefined;

afterEach(async () => {
  await live?.shutdown();
  live = undefined;
  otel.trace.disable();
  logs.warn = [];
});

/** ExportTraceServiceResponse{ partial_success{ rejected_spans: n } }, encoded by hand. */
const rejected = (n: number) => new Uint8Array([0x0a, 0x02, 0x08, n]);
const proto = (body: Uint8Array, status = 200) =>
  new Response(body as BodyInit, { status, headers: { 'content-type': 'application/x-protobuf' } });

async function setup() {
  const key = await AgentKey.generate('ES256');
  const as = await FakeAS.create(key);
  const af = new AuthFI({
    issuer: as.issuer,
    fetch: as.t.fake.fetch,
    retries: 0,
    logger,
  });
  const agent = af.agent({ agentId: AGENT_ID, key });
  const url = `${as.issuer}/otlp/v1/traces`;
  as.t.fake.on('POST', url, () => proto(new Uint8Array()));
  return { as, af, agent, url, fake: as.t.fake };
}

async function step(t: AuthFITelemetry, attributes: Record<string, string> = {}, events: string[] = []) {
  const span = t.tracer.startSpan('ai.generateText', { attributes });
  for (const e of events) span.addEvent(e, { content: 'event-secret' });
  span.end();
  // A failed export rejects the flush; the tests read the outcome from the log and the requests.
  await t.forceFlush().catch(() => undefined);
}

describe('exporting steps to AuthFI', () => {
  it("posts OTLP protobuf to the issuer's /otlp/v1/traces under the agent's token, tagged with agent and run", async () => {
    const { agent, url, fake, as } = await setup();
    live = registerAuthFITelemetry({ source: agent, runId: 'run-7', global: false, logger });
    await step(live);
    const posts = fake.to(url);
    expect(posts).toHaveLength(1);
    expect(posts[0]!.headers.get('content-type')).toBe('application/x-protobuf');
    expect(posts[0]!.headers.get('authorization')).toMatch(/^Bearer eyJ/);
    expect(posts[0]!.headers.get('user-agent')).toMatch(/\(agent\)$/);
    const body = posts[0]!.body;
    for (const text of ['authfi.agent_id', AGENT_ID, 'authfi.run_id', 'run-7', 'ai.generateText'])
      expect(body).toContain(text);
    expect(as.minted).toBe(1);
  });

  it('reads the token for every export: a renewed token is used, none is frozen into the exporter', async () => {
    const { agent, url, fake, as } = await setup();
    as.tokenLifetime = 30;
    live = registerAuthFITelemetry({ source: agent, global: false, logger });
    await step(live);
    await step(live);
    const [a, b] = fake.to(url).map((r) => r.headers.get('authorization'));
    expect(a).toMatch(/^Bearer /);
    expect(b).toMatch(/^Bearer /);
    expect(b).not.toBe(a);
  });

  it('renews the token once when the endpoint refuses it, and says so when it still refuses', async () => {
    const { agent, url, fake, as } = await setup();
    live = registerAuthFITelemetry({ source: agent, global: false, logger });
    fake.on('POST', url, (_r, n) =>
      n === 1 ? json({ error: 'invalid_token' }, 401) : proto(new Uint8Array()),
    );
    await step(live);
    expect(fake.to(url)).toHaveLength(2);
    expect(as.minted).toBe(2);
    expect(logs.warn).toEqual([]);
    fake.on('POST', url, () => json({ error: 'invalid_token' }, 401));
    await step(live);
    expect(logs.warn.join('\n')).toContain('did not take the trace export');
    expect(fake.to(url)).toHaveLength(4);
  });

  it('reports a failed export and the spans AuthFI did not keep', async () => {
    const { agent, url, fake } = await setup();
    live = registerAuthFITelemetry({ source: agent, global: false, logger });
    fake.on('POST', url, () => json({ error: 'unavailable' }, 503));
    await step(live);
    expect(logs.warn.join('\n')).toContain('did not take the trace export');
    fake.on('POST', url, () => proto(rejected(3)));
    await step(live);
    expect(logs.warn.join('\n')).toContain('did not keep some spans');
  });

  it('works for a machine client, with no agent id on the spans', async () => {
    const { af, url, fake } = await setup();
    fake.on('POST', `${af.issuer}/oauth/token`, () =>
      json({ access_token: 'at-m2m', token_type: 'Bearer', expires_in: 900 }),
    );
    const m2m = af.clientCredentials({ clientId: 'app_m', clientSecret: new Secret('s3cret') });
    live = registerAuthFITelemetry({ source: m2m, runId: 'run-m', global: false, logger });
    await step(live);
    const post = fake.to(url)[0]!;
    expect(post.headers.get('authorization')).toBe('Bearer at-m2m');
    expect(post.headers.get('user-agent')).toMatch(/\(client-credentials\)$/);
    expect(post.body).toContain('run-m');
    expect(post.body).not.toContain('authfi.agent_id');
  });
});

describe('content', () => {
  const secrets = {
    'gen_ai.input.messages': 'SECRET-PROMPT',
    'gen_ai.output.messages': 'SECRET-ANSWER',
    'gen_ai.tool.call.arguments': 'SECRET-ARGS',
    'gen_ai.tool.call.result': 'SECRET-RESULT',
    'ai.prompt': 'SECRET-AI-PROMPT',
    'ai.response.text': 'SECRET-AI-TEXT',
    'ai.toolCall.args': 'SECRET-AI-ARGS',
    'llm.input_messages.0.content': 'SECRET-LLM',
    'gen_ai.request.model': 'claude-test',
  };

  it('is dropped before export by default, and the model name stays', async () => {
    const { agent, url, fake } = await setup();
    live = registerAuthFITelemetry({ source: agent, global: false, logger });
    await step(live, secrets, ['gen_ai.user.message']);
    const body = fake.to(url)[0]!.body;
    expect(body).not.toContain('SECRET');
    expect(body).not.toContain('event-secret');
    expect(body).toContain('claude-test');
  });

  it('is exported when the tenant allows it', async () => {
    const { agent, url, fake } = await setup();
    live = registerAuthFITelemetry({ source: agent, global: false, captureContent: true, logger });
    await step(live, secrets);
    expect(fake.to(url)[0]!.body).toContain('SECRET-PROMPT');
  });

  it('names the attributes it treats as content', () => {
    expect(isContentAttribute('gen_ai.input.messages')).toBe(true);
    expect(isContentAttribute('gen_ai.prompt.0.content')).toBe(true);
    expect(isContentAttribute('ai.toolCall.result')).toBe(true);
    expect(isContentAttribute('gen_ai.usage.input_tokens')).toBe(false);
    expect(isContentAttribute('gen_ai.request.model')).toBe(false);
    expect(isContentAttribute('authfi.run_id')).toBe(false);
  });
});

describe('registration', () => {
  it('registers the process tracer provider, once', async () => {
    const { agent, url, fake } = await setup();
    live = registerAuthFITelemetry({ source: agent, logger });
    const span = otel.trace.getTracer('app').startSpan('step');
    span.end();
    await live.forceFlush();
    expect(fake.to(url)).toHaveLength(1);
    expect(() => registerAuthFITelemetry({ source: agent, logger })).toThrow('already registered');
  });

  it('makes a run id when none is given and refuses one the platform would drop', async () => {
    const { agent } = await setup();
    live = registerAuthFITelemetry({ source: agent, global: false, logger });
    expect(live.runId).toMatch(/^run-[0-9a-f]{24}$/);
    expect(() => registerAuthFITelemetry({ source: agent, runId: 'bad id', global: false })).toThrow('runId');
  });

  it('refuses a source that has no gateways, and exports nothing after shutdown', async () => {
    expect(() => new AuthFISpanExporter({ source: {} as never })).toThrow('AgentAuth or a ClientCredentials');
    const { agent, url, fake } = await setup();
    const exporter = new AuthFISpanExporter({ source: agent, logger });
    await exporter.forceFlush();
    await exporter.shutdown();
    const result = await new Promise<{ code: number }>((resolve) => {
      exporter.export([], resolve);
    });
    expect(result.code).toBe(1);
    expect(fake.to(url)).toHaveLength(0);
  });
});
