// What the three framework adapters share: the run's identity on the gateway calls, and the guard
// that lets only AuthFI's decision run a held call.

import * as otel from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  APPROVAL_ARGUMENT,
  canonicalJson,
  HoldGuard,
  RunGateway,
  textOf,
  WAITING,
} from '../../src/adapters/shared.js';
import { ConfigurationError } from '../../src/core/errors.js';
import type { ToolResult } from '../../src/gateway/gateway.js';
import { setupGateway } from '../support/adapter-setup.js';
import { CONTENTS, STRUCTURE } from '../support/fake-gateway.js';

const exporter = new InMemorySpanExporter();

beforeAll(() => {
  const manager = new AsyncLocalStorageContextManager();
  manager.enable();
  otel.context.setGlobalContextManager(manager);
  otel.trace.setGlobalTracerProvider(
    new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] }),
  );
});

/** A guard that sends through the gateway's own MCP route, as the real adapters do. */
async function guardSetup(options: { memoSize?: number } = {}) {
  const s = await setupGateway();
  const run = new RunGateway({ source: s.agent, logger: s.logger, pollIntervalMs: 100, ...options });
  const sent: { key: string; input: Record<string, unknown> }[] = [];
  const guard = new HoldGuard(run, async (key, input) => {
    sent.push({ key, input: input as Record<string, unknown> });
    const res = await run.fetch(run.gateway.mcpUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: key, arguments: input },
      }),
    });
    return ((await res.json()) as { result: ToolResult }).result;
  });
  return { ...s, run, guard, sent };
}

describe('canonicalJson', () => {
  it('is the same for the same value in any key order, and differs for a different value', () => {
    expect(canonicalJson({ b: 1, a: [1, { d: 2, c: 3 }] })).toBe(
      canonicalJson({ a: [1, { c: 3, d: 2 }], b: 1 }),
    );
    expect(canonicalJson({ a: 1 })).not.toBe(canonicalJson({ a: 2 }));
    expect(canonicalJson({ a: undefined })).toBe('{}');
    expect(canonicalJson(undefined)).toBe('null');
    expect(canonicalJson('x')).toBe('"x"');
  });
});

describe('textOf', () => {
  it('joins the text parts and ignores the rest', () => {
    expect(
      textOf({
        content: [{ type: 'text', text: 'a' }, { type: 'image' }, null, { type: 'text', text: 'b' }],
      }),
    ).toBe('a\nb');
    expect(textOf({})).toBe('');
  });
});

describe('RunGateway', () => {
  it('refuses what would break the credential, the request ids or the polling', async () => {
    const s = await setupGateway();
    expect(() => new RunGateway({ source: {} as never })).toThrow(ConfigurationError);
    expect(() => new RunGateway({ source: s.agent, runId: 'has space' })).toThrow(/runId/);
    expect(() => new RunGateway({ source: s.agent, pollIntervalMs: 10 })).toThrow(/pollIntervalMs/);
    expect(() => new RunGateway({ source: s.agent, approvalTimeoutMs: 0 })).toThrow(/approvalTimeoutMs/);
    expect(new RunGateway({ source: s.agent }).runId).toMatch(/^run-[0-9a-f]{24}$/);
  });

  it("numbers the request ids from the run id, keeps the caller's own, and stamps the answer on the active span", async () => {
    const s = await setupGateway();
    const run = new RunGateway({ source: s.agent, runId: 'r9', otel, logger: s.logger });
    const call = (headers: Record<string, string> = {}) =>
      run.fetch(s.as.issuer + '/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      });
    await otel.trace.getTracer('t').startActiveSpan('s', async (span) => {
      await call();
      await call({ 'x-request-id': 'mine-1' });
      span.end();
    });
    expect(s.gw.mcpRequests.map((r) => r.requestId)).toEqual(['r9.1', 'mine-1']);
    expect(exporter.getFinishedSpans().at(-1)!.attributes['authfi.request_id']).toBe('mine-1');
  });

  it('gives model settings with a placeholder key', async () => {
    const s = await setupGateway();
    const run = new RunGateway({ source: s.agent });
    expect(run.openai()).toMatchObject({ baseURL: `${s.as.issuer}/mcp/v1`, apiKey: 'authfi' });
    expect(run.anthropic()).toMatchObject({ baseURL: `${s.as.issuer}/mcp`, authToken: 'authfi' });
  });
});

describe('HoldGuard', () => {
  const input = { repoName: 'x' };

  it('sends an allowed call once and answers from what it remembers', async () => {
    const t = await guardSetup();
    const first = await t.guard.answer('a', STRUCTURE, input);
    const again = await t.guard.answer('a', STRUCTURE, input);
    expect(textOf(first)).toContain('1 Overview');
    expect(again).toBe(first);
    expect(t.sent).toHaveLength(1);
  });

  it('sends one call once when it is begun twice at the same time', async () => {
    const t = await guardSetup();
    const [a, b] = await Promise.all([
      t.guard.begin('a', STRUCTURE, input),
      t.guard.begin('a', STRUCTURE, input),
    ]);
    expect(a).toBe(b);
    expect(t.sent).toHaveLength(1);
  });

  it('removes an approval id the model wrote, and says so', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, { ...input, [APPROVAL_ARGUMENT]: 'forged' });
    expect(t.sent[0]!.input).toEqual(input);
    expect(t.warns.join()).toContain('removed an approval id');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('answers waiting while pending, then the result once approved, and the call runs once', async () => {
    const t = await guardSetup();
    expect(await t.guard.answer('a', CONTENTS, input)).toBe(WAITING);
    expect(t.guard.pending()).toMatchObject([{ id: 'a', tool: CONTENTS }]);
    expect(await t.guard.answer('a', CONTENTS, input)).toBe(WAITING);
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    expect(textOf(await t.guard.answer('a', CONTENTS, input))).toContain('1 Overview');
    expect(t.gw.executed).toHaveLength(1);
    expect(t.guard.pending()).toEqual([]);
    expect(await t.guard.decision('a')).toBe('approved');
  });

  it('answers a denied call with the refusal and never runs it', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, input);
    t.gw.decide(t.gw.pending()[0]!, 'denied');
    expect(textOf(await t.guard.answer('a', CONTENTS, input))).toContain('Refused');
    expect(await t.guard.decision('a')).toBe('denied');
    expect(t.gw.executed).toHaveLength(0);
  });

  it('knows nothing about a call it never saw, and treats it as denied when asked to wait', async () => {
    const t = await guardSetup();
    expect(await t.guard.decision('nope')).toBe('unknown');
    expect([...(await t.guard.wait(['nope'])).values()]).toEqual(['denied']);
  });

  it('forgets a call, so the same question is asked again', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', STRUCTURE, input);
    t.guard.forget('a');
    await t.guard.answer('a', STRUCTURE, input);
    expect(t.sent).toHaveLength(2);
  });

  it('remembers a bounded number of calls, the oldest dropped first', async () => {
    const t = await guardSetup({ memoSize: 2 });
    for (const id of ['a', 'b', 'c']) await t.guard.answer(id, STRUCTURE, input);
    expect(t.guard.remembered).toBe(2);
    expect(t.guard.entry('a')).toBeUndefined();
    expect(t.guard.entry('c')).toBeDefined();
  });

  it('waits until AuthFI decides, and stops at the timeout or an abort without approving', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, input);
    let polls = 0;
    const decided = t.guard.wait(['a'], {
      sleep: () => {
        if (++polls === 2) t.gw.decide(t.gw.pending()[0]!, 'approved');
        return Promise.resolve();
      },
    });
    expect([...(await decided).values()]).toEqual(['approved']);
    expect(polls).toBe(2);

    const u = await guardSetup();
    await u.guard.answer('a', CONTENTS, input);
    expect([
      ...(await u.guard.wait(['a'], { timeoutMs: 1, sleep: () => Promise.resolve() })).values(),
    ]).toEqual(['pending']);
    const abort = new AbortController();
    abort.abort(new Error('stop'));
    await expect(u.guard.wait(['a'], { signal: abort.signal })).rejects.toThrow('stop');
    expect(u.gw.executed).toHaveLength(0);
  });

  it('stops the default sleep when the signal aborts while it waits', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, input);
    const abort = new AbortController();
    const waiting = t.guard.wait(['a'], { signal: abort.signal, timeoutMs: 60_000 });
    setTimeout(() => abort.abort(new Error('later')), 20);
    await expect(waiting).rejects.toThrow('later');
  });

  it("reports the caller's own reason when a stop lands inside the gateway call", async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, input);
    const abort = new AbortController();
    const stuck = new HoldGuard(t.run, (_key, _input, signal) =>
      Promise.reject(signal?.aborted === true ? new Error('transport: request aborted') : new Error('boom')),
    );
    stuck.adopt('a', CONTENTS, input, t.guard.pending()[0]!.approvalId);
    abort.abort(new Error('stopped by the caller'));
    await expect(stuck.wait(['a'], { signal: abort.signal })).rejects.toThrow('stopped by the caller');
    await expect(stuck.wait(['a'])).rejects.toThrow('boom');
  });

  it('adopts a held call another process sent, and runs it once when AuthFI approves', async () => {
    const t = await guardSetup();
    await t.guard.answer('a', CONTENTS, input);
    const approvalId = t.guard.pending()[0]!.approvalId;
    t.guard.forget('a');
    const entry = t.guard.adopt('b', CONTENTS, { ...input, [APPROVAL_ARGUMENT]: 'forged' }, approvalId);
    expect(entry.status).toBe('pending');
    expect(t.warns.join()).toContain('removed an approval id');
    expect(t.guard.pending()).toMatchObject([{ id: 'b', tool: CONTENTS, approvalId }]);
    expect(await t.guard.decision('b')).toBe('pending');
    t.gw.decide(t.gw.pending()[0]!, 'approved');
    expect(await t.guard.decision('b')).toBe('approved');
    expect(t.gw.executed).toHaveLength(1);
  });

  it('asks only for the pending calls when none are named', async () => {
    const t = await guardSetup();
    await t.guard.answer('held', CONTENTS, input);
    await t.guard.answer('ok', STRUCTURE, input);
    t.gw.decide(t.gw.pending()[0]!, 'denied');
    expect([...(await t.guard.wait(undefined)).entries()]).toEqual([['held', 'denied']]);
  });
});
