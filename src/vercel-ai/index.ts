/**
 * The Vercel AI SDK (`ai` 7) on AuthFI's MCP and AI gateways, with no glue of the app's own: the
 * credential per request below the tracer, refusals as tool results, approvals through the AI
 * SDK's `toolApproval` that resume only on AuthFI's decision, and content kept out of telemetry.
 *
 * @example
 * const authfi = createVercelAI({ source: agent, approvalSecret: new Secret(process.env.APPROVAL_SECRET!) });
 * const anthropic = createAnthropic(authfi.anthropic());
 * const mcp = await createMCPClient({ transport: authfi.mcpTransport() });
 * const tools = authfi.tools(await mcp.tools());
 * let result = await generateText({ model: anthropic(MODEL), tools, messages, ...authfi.approvals() });
 * while (authfi.pendingApprovals(result).length > 0) {
 *   messages.push(...result.response.messages, await authfi.awaitApprovals(result));
 *   result = await generateText({ model: anthropic(MODEL), tools, messages, ...authfi.approvals() });
 * }
 *
 * @packageDocumentation
 */

import type { ToolApprovalRequestOutput, ToolApprovalStatus, ToolSet } from 'ai';
import { base64url, constantTimeEqual, randomBytes, utf8 } from '../core/bytes.js';
import { ConfigurationError } from '../core/errors.js';
import { consoleLogger, type Logger } from '../core/logger.js';
import { isSecret, type Secret } from '../core/secret.js';
import type { OpenTelemetryApi } from '../core/transport.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, type Gateway, type ToolResult } from '../gateway/gateway.js';

/** A credential with gateways: an `AgentAuth`, a `DelegatedToken`, and in release 1 a mandate. */
export interface GatewaySource {
  gateway(): Gateway;
}

/** The OpenTelemetry API, for spans and the request id on them. */
export interface VercelOtelApi extends OpenTelemetryApi {
  readonly trace: {
    getActiveSpan(): { setAttribute(key: string, value: string): unknown } | undefined;
  };
}

/** How the adapter is configured. */
export interface VercelAIOptions {
  /** The credential the run uses: the agent, or a token it holds for a person. */
  readonly source: GatewaySource;
  /**
   * The secret the AI SDK signs approval requests with (32 bytes or more), the same in every
   * process that may resume a run, so a forged approval request is refused. Required.
   */
  readonly approvalSecret: Secret | Uint8Array;
  /** The run's id: on spans as `authfi.run_id`, and the prefix of each call's `X-Request-Id`. */
  readonly runId?: string | undefined;
  /** Record prompts, outputs and tool payloads in telemetry. Off by default; a tenant policy decision. */
  readonly captureContent?: boolean | undefined;
  /** How often to ask the gateway about a pending approval (default 3 000 ms). */
  readonly pollIntervalMs?: number | undefined;
  /** How long `awaitApprovals` waits (default 15 minutes). */
  readonly approvalTimeoutMs?: number | undefined;
  /** How many tool calls the adapter remembers, oldest dropped first (default 10 000). */
  readonly memoSize?: number | undefined;
  /** The `@opentelemetry/api` module, to stamp request ids on the active span. */
  readonly otel?: VercelOtelApi | undefined;
  readonly logger?: Logger | undefined;
}

/** The object forms of the AI SDK's own `ToolApprovalStatus`, which are the ones this adapter answers with. */
export type ApprovalDecision = Extract<ToolApprovalStatus, { type: string }>;

type Status = 'new' | 'allowed' | 'refused' | 'pending' | 'approved' | 'denied';

interface Entry {
  readonly key: string;
  readonly input: unknown;
  status: Status;
  approvalId: string | undefined;
  result: ToolResult | undefined;
}

const RUN_ID = /^[A-Za-z0-9._:-]{1,96}$/;
const REASON_PREFIX = 'AuthFI approval ';
/**
 * The approval request's reason: `AuthFI approval <id>.<mac>`. The AI SDK signs an approval request
 * but not its reason, and a resumed run reads its messages from the browser, so the AuthFI approval
 * id in the reason is bound to the tool call by an HMAC under the approval secret.
 */
const REASON = /^AuthFI approval ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const WAITING: ToolResult = { content: [{ type: 'text', text: HOLD_MESSAGE }], isError: true };
const DENIED_REASON = 'A person did not approve this action in AuthFI.';
const PENDING_REASON = 'This action has not been approved in AuthFI yet.';

/** A map that forgets its oldest entries past a size. */
class Memo {
  readonly #map = new Map<string, Entry>();
  constructor(readonly size: number) {}
  get(id: string): Entry | undefined {
    const e = this.#map.get(id);
    if (e !== undefined) {
      this.#map.delete(id);
      this.#map.set(id, e);
    }
    return e;
  }
  set(id: string, e: Entry): void {
    this.#map.delete(id);
    this.#map.set(id, e);
    while (this.#map.size > this.size) {
      const oldest = this.#map.keys().next().value;
      if (oldest === undefined) break;
      this.#map.delete(oldest);
    }
  }
  delete(id: string): void {
    this.#map.delete(id);
  }
  get length(): number {
    return this.#map.size;
  }
}

function withoutApprovalArgument(input: unknown, logger: Logger, key: string): unknown {
  if (typeof input !== 'object' || input === null || !(APPROVAL_ARGUMENT in input)) return input;
  const { [APPROVAL_ARGUMENT]: _dropped, ...copy } = input as Record<string, unknown>;
  logger.warn('removed an approval id the model put in a tool call; only AuthFI adds it', { tool: key });
  return copy;
}

function hex(n: number): string {
  return Array.from(randomBytes(n), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The adapter for one agent run on the Vercel AI SDK. Build one per run with
 * {@link createVercelAI}.
 */
export class VercelAIAdapter {
  readonly runId: string;
  readonly captureContent: boolean;
  readonly #gateway: Gateway;
  readonly #secret: Uint8Array;
  readonly #pollMs: number;
  readonly #timeoutMs: number;
  readonly #otel: VercelOtelApi | undefined;
  readonly #logger: Logger;
  readonly #tools = new Map<
    string,
    { execute: (input: unknown, options: Record<string, unknown>) => Promise<unknown> }
  >();
  readonly #memo: Memo;
  #calls = 0;
  #macKey: Promise<CryptoKey> | undefined;

  constructor(options: VercelAIOptions) {
    if (typeof (options.source as Partial<GatewaySource> | undefined)?.gateway !== 'function') {
      throw new ConfigurationError(
        'source must be an AgentAuth or a DelegatedToken: the adapter sends its token to the gateways',
      );
    }
    const secret = isSecret(options.approvalSecret)
      ? new TextEncoder().encode(options.approvalSecret.reveal())
      : options.approvalSecret;
    if (!(secret instanceof Uint8Array) || secret.length < 32) {
      throw new ConfigurationError(
        'approvalSecret is required, at least 32 bytes, and the same in every process that may resume a run: it signs approval requests',
      );
    }
    const runId = options.runId ?? `run-${hex(12)}`;
    if (!RUN_ID.test(runId))
      throw new ConfigurationError('runId must be 1-96 of A-Z a-z 0-9 . _ : - (it prefixes X-Request-Id)');
    const pollMs = options.pollIntervalMs ?? 3000;
    const timeoutMs = options.approvalTimeoutMs ?? 15 * 60_000;
    if (!(pollMs >= 100) || !(timeoutMs > 0))
      throw new ConfigurationError('pollIntervalMs must be at least 100 and approvalTimeoutMs positive');
    this.#gateway = options.source.gateway();
    this.#secret = secret;
    this.runId = runId;
    this.captureContent = options.captureContent === true;
    this.#pollMs = pollMs;
    this.#timeoutMs = timeoutMs;
    this.#otel = options.otel;
    this.#logger = options.logger ?? consoleLogger;
    this.#memo = new Memo(options.memoSize ?? 10_000);
  }

  /** Attributes to stamp on the AI SDK's spans: `authfi.agent_id` and `authfi.run_id`. */
  readonly enrichSpan = (): Record<string, string> => ({
    ...(this.#gateway.agentId === undefined ? {} : { 'authfi.agent_id': this.#gateway.agentId }),
    'authfi.run_id': this.runId,
  });

  /**
   * A `fetch` for the gateways: the current token on each request (never in a header a tracer
   * reads), `X-Request-Id` `<runId>.<n>`, `traceparent`, no redirects, AuthFI's origins only. The
   * request id the gateway answers is set on the active span.
   */
  readonly fetch: typeof fetch = async (input, init) => {
    const headers = new Headers(new Request(input, init).headers);
    if (!headers.has('x-request-id')) headers.set('x-request-id', `${this.runId}.${String(++this.#calls)}`);
    const res = await this.#gateway.fetch(input, { ...init, headers });
    const span = this.#otel?.trace.getActiveSpan();
    const answered = res.headers.get('x-request-id');
    if (span !== undefined && answered !== null) span.setAttribute('authfi.request_id', answered);
    return res;
  };

  /**
   * Settings for `createAnthropic` from `@ai-sdk/anthropic`: the AI gateway's model route.
   * `authToken` selects the `Authorization` header; its value is replaced on every request.
   */
  anthropic(): { baseURL: string; authToken: string; fetch: typeof fetch } {
    return {
      baseURL: `${this.#gateway.modelBaseUrl('anthropic')}/v1`,
      authToken: 'authfi',
      fetch: this.fetch,
    };
  }

  /** A transport for `createMCPClient` from `@ai-sdk/mcp`: the project's MCP gateway. */
  mcpTransport(): { type: 'http'; url: string; fetch: typeof fetch; redirect: 'error' } {
    return { type: 'http', url: this.#gateway.mcpUrl, fetch: this.fetch, redirect: 'error' };
  }

  /**
   * The MCP tools for `generateText`, under their gateway names (`<server>__<tool>`). Each execute
   * strips a model-written approval id, calls the gateway, and answers a refusal as the tool's
   * result. A call AuthFI already answered during approval is not made again.
   */
  tools<T extends ToolSet>(mcpTools: T): T {
    if (typeof mcpTools !== 'object')
      throw new ConfigurationError('tools() takes the record mcpClient.tools() returns');
    const out: Record<string, unknown> = {};
    for (const [key, tool] of Object.entries(mcpTools)) {
      const execute = (tool as { execute?: unknown }).execute;
      if (typeof execute !== 'function')
        throw new ConfigurationError(`MCP tool ${key} has no execute function`);
      this.#tools.set(key, {
        execute: execute as (input: unknown, options: Record<string, unknown>) => Promise<unknown>,
      });
      out[key] = {
        ...tool,
        execute: (input: unknown, opts: Record<string, unknown>) => this.#execute(key, input, opts),
      };
    }
    return out as T;
  }

  /** The grant object of a tool (`mcp:<server>.<tool>`), for a CIBA request or a token exchange. */
  scope(tool: { readonly _meta?: Readonly<Record<string, unknown>> | undefined }): string | undefined {
    return this.#gateway.scopeOf(tool);
  }

  async #call(key: string, input: unknown, opts: Record<string, unknown> = {}): Promise<ToolResult> {
    const tool = this.#tools.get(key);
    if (tool === undefined)
      throw new ConfigurationError(`no AuthFI tool ${key}: pass the tools through authfi.tools() first`);
    return (await tool.execute(input, opts)) as ToolResult;
  }

  #record(entry: Entry, result: ToolResult, approving: boolean): void {
    const outcome = this.#gateway.readResult(result);
    if (outcome.kind === 'approval_required') {
      entry.status = 'pending';
      entry.approvalId = outcome.approvalId;
      entry.result = undefined;
      return;
    }
    entry.result = result;
    if (outcome.kind === 'refused') entry.status = approving ? 'denied' : 'refused';
    else entry.status = approving ? 'approved' : 'allowed';
  }

  /** Asks the gateway again with the approval id: still pending, approved (the call ran), or refused. */
  async #check(entry: Entry, opts: Record<string, unknown> = {}): Promise<void> {
    const input = { ...(entry.input as Record<string, unknown>), [APPROVAL_ARGUMENT]: entry.approvalId };
    this.#record(entry, await this.#call(entry.key, input, opts), true);
  }

  async #execute(key: string, raw: unknown, opts: Record<string, unknown>): Promise<unknown> {
    const input = withoutApprovalArgument(raw, this.#logger, key);
    const id = typeof opts.toolCallId === 'string' ? opts.toolCallId : undefined;
    const known = id === undefined ? undefined : this.#memo.get(id);
    if (
      known?.result !== undefined &&
      (known.status === 'allowed' || known.status === 'approved' || known.status === 'refused')
    ) {
      if (id !== undefined) this.#memo.delete(id);
      return known.result;
    }
    if (known?.status === 'pending') {
      await this.#check(known, opts);
      return known.result ?? WAITING;
    }
    const entry: Entry = { key, input, status: 'new', approvalId: undefined, result: undefined };
    this.#record(entry, await this.#call(key, input, opts), false);
    // A hold's text tells the model how to retry with the approval id; the model never sees it.
    if (entry.status === 'pending') {
      if (id !== undefined) this.#memo.set(id, entry);
      return WAITING;
    }
    return entry.result;
  }

  #approve(key: string) {
    return async (
      raw: unknown,
      options: { toolCallId?: string; messages?: readonly unknown[] } = {},
    ): Promise<ApprovalDecision> => {
      const id = options.toolCallId;
      if (id === undefined) return { type: 'not-applicable' };
      const input = withoutApprovalArgument(raw, this.#logger, key);
      const entry = this.#memo.get(id) ?? (await this.#restore(key, input, id, options.messages));
      if (entry === undefined) {
        // First evaluation: AuthFI decides when the call reaches the gateway, so it is made now, once.
        const fresh: Entry = { key, input, status: 'new', approvalId: undefined, result: undefined };
        this.#memo.set(id, fresh);
        try {
          this.#record(fresh, await this.#call(key, input), false);
        } catch (e) {
          this.#memo.delete(id);
          throw e;
        }
        if (fresh.status === 'pending' && fresh.approvalId !== undefined)
          return { type: 'user-approval', reason: await this.#reasonFor(id, key, fresh.approvalId) };
        return { type: 'not-applicable' }; // allowed or refused: execute returns the answer AuthFI gave
      }
      // Evaluated again on resume: only AuthFI's decision counts.
      if (entry.status === 'pending') await this.#check(entry);
      if (entry.status === 'approved' || entry.status === 'allowed') return { type: 'approved' };
      if (entry.status === 'pending') return { type: 'denied', reason: PENDING_REASON };
      this.#memo.delete(id);
      return { type: 'denied', reason: DENIED_REASON };
    };
  }

  #mac(toolCallId: string, toolName: string, approvalId: string): Promise<Uint8Array> {
    this.#macKey ??= crypto.subtle.importKey(
      'raw',
      new Uint8Array(this.#secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const message = utf8(`${toolCallId}\u0000${toolName}\u0000${approvalId}`);
    return this.#macKey.then(async (key) => new Uint8Array(await crypto.subtle.sign('HMAC', key, message)));
  }

  async #reasonFor(toolCallId: string, toolName: string, approvalId: string): Promise<string> {
    return `${REASON_PREFIX}${approvalId}.${base64url(await this.#mac(toolCallId, toolName, approvalId))}`;
  }

  /**
   * The memo entry of a call from another process, read back from the approval request's reason,
   * only when its HMAC shows this adapter's secret bound that approval id to that tool call.
   */
  async #restore(
    key: string,
    input: unknown,
    toolCallId: string,
    messages: readonly unknown[] | undefined,
  ): Promise<Entry | undefined> {
    for (const m of messages ?? []) {
      const content = (m as { role?: string; content?: unknown }).content;
      if (!Array.isArray(content)) continue;
      for (const p of content as { type?: string; toolCallId?: string; reason?: string }[]) {
        if (p.type !== 'tool-approval-request' || p.toolCallId !== toolCallId) continue;
        const parsed = REASON.exec(p.reason ?? '');
        const approvalId = parsed?.[1];
        const given = parsed?.[2];
        if (approvalId === undefined || given === undefined) return undefined;
        const expected = base64url(await this.#mac(toolCallId, key, approvalId));
        if (!constantTimeEqual(utf8(given), utf8(expected))) {
          this.#logger.warn(
            'ignored an approval request whose AuthFI approval id this adapter did not sign',
            {
              tool: key,
            },
          );
          return undefined;
        }
        const entry: Entry = { key, input, status: 'pending', approvalId, result: undefined };
        this.#memo.set(toolCallId, entry);
        return entry;
      }
    }
    return undefined;
  }

  /**
   * Settings for `generateText` and `streamText`: a `toolApproval` for each AuthFI tool, and the
   * secret that signs approval requests. Spread them into the call; add your own tools' entries to
   * `toolApproval` if you have any.
   */
  approvals(): {
    toolApproval: Record<string, ReturnType<VercelAIAdapter['approvalFor']>>;
    experimental_toolApprovalSecret: Uint8Array;
  } {
    const toolApproval: Record<string, ReturnType<VercelAIAdapter['approvalFor']>> = {};
    for (const key of this.#tools.keys()) toolApproval[key] = this.approvalFor(key);
    return { toolApproval, experimental_toolApprovalSecret: this.#secret };
  }

  /** The `toolApproval` function for one AuthFI tool. */
  approvalFor(
    key: string,
  ): (
    input: unknown,
    options?: { toolCallId?: string; messages?: readonly unknown[] },
  ) => Promise<ApprovalDecision> {
    return this.#approve(key);
  }

  /** The approval requests in a result that wait on AuthFI. */
  pendingApprovals(result: { readonly content?: readonly unknown[] }): ToolApprovalRequestOutput<ToolSet>[] {
    return (result.content ?? []).filter(
      (p): p is ToolApprovalRequestOutput<ToolSet> =>
        typeof p === 'object' &&
        p !== null &&
        (p as { type?: unknown }).type === 'tool-approval-request' &&
        this.#tools.has((p as ToolApprovalRequestOutput<ToolSet>).toolCall.toolName),
    );
  }

  /**
   * Waits for AuthFI's decision on each pending approval in `result`, asking the gateway again with
   * the approval id, and returns the tool message to append before calling `generateText` again.
   * Each answer comes from AuthFI's decision alone. An approved call already ran once, through the
   * gateway; the resumed run returns that result instead of calling again.
   */
  async awaitApprovals(
    result: { readonly content?: readonly unknown[] },
    options: {
      signal?: AbortSignal;
      timeoutMs?: number;
      sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    } = {},
  ): Promise<{
    role: 'tool';
    content: { type: 'tool-approval-response'; approvalId: string; approved: boolean; reason?: string }[];
  }> {
    const timeout = options.timeoutMs ?? this.#timeoutMs;
    const deadline = performance.now() + timeout;
    const sleep =
      options.sleep ??
      ((ms: number, signal?: AbortSignal) =>
        new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, ms);
          signal?.addEventListener('abort', () => {
            clearTimeout(t);
            reject(signal.reason as Error);
          });
        }));
    const content = await Promise.all(
      this.pendingApprovals(result).map(async (part) => {
        const { toolCallId, toolName } = part.toolCall;
        const input: unknown = part.toolCall.input;
        const entry =
          this.#memo.get(toolCallId) ??
          (await this.#restore(toolName, input, toolCallId, [{ content: [{ ...part, toolCallId }] }]));
        if (entry === undefined)
          throw new ConfigurationError(`no AuthFI approval is known for tool call ${toolCallId}`);
        while (entry.status === 'pending') {
          if (performance.now() + this.#pollMs > deadline) {
            return {
              type: 'tool-approval-response' as const,
              approvalId: part.approvalId,
              approved: false,
              reason: PENDING_REASON,
            };
          }
          await sleep(this.#pollMs, options.signal);
          await this.#check(entry, options.signal === undefined ? {} : { abortSignal: options.signal });
        }
        const approved = entry.status === 'approved' || entry.status === 'allowed';
        if (!approved) this.#memo.delete(toolCallId);
        return {
          type: 'tool-approval-response' as const,
          approvalId: part.approvalId,
          approved,
          ...(approved ? {} : { reason: DENIED_REASON }),
        };
      }),
    );
    return { role: 'tool', content };
  }

  /**
   * Wraps an `ai` telemetry integration (such as `@ai-sdk/otel`'s) so it records no prompts,
   * outputs, tool arguments or results unless `captureContent` is on.
   */
  telemetry<T extends object>(integration: T): T {
    if (typeof integration !== 'object')
      throw new ConfigurationError('telemetry() takes a telemetry integration object');
    const capture = this.captureContent;
    return new Proxy(integration, {
      get(target, prop) {
        const value: unknown = Reflect.get(target, prop, target);
        if (typeof value !== 'function') return value;
        const fn = value as (...args: unknown[]) => unknown;
        if (!capture && typeof prop === 'string' && /^(experimental_)?on[A-Za-z]*Start$/.test(prop)) {
          return (event: unknown, ...rest: unknown[]) =>
            fn.call(
              target,
              typeof event === 'object' && event !== null
                ? { ...event, recordInputs: false, recordOutputs: false }
                : event,
              ...rest,
            );
        }
        return fn.bind(target);
      },
    });
  }

  /** How many tool calls the adapter remembers right now. */
  get remembered(): number {
    return this.#memo.length;
  }
}

/** The Vercel AI SDK adapter for one agent run. */
export function createVercelAI(options: VercelAIOptions): VercelAIAdapter {
  return new VercelAIAdapter(options);
}

export { APPROVAL_ARGUMENT, HOLD_MESSAGE };
