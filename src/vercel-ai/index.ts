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
import { base64url, constantTimeEqual, utf8 } from '../core/bytes.js';
import { ConfigurationError } from '../core/errors.js';
import { consoleLogger, type Logger } from '../core/logger.js';
import { isSecret, type Secret } from '../core/secret.js';
import {
  HoldGuard,
  RunGateway,
  type AdapterOptions,
  type GatewaySource,
  type HoldEntry,
  type SpanApi,
} from '../adapters/shared.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, type ToolResult } from '../gateway/gateway.js';

export type { GatewaySource };

/** The OpenTelemetry API, for spans and the request id on them. */
export type VercelOtelApi = SpanApi;

/** How the adapter is configured. */
export interface VercelAIOptions extends AdapterOptions {
  /**
   * The secret the AI SDK signs approval requests with (32 bytes or more), the same in every
   * process that may resume a run, so a forged approval request is refused. Required.
   */
  readonly approvalSecret: Secret | Uint8Array;
  /** Record prompts, outputs and tool payloads in telemetry. Off by default; a tenant policy decision. */
  readonly captureContent?: boolean | undefined;
}

/** The object forms of the AI SDK's own `ToolApprovalStatus`, which are the ones this adapter answers with. */
export type ApprovalDecision = Extract<ToolApprovalStatus, { type: string }>;

const REASON_PREFIX = 'AuthFI approval ';
/**
 * The approval request's reason: `AuthFI approval <id>.<mac>`. The AI SDK signs an approval request
 * but not its reason, and a resumed run reads its messages from the browser, so the AuthFI approval
 * id in the reason is bound to the tool call by an HMAC under the approval secret.
 */
const REASON = /^AuthFI approval ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const DENIED_REASON = 'A person did not approve this action in AuthFI.';
const PENDING_REASON = 'This action has not been approved in AuthFI yet.';

type ToolExecute = (input: unknown, options: Record<string, unknown>) => Promise<unknown>;

/**
 * The adapter for one agent run on the Vercel AI SDK. Build one per run with
 * {@link createVercelAI}. The run's gateway `fetch` and the hold logic are the shared
 * {@link RunGateway} and {@link HoldGuard}; this class is the AI SDK's own seam over them
 * (`execute`, `toolApproval`, the signed approval request).
 */
export class VercelAIAdapter {
  readonly runId: string;
  readonly captureContent: boolean;
  readonly #run: RunGateway;
  readonly #guard: HoldGuard;
  readonly #source: GatewaySource;
  #steps: Promise<import('../otel/index.js').AuthFITelemetry> | undefined;
  readonly #secret: Uint8Array;
  readonly #logger: Logger;
  readonly #tools = new Map<string, { execute: ToolExecute }>();
  #anonymous = 0;
  #macKey: Promise<CryptoKey> | undefined;

  /** Attributes to stamp on the AI SDK's spans: `authfi.agent_id` and `authfi.run_id`. */
  readonly enrichSpan: () => Record<string, string>;

  /**
   * A `fetch` for the gateways: the current token on each request (never in a header a tracer
   * reads), `X-Request-Id` `<runId>.<n>`, `traceparent`, no redirects, AuthFI's origins only. The
   * request id the gateway answers is set on the active span.
   */
  readonly fetch: typeof fetch;

  constructor(options: VercelAIOptions) {
    this.#run = new RunGateway(options);
    const secret = isSecret(options.approvalSecret)
      ? new TextEncoder().encode(options.approvalSecret.reveal())
      : options.approvalSecret;
    if (!(secret instanceof Uint8Array) || secret.length < 32) {
      throw new ConfigurationError(
        'approvalSecret is required, at least 32 bytes, and the same in every process that may resume a run: it signs approval requests',
      );
    }
    this.#source = options.source;
    this.#secret = secret;
    this.runId = this.#run.runId;
    this.captureContent = options.captureContent === true;
    this.#logger = options.logger ?? consoleLogger;
    this.#guard = new HoldGuard(this.#run, (key, input, signal, context) =>
      this.#call(key, input, signal, context),
    );
    this.enrichSpan = this.#run.enrichSpan;
    this.fetch = this.#run.fetch;
  }

  /**
   * Settings for `createAnthropic` from `@ai-sdk/anthropic`: the AI gateway's model route.
   * `authToken` selects the `Authorization` header; its value is replaced on every request.
   */
  anthropic(): { baseURL: string; authToken: string; fetch: typeof fetch } {
    return {
      baseURL: `${this.#run.gateway.modelBaseUrl('anthropic')}/v1`,
      authToken: 'authfi',
      fetch: this.fetch,
    };
  }

  /** A transport for `createMCPClient` from `@ai-sdk/mcp`: the project's MCP gateway. */
  mcpTransport(): { type: 'http'; url: string; fetch: typeof fetch; redirect: 'error' } {
    return { type: 'http', url: this.#run.gateway.mcpUrl, fetch: this.fetch, redirect: 'error' };
  }

  /**
   * The MCP tools for `generateText`, under their gateway names (`<server>__<tool>`). Each execute
   * omits the tools AuthFI says are never allowed to this agent, strips a model-written approval id, calls the gateway, and answers a refusal as the tool's
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
      // A tool the gateway says is never allowed to this agent is not offered to the model.
      if (!this.#run.gateway.offerable(tool as object)) continue;
      this.#tools.set(key, { execute: execute as ToolExecute });
      out[key] = {
        ...tool,
        execute: (input: unknown, opts: Record<string, unknown>) => this.#execute(key, input, opts),
      };
    }
    return out as T;
  }

  /** The grant object of a tool (`mcp:<server>.<tool>`), for a CIBA request or a token exchange. */
  scope(tool: { readonly _meta?: Readonly<Record<string, unknown>> | undefined }): string | undefined {
    return this.#run.gateway.scopeOf(tool);
  }

  /** Sends one call to the gateway through the AI SDK's own tool, with the options it was given. */
  async #call(
    key: string,
    input: unknown,
    signal: AbortSignal | undefined,
    context: unknown,
  ): Promise<ToolResult> {
    const tool = this.#tools.get(key);
    if (tool === undefined)
      throw new ConfigurationError(`no AuthFI tool ${key}: pass the tools through authfi.tools() first`);
    const { abortSignal: _stale, ...opts } = (context ?? {}) as Record<string, unknown>;
    return (await tool.execute(
      input,
      signal === undefined ? opts : { ...opts, abortSignal: signal },
    )) as ToolResult;
  }

  async #execute(key: string, raw: unknown, opts: Record<string, unknown>): Promise<unknown> {
    const given = typeof opts.toolCallId === 'string' ? opts.toolCallId : undefined;
    const id = given ?? `anonymous-${String(++this.#anonymous)}`;
    const signal = opts.abortSignal instanceof AbortSignal ? opts.abortSignal : undefined;
    const result = await this.#guard.answer(id, key, raw, signal, opts);
    // A held call stays remembered, under the AI SDK's id for it, until AuthFI decides.
    if (given === undefined || this.#guard.entry(id)?.status !== 'pending') this.#guard.forget(id);
    return result;
  }

  #approve(key: string) {
    return async (
      raw: unknown,
      options: { toolCallId?: string; messages?: readonly unknown[] } = {},
    ): Promise<ApprovalDecision> => {
      const id = options.toolCallId;
      if (id === undefined) return { type: 'not-applicable' };
      const known = this.#guard.entry(id) ?? (await this.#restore(key, raw, id, options.messages));
      if (known === undefined) {
        // First evaluation: AuthFI decides when the call reaches the gateway, so it is made now, once.
        const fresh = await this.#guard.begin(id, key, raw);
        if (fresh.status === 'pending' && fresh.approvalId !== undefined)
          return { type: 'user-approval', reason: await this.#reasonFor(id, key, fresh.approvalId) };
        return { type: 'not-applicable' }; // allowed or refused: execute returns the answer AuthFI gave
      }
      // Evaluated again on resume: only AuthFI's decision counts.
      const decision = await this.#guard.decision(id);
      if (decision === 'approved') return { type: 'approved' };
      if (decision === 'pending') return { type: 'denied', reason: PENDING_REASON };
      this.#guard.forget(id);
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
   * The guard's entry for a call from another process, read back from the approval request's
   * reason, only when its HMAC shows this adapter's secret bound that approval id to that tool call.
   */
  async #restore(
    key: string,
    input: unknown,
    toolCallId: string,
    messages: readonly unknown[] | undefined,
  ): Promise<HoldEntry | undefined> {
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
        return this.#guard.adopt(toolCallId, key, input, approvalId);
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
      signal?: AbortSignal | undefined;
      timeoutMs?: number | undefined;
      sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    } = {},
  ): Promise<{
    role: 'tool';
    content: { type: 'tool-approval-response'; approvalId: string; approved: boolean; reason?: string }[];
  }> {
    const parts = this.pendingApprovals(result);
    for (const part of parts) {
      const { toolCallId, toolName } = part.toolCall;
      const input: unknown = part.toolCall.input;
      const known =
        this.#guard.entry(toolCallId) ??
        (await this.#restore(toolName, input, toolCallId, [{ content: [{ ...part, toolCallId }] }]));
      if (known === undefined)
        throw new ConfigurationError(`no AuthFI approval is known for tool call ${toolCallId}`);
    }
    const decisions = await this.#guard.wait(
      parts.map((p) => p.toolCall.toolCallId),
      options,
    );
    const content = parts.map((part) => {
      const { toolCallId } = part.toolCall;
      const decision = decisions.get(toolCallId) ?? 'denied';
      if (decision === 'denied') this.#guard.forget(toolCallId);
      return {
        type: 'tool-approval-response' as const,
        approvalId: part.approvalId,
        approved: decision === 'approved',
        ...(decision === 'approved'
          ? {}
          : { reason: decision === 'pending' ? PENDING_REASON : DENIED_REASON }),
      };
    });
    return { role: 'tool', content };
  }

  /**
   * Sends this run's steps (model calls, tool calls) to AuthFI, in one line: registers the AI SDK's
   * own OpenTelemetry integration (`@ai-sdk/otel`) over a tracer provider that exports to
   * `<issuer>/otlp/v1/traces` under this credential, stamps `authfi.agent_id` and this run's
   * `authfi.run_id` on every span, and records no content unless `captureContent` is on. Needs
   * `@ai-sdk/otel`, `@opentelemetry/api`, `@opentelemetry/sdk-trace-base` and
   * `@opentelemetry/otlp-transformer`.
   *
   * The AI SDK's `registerTelemetry` only adds integrations, so this adds one, once per adapter, and
   * `shutdown()` takes it out again and sends what is buffered: call it before the process exits.
   *
   * @example
   * const steps = await authfi.exportSteps();
   * // ... generateText(...) ...
   * await steps.shutdown();
   */
  async exportSteps(
    options: { scheduleDelayMs?: number | undefined } = {},
  ): Promise<import('../otel/index.js').AuthFITelemetry> {
    this.#steps ??= this.#startSteps(options);
    return this.#steps;
  }

  async #startSteps(options: {
    scheduleDelayMs?: number | undefined;
  }): Promise<import('../otel/index.js').AuthFITelemetry> {
    const [{ registerAuthFITelemetry }, { OpenTelemetry }, { registerTelemetry }] = await Promise.all([
      import('../otel/index.js'),
      import('@ai-sdk/otel'),
      import('ai'),
    ]);
    const telemetry = registerAuthFITelemetry({
      source: this.#source,
      runId: this.runId,
      captureContent: this.captureContent,
      global: false,
      logger: this.#logger,
      scheduleDelayMs: options.scheduleDelayMs,
    });
    const integration = this.telemetry(new OpenTelemetry({ tracer: telemetry.tracer }));
    registerTelemetry(integration);
    return {
      ...telemetry,
      shutdown: async () => {
        // The AI SDK has no way to unregister; take our integration out of its list by identity.
        const list = (globalThis as { AI_SDK_TELEMETRY_INTEGRATIONS?: unknown[] })
          .AI_SDK_TELEMETRY_INTEGRATIONS;
        const at = list?.indexOf(integration) ?? -1;
        if (at >= 0) list?.splice(at, 1);
        this.#steps = undefined;
        await telemetry.shutdown();
      },
    };
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
    return this.#guard.remembered;
  }
}

/** The Vercel AI SDK adapter for one agent run. */
export function createVercelAI(options: VercelAIOptions): VercelAIAdapter {
  return new VercelAIAdapter(options);
}

export { APPROVAL_ARGUMENT, HOLD_MESSAGE };
