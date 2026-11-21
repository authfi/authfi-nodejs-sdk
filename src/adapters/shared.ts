/**
 * What the framework adapters (`./langchain`, `./openai-agents`, `./mastra`) share, so each one is
 * only the framework's own seam: the run's gateway `fetch` (run id, request ids, the credential
 * per request), and the guard that turns AuthFI's holds into the framework's approval mechanism
 * while letting only AuthFI's decision count.
 *
 * @packageDocumentation
 */

import { APIError, ApprovalPollRefused, ConfigurationError, NotSupportedError } from '../core/errors.js';
import { randomBytes } from '../core/bytes.js';
import { consoleLogger, type Logger } from '../core/logger.js';
import type { OpenTelemetryApi } from '../core/transport.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, type Gateway, type ToolResult } from '../gateway/gateway.js';
import type { Approval } from '../agents/agent.js';

/** A credential with gateways: an `AgentAuth`, a `DelegatedToken`, and in release 1 a mandate. */
export interface GatewaySource {
  gateway(): Gateway;
}

/** What reads an approval's state with the agent's own token: an `AgentAuth`. */
export interface ApprovalSource {
  approval(approvalId: string, options?: { signal?: AbortSignal | undefined }): Promise<Approval>;
}

/** The OpenTelemetry API, for the request id on the active span. */
export interface SpanApi extends Omit<OpenTelemetryApi, 'trace'> {
  readonly trace: {
    getActiveSpan(): { setAttribute(key: string, value: string): unknown } | undefined;
  };
}

/** Options every framework adapter takes. */
export interface AdapterOptions {
  /** The credential the run uses: the agent, or a token it holds for a person. */
  readonly source: GatewaySource;
  /** The run's id: on spans as `authfi.run_id`, and the prefix of each call's `X-Request-Id`. */
  readonly runId?: string | undefined;
  /** How often to ask the gateway about a pending approval (default 3 000 ms). */
  readonly pollIntervalMs?: number | undefined;
  /** How long waiting for a decision lasts (default 15 minutes). */
  readonly approvalTimeoutMs?: number | undefined;
  /**
   * Ask AuthFI where a held call's approval stands (`GET /v1/ai/auth/approvals/{id}`, with the agent's OWN access
   * token) instead of sending the call to the gateway each interval; the gateway is asked once, when the approval
   * is no longer pending, to release or refuse the call. Needs `source` to be an `AgentAuth`: a token held for a
   * person is refused on that route. A 401, 403 or 404 ends the wait at once with {@link ApprovalPollRefused}.
   */
  readonly approvalPoll?: boolean | undefined;
  /**
   * Wait for a held call's decision inside the tool, where the framework lets a tool take as long as it needs, and
   * continue by itself: no pause for the app to resume. Bounded by `approvalTimeoutMs`; undecided at the timeout
   * the model is told the call is waiting, never that it ran.
   */
  readonly waitInTool?: boolean | undefined;
  /** How many tool calls the adapter remembers, oldest dropped first (default 10 000). */
  readonly memoSize?: number | undefined;
  /** The `@opentelemetry/api` module, to stamp the request id on the active span. */
  readonly otel?: SpanApi | undefined;
  readonly logger?: Logger | undefined;
}

const RUN_ID = /^[A-Za-z0-9._:-]{1,96}$/;

/** What a model is told while a person has not decided. */
export const WAITING: ToolResult = { content: [{ type: 'text', text: HOLD_MESSAGE }], isError: true };

function hex(n: number): string {
  return Array.from(randomBytes(n), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** The text of a tool result, for frameworks whose tools answer with a string. */
export function textOf(result: ToolResult): string {
  return (result.content ?? [])
    .map((p) =>
      typeof p === 'object' && p !== null && (p as { type?: unknown }).type === 'text'
        ? (p as { text?: unknown }).text
        : undefined,
    )
    .filter((t): t is string => typeof t === 'string')
    .join('\n');
}

/** The same JSON for the same value whatever the key order, for naming a call by what it asks. */
export function canonicalJson(value: unknown): string {
  if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') return 'null';
  if (typeof value !== 'object' || value === null) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/** The credential and run identity of one agent run on the gateways. */
export class RunGateway {
  readonly runId: string;
  readonly gateway: Gateway;
  readonly logger: Logger;
  readonly pollMs: number;
  readonly timeoutMs: number;
  readonly memoSize: number;
  readonly waitInTool: boolean;
  readonly #approvals: ApprovalSource | undefined;
  readonly #otel: SpanApi | undefined;
  #calls = 0;

  constructor(options: AdapterOptions) {
    if (typeof (options.source as Partial<GatewaySource> | undefined)?.gateway !== 'function') {
      throw new ConfigurationError(
        'source must be an AgentAuth or a DelegatedToken: the adapter sends its token to the gateways',
      );
    }
    const runId = options.runId ?? `run-${hex(12)}`;
    if (!RUN_ID.test(runId))
      throw new ConfigurationError('runId must be 1-96 of A-Z a-z 0-9 . _ : - (it prefixes X-Request-Id)');
    const pollMs = options.pollIntervalMs ?? 3000;
    const timeoutMs = options.approvalTimeoutMs ?? 15 * 60_000;
    if (!(pollMs >= 100) || !(timeoutMs > 0))
      throw new ConfigurationError('pollIntervalMs must be at least 100 and approvalTimeoutMs positive');
    if (options.approvalPoll === true) {
      const own = options.source as Partial<ApprovalSource>;
      if (typeof own.approval !== 'function')
        throw new ConfigurationError(
          "approvalPoll needs source to be the agent itself (an AgentAuth): AuthFI answers an approval's state to the agent's own token, never to one held for a person",
        );
      this.#approvals = own as ApprovalSource;
    }
    this.waitInTool = options.waitInTool === true;
    this.gateway = options.source.gateway();
    this.runId = runId;
    this.pollMs = pollMs;
    this.timeoutMs = timeoutMs;
    this.memoSize = options.memoSize ?? 10_000;
    this.logger = options.logger ?? consoleLogger;
    this.#otel = options.otel;
  }

  /** Whether holds are polled on the approval route rather than on the gateway. */
  get polls(): boolean {
    return this.#approvals !== undefined;
  }

  /**
   * Where an approval stands, read with the agent's own token. A 401, 403 or 404 is {@link ApprovalPollRefused}: the
   * answer will not change, so nothing waits on it.
   */
  async approvalStatus(approvalId: string, signal?: AbortSignal): Promise<string> {
    if (this.#approvals === undefined) throw new ConfigurationError('approvalPoll is not on');
    try {
      return (await this.#approvals.approval(approvalId, { signal })).status;
    } catch (e) {
      const status = e instanceof APIError || e instanceof NotSupportedError ? e.status : undefined;
      if (e instanceof NotSupportedError || status === 401 || status === 403 || status === 404) {
        this.logger.warn('AuthFI would not say where an approval stands; the wait ends', {
          approval: approvalId,
          status,
        });
        throw new ApprovalPollRefused(
          approvalId,
          `AuthFI refused to read approval ${approvalId} for this agent (HTTP ${String(status ?? 'n/a')}): waiting longer cannot help`,
          { status, requestId: (e as APIError).requestId, cause: e },
        );
      }
      throw e;
    }
  }

  /** Attributes to stamp on the framework's spans: `authfi.agent_id` and `authfi.run_id`. */
  readonly enrichSpan = (): Record<string, string> => ({
    ...(this.gateway.agentId === undefined ? {} : { 'authfi.agent_id': this.gateway.agentId }),
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
    const res = await this.gateway.fetch(input, { ...init, headers });
    const span = this.#otel?.trace.getActiveSpan();
    const answered = res.headers.get('x-request-id');
    if (span !== undefined && answered !== null) span.setAttribute('authfi.request_id', answered);
    return res;
  };

  /**
   * Settings for an OpenAI-compatible client (`new OpenAI(...)`, `@langchain/openai`'s
   * `configuration`): the AI gateway's model route. `apiKey` is a placeholder; the real credential
   * replaces the `Authorization` header on every request.
   */
  openai(): { baseURL: string; apiKey: string; fetch: typeof fetch } {
    return { baseURL: this.gateway.modelBaseUrl('openai'), apiKey: 'authfi', fetch: this.fetch };
  }

  /** Settings for an Anthropic client (`new Anthropic(...)`, `@langchain/anthropic`'s `clientOptions`). */
  anthropic(): { baseURL: string; authToken: string; fetch: typeof fetch } {
    return { baseURL: this.gateway.modelBaseUrl('anthropic'), authToken: 'authfi', fetch: this.fetch };
  }
}

type Status = 'allowed' | 'refused' | 'pending' | 'approved' | 'denied';

/** What the guard remembers about one tool call. */
export interface HoldEntry {
  readonly key: string;
  readonly input: unknown;
  status: Status;
  /** The approval belongs to another run than this process's. Set once, with the refusal. */
  raiseAgain: boolean;
  approvalId: string | undefined;
  result: ToolResult | undefined;
  /** What the framework gave the call, handed back when it is sent again with its approval id. */
  readonly context: unknown;
}

/** Sends one tool call to the gateway and returns its full result (with `isError` and `_meta`). */
export type SendCall = (
  key: string,
  input: unknown,
  signal?: AbortSignal,
  context?: unknown,
) => Promise<ToolResult>;

/** What AuthFI has decided about a call a person had to approve. */
/**
 * `raise_again`: the gateway would not release the call to this process because another run raised the approval
 * (the project binds approvals to the run); the app asks for the call again.
 */
export type Decision = 'approved' | 'denied' | 'pending' | 'raise_again';

/** A call that waits on a person, as {@link HoldGuard.pending} lists it. */
export interface PendingApproval {
  readonly id: string;
  readonly tool: string;
  readonly approvalId: string;
  /** The tool's arguments, as the call was first made, so a new process can ask again with the approval id. */
  readonly input: unknown;
}

function withoutApprovalArgument(input: unknown, logger: Logger, key: string): unknown {
  if (typeof input !== 'object' || input === null || !(APPROVAL_ARGUMENT in input)) return input;
  const { [APPROVAL_ARGUMENT]: _dropped, ...copy } = input as Record<string, unknown>;
  logger.warn('removed an approval id the model put in a tool call; only AuthFI adds it', { tool: key });
  return copy;
}

/**
 * Remembers each call that AuthFI held for a person and asks the gateway again, with the approval
 * id it read, until AuthFI decides. A framework's own approval (a click in an app, `state.approve`)
 * never counts: the answer always comes from the gateway.
 */
export class HoldGuard {
  readonly #run: RunGateway;
  readonly #send: SendCall;
  readonly #memo = new Map<string, HoldEntry>();
  readonly #opening = new Map<string, Promise<HoldEntry>>();

  constructor(run: RunGateway, send: SendCall) {
    this.#run = run;
    this.#send = send;
  }

  /** How many tool calls are remembered right now. */
  get remembered(): number {
    return this.#memo.size;
  }

  #remember(id: string, entry: HoldEntry): void {
    this.#memo.delete(id);
    this.#memo.set(id, entry);
    while (this.#memo.size > this.#run.memoSize) {
      const oldest = this.#memo.keys().next().value;
      if (oldest === undefined) break;
      this.#memo.delete(oldest);
    }
  }

  #record(entry: HoldEntry, result: ToolResult, approving: boolean): void {
    const outcome = this.#run.gateway.readResult(result);
    if (outcome.kind === 'approval_required') {
      entry.status = 'pending';
      entry.approvalId = outcome.approvalId;
      entry.result = undefined;
      return;
    }
    // A call a mandate refused is told to the model with what it can still do, whichever framework asks.
    entry.result =
      outcome.kind === 'refused' && outcome.nextStep !== undefined
        ? { ...result, content: [{ type: 'text', text: outcome.modelText }] }
        : result;
    entry.raiseAgain = outcome.kind === 'refused' && outcome.why === 'approval_other_run';
    if (outcome.kind === 'refused') entry.status = approving ? 'denied' : 'refused';
    else entry.status = approving ? 'approved' : 'allowed';
  }

  async #recheck(entry: HoldEntry, signal?: AbortSignal): Promise<void> {
    const input = { ...(entry.input as Record<string, unknown>), [APPROVAL_ARGUMENT]: entry.approvalId };
    this.#record(entry, await this.#send(entry.key, input, signal, entry.context), true);
  }

  /**
   * The first sight of a call: sends it to the gateway once and remembers the answer under `id`.
   * A call already known is not sent again. Allowed and refused calls are answered by
   * {@link HoldGuard.answer} from what was remembered.
   */
  async begin(
    id: string,
    key: string,
    raw: unknown,
    signal?: AbortSignal,
    context?: unknown,
  ): Promise<HoldEntry> {
    const known = this.#memo.get(id);
    if (known !== undefined) return known;
    // The same call asked again while it is being sent is the same call: one gateway call, one answer.
    const running = this.#opening.get(id);
    if (running !== undefined) return running;
    const opening = this.#open(id, key, raw, signal, context).finally(() => this.#opening.delete(id));
    this.#opening.set(id, opening);
    return opening;
  }

  async #open(
    id: string,
    key: string,
    raw: unknown,
    signal: AbortSignal | undefined,
    context: unknown,
  ): Promise<HoldEntry> {
    const entry: HoldEntry = {
      key,
      input: withoutApprovalArgument(raw, this.#run.logger, key),
      status: 'allowed',
      raiseAgain: false,
      approvalId: undefined,
      result: undefined,
      context,
    };
    this.#record(entry, await this.#send(key, entry.input, signal, context), false);
    this.#remember(id, entry);
    return entry;
  }

  /**
   * Remembers a call that waits on a person and that this process did not send, from the approval
   * id read back by the caller (who has proven it is AuthFI's, not a model's or a browser's).
   */
  adopt(id: string, key: string, raw: unknown, approvalId: string, context?: unknown): HoldEntry {
    const entry: HoldEntry = {
      key,
      input: withoutApprovalArgument(raw, this.#run.logger, key),
      status: 'pending',
      raiseAgain: false,
      approvalId,
      result: undefined,
      context,
    };
    this.#remember(id, entry);
    return entry;
  }

  /** The remembered call, if any. */
  entry(id: string): HoldEntry | undefined {
    return this.#memo.get(id);
  }

  /** Forgets a call. */
  forget(id: string): void {
    this.#memo.delete(id);
  }

  /** Asks the gateway about a pending call once, and says where it stands. */
  async decision(id: string, signal?: AbortSignal): Promise<Decision | 'unknown'> {
    const entry = this.#memo.get(id);
    if (entry === undefined) return 'unknown';
    if (entry.status === 'pending') {
      // With approvalPoll the gateway is asked only once the person has decided, to release or refuse the call.
      if (this.#run.polls && entry.approvalId !== undefined) {
        if ((await this.#run.approvalStatus(entry.approvalId, signal)) === 'pending') return 'pending';
      }
      await this.#recheck(entry, signal);
    }
    if (entry.status === 'pending') return 'pending';
    if (entry.raiseAgain) return 'raise_again';
    return entry.status === 'approved' || entry.status === 'allowed' ? 'approved' : 'denied';
  }

  /**
   * The answer a tool gives the model: the gateway's result for an allowed or refused call, the
   * result of an approved call (made once, when AuthFI approved it), and "waiting" while a person
   * has not decided. A call made for the first time here is sent now. The call stays remembered, so
   * a framework that runs a step again after a pause gets the same answer without a second call;
   * {@link HoldGuard.forget} it when an `id` names what was asked rather than one call.
   */
  async answer(
    id: string,
    key: string,
    raw: unknown,
    signal?: AbortSignal,
    context?: unknown,
  ): Promise<ToolResult> {
    const entry = await this.begin(id, key, raw, signal, context);
    if (entry.status === 'pending') await this.#recheck(entry, signal);
    return entry.status === 'pending' || entry.result === undefined ? WAITING : entry.result;
  }

  /**
   * The calls that wait on a person, with what is needed to remember them in another process: see
   * {@link HoldGuard.restore}.
   */
  pending(): PendingApproval[] {
    return [...this.#memo.entries()]
      .filter((e): e is [string, HoldEntry & { approvalId: string }] => {
        return e[1].status === 'pending' && e[1].approvalId !== undefined;
      })
      .map(([id, e]) => ({ id, tool: e.key, approvalId: e.approvalId, input: e.input }));
  }

  /**
   * Remembers calls a person was asked about by another process (what {@link HoldGuard.pending} returned there,
   * kept by the app beside the framework's own saved state), so the resumed run asks the gateway about the same
   * approval instead of opening a second one. A call already known here is left as it is.
   */
  restore(pending: readonly PendingApproval[]): void {
    for (const p of pending) {
      if (this.#memo.has(p.id)) continue;
      this.adopt(p.id, p.tool, p.input, p.approvalId);
    }
  }

  /**
   * Waits inside a tool for AuthFI's decision on call `id`, bounded by the approval timeout. Undecided at the
   * timeout is `pending`, never approved.
   */
  async settle(id: string, signal?: AbortSignal): Promise<Decision> {
    return (await this.wait([id], { signal })).get(id) ?? 'denied';
  }

  /**
   * Waits until AuthFI has decided every call in `ids` (all pending ones when omitted), asking the
   * gateway again each poll interval. A call still undecided at the timeout is reported `pending`:
   * it is never treated as approved.
   */
  async wait(
    ids: readonly string[] | undefined,
    options: {
      signal?: AbortSignal | undefined;
      timeoutMs?: number | undefined;
      sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    } = {},
  ): Promise<Map<string, Decision>> {
    const deadline = performance.now() + (options.timeoutMs ?? this.#run.timeoutMs);
    const sleep = options.sleep ?? defaultSleep;
    const out = new Map<string, Decision>();
    await Promise.all(
      (ids ?? this.pending().map((p) => p.id)).map(async (id) => {
        try {
          let d = await this.decision(id, options.signal);
          while (d === 'pending' && performance.now() + this.#run.pollMs <= deadline) {
            await sleep(this.#run.pollMs, options.signal);
            d = await this.decision(id, options.signal);
          }
          out.set(id, d === 'unknown' ? 'denied' : d);
        } catch (e) {
          // A stop the caller asked for is reported as the caller's own reason, wherever it landed.
          if (options.signal?.aborted === true) throw options.signal.reason as Error;
          throw e;
        }
      }),
    );
    return out;
  }
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(signal.reason as Error);
      return;
    }
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        reject(signal.reason as Error);
      },
      { once: true },
    );
  });
}

export { APPROVAL_ARGUMENT, HOLD_MESSAGE };
