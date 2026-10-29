/**
 * Mastra on AuthFI's MCP and AI gateways: the project's MCP tools through Mastra's own `MCPClient`
 * with the credential per request, a held call as Mastra's own tool approval that resumes only on
 * AuthFI's decision, and a refusal as the tool's answer.
 *
 * @example
 * const authfi = createMastra({ source: agent });
 * const mcp = new MCPClient({ servers: { authfi: authfi.mcpServer() } });
 * const tools = authfi.tools(await mcp.listTools());
 * const agentDef = new Agent({ id: 'a', name: 'a', instructions, model, tools });
 * const out = await agentDef.generate(prompt); // a hold suspends the run for approval
 * await authfi.awaitApprovals();               // AuthFI's decision, not a click in this app
 * await agentDef.approveToolCall({ runId: out.runId });
 *
 * @packageDocumentation
 */

import { ConfigurationError } from '../core/errors.js';
import {
  canonicalJson,
  HoldGuard,
  RunGateway,
  type AdapterOptions,
  type Decision,
} from '../adapters/shared.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, type ToolResult } from '../gateway/gateway.js';

export type { AdapterOptions as MastraOptions, GatewaySource, SpanApi } from '../adapters/shared.js';

/** The part of a Mastra tool the adapter replaces or reads. */
export interface MastraToolLike {
  execute?: ((input: unknown, context?: MastraContextLike) => Promise<unknown>) | undefined;
}

/** The part of Mastra's tool execution context the adapter reads. */
export interface MastraContextLike {
  readonly toolCallId?: string | undefined;
  readonly abortSignal?: AbortSignal | undefined;
}

/** A Mastra MCP server definition (`new MCPClient({ servers })`) for the project's gateway. */
export interface MastraServerDefinition {
  url: URL;
  fetch: (url: string | URL, init?: RequestInit) => Promise<Response>;
  /** A refusal comes back as the tool's result, not as an exception. */
  onToolError: 'return';
}

/**
 * The adapter for one agent run on Mastra. Build one per run with {@link createMastra}.
 */
export class MastraAdapter {
  readonly #run: RunGateway;
  readonly #guard: HoldGuard;
  readonly #tools = new Map<string, NonNullable<MastraToolLike['execute']>>();

  constructor(options: AdapterOptions) {
    this.#run = new RunGateway(options);
    this.#guard = new HoldGuard(this.#run, async (key, input, signal, context) => {
      const execute = this.#tools.get(key);
      if (execute === undefined)
        throw new ConfigurationError(`no AuthFI tool ${key}: pass the tools through authfi.tools() first`);
      const base = (context ?? {}) as MastraContextLike;
      return (await execute(input, {
        ...base,
        ...(signal === undefined ? {} : { abortSignal: signal }),
      })) as ToolResult;
    });
  }

  /** The run's id. */
  get runId(): string {
    return this.#run.runId;
  }

  /** A `fetch` for the gateways: see {@link RunGateway.fetch}. */
  get fetch(): typeof fetch {
    return this.#run.fetch;
  }

  /** Attributes to stamp on spans: `authfi.agent_id` and `authfi.run_id`. */
  readonly enrichSpan = (): Record<string, string> => this.#run.enrichSpan();

  /** Settings for an OpenAI-compatible Mastra model (`{ url, apiKey, fetch }` provider): the AI gateway's model route. */
  openai(): { baseURL: string; apiKey: string; fetch: typeof fetch } {
    return this.#run.openai();
  }

  /** The server definition for `new MCPClient({ servers: { <name>: ... } })`. */
  mcpServer(): MastraServerDefinition {
    return {
      url: new URL(this.#run.gateway.mcpUrl),
      fetch: (url, init) => this.#run.fetch(url, init),
      onToolError: 'return',
    };
  }

  /**
   * The tools `mcp.listTools()` returned, with AuthFI's decision in front of each: a model-written
   * approval id is removed, a refusal is the tool's answer, and a call that needs a person goes
   * through Mastra's own approval and runs only once AuthFI has approved it.
   */
  tools<T extends Record<string, object>>(listed: T): T {
    if (typeof listed !== 'object' || (listed as unknown) === null)
      throw new ConfigurationError('tools() takes the record mcp.listTools() returns');
    const out: Record<string, object> = {};
    for (const [name, tool] of Object.entries(listed)) {
      const execute = (tool as MastraToolLike).execute;
      if (typeof execute !== 'function')
        throw new ConfigurationError(`MCP tool ${name} has no execute function`);
      // The gateway names the tool by its MCP name; Mastra keys it `<server>_<tool>`.
      this.#tools.set(name, execute.bind(tool));
      const idOf = (input: unknown, toolCallId: string | undefined): string =>
        toolCallId ?? `${name}\u0000${canonicalJson(input)}`;
      const needsApproval = async (input: unknown, ctx?: MastraContextLike): Promise<boolean> => {
        const id = idOf(input, ctx?.toolCallId);
        const seen = this.#guard.entry(id) !== undefined;
        const entry = await this.#guard.begin(id, name, input, ctx?.abortSignal, ctx);
        if (entry.status !== 'pending') return false;
        return seen ? (await this.#guard.decision(id, ctx?.abortSignal)) === 'pending' : true;
      };
      const wrapped = async (input: unknown, ctx?: MastraContextLike): Promise<unknown> => {
        const id = idOf(input, ctx?.toolCallId);
        const result = await this.#guard.answer(id, name, input, ctx?.abortSignal, ctx);
        if (ctx?.toolCallId === undefined) this.#guard.forget(id);
        return result;
      };
      out[name] = new Proxy(tool, {
        get(target, prop) {
          if (prop === 'execute') return wrapped;
          if (prop === 'needsApprovalFn') return needsApproval;
          if (prop === 'requireApproval') return true;
          const value: unknown = Reflect.get(target, prop, target);
          return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
        },
      });
    }
    return out as T;
  }

  /** The calls that wait on a person's approval in AuthFI. */
  pendingApprovals(): { id: string; tool: string; approvalId: string }[] {
    return this.#guard.pending();
  }

  /**
   * Waits for AuthFI's decision on every pending call, asking the gateway again each poll
   * interval. Approve in Mastra afterwards: the tool asks the gateway once more, so a call AuthFI
   * has not approved is answered "waiting", never run.
   */
  async awaitApprovals(
    options: {
      signal?: AbortSignal | undefined;
      timeoutMs?: number | undefined;
      sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    } = {},
  ): Promise<Map<string, Decision>> {
    return this.#guard.wait(undefined, options);
  }

  /** How many tool calls the adapter remembers right now. */
  get remembered(): number {
    return this.#guard.remembered;
  }
}

/** The Mastra adapter for one agent run. */
export function createMastra(options: AdapterOptions): MastraAdapter {
  return new MastraAdapter(options);
}

export { APPROVAL_ARGUMENT, HOLD_MESSAGE };
