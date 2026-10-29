/**
 * The OpenAI Agents SDK for JavaScript on AuthFI's MCP and AI gateways: the project's MCP tools as
 * function tools, a held call as the SDK's own `needsApproval` interruption that resumes only on
 * AuthFI's decision, and the credential per request.
 *
 * @example
 * const authfi = createOpenAIAgents({ source: agent });
 * const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
 * await server.connect();
 * const agentDef = new Agent({ name: 'a', model, tools: await authfi.tools(server) });
 * let result = await run(agentDef, 'Read the wiki of pallets/itsdangerous.');
 * while (result.interruptions?.length) {
 *   await authfi.awaitApprovals(result.state); // approves or rejects as AuthFI decided
 *   result = await run(agentDef, result.state);
 * }
 *
 * @packageDocumentation
 */

import { tool, type FunctionTool } from '@openai/agents';
import { ConfigurationError } from '../core/errors.js';
import {
  canonicalJson,
  HoldGuard,
  RunGateway,
  textOf,
  type AdapterOptions,
  type Decision,
} from '../adapters/shared.js';
import { APPROVAL_ARGUMENT, HOLD_MESSAGE, type ToolResult } from '../gateway/gateway.js';

export type { AdapterOptions as OpenAIAgentsOptions, GatewaySource, SpanApi } from '../adapters/shared.js';

/** The part of `MCPServerStreamableHttp` the adapter uses. */
export interface McpServerLike {
  listTools(): Promise<
    readonly {
      name: string;
      description?: string | undefined;
      inputSchema: unknown;
      _meta?: Readonly<Record<string, unknown>> | undefined;
      annotations?: Readonly<Record<string, unknown>> | undefined;
    }[]
  >;
  callToolResult?(name: string, args: Record<string, unknown> | null): Promise<unknown>;
}

/** The part of a run state `awaitApprovals` resolves. */
export interface RunStateLike {
  getInterruptions(): readonly {
    rawItem: { callId?: string | undefined } & Record<string, unknown>;
  }[];
  approve(item: never): void;
  reject(item: never, options?: { message?: string }): void;
}

const DENIED_MESSAGE = 'A person did not approve this action in AuthFI.';
const PENDING_MESSAGE = 'This action has not been approved in AuthFI yet.';

/**
 * The adapter for one agent run on the OpenAI Agents SDK for JavaScript. Build one per run with
 * {@link createOpenAIAgents}.
 */
export class OpenAIAgentsAdapter {
  readonly #run: RunGateway;
  readonly #guard: HoldGuard;
  #server: McpServerLike | undefined;

  constructor(options: AdapterOptions) {
    this.#run = new RunGateway(options);
    this.#guard = new HoldGuard(this.#run, async (key, input) => {
      const server = this.#server;
      if (server?.callToolResult === undefined)
        throw new ConfigurationError('pass the MCP server through tools() first');
      return (await server.callToolResult(key, input as Record<string, unknown>)) as ToolResult;
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

  /** Settings for `new OpenAI(...)`: the AI gateway's model route. */
  openai(): { baseURL: string; apiKey: string; fetch: typeof fetch } {
    return this.#run.openai();
  }

  /** Options for `new MCPServerStreamableHttp(...)`: the project's MCP gateway with AuthFI's `fetch`. */
  mcpServerOptions(name = 'authfi'): { name: string; url: string; fetch: typeof fetch } {
    return { name, url: this.#run.gateway.mcpUrl, fetch: this.#run.fetch };
  }

  /**
   * The MCP tools of the project as function tools, under the gateway's names
   * (`<server>__<tool>`). A refusal is the tool's answer to the model. A call that needs a
   * person's approval is a `needsApproval` interruption; whatever the app answers, the tool runs
   * only once AuthFI has approved it.
   */
  async tools(server: McpServerLike): Promise<FunctionTool[]> {
    if (typeof (server as Partial<McpServerLike> | undefined)?.callToolResult !== 'function')
      throw new ConfigurationError('tools() takes a connected MCPServerStreamableHttp');
    this.#server = server;
    const listed = await server.listTools();
    // A tool the gateway says is never allowed to this agent is not offered to the model.
    return listed
      .filter((mcp) => this.#run.gateway.offerable(mcp))
      .map((mcp) => {
        const key = mcp.name;
        const idOf = (input: unknown, callId: string | undefined): string =>
          callId ?? `${key}\u0000${canonicalJson(input)}`;
        return tool({
          name: key,
          description: mcp.description ?? '',
          parameters: mcp.inputSchema as never,
          strict: false,
          needsApproval: async (_context: unknown, input: unknown, callId?: string) => {
            const id = idOf(input, callId);
            const seen = this.#guard.entry(id) !== undefined;
            const entry = await this.#guard.begin(id, key, input);
            if (entry.status !== 'pending') return false;
            return seen ? (await this.#guard.decision(id)) === 'pending' : true;
          },
          execute: async (
            input: unknown,
            _context: unknown,
            details?: { toolCall?: { callId?: string } },
          ) => {
            const id = idOf(input, details?.toolCall?.callId);
            const result = await this.#guard.answer(id, key, input);
            if (details?.toolCall?.callId === undefined) this.#guard.forget(id);
            return textOf(result);
          },
        });
      });
  }

  /** The calls that wait on a person's approval in AuthFI. */
  pendingApprovals(): { id: string; tool: string; approvalId: string }[] {
    return this.#guard.pending();
  }

  /**
   * Waits for AuthFI's decision on each interruption of `state`, then approves the ones AuthFI
   * approved and rejects the rest (a call still undecided at the timeout is rejected, never
   * approved). Run the agent again with the same state afterwards.
   */
  async awaitApprovals(
    state: RunStateLike,
    options: {
      signal?: AbortSignal | undefined;
      timeoutMs?: number | undefined;
      sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    } = {},
  ): Promise<Map<string, Decision>> {
    const items = state.getInterruptions();
    const ids = items
      .map((i) => i.rawItem.callId)
      .filter((id): id is string => id !== undefined && this.#guard.entry(id) !== undefined);
    const decisions = await this.#guard.wait(ids, options);
    for (const item of items) {
      const id = item.rawItem.callId;
      const decision = id === undefined ? undefined : decisions.get(id);
      if (decision === 'approved') state.approve(item as never);
      else
        state.reject(item as never, { message: decision === 'pending' ? PENDING_MESSAGE : DENIED_MESSAGE });
    }
    return decisions;
  }

  /** How many tool calls the adapter remembers right now. */
  get remembered(): number {
    return this.#guard.remembered;
  }
}

/** The OpenAI Agents JS adapter for one agent run. */
export function createOpenAIAgents(options: AdapterOptions): OpenAIAgentsAdapter {
  return new OpenAIAgentsAdapter(options);
}

export { APPROVAL_ARGUMENT, HOLD_MESSAGE };
