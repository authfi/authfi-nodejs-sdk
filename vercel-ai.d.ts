import authfi = require('./index');

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** Status a toolApproval function returns, as `ai` 7 defines it. */
type ToolApprovalStatus =
  | { type: 'not-applicable' }
  | { type: 'approved'; reason?: string }
  | { type: 'denied'; reason?: string }
  | { type: 'user-approval'; reason?: string };

type ToolApprovalFunction = (
  input: unknown,
  options: { toolCallId: string; messages: unknown[]; [option: string]: unknown },
) => Promise<ToolApprovalStatus>;

/** A tool-approval-request part of a generateText or streamText result. */
interface ToolApprovalRequestPart {
  type: 'tool-approval-request';
  approvalId: string;
  toolCall: { toolCallId: string; toolName: string; input: unknown; [field: string]: unknown };
  reason?: string;
  signature?: string;
  [field: string]: unknown;
}

/** The tool message to append before calling generateText again. */
interface ApprovalResponsesMessage {
  role: 'tool';
  content: Array<{ type: 'tool-approval-response'; approvalId: string; approved: boolean; reason?: string }>;
}

/** What the gateway decided about one tools/call. */
type GatewayDecision =
  | { kind: 'allowed' }
  | { kind: 'refused'; code: string | null; reason: string }
  | { kind: 'held'; approvalId: string; code: string; reason: string };

interface VercelAIOptions {
  /** The agent whose identity the run uses. Its issuer is the project the gateways belong to. */
  agent: authfi.AgentAuth;
  /** The token to send: the agent's own (the default) or a DelegatedToken it holds for a person. */
  credentials?: authfi.AgentAuth | authfi.DelegatedToken;
  /** Prefixes every X-Request-Id; stamped on spans as authfi.run_id. 1-96 of A-Z a-z 0-9 . _ : -. Defaults to a random id. */
  runId?: string;
  /** Let telemetry record prompts, outputs, tool arguments and results. Defaults to false. */
  captureContent?: boolean;
  /** Signs approval requests (at least 32 bytes). Give the same secret to every process that resumes a run. Defaults to a random one. */
  approvalSecret?: string | Uint8Array;
  /** Milliseconds between asks while an approval is pending. Defaults to 3000. */
  pollInterval?: number;
  /** How long awaitApprovals waits, in milliseconds. Defaults to 15 minutes. */
  approvalTimeout?: number;
  /** The @opentelemetry/api module, when the SDK cannot load it itself. */
  otel?: unknown;
}

declare class VercelAIAdapter {
  constructor(options: VercelAIOptions);
  readonly runId: string;
  readonly issuer: string;
  /** Sends the current token, X-Request-Id and, with OpenTelemetry, traceparent, to the project's origin only. */
  fetch: Fetch;
  /** Settings for createAnthropic from @ai-sdk/anthropic. */
  anthropic(): { baseURL: string; authToken: string; fetch: Fetch };
  /** A transport for createMCPClient from @ai-sdk/mcp. */
  mcpTransport(): { type: 'http'; url: string; fetch: Fetch };
  /** The MCP client's tools under provider-legal keys, governed by AuthFI. */
  tools<T extends Record<string, { execute?: (...args: any[]) => unknown }>>(mcpTools: T): Record<string, T[keyof T]>;
  /** The MCP name behind a provider-legal key, or null. */
  mcpName(key: string): string | null;
  /** The scope that grants the tool (mcp:<server>.<tool>), for a CIBA request or a token exchange; null when unknown. */
  scope(key: string): string | null;
  /** Spread into generateText or streamText. */
  approvals(): { toolApproval: Record<string, ToolApprovalFunction>; experimental_toolApprovalSecret: string | Uint8Array };
  /** The approval requests in a result that wait on AuthFI. */
  pendingApprovals(result: { content?: unknown[] }): ToolApprovalRequestPart[];
  /** Waits for AuthFI's decisions and returns the responses built from them. */
  awaitApprovals(result: { content?: unknown[] }, options?: { signal?: AbortSignal; timeout?: number }): Promise<ApprovalResponsesMessage>;
  /** Wraps a telemetry integration so content is recorded only when captureContent is true. */
  telemetry<T extends object>(integration: T): T;
  /** For @ai-sdk/otel's OpenTelemetry: authfi.agent_id and authfi.run_id on every span. */
  enrichSpan: (options?: unknown) => Record<string, string>;
}

declare function createVercelAI(options: VercelAIOptions): VercelAIAdapter;
declare function decisionOf(result: unknown): GatewayDecision;
declare function refusalFromError(error: unknown): Record<string, unknown> | null;
declare function legalToolName(mcpName: string): string;
declare function toolKeys(mcpNames: string[]): Map<string, string>;
declare const APPROVAL_ARG: '_authfi_approval_id';

export {
  createVercelAI, VercelAIAdapter, VercelAIOptions, GatewayDecision, ApprovalResponsesMessage, ToolApprovalRequestPart,
  decisionOf, refusalFromError, legalToolName, toolKeys, APPROVAL_ARG,
};
