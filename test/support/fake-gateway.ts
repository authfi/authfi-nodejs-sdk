// A fake MCP gateway and AI gateway model route, answering as authfi-regional-mcp does on main
// (3617565): tool names <server>__<tool> with the grant object in _meta; a refusal is a result with
// isError and _meta io.authfi/refusal; a hold is the dispatch.go prose; the token itself refused is
// HTTP 401. A held call opens an approval; a retry with _authfi_approval_id answers the hold again
// while it is pending, runs the call once after approval (with the same arguments only), and is
// refused once denied or used. The model route answers like Anthropic's Messages API.

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt } from 'jose';
import type { FakeAS } from './fake-as.js';
import { json, type Recorded } from './fake-fetch.js';

export const TOOLS = {
  'deepwiki.read_wiki_structure': 'granted',
  'deepwiki.read_wiki_contents': 'step_up',
  'deepwiki.ask_wiki_question': 'ungranted',
} as const;
type ToolName = keyof typeof TOOLS;

export const STRUCTURE = 'deepwiki__read_wiki_structure';
export const CONTENTS = 'deepwiki__read_wiki_contents';
export const QUESTION = 'deepwiki__ask_wiki_question';

/** What the gateway says of each tool for the calling agent (architecture section 6). */
const OUTLOOK = {
  [STRUCTURE]: 'no_policy_restriction',
  [CONTENTS]: 'may_require_approval',
  [QUESTION]: 'never_allowed',
} as const;
let advertise: 'off' | 'meta' | 'annotation' | 'both-conflicting' = 'off';

/**
 * Where `tools/list` puts the outlook, for the gateways made after this call: in `_meta` (current
 * gateways), in the annotation (older ones), both with the annotation wrong, or nowhere (default).
 */
export function advertiseGovernance(where: typeof advertise): void {
  advertise = where;
}

function outlookOf(wire: string): Record<string, unknown> {
  const key = 'io.authfi/governance';
  const value = OUTLOOK[wire as keyof typeof OUTLOOK];
  switch (advertise) {
    case 'meta':
      return { _meta: { 'io.authfi/scope': scopeOf(wire), [key]: value } };
    case 'annotation':
      return { _meta: { 'io.authfi/scope': scopeOf(wire) }, annotations: { [key]: value } };
    case 'both-conflicting':
      return {
        _meta: { 'io.authfi/scope': scopeOf(wire), [key]: value },
        annotations: { [key]: 'no_policy_restriction' },
      };
    default:
      return { _meta: { 'io.authfi/scope': scopeOf(wire) } };
  }
}

const scopeOf = (wire: string): string => `mcp:${wire.replace('__', '.')}`;

interface ModelBody {
  model: string;
  messages: {
    role: string;
    content: string | { type: string; text?: string; content?: unknown; name?: string }[];
  }[];
  tools?: { name: string }[];
}

export class FakeGateway {
  revoked = false;
  readonly approvals = new Map<
    string,
    { tool: ToolName; digest: string; status: 'pending' | 'approved' | 'denied' | 'used' }
  >();
  readonly executed: { tool: string; args: Record<string, unknown> }[] = [];
  readonly mcpRequests: {
    method: string;
    name?: string;
    args?: Record<string, unknown>;
    authorization: string | null;
    requestId: string | null;
    traceparent: string | null;
    apiKey: string | null;
  }[] = [];
  readonly modelRequests: {
    body: ModelBody;
    authorization: string | null;
    apiKey: string | null;
    requestId: string | null;
    traceparent: string | null;
  }[] = [];
  modelScript: ((body: ModelBody) => { content: unknown[]; stop_reason: string }) | undefined;

  constructor(readonly as: FakeAS) {
    as.t.fake.on('POST', `${as.issuer}/mcp`, (r) => this.#mcp(r));
    as.t.fake.on('POST', `${as.issuer}/mcp/v1/messages`, (r) => this.#model(r));
    as.t.fake.on('GET', `${as.issuer}/mcp`, () => new Response(null, { status: 405 }));
    as.t.fake.on('DELETE', `${as.issuer}/mcp`, () => new Response(null, { status: 405 }));
  }

  decide(approvalId: string, status: 'approved' | 'denied'): void {
    const a = this.approvals.get(approvalId);
    if (a === undefined) throw new Error(`no approval ${approvalId}`);
    a.status = status;
  }

  pending(): string[] {
    return [...this.approvals.entries()].filter(([, a]) => a.status === 'pending').map(([id]) => id);
  }

  toolCalls() {
    return this.mcpRequests.filter((r) => r.method === 'tools/call');
  }

  /** What the model was last sent as the tool's answer. */
  lastToolResult(): string {
    const messages = this.modelRequests.at(-1)!.body.messages;
    const last = messages.at(-1)!;
    const block = (last.content as { type: string; content?: unknown }[]).find(
      (b) => b.type === 'tool_result',
    )!;
    return typeof block.content === 'string'
      ? block.content
      : (block.content as { text?: string }[]).map((c) => c.text ?? '').join('');
  }

  /** Every byte the model was sent, for checking what it never saw. */
  everythingTheModelSaw(): string {
    return JSON.stringify(this.modelRequests.map((r) => r.body));
  }

  #authorized(h: Headers): boolean {
    const auth = h.get('authorization') ?? '';
    if (!auth.startsWith('Bearer ') || this.revoked) return false;
    try {
      const claims = decodeJwt(auth.slice(7));
      return claims.iss === this.as.issuer && (claims.exp ?? 0) > Date.now() / 1000;
    } catch {
      return false;
    }
  }

  #echo(r: Recorded): Record<string, string> {
    const id = r.headers.get('x-request-id');
    return id === null ? {} : { 'x-request-id': id };
  }

  #mcp(r: Recorded): Response {
    const msg = JSON.parse(r.body) as {
      id?: number;
      method: string;
      params?: { name?: string; arguments?: Record<string, unknown>; protocolVersion?: string };
    };
    this.mcpRequests.push({
      method: msg.method,
      ...(msg.params?.name === undefined ? {} : { name: msg.params.name }),
      ...(msg.params?.arguments === undefined ? {} : { args: msg.params.arguments }),
      authorization: r.headers.get('authorization'),
      requestId: r.headers.get('x-request-id'),
      traceparent: r.headers.get('traceparent'),
      apiKey: r.headers.get('x-api-key'),
    });
    const echo = this.#echo(r);
    if (!this.#authorized(r.headers)) {
      return json({ error: 'invalid_token' }, 401, {
        'www-authenticate': 'Bearer error="invalid_token"',
        ...echo,
      });
    }
    if (msg.id === undefined) return new Response(null, { status: 202, headers: echo });
    const ok = (result: unknown) => json({ jsonrpc: '2.0', id: msg.id, result }, 200, echo);
    switch (msg.method) {
      case 'initialize':
        return ok({
          protocolVersion: msg.params?.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: 'authfi-mcp-gateway', version: 'test' },
        });
      case 'tools/list':
        return ok({
          tools: (Object.keys(TOOLS) as ToolName[]).map((n) => ({
            name: n.replace('.', '__'),
            description: `${n} on DeepWiki`,
            inputSchema: {
              type: 'object',
              properties: { repoName: { type: 'string' } },
              required: ['repoName'],
            },
            ...outlookOf(n.replace('.', '__')),
          })),
        });
      case 'tools/call':
        return ok(this.#call(msg.params?.name ?? '', msg.params?.arguments ?? {}));
      default:
        return json(
          { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } },
          200,
          echo,
        );
    }
  }

  #call(wire: string, raw: Record<string, unknown>) {
    const tool = (Object.keys(TOOLS) as ToolName[]).find((n) => n.replace('.', '__') === wire);
    const { _authfi_approval_id: approvalId, ...args } = raw;
    const refused = (code: string, reason: string, extra: Record<string, string> = {}) => ({
      content: [
        { type: 'text', text: `Refused (${[extra.error, code].filter(Boolean).join(', ')}): ${reason}.` },
      ],
      isError: true,
      _meta: { 'io.authfi/refusal': { reason, code, ...extra } },
    });
    const hold = (id: string, code: string) => ({
      content: [
        {
          type: 'text',
          text: `Waiting for approval ${id} (${code}). A person must approve this action in the AuthFI console. Retry this call with an argument "_authfi_approval_id": "${id}" once it is approved.`,
        },
      ],
      isError: true,
    });
    const run = () => {
      this.executed.push({ tool: tool!, args });
      return {
        content: [{ type: 'text', text: `${tool!} for ${String(args.repoName)}: 1 Overview, 2 Signing` }],
      };
    };
    if (tool === undefined) return refused('unknown_upstream', 'unknown upstream');
    if (TOOLS[tool] === 'ungranted') {
      return refused('no_match', `no grant lets this agent call ${tool}`, {
        error: 'insufficient_scope',
        required_scope: `mcp:${tool}`,
      });
    }
    if (TOOLS[tool] === 'granted') return run();
    const digest = createHash('sha256').update(JSON.stringify(args)).digest('hex');
    if (typeof approvalId !== 'string') {
      const id = randomUUID();
      this.approvals.set(id, { tool, digest, status: 'pending' });
      return hold(id, 'approval_required');
    }
    const a = this.approvals.get(approvalId);
    if (a?.tool !== tool) return refused('approval_unknown', 'approval not found');
    if (a.digest !== digest) return refused('approval_mismatch', 'approval was raised for other arguments');
    if (a.status === 'pending') return hold(approvalId, 'approval_pending');
    if (a.status === 'denied')
      return refused('approval_denied', 'approval denied', { approval_id: approvalId });
    if (a.status === 'used') return refused('approval_used', 'approval already used');
    a.status = 'used';
    return run();
  }

  #model(r: Recorded): Response {
    const body = JSON.parse(r.body) as ModelBody;
    this.modelRequests.push({
      body,
      authorization: r.headers.get('authorization'),
      apiKey: r.headers.get('x-api-key'),
      requestId: r.headers.get('x-request-id'),
      traceparent: r.headers.get('traceparent'),
    });
    const echo = this.#echo(r);
    if (!this.#authorized(r.headers))
      return json(
        { type: 'error', error: { type: 'authentication_error', message: 'invalid token' } },
        401,
        echo,
      );
    const out = (this.modelScript ?? defaultScript)(body);
    return json(
      {
        id: `msg_${randomBytes(6).toString('hex')}`,
        type: 'message',
        role: 'assistant',
        model: body.model,
        content: out.content,
        stop_reason: out.stop_reason,
        stop_sequence: null,
        usage: { input_tokens: 10, output_tokens: 5 },
      },
      200,
      echo,
    );
  }
}

/** The default model: call the first tool once, then answer with what the tool said. */
function defaultScript(body: ModelBody) {
  const last = body.messages.at(-1)!;
  const blocks = Array.isArray(last.content) ? last.content : [{ type: 'text', text: last.content }];
  const result = blocks.find((b) => b.type === 'tool_result');
  if (result !== undefined) {
    const text = Array.isArray(result.content)
      ? (result.content as { text?: string }[]).map((c) => c.text ?? '').join(' ')
      : String(result.content);
    return { content: [{ type: 'text', text: `Tool said: ${text}` }], stop_reason: 'end_turn' };
  }
  if (body.tools !== undefined && body.tools.length > 0) {
    return {
      content: [
        {
          type: 'tool_use',
          id: `toolu_${randomBytes(6).toString('hex')}`,
          name: body.tools[0]!.name,
          input: { repoName: 'pallets/itsdangerous' },
        },
      ],
      stop_reason: 'tool_use',
    };
  }
  return { content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn' };
}
