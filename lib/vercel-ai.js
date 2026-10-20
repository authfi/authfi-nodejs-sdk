'use strict';

// The Vercel AI SDK (`ai` 7) on AuthFI's AI gateway and MCP gateway, with no glue of the app's own.
//
//   credentials  `anthropic()` and `mcpTransport()` hand @ai-sdk/anthropic and @ai-sdk/mcp a fetch
//                that sends the agent's current token as Authorization: Bearer on every request.
//   tool names   `tools()` keys each MCP tool by a name every model provider accepts, while its
//                execute still calls the MCP name; the gateway's dotted names and its `__` names
//                both map to the same key.
//   decisions    a refusal reaches the model as a tool result naming the reason, whether the gateway
//                answers it as HTTP 403 or as a tool error.
//   approvals    `approvals()` gives generateText a toolApproval that asks AuthFI by making the
//                governed call, remembers each toolCallId's outcome so the SDK's re-evaluation on
//                resume never opens a second approval, and answers approved only when AuthFI did.
//   telemetry    `telemetry()` wraps an OpenTelemetry integration so prompts, outputs, tool arguments
//                and results are not recorded unless content capture is allowed; `enrichSpan` stamps
//                the agent id and run id; each gateway call carries X-Request-Id, and the id the
//                gateway answered with is set on the span that made the call.
//
// Nothing here imports `ai` or its providers: the adapter works on the objects they produce.

const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const { AgentAuth, AgentAuthError, DelegatedToken } = require('./agent');

/** What Anthropic, OpenAI, Bedrock and Gemini all accept as a tool name. */
const PROVIDER_TOOL_NAME = /^[A-Za-z0-9_-]{1,64}$/;
/** The gateway keeps a caller's X-Request-Id only when it is 1-128 of these characters. */
const REQUEST_ID_CHARS = /^[A-Za-z0-9._:-]+$/;
const MAX_RUN_ID = 96;
/** The tool argument that carries an approval id on a retried call. */
const APPROVAL_ARG = '_authfi_approval_id';
/** Where the gateway puts a refusal's code and approval id beside the text. */
const REFUSAL_META = 'io.authfi/refusal';
const HOLD_CODES = new Set(['approval_required', 'approval_pending']);
/** The reason on a tool-approval-request names the AuthFI approval, so a resume in another process can find it. */
const REASON_PREFIX = 'AuthFI approval ';
const REASON_ID = /^AuthFI approval ([A-Za-z0-9_-]+):/;

function textOf(result) {
  const parts = result && Array.isArray(result.content) ? result.content : [];
  return parts.filter((p) => p && p.type === 'text' && typeof p.text === 'string').map((p) => p.text).join('\n');
}

/**
 * What the gateway decided about one tools/call, from its result.
 *   allowed  the tool ran (its own isError, if any, is the tool's answer)
 *   refused  AuthFI refused it; `reason` is the sentence the model reads
 *   held     a person must approve it first; `approvalId` names the approval
 */
function decisionOf(result) {
  if (!result || !result.isError) return { kind: 'allowed' };
  const text = textOf(result);
  const meta = result._meta && result._meta[REFUSAL_META];
  if (meta && typeof meta === 'object') {
    if (meta.approval_id && HOLD_CODES.has(meta.code)) {
      return { kind: 'held', approvalId: String(meta.approval_id), code: meta.code, reason: text };
    }
    return { kind: 'refused', code: meta.code || meta.error || null, reason: text };
  }
  const hold = text.match(/^Approval required\.[\s\S]*?\(approval ([A-Za-z0-9_-]+)\)/) || text.match(/^Waiting for approval ([A-Za-z0-9_-]+)/);
  if (hold) return { kind: 'held', approvalId: hold[1], code: 'approval_required', reason: text };
  if (/^(Denied by policy:|Refused\b)/.test(text)) return { kind: 'refused', code: null, reason: text };
  return { kind: 'allowed' };
}

/**
 * The gateway used to answer a per-tool refusal with HTTP 403 and the tool result as the body, and
 * MCP clients raise that as a transport error. Returns that tool result, or null for any other error
 * (a 401 for a revoked agent stays an error: the run must end).
 */
function refusalFromError(e) {
  if (!e || e.statusCode !== 403 || typeof e.responseBody !== 'string') return null;
  let body;
  try { body = JSON.parse(e.responseBody); } catch { return null; }
  const result = body && body.result;
  if (!result || result.isError !== true || !Array.isArray(result.content)) return null;
  return result;
}

function shortHash(s) {
  return crypto.createHash('sha256').update(s).digest('hex').slice(0, 8);
}

/** The provider-legal spelling of one MCP tool name: `<server>.<tool>` becomes `<server>__<tool>`. */
function legalToolName(mcpName) {
  if (PROVIDER_TOOL_NAME.test(mcpName)) return mcpName;
  const name = String(mcpName).replace('.', '__').replace(/[^A-Za-z0-9_-]/g, '_') || 'tool';
  return name.length <= 64 ? name : `${name.slice(0, 55)}_${shortHash(mcpName)}`;
}

/**
 * Maps MCP tool names to provider-legal keys, one-to-one. A name that is already legal keeps its
 * spelling; a mapped name that would collide with another gets a hash suffix of its MCP name.
 */
function toolKeys(mcpNames) {
  const keys = new Map();
  const taken = new Map(); // key -> mcp name
  const legal = mcpNames.filter((n) => PROVIDER_TOOL_NAME.test(n));
  for (const n of legal) { keys.set(n, n); taken.set(n, n); }
  for (const n of mcpNames) {
    if (keys.has(n)) continue;
    let key = legalToolName(n);
    if (taken.has(key)) key = `${key.slice(0, 55)}_${shortHash(n)}`;
    if (taken.has(key)) throw new AgentAuthError('invalid_request', `MCP tools ${taken.get(key)} and ${n} map to one provider name, ${key}`, 400);
    keys.set(n, key);
    taken.set(key, n);
  }
  return keys;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(signal.reason || new Error('aborted'));
    const t = setTimeout(() => { if (signal) signal.removeEventListener('abort', onAbort); resolve(); }, ms);
    function onAbort() { clearTimeout(t); reject(signal.reason || new Error('aborted')); }
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
}

function loadOtel(given) {
  if (given) return given;
  try {
    return require('@opentelemetry/api'); // eslint-disable-line global-require
  } catch {
    return null;
  }
}

const HEADER_SETTER = { set: (carrier, key, value) => carrier.set(key, value) };
const SPAN_ERROR = 2; // SpanStatusCode.ERROR

/**
 * The adapter for one agent run.
 *
 *   const authfi = createVercelAI({ agent });
 *   const anthropic = createAnthropic(authfi.anthropic());
 *   const mcp = await createMCPClient({ transport: authfi.mcpTransport() });
 *   const tools = authfi.tools(await mcp.tools());
 *   registerTelemetry(authfi.telemetry(new OpenTelemetry({ tracer, enrichSpan: authfi.enrichSpan })));
 *
 *   let result = await generateText({ model: anthropic(MODEL), tools, messages, ...authfi.approvals() });
 *   while (authfi.pendingApprovals(result).length) {
 *     messages.push(...result.response.messages, await authfi.awaitApprovals(result));
 *     result = await generateText({ model: anthropic(MODEL), tools, messages, ...authfi.approvals() });
 *   }
 */
class VercelAIAdapter {
  constructor({
    agent,
    credentials,
    runId,
    captureContent = false,
    approvalSecret,
    pollInterval = 3000,
    approvalTimeout = 15 * 60 * 1000,
    otel,
  } = {}) {
    if (!(agent instanceof AgentAuth)) {
      throw new AgentAuthError('invalid_request', 'agent must be an AgentAuth: the adapter sends that agent\'s token', 400);
    }
    const creds = credentials || agent;
    if (!(creds instanceof AgentAuth || creds instanceof DelegatedToken)) {
      throw new AgentAuthError('invalid_request', 'credentials must be the agent or a DelegatedToken it holds for a person', 400);
    }
    const run = runId === undefined ? `run_${crypto.randomBytes(12).toString('hex')}` : String(runId);
    if (!run || run.length > MAX_RUN_ID || !REQUEST_ID_CHARS.test(run)) {
      throw new AgentAuthError('invalid_request', `runId must be 1-${MAX_RUN_ID} of A-Z a-z 0-9 . _ : - (it prefixes X-Request-Id)`, 400);
    }
    if (!(pollInterval >= 100) || !(approvalTimeout > 0)) {
      throw new AgentAuthError('invalid_request', 'pollInterval must be at least 100 ms and approvalTimeout positive', 400);
    }
    this.agent = agent;
    this.runId = run;
    this.captureContent = captureContent === true;
    this.pollInterval = pollInterval;
    this.approvalTimeout = approvalTimeout;
    this.issuer = agent.issuer;
    Object.defineProperty(this, '_secret', {
      value: approvalSecret === undefined ? crypto.randomBytes(32) : approvalSecret,
      enumerable: false,
    });
    if (!this._secret || this._secret.length < 32) {
      throw new AgentAuthError('invalid_request', 'approvalSecret must be at least 32 bytes', 400);
    }
    this._otel = loadOtel(otel);
    this._otelWarned = false;
    this._calls = new AsyncLocalStorage(); // the governed call a gateway fetch belongs to
    this._tools = new Map(); // key -> { mcpName, base }
    this._memo = new Map(); // toolCallId -> entry
    /** A fetch for the AuthFI gateways: the current token, X-Request-Id, and traceparent when OpenTelemetry is present. */
    this.fetch = this._gatewayFetch(creds.fetch);
    this.enrichSpan = () => ({ 'authfi.agent_id': this.agent.agentId, 'authfi.run_id': this.runId });
  }

  /** Settings for @ai-sdk/anthropic's createAnthropic: the model route of the AI gateway. */
  anthropic() {
    // authToken selects Authorization: Bearer (apiKey would be x-api-key, which the gateway does not
    // read); the value is replaced on every request by this.fetch with the current token.
    return { baseURL: `${this.issuer}/mcp/v1`, authToken: 'authfi-agent-token', fetch: this.fetch };
  }

  /** A transport for @ai-sdk/mcp's createMCPClient: the project's MCP gateway. */
  mcpTransport() {
    return { type: 'http', url: `${this.issuer}/mcp`, fetch: this.fetch };
  }

  _gatewayFetch(credentialFetch) {
    return async (input, init = {}) => {
      const headers = new Headers(init.headers);
      const sent = headers.get('x-request-id') && REQUEST_ID_CHARS.test(headers.get('x-request-id'))
        ? headers.get('x-request-id')
        : `${this.runId}.${crypto.randomBytes(8).toString('hex')}`;
      headers.set('x-request-id', sent);
      const otel = this._otel;
      if (otel) otel.propagation.inject(otel.context.active(), headers, HEADER_SETTER);
      const res = await credentialFetch(input, { ...init, headers });
      const answered = res.headers.get('x-request-id') || sent;
      const call = this._calls.getStore();
      if (call) call.requestIds.push(answered);
      const span = otel && otel.trace.getActiveSpan();
      if (span) {
        span.setAttribute('authfi.request_id', answered);
        if (answered !== sent) span.setAttribute('authfi.request_id.sent', sent);
      }
      return res;
    };
  }

  /**
   * The MCP tools under provider-legal keys. Each execute still calls the MCP name, answers a
   * refusal as a tool result, and returns the outcome AuthFI already gave for that toolCallId.
   * `mcpTools` is what `mcpClient.tools()` returns.
   */
  tools(mcpTools) {
    if (!mcpTools || typeof mcpTools !== 'object') {
      throw new AgentAuthError('invalid_request', 'tools() takes the record that mcpClient.tools() returns', 400);
    }
    const names = Object.keys(mcpTools);
    const keys = toolKeys(names);
    const out = {};
    for (const mcpName of names) {
      const base = mcpTools[mcpName];
      if (!base || typeof base.execute !== 'function') {
        throw new AgentAuthError('invalid_request', `MCP tool ${mcpName} has no execute function`, 400);
      }
      const key = keys.get(mcpName);
      const known = this._tools.get(key);
      if (known && known.mcpName !== mcpName) {
        throw new AgentAuthError('invalid_request', `MCP tools ${known.mcpName} and ${mcpName} map to one provider name, ${key}`, 400);
      }
      this._tools.set(key, { mcpName, base });
      out[key] = { ...base, execute: (input, options) => this._execute(key, input, options) };
    }
    return out;
  }

  /** The MCP name behind a provider-legal key, or null. */
  mcpName(key) {
    const t = this._tools.get(key);
    return t ? t.mcpName : null;
  }

  /**
   * The scope that grants a tool (`mcp:<server>.<tool>`), for a CIBA request or a token exchange:
   * the one the gateway publishes in the tool's _meta, else built from its dotted MCP name.
   */
  scope(key) {
    const t = this._tools.get(key);
    if (!t) return null;
    const published = t.base._meta && t.base._meta['io.authfi/scope'];
    if (typeof published === 'string' && published) return published;
    return t.mcpName.includes('.') ? `mcp:${t.mcpName}` : null;
  }

  /** One tools/call through the gateway, answered as a decision; a 403 refusal becomes its tool result. */
  async _call(key, input, options = {}) {
    const { base } = this._tools.get(key);
    const call = { requestIds: [] };
    let result;
    try {
      result = await this._calls.run(call, () => base.execute(input, options));
    } catch (e) {
      result = refusalFromError(e);
      if (!result) throw e;
    }
    return { result, decision: decisionOf(result), requestIds: call.requestIds };
  }

  _inSpan(name, attributes, fn) {
    const otel = this._otel;
    if (!otel) return fn(null);
    const tracer = otel.trace.getTracer('@authfi/sdk');
    return tracer.startActiveSpan(name, { attributes: { ...this.enrichSpan(), ...attributes } }, async (span) => {
      try {
        return await fn(span);
      } catch (e) {
        span.setStatus({ code: SPAN_ERROR });
        throw e;
      } finally {
        span.end();
      }
    });
  }

  /** Records a gateway answer on a memo entry. */
  _record(entry, { result, decision, requestIds }, { approving }) {
    entry.requestIds.push(...requestIds);
    if (decision.kind === 'held') {
      entry.status = 'pending';
      entry.approvalId = decision.approvalId;
      entry.reason = decision.reason;
      entry.held = result;
      return;
    }
    if (decision.kind === 'refused') {
      entry.status = approving ? 'denied' : 'refused';
      entry.reason = decision.reason;
      entry.result = result;
      return;
    }
    entry.status = approving ? 'approved' : 'allowed';
    entry.reason = approving ? `Approved in AuthFI (approval ${entry.approvalId})` : null;
    entry.result = result;
  }

  /** Asks the gateway again with the approval id: still pending, approved (and run), or refused. */
  async _check(entry, options = {}) {
    const answer = await this._call(entry.key, { ...entry.input, [APPROVAL_ARG]: entry.approvalId }, options);
    this._record(entry, answer, { approving: true });
    return entry;
  }

  /**
   * The memo entry for a tool call. After a restart there is none, and the AuthFI approval id is
   * read back from the reason this adapter put on the tool-approval-request.
   */
  _entryFor(key, input, toolCallId, reason) {
    const known = this._memo.get(toolCallId);
    if (known) return known;
    const id = typeof reason === 'string' && reason.match(REASON_ID);
    if (!id) return null;
    const entry = this._newEntry(key, input, toolCallId);
    entry.status = 'pending';
    entry.approvalId = id[1];
    return entry;
  }

  _newEntry(key, input, toolCallId) {
    const entry = { key, input, toolCallId, status: 'new', approvalId: null, reason: null, result: undefined, held: null, requestIds: [] };
    this._memo.set(toolCallId, entry);
    return entry;
  }

  /** The toolApproval function for one AuthFI tool. */
  _approve(key) {
    return async (input, { toolCallId, messages } = {}) => {
      const entry = this._entryFor(key, input, toolCallId, requestReason(messages, toolCallId));
      if (!entry) {
        // First evaluation: AuthFI decides when the call reaches the gateway, so the call is made now.
        const fresh = this._newEntry(key, input, toolCallId);
        try {
          await this._inSpan('authfi.tool_approval', this._spanTool(key, toolCallId), async (span) => {
            this._record(fresh, await this._call(key, input), { approving: false });
            if (span) this._stampDecision(span, fresh);
          });
        } catch (e) {
          this._memo.delete(toolCallId);
          throw e;
        }
        if (fresh.status === 'pending') return { type: 'user-approval', reason: approvalReason(fresh) };
        return { type: 'not-applicable' }; // allowed or refused: execute returns the gateway's answer
      }
      // Evaluated again: the SDK is resuming a call a tool-approval-response approved. Only AuthFI's
      // decision counts; an approval it has not given is a denial.
      if (entry.status === 'pending') {
        await this._inSpan('authfi.approval_check', this._spanTool(key, toolCallId), async (span) => {
          await this._check(entry);
          if (span) this._stampDecision(span, entry);
        });
      }
      if (entry.status === 'approved' || entry.status === 'allowed') return { type: 'approved' };
      if (entry.status === 'pending') {
        return { type: 'denied', reason: `AuthFI approval ${entry.approvalId} has not been approved yet` };
      }
      this._memo.delete(toolCallId); // refused: nothing will run, and the gateway answers a retry itself
      return { type: 'denied', reason: entry.reason || 'Refused by AuthFI' };
    };
  }

  /** Runs one tool call: the outcome AuthFI already gave, or the governed call. */
  async _execute(key, input, options = {}) {
    const entry = this._memo.get(options.toolCallId);
    if (entry && entry.result !== undefined) {
      this._memo.delete(options.toolCallId);
      const span = this._otel && this._otel.trace.getActiveSpan();
      if (span && entry.requestIds.length) span.setAttribute('authfi.request_id', entry.requestIds[entry.requestIds.length - 1]);
      return entry.result;
    }
    if (entry && entry.status === 'pending') {
      // Executed without AuthFI's decision being known: ask the gateway, which decides.
      await this._check(entry, options);
      if (entry.status !== 'pending') this._memo.delete(options.toolCallId);
      return entry.result !== undefined ? entry.result : entry.held;
    }
    return (await this._call(key, input, options)).result;
  }

  _spanTool(key, toolCallId) {
    return { 'gen_ai.tool.name': key, 'authfi.tool': this.mcpName(key), 'gen_ai.tool.call.id': toolCallId };
  }

  _stampDecision(span, entry) {
    span.setAttribute('authfi.decision', entry.status);
    if (entry.approvalId) span.setAttribute('authfi.approval_id', entry.approvalId);
  }

  /**
   * Settings for generateText or streamText: the toolApproval for every AuthFI tool, and the secret
   * that signs approval requests so a forged one is refused. Spread them into the call, and add the
   * app's own entries for its other tools: `toolApproval: { ...authfi.approvals().toolApproval, mine: ... }`.
   */
  approvals() {
    const toolApproval = {};
    for (const key of this._tools.keys()) toolApproval[key] = this._approve(key);
    return { toolApproval, experimental_toolApprovalSecret: this._secret };
  }

  /** The tool-approval-request parts in a result that are waiting on AuthFI. */
  pendingApprovals(result) {
    const content = (result && result.content) || [];
    return content.filter((p) => p && p.type === 'tool-approval-request' && p.toolCall && this._tools.has(p.toolCall.toolName));
  }

  /**
   * Waits for AuthFI's decision on every approval request in `result` that is AuthFI's, and returns
   * the tool message to append before calling generateText again. Each response is built from
   * AuthFI's decision alone. An approved call has already run once, through the gateway, and the
   * resumed run returns that result instead of calling again.
   */
  async awaitApprovals(result, { signal, timeout = this.approvalTimeout, sleep: wait = sleep } = {}) {
    const deadline = Date.now() + timeout;
    const content = await Promise.all(this.pendingApprovals(result).map(async (part) => {
      const { toolCallId, toolName, input } = part.toolCall;
      const entry = this._entryFor(toolName, input, toolCallId, part.reason);
      if (!entry) throw new AgentAuthError('invalid_request', `No AuthFI approval is known for tool call ${toolCallId}`, 400);
      await this._inSpan('authfi.approval_wait', { ...this._spanTool(toolName, toolCallId), 'authfi.approval_id': entry.approvalId || '' }, async (span) => {
        while (entry.status === 'pending') {
          if (Date.now() + this.pollInterval > deadline) {
            throw new AgentAuthError('authorization_pending', `AuthFI approval ${entry.approvalId} was not decided within ${Math.round(timeout / 1000)} s; it may still be decided`, 408);
          }
          await wait(this.pollInterval, signal);
          await this._check(entry, { abortSignal: signal });
        }
        if (span) this._stampDecision(span, entry);
      });
      // A denied call is never executed or evaluated again, so nothing needs its entry.
      if (entry.status === 'denied') this._memo.delete(toolCallId);
      return {
        type: 'tool-approval-response',
        approvalId: part.approvalId,
        approved: entry.status === 'approved',
        reason: entry.reason || undefined,
      };
    }));
    return { role: 'tool', content };
  }

  /**
   * Wraps an `ai` telemetry integration (for example @ai-sdk/otel's OpenTelemetry) so that it
   * records no prompts, outputs, tool arguments or tool results unless content capture is allowed.
   * With `captureContent: true` each call's own recordInputs and recordOutputs apply.
   */
  telemetry(integration) {
    if (!integration || typeof integration !== 'object') {
      throw new AgentAuthError('invalid_request', 'telemetry() takes a telemetry integration object', 400);
    }
    if (!this._otel && !this._otelWarned) {
      this._otelWarned = true;
      process.emitWarning('@opentelemetry/api is not loadable from @authfi/sdk, so gateway request ids are not set on spans and traceparent is not sent; pass it as the otel option', { code: 'AUTHFI_OTEL_UNAVAILABLE' });
    }
    const capture = this.captureContent;
    return new Proxy(integration, {
      get(target, prop) {
        const value = Reflect.get(target, prop, target);
        if (typeof value !== 'function') return value;
        // Every operation start event carries recordInputs and recordOutputs; the integration keeps
        // them for the operation's spans, its steps and its tool calls.
        if (!capture && typeof prop === 'string' && /^(experimental_)?on[A-Za-z]*Start$/.test(prop)) {
          return (event, ...rest) => value.call(target, event && typeof event === 'object'
            ? { ...event, recordInputs: false, recordOutputs: false }
            : event, ...rest);
        }
        return value.bind(target);
      },
    });
  }
}

function approvalReason(entry) {
  return `${REASON_PREFIX}${entry.approvalId}: a person must approve this call in AuthFI`;
}

/** The reason on the tool-approval-request for a tool call, from the messages the SDK passes on resume. */
function requestReason(messages, toolCallId) {
  for (const m of messages || []) {
    if (!m || m.role !== 'assistant' || !Array.isArray(m.content)) continue;
    for (const p of m.content) {
      if (p && p.type === 'tool-approval-request' && p.toolCallId === toolCallId) return p.reason;
    }
  }
  return undefined;
}

/** The Vercel AI SDK adapter for one agent run. */
function createVercelAI(options) {
  return new VercelAIAdapter(options);
}

module.exports = {
  createVercelAI,
  VercelAIAdapter,
  decisionOf,
  refusalFromError,
  legalToolName,
  toolKeys,
  APPROVAL_ARG,
};
