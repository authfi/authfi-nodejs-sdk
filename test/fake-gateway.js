'use strict';

// A fake AuthFI MCP gateway and AI gateway model route, served through the fake authorization
// server's fetch (fake-as.js `other`). It answers the way platform-beta did on 2026-10-20 in two
// modes:
//
//   legacy   tools/list names tools <server>.<tool>; a missing grant is HTTP 403 with
//            WWW-Authenticate insufficient_scope and the tool result as the body; a hold is the text
//            "Approval required. ... (approval <id>) ..."; other refusals are "Denied by policy: ...".
//   current  tools/list names tools <server>__<tool> with the grant object in _meta io.authfi/scope,
//            tools/call accepts both spellings, and every refusal or hold is HTTP 200 with isError
//            and _meta io.authfi/refusal {error, code, reason, required_scope, approval_id}
//            (authfi-regional-mcp PRs #74 and #75).
//
// Approvals follow the gateway: a held call opens an approval; a retry with _authfi_approval_id
// answers pending while it is pending, runs the call once after it is approved (and only with the
// same arguments), and refuses it once denied or used. The model route answers like Anthropic's
// Messages API, including its 400 for a tool name outside ^[a-zA-Z0-9_-]{1,128}$.

const crypto = require('crypto');
const { ISSUER, decode } = require('./fake-as');

const TOOLS = {
  'deepwiki.read_wiki_structure': 'granted',
  'deepwiki.read_wiki_contents': 'step_up',
  'deepwiki.ask_wiki_question': 'ungranted',
};
const INPUT_SCHEMA = { type: 'object', properties: { repoName: { type: 'string' } }, required: ['repoName'] };
const ANTHROPIC_TOOL_NAME = /^[a-zA-Z0-9_-]{1,128}$/;

function digest(args) {
  return crypto.createHash('sha256').update(JSON.stringify(args, Object.keys(args).sort())).digest('hex');
}

function fakeGateway(as, { mode = 'current' } = {}) {
  const gw = {
    mode,
    revoked: false,
    approvals: new Map(), // id -> {tool, digest, status: pending|approved|denied|used}
    executed: [], // {tool, args}
    mcpRequests: [], // {method, name, args, authorization, requestId}
    modelRequests: [], // {body, authorization, apiKey, requestId}
    modelScript: null, // (body) => {content, stop_reason}
  };

  const wireName = (n) => n.replace('.', '__');
  const catalogue = () => Object.keys(TOOLS).map((n) => ({
    name: mode === 'current' ? wireName(n) : n,
    description: `${n} on DeepWiki`,
    inputSchema: INPUT_SCHEMA,
    ...(mode === 'current' ? { _meta: { 'io.authfi/scope': `mcp:${n}` } } : {}),
  }));
  const resolve = (name) => {
    if (TOOLS[name]) return name;
    if (mode === 'current') return Object.keys(TOOLS).find((n) => wireName(n) === name) || null;
    return null;
  };

  const respond = (status, body, headers = {}) => new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

  function agentOf(headers) {
    const auth = headers.get('authorization') || '';
    if (!auth.startsWith('Bearer ')) return null;
    try {
      const claims = decode(auth.slice(7).split('.')[1]);
      if (claims.iss !== ISSUER || !(claims.exp > Date.now() / 1000)) return null;
      return claims.sub;
    } catch {
      return null;
    }
  }

  function refusal(id, tool, { code, text, error = null, approvalId = null, status = 200 }) {
    if (mode === 'legacy' && status === 403) {
      return respond(403, { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } }, {
        'www-authenticate': `Bearer error="insufficient_scope", scope="mcp:${tool}", resource_metadata="${ISSUER}/.well-known/oauth-protected-resource"`,
      });
    }
    const result = { content: [{ type: 'text', text }], isError: true };
    if (mode === 'current') {
      result._meta = { 'io.authfi/refusal': { error, code, reason: text, required_scope: error ? `mcp:${tool}` : undefined, approval_id: approvalId || undefined } };
    }
    return respond(200, { jsonrpc: '2.0', id, result });
  }

  function hold(id, tool, approvalId, code) {
    const text = mode === 'current'
      ? `Waiting for approval ${approvalId} (${code}). A person must approve this action in the AuthFI console. Retry this call with an argument "_authfi_approval_id": "${approvalId}" once it is approved.`
      : `Approval required. A human must approve this action in the AuthFI console (approval ${approvalId}). Retry this call with an argument "_authfi_approval_id": "${approvalId}" once it is approved.`;
    return refusal(id, tool, { code, text, approvalId });
  }

  function denied(id, tool, code, words) {
    const text = mode === 'current' ? `Refused (${code}): ${words}.` : `Denied by policy: ${words}`;
    return refusal(id, tool, { code, text });
  }

  function run(id, tool, args) {
    gw.executed.push({ tool, args });
    return respond(200, { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `${tool} for ${args.repoName}: 1 Overview, 2 Signing` }] } });
  }

  function toolsCall(id, params) {
    const tool = resolve(params.name);
    const { _authfi_approval_id: approvalId, ...args } = params.arguments || {};
    if (!tool) return denied(id, params.name, 'unknown_upstream', 'unknown upstream');
    if (TOOLS[tool] === 'ungranted') {
      const text = mode === 'current'
        ? `Refused (insufficient_scope, no_match): no grant lets this agent call ${tool}. The call needs the scope mcp:${tool}.`
        : 'Denied by policy: no_match';
      return refusal(id, tool, { code: 'no_match', error: 'insufficient_scope', text, status: 403 });
    }
    if (TOOLS[tool] === 'granted') return run(id, tool, args);
    if (!approvalId) {
      const newId = crypto.randomUUID();
      gw.approvals.set(newId, { tool, digest: digest(args), status: 'pending' });
      return hold(id, tool, newId, 'approval_required');
    }
    const a = gw.approvals.get(approvalId);
    if (!a || a.tool !== tool) return denied(id, tool, 'approval_unknown', 'approval not found');
    if (a.digest !== digest(args)) return denied(id, tool, 'approval_mismatch', 'approval was raised for other arguments');
    if (a.status === 'pending') return hold(id, tool, approvalId, 'approval_pending');
    if (a.status === 'denied') return denied(id, tool, 'approval_denied', mode === 'current' ? `approval denied (approval ${approvalId})` : 'approval denied');
    if (a.status === 'used') return denied(id, tool, 'approval_used', 'approval already used');
    a.status = 'used';
    return run(id, tool, args);
  }

  async function mcp(init) {
    const headers = new Headers(init.headers);
    const requestId = headers.get('x-request-id');
    const echo = requestId ? { 'x-request-id': requestId } : {};
    if ((init.method || 'GET') !== 'POST') return new Response(null, { status: 405, headers: echo });
    const msg = JSON.parse(init.body);
    gw.mcpRequests.push({
      method: msg.method, name: msg.params && msg.params.name, args: msg.params && msg.params.arguments,
      authorization: headers.get('authorization'), requestId, traceparent: headers.get('traceparent'),
    });
    if (gw.revoked || !agentOf(headers)) {
      return new Response(JSON.stringify({ error: 'invalid_token' }), {
        status: 401, headers: { 'content-type': 'application/json', 'www-authenticate': 'Bearer error="invalid_token"', ...echo },
      });
    }
    const withEcho = async (res) => { for (const [k, v] of Object.entries(echo)) res.headers.set(k, v); return res; };
    if (msg.id === undefined) return withEcho(new Response(null, { status: 202 }));
    switch (msg.method) {
      case 'initialize':
        return withEcho(respond(200, { jsonrpc: '2.0', id: msg.id, result: {
          protocolVersion: msg.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'authfi-mcp-gateway', version: 'test' },
        } }));
      case 'tools/list':
        return withEcho(respond(200, { jsonrpc: '2.0', id: msg.id, result: { tools: catalogue() } }));
      case 'tools/call':
        return withEcho(toolsCall(msg.id, msg.params));
      default:
        return withEcho(respond(200, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } }));
    }
  }

  // The default model: call the first tool it is given once, then answer with what the tool said.
  function defaultScript(body) {
    const last = body.messages[body.messages.length - 1];
    const blocks = Array.isArray(last.content) ? last.content : [{ type: 'text', text: last.content }];
    const result = blocks.find((b) => b.type === 'tool_result');
    if (result) {
      const text = Array.isArray(result.content) ? result.content.map((c) => c.text || '').join(' ') : String(result.content);
      return { content: [{ type: 'text', text: `Tool said: ${text}` }], stop_reason: 'end_turn' };
    }
    if (body.tools && body.tools.length) {
      return {
        content: [{ type: 'tool_use', id: `toolu_${crypto.randomBytes(6).toString('hex')}`, name: body.tools[0].name, input: { repoName: 'pallets/itsdangerous' } }],
        stop_reason: 'tool_use',
      };
    }
    return { content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn' };
  }

  async function model(init) {
    const headers = new Headers(init.headers);
    const requestId = headers.get('x-request-id');
    const echo = requestId ? { 'x-request-id': requestId } : {};
    const body = JSON.parse(init.body);
    gw.modelRequests.push({ body, authorization: headers.get('authorization'), apiKey: headers.get('x-api-key'), requestId, traceparent: headers.get('traceparent') });
    if (gw.revoked || !agentOf(headers)) {
      return respond(401, { type: 'error', error: { type: 'authentication_error', message: 'invalid token' } }, echo);
    }
    for (const [i, t] of (body.tools || []).entries()) {
      if (!ANTHROPIC_TOOL_NAME.test(t.name)) {
        return respond(400, { type: 'error', error: { type: 'invalid_request_error', message: `tools.${i}.custom.name: String should match pattern '^[a-zA-Z0-9_-]{1,128}$'` } }, echo);
      }
    }
    const out = (gw.modelScript || defaultScript)(body);
    return respond(200, {
      id: `msg_${crypto.randomBytes(6).toString('hex')}`, type: 'message', role: 'assistant', model: body.model,
      content: out.content, stop_reason: out.stop_reason, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 5 },
    }, echo);
  }

  as.other = (url, init = {}) => {
    if (url === `${ISSUER}/mcp`) return mcp(init);
    if (url === `${ISSUER}/mcp/v1/messages`) return model(init);
    return respond(404, { error: 'not_found' });
  };

  gw.decide = (approvalId, status) => { gw.approvals.get(approvalId).status = status; };
  gw.pending = () => [...gw.approvals.entries()].filter(([, a]) => a.status === 'pending').map(([id]) => id);
  gw.toolCalls = () => gw.mcpRequests.filter((r) => r.method === 'tools/call');
  return gw;
}

module.exports = { fakeGateway, TOOLS };
