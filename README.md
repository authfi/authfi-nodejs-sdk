# AuthFI Node.js SDK

Official Node.js SDK for [AuthFI](https://authfi.io) — the identity control plane.

## Install

```bash
npm install @authfi/sdk
```

## Quick Start (Express)

```js
const authfi = require('@authfi/sdk');

const auth = authfi({
  issuer: 'https://acme.authfi.io',   // your project's origin, which is its issuer
  audience: 'https://api.acme.com',   // the aud this API accepts
  apiKey: 'sk_live_...',              // only for permission sync
});

// Permission middleware
app.get('/api/users', auth.require('read:users'), (req, res) => {
  console.log(req.user); // decoded JWT claims
  res.json(users);
});

// Role middleware
app.get('/admin', auth.requireRole('admin'), handler);

// Start — syncs permissions + pre-fetches the issuer's keys
auth.start().then(() => app.listen(3000));
```

## Features

- Token verification with the keys at the project's `jwks_uri` (from its discovery document):
  RS256, PS256, ES256 and EdDSA, the algorithm chosen by the key and never by the token;
  `iss`, `aud` and `exp` required
- `auth.require("read:users")` — Express middleware
- `auth.requireRole("admin")` — role-based access
- `auth.authenticate()` — JWT only, no permission check
- Agent identity: an agent's own key (EdDSA, ES256 or PS256), `private_key_jwt` client
  credentials, CIBA, RFC 8693 token exchange, tokens renewed before they expire
- Vercel AI SDK adapter (`@authfi/sdk/vercel-ai`): refreshing credentials for the model and MCP
  clients, provider-legal tool names, refusals as tool results, approvals through `toolApproval`,
  and telemetry that records no content by default
- Permission auto-sync on `start()`
- Cloud credentials (GCP/AWS/Azure/OCI)
- TypeScript definitions included
- Zero dependencies — uses Node.js crypto (the Vercel AI SDK adapter works on the objects `ai`
  creates and does not import it)

## Verifying tokens

`verifyToken(token)` (and the middleware) accept a token only when:

- its `kid` names a key the issuer publishes, and the token's `alg` is the one that key signs with;
- `iss` is the issuer and `aud` contains `audience`;
- it has an `exp` that has not passed.

That covers a person's token (RS256) and an agent's token, including one an agent holds for a
person (EdDSA, with `act.sub` naming the agent). A refusal is a `TokenError` whose `code` says why
(`audience_mismatch`, `alg_mismatch`, `token_expired`, ...). Without an `audience` the middleware
answers 500: verifying a token without checking who it is for is not offered.

## Agent identity

An AI agent authenticates with a key it holds: it signs a short assertion (RFC 7523
`private_key_jwt`) and the private key never leaves the process. Every endpoint comes from the
project's authorization-server metadata, so the only thing to configure is the project's origin.

```js
const fs = require('fs');
const { AgentKey, AgentAuth } = require('@authfi/sdk');

// Once, at setup: generate a key, keep the private half in a 0600 file, register the public half
// with the project (the console API's registerAgent takes publicJwk and jwkKid).
const key = AgentKey.generate('ES256');            // or 'EdDSA', 'PS256'
fs.writeFileSync('/run/secrets/agent-key.pem', key.privatePem(), { mode: 0o600 });
console.log(JSON.stringify(key.publicJwk()));       // { kty, crv, x, y, kid, alg, use }

// At run time:
const agent = new AgentAuth({
  issuer: 'https://acme.authfi.io',                 // required; there is no default project
  agentId: 'agt_...',
  key: AgentKey.fromFile('/run/secrets/agent-key.pem', { kid: '<the kid you registered>' }),
});
const token = await agent.token();                 // cached, renewed 60 s before it expires
```

`AgentAuth.fromEnv()` reads `AUTHFI_ISSUER`, `AUTHFI_AGENT_ID`, `AUTHFI_AGENT_KEY_FILE`,
`AUTHFI_AGENT_KID` and, optionally, `AUTHFI_AGENT_RESOURCE`.

A refusal is an `AgentAuthError` whose `error` is the OAuth code (`invalid_client`,
`access_denied`, ...). It is not retried: a fresh assertion for a refused key is refused too.

### Passing the token to a framework

`agent.fetch` sets `Authorization: Bearer <current token>` on every request, so a long run never
sends an expired token, and it refuses to send the token anywhere but the project's origin. Hand it
to a client as its `fetch`, never the token as a header set when the client is built: tracers
record a client's construction arguments. For the Vercel AI SDK, use the adapter below.

## Vercel AI SDK

`@authfi/sdk/vercel-ai` connects an agent built on the Vercel AI SDK (`ai` 7) to the project's AI
gateway and MCP gateway:

```js
import { generateText, stepCountIs, registerTelemetry } from 'ai';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import { OpenTelemetry } from '@ai-sdk/otel';
import { AgentAuth } from '@authfi/sdk';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const agent = AgentAuth.fromEnv();
const authfi = createVercelAI({ agent });

const anthropic = createAnthropic(authfi.anthropic());            // the model route, Bearer per request
const mcp = await createMCPClient({ transport: authfi.mcpTransport() });
const tools = authfi.tools(await mcp.tools());                    // names every provider accepts
registerTelemetry(authfi.telemetry(new OpenTelemetry({ enrichSpan: authfi.enrichSpan })));

const messages = [{ role: 'user', content: 'Summarise the wiki of pallets/itsdangerous.' }];
let result = await generateText({
  model: anthropic('claude-haiku-5-5'), tools, messages, stopWhen: stepCountIs(5), ...authfi.approvals(),
});
while (authfi.pendingApprovals(result).length) {
  // A person approves or denies in AuthFI; the responses are built from that decision only.
  messages.push(...result.response.messages, await authfi.awaitApprovals(result));
  result = await generateText({
    model: anthropic('claude-haiku-5-5'), tools, messages, stopWhen: stepCountIs(5), ...authfi.approvals(),
  });
}
```

What each piece does:

- **Credentials.** `anthropic()` and `mcpTransport()` give the provider and the MCP client
  `authfi.fetch`, which sends the agent's current token as `Authorization: Bearer` on every request.
  To act for a person, pass the `DelegatedToken` as `credentials`:
  `createVercelAI({ agent, credentials: delegated })`.
- **Tool names.** `tools()` keys each MCP tool by a name that matches `^[A-Za-z0-9_-]{1,64}$`
  (`deepwiki.read_wiki_structure` becomes `deepwiki__read_wiki_structure`), while the tool still
  calls its MCP name. `authfi.mcpName(key)` gives the MCP name back.
- **Refusals.** A call AuthFI refuses reaches the model as the tool's result, naming the reason
  (`no_match`, outside what the person approved, approval denied), and the run goes on. A token the
  gateway no longer accepts (a revoked agent) still ends the run.
- **Approvals.** `approvals()` returns the `toolApproval` for every AuthFI tool and the
  `experimental_toolApprovalSecret` that signs approval requests. On a tool call, AuthFI decides at
  the gateway, so the adapter makes the governed call: an allowed call's result is what `execute`
  returns, and a held call becomes a `tool-approval-request` whose `reason` names the AuthFI
  approval. `awaitApprovals()` waits for the person's decision (every `pollInterval`, up to
  `approvalTimeout`, or until its `signal` aborts) and returns the `tool-approval-response`
  message. The AI SDK checks `toolApproval` again when the run resumes; the adapter answers from
  the outcome it remembered for that tool call, so the resume asks AuthFI for no second approval,
  and an approval AuthFI has not given is answered as a denial. An approved call runs once, when
  AuthFI releases it, and the resumed run returns that result.
- **Resuming in another process.** Give every process the same `approvalSecret` (32 bytes or
  more). The adapter reads the approval back from the request's `reason`.
- **Telemetry.** `telemetry(integration)` turns off the recording of prompts, outputs, tool
  arguments and tool results, whatever a call's `recordInputs` and `recordOutputs` say. Pass
  `captureContent: true` to `createVercelAI` to let each call decide. `enrichSpan` adds
  `authfi.agent_id` and `authfi.run_id` to every span. Every gateway request carries
  `X-Request-Id: <runId>.<random>` (pass your framework's run id as `runId` to choose the prefix),
  and the span that made the request gets `authfi.request_id`, the id the gateway recorded it
  under. With `@opentelemetry/api` loaded, requests also carry `traceparent`, and the approval
  check runs inside an `authfi.tool_approval` span. If the SDK cannot load `@opentelemetry/api`
  itself, pass it as `otel`.

`examples/vercel-ai/` is a complete agent that makes a model call, a granted call, a refused call,
an approved call and a denied call, with its trace sent to a local capture server.

### Acting for a person

With CIBA the person approves on their own device and the agent never sees their credentials:

```js
const approval = await agent.requestUserApproval({
  loginHint: 'jane@acme.com',
  bindingMessage: 'Let the support agent read your open tickets',
});
const delegated = await agent.awaitUserToken(approval);   // polls without blocking
await delegated.token();   // sub = the person, act.sub = the agent
```

With a person's token in hand (the project must have granted the agent delegation for them):

```js
const delegated = await agent.exchangeToken({ subjectToken: personToken, resource: 'https://api.acme.com' });
await delegated.token();   // renewed by exchanging again while personToken is valid
```

A delegated token has its own `fetch`. A CIBA token cannot be renewed: when it expires, ask the
person again.

## Cloud Credentials (AuthFI Connect)

```js
const creds = await auth.cloud.credentials(userToken, 'gcp', {
  project: 'my-project'
});
```

## Running Tests

```bash
npm ci      # the Vercel AI SDK packages the adapter's tests run against (devDependencies, Node 22)
npm test
```

`test/live.test.js` runs against a real project and is skipped unless `AUTHFI_LIVE_ISSUER` and
`AUTHFI_LIVE_CONSOLE_TOKEN` (an administrator's console token on a testing project) are set; it
registers one agent per key type and removes them afterwards.

## License

MIT
