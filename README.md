# AuthFI SDK for Node.js

The AuthFI SDK for Node.js, edge runtimes and browsers. One package, one core, for everything an
AuthFI project does: verifying tokens on your API, machine clients, AI agents and people signing in.

Every area is made from one `AuthFI` object for your project, so they share one HTTP transport,
one discovery and key cache, one logger and one set of typed errors.

## Install

The package is not on npm yet. Install it from GitHub, pinned to a release tag or a commit:

```bash
npm install github:authfi/authfi-nodejs-sdk#<tag-or-commit>
```

npm builds the package from source on install (its `prepare` script), so the machine needs `git`.

**Requirements:** Node.js 22.12 or later. The core uses Web APIs only (`fetch`, Web Crypto through
[`jose`](https://github.com/panva/jose)), so it also runs in edge runtimes and browsers. `jose` is the
only runtime dependency.

## The project

```ts
import { AuthFI } from '@authfi/sdk';

const af = new AuthFI({ issuer: 'https://acme.authfi.io' });
// or: const af = AuthFI.fromEnv();   // AUTHFI_ISSUER, and AUTHFI_API_ORIGIN when set
```

The issuer is the one required setting: `https://<slug>.authfi.io`, or your project's custom domain.
The SDK reads everything else from the issuer's discovery document, so no endpoint is hard-coded.
Build one `AuthFI` per issuer and process and share it: it owns the caches.

| Option | Default | |
|---|---|---|
| `issuer` | (required) | `https`, no trailing slash. Plain `http` is accepted for `localhost`, `127.0.0.1` and `[::1]` only |
| `apiOrigin` | from discovery | The origin of the project's machine APIs, for a custom-domain issuer |
| `timeout` | `{ attemptMs: 15000, totalMs: 30000 }` | Per attempt, and per call with its retries |
| `retries` | `2` | Only for requests that are safe to send again (below) |
| `leewayMs` | `60000` | Clock leeway when checking token times, 0 to 300 000 |
| `fetch` | the global `fetch` | A proxy-aware or instrumented `fetch` |
| `logger` | warnings to the console | Any `{ debug, info, warn, error }` logger, such as pino |
| `otel` | none | `import * as otel from '@opentelemetry/api'`, to send the active trace as `traceparent` |
| `userAgentSuffix` | none | Appended to the `User-Agent`, such as `my-app/1.4` |

### What the transport does for every call

- **Timeouts** per attempt and per call. **Redirects are never followed.** Answers are capped at
  1 MiB (discovery and key sets at 256 KiB).
- **Retries** at most twice, with jittered backoff, honouring `Retry-After`. A request that may have
  created state (a code redeemed, a refresh, a person asked to approve, a token exchange) is never
  sent twice after it left: `fetch` cannot tell a refused connection from a reset after the body was
  sent, so only `429`, and `503` with `Retry-After`, are retried for those.
- **An `X-Request-Id`** on every call (`afr-` and a ULID), the same on every retry, and a
  `traceparent`. Both are joined to the platform's records.
- **Deprecations:** a `Deprecation` or `Sunset` answer is logged once per URL, with its successor.

## Sign people in

For a server-rendered app (the pattern the OAuth guidance for browser apps recommends):

```ts
const web = af.webApp({
  clientId: 'app_…',
  clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET!), // leave out for a public client
  redirectUri: 'https://app.example.com/callback',
  stateKey: new Secret(process.env.AUTHFI_STATE_KEY!),         // 32 random bytes, base64
});

// GET /login
const pending = await web.startSignIn({ acrValues: ['urn:authfi:acr:mfa'] });
setCookie('authfi_pending', await pending.dump());            // encrypted, safe in a cookie
redirect(pending.url);

// GET /callback
const { tokens, user } = await web.finishSignIn(req.url, await web.loadPending(cookie('authfi_pending')));

const fresher = await web.refresh(tokens);                     // single-flight; rotates the refresh token
const url = await web.signOut(tokens, { postLogoutRedirectUri }); // revokes the refresh token first
```

- PKCE (S256), `state` and `nonce` on every sign-in. The callback's `iss` is required and must be
  the issuer exactly; `state` is compared in constant time; a code is redeemed once. A callback that
  repeats `iss`, `state`, `code` or `error` is refused (`callback_parameter_repeated`), not read.
- `pending.dump()` is encrypted (AES-256-GCM under `stateKey`, bound to the app and redirect URI,
  ten minutes). Never put the pending values in a signed cookie: its holder can read it.
- The ID token is verified: the algorithm the issuer lists for ID tokens, `aud`/`azp`, `nonce`,
  `at_hash`, and the `acr` and `max_age` asked for; a weaker sign-in is `StepUpRequired`.
- `await web.session(tokens, { key, store })` stores the tokens and returns a signed-in person's
  token as a `TokenSource`, refreshed through the `TokenStore` with `compareAndSet`, so two workers
  never spend the same refresh token.
- `web.userinfo(tokens)` reads what userinfo releases, and refuses an answer about another person
  than the one who signed in. A refresh that answers an ID token is verified too, and must name the
  same person (`id_token_subject_changed`).
- Silent sign-in (`prompt=none`) and back-channel logout are not offered by the platform; asking for
  `prompt: 'none'` raises `NotSupportedError`.

## Protect an API

```ts
import { AuthFI } from '@authfi/sdk';
import { protect, authfiErrorHandler } from '@authfi/sdk/express';

const af = AuthFI.fromEnv();
const verifier = af.verifier({ audience: ['api_orders', 'app_web'], expectedTenantId: process.env.AUTHFI_TENANT_ID });

app.get('/orders', protect(verifier, { permissions: ['orders:read'] }), (req, res) => {
  res.json({ caller: req.authfi!.principal.toString() });
});
app.use(authfiErrorHandler());
```

- **`audience` is required**, with no "skip": your API's client id (machine and agent tokens minted
  with `resource`), and the client ids of the front ends that call it (a person's token names the app
  they signed in to). AuthFI's own audiences (the issuer, `<issuer>/mcp`, the console) are refused.
- **`expectedTenantId`** pins the issuer to its tenant. Set it.
- **Authorize on `permissions` and `roles`.** On person and machine tokens `scope` is what the
  client asked for. In one guard, `permissions` and `scopes` need all, `anyPermission` and `roles`
  need one, and the kinds combine with AND. An empty list is a configuration error.
- **What a caller sees** is the platform's answer: one opaque `401 invalid_token` for every refused
  token, `403 insufficient_scope` naming the scopes, `403 forbidden` naming nothing, and RFC 9470
  step-up (`401 insufficient_user_authentication` with `acr_values`). The precise cause
  (`token_expired`, `token_audience_mismatch`, …) goes to your log. `exposeRefusalCode: true` puts
  it in the body too; use it for an internal API only, because it tells a caller which check failed.
- `resourceMetadata` adds your RFC 9728 metadata URL to the 401 challenge.

The verifier checks `typ at+jwt` (so an ID token is refused), the algorithm against the issuer's key
(`RS256`, `ES256`, `EdDSA`; never `none` or `HS*`), `iss`, `aud`, `exp`, `nbf`, `iat`, `sub`,
`tenant_id`, a sender-constrained token presented as Bearer, and a chain of actors. Every verified
token has one shape:

| Field | |
|---|---|
| `principal` | who the token is for: `{ kind, id }`, kind `user`, `app` or `agent` |
| `actor` | who acts for them (`act.sub`): the agent of a delegated token |
| `tokenKind` | `person`, `machine`, `agent` or `delegated` |
| `permissions`, `roles`, `groups`, `scopes` | sets |
| `orgId`, `acr`, `amr`, `authTime`, `expiresAt`, `claims` | |

Compare principals, never `sub` strings: a delegated token types its subject (`user:…`).

Without Express, call `verifier.verifyRequest(request)` with a Fetch API `Request` (or its
`authorization` header), and answer refusals with `refusalAnswer(error)`, which builds the same
status, challenge and body.

**Several projects.** A server that accepts tokens from several issuers keeps one verifier each,
pinned to its tenant:

```ts
const verifier = new MultiIssuerVerifier({
  'https://acme.authfi.io': { verifier: acme.verifier({ audience: 'api_orders' }), tenantId: '4e46e0c4-…' },
  'https://globex.authfi.io': { verifier: globex.verifier({ audience: 'api_orders' }), tenantId: '9a1d…' },
});
```

**A per-object question**, or a fresh answer, goes to the project's decision point:

```ts
const { allowed, approvalRequired } = await af.check(m2m, {
  subject: 'user:usr_1', relation: 'orders:refund', object: 'order:4411',
});
```

## Agent tokens and revocation

An agent's token (`sub` or `client_id` starting `agt_`, or an `act` claim) is accepted only when the
request proves it. With `agentTokens: 'enforce'` (the default) `verifier.verifyRequest()` and
`protect()` require:

1. `Authorization: DPoP <token>` with `cnf.jkt`, and exactly one valid DPoP proof (RFC 9449): `typ
   dpop+jwt`; EdDSA, ES256 or PS256 bound to the embedded key; `htm` and `htu` equal to this request;
   `iat` within 60 s (5 s ahead); `ath` the token's hash; the key's RFC 7638 thumbprint equal to
   `cnf.jkt`; a `jti` not used before (single use per key); and the server nonce when `nonceKey` is set;
2. a signing key certified by a chain: the key set's `x5c` leaf certifies it, `x5t#S256` in the
   token header and the key set equals the leaf, the chain reaches a pinned AuthFI root (SHA-256 of
   its SPKI; `rootPins` and `rootCerts` override), the leaf and every CA between state AuthFI policy
   `1.3.6.1.4.1.67322.1.1` or `.1.2`, and every signature and date verifies.

```ts
const verifier = af.verifier({
  audience: 'api_orders',
  publicUrl: 'https://api.example.com', // the origin clients call: the Host header is never used
  // trustForwarded: true,              // behind a proxy you control, instead of publicUrl
  // replayGuard, nonceKey, rootPins, rootCerts, agentTokens: 'watch' | 'off'
});
```

`verifier.verify(token)` has no request to prove anything with, so it refuses an agent's token as
`agent_token_needs_request`. With more than one replica supply a shared `replayGuard`
(`record(key, expiresAtMs)`). `watch` logs what `enforce` would refuse and accepts; `off` skips both
checks and warns once.

Access tokens verify offline, so a withdrawn agent would keep working until its token expires.
`@authfi/sdk/signals` takes the signed Shared Signals event (RFC 8935 push) AuthFI sends:

```ts
import { createReceiver, createRevocationStore, registerStream } from '@authfi/sdk/signals';

const revocations = createRevocationStore({ tokenLifetimeSeconds: 86_400 }); // your longest token
const verifier = af.verifier({ audience: 'api_orders', publicUrl, revocations });
app.post('/ssf/push', createReceiver(af, { revocations, audience: 'my-stream', authToken: process.env.PUSH_BEARER }));
await registerStream(af, operatorBearer, { audience: 'my-stream', endpointUrl: 'https://api.example.com/ssf/push' });
```

The receiver answers 202 (also for a retry and for an event older than any token it could affect),
400 `{"err","description"}` for a SET that is refused for good, and 503 for anything that can heal (a
key not in the key set yet, a key set it cannot read, an `iat` ahead of its clock), because the
transmitter treats a 400 as final. `session-revoked`, `account-purged` and `credential-compromise`
revoke the subject: tokens issued at or before the event's `iat` are refused as `token_revoked` (the
error carries the event's `jti` as `ref`); a token issued after it is accepted. A delegated token is
refused when its actor is revoked. The store is in memory: a restart empties it, so run one stream per
process and keep token lifetimes short.

## Machine clients

```ts
const m2m = af.clientCredentials({
  clientId: process.env.AUTHFI_CLIENT_ID!,
  clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET!),
  resource: 'api_orders',              // the API's client id: the token's audience
  sendTo: ['https://api.example.com'], // the only origin the token goes to
});
const res = await m2m.fetch('https://api.example.com/orders');
```

The token is cached per resource and scope, renewed at two thirds of its lifetime, and minted once
for concurrent callers. Without `resource` the token names the client itself as its audience, which
no API should accept, and the SDK warns once.

## AI agents

An agent is an OAuth client with a key. Its token comes from the same token endpoint as a machine
client's, and an API verifies it with the same verifier as a person's.

```ts
import { AuthFI } from '@authfi/sdk';
import { agentFromEnv, generateAgentKeyFile } from '@authfi/sdk/node';

// Once: make the key, keep the private half in a 0600 file, register the public half in the console.
const key = await generateAgentKeyFile('./agent-key.pem', 'EdDSA');
console.log(key.publicJwk(), await key.thumbprint());

// At run time: AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KID, AUTHFI_AGENT_KEY_FILE.
const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);
const res = await agent.fetch(`${af.issuer}/mcp`, { method: 'POST', body });
```

| | |
|---|---|
| `agent.token()`, `agent.fetch`, `agent.headers()` | the agent's own token (client credentials with its key); its audience is the gateway, and it goes only to AuthFI |
| `agent.forResource(resource, { sendTo })` | a token for your own API, sent only to `sendTo` |
| `agent.capabilities()` | what the agent is granted |
| `agent.tokenAsUser({ loginHint, bindingMessage })` | act for a person with no browser: they approve on their own device (CIBA) |
| `agent.exchange(personToken)` | act for a person signed in to your app (token exchange) |
| `agent.transactionToken(action)`, `agent.authorizeAction(txn)` | freeze a high-risk action, then ask the gate |
| `agent.requestApproval(action)`, `agent.waitForApproval(id)` | a person approves one action; no token results |

**Two ways of asking a person, two names.** `tokenAsUser` (CIBA) ends in a token the agent uses to
act for the person. `requestApproval` ends in a decision about one action, and no token.

**The tokens an agent holds for a person** are `DelegatedToken`s: their `subject` is the person, their
`actor` the agent, and `via` says how they were obtained. One from token exchange renews by
exchanging again while the person's token is valid; one from CIBA does not renew, because only the
person can consent again, and raises `ConsentExpired` near expiry.

- `bindingMessage` is required: it is what the person reads before approving.
- A request that asks a person something (CIBA, an approval) is sent once; a retry would ask twice.
- Registration and key rotation are console steps. The SDK never uploads a private key.
- The key file is the default. `AUTHFI_AGENT_PRIVATE_KEY` (the PEM in the environment) is for runtimes
  with no file system; on Node the SDK warns when it reads one. In an edge worker, build the key with
  `AgentKey.fromPem(env.AUTHFI_AGENT_PRIVATE_KEY, { kid })` and `af.agent({ agentId, key })`.
- `agent.approval(id)` raises `NotSupportedError` (`agent_approval_status`) on a project that does
  not offer approval status to agents.

### Every call is proven by a key only this process holds (DPoP)

The agent's tokens for AuthFI are bound to a key the process makes for itself (RFC 9449): it lives in
memory, is never written down and cannot be read back, so a stolen token, log line or header is of no use
without it. You write nothing for this. `agent.token()`, `agent.fetch`, `agent.headers(method, url)` and
every gateway, model, cloud and `/otlp/v1/traces` call send `Authorization: DPoP <token>` and a proof made
for that request; the server's nonce (`use_dpop_nonce`) is answered once. `agent.dpop` is the key a token
is bound to (undefined for a Bearer one). Acting for a person (`tokenAsUser`, `exchange`) is bound to the
same key, and the delegated token renews bound. A token for your own API (`forResource`) stays Bearer, because
a verifier built on this SDK takes no proof; pass `dpop: false` to `af.agent(...)` to keep every token
Bearer (the gateways refuse a bound agent's Bearer token, not an unbound one).

### A mandate is the authority for one job

A person gives an agent a **mandate** for a piece of work, narrowed from what the agent may ever do. The
mandate is a credential: hand it to an adapter in place of the agent, and the gateway holds every call to it.

```ts
await agent.withMandate(
  'support.refund', // a template of the project's
  { subjectToken: personsToken, params: { order: '4411' } },
  async (mandate) => {
    const authfi = createVercelAI({ source: mandate, approvalSecret });
    // ... a tool outside the mandate, a spend over its budget and an ended mandate are refused ...
  },
);
```

| | |
|---|---|
| `agent.mandate(template, { subjectToken, params?, ttlSeconds? })` | the `Mandate`, waiting for the person's approval when the template needs it |
| `agent.requestMandate(...)` / `agent.awaitMandate(pending)` | the same in two steps: show the person `pending.approvalUrl` in between |
| `agent.withMandate(template, options, work)` | runs `work(mandate)` and forgets the mandate after, however `work` ends |
| `mandate.gateway()`, `mandate.cloud`, `mandate.fetch` | the gateways, cloud credentials and a `fetch`, held to the mandate |
| `mandate.mandateId`, `.template`, `.tools`, `.budgets`, `.expiresAt` | what the platform granted |

A mandate is one level deep: inside `withMandate`, asking for another is refused, and nothing a refused call
says offers a wider one. Nothing swaps the agent's own token for the mandate's behind your back, because a
framework may keep an MCP session open from before it: you pass the mandate in. The mandate's token is held
by the process's key and never printed or serialised.

A refused tool call says what the agent can still do. `gateway.readResult(result)` gives `why`
(`outside_mandate`, `over_budget`, `mandate_ended`, `cannot_meter`, `bad_arguments`, `in_progress` or
`refused`), `nextStep` and `modelText`, and every adapter hands the model that same text. `refusalData(outcome)`
is the same as data for code that plans around it.

### Cloud credentials by handle

`gateway.cloud.credentials({ account, role })` (also `agent.cloud`, `mandate.cloud`) returns a **handle**
(`credentialId`, `account`, `role`, `expiresAt`, `scope`) and never a secret, so it is safe in a tool result a
model reads. The runtime that calls the cloud fetches the secret with `cloud.secret(handle)`: once, with the
same key, and not after it expires (`POST /mcp/v1/cloud/credentials/{credential_id}/secret`).
`cloud.fetchCredential(request)` does both for code that is not a tool.

## Connect from the environment

`connect()` (from `@authfi/sdk/node`) reads `AUTHFI_ISSUER` and the credential, and returns what the
gateways and the Vercel AI adapter take as `source`:

- an agent, the default: `AUTHFI_AGENT_ID`. On a workload an admin bound to the agent it signs in **as an
  instance**, with no key to keep (below). Otherwise, legacy, with `AUTHFI_AGENT_KEY_FILE` (or
  `AUTHFI_AGENT_PRIVATE_KEY` and `AUTHFI_AGENT_KID`), exactly as `agentFromEnv` reads them; `connect()` says
  so once;
- else a machine client: `AUTHFI_CLIENT_ID` with `AUTHFI_CLIENT_SECRET`. Its token is minted for the
  gateway (`<issuer>/mcp`) and reaches the gateways as a client, with no agent id; the gateway records the
  caller as `client-credentials`.

A missing variable is a `ConfigurationError` that names it. When `@opentelemetry/api` is installed it is
given to the project, so each gateway call carries the active trace.

### Sign in as an instance

An instance is one execution of the agent: a pod, a process, a laptop session. It makes its key in memory,
shows where it runs (its **evidence**), and trades that for a 15-minute attestation and a token bound to its
key. `connect()` finds the evidence itself:

| Variable | |
|---|---|
| `AUTHFI_AGENT_ID` | the agent (`agt_...`) |
| `AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE` | the projected service-account token, if it is not at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Project it with `audience` set to the project's origin and `expirationSeconds: 600`; it works once, so the kubelet's rotation renews it |
| `AUTHFI_DEVICE_KEY_FILE`, `AUTHFI_DEVICE_KEY_KID` | the device key the device was bound with, for a laptop. Custody is `software` until hardware attestation is verified |
| `AUTHFI_CONFIG_VERSION`, `AUTHFI_CONFIG_DIGEST` | the signed configuration this instance runs (`7`, `sha256:...`); the platform attests no instance without one |
| `AUTHFI_IMAGE_DIGEST` | the image it runs, `sha256:<64 hex>` |

The instance then runs challenge, attest and the token request (`OAuth-Client-Attestation`,
`OAuth-Client-Attestation-PoP` and `DPoP` headers), and attests again before the attestation expires.
`instance.instanceId` is the id the platform gave it. A key file named with no configuration is the legacy key,
as it always was. An instance has no key to sign an assertion with, so CIBA, `requestApproval` and
`requestMandate` are refused with the fix; token exchange works. The platform gives every failed sign-in the
same 401, so an error names the causes to check and points at the `agent.attest.refused` event on the audit tape.

```ts
import { connect } from '@authfi/sdk/node';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const authfi = createVercelAI({ source: await connect(), approvalSecret });
```

## Steps to AuthFI

`@authfi/sdk/otel` exports the steps of your framework (model calls, tool calls) to
`<issuer>/otlp/v1/traces` as OTLP/HTTP protobuf. AuthFI keeps each span as the token's agent's.

- The credential is read for every export, so a renewed token is used and none is held in a header; a
  refused token is renewed once.
- Prompts, answers and tool arguments and results are dropped before export unless `captureContent`
  is on (AuthFI drops them on arrival too).
- Every span carries `authfi.agent_id` and `authfi.run_id`.
- Install the optional peers: `@opentelemetry/api`, `@opentelemetry/sdk-trace-base`,
  `@opentelemetry/otlp-transformer` (and `@ai-sdk/otel` for the AI SDK).

```ts
// Vercel AI SDK: one line, wired through the AI SDK's own telemetry seam.
const steps = await authfi.exportSteps();
// ... generateText(...) ...
await steps.shutdown(); // sends what is buffered

// Any other framework that takes an OpenTelemetry tracer:
import { registerAuthFITelemetry } from '@authfi/sdk/otel';
const telemetry = registerAuthFITelemetry({ source: await connect(), global: false });
// give telemetry.tracer to the framework
```

## The gateways

`agent.gateway()`, `delegatedToken.gateway()` or `clientCredentials.gateway()` is the project's MCP gateway and AI gateway for
that credential.

| | |
|---|---|
| `gateway.mcpUrl` | `<issuer>/mcp` |
| `gateway.forRun(runId?)` | the same credential for one run: each call's `X-Request-Id` is `<runId>.<n>` (the run id also goes on spans as `authfi.run_id`); `gateway.serverRunId` is the run AuthFI derived, from `AuthFI-Run-Id` |
| `gateway.modelBaseUrl('anthropic' \| 'openai')` | the base URL for a provider SDK |
| `gateway.fetch` | the credential per request, `X-Request-Id` and `traceparent`, AuthFI's origins only, no redirects; a 401 is `GatewayTokenRefused` |
| `gateway.readResult(result)` | a `ToolOutcome`: `allowed`, `refused` (with `code`, `reason`, `requiredScope`) or `approval_required` (with `approvalId`) |
| `gateway.scopeOf(tool)` | the grant object of a tool, from `tools/list` |
| `gateway.cloudCredentials({ account, role, expiresInSeconds? })` | a handle to a short-lived cloud credential (`expiresInSeconds` from 1 to 900, default 900), or `approval_required`; `gateway.cloudSecret(id)` fetches its secret once (see above) |

A refusal and a hold are values, not exceptions: a framework hands them to the model as the tool's
answer. Never give a hold's text to a model: it names the approval. An adapter strips an
`_authfi_approval_id` (`APPROVAL_ARGUMENT`) a model writes, and adds it only on a resume.

## LangSmith and A2A

**Tracing.** `registerAuthFITelemetry` (`@authfi/sdk/otel`) follows LangSmith's OpenTelemetry mapping
(`langsmith.span.kind`, `langsmith.trace.name` on a root span, `langsmith.metadata.authfi_agent_id` and
`authfi_run_id`), so a customer who also adds LangSmith's exporter to the same provider changes no code. With
`@opentelemetry/api` given to the project (`connect()` does), every `gateway.readResult` is also recorded as a
finished `tool` child span of the step that made the call, with `authfi.decision.outcome`
(`allow`, `deny`, `needs_approval`), the rule or grant that decided, `authfi.decision.id` and `authfi.mandate.id`
where the gateway named them in `_meta["io.authfi/decision"]`. Content capture is off by default; with it on or
off, a value shaped like a token or a key and any attribute named like a credential leave as `[redacted]`. The
SDK never forwards the AuthFI token to LangSmith.

**A2A 1.0** (`@authfi/sdk/a2a`). `remote(agent, 'https://partner.example', { trustRoots: [R1_PEM] })` fetches
the agent card, verifies its JWS (RFC 8785; an AuthFI agent's chain must lead to a root you trust and carry the
agent-custody policy `1.3.6.1.4.1.67322.1.4`) or refuses it, and returns an agent to `send()` to. The token goes
to the card's own origin only. `statusFor(decision)` and `statusForOutcome(outcome)` map an AuthFI decision to
the state a remote caller reads: `TASK_STATE_INPUT_REQUIRED` when a person must approve, `TASK_STATE_AUTH_REQUIRED`
for consent or credentials, `TASK_STATE_REJECTED` with the reason for a deny.

## Frameworks

| Framework | Package | |
|---|---|---|
| Express | `@authfi/sdk/express` | `protect`, `authfiErrorHandler` |
| Vercel AI SDK 7 | `@authfi/sdk/vercel-ai` | `createVercelAI({ source, approvalSecret })`: `.anthropic()`, `.mcpTransport()`, `.tools()`, `.approvals()`, `.awaitApprovals()`, `.telemetry()`, `.exportSteps()` |
| OpenTelemetry | `@authfi/sdk/otel` | `registerAuthFITelemetry({ source })`, `AuthFISpanExporter` |

Framework packages are optional peer dependencies; install the ones you use.

## Webhooks

AuthFI signs every delivery: `X-AuthFI-Signature-256: sha256=<hex>`, the HMAC-SHA256 of
`<X-AuthFI-Timestamp>.<raw body>` under the subscription's secret (returned once, when the
subscription is created). `verifyWebhook` checks it in constant time and the timestamp against a
5-minute window, and returns the typed event. Hand it the **raw** body: a parsed and re-serialised
body no longer matches.

```ts
import express from 'express';
import { isAuthFIError, Secret, verifyWebhook } from '@authfi/sdk';

const secret = new Secret(process.env.AUTHFI_WEBHOOK_SECRET!);

app.post('/hooks/authfi', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const event = await verifyWebhook({ body: req.body, headers: req.headers, secret });
    switch (event.type) {
      case 'user.deleted':
        await removeAccount(event.data.resourceId);
        break;
      default: // the platform can add events without an SDK release
    }
    res.sendStatus(204);
  } catch (e) {
    if (isAuthFIError(e, 'InvalidWebhook')) return res.sendStatus(400); // e.code says why
    throw e;
  }
});
```

`WEBHOOK_EVENTS` lists the event names. The delivery id (`event.deliveryId`) is not signed: use it to
drop repeats, never to decide what to trust. `toleranceSeconds` narrows or widens the window.

## Administer the project

`@authfi/sdk/admin` is the project's administration API: organizations (members, invitations, join
requests), users, roles, permissions and role bindings. The credential decides what is allowed: the
platform gates each call on a permission (`manage:organizations`, `manage:users`, `manage:roles`,
`read:policy`) and on the project's plan, and a refusal is an `APIError` with `status` (401, 402,
403) and `code`.

A machine app needs two things set up in AuthFI before its first admin call works:

1. **The console is an allowed audience.** `authfi-console` is in the app's allowed audiences, and the
   token is requested with `resource=authfi-console` (the `resource` option below). A token without it
   is for the app itself, and the admin API refuses it.
2. **The app holds a role that allows the call.** The principal `app:<client_id>` holds a role with
   `manage:organizations` and/or `manage:users` (and `manage:roles` for roles and bindings).

Calls only a person can make stay refused for a machine app whatever its role: see the end of this
section.

```ts
import { AdminClient } from '@authfi/sdk/admin';

// resource: the token's audience is the console API; sendTo: the project's own origin, the only
// place this token may go.
const m2m = af.clientCredentials({
  clientId,
  clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET!),
  resource: 'authfi-console',
  sendTo: [af.apiOrigin],
});
const admin = new AdminClient(af, m2m);

const org = await admin.organizations.create({ slug: 'initech', displayName: 'Initech' });
const invite = await admin.organizations.invitations.create(org.id, { email: 'ada@initech.example', role: 'admin' });
// The platform does not email it: send invite.token.reveal() to the invitee.

for await (const user of admin.users.all({ query: 'ada' })) console.log(user.id, user.status);

const role = await admin.roles.create({ name: 'billing' });
await admin.bindings.assign({ subject: 'user:usr_1', roleId: role.id });
```

Lists return a `Page` (`items`, `nextCursor`, `hasMore`) and have an `all()` that walks the pages.
Two things to know:

- **Organization roles are not PDP roles.** `members.add(orgId, { userId, role })` sets the person's
  role inside that organization; `admin.bindings` grants tenant-wide roles.
- **Some calls need a person.** Accepting an invitation (`invitations.accept`, with the invitee's own
  token in a `Secret`) and the join-request calls are refused for a machine client. Asking to join
  happens at sign-up and is not in the public API.

## Examples

| Example | |
|---|---|
| [`examples/sign-in-web`](examples/sign-in-web) | Signing people in to an Express app, with refresh and sign-out |
| [`examples/protect-an-api`](examples/protect-an-api) | An Express API that verifies tokens and authorizes on permissions |
| [`examples/machine-to-machine`](examples/machine-to-machine) | A job calling that API with a client-credentials token |
| [`examples/agent-identity`](examples/agent-identity) | An agent's key, its token, and a call through the MCP gateway |
| [`examples/agent-for-a-person-voice`](examples/agent-for-a-person-voice) | Acting for a caller with no browser (CIBA) |
| [`examples/agent-for-a-signed-in-user`](examples/agent-for-a-signed-in-user) | Acting for a person signed in to your app (token exchange) |
| [`examples/action-gate`](examples/action-gate) | Freezing a high-risk action before running it |
| [`examples/agent-model-gateway`](examples/agent-model-gateway) | Model calls through the AI gateway, the token kept out of traces |
| [`examples/approvals-vercel-ai`](examples/approvals-vercel-ai) | A Vercel AI SDK agent that pauses on an approval and resumes on AuthFI's decision |

## Secrets

Client secrets, tokens, assertions and private keys are held in a `Secret`. It prints, inspects and
serialises as `Secret(***)`, and `reveal()` is the one way to read it.

```ts
import { Secret } from '@authfi/sdk';

const clientSecret = new Secret(process.env.AUTHFI_CLIENT_SECRET ?? '');
console.log({ clientSecret }); // { clientSecret: Secret(***) }
```

## Errors

Every error is an `AuthFIError` with a stable `code`. Branch on the code, never on the message, and
keep a default arm: the platform adds codes without an SDK release.

```ts
import { isAuthFIError } from '@authfi/sdk';

try {
  await af.metadata();
} catch (e) {
  if (isAuthFIError(e, 'TransportError') && e.retryable) {
    // try again later
  } else if (isAuthFIError(e)) {
    log.error({ code: e.code, requestId: e.requestId }, 'AuthFI call failed');
  } else {
    throw e;
  }
}
```

Use `isAuthFIError(e, kind)` rather than `instanceof`: a program that loads the package both as ESM
and CommonJS has two copies of each class.

| Error | When |
|---|---|
| `ConfigurationError` | A setting is wrong. Raised before anything is sent |
| `TransportError` | Timeout, connection failure, refused redirect, oversized answer; `.retryable` |
| `DiscoveryError` | The issuer's discovery document or key set is unusable |
| `OAuthError` (`StepUpRequired`, `ConsentDenied`, `ConsentExpired`, `TemporarilyUnavailable`) | An OAuth endpoint refused; `code` is its `error` |
| `APIError` | An AuthFI API refused; `code` is the platform's code |
| `InvalidToken` (`InsufficientPermission`, `InsufficientScope`, `InsufficientAuthentication`) | A token was refused; `code` is the kernel's refusal code |
| `GatewayTokenRefused` | The gateway refused the token itself (401); the agent run ends |
| `NotSupportedError` | The project does not offer this to this kind of client; `.feature` |

## Credentials: `TokenSource`

Every credential the SDK makes (a machine client, an agent, a token held for a person) is a
`TokenSource`:

```ts
interface TokenSource {
  readonly sendTo: readonly string[];         // the only origins it may be sent to
  token(): Promise<string>;                   // a current token, renewed as needed
  headers(method: string, url: string): Promise<Record<string, string>>;
  readonly fetch: typeof fetch;               // attaches the credential; refuses other origins
}
```

Framework adapters and gateway helpers take any `TokenSource`. Call `token()` or `headers()` inside
the request path and keep no reference to the result.

### Concurrent callers and a spent refresh token

Callers that ask for the same token at the same moment share one request. An `AbortSignal` ends only
its own caller's wait: aborting one caller never fails the others, and a refresh already sent is not
abandoned, so the rotated token the platform issued is kept.

The sharing lasts while the request is in flight. A refresh token is single use: a caller that arrives
later with a refresh token that has already been spent is not handed the earlier result. It goes to
the server and gets `invalid_grant`, so a replayed refresh token is never answered from memory.

## Contributing

```bash
npm install            # npm 11 or later
npm run lint           # eslint (typescript-eslint strict, type-checked) and prettier
npm run typecheck      # tsc --strict, exactOptionalPropertyTypes, noUncheckedIndexedAccess
npm test               # vitest: Node and the edge runtime
npm run test:coverage
npm run build && npm run check:package && npm run check:browser
```

## License

Apache-2.0. See [LICENSE](LICENSE).
