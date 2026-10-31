# Changelog

All notable changes to this package. It follows [Semantic Versioning](https://semver.org): before
1.0 a minor version may break, but only with an entry here and one minor version of deprecation.

## 0.2.0 (unreleased)

### Added

- **Model calls through the AI gateway are tested to prove the key.** The gateway's `fetch` (and so every
  adapter's `openai()` / `anthropic()` settings) sends `Authorization: DPoP` with a proof on the Anthropic,
  Chat Completions and Responses routes, against a gateway stand-in that refuses an unproven model call
  (`MCP_MODEL_PROOF_CHECK=enforce`, `EMODEL020`). A model call that goes with a Bearer token and no proof is said
  once in the log, because the gateway refuses it once the check is enforced, unless the workload is caged.
- **A run's first gateway call now answers the server's DPoP nonce.** The key a token is bound to is known only
  once the token is minted, and the gateway `fetch` read it before the first mint: with a nonce required, the
  first call of a run was reported as a refused token (`GatewayTokenRefused`). It mints first.
- **Agent identity, ported from the Python SDK (#52, #53).**
  - **DPoP on every gateway call.** An agent's tokens for AuthFI are bound to a per-process key (RFC 9449);
    `agent.fetch`, `headers()`, the gateways, the cloud door and the trace export carry a proof per request and
    answer the server's nonce once. CIBA and token exchange are bound to the same key, and a delegated token
    renews bound. `agent.dpop` is the key; `af.agent({ dpop: false })` keeps tokens Bearer.
    `TokenSource.headers` now gives `Authorization: DPoP` and a `DPoP` proof for a bound token, and the
    action gate and approval-status calls send the proof too.
  - **Mandates.** `agent.mandate()`, `requestMandate()` / `awaitMandate()` and `withMandate()` start a
    mandate by token exchange (an actor assertion naming the key, `authorization_details` of type
    `authfi_mandate`). A `Mandate` is a credential for the adapters; it is one level deep, closed after use,
    and a refused call says why (`why`, `nextStep`, `modelText`) in every adapter.
  - **Cloud credentials by handle.** `gateway.cloudCredentials()` returns a handle and no secret;
    `gateway.cloudSecret(id)` / `gateway.cloud.secret(handle)` fetches the secret once, under the same key
    (`POST /mcp/v1/cloud/credentials/{credential_id}/secret`). **Breaking:** `CloudCredentialOutcome.issued`
    carries `handle`, not `credential`.
  - **Instance sign-in in `connect()`.** `InstanceAuth`, `instanceFromEnv`, `findEvidence` and the
    `AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE`, `AUTHFI_DEVICE_KEY_FILE`, `AUTHFI_CONFIG_VERSION`,
    `AUTHFI_CONFIG_DIGEST` and `AUTHFI_IMAGE_DIGEST` variables. An agent key file stays as the labelled
    legacy fallback.
  - **LangSmith mapping** in `@authfi/sdk/otel` (run type, trace name, metadata), a decision span per
    `readResult`, and redaction of secret-shaped values on every export.
  - **`@authfi/sdk/a2a`**: signed agent cards (RFC 8785, `x5c` to a root you trust), calling a remote agent,
    and the AuthFI decision to A2A task state mapping.
- **The adapters do not offer a tool the gateway says is never allowed** (`vercel-ai`, `langchain`,
  `openai-agents`, `mastra`): the outlook `io.authfi/governance` is read from the tool's `_meta`,
  falling back to the annotation for older gateways (`Gateway.governanceOf`, `Gateway.offerable`).
  Advisory only: the gateway still decides every call, and a call to a hidden tool is refused.
- **Agent tokens are proven, and withdrawn agents are refused** (ported from 0.1 #30 and #31): DPoP
  proofs (RFC 9449), the AuthFI certificate chain of the signing key, `agentTokens` modes,
  `publicUrl`, `trustForwarded`, `replayGuard`, `nonceKey`, `rootPins`/`rootCerts`, and
  `@authfi/sdk/signals` (receiver, revocation store, `registerStream`). `verify()` refuses an agent's
  token (`agent_token_needs_request`). `protect()` no longer takes `publicUrl`: set it on the verifier.
- **Webhook verification**: `verifyWebhook({ body, headers, secret })` checks
  `X-AuthFI-Signature-256` (HMAC-SHA256 over `<timestamp>.<body>`) in constant time with Web Crypto,
  enforces a timestamp window (300 seconds by default), and returns a typed event. Refusals are
  `InvalidWebhook` with a code (`webhook_signature_invalid`, `webhook_timestamp_outside_tolerance`,
  and others). `WEBHOOK_EVENTS` lists the platform's event names. Shared vectors:
  `conformance/webhooks.json`.
- **`@authfi/sdk/admin`**: `new AdminClient(af, credential)` for organizations (members,
  invitations, accepting an invitation, join requests), users, roles, permissions and role bindings,
  on `<origin>/apis/regional/v1`, with typed models, cursor pagination (`list`, `all`) and the
  platform's refusals as `APIError`.
- **One core for every area.** `new AuthFI({ issuer })` (or `AuthFI.fromEnv()`) is the project: its
  discovery, key set and one HTTP transport. The issuer is the only required setting; every endpoint
  comes from the issuer's discovery document.
- **The transport:** timeouts per attempt and per call, a retry table that never sends a
  state-creating request twice, `X-Request-Id` and `traceparent` on every call, a `User-Agent`, no
  redirects, capped answers, and a warning when the platform deprecates a URL.
- **`Secret`**, which never prints, serialises or clones its value, and `isSecret(value)`, which
  recognises one from either build (ESM or CommonJS) where `instanceof` cannot.
- **Typed errors** under `AuthFIError`, with `isAuthFIError(e, kind)`, carrying the kernel's token
  refusal codes (generated from the AuthFI kernel at v0.58.0).
- **Plain `http` is refused** except to loopback: in a discovery document (`jwks_uri` and every
  `*_endpoint`) and on every request the transport sends, so a hostile or misconfigured document
  cannot make the SDK send a credential in the clear.
- **One caller's abort ends that caller's wait only.** Concurrent calls for the same token share one
  request, and `AbortSignal`s apply to each caller separately, so aborting one never fails the others
  or abandons a refresh whose rotated token the platform has already issued.
- **`TokenSource`**, the one credential interface, with an origin guard on `headers()` and `fetch`.
- **`TokenSet`, `TokenStore` and `MemoryTokenStore`** for people's tokens.
- TypeScript source, built to ESM and CommonJS with generated types.
- **People signing in to a server-rendered app**: `af.webApp({ clientId, clientSecret?, redirectUri,
  stateKey })` with `startSignIn` (PKCE S256, `state`, `nonce`), an encrypted `PendingSignIn`
  (`dump`, `loadPending`), `finishSignIn` (`iss` required, constant-time `state`, the code redeemed
  once, the ID token verified), `refresh` (single-flight), `userinfo`, `signOut` (revokes the refresh
  token, or the access token when there is none, then the end-session URL), `session(tokens, { key,
  store })`, and `StepUpRequired` for a weaker
  sign-in. `InvalidCallback` (`callback_*`), `InvalidIdToken` (`id_token_*`) and `InvalidPendingSignIn`
  (`pending_sign_in_malformed`, `_tampered`, `_expired`), the same classes and codes as the Python SDK.
- **A strict verifier**, `af.verifier({ audience, expectedTenantId })`: `typ at+jwt`, the algorithm
  pinned to the issuer's key (`RS256`, `ES256`, `EdDSA`), `iss`, a required audience that is never
  AuthFI's own, `exp`/`nbf`/`iat` with leeway, `sub`, the tenant pin, bound tokens and actor chains.
  Refusals carry the kernel's codes. One `AccessToken` shape for every kind of token, with
  `principal`, `actor` and `tokenKind`. `verifyRequest` takes a Fetch `Request` or its parts.
- `MultiIssuerVerifier`, pinning each trusted issuer to its tenant; it accepts a `TokenVerifier`
  from either build (`isTokenVerifier`).
- `@authfi/sdk/express`: `protect(verifier, { permissions, anyPermission, roles, scopes, optional })`
  and `authfiErrorHandler()`, answering refusals as the platform does. A caller's `X-Request-Id` is
  echoed and logged only when it is one the platform accepts. A key or discovery outage is a 503 with
  `Retry-After`; anything else that is not a refusal, a bug or a misconfiguration, is a 500 with none,
  and the error is logged with its message, stack and cause. `publicUrl` names the origin a DPoP proof
  is checked against, so the `Host` header need not be trusted.
- `refusalAnswer()` and the requirement helpers, for other frameworks.
- `af.clientCredentials()`, a machine client's token source.
- `af.check()`, the project's decision point.
- **AI agents** on the same core: `af.agent({ agentId, key })` with `AgentKey` (Ed25519, P-256 or RSA
  3072, held as a Web Crypto key), the agent's own token (a fresh five-minute assertion per
  attempt, cached, single-flight), `forResource` with `sendTo`, `capabilities`, CIBA
  (`requestUserToken`, `awaitUserToken`, `tokenAsUser`; `bindingMessage` required), token exchange
  (`exchange`, no client authentication), `DelegatedToken` (`subject`, `actor`, `via`), the
  transaction token and gate, and approvals (`requestApproval`, `approval`, `waitForApproval`).
  A wait that runs out its own `timeoutMs` (`awaitUserToken`, `waitForApproval`) throws `WaitTimeout`
  (`code === 'wait_timeout'`, with the approval's id when it has one) and leaves the request open; a
  CIBA request that really expired is `ConsentExpired`. Both waits take `pollIntervalMs` (finite and above zero, else `ConfigurationError`; the CIBA wait never polls faster than the platform's interval, so a smaller value is raised to it). `authorization_pending` is the server's word
  and is never raised locally.
- **The gateways**: `agent.gateway()` and `delegatedToken.gateway()`, with `mcpUrl`, `modelBaseUrl`,
  an origin-pinned `fetch` (a 401 is `GatewayTokenRefused`), `readResult` returning a `ToolOutcome`
  (`allowed`, `refused`, `approval_required`), `scopeOf`, `cloudCredentials` (a credential is issued on 201; 202 asks for approval; `expiresInSeconds` is 1 to 900), and `APPROVAL_ARGUMENT`.
  The gateway's hold is read by `HOLD_PATTERN`, the same pattern as the Python SDK's, and a model
  is told `HOLD_MESSAGE`.
- **`connect()`** (`@authfi/sdk/node`): the credential from the environment in one call, an agent
  key by default or `AUTHFI_CLIENT_ID` with `AUTHFI_CLIENT_SECRET`. A client-credentials token is now a
  gateway source (`clientCredentials.gateway()`), minted for the gateway and labelled `client-credentials`.
- **Run id:** `gateway.forRun(runId?)` sends `<runId>.<n>` as `X-Request-Id` on every call;
  `gateway.serverRunId` is the run the gateway derived from the token (`AuthFI-Run-Id`).
- **`@authfi/sdk/otel`**: `registerAuthFITelemetry` exports framework steps to `/otlp/v1/traces` under the
  credential's current token, with content off by default and `authfi.agent_id` / `authfi.run_id` on every
  span. `createVercelAI().exportSteps()` wires it into the AI SDK. `@opentelemetry/*` and `@ai-sdk/otel`
  are optional peers.
- **`@authfi/sdk/vercel-ai`**: `createVercelAI({ source, approvalSecret })` for the Vercel AI SDK 7:
  the credential per request, refusals as tool results, approvals that resume only on AuthFI's
  decision (memo per tool call, bounded), the AuthFI approval id in each approval request bound to
  its tool call by an HMAC under `approvalSecret`, the hold text kept from the model, a model-written
  approval id stripped, content kept out of telemetry by default. `ai` (7.0.82 or later) and `@ai-sdk/*` are
  optional peers, tested at their lowest versions in CI.
- `@authfi/sdk/node`: `readAgentKey` (refuses a key file others can read, checked on the open file),
  `generateAgentKeyFile` (makes a key into a new 0600 file, never overwrites, and returns a key that
  cannot be written again) and `agentFromEnv`.
- `conformance/vectors.json`: tokens with the outcome every AuthFI SDK must produce, run in Node and
  in the edge runtime.

### Build and CI

- `pipeline.yml`: lint, the tests on Node 22, 24 and 26 and in the edge runtime with coverage gates,
  and a build checked by publint, attw and a browser bundle; one required check, `ci`. No secrets
  in any pull-request job, every action pinned by commit.
- `live.yml` (main and on demand, protected environment) and `weekly.yml` (platform drift and the
  kernel codes against its newest tag).
- `SECURITY.md`.

### Changed

- **An access token is read from `client_id` and `scope` only**, as the design says; `azp` and `scp`
  are not stand-ins for them. A typed `agent:` or `app:` subject keeps its own kind when the token
  names an actor, and a token is expired from `exp` plus the leeway, in every SDK.
- **Verification is strict.** A missing `audience` is a `ConfigurationError`, not "accept any".
  ID tokens, transaction tokens and tokens without `kid` are refused. Agent tokens (EdDSA) verify.
- **Refusals no longer leak to the caller.** The 0.1 middleware answered `err.message`, and a 403
  listed the missing permissions; both are now the platform's opaque answers.
- **Node.js 22.12 or later is required** (Node 18 and 20 are past end of life).
- **Install from GitHub runs a build.** The package is TypeScript now, so the codeload tarball URL
  in the previous README no longer installs a usable package; install with
  `npm install github:authfi/authfi-nodejs-sdk#<tag>`, which needs git.
- The hand-written `index.js` and `index.d.ts` are replaced by the TypeScript source.

### Deprecated (removed in 1.0)

- The 0.1 factory `authfi(config)`, kept as the default export in ESM and CommonJS and rebuilt on
  the new core: `require`, `requireRole` and `authenticate` delegate to `protect` (and still set
  `req.user`), `verifyToken` uses the strict verifier, `start` reads discovery. Each warns once.

### Removed

- `registerPermission`, `syncPermissions` and `autoSync`: no permission sync exists on the platform.
  The calls throw `NotSupportedError`.
- `cloud.credentials` and `cloud.token`: their route is not open to applications. They throw
  `NotSupportedError`; agents get cloud credentials through the gateway.
