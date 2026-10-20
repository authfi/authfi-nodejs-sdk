# Changelog

All notable changes to this package. It follows [Semantic Versioning](https://semver.org): before
1.0 a minor version may break, but only with an entry here and one minor version of deprecation.

## 0.2.0 (unreleased)

### Added

- **One core for every area.** `new AuthFI({ issuer })` (or `AuthFI.fromEnv()`) is the project: its
  discovery, key set and one HTTP transport. The issuer is the only required setting; every endpoint
  comes from the issuer's discovery document.
- **The transport:** timeouts per attempt and per call, a retry table that never sends a
  state-creating request twice, `X-Request-Id` and `traceparent` on every call, a `User-Agent`, no
  redirects, capped answers, and a warning when the platform deprecates a URL.
- **`Secret`**, which never prints, serialises or clones its value.
- **Typed errors** under `AuthFIError`, with `isAuthFIError(e, kind)`, carrying the kernel's token
  refusal codes (generated from authfi-regional-kernel v0.58.0).
- **`TokenSource`**, the one credential interface, with an origin guard on `headers()` and `fetch`.
- **`TokenSet`, `TokenStore` and `MemoryTokenStore`** for people's tokens.
- TypeScript source, built to ESM and CommonJS with generated types.
- **People signing in to a server-rendered app**: `af.webApp({ clientId, clientSecret?, redirectUri,
  stateKey })` with `startSignIn` (PKCE S256, `state`, `nonce`), an encrypted `PendingSignIn`
  (`dump`, `loadPending`), `finishSignIn` (`iss` required, constant-time `state`, the code redeemed
  once, the ID token verified), `refresh` (single-flight), `userinfo`, `signOut` (revokes the refresh
  token, then the end-session URL), `session({ key, store })`, and `StepUpRequired` for a weaker
  sign-in. `SignInError` and `InvalidPendingSignIn` for refused callbacks and blobs.
- **A strict verifier**, `af.verifier({ audience, expectedTenantId })`: `typ at+jwt`, the algorithm
  pinned to the issuer's key (`RS256`, `ES256`, `EdDSA`), `iss`, a required audience that is never
  AuthFI's own, `exp`/`nbf`/`iat` with leeway, `sub`, the tenant pin, bound tokens and actor chains.
  Refusals carry the kernel's codes. One `AccessToken` shape for every kind of token, with
  `principal`, `actor` and `tokenKind`. `verifyRequest` takes a Fetch `Request` or its parts.
- `MultiIssuerVerifier`, pinning each trusted issuer to its tenant.
- `@authfi/sdk/express`: `protect(verifier, { permissions, anyPermission, roles, scopes, optional })`
  and `authfiErrorHandler()`, answering refusals as the platform does.
- `refusalAnswer()` and the requirement helpers, for other frameworks.
- `af.clientCredentials()`, a machine client's token source.
- `af.check()`, the project's decision point.
- **AI agents** on the same core: `af.agent({ agentId, key })` with `AgentKey` (Ed25519, P-256 or RSA
  3072, held as a Web Crypto key), the agent's own token (a fresh five-minute assertion per
  attempt, cached, single-flight), `forResource` with `sendTo`, `capabilities`, CIBA
  (`requestUserToken`, `awaitUserToken`, `tokenAsUser`; `bindingMessage` required), token exchange
  (`exchange`, no client authentication), `DelegatedToken` (`subject`, `actor`, `via`), the
  transaction token and gate, and approvals (`requestApproval`, `approval`, `waitForApproval`).
- **The gateways**: `agent.gateway()` and `delegatedToken.gateway()`, with `mcpUrl`, `modelBaseUrl`,
  an origin-pinned `fetch` (a 401 is `GatewayTokenRefused`), `readResult` returning a `ToolOutcome`
  (`allowed`, `refused`, `approval_required`), `scopeOf`, `cloudCredentials`, and `APPROVAL_ARGUMENT`.
- **`@authfi/sdk/vercel-ai`**: `createVercelAI({ source, approvalSecret })` for the Vercel AI SDK 7:
  the credential per request, refusals as tool results, approvals that resume only on AuthFI's
  decision (memo per tool call, bounded), the hold text kept from the model, a model-written approval
  id stripped, content kept out of telemetry by default. `ai` and `@ai-sdk/*` are optional peers.
- `@authfi/sdk/node`: `readAgentKey` (refuses a key file others can read), `writeAgentKey` (0600,
  never overwrites) and `agentFromEnv`.
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

- **Verification is strict.** A missing `audience` is a `ConfigurationError`, not "accept any".
  ID tokens, transaction tokens and tokens without `kid` are refused. Agent tokens (EdDSA) verify.
- **Refusals no longer leak to the caller.** The 0.1 middleware answered `err.message`, and a 403
  listed the missing permissions; both are now the platform's opaque answers.

- **Node.js 22.12 or later is required** (Node 18 and 20 are past end of life).
- **Install from GitHub runs a build.** The package is TypeScript now, so the codeload tarball URL
  in the previous README no longer installs a usable package; install with
  `npm install github:authfi/authfi-nodejs-sdk#<tag>` or from a release tarball.
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
