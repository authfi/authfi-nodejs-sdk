# Migrating to 0.2

0.2 rebuilds the SDK on one core shared by every area. Nothing was published to npm before, so the
only users are programs installed from GitHub `main`. Each section below says what changes and what
to write instead.

## Install

The package is TypeScript now and builds on install. Replace the codeload tarball URL with either:

```bash
npm install github:authfi/authfi-nodejs-sdk#<tag-or-commit>      # needs git
npm install https://github.com/authfi/authfi-nodejs-sdk/releases/download/<tag>/authfi-sdk-<version>.tgz
```

## Node.js

Node.js 22.12 or later is required. The package is ESM and CommonJS; both `import` and `require`
work.

## Configuration

The project is configured by its **issuer**, never by a tenant slug and an API host:

| Before | 0.2 |
|---|---|
| `authfi({ tenant: 'acme', apiKey, apiUrl: 'https://api.authfi.io' })` | `new AuthFI({ issuer: 'https://acme.authfi.io' })` |
| endpoints built from `apiUrl/<tenant>/...` | every endpoint read from `<issuer>/.well-known/openid-configuration` |
| `apiKey` (`sk_live_…`) | not used: the platform issues no such key |

## Verifying tokens

```ts
// 0.1
const auth = authfi({ tenant: 'acme', apiKey: 'sk_live_…' });
app.get('/users', auth.require('read:users'), handler); // req.user = claims

// 0.2
import { AuthFI } from '@authfi/sdk';
import { protect, authfiErrorHandler } from '@authfi/sdk/express';
const af = new AuthFI({ issuer: 'https://acme.authfi.io' });
const verifier = af.verifier({ audience: ['api_users', 'app_web'] });
app.get('/users', protect(verifier, { permissions: ['read:users'] }), handler); // req.authfi
app.use(authfiErrorHandler());
```

| 0.1 | 0.2 |
|---|---|
| `auth.require(...perms)` (all of them) | `protect(verifier, { permissions })` (all of them) |
| `auth.requireRole(...roles)` (any of them) | `protect(verifier, { roles })` (any of them) |
| `auth.authenticate()` | `protect(verifier)` |
| `auth.verifyToken(token)` returns claims | `verifier.verify(token)` returns an `AccessToken`; `.claims` holds the claims |
| `req.user` | `req.authfi` (`req.user` is still set by the deprecated factory) |
| `req.user.email` | not on access tokens: read the ID token at sign-in, or userinfo |
| an RS256-only check with no `iss` or `aud` | the strict verifier; `audience` is required |

**What breaks on purpose:** a verifier without an audience, a token without `kid`, an ID token used
as a bearer, and a 403 body that named the missing permissions.

The 0.1 factory still works for one minor version (`require('@authfi/sdk')(config)` and
`import authfi from '@authfi/sdk'`), with a warning per call; pass `issuer` and `audience` to it.

## Removed calls

| 0.1 | 0.2 |
|---|---|
| `registerPermission`, `syncPermissions`, `autoSync` | none: manage permissions in the console. The calls throw `NotSupportedError` |
| `cloud.credentials`, `cloud.token` | agents: the gateway's cloud credentials. The calls throw `NotSupportedError` |

## Agents

Nothing about agents was released on `main`, so there are no aliases. Code written against the
open pull request #10 changes as follows:

| PR #10 | 0.2 |
|---|---|
| `new AgentAuth({ issuer, agentId, key })` | `af.agent({ agentId, key })`, from the project |
| `AgentAuth.fromEnv()` | `agentFromEnv(af)` from `@authfi/sdk/node` |
| `AgentKey.fromFile(path, { kid })` | `readAgentKey(path, { kid })` from `@authfi/sdk/node` (refuses a file others can read) |
| `AgentKey.generate()` (sync) | `await AgentKey.generate()` (Web Crypto) |
| `key.privatePem()` | none: `generateAgentKeyFile(path)` makes a key straight into a new 0600 file, and no key object returns its private half |
| `requestUserApproval({ ... })` | `requestUserToken({ loginHint, bindingMessage })`; `bindingMessage` is required |
| `awaitUserToken(approval, { timeout })` | `awaitUserToken(request, { timeoutMs })` |
| `exchangeToken({ subjectToken })` | `exchange(new Secret(subjectToken))` or `exchange(tokenSource)` |
| `authHeader()` | `headers(method, url)` |
| `AgentAuthError.error` | `AuthFIError.code`; `ConsentDenied`, `ConsentExpired` for the person's answers |
| `allowedOrigins` | `forResource(resource, { sendTo })` |

## The Vercel AI adapter

Nothing about it was released on `main`. Code written against the open pull request #12:

| PR #12 | 0.2 |
|---|---|
| `createVercelAI({ agent, credentials })` | `createVercelAI({ source })`: an `AgentAuth` or a `DelegatedToken` |
| `approvalSecret` optional (random per process) | required, 32 bytes or more, the same in every process that may resume a run |
| `pollInterval`, `approvalTimeout` | `pollIntervalMs`, `approvalTimeoutMs` |
| tool names mapped from `<server>.<tool>` | the gateway's names (`<server>__<tool>`), unchanged |
| `APPROVAL_ARG` | `APPROVAL_ARGUMENT` |
| `decisionOf(result)` (`held`) | `gateway.readResult(result)` (`approval_required`) |
| a 403 tool refusal turned into a result | removed: the gateway answers a refusal as a tool result |

## Signing people in

0.1 had no sign-in. Apps that wrote the code flow by hand can move to `af.webApp()`; check what it
does that hand-written flows often miss: the callback's `iss`, an encrypted pending sign-in instead of
a signed cookie, the ID token's `nonce` and `at_hash`, single-flight refresh, and revoking the refresh
token at sign-out.
