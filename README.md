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

npm builds the package from source on install (its `prepare` script), which needs `git` on the
machine. In an image without `git`, install the tarball attached to a GitHub release instead:

```bash
npm install https://github.com/authfi/authfi-nodejs-sdk/releases/download/<tag>/authfi-sdk-<version>.tgz
```

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

## Examples

| Example | |
|---|---|
| [`examples/protect-an-api`](examples/protect-an-api) | An Express API that verifies tokens and authorizes on permissions |
| [`examples/machine-to-machine`](examples/machine-to-machine) | A job calling that API with a client-credentials token |
| [`examples/agent-identity`](examples/agent-identity) | An agent's key, its token, and a call through the MCP gateway |
| [`examples/agent-for-a-person-voice`](examples/agent-for-a-person-voice) | Acting for a caller with no browser (CIBA) |
| [`examples/agent-for-a-signed-in-user`](examples/agent-for-a-signed-in-user) | Acting for a person signed in to your app (token exchange) |
| [`examples/action-gate`](examples/action-gate) | Freezing a high-risk action before running it |

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
