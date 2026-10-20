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
