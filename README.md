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
- Permission auto-sync on `start()`
- Cloud credentials (GCP/AWS/Azure/OCI)
- TypeScript definitions included
- Zero dependencies — uses Node.js crypto

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
sends an expired token, and it refuses to send the token anywhere but the project's origin. With
the Vercel AI SDK:

```js
const { createAnthropic } = require('@ai-sdk/anthropic');
const { createMCPClient } = require('@ai-sdk/mcp');

const anthropic = createAnthropic({
  baseURL: `${agent.issuer}/mcp/v1`,
  authToken: 'set-per-request',                     // selects Bearer; agent.fetch replaces the value
  fetch: agent.fetch,
});
const mcp = await createMCPClient({
  transport: { type: 'http', url: `${agent.issuer}/mcp`, fetch: agent.fetch },
});
```

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
npm test
```

`test/live.test.js` runs against a real project and is skipped unless `AUTHFI_LIVE_ISSUER` and
`AUTHFI_LIVE_CONSOLE_TOKEN` (an administrator's console token on a testing project) are set; it
registers one agent per key type and removes them afterwards.

## License

MIT
