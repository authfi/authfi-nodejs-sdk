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
  tenant: 'acme',
  apiKey: 'sk_live_...',
});

// Permission middleware
app.get('/api/users', auth.require('read:users'), (req, res) => {
  console.log(req.user); // decoded JWT claims
  res.json(users);
});

// Role middleware
app.get('/admin', auth.requireRole('admin'), handler);

// Start — syncs permissions + pre-fetches JWKS
auth.start().then(() => app.listen(3000));
```

## Features

- JWKS + RS256/PS256/ES256/EdDSA token verification with caching
- `auth.require("read:users")` — Express middleware
- `auth.requireRole("admin")` — role-based access
- `auth.authenticate()` — JWT only, no permission check
- Permission auto-sync on `start()`
- Shared Signals push receiver and revocation store, so a revoked agent is refused at once (see Revocation)
- Cloud credentials (GCP/AWS/Azure/OCI)
- TypeScript definitions included
- Zero dependencies — uses Node.js crypto

## Revocation: stop an agent's tokens the moment AuthFI withdraws it

Access tokens verify offline, so a revoked or suspended agent keeps working until its token expires, unless AuthFI tells you. AuthFI sends a signed Shared Signals event (RFC 8935 push) when an agent is revoked, suspended or deleted. `auth.receiver()` takes it and `verifyToken` refuses the agent's earlier tokens at once.

```js
const store = authfi.createRevocationStore({
  tokenLifetimeSeconds: 86400, // at least the longest token you accept
});
const auth = authfi({
  tenant: 'acme',
  apiKey: 'sk_live_...',
  issuer: 'https://acme.authfi.io',
  revocations: store, // verifyToken and the middleware now check revocations
});

app.post('/ssf/push', auth.receiver({
  audience: 'my-stream',              // the audience you registered the stream with
  authToken: process.env.PUSH_BEARER, // optional: the bearer AuthFI sends on each push
  onSignal: (s) => console.log(s.event, s.subject),
}));
```

The receiver reads the request body itself (or `req.body` if a body parser already made it a string or Buffer), so it also works in a plain `http.createServer`. What it does, and what it refuses:

- POST with `Content-Type: application/secevent+jwt`, at most 16 KiB; any other method is 405. If you set `authToken`, the push must carry that bearer (401 otherwise).
- The SET is a JWS signed by a key in the project's key set (the one that verifies agent tokens), with `typ` `secevent+jwt`. `none` and HMAC are refused. AuthFI treats a 400 as final and stops the stream, so a condition that can heal answers 503 and AuthFI retries: a key that is not in the key set yet (a rotation), a key set that cannot be read, or an `iat` more than 60 seconds ahead of this server's clock.
- `iss` is the configured issuer, `aud` includes your stream audience, `jti` and `iat` are present, `iat` is present, `exp` (if present) has not passed, `sub_id` names the subject, `events` holds objects.
- Accepted: `202`. Refused: `400` with `{"err": ..., "description": ...}` where `err` is `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` or `authentication_failed`. Nothing is recorded for a refused SET.
- A SET older than any token it could affect (`tokenLifetimeSeconds`) is answered `202` and not applied.
- A `jti` seen before is answered `202` and applied once, so AuthFI can retry a push whose answer was lost. The set of seen ids is bounded.

`session-revoked`, `account-purged` and `credential-compromise` revoke the subject: tokens issued at or before the SET's `iat` are refused (`verifyToken` throws an error with `code` `token_revoked`), and a token issued after it is accepted. A delegated token is refused when any actor in its `act` chain is revoked. With a store configured, a token with no `iat` or `exp` is refused (error code `token_iat_exp_required`). `token-claims-change` with `resumed: true` reaches `onSignal` with `resumed` set and changes nothing else: a resumed agent mints a new token, which is newer than the revocation.

The error `verifyToken` throws for a revoked token carries the jti of the revoking SET as `error.ref` (and in its message), so a refusal can be traced to the event that caused it. `store.revoke(subject, notBefore, ref)`, `store.isRevoked(subject, issuedAt)` and `store.find(subject, issuedAt)` take Unix seconds and are there for your own use. The store holds at most `maxEntries` subjects (default 100,000) and forgets a revocation once it is older than `tokenLifetimeSeconds`. `verifyToken` refuses a token that lives longer than that (error code `revocation_store_misconfigured`): set it to your longest token lifetime. When it is full it drops the oldest revocations and refuses every token issued before the newest one it dropped, whatever its subject, until that time passes `tokenLifetimeSeconds`: a full store costs some holders a new token and never lets a revoked one through.

`verifyToken` verifies RS256, PS256, ES256 and EdDSA tokens, which is what agent tokens use, and refuses a Security Event Token presented as an access token.

Subjects match exactly: `agent:agt_42` is not `AGENT:AGT_42` and not a bare `agt_42`. AuthFI always sends the `agent:<id>` form.

To register the stream from code, `auth.registerStream(bearer, { audience: 'my-stream', endpointUrl: 'https://api.example.com/ssf/push', authToken })` reads the issuer's `/.well-known/ssf-configuration` and posts the registration to the `configuration_endpoint` it names, which must be on the issuer's host. The bearer is a credential allowed to register streams, and no redirect is followed with it.

The store lives in memory. A restart empties it, so until the tokens issued before the restart expire, a revoked agent is accepted again; a replica only learns of revocations pushed to its own endpoint. Run one stream per process and keep the token lifetime short.

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

## License

MIT
