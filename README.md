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
