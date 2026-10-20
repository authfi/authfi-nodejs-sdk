# AuthFI Node.js SDK

Official Node.js SDK for [AuthFI](https://authfi.io) — the identity control plane.

## Install

Install from GitHub, pinned to a release tag or a commit on `main`:

```bash
npm install https://codeload.github.com/authfi/authfi-nodejs-sdk/tar.gz/<ref>
```

`<ref>` is a release tag (`refs/tags/v<version>`) or a full commit SHA. The tarball URL needs no
git in the image; `npm install github:authfi/authfi-nodejs-sdk#<tag>` does, and fails without it.
The package installs as `@authfi/sdk`, so `require('@authfi/sdk')` works either way.

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

- JWKS + RS256 token verification with caching
- `auth.require("read:users")` — Express middleware
- `auth.requireRole("admin")` — role-based access
- `auth.authenticate()` — JWT only, no permission check
- Permission auto-sync on `start()`
- Cloud credentials (GCP/AWS/Azure/OCI)
- TypeScript definitions included
- Zero dependencies — uses Node.js crypto

## Cloud Credentials (AuthFI Connect)

```js
const creds = await auth.cloud.credentials(userToken, 'gcp', {
  project: 'my-project'
});
```

## Running Tests

```bash
node --test test.js
```

13 unit tests — all passing.

## License

Apache-2.0. See [LICENSE](LICENSE).
