# Migrating to 0.2

0.2 rebuilds the SDK on one core shared by every area. Nothing was published to npm before, so the
only users are programs installed from GitHub `main`. Each section below says what changes and what
to write instead.

## Install

The package is TypeScript now and builds on install. Replace the codeload tarball URL with the git install (the machine needs `git`):

```bash
npm install github:authfi/authfi-nodejs-sdk#<tag-or-commit>
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
