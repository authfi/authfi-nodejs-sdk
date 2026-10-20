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

### Changed

- **Node.js 22.12 or later is required** (Node 18 and 20 are past end of life).
- **Install from GitHub runs a build.** The package is TypeScript now, so the codeload tarball URL
  in the previous README no longer installs a usable package; install with
  `npm install github:authfi/authfi-nodejs-sdk#<tag>` or from a release tarball.
- The hand-written `index.js` and `index.d.ts` are replaced by the TypeScript source.
