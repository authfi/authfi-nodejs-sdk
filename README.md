# AuthFI Node.js SDK

Official Node.js SDK for [AuthFI](https://authfi.io) — the identity control plane.

Zero dependencies: it uses `node:crypto` only. Node 18 or later.

## Install

```bash
npm install @authfi/sdk
```

## Quick Start: a resource server (Express)

```js
const authfi = require('@authfi/sdk');

const auth = authfi({
  issuer: 'https://acme.authfi.io',      // your project issuer
  audience: 'orders-api',                // the client id of THIS API (required)
  publicUrl: 'https://api.example.com',  // the origin your clients call (required for agent tokens)
  tenant: 'acme',                        // for permission sync and cloud credentials
  apiKey: 'sk_live_...',
});

// Verifies the token. For an agent token it also checks the DPoP proof of this request and the
// certificate chain of the key that signed the token. Sets req.user to the verified claims.
app.get('/api/orders', auth.require('read:orders'), (req, res) => res.json(orders));

app.get('/admin', auth.requireRole('admin'), handler);

// Outside Express (any framework), verify the request yourself.
const claims = await auth.verifyRequest(req);   // throws AuthFIError with a stable .code

auth.start().then(() => app.listen(3000));       // pre-fetches the key set, syncs permissions
```

A person's access token is checked as `Bearer`. `verifyToken(token)` is for person tokens only; it
refuses an agent token with `agent_token_needs_request`, because an agent token is proven by the
request that carries it.

## What is verified

Every token, always, with no switch to turn it off:

- compact JWS of 3 parts, at most 16 KiB, strict base64url;
- `alg` is RS256, PS256, ES256 or EdDSA and fits the issuer's key for that `kid` (kty and crv);
  `none` and `HS*` are refused; keys come only from the issuer's key set, never from the token;
- `typ` is `at+jwt` (an ID token is not accepted as a bearer token);
- `iss` equals `issuer`; `aud` includes one of `audience`; `exp` is present and in the future;
  `nbf` and `iat` are not in the future (leeway at most 300 s); `sub` and `tenant_id` are present,
  and `tenant_id` equals `tenantId` when that is set.

### Agent tokens

A token is an agent token when its `sub` or `client_id` starts with the exact, case-sensitive prefix
`agt_`, or it carries an `act` claim. With `agentTokens: 'enforce'` (the default) such a token is accepted only when:

1. it carries `cnf.jkt`, is presented with the `DPoP` scheme (`Authorization: DPoP <token>`), and
   the request carries exactly one valid DPoP proof (RFC 9449): `typ dpop+jwt`; EdDSA, ES256 or
   PS256 by the embedded key; `htm` and `htu` equal this request; `iat` within 60 s (5 s ahead);
   `ath` is the hash of the token; the key's RFC 7638 thumbprint equals `cnf.jkt`; the `jti` is
   unused (single use per key); and the server `nonce` when `nonceKey` is set;
2. the key that signed the token is certified by a chain: the JWKS key's `x5c` leaf certifies that
   key, `x5t#S256` in the token header and the JWKS equals the leaf, the chain reaches a pinned
   AuthFI root (by SPKI SHA-256), the leaf and every CA between state AuthFI policy
   `1.3.6.1.4.1.67322.1.1` or `.1.2`, the leaf is `digitalSignature` and not a CA, and every
   signature and date verifies.

A person token that carries `cnf` also needs its proof. A plain person bearer token is unchanged.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `issuer` | required | The project issuer URL. The key set is `${issuer}/.well-known/jwks.json`. |
| `audience` | required | Client id of your API (string or list). AuthFI's own audiences (the issuer, `authfi-console`, `authfi-workspace`, the API URL) are refused. |
| `tenantId` | none | Refuse tokens of any other `tenant_id`. |
| `jwksUrl` | issuer key set | Override the key set URL. |
| `leeway` | `60` | Clock leeway in seconds, 0 to 300. |
| `agentTokens` | `'enforce'` | `'enforce'`, `'watch'` (check, log the refusal code, allow) or `'off'` (explicit; logged once; the proof is still required for a token that carries `cnf`). |
| `publicUrl` | none | The origin clients call, for the DPoP `htu` check, for example `https://api.example.com` (origin only, no path). Required for agent tokens unless `trustForwarded`. |
| `trustForwarded` | `false` | Build the origin from `X-Forwarded-Proto` and `X-Forwarded-Host` (the last entry, which the proxy appended) when no `publicUrl` is set; a configured `publicUrl` always wins. Set it only behind a proxy that appends them; otherwise a client could choose the URL its proof is for. The `Host` header is never used. |
| `replayGuard` | in memory | `{ record(key, expiresAtMs) }` returning true when the key was new. The default holds at most 100000 proofs for one process (`replayMax`) and at most 1000 per proof key (`replayPerKey`); when a cap is reached it answers `dpop_replay_guard_full` (HTTP 503, `Retry-After`), never `dpop_replayed`. A custom guard returns `'full'` for the same case. **With more than one replica, supply a shared store** (for example Redis `SET key 1 NX PX`); otherwise a proof can be replayed against another replica. |
| `nonceKey` | none | At least 16 bytes (the project's `DPOP_NONCE_KEY`). Turns on server nonces: a proof without a current nonce is refused with `dpop_nonce`, a `DPoP-Nonce` header and `WWW-Authenticate: DPoP error="use_dpop_nonce"`. |
| `rootPins` | AuthFI Root CA R1 | Hex SHA-256 values of trusted root public keys. Replaces the built-in pin (for a private region). Never read from the JWKS. |
| `rootCerts` | none | PEM roots to complete a chain whose JWKS `x5c` omits the root. A root counts only when its key is pinned. |
| `logger` | none | `{ warn, debug }`. Receives refusal codes, never token or proof content. |

Existing options `tenant`, `apiKey`, `apiUrl`, `applicationId`, `clientSecret`, `autoSync` and
`jwksRefreshInterval` are unchanged.

## Refusal codes

Every refusal is an `AuthFIError` with a stable `code` and a message that holds nothing from the
token. The middleware answers `401` with `{ "error": "<code>" }` (`503` for `jwks_unavailable`).

`dpop_missing`, `dpop_multiple`, `dpop_malformed`, `dpop_type`, `dpop_alg`, `dpop_signature`,
`dpop_method`, `dpop_url`, `dpop_iat`, `dpop_ath`, `dpop_replayed`, `dpop_key_mismatch`,
`dpop_nonce`, `dpop_replay_guard_full`, `chain_not_proven`, `chain_policy`, `chain_pin`, `agent_token_needs_request`, and the
baseline codes `token_malformed`, `token_too_large`, `token_alg_not_allowed`, `token_kid_required`,
`token_crit_not_supported`, `token_typ_invalid`, `token_unknown_key`, `token_alg_key_mismatch`,
`token_signature_invalid`, `token_issuer_mismatch`, `token_audience_mismatch`, `token_expired`,
`token_exp_required`, `token_not_yet_valid`, `token_sub_required`, `token_tenant_required`,
`token_tenant_not_issuers`, `token_dpop_proof_required`, `token_act_chain_unsupported`,
`jwks_unavailable`, `missing_authorization`, `sdk_not_configured`.

## What an agent client sends

An agent calls your API with the token AuthFI minted for it and a fresh proof for each request:

```
GET /api/orders HTTP/1.1
Host: api.example.com
Authorization: DPoP <access token>
DPoP: <proof>
```

The proof is a JWS signed with the agent's own key (the one whose thumbprint is the token's
`cnf.jkt`):

```
header:  { "typ": "dpop+jwt", "alg": "EdDSA", "jwk": { <the agent's public key> } }
payload: { "jti": "<random, unique>", "htm": "GET", "htu": "https://api.example.com/api/orders",
           "iat": <now>, "ath": "<base64url SHA-256 of the access token>", "nonce": "<if asked>" }
```

`htu` has no query string or fragment. A new proof is made for every request. When the server
answers `401` with a `DPoP-Nonce` header, retry once with that value as `nonce`.

## Revocation: stop an agent's tokens the moment AuthFI withdraws it

Access tokens verify offline, so a revoked or suspended agent keeps working until its token expires, unless AuthFI tells you. AuthFI sends a signed Shared Signals event (RFC 8935 push) when an agent is revoked, suspended or deleted. `auth.receiver()` takes it, and `verifyRequest`, `verifyToken` and the middleware refuse the agent's earlier tokens at once.

```js
const store = authfi.createRevocationStore({
  tokenLifetimeSeconds: 86400, // at least the longest token you accept
});
const auth = authfi({
  issuer: 'https://acme.authfi.io',
  audience: 'client-id-of-your-api',
  publicUrl: 'https://api.example.com',
  revocations: store, // verification now checks revocations
});

app.post('/ssf/push', auth.receiver({
  audience: 'my-stream',              // the audience you registered the stream with
  authToken: process.env.PUSH_BEARER, // optional: the bearer AuthFI sends on each push
  onSignal: (s) => console.log(s.event, s.subject),
}));
```

The receiver reads the request body itself (or `req.body` if a body parser already made it a string or Buffer), so it also works in a plain `http.createServer`. What it does, and what it refuses:

- POST with `Content-Type: application/secevent+jwt`, at most 16 KiB; any other method is 405. If you set `authToken`, the push must carry that bearer (401 otherwise).
- The SET is a JWS signed by a key in the project's key set, with `typ` `secevent+jwt`. `none` and HMAC are refused. AuthFI treats a 400 as final and stops the stream, so a condition that can heal answers 503 and AuthFI retries: a key that is not in the key set yet (a rotation), a key set that cannot be read (fetched again after 15 seconds), or an `iat` more than 60 seconds ahead of this server's clock.
- `iss` is the configured issuer, `aud` includes your stream audience, `jti` and `iat` are present, `exp` (if present) has not passed, `sub_id` names the subject, `events` holds objects.
- Accepted: `202`. Refused: `400` with `{"err": ..., "description": ...}` where `err` is `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` or `authentication_failed`. Nothing is recorded for a refused SET.
- A SET older than any token it could affect (`tokenLifetimeSeconds`) is answered `202` and not applied.
- A `jti` seen before is answered `202` and applied once, so AuthFI can retry a push whose answer was lost. The set of seen ids is bounded.

`session-revoked`, `account-purged` and `credential-compromise` revoke the subject: tokens issued at or before the SET's `iat` are refused with code `token_revoked`, and a token issued after it is accepted. Revocation is checked before the DPoP proof, so a withdrawn agent is answered `token_revoked` wherever its token is presented. A delegated token is refused when its actor is revoked; a delegation chain (an `act` inside an `act`) is refused outright. With a store configured, a token with no `iat` is refused (`token_iat_exp_required`). `token-claims-change` with `resumed: true` reaches `onSignal` with `resumed` set and changes nothing else: a resumed agent mints a new token, which is newer than the revocation.

The error for a revoked token carries the jti of the revoking SET as `error.ref`, so a refusal can be traced to the event that caused it. `store.revoke(subject, notBefore, ref)`, `store.isRevoked(subject, issuedAt)` and `store.find(subject, issuedAt)` take Unix seconds and are there for your own use. The store holds at most `maxEntries` subjects (default 100,000) and forgets a revocation once it is older than `tokenLifetimeSeconds`. Verification refuses a token that lives longer than that (`revocation_store_misconfigured`): set it to your longest token lifetime. When it is full it drops the oldest revocations and refuses every token issued before the newest one it dropped, whatever its subject, until that time passes `tokenLifetimeSeconds`: a full store costs some holders a new token and never lets a revoked one through.

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
