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

A token is an agent token when its `sub` or `client_id` starts with `agt_`, or it carries an `act`
claim. With `agentTokens: 'enforce'` (the default) such a token is accepted only when:

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
| `trustForwarded` | `false` | Build the origin from `X-Forwarded-Proto` and `X-Forwarded-Host`. Set it only behind a proxy that overwrites them; otherwise a client could choose the URL its proof is for. The `Host` header is never used. |
| `replayGuard` | in memory | `{ record(key, expiresAtMs) }` returning true when the key was new. The default holds at most 100000 proofs for one process and refuses when full. **With more than one replica, supply a shared store** (for example Redis `SET key 1 NX PX`); otherwise a proof can be replayed against another replica. |
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
`dpop_nonce`, `chain_not_proven`, `chain_policy`, `chain_pin`, `agent_token_needs_request`, and the
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
