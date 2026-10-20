# Protect an API (Express)

An Express API that verifies AuthFI access tokens and authorizes each route on permissions.

```bash
cp .env.example .env    # set AUTHFI_ISSUER and API_AUDIENCE
npm install @authfi/sdk express
node --env-file=.env --import tsx server.ts
```

**Choosing `audience`.** A token names who it is for:

- a machine client's or agent's token names your API's client id when it was minted with
  `resource=<your API's client id>`;
- a person's token names the **front end** they signed in to.

So list your API's client id and the client ids of the front ends that call it. AuthFI's own
audiences (the issuer, `<issuer>/mcp`, the console) are refused at startup: accepting them would let a
token minted for the gateway be replayed at your API.

**Permissions, not scope.** Authorize on `permissions` and `roles`. On person and machine tokens
`scope` is whatever the client asked for.

**What callers see.** A refused token is answered `401` with one fixed `invalid_token` description,
whatever the cause; the cause (`token_expired`, `token_audience_mismatch`, …) goes to your log. A
missing permission is `403 forbidden`; a missing scope `403 insufficient_scope`; too weak a sign-in
`401 insufficient_user_authentication` with `acr_values`, so the client can sign the person in again.
