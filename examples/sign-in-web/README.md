# Sign people in (Express)

A server-rendered app that signs people in with AuthFI: the authorization code flow with PKCE.

```bash
cp .env.example .env    # set the app's client id and secret, and a state key
node --env-file=.env --import tsx server.ts
```

Make the state key once: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`.

What the SDK takes care of:

- **PKCE, `state` and `nonce`** on every sign-in, and the callback's `iss` checked against the issuer
  (a callback without it is refused).
- **The pending sign-in never reaches the browser readable.** It holds the PKCE verifier and the
  nonce, so `pending.dump()` encrypts it under your state key, bound to the app and its redirect
  URI, for ten minutes. A signed cookie (Express's `cookie-session`, Flask's `session`) is readable
  by its holder: store the blob, never the values.
- **The ID token is verified**: the algorithm the issuer lists for ID tokens, the audience, the
  nonce, `at_hash`, and the `acr` and `max_age` you asked for. A weaker sign-in is `StepUpRequired`,
  with the `acr` to ask for again.
- **Refresh tokens rotate**, and reusing a spent one signs the person out everywhere. `web.session()`
  refreshes through your `TokenStore` with `compareAndSet`, so two workers never spend the same one.
  `MemoryTokenStore` is for one process; give several workers a shared store.
- **Sign-out revokes the refresh token**, because the platform's sign-out ends the browser session but
  not the app's refresh token, then returns the end-session URL. `postLogoutRedirectUri` must share the
  scheme and host of one of the app's redirect URIs.
