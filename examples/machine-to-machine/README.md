# Machine to machine

A job that calls an API as a machine client (OAuth client credentials).

```bash
cp .env.example .env
npm install @authfi/sdk
node --env-file=.env --import tsx job.ts
```

- **`resource`** is the API's client id, so the token's audience is that API. Without it the token
  names the job itself as its audience, which no API should accept.
- **`sendTo`** is the API's exact origin. `m2m.fetch` and `m2m.headers()` refuse to attach the token
  to any other origin.
- The token is cached and renewed at two thirds of its lifetime; concurrent callers share one mint.
