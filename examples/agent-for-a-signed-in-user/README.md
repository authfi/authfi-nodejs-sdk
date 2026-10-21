# Acting for a person signed in to your app (token exchange)

When a person is signed in to your app, an agent can act for them without asking again: the
person's access token is exchanged (RFC 8693) for a token whose subject is the person and whose
actor is the agent.

```bash
cp .env.example .env
node --env-file=.env --import tsx server.ts
```

- The project decides who may act for whom: until an admin allows this agent to act for the person,
  the exchange is refused `access_denied`.
- The exchange carries no client authentication: the agent proves itself with its own token as the
  `actor_token`.
- The delegated token renews by exchanging again while the person's token is valid, and raises
  `ConsentExpired` once it is not.
- `exchange` takes a `Secret` or a `TokenSource`, never a bare string, so a raw token in your code
  shows up in review.
