# The action gate

For a high-risk action, the agent first asks for a transaction token, which freezes the action, its
resource and its parameters for 60 seconds. The project's constraints are checked before it is
minted, so an over-limit action never gets a signed artefact. The gate then answers `allow`, `deny`
or `approval_required`, and refuses if anything differs from what was frozen.

```bash
cp .env.example .env
node --env-file=.env --import tsx agent.ts
```

This is AuthFI's own gate. It is named after the IETF Transaction Tokens draft but does not follow
it.
