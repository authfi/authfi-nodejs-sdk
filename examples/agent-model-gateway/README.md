# Model calls through the AI gateway

Send an agent's model calls through AuthFI, with the token kept out of traces.

```bash
cp .env.example .env
node --env-file=.env --import tsx agent.ts
```

| API | Base URL |
|---|---|
| Anthropic Messages (the Anthropic SDKs add `/v1/messages`) | `gateway.modelBaseUrl('anthropic')`: `<issuer>/mcp` |
| OpenAI Chat Completions and Responses | `gateway.modelBaseUrl('openai')`: `<issuer>/mcp/v1` |

**Keep the token out of traces.** Give a provider SDK `gateway.fetch`, which attaches the agent's
current token to each request. Never put the token in an API key, a default header or an extra
header: tracers such as LangSmith and the OpenAI Agents exporter record those. A placeholder API key
is fine; the gateway reads `Authorization` first.

A model is named `<provider>/<model>` when more than one provider serves it.
