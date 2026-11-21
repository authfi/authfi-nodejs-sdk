# Model calls through the LLM gateway

Send an agent's model calls through AuthFI, with the token kept out of traces.

```bash
cp .env.example .env
node --env-file=.env --import tsx agent.ts
```

| API | Base URL |
|---|---|
| Anthropic Messages (the Anthropic SDKs add `/v1/messages`) | `gateway.modelBaseUrl('anthropic')`: `<issuer>/llm` |
| OpenAI Chat Completions and Responses | `gateway.modelBaseUrl('openai')`: `<issuer>/llm/v1` |

**The model door has its own token.** `/llm` takes only a token minted for `<issuer>/llm`, and `/mcp` only one
minted for `<issuer>/mcp`. `gateway.fetch` asks for the second token itself (same key, same run) and sends each door
its own, so there is nothing to configure.

**Keep the token out of traces.** Give a provider SDK `gateway.fetch`, which attaches the agent's
current token to each request. Never put the token in an API key, a default header or an extra
header: tracers such as LangSmith and the OpenAI Agents exporter record those. A placeholder API key
is fine; the gateway reads `Authorization` first.

A model is named `<provider>/<model>` when more than one provider serves it.
