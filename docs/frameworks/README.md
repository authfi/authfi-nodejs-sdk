# Frameworks

One credential, and each framework's own tool, model, approval and tracing seams go through AuthFI:

```ts
import { connect } from '@authfi/sdk/node';

const source = await connect();   // AUTHFI_ISSUER and AUTHFI_AGENT_ID; keyless on a bound workload
```

| Framework | Import | Page |
|---|---|---|
| Vercel AI SDK 7 | `@authfi/sdk/vercel-ai` | [vercel-ai](vercel-ai.md) |
| LangChain.js and LangGraph.js | `@authfi/sdk/langchain` | [langchain](langchain.md) |
| OpenAI Agents SDK | `@authfi/sdk/openai-agents` | [openai-agents](openai-agents.md) |
| Mastra | `@authfi/sdk/mastra` | [mastra](mastra.md) |
| Express (protect an API) | `@authfi/sdk/express` | [express](express.md) |

Start with the [quickstart](../quickstart.md). The framework packages are optional peers: install the ones you use.
In every adapter, models go through `<issuer>/llm`, tools through `<issuer>/mcp`, a call a person must approve pauses
and resumes on the person's decision, and the token is attached to each request by the adapter and never appears in
a framework setting or a trace.
