# LangChain.js and LangGraph.js

```bash
npm install @authfi/sdk @langchain/core @langchain/langgraph @langchain/mcp-adapters @langchain/anthropic
```

```ts
// Client and StreamableHTTPClientTransport are the MCP TypeScript SDK's.
import { connect } from '@authfi/sdk/node';
import { createLangChain } from '@authfi/sdk/langchain';

const authfi = createLangChain({ source: await connect() });
const client = new Client({ name: 'app', version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(new URL(authfi.mcpUrl), authfi.transportOptions()));
const tools = await authfi.tools(client, 'authfi');         // the gateway's tools, as LangChain tools

const graph = createAgent({ model, tools, checkpointer: new MemorySaver() });
let out = await graph.invoke({ messages }, config);
while (authfi.pendingApprovals().length > 0) {              // a call a person must approve
  await authfi.awaitApprovals();                            // AuthFI's decision, not a click in your app
  out = await graph.invoke(new Command({ resume: true }), config);
}
```

- **Model:** `authfi.anthropic()` is the `clientOptions` for `@langchain/anthropic` (and `authfi.openai()` the settings
  for `@langchain/openai`): calls go to `<issuer>/llm` with the agent's token.
- **Tools** from `<issuer>/mcp` under the gateway's names; a refusal is the tool's answer to the model.
- **Approval** is LangGraph's own `interrupt()`, resumed only on AuthFI's decision.
