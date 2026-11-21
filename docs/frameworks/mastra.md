# Mastra

```bash
npm install @authfi/sdk @mastra/core @mastra/mcp
```

```ts
import { Agent } from '@mastra/core/agent';
import { MCPClient } from '@mastra/mcp';
import { connect } from '@authfi/sdk/node';
import { createMastra } from '@authfi/sdk/mastra';

const authfi = createMastra({ source: await connect() });
const mcp = new MCPClient({ servers: { authfi: authfi.mcpServer() } });
const tools = authfi.tools(await mcp.listTools());

const agent = new Agent({ id: 'support', name: 'support', instructions, model, tools });
const out = await agent.generate('Refund order 4411');       // a call a person must approve suspends the run
await authfi.awaitApprovals();                               // AuthFI's decision, not a click in your app
await agent.approveToolCall({ runId: out.runId });
```

- **Model:** `authfi.openai()` gives the settings for an OpenAI-compatible Mastra model: calls go to
  `<issuer>/llm/v1` with the agent's token.
- **Tools** from `<issuer>/mcp` through Mastra's own `MCPClient`, under the gateway's names; a refusal is the tool's answer.
- **Approval** is Mastra's own tool approval, approved only on AuthFI's decision.
