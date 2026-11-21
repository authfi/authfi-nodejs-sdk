# OpenAI Agents SDK

```bash
npm install @authfi/sdk @openai/agents
```

```ts
import { Agent, MCPServerStreamableHttp, run } from '@openai/agents';
import { connect } from '@authfi/sdk/node';
import { createOpenAIAgents } from '@authfi/sdk/openai-agents';

const authfi = createOpenAIAgents({ source: await connect() });
const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
await server.connect();

const agent = new Agent({ name: 'support', model, tools: await authfi.tools(server) });
let result = await run(agent, 'Refund order 4411');
while (result.interruptions?.length) {                      // a call a person must approve
  await authfi.awaitApprovals(result.state);                // approves or rejects as AuthFI decided
  result = await run(agent, result.state);
}
```

- **Model:** `authfi.openai()` gives the settings for `new OpenAI(...)`: calls go to `<issuer>/llm/v1` with the agent's token.
- **Tools** from `<issuer>/mcp` as function tools, under the gateway's names.
- **Approval** is the SDK's own `needsApproval` interruption, resolved only on AuthFI's decision.
