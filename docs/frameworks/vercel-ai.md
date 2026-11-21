# Vercel AI SDK

```bash
npm install @authfi/sdk ai @ai-sdk/anthropic @ai-sdk/mcp
```

```ts
import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import { generateText, stepCountIs, type ModelMessage } from 'ai';
import { Secret } from '@authfi/sdk';
import { connect } from '@authfi/sdk/node';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const authfi = createVercelAI({ source: await connect(), approvalSecret: new Secret(process.env.APPROVAL_SECRET ?? '') });
const model = createAnthropic(authfi.anthropic())('claude-haiku-5-5');
const mcp = await createMCPClient({ transport: authfi.mcpTransport() });
const tools = authfi.tools(await mcp.tools());

const messages: ModelMessage[] = [{ role: 'user', content: 'Refund order 4411' }];
const run = () => generateText({ model, tools, messages, stopWhen: stepCountIs(4), ...authfi.approvals() });

let result = await run();
while (authfi.pendingApprovals(result).length > 0) {            // a call a person must approve
  messages.push(...result.response.messages, await authfi.awaitApprovals(result));   // AuthFI's decision
  result = await run();
}
```

- **Model** through `<issuer>/llm`, **tools** through `<issuer>/mcp`, the agent's token on each request.
- **Approval** is the AI SDK's own approval request; `awaitApprovals` resumes it only on AuthFI's decision. An approval the
  app makes up is refused, and the model never reads the approval id.
- **Steps:** `await authfi.exportSteps()` sends model and tool steps to AuthFI, with no content unless you turn it on.
