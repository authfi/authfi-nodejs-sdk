// An agent on the Vercel AI SDK, governed by AuthFI: the model and the tools go through the
// gateways with the agent's token, a refusal reaches the model as the tool's answer, and a call a
// person must approve pauses until AuthFI decides.
//
//   node --env-file=.env --import tsx agent.ts

import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import { generateText, stepCountIs, type ModelMessage } from 'ai';
import { AuthFI, Secret } from '@authfi/sdk';
import { agentFromEnv } from '@authfi/sdk/node';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);

const authfi = createVercelAI({
  source: agent,
  // The same secret in every process that may resume a run; it signs the approval requests.
  approvalSecret: new Secret(process.env.APPROVAL_SECRET ?? ''),
});
const model = createAnthropic(authfi.anthropic())(process.env.AUTHFI_MODEL ?? 'claude-haiku-5-5');
const mcp = await createMCPClient({ transport: authfi.mcpTransport() });
const tools = authfi.tools(await mcp.tools());

const messages: ModelMessage[] = [{ role: 'user', content: 'Read the wiki of pallets/itsdangerous.' }];
const run = () => generateText({ model, tools, messages, stopWhen: stepCountIs(4), ...authfi.approvals() });

let result = await run();
while (authfi.pendingApprovals(result).length > 0) {
  console.log('waiting for a person to decide in AuthFI');
  // Asks the gateway, never the model or the app: only AuthFI's decision resumes the call.
  messages.push(...result.response.messages, await authfi.awaitApprovals(result));
  result = await run();
}
console.log(result.text);
await mcp.close();
