// An agent with its own identity: its key, its token, and a call through the MCP gateway.
//
//   node --env-file=.env --import tsx agent.ts

import { AuthFI, isAuthFIError } from '@authfi/sdk';
import { agentFromEnv } from '@authfi/sdk/node';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);

console.log('capabilities:', [...(await agent.capabilities())]);

// agent.fetch attaches a current token to each request and refuses any origin but AuthFI's.
try {
  const res = await agent.fetch(`${af.issuer}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  const body = (await res.json()) as { result?: { tools?: { name: string }[] } };
  console.log(
    'tools:',
    body.result?.tools?.map((t) => t.name),
  );
} catch (e) {
  if (isAuthFIError(e)) console.error('AuthFI refused:', e.code, e.requestId);
  else throw e;
}
