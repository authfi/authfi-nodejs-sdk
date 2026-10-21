// A model call through AuthFI's AI gateway with the agent's own token, kept out of any tracer:
// the credential is attached per request by the gateway's fetch, never set as an API key or a
// default header a tracer would record.
//
//   node --env-file=.env --import tsx agent.ts

import { AuthFI } from '@authfi/sdk';
import { agentFromEnv } from '@authfi/sdk/node';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);
const gateway = agent.gateway();

// Anthropic's Messages API on the gateway. A provider SDK takes the same two settings:
// baseURL: gateway.modelBaseUrl('anthropic'), fetch: gateway.fetch.
const res = await gateway.fetch(`${gateway.modelBaseUrl('anthropic')}/v1/messages`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'anthropic-version': '2023-06-01' },
  body: JSON.stringify({
    model: process.env.AUTHFI_MODEL ?? 'claude-haiku-5-5',
    max_tokens: 200,
    messages: [{ role: 'user', content: 'Say hello in five words.' }],
  }),
});
console.log(res.status, await res.json());
