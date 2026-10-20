// A voice agent acting for a caller who has no browser: the caller approves on their own phone
// (OpenID CIBA), reading the binding message, and the agent never sees a code or a password.
//
//   CALLER=ada@example.com node --env-file=.env --import tsx agent.ts

import { AuthFI, isAuthFIError } from '@authfi/sdk';
import { agentFromEnv } from '@authfi/sdk/node';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);

try {
  const forCaller = await agent.tokenAsUser({
    loginHint: process.env.CALLER ?? 'ada@example.com',
    bindingMessage: 'Refund order 4411', // what the caller reads before approving
    scope: ['mcp:refunds.create'],
    timeoutMs: 120_000,
  });
  console.log(`acting for ${forCaller.subject?.toString() ?? 'unknown'}`, [...forCaller.scopes]);
  // forCaller is a TokenSource: use forCaller.fetch, or hand it to a framework adapter.
} catch (e) {
  if (isAuthFIError(e, 'ConsentDenied')) console.log('the caller said no');
  else if (isAuthFIError(e, 'ConsentExpired')) console.log('the request lapsed before the caller answered');
  else throw e;
}
