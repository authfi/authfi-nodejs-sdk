// An app whose signed-in users have an agent act for them: the person's token is exchanged for one
// the agent holds for them (RFC 8693), naming the person as subject and the agent as actor.
//
//   node --env-file=.env --import tsx server.ts

import express from 'express';
import { AuthFI, Secret } from '@authfi/sdk';
import { authfiErrorHandler, protect } from '@authfi/sdk/express';
import { agentFromEnv } from '@authfi/sdk/node';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);
const verifier = af.verifier({ audience: (process.env.API_AUDIENCE ?? 'app_web').split(',') });

const app = express();
app.post('/assistant/summarise', protect(verifier), async (req, res, next) => {
  try {
    // The person's own token, from the request, wrapped so it is never logged or kept.
    const personToken = new Secret((req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''));
    // The project must allow this agent to act for this person; otherwise this is access_denied.
    const forPerson = await agent.exchange(personToken, { scope: ['mcp:docs.read'] });
    res.json({
      subject: forPerson.subject?.toString(),
      actor: forPerson.actor?.toString(),
      scopes: [...forPerson.scopes],
    });
  } catch (e) {
    next(e);
  }
});
app.use(authfiErrorHandler());
app.listen(Number(process.env.PORT ?? 3000));
