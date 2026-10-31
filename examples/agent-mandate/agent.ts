// One job under a mandate, with a cloud credential by handle.
//
//   node --env-file=.env --import tsx agent.ts

import { Secret } from '@authfi/sdk';
import { connect } from '@authfi/sdk/node';

const credential = await connect();
if (!('withMandate' in credential)) throw new Error('this example needs an agent, not a machine client');

const person = new Secret(process.env.PERSON_TOKEN ?? '');

await credential.withMandate(
  'support.refund',
  { subjectToken: person, params: { order: '4411' } },
  async (mandate) => {
    console.log('mandate', mandate.mandateId, 'allows', mandate.tools);

    const res = await mandate.gateway().fetch(`${credential.project.issuer}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'billing__refund', arguments: { order: '4411', amount: 40 } },
      }),
    });
    const outcome = mandate.gateway().readResult(((await res.json()) as { result: unknown }).result);
    if (outcome.kind === 'refused') console.log(outcome.why, '-', outcome.nextStep);

    // A handle is safe to show a model; the secret is for this runtime alone, once.
    const issued = await mandate.cloud.credentials({ account: '123456789012', role: 'refund-reader' });
    if (issued.kind === 'issued') {
      const secret = await mandate.cloud.secret(issued.handle);
      console.log('cloud key', secret.accessKeyId, 'expires', secret.expiresAt);
    }
  },
);
