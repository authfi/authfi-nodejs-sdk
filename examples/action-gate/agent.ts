// Freeze a high-risk action before running it: the transaction token fixes the action, resource and
// parameters, and the gate refuses anything that differs.
//
//   node --env-file=.env --import tsx agent.ts

import { AuthFI } from '@authfi/sdk';
import { agentFromEnv } from '@authfi/sdk/node';

const af = AuthFI.fromEnv();
const agent = await agentFromEnv(af);

const txn = await agent.transactionToken('refund.create', {
  resource: 'order:4411',
  context: { amount: 120, currency: 'EUR' },
});
const decision = await agent.authorizeAction(txn);

switch (decision.decision) {
  case 'allow':
    console.log('refunding order 4411');
    break;
  case 'approval_required':
    console.log(`a person must approve first (approval ${decision.approvalId ?? 'unknown'})`);
    break;
  case 'deny':
    console.log('refused:', decision.reason);
    break;
}
