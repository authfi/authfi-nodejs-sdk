import { NotSupportedError } from '../core/errors.js';

const NO_ASSERTION =
  'An instance signs in by attestation, which does not yet cover asking a person (CIBA), opening an ' +
  'approval or starting a mandate. Use token exchange for a person who signed in to your app, or sign in ' +
  'with an agent key for this call.';

/** The refusal of a call that needs the agent's key, for an instance that has none. */
export function noAssertion(): NotSupportedError {
  return new NotSupportedError('instance_assertion', NO_ASSERTION);
}
