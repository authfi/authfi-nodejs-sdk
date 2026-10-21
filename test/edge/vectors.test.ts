// The conformance vectors in the edge runtime: EdDSA, ES256 and RS256 verified with Web Crypto only.
import { describe } from 'vitest';
import { runVectors } from '../support/vectors.js';

describe('the conformance vectors in the edge runtime', () => {
  runVectors();
});
