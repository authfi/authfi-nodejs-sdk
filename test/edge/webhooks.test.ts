// The webhook vectors in the edge runtime: the HMAC is checked with Web Crypto only.
import { describe } from 'vitest';
import { runWebhookVectors } from '../support/webhook-vectors.js';

describe('the webhook vectors in the edge runtime', () => {
  runWebhookVectors();
});
