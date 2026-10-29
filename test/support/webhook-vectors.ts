// Runs the webhook conformance vectors (conformance/webhooks.json) through the verifier, in whichever
// runtime the test file runs in.

import { expect, it } from 'vitest';
import doc from '../../conformance/webhooks.json' with { type: 'json' };
import { isAuthFIError } from '../../src/core/errors.js';
import { Secret } from '../../src/core/secret.js';
import { verifyWebhook } from '../../src/webhooks/verify.js';
import { WEBHOOK_EVENTS } from '../../src/webhooks/events.js';
import { TestClock } from './issuer.js';

interface Case {
  name: string;
  body: string;
  headers: Record<string, string>;
  expect: string;
  type?: string;
  resource_id?: string;
}

export function runWebhookVectors(): void {
  const clock = new TestClock();
  clock.wall = doc.now * 1000;
  const secret = new Secret(doc.secret);

  for (const c of doc.cases as Case[]) {
    it(c.name, async () => {
      const run = verifyWebhook({
        body: c.body,
        headers: c.headers,
        secret,
        toleranceSeconds: doc.tolerance_seconds,
        clock,
      });
      if (c.expect === 'ok') {
        const event = await run;
        expect(event.type).toBe(c.type);
        expect(event.data.resourceId).toBe(c.resource_id);
        expect(event.deliveryId).toBe('del_1');
        return;
      }
      const err = await run.then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(isAuthFIError(err, 'InvalidWebhook')).toBe(true);
      expect((err as { code: string }).code).toBe(c.expect);
    });
  }

  it('lists the same events as the vectors', () => {
    expect([...WEBHOOK_EVENTS]).toEqual(doc.events);
  });
}
