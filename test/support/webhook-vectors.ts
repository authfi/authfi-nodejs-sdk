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
  id?: string;
  request_id?: string | null;
  delivery_id?: string;
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
        expect(event.id).toBe(c.id);
        expect(event.requestId).toBe(c.request_id ?? undefined);
        expect(event.deliveryId).toBe(c.delivery_id);
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

  it('keeps the event id apart from the request id', () => {
    const ok = (doc.cases as Case[]).filter((c) => c.expect === 'ok');
    for (const c of ok) {
      expect(c.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(c.id).not.toBe(c.request_id);
    }
    const bulk = ok.filter((c) => c.request_id === 'req_bulk_01');
    expect(bulk).toHaveLength(2);
    expect(bulk[0]?.id).not.toBe(bulk[1]?.id);
    // A replay is the same event again: the same event id, a new delivery id.
    const first = ok.find((c) => c.name === 'fresh delivery');
    const replay = ok.find((c) => c.name === 'replay of an event');
    expect(first).toBeDefined();
    expect(replay?.id).toBe(first?.id);
    expect(replay?.delivery_id).not.toBe(first?.delivery_id);
  });

  it('lists the same events as the vectors', () => {
    expect([...WEBHOOK_EVENTS]).toEqual(doc.events);
  });
}
