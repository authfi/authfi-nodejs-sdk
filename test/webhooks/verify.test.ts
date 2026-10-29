import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ConfigurationError, isAuthFIError } from '../../src/core/errors.js';
import { Secret } from '../../src/core/secret.js';
import { verifyWebhook } from '../../src/webhooks/verify.js';
import { TestClock } from '../support/issuer.js';
import { runWebhookVectors } from '../support/webhook-vectors.js';

const SECRET = 'whsec_unit';
const clock = new TestClock();
const NOW = Math.floor(clock.now() / 1000);
const BODY = JSON.stringify({
  id: 'req_9',
  event: 'login.failed',
  timestamp: '2026-10-20T11:59:59Z',
  data: { actor: 'user:u1' },
});

// An independent oracle: Node's createHmac, not the SubtleCrypto path the verifier uses.
function signed(body: string | Uint8Array, ts = NOW, secret = SECRET): Record<string, string> {
  const mac = createHmac('sha256', secret).update(`${String(ts)}.`).update(body).digest('hex');
  return { 'x-authfi-timestamp': String(ts), 'x-authfi-signature-256': `sha256=${mac}` };
}

const refusal = async (p: Promise<unknown>): Promise<string> => {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(isAuthFIError(e, 'InvalidWebhook')).toBe(true);
  return (e as { code: string }).code;
};

const base = { secret: new Secret(SECRET), clock };

describe('conformance vectors', () => {
  runWebhookVectors();
});

describe('verifyWebhook', () => {
  it('accepts what an independent HMAC signs, from a header record, Headers or bytes', async () => {
    const headers = signed(BODY);
    const a = await verifyWebhook({ ...base, body: BODY, headers });
    const b = await verifyWebhook({ ...base, body: BODY, headers: new Headers(headers) });
    const c = await verifyWebhook({ ...base, body: new TextEncoder().encode(BODY), headers });
    expect(a).toEqual(b);
    expect(a).toEqual(c);
    expect(a).toMatchObject({ id: 'req_9', type: 'login.failed', data: { actor: 'user:u1' } });
    expect(a.deliveryId).toBeUndefined();
  });

  it('reads Node-style headers case-insensitively, including a single-element array', async () => {
    const h = signed(BODY);
    const event = await verifyWebhook({
      ...base,
      body: BODY,
      headers: {
        'X-AuthFI-Timestamp': [h['x-authfi-timestamp']!],
        'X-AuthFI-Signature-256': h['x-authfi-signature-256'],
        'X-AuthFI-Delivery': 'd-7',
      },
    });
    expect(event.deliveryId).toBe('d-7');
  });

  it('refuses a header sent twice, in an array or under two spellings', async () => {
    const h = signed(BODY);
    expect(
      await refusal(
        verifyWebhook({
          ...base,
          body: BODY,
          headers: { ...h, 'x-authfi-signature-256': [h['x-authfi-signature-256']!, h['x-authfi-signature-256']!] },
        }),
      ),
    ).toBe('webhook_signature_malformed');
    expect(
      await refusal(
        verifyWebhook({
          ...base,
          body: BODY,
          headers: { ...h, 'X-AuthFI-Signature-256': h['x-authfi-signature-256'] },
        }),
      ),
    ).toBe('webhook_signature_malformed');
  });

  it('refuses a body that was parsed and re-serialised', async () => {
    const pretty = JSON.stringify(JSON.parse(BODY), null, 2);
    expect(await refusal(verifyWebhook({ ...base, body: pretty, headers: signed(BODY) }))).toBe(
      'webhook_signature_invalid',
    );
  });

  it('checks the signature before freshness, so a stranger learns nothing about the window', async () => {
    const stale = signed(BODY, NOW - 10_000, 'someone-else');
    expect(await refusal(verifyWebhook({ ...base, body: BODY, headers: stale }))).toBe('webhook_signature_invalid');
  });

  it('honours a tighter tolerance', async () => {
    const headers = signed(BODY, NOW - 31);
    expect(await refusal(verifyWebhook({ ...base, body: BODY, headers, toleranceSeconds: 30 }))).toBe(
      'webhook_timestamp_outside_tolerance',
    );
    expect((await verifyWebhook({ ...base, body: BODY, headers, toleranceSeconds: 60 })).type).toBe('login.failed');
  });

  it('refuses an empty signature header', async () => {
    const h = { ...signed(BODY), 'x-authfi-signature-256': '' };
    expect(await refusal(verifyWebhook({ ...base, body: BODY, headers: h }))).toBe('webhook_signature_missing');
  });

  it('refuses a signed body that is not UTF-8', async () => {
    const bytes = new Uint8Array([0x7b, 0xff, 0x7d]);
    expect(await refusal(verifyWebhook({ ...base, body: bytes, headers: signed(bytes) }))).toBe(
      'webhook_body_invalid',
    );
  });

  it('refuses a data member that is not an object, and a missing id', async () => {
    for (const bad of [
      { id: 'x', event: 'user.created', timestamp: 't', data: [] },
      { id: 'x', event: 'user.created', timestamp: 't', data: null },
      { event: 'user.created', timestamp: 't', data: {} },
    ]) {
      const body = JSON.stringify(bad);
      expect(await refusal(verifyWebhook({ ...base, body, headers: signed(body) }))).toBe('webhook_body_invalid');
    }
  });

  it('keeps an event name it does not know, and ignores data members of the wrong type', async () => {
    const body = JSON.stringify({ id: '', event: 'thing.happened', timestamp: 't', data: { actor: 5, subject: 's' } });
    const event = await verifyWebhook({ ...base, body, headers: signed(body) });
    expect(event.type).toBe('thing.happened');
    expect(event.data).toEqual({ actor: undefined, subject: 's', resourceType: undefined, resourceId: undefined });
  });

  it('misuse is a ConfigurationError, not a webhook refusal', async () => {
    const headers = signed(BODY);
    await expect(verifyWebhook({ ...base, body: BODY, headers, secret: SECRET as unknown as Secret })).rejects.toThrow(
      ConfigurationError,
    );
    await expect(verifyWebhook({ ...base, body: BODY, headers, toleranceSeconds: 0 })).rejects.toThrow(
      ConfigurationError,
    );
    await expect(
      verifyWebhook({ ...base, body: JSON.parse(BODY) as unknown as string, headers }),
    ).rejects.toThrow(/raw request body/);
  });

  it('works with the system clock when none is given', async () => {
    const now = Math.floor(Date.now() / 1000);
    const event = await verifyWebhook({ secret: new Secret(SECRET), body: BODY, headers: signed(BODY, now) });
    expect(event.type).toBe('login.failed');
  });
});
