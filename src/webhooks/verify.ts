import { utf8 } from '../core/bytes.js';
import { systemClock, type Clock } from '../core/clock.js';
import { ConfigurationError, InvalidWebhook } from '../core/errors.js';
import { isSecret, type Secret } from '../core/secret.js';
import type { WebhookEventName } from './events.js';

/** The header carrying `sha256=` and the hex HMAC of `<timestamp>.<body>`. */
export const SIGNATURE_HEADER = 'x-authfi-signature-256';
/** The header carrying the delivery time, in whole seconds since the epoch. */
export const TIMESTAMP_HEADER = 'x-authfi-timestamp';
/** The header carrying the delivery id. It is not signed. */
export const DELIVERY_HEADER = 'x-authfi-delivery';

/** How far a delivery's timestamp may be from now, in seconds, when none is given. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** The request headers of a delivery: a `Headers`, or the record Node's `http` and Express hand you. */
export type WebhookHeaders = Headers | Readonly<Record<string, string | readonly string[] | undefined>>;

/** What {@link verifyWebhook} checks a delivery against. */
export interface VerifyWebhookOptions {
  /** The raw request body, exactly as received: parsed and re-serialised JSON no longer matches the signature. */
  readonly body: string | Uint8Array;
  readonly headers: WebhookHeaders;
  /** The subscription's signing secret, returned once when the subscription was created. */
  readonly secret: Secret;
  /** How far the timestamp may be from now, in seconds, in either direction. Default 300. */
  readonly toleranceSeconds?: number | undefined;
  /** Tests inject one. */
  readonly clock?: Clock | undefined;
}

/** The facts an event carries. Each is present only when the platform sent it. */
export interface WebhookEventData {
  /** Who did it, such as `user:<id>`. */
  readonly actor?: string | undefined;
  /** Who or what it was done to. */
  readonly subject?: string | undefined;
  readonly resourceType?: string | undefined;
  readonly resourceId?: string | undefined;
}

/** A delivery whose signature and freshness were proven. */
export interface WebhookEvent {
  /** The id of the request that caused the event. Several events can share one; it is not unique per delivery. */
  readonly id: string;
  /**
   * The event name from the signed body. It is a {@link WebhookEventName} today; the platform can add
   * names without an SDK release, so a `switch` needs a `default` arm.
   */
  readonly type: WebhookEventName | (string & {});
  /** When the platform built the event (RFC 3339). */
  readonly timestamp: string;
  readonly data: WebhookEventData;
  /**
   * The `X-AuthFI-Delivery` header: one id per delivery, for de-duplicating. It is NOT covered by the
   * signature; use it to drop repeats, never to decide what to trust.
   */
  readonly deliveryId: string | undefined;
}

const SIGNATURE = /^sha256=([0-9a-fA-F]{64})$/;
const TIMESTAMP = /^[0-9]{1,15}$/;

function repeated(name: string): InvalidWebhook {
  return new InvalidWebhook('webhook_signature_malformed', `the ${name} header is repeated`);
}

function headerOf(headers: WebhookHeaders, name: string): string | undefined {
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name) ?? undefined;
  let found: string | readonly string[] | undefined;
  let seen = false;
  for (const [key, value] of Object.entries(
    headers as Record<string, string | readonly string[] | undefined>,
  )) {
    if (key.toLowerCase() !== name) continue;
    if (seen) throw repeated(name);
    seen = true;
    found = value;
  }
  if (found === undefined || typeof found === 'string') return found;
  if (found.length > 1) throw repeated(name);
  return found[0];
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function parseEvent(text: string, deliveryId: string | undefined): WebhookEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new InvalidWebhook('webhook_body_invalid', 'the signed body is not JSON');
  }
  const body = parsed as Record<string, unknown> | null;
  if (
    typeof body !== 'object' ||
    body === null ||
    typeof body.event !== 'string' ||
    body.event === '' ||
    typeof body.id !== 'string' ||
    typeof body.timestamp !== 'string' ||
    typeof body.data !== 'object' ||
    body.data === null ||
    Array.isArray(body.data)
  ) {
    throw new InvalidWebhook('webhook_body_invalid', 'the signed body is not an AuthFI event');
  }
  const data = body.data as Record<string, unknown>;
  const field = (key: string): string | undefined => {
    const value = data[key];
    return typeof value === 'string' ? value : undefined;
  };
  return {
    id: body.id,
    type: body.event,
    timestamp: body.timestamp,
    data: {
      actor: field('actor'),
      subject: field('subject'),
      resourceType: field('resource_type'),
      resourceId: field('resource_id'),
    },
    deliveryId,
  };
}

/**
 * Proves a webhook delivery came from AuthFI and is fresh, and returns the event. The platform signs
 * `hex(HMAC-SHA256(secret, "<X-AuthFI-Timestamp>.<body>"))` into `X-AuthFI-Signature-256` as
 * `sha256=<hex>`. The comparison is constant-time; the signature is checked before the timestamp, so
 * a caller without the secret learns nothing from the freshness answer. Throws {@link InvalidWebhook}
 * for anything it cannot trust: answer 400 and do not act.
 *
 * @example
 * app.post('/hooks/authfi', express.raw({ type: 'application/json' }), async (req, res) => {
 *   try {
 *     const event = await verifyWebhook({ body: req.body, headers: req.headers, secret });
 *     if (event.type === 'user.deleted') await removeAccount(event.data.resourceId);
 *     res.sendStatus(204);
 *   } catch (e) {
 *     if (isAuthFIError(e, 'InvalidWebhook')) return res.sendStatus(400);
 *     throw e;
 *   }
 * });
 */
export async function verifyWebhook(options: VerifyWebhookOptions): Promise<WebhookEvent> {
  const { body, headers, secret } = options;
  if (!isSecret(secret)) {
    throw new ConfigurationError('secret must be a Secret: new Secret(process.env.AUTHFI_WEBHOOK_SECRET)');
  }
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (!Number.isFinite(tolerance) || tolerance <= 0) {
    throw new ConfigurationError('toleranceSeconds must be a positive number of seconds');
  }
  if (typeof body !== 'string' && !(body instanceof Uint8Array)) {
    throw new ConfigurationError(
      'body must be the raw request body (a string or bytes): a parsed object no longer matches the signature',
    );
  }

  const signature = headerOf(headers, SIGNATURE_HEADER);
  if (signature === undefined || signature === '') {
    throw new InvalidWebhook('webhook_signature_missing', `the ${SIGNATURE_HEADER} header is missing`);
  }
  const match = SIGNATURE.exec(signature);
  if (match?.[1] === undefined) {
    throw new InvalidWebhook(
      'webhook_signature_malformed',
      `the ${SIGNATURE_HEADER} header is not sha256=<hex>`,
    );
  }
  const timestamp = headerOf(headers, TIMESTAMP_HEADER);
  if (timestamp === undefined || !TIMESTAMP.test(timestamp)) {
    throw new InvalidWebhook(
      'webhook_timestamp_invalid',
      `the ${TIMESTAMP_HEADER} header is missing or not a whole number of seconds`,
    );
  }

  const bytes = typeof body === 'string' ? utf8(body) : body;
  const prefix = utf8(`${timestamp}.`);
  const signed = new Uint8Array(prefix.length + bytes.length);
  signed.set(prefix, 0);
  signed.set(bytes, prefix.length);
  const key = await crypto.subtle.importKey(
    'raw',
    utf8(secret.reveal()),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  // SubtleCrypto compares the MAC in constant time.
  const valid = await crypto.subtle.verify('HMAC', key, fromHex(match[1]), signed);
  if (!valid) throw new InvalidWebhook('webhook_signature_invalid', 'the signature does not match the body');

  const nowSeconds = (options.clock ?? systemClock).now() / 1000;
  if (Math.abs(nowSeconds - Number(timestamp)) > tolerance) {
    throw new InvalidWebhook(
      'webhook_timestamp_outside_tolerance',
      `the delivery is more than ${String(tolerance)} seconds from now: a replay, or a clock out of step`,
    );
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new InvalidWebhook('webhook_body_invalid', 'the signed body is not UTF-8');
  }
  return parseEvent(text, headerOf(headers, DELIVERY_HEADER));
}
