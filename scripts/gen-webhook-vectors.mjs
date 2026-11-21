#!/usr/bin/env node
// Generates conformance/webhooks.json: signed webhook deliveries and the outcome every AuthFI SDK must
// produce for each. Everything is fixed (ids, clock, test secrets), so the output is deterministic.
//
//   node scripts/gen-webhook-vectors.mjs           writes the file
//   node scripts/gen-webhook-vectors.mjs --check   fails if the file differs from what this would write
//
// Signature: "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)), the body exactly as sent.

import { createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const FILE = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'conformance', 'webhooks.json');

const SECRET = 'whsec_conformance_secret_1';
const OTHER_SECRET = 'whsec_other';
const NOW = 1_792_497_600;
const TOLERANCE = 300;

// Event ids are UUIDv7 values, the form the platform dispatcher sends in `id`; request ids are the
// separate, optional `request_id` of the request that caused the event.
const ID = (n) => `0192f3a0-0000-7000-8000-${String(n).padStart(12, '0')}`;
const REQ = 'req_01';

const sign = (secret, timestamp, body) =>
  `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex')}`;

// The platform marshals a Go map, so the real body has its keys in alphabetical order; the vectors do too.
function event({ id, requestId, type = 'user.created', subject = 'u2' }) {
  const body = {
    data: {
      actor: 'user:u1',
      resource_id: subject,
      resource_type: 'user',
      subject: `user:${subject}`,
    },
    event: type,
    id,
  };
  if (requestId !== undefined) body.request_id = requestId;
  body.timestamp = '2026-10-20T11:59:58Z';
  return JSON.stringify(body);
}

const BASE = event({ id: ID(1), requestId: REQ });

// A delivery signed with `secret` over `signedBody` at `signedAt`, sent with `timestamp` and `delivery`.
function delivery({
  body = BASE,
  signedBody = body,
  timestamp = String(NOW),
  signedAt = timestamp,
  secret = SECRET,
  delivery: deliveryId = 'del_1',
}) {
  return {
    body,
    headers: {
      'X-AuthFI-Timestamp': timestamp,
      'X-AuthFI-Signature-256': sign(secret, signedAt, signedBody),
      'X-AuthFI-Delivery': deliveryId,
      'X-AuthFI-Event': 'user.created',
    },
  };
}

const ok = (name, d, extra) => ({
  name,
  ...d,
  expect: 'ok',
  type: 'user.created',
  id: ID(1),
  request_id: REQ,
  resource_id: 'u2',
  delivery_id: d.headers['X-AuthFI-Delivery'],
  ...extra,
});
const refused = (name, d, code) => ({ name, ...d, expect: code });
const without = (d, ...names) => {
  const headers = { ...d.headers };
  for (const n of names) delete headers[n];
  return { ...d, headers };
};
const withSignature = (d, signature) => ({
  ...d,
  headers: { ...d.headers, 'X-AuthFI-Signature-256': signature },
});

const roleBody =
  '{"data":{"resource_id":"r1","resource_type":"role","subject":"user:ü-é"},' +
  `"event":"role.assigned","id":"${ID(2)}","request_id":"${REQ}","timestamp":"2026-10-20T11:59:58Z"}`;

const good = delivery({});
const cases = [
  ok('fresh delivery', delivery({ timestamp: String(NOW - 2) })),
  ok('non-ASCII body', delivery({ body: roleBody }), {
    type: 'role.assigned',
    id: ID(2),
    resource_id: 'r1',
  }),
  ok('edge of the window', delivery({ timestamp: String(NOW - TOLERANCE) })),
  refused(
    'one second past the window',
    delivery({ timestamp: String(NOW - TOLERANCE - 1) }),
    'webhook_timestamp_outside_tolerance',
  ),
  refused(
    'a timestamp from the future',
    delivery({ timestamp: String(NOW + TOLERANCE + 1) }),
    'webhook_timestamp_outside_tolerance',
  ),
  refused(
    'body altered after signing',
    delivery({ body: event({ id: ID(1), requestId: REQ, subject: 'u3' }), signedBody: BASE }),
    'webhook_signature_invalid',
  ),
  refused('signed with another secret', delivery({ secret: OTHER_SECRET }), 'webhook_signature_invalid'),
  refused(
    'timestamp altered after signing',
    delivery({ signedAt: String(NOW - 1) }),
    'webhook_signature_invalid',
  ),
  refused(
    'signature header missing',
    without(good, 'X-AuthFI-Signature-256', 'X-AuthFI-Delivery', 'X-AuthFI-Event'),
    'webhook_signature_missing',
  ),
  refused(
    'signature without the sha256= prefix',
    withSignature(good, good.headers['X-AuthFI-Signature-256'].slice('sha256='.length)),
    'webhook_signature_malformed',
  ),
  refused('signature of the wrong length', withSignature(good, 'sha256=abcd'), 'webhook_signature_malformed'),
  refused(
    'timestamp header missing',
    without(good, 'X-AuthFI-Timestamp', 'X-AuthFI-Delivery', 'X-AuthFI-Event'),
    'webhook_timestamp_invalid',
  ),
  refused(
    'timestamp not a whole number',
    without(delivery({ timestamp: '12.5' }), 'X-AuthFI-Delivery', 'X-AuthFI-Event'),
    'webhook_timestamp_invalid',
  ),
  refused('signed body is not JSON', delivery({ body: 'not json' }), 'webhook_body_invalid'),
  refused('signed body is not an event', delivery({ body: '{"hello":"world"}' }), 'webhook_body_invalid'),
  // The old shape, where the request id stood in for the event id: a verifier must not fall back to it.
  refused(
    'signed body has a request id but no event id',
    delivery({
      body: '{"data":{},"event":"user.created","request_id":"req_01","timestamp":"2026-10-20T11:59:58Z"}',
    }),
    'webhook_body_invalid',
  ),
  // One request that caused two events: same request_id, different event ids (comms#124).
  ok(
    'bulk request, first event',
    delivery({ body: event({ id: ID(3), requestId: 'req_bulk_01', subject: 'u4' }) }),
    { id: ID(3), request_id: 'req_bulk_01', resource_id: 'u4' },
  ),
  ok(
    'bulk request, second event',
    delivery({
      body: event({ id: ID(4), requestId: 'req_bulk_01', subject: 'u5' }),
      delivery: 'del_2',
    }),
    { id: ID(4), request_id: 'req_bulk_01', resource_id: 'u5' },
  ),
  // The same event delivered again: same id, a new delivery id.
  ok('replay of an event', delivery({ delivery: 'del_3' })),
  // request_id is optional; an event without one has no requestId.
  ok('event without a request id', delivery({ body: event({ id: ID(5) }), delivery: 'del_4' }), {
    id: ID(5),
    request_id: null,
  }),
];

const doc = {
  description:
    'AuthFI webhook conformance vectors, generated by scripts/gen-webhook-vectors.mjs: verify each delivery with `secret` at `now` (seconds) and `tolerance_seconds`. The signature is hex(HMAC-SHA256(secret, timestamp + "." + body)) as `sha256=<hex>` in X-AuthFI-Signature-256, as the platform\'s webhook dispatcher signs it. `expect` is `ok` or the refusal code. On ok cases `id` is the event id (UUIDv7, the same on every delivery of the event), `request_id` is the optional id of the request that caused it (null when the body has none; several events can share one) and `delivery_id` is X-AuthFI-Delivery. Headers are case-insensitive.',
  secret: SECRET,
  now: NOW,
  tolerance_seconds: TOLERANCE,
  events: [
    'user.created',
    'user.updated',
    'user.deleted',
    'user.blocked',
    'user.mfa_enrolled',
    'group.member_added',
    'group.member_removed',
    'organization.created',
    'role.assigned',
    'session.revoked',
    'login.success',
    'login.failed',
  ],
  cases,
};

const text = `${JSON.stringify(doc, null, 2)}\n`;

if (process.argv.includes('--check')) {
  if (readFileSync(FILE, 'utf8') !== text) {
    process.stderr.write(
      'gen-webhook-vectors: conformance/webhooks.json is out of date; run the generator\n',
    );
    process.exit(1);
  }
  process.stdout.write('gen-webhook-vectors: ok\n');
} else {
  writeFileSync(FILE, text);
  process.stdout.write(`gen-webhook-vectors: wrote ${cases.length} cases\n`);
}
