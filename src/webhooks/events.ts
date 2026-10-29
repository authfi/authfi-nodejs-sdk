/**
 * The event names a webhook subscription can receive, as the platform delivers them in
 * `X-AuthFI-Event` and in the signed body's `event`. Source: the public event vocabulary of the
 * webhook dispatcher (`webhookdispatch` in `authfi-regional-comms`); an event outside it is never
 * delivered.
 */
export const WEBHOOK_EVENTS = [
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
] as const;

/** One of the names in {@link WEBHOOK_EVENTS}. */
export type WebhookEventName = (typeof WEBHOOK_EVENTS)[number];
