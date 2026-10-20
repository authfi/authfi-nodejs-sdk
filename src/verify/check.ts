import { TransportError } from '../core/errors.js';
import { apiErrorOf, dataOf } from '../core/oauth.js';
import type { Core } from '../core/project.js';
import { Secret } from '../core/secret.js';
import type { TokenSource } from '../core/token-source.js';
import { contextOf } from '../core/transport.js';

/** A question for the project's decision point: may `subject` have `relation` on `object`? */
export interface CheckRequest {
  /** The principal asking, typed: `user:<id>`, `app:<client id>`, `agent:<agent id>`. */
  readonly subject: string;
  /** The permission or relationship, such as `orders:refund` or `editor`. */
  readonly relation: string;
  /** The resource, such as `order:4411`. */
  readonly object: string;
  /** Attributes the project's policies read, such as `{ amount: 12000 }`. */
  readonly context?: Readonly<Record<string, unknown>> | undefined;
  readonly signal?: AbortSignal | undefined;
}

/** The decision. `approvalRequired` means allowed in principle once a person approves; not allowed yet. */
export interface CheckResult {
  readonly allowed: boolean;
  readonly approvalRequired: boolean;
  readonly reason: string | undefined;
}

/**
 * Asks the project's decision point (`POST /apis/regional/v1/check`) a per-object question, for a
 * fresh answer, or for a delegated token that carries no permissions. Any project access token may
 * call it: a {@link TokenSource}, or a token you hold wrapped in a {@link Secret}.
 */
export async function checkAccess(
  core: Core,
  credential: TokenSource | Secret,
  req: CheckRequest,
): Promise<CheckResult> {
  const url = `${await core.apiOrigin(req.signal)}/apis/regional/v1/check`;
  const auth =
    credential instanceof Secret
      ? { authorization: `Bearer ${credential.reveal()}` }
      : await credential.headers('POST', url);
  const res = await core.transport.send({
    method: 'POST',
    url,
    retry: 'safe',
    signal: req.signal,
    headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({
      subject: req.subject,
      relation: req.relation,
      object: req.object,
      context: req.context,
    }),
  });
  if (res.status !== 200) throw apiErrorOf(res);
  const data = dataOf(res) as { allowed?: unknown; requires_approval?: unknown; reason?: unknown } | null;
  if (typeof data?.allowed !== 'boolean') {
    throw new TransportError('response_invalid', `${url} answered no decision`, {
      ...contextOf(res),
      retryable: false,
    });
  }
  return {
    allowed: data.allowed,
    approvalRequired: data.requires_approval === true,
    reason: typeof data.reason === 'string' && data.reason !== '' ? data.reason : undefined,
  };
}
