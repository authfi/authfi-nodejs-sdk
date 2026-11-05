import { NotSupportedError } from '../core/errors.js';
import { contextOf, jsonOf, type HttpResponse } from '../core/transport.js';

const OBSERVE_ONLY =
  'This instance was admitted only to be observed (AUTHFI_CONFIG_OBSERVE): the platform does not let it ask a person ' +
  'or open an approval. Ask a person to approve a configuration version for the agent, then set ' +
  'AUTHFI_CONFIG_VERSION and AUTHFI_CONFIG_DIGEST and drop AUTHFI_CONFIG_OBSERVE.';

const CODE = 'observe_only_instance';

/** The string members `error`, `code` and `authfi_error` of the answer's body. */
function codesOf(res: HttpResponse): string[] {
  let body: unknown;
  try {
    body = jsonOf(res);
  } catch {
    return [];
  }
  if (typeof body !== 'object' || body === null) return [];
  const fields = body as Record<string, unknown>;
  return ['error', 'code', 'authfi_error'].flatMap((k) => (typeof fields[k] === 'string' ? [fields[k]] : []));
}

/**
 * The readable refusal of an instance that was admitted only to be observed, or undefined when the answer is
 * not that. The platform answers such an instance 403 `observe_only_instance` (our API) or 403
 * `unauthorized_client` (the OAuth endpoints); no other 403 is read this way, and an agent-key credential never
 * reaches it.
 */
export function observeOnlyRefusal(res: HttpResponse): NotSupportedError | undefined {
  if (res.status !== 403) return undefined;
  const codes = codesOf(res);
  if (!codes.includes(CODE) && !codes.includes('unauthorized_client')) return undefined;
  return new NotSupportedError(CODE, OBSERVE_ONLY, contextOf(res));
}
