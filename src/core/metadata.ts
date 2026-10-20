import { maxAgeOf, type Loaded } from './cache.js';
import { DiscoveryError } from './errors.js';
import { contextOf, jsonOf, MAX_DOCUMENT_BYTES, type Transport } from './transport.js';

/**
 * The issuer's authorization-server metadata (RFC 8414 / OpenID Connect Discovery), with the wire
 * names. Only `issuer`, `token_endpoint` and `jwks_uri` are guaranteed; read the rest as optional.
 */
export interface ServerMetadata {
  readonly issuer: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly authorization_endpoint?: string;
  readonly userinfo_endpoint?: string;
  readonly revocation_endpoint?: string;
  readonly introspection_endpoint?: string;
  readonly end_session_endpoint?: string;
  readonly backchannel_authentication_endpoint?: string;
  readonly grant_types_supported?: readonly string[];
  readonly response_types_supported?: readonly string[];
  readonly token_endpoint_auth_methods_supported?: readonly string[];
  readonly token_endpoint_auth_signing_alg_values_supported?: readonly string[];
  readonly id_token_signing_alg_values_supported?: readonly string[];
  readonly code_challenge_methods_supported?: readonly string[];
  readonly scopes_supported?: readonly string[];
  readonly acr_values_supported?: readonly string[];
  readonly [field: string]: unknown;
}

const PATHS = ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'] as const;
const REQUIRED = ['token_endpoint', 'jwks_uri'] as const;

function stringList(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every((v) => typeof v === 'string'));
}

/** Checks a fetched document against the issuer it was fetched for and the fields the SDK needs. */
export function checkMetadata(doc: unknown, issuer: string, url: string): ServerMetadata {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new DiscoveryError('discovery_failed', `${url} did not answer a JSON object`);
  }
  const record = doc as Record<string, unknown>;
  if (record.issuer !== issuer) {
    throw new DiscoveryError(
      'issuer_mismatch',
      `${url} names the issuer ${JSON.stringify(record.issuer)}, not ${issuer}; its keys and endpoints would be another issuer's`,
    );
  }
  for (const field of REQUIRED) {
    if (typeof record[field] !== 'string' || record[field] === '') {
      throw new DiscoveryError('discovery_failed', `${url} has no ${field}`);
    }
  }
  for (const [k, v] of Object.entries(record)) {
    if (k.endsWith('_supported') && typeof v !== 'boolean' && !stringList(v)) {
      throw new DiscoveryError('discovery_failed', `${url} has a ${k} that is not a list of strings`);
    }
  }
  return Object.freeze({ ...record }) as ServerMetadata;
}

/**
 * Fetches the issuer's metadata: the OpenID document, falling back to the RFC 8414 one (the platform
 * serves the same bytes at both).
 */
export async function loadMetadata(transport: Transport, issuer: string): Promise<Loaded<ServerMetadata>> {
  let last: DiscoveryError | undefined;
  for (const path of PATHS) {
    const url = issuer + path;
    const res = await transport.send({ method: 'GET', url, retry: 'safe', maxBytes: MAX_DOCUMENT_BYTES });
    if (res.status === 404) {
      last = new DiscoveryError('discovery_failed', `${url} answered 404`, contextOf(res));
      continue;
    }
    if (res.status !== 200) {
      throw new DiscoveryError(
        'discovery_failed',
        `${url} answered HTTP ${String(res.status)}`,
        contextOf(res),
      );
    }
    return {
      value: checkMetadata(jsonOf(res), issuer, url),
      maxAgeMs: maxAgeOf(res.headers.get('cache-control')),
    };
  }
  throw last ?? new DiscoveryError('discovery_failed', `no discovery document at ${issuer}`);
}
