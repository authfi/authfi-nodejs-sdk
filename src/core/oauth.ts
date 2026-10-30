import { base64, utf8 } from './bytes.js';
import {
  APIError,
  OAuthError,
  StepUpRequired,
  TemporarilyUnavailable,
  TransportError,
  type ErrorContext,
} from './errors.js';
import type { DPoPSigner } from './dpop.js';
import { Secret } from './secret.js';
import { contextOf, jsonOf, type HttpResponse, type RetryClass, type Transport } from './transport.js';

/** The grant type URIs the platform serves at its token endpoint. */
export const GRANT = {
  authorizationCode: 'authorization_code',
  refreshToken: 'refresh_token',
  clientCredentials: 'client_credentials',
  ciba: 'urn:openid:params:grant-type:ciba',
  tokenExchange: 'urn:ietf:params:oauth:grant-type:token-exchange',
} as const;

/** One of the {@link GRANT} values. */
export type GrantType = (typeof GRANT)[keyof typeof GRANT];

/** The RFC 8693 token type of an access token. */
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * How a client authenticates at the token endpoint.
 *
 * - `none`: a public client (an app with PKCE and no secret); sends `client_id` only.
 * - `client_secret_basic` (preferred) and `client_secret_post`: a confidential client's secret.
 * - `assertion`: a client that signs an RFC 7523 assertion per attempt (the agent's key). The
 *   platform accepts it from agents only.
 */
export type ClientAuth =
  | { readonly method: 'none'; readonly clientId: string }
  | {
      readonly method: 'client_secret_basic' | 'client_secret_post';
      readonly clientId: string;
      readonly clientSecret: Secret;
    }
  | {
      readonly method: 'private_key_jwt';
      readonly clientId: string;
      /** Signs a fresh assertion for the token endpoint `audience`; called once per attempt. */
      readonly assertion: (audience: string) => Promise<Secret>;
    };

const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, '+');
}

/**
 * Adds the client's authentication to a form and headers, for one attempt. `audience` is the token
 * endpoint, which an assertion names.
 */
export async function applyClientAuth(
  auth: ClientAuth,
  form: URLSearchParams,
  headers: Record<string, string>,
  audience: string,
): Promise<void> {
  switch (auth.method) {
    case 'none':
      form.set('client_id', auth.clientId);
      return;
    case 'client_secret_basic': {
      // RFC 6749 §2.3.1: each part form-urlencoded before the Basic encoding.
      const pair = `${formEncode(auth.clientId)}:${formEncode(auth.clientSecret.reveal())}`;
      headers.authorization = `Basic ${base64(utf8(pair))}`;
      return;
    }
    case 'client_secret_post':
      form.set('client_id', auth.clientId);
      form.set('client_secret', auth.clientSecret.reveal());
      return;
    case 'private_key_jwt':
      form.set('client_id', auth.clientId);
      form.set('client_assertion_type', CLIENT_ASSERTION_TYPE);
      form.set('client_assertion', (await auth.assertion(audience)).reveal());
      return;
  }
}

/** A successful token response. The tokens are {@link Secret}s. */
export interface TokenResponse {
  readonly accessToken: Secret;
  readonly tokenType: string;
  /** When the access token expires, in epoch milliseconds. */
  readonly expiresAt: number;
  readonly refreshToken: Secret | undefined;
  readonly idToken: Secret | undefined;
  readonly scope: readonly string[];
  readonly issuedTokenType: string | undefined;
  /** The fields the SDK does not model (for example an agent token's `capabilities`), read-only. */
  readonly extra: Readonly<Record<string, unknown>>;
  readonly requestId: string;
}

/** Splits a space-delimited scope string. */
export function scopeList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && v !== '');
  return typeof value === 'string' ? value.split(' ').filter((s) => s !== '') : [];
}

/** The `{ error, error_description }` fields of an answer, when it has them. */
function envelope(body: unknown): { error: string; description: string | undefined } | undefined {
  if (typeof body !== 'object' || body === null) return undefined;
  const { error, error_description: description } = body as Record<string, unknown>;
  if (typeof error !== 'string' || error === '') return undefined;
  return { error, description: typeof description === 'string' ? description : undefined };
}

function parseOrUndefined(res: HttpResponse): unknown {
  try {
    return jsonOf(res);
  } catch {
    return undefined;
  }
}

/**
 * The typed error for an OAuth endpoint's refusal (RFC 6749 §5.2). `insufficient_user_authentication`
 * becomes {@link StepUpRequired} (its `acr` is never parsed out of the description), and 503 or
 * `temporarily_unavailable` becomes {@link TemporarilyUnavailable}.
 */
export function oauthErrorOf(res: HttpResponse, extra: ErrorContext = {}): OAuthError | APIError {
  const body = parseOrUndefined(res);
  const env = envelope(body);
  const context = { ...contextOf(res), ...extra };
  if (env === undefined) {
    return new APIError(
      res.status >= 500 ? 'server_error' : 'response_invalid',
      `the endpoint answered HTTP ${String(res.status)} with no OAuth error`,
      context,
    );
  }
  if (env.error === 'insufficient_user_authentication') return new StepUpRequired(env.description, context);
  if (env.error === 'temporarily_unavailable' || res.status === 503) {
    return new TemporarilyUnavailable(env.error, env.description, context);
  }
  return new OAuthError(env.error, env.description, context);
}

/**
 * The typed error for a refusal from our API (`{"error": code, "error_description"}`). A body with
 * no envelope still becomes an {@link APIError}, coded by the HTTP status.
 */
export function apiErrorOf(res: HttpResponse): APIError {
  const env = envelope(parseOrUndefined(res));
  const code = env?.error ?? (res.status >= 500 ? 'server_error' : `http_${String(res.status)}`);
  return new APIError(code, env?.description, contextOf(res));
}

/** The `data` member of our API's success envelope (`{"data": …}`). */
export function dataOf(res: HttpResponse): unknown {
  const body = jsonOf(res);
  if (typeof body !== 'object' || body === null || !('data' in body)) {
    throw new TransportError('response_invalid', `${res.url} answered without a data envelope`, {
      ...contextOf(res),
      retryable: false,
    });
  }
  return body.data;
}

/** Parses a token endpoint's success answer. */
export function parseTokenResponse(res: HttpResponse, nowMs: number): TokenResponse {
  const body = jsonOf(res);
  if (typeof body !== 'object' || body === null) {
    throw new TransportError(
      'response_invalid',
      `${res.url} answered a token response that is not an object`,
      {
        ...contextOf(res),
        retryable: false,
      },
    );
  }
  const r = body as Record<string, unknown>;
  const {
    access_token,
    token_type,
    expires_in,
    refresh_token,
    id_token,
    scope,
    issued_token_type,
    ...extra
  } = r;
  if (typeof access_token !== 'string' || access_token === '') {
    throw new TransportError('response_invalid', `${res.url} answered no access_token`, {
      ...contextOf(res),
      retryable: false,
    });
  }
  const lifetime =
    typeof expires_in === 'number' && expires_in > 0 ? expires_in : expiresInOf(access_token, nowMs);
  return {
    accessToken: new Secret(access_token),
    tokenType: typeof token_type === 'string' ? token_type : 'Bearer',
    expiresAt: nowMs + lifetime * 1000,
    refreshToken:
      typeof refresh_token === 'string' && refresh_token !== '' ? new Secret(refresh_token) : undefined,
    idToken: typeof id_token === 'string' && id_token !== '' ? new Secret(id_token) : undefined,
    scope: scopeList(scope),
    issuedTokenType: typeof issued_token_type === 'string' ? issued_token_type : undefined,
    extra: Object.freeze({ ...extra }),
    requestId: res.requestId,
  };
}

/** Seconds until a JWT's `exp`, read without verifying (the client's own token), or 0. */
function expiresInOf(jwt: string, nowMs: number): number {
  try {
    const payload = JSON.parse(atob((jwt.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/'))) as {
      exp?: unknown;
    };
    return typeof payload.exp === 'number' ? Math.max(0, payload.exp - Math.floor(nowMs / 1000)) : 0;
  } catch {
    return 0;
  }
}

/** One request to the token endpoint. */
export interface TokenRequest {
  readonly tokenEndpoint: string;
  readonly params: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** The client's authentication; omitted for a grant that authenticates by its own tokens (token exchange). */
  readonly auth?: ClientAuth | undefined;
  readonly retry: RetryClass;
  readonly signal?: AbortSignal | undefined;
  readonly requestId?: string | undefined;
  /** Asks for a token bound to this key: a proof goes with every attempt, and the server's nonce is answered once. */
  readonly dpop?: DPoPSigner | undefined;
  /** Headers and form fields added to every attempt (a fresh actor assertion, the client attestation), made each time. */
  readonly attempt?:
    (() => Promise<{ headers?: Record<string, string>; params?: Record<string, string> }>) | undefined;
}

/**
 * Posts a token request and returns the parsed answer, or throws the typed OAuth error. The form and
 * any client assertion are built per attempt.
 */
export async function requestToken(
  transport: Transport,
  req: TokenRequest,
  nowMs: () => number,
): Promise<TokenResponse> {
  const res = await sendTokenRequest(transport, req);
  if (res.status !== 200) throw oauthErrorOf(res);
  return parseTokenResponse(res, nowMs());
}

/** Posts a token request and returns the raw answer, for a caller that reads a refusal's body itself. */
export async function sendTokenRequest(transport: Transport, req: TokenRequest): Promise<HttpResponse> {
  return transport.send({
    method: 'POST',
    url: req.tokenEndpoint,
    retry: req.retry,
    signal: req.signal,
    requestId: req.requestId,
    ...(req.dpop === undefined ? {} : { dpop: { signer: req.dpop } }),
    prepare: async () => {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(req.params)) {
        if (v === undefined) continue;
        if (typeof v === 'string') {
          if (v !== '') form.set(k, v);
        } else {
          for (const item of v) form.append(k, item);
        }
      }
      const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
      if (req.auth !== undefined) await applyClientAuth(req.auth, form, headers, req.tokenEndpoint);
      if (req.attempt !== undefined) {
        const extra = await req.attempt();
        Object.assign(headers, extra.headers);
        for (const [k, v] of Object.entries(extra.params ?? {})) form.set(k, v);
      }
      return { headers, body: form.toString() };
    },
  });
}
