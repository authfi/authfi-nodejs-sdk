import { ConfigurationError, GatewayTokenRefused, TransportError } from '../core/errors.js';
import { isValidRequestId, isValidRunId, newRunId, requestId as newRequestId } from '../core/ids.js';
import { apiErrorOf, dataOf } from '../core/oauth.js';
import type { DPoPSigner } from '../core/dpop.js';
import type { Core } from '../core/project.js';
import { Secret } from '../core/secret.js';
import { learnNonce, requireAllowedOrigin, type TokenSource } from '../core/token-source.js';
import { contextOf } from '../core/transport.js';
import { SDK_VERSION } from '../core/version.js';
import { recordDecision, type DecisionNames } from './decision-span.js';

/**
 * The tool argument that carries an AuthFI approval id on a retried call. Only an adapter adds it,
 * from the id it read; one a model writes is stripped.
 */
export const APPROVAL_ARGUMENT = '_authfi_approval_id';

/** Where the gateway puts a refusal's codes beside the text the model reads. */
const REFUSAL_META = 'io.authfi/refusal';
/** Where `tools/list` names the grant object (`mcp:<upstream>.<tool>`) of each tool. */
const SCOPE_META = 'io.authfi/scope';
/** The calling agent's advisory outlook for a tool: in `_meta` (kept by every MCP client) and, for older gateways, in `annotations`. */
const GOVERNANCE_KEY = 'io.authfi/governance';
/**
 * The gateway's hold, as prose until it answers a structured one, read by this one pattern in every
 * AuthFI SDK (Python exports the same string). It matches the gateway's exact message, which
 * `test/support/hold-result.json` holds verbatim: "Waiting for approval <id> (<code>). A person must
 * approve this action in the AuthFI console. …". Both sentences are required, so a tool whose output
 * quotes only the first is not a hold.
 */
export const HOLD_PATTERN =
  '^Waiting for approval ([A-Za-z0-9_-]+) \\(([a-z_]+)\\)\\. A person must approve this action';
const HOLD = new RegExp(HOLD_PATTERN);

/** What a model is told about a held call: the wait, never an instruction or an id. */
export const HOLD_MESSAGE = "This action is waiting for a person's approval in AuthFI.";

/**
 * What a call a mandate refused means, and what the agent can still do. A mandate is one level deep and
 * nothing raises trust, so no advice here starts a new mandate or asks for a wider one: the way out of a
 * refusal is a different step inside the mandate, or stopping and telling the person.
 */
export const MANDATE_GUIDANCE: Readonly<Record<string, { why: string; nextStep: string }>> = Object.freeze({
  EMDT003: {
    why: 'mandate_ended',
    nextStep: 'The mandate has run out of time. Stop, and tell the person what is done and what is not.',
  },
  EMDT004: {
    why: 'mandate_ended',
    nextStep: 'The mandate has ended. Stop, and tell the person what is done and what is not.',
  },
  EMDT005: {
    why: 'outside_mandate',
    nextStep:
      'This tool is outside the mandate you were given. Use a tool the mandate allows, or stop and tell the person what you could not do.',
  },
  EMDT006: {
    why: 'over_budget',
    nextStep: "This would go over the mandate's budget. Do less, or stop and tell the person.",
  },
  EMDT007: {
    why: 'outside_mandate',
    nextStep:
      'A rule of the mandate does not allow these arguments. Change them to fit the mandate, or stop and tell the person.',
  },
  EMDT009: {
    why: 'cannot_meter',
    nextStep:
      "The mandate cannot count this call's cost. Give the amount the tool needs, or choose another step.",
  },
  EMDT010: {
    why: 'bad_arguments',
    nextStep: 'The arguments are not what the tool accepts. Correct them and call again.',
  },
  EMDT012: {
    why: 'in_progress',
    nextStep:
      'An earlier attempt of this call is still running. Do not repeat it: wait, then look at its result.',
  },
  EMDT013: {
    why: 'cannot_meter',
    nextStep: "This call spends from the mandate's budget and needs an Idempotency-Key.",
  },
  EMDT014: {
    why: 'cannot_meter',
    nextStep: 'The mandate cannot price this model call before it runs. Ask for something smaller.',
  },
});

/** The refusal as data an agent can plan around: `refused`, `why`, `code`, `reason`, `nextStep`. */
export function refusalData(outcome: {
  readonly code: string | undefined;
  readonly error: string | undefined;
  readonly reason: string;
  readonly requiredScope: string | undefined;
  readonly why: string;
  readonly nextStep: string | undefined;
}): Record<string, unknown> {
  return {
    refused: true,
    why: outcome.why,
    code: outcome.code ?? outcome.error,
    ...(outcome.reason === '' ? {} : { reason: outcome.reason }),
    ...(outcome.requiredScope === undefined ? {} : { required_scope: outcome.requiredScope }),
    ...(outcome.nextStep === undefined ? {} : { next_step: outcome.nextStep }),
  };
}

function modelTextOf(o: {
  readonly code: string | undefined;
  readonly error: string | undefined;
  readonly reason: string;
  readonly requiredScope: string | undefined;
  readonly nextStep: string | undefined;
}): string {
  let text = `Refused by AuthFI (${o.code ?? o.error ?? 'refused'})${o.reason === '' ? '' : `: ${o.reason}`}.`;
  if (o.requiredScope !== undefined) text += ` The call needs the scope ${o.requiredScope}.`;
  if (o.nextStep !== undefined) text += ` ${o.nextStep}`;
  return text;
}

/** An MCP `tools/call` result, as the gateway answers it. */
export interface ToolResult {
  readonly content?: readonly unknown[];
  readonly isError?: boolean;
  readonly _meta?: Readonly<Record<string, unknown>>;
  readonly [key: string]: unknown;
}

/**
 * What AuthFI decided about one tool call, read from its result. A refusal and a hold are values,
 * not exceptions, because the framework hands them to the model as the tool's answer.
 *
 * - `allowed`: the tool ran; `result` is its answer (its own `isError`, if any, is the tool's).
 * - `refused`: AuthFI refused it; the model reads `result`, code reads the fields.
 * - `approval_required`: a person must approve it first. Never give this result's text to a model.
 */
export type ToolOutcome =
  | { readonly kind: 'allowed'; readonly result: ToolResult }
  | {
      readonly kind: 'refused';
      readonly result: ToolResult;
      readonly reason: string;
      readonly code: string | undefined;
      readonly error: string | undefined;
      readonly requiredScope: string | undefined;
      /** Why in one word: `outside_mandate`, `over_budget`, `mandate_ended`, ... or `refused`. */
      readonly why: string;
      /** What the agent can still do, for a call a mandate refused; undefined for any other refusal. */
      readonly nextStep: string | undefined;
      /** What a model may read about this refusal (the same text, whatever the framework). */
      readonly modelText: string;
    }
  | { readonly kind: 'approval_required'; readonly approvalId: string; readonly code: string };

/** The response header on which the gateway returns the run it derived from the token. */
const RUN_HEADER = 'AuthFI-Run-Id';

/** The cloud credential door, under the model routes. */
const CLOUD_PATH = '/mcp/v1/cloud/credentials';

/** The longest credential the platform issues, in seconds. */
const MAX_CLOUD_SECONDS = 900;

/**
 * What a model, and so a tool result, is told of a cloud credential: it names the credential and carries no
 * secret. The runtime fetches the secret itself, once, with {@link CloudAccess.secret}.
 */
export interface CloudHandle {
  readonly credentialId: string;
  readonly account: string;
  readonly role: string;
  readonly expiresAt: Date | undefined;
  readonly scope: string | undefined;
}

/** A short-lived cloud credential, fetched by its handle. The secret parts are {@link Secret}s. */
export interface CloudCredential {
  readonly provider: string;
  readonly credentialId: string;
  readonly expiresAt: Date | undefined;
  readonly accessKeyId: string | undefined;
  readonly secretAccessKey: Secret | undefined;
  readonly sessionToken: Secret | undefined;
  readonly accessToken: Secret | undefined;
}

/** The gateway's answer to a cloud credential request: a handle, or an approval to wait for. */
export type CloudCredentialOutcome =
  | { readonly kind: 'issued'; readonly handle: CloudHandle }
  | { readonly kind: 'approval_required'; readonly approvalId: string };

function textOf(result: ToolResult): string {
  return (result.content ?? [])
    .map((p) =>
      typeof p === 'object' && p !== null && (p as { type?: unknown }).type === 'text'
        ? (p as { text?: unknown }).text
        : undefined,
    )
    .filter((t): t is string => typeof t === 'string')
    .join('\n');
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * The project's gateways for one credential: the MCP gateway (`<issuer>/mcp`) and the AI gateway's
 * model routes. Made by `agent.gateway()` or `delegatedToken.gateway()`.
 */
export class Gateway {
  #cloud: CloudAccess | undefined;
  /** The MCP gateway endpoint, `<issuer>/mcp`. */
  readonly mcpUrl: string;
  /** The agent the credential belongs to (its own, or the actor of a delegated token). */
  readonly agentId: string | undefined;
  /**
   * What the credential is: `agent` (an agent key) or `client_credentials` (a machine client's
   * id and secret). Sent in the User-Agent, which the gateway records as the caller's name for
   * itself, so the console can tell the two apart.
   */
  readonly kind: 'agent' | 'client_credentials';
  /** This run's id (see {@link Gateway.forRun}): the prefix of each call's `X-Request-Id`. Undefined on a gateway not bound to a run. */
  readonly runId: string | undefined;
  /** The OTLP/HTTP trace endpoint of the project, `<issuer origin>/otlp/v1/traces`. */
  readonly otlpTracesUrl: string;
  #serverRunId: string | undefined;
  #calls = 0;
  readonly #core: Core;
  readonly #source: TokenSource;
  readonly #origins: () => Promise<readonly string[]>;

  /** Use `agent.gateway()` or `delegatedToken.gateway()`. */
  constructor(
    core: Core,
    source: TokenSource,
    agentId: string | undefined,
    options: { kind?: 'agent' | 'client_credentials'; runId?: string | undefined } = {},
  ) {
    if (options.runId !== undefined && !isValidRunId(options.runId))
      throw new ConfigurationError('runId must be 1-96 of A-Z a-z 0-9 . _ : - (it prefixes X-Request-Id)');
    this.#core = core;
    this.#source = source;
    this.agentId = agentId;
    this.kind = options.kind ?? 'agent';
    this.runId = options.runId;
    this.mcpUrl = `${core.issuer}/mcp`;
    this.otlpTracesUrl = `${new URL(core.issuer).origin}/otlp/v1/traces`;
    this.#origins = () => core.ownOrigins();
  }

  /**
   * A gateway for one run of the same credential: each call's `X-Request-Id` is `<runId>.<n>`, so
   * the run's calls join in the gateway's records and the spans of the run carry the same id.
   * Without `runId` a fresh one is made.
   */
  forRun(runId: string = newRunId()): Gateway {
    return new Gateway(this.#core, this.#source, this.agentId, { kind: this.kind, runId });
  }

  /**
   * The run the gateway derived from the token and returned in `AuthFI-Run-Id` on its last answer,
   * or undefined before any answer. The gateway decides this id; a caller cannot choose it.
   */
  get serverRunId(): string | undefined {
    return this.#serverRunId;
  }

  /**
   * The base URL to give a model provider's SDK: `<issuer>/mcp` for the Anthropic SDKs (they add
   * `/v1/messages`), `<issuer>/mcp/v1` for OpenAI-compatible clients.
   */
  modelBaseUrl(api: 'anthropic' | 'openai'): string {
    return api === 'anthropic' ? this.mcpUrl : `${this.mcpUrl}/v1`;
  }

  /** The grant object of a tool from `tools/list` (`mcp:<upstream>.<tool>`), or undefined without AuthFI's `_meta`. */
  scopeOf(tool: { readonly _meta?: Readonly<Record<string, unknown>> | undefined }): string | undefined {
    return str(tool._meta?.[SCOPE_META]);
  }

  /**
   * The calling agent's advisory outlook for a tool from `tools/list`: `no_policy_restriction`,
   * `may_require_approval` or `never_allowed`; undefined when the gateway has no opinion. Read from
   * `_meta` first, because a client that drops unknown annotation keys (Python `mcp` 2.x) still keeps
   * it; the annotation is the fallback for older gateways. Advisory only: the gateway decides each call.
   */
  governanceOf(tool: {
    readonly _meta?: Readonly<Record<string, unknown>> | undefined;
    readonly annotations?: Readonly<Record<string, unknown>> | undefined;
  }): string | undefined {
    return str(tool._meta?.[GOVERNANCE_KEY]) ?? str(tool.annotations?.[GOVERNANCE_KEY]);
  }

  /**
   * Whether the model may be offered the tool: false when {@link Gateway.governanceOf} says
   * `never_allowed`. Advisory only: a tool shown is still decided per call, and a call to a hidden
   * tool is refused by the gateway.
   */
  offerable(tool: {
    readonly _meta?: Readonly<Record<string, unknown>> | undefined;
    readonly annotations?: Readonly<Record<string, unknown>> | undefined;
  }): boolean {
    return this.governanceOf(tool) !== 'never_allowed';
  }

  /**
   * What AuthFI decided about a tool call, from its result (see {@link ToolOutcome}). The decision is also
   * recorded as a child span of the active OpenTelemetry span, when the project was given the API.
   */
  readResult(result: unknown, names: DecisionNames = {}): ToolOutcome {
    const outcome = this.#read(result);
    recordDecision(this.#core.otel, outcome, names);
    return outcome;
  }

  #read(result: unknown): ToolOutcome {
    if (typeof result !== 'object' || result === null) {
      throw new TransportError('response_invalid', 'a tool result is not an object', { retryable: false });
    }
    const r = result as ToolResult;
    if (r.isError !== true) return { kind: 'allowed', result: r };
    const meta = r._meta?.[REFUSAL_META];
    if (typeof meta === 'object' && meta !== null) {
      const m = meta as Record<string, unknown>;
      const code = str(m.code);
      const guidance = code === undefined ? undefined : MANDATE_GUIDANCE[code];
      const refusal = {
        reason: str(m.reason) ?? textOf(r),
        code,
        error: str(m.error),
        requiredScope: str(m.required_scope),
        nextStep: guidance?.nextStep,
      };
      return {
        kind: 'refused',
        result: r,
        ...refusal,
        why: guidance?.why ?? 'refused',
        modelText: modelTextOf(refusal),
      };
    }
    const hold = HOLD.exec(textOf(r));
    if (hold?.[1] !== undefined && hold[2] !== undefined)
      return { kind: 'approval_required', approvalId: hold[1], code: hold[2] };
    return { kind: 'allowed', result: r };
  }

  /**
   * A `fetch` for the gateways: the credential on each request (a key-bound one with a proof made for the
   * request, answering the server's nonce once), `X-Request-Id` and `traceparent`, no redirects, and only
   * to AuthFI's origins. A 401 from the gateway refuses the token itself and throws
   * {@link GatewayTokenRefused}, which ends the run: retrying cannot help.
   */
  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    requireAllowedOrigin(request.url, await this.#origins());
    const bound = this.#source.dpop;
    // A key-bound token is answered once more when the server asks for its nonce.
    const again = bound === undefined ? undefined : request.clone();
    let sent = await this.#send(request);
    const key = this.#source.dpop;
    if (key !== undefined && again !== undefined && (await learnNonce(key, request.url, sent.res))) {
      sent = await this.#send(again);
    }
    const { res, headers } = sent;
    const answeredRun = res.headers.get(RUN_HEADER);
    if (answeredRun !== null && answeredRun !== '') this.#serverRunId = answeredRun;
    if (res.status === 401) {
      await res.body?.cancel();
      throw new GatewayTokenRefused(
        'the gateway refused the token: it is missing, expired, revoked or for another audience',
        {
          status: 401,
          requestId: res.headers.get('x-request-id') ?? headers.get('x-request-id') ?? undefined,
        },
      );
    }
    return res;
  };

  async #send(request: Request): Promise<{ res: Response; headers: Headers }> {
    const headers = new Headers(request.headers);
    for (const [k, v] of Object.entries(await this.#source.headers(request.method, request.url)))
      headers.set(k, v);
    const given = headers.get('x-request-id');
    if (given === null || !isValidRequestId(given))
      headers.set(
        'x-request-id',
        this.runId === undefined ? newRequestId() : `${this.runId}.${String(++this.#calls)}`,
      );
    if (!headers.has('user-agent'))
      headers.set('user-agent', `authfi-node/${SDK_VERSION} (${this.kind.replace('_', '-')})`);
    for (const [k, v] of Object.entries(this.#core.transport.traceHeaders()))
      if (!headers.has(k)) headers.set(k, v);
    headers.delete('x-api-key');
    const res = await this.#core.fetch(new Request(request, { headers, redirect: 'error' }));
    return { res, headers };
  }

  /** Cloud credentials: a handle from the gateway, and its secret fetched once by the runtime. */
  get cloud(): CloudAccess {
    this.#cloud ??= new CloudAccess(this);
    return this.#cloud;
  }

  /** The credential and the key it is bound to, for a request this class sends through the transport. */
  async #authed(url: string): Promise<{
    headers: Record<string, string>;
    dpop: { signer: DPoPSigner; accessToken: Secret } | undefined;
  }> {
    requireAllowedOrigin(url, this.#source.sendTo);
    const token = new Secret(await this.#source.token());
    const signer = this.#source.dpop;
    return {
      headers: { authorization: `${signer === undefined ? 'Bearer' : 'DPoP'} ${token.reveal()}` },
      dpop: signer === undefined ? undefined : { signer, accessToken: token },
    };
  }

  /**
   * Fetches a cloud credential's secret, once (`POST /mcp/v1/cloud/credentials/{credential_id}/secret`).
   * Only the instance the handle was issued to can do it, proven by the token's key: a handle read by
   * anyone else is no use. A second fetch is refused (`ECLOUDCRED014`), and so is one after the credential
   * expired. This is for the runtime that calls the cloud, never for a tool result a model reads.
   */
  async cloudSecret(
    credentialId: string,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<CloudCredential> {
    if (typeof credentialId !== 'string' || credentialId.trim() === '')
      throw new ConfigurationError('credentialId is required: the handle the gateway issued');
    const url = `${await this.#core.apiOrigin(options.signal)}${CLOUD_PATH}/${encodeURIComponent(credentialId)}/secret`;
    const { headers, dpop } = await this.#authed(url);
    const res = await this.#core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal: options.signal,
      headers: { ...headers, 'content-type': 'application/json' },
      body: '{}',
      ...(dpop === undefined ? {} : { dpop }),
    });
    if (res.status === 401) throw new GatewayTokenRefused('the gateway refused the token', contextOf(res));
    if (res.status !== 200) throw apiErrorOf(res);
    const c = dataOf(res) as Record<string, unknown> | null;
    if (typeof c?.provider !== 'string')
      throw new TransportError('response_invalid', `${url} answered no credential`, {
        ...contextOf(res),
        retryable: false,
      });
    const expiration = str(c.expiration);
    const expiresIn = typeof c.expires_in === 'number' && c.expires_in > 0 ? c.expires_in : undefined;
    const secret = (v: unknown): Secret | undefined =>
      str(v) === undefined ? undefined : new Secret(v as string);
    return {
      provider: c.provider,
      credentialId: str(c.credential_id) ?? credentialId,
      expiresAt:
        expiration !== undefined
          ? new Date(expiration)
          : expiresIn !== undefined
            ? new Date(this.#core.clock.now() + expiresIn * 1000)
            : undefined,
      accessKeyId: str(c.access_key_id),
      secretAccessKey: secret(c.secret_access_key),
      sessionToken: secret(c.session_token),
      accessToken: secret(c.access_token),
    };
  }

  /**
   * Asks the gateway for a short-lived cloud credential for a role (`POST /mcp/v1/cloud/credentials`). The
   * answer is a handle (`credentialId`, `account`, `role`, `expiresAt`, `scope`), never the secret: fetch
   * that with {@link Gateway.cloudSecret}. A role that needs a person's approval answers
   * `approval_required` with an approval id; call again with `approvalId` once they decided. A refusal is
   * an `APIError` with the gateway's code.
   */
  async cloudCredentials(request: {
    account: string;
    role: string;
    expiresInSeconds?: number | undefined;
    sessionPolicy?: Readonly<Record<string, unknown>> | undefined;
    approvalId?: string | undefined;
    signal?: AbortSignal | undefined;
  }): Promise<CloudCredentialOutcome> {
    if (!request.account || !request.role) throw new ConfigurationError('account and role are required');
    const seconds = request.expiresInSeconds;
    if (seconds !== undefined && (!Number.isInteger(seconds) || seconds < 1 || seconds > MAX_CLOUD_SECONDS)) {
      throw new ConfigurationError(
        `expiresInSeconds must be a whole number of seconds from 1 to ${MAX_CLOUD_SECONDS}, the platform's limit`,
      );
    }
    const url = `${await this.#core.apiOrigin(request.signal)}${CLOUD_PATH}`;
    const { headers, dpop } = await this.#authed(url);
    const res = await this.#core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal: request.signal,
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({
        account: request.account,
        role: request.role,
        duration_seconds: request.expiresInSeconds ?? 900,
        session_policy: request.sessionPolicy,
        approval_id: request.approvalId,
      }),
      ...(dpop === undefined ? {} : { dpop }),
    });
    if (res.status === 401) throw new GatewayTokenRefused('the gateway refused the token', contextOf(res));
    if (res.status === 202) {
      const data = dataOf(res) as { approval_id?: unknown } | null;
      const approvalId = str(data?.approval_id);
      if (approvalId === undefined)
        throw new TransportError('response_invalid', `${url} answered 202 with no approval id`, {
          ...contextOf(res),
          retryable: false,
        });
      return { kind: 'approval_required', approvalId };
    }
    if (res.status !== 201) {
      if (res.status >= 200 && res.status < 300) {
        throw new TransportError(
          'response_invalid',
          `${url} answered ${res.status}; only 201 or 202 mean a credential was issued`,
          {
            ...contextOf(res),
            retryable: false,
          },
        );
      }
      throw apiErrorOf(res);
    }
    const c = dataOf(res) as Record<string, unknown> | null;
    const credentialId = str(c?.credential_id);
    if (c === null || credentialId === undefined)
      throw new TransportError('response_invalid', `${url} answered no credential handle`, {
        ...contextOf(res),
        retryable: false,
      });
    const expiresAt = str(c.expires_at);
    return {
      kind: 'issued',
      handle: {
        credentialId,
        account: str(c.account) ?? request.account,
        role: str(c.role) ?? request.role,
        expiresAt:
          expiresAt === undefined || Number.isNaN(Date.parse(expiresAt)) ? undefined : new Date(expiresAt),
        scope: str(c.scope),
      },
    };
  }

  /** The endpoint and agent only. */
  toString(): string {
    return `Gateway(${this.mcpUrl}${this.agentId === undefined ? '' : ` as ${this.agentId}`})`;
  }
}

/**
 * Cloud credentials through the gateway, by handle. `credentials` returns a handle (what a tool result
 * may carry); `secret` fetches the secret once, for the runtime that calls the cloud; `fetchCredential` does
 * both. Made by `gateway.cloud`, `agent.cloud` and `mandate.cloud`.
 */
export class CloudAccess {
  readonly #gateway: Gateway;

  constructor(gateway: Gateway) {
    this.#gateway = gateway;
  }

  /** See {@link Gateway.cloudCredentials}. */
  credentials(request: Parameters<Gateway['cloudCredentials']>[0]): Promise<CloudCredentialOutcome> {
    return this.#gateway.cloudCredentials(request);
  }

  /** See {@link Gateway.cloudSecret}. */
  secret(
    handle: CloudHandle | string,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<CloudCredential> {
    return this.#gateway.cloudSecret(typeof handle === 'string' ? handle : handle.credentialId, options);
  }

  /**
   * A handle and its secret in one step, for code that calls the cloud itself. A role held for a person's
   * approval answers `approval_required`, as {@link CloudAccess.credentials} does.
   */
  async fetchCredential(
    request: Parameters<Gateway['cloudCredentials']>[0],
  ): Promise<
    | { readonly kind: 'issued'; readonly handle: CloudHandle; readonly credential: CloudCredential }
    | { readonly kind: 'approval_required'; readonly approvalId: string }
  > {
    const outcome = await this.credentials(request);
    if (outcome.kind !== 'issued') return outcome;
    return {
      kind: 'issued',
      handle: outcome.handle,
      credential: await this.secret(outcome.handle, { signal: request.signal }),
    };
  }
}
