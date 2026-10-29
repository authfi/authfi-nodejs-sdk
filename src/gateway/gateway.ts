import { ConfigurationError, GatewayTokenRefused, TransportError } from '../core/errors.js';
import { isValidRequestId, isValidRunId, newRunId, requestId as newRequestId } from '../core/ids.js';
import { apiErrorOf, dataOf } from '../core/oauth.js';
import type { Core } from '../core/project.js';
import { Secret } from '../core/secret.js';
import { requireAllowedOrigin, type TokenSource } from '../core/token-source.js';
import { contextOf } from '../core/transport.js';
import { SDK_VERSION } from '../core/version.js';

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
    }
  | { readonly kind: 'approval_required'; readonly approvalId: string; readonly code: string };

/** The response header on which the gateway returns the run it derived from the token. */
const RUN_HEADER = 'AuthFI-Run-Id';

/** The longest credential the platform issues, in seconds. */
const MAX_CLOUD_SECONDS = 900;

/** A short-lived cloud credential the gateway issued. The secret parts are {@link Secret}s. */
export interface CloudCredential {
  readonly provider: string;
  readonly credentialId: string;
  readonly expiresAt: Date | undefined;
  readonly accessKeyId: string | undefined;
  readonly secretAccessKey: Secret | undefined;
  readonly sessionToken: Secret | undefined;
  readonly accessToken: Secret | undefined;
}

/** The gateway's answer to a cloud credential request. */
export type CloudCredentialOutcome =
  | { readonly kind: 'issued'; readonly credential: CloudCredential }
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

  /** What AuthFI decided about a tool call, from its result (see {@link ToolOutcome}). */
  readResult(result: unknown): ToolOutcome {
    if (typeof result !== 'object' || result === null) {
      throw new TransportError('response_invalid', 'a tool result is not an object', { retryable: false });
    }
    const r = result as ToolResult;
    if (r.isError !== true) return { kind: 'allowed', result: r };
    const meta = r._meta?.[REFUSAL_META];
    if (typeof meta === 'object' && meta !== null) {
      const m = meta as Record<string, unknown>;
      return {
        kind: 'refused',
        result: r,
        reason: str(m.reason) ?? textOf(r),
        code: str(m.code),
        error: str(m.error),
        requiredScope: str(m.required_scope),
      };
    }
    const hold = HOLD.exec(textOf(r));
    if (hold?.[1] !== undefined && hold[2] !== undefined)
      return { kind: 'approval_required', approvalId: hold[1], code: hold[2] };
    return { kind: 'allowed', result: r };
  }

  /**
   * A `fetch` for the gateways: the credential on each request, `X-Request-Id` and `traceparent`,
   * no redirects, and only to AuthFI's origins. A 401 from the gateway refuses the token itself and
   * throws {@link GatewayTokenRefused}, which ends the run: retrying cannot help.
   */
  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    requireAllowedOrigin(request.url, await this.#origins());
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

  /**
   * Asks the gateway for a short-lived cloud credential for a role (`POST /mcp/v1/cloud/credentials`).
   * A role that needs a person's approval answers `approval_required` with an approval id; call
   * again with `approvalId` once they decided. A refusal is an `APIError` with the gateway's code.
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
    const url = `${await this.#core.apiOrigin(request.signal)}/mcp/v1/cloud/credentials`;
    const res = await this.#core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal: request.signal,
      prepare: async () => ({
        headers: { ...(await this.#source.headers('POST', url)), 'content-type': 'application/json' },
        body: JSON.stringify({
          account: request.account,
          role: request.role,
          duration_seconds: request.expiresInSeconds ?? 900,
          session_policy: request.sessionPolicy,
          approval_id: request.approvalId,
        }),
      }),
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
      kind: 'issued',
      credential: {
        provider: c.provider,
        credentialId: str(c.credential_id) ?? '',
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
      },
    };
  }

  /** The endpoint and agent only. */
  toString(): string {
    return `Gateway(${this.mcpUrl}${this.agentId === undefined ? '' : ` as ${this.agentId}`})`;
  }
}
