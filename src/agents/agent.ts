import { CachedDocument, maxAgeOf, SingleFlight } from '../core/cache.js';
import {
  ConfigurationError,
  ConsentDenied,
  ConsentExpired,
  DiscoveryError,
  NotSupportedError,
  OAuthError,
  TransportError,
  WaitTimeout,
} from '../core/errors.js';
import { isBoundTo, type DPoPSigner } from '../core/dpop.js';
import {
  ACCESS_TOKEN_TYPE,
  apiErrorOf,
  dataOf,
  GRANT,
  oauthErrorOf,
  parseTokenResponse,
  requestToken,
  sendTokenRequest,
  type ClientAuth,
  type TokenResponse,
} from '../core/oauth.js';
import type { ServerMetadata } from '../core/metadata.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { isSecret, Secret } from '../core/secret.js';
import { BaseTokenSource, checkSendTo, type TokenOptions, type TokenSource } from '../core/token-source.js';
import { contextOf, jsonOf, type HttpResponse } from '../core/transport.js';
import { isAtOrUnder, originOf } from '../core/urls.js';
import { decodeUnverified } from '../verify/verifier.js';
import type { Signer } from './agent-key.js';
import { clientAssertion } from './assertion.js';
import { DelegatedToken } from './delegated.js';
import { Gateway, type CloudAccess } from '../gateway/gateway.js';
import { Mandate, MANDATE_DETAIL_TYPE, type MandatePending } from './mandate.js';
import { noAssertion } from './no-assertion.js';
import { refuseNested, runInMandate } from './scope.js';

/**
 * How an instance of the agent signs in instead of presenting a key (see `InstanceAuth`). It returns the
 * token answer of the attested `client_credentials` request, bound to `signer`'s key.
 */
export interface InstanceSignIn {
  mint(request: {
    readonly meta: ServerMetadata;
    readonly resource: string | undefined;
    readonly signer: DPoPSigner;
    readonly signal?: AbortSignal | undefined;
  }): Promise<TokenResponse>;
}

/** How `af.agent()` is configured. */
export interface AgentOptions {
  /** The agent's id, `agt_…`, from the console. */
  readonly agentId: string;
  /** The agent's key: an `AgentKey`, or another {@link Signer} (a KMS, an HSM). */
  readonly key: Signer;
  /**
   * The resource the agent's own token is for, when it is AuthFI's own (the default is the gateway,
   * `<issuer>/mcp`). For a customer API use `agent.forResource(resource, { sendTo })`.
   */
  readonly resource?: string | undefined;
  /** Mint a new token this long before the current one expires (default 60 000 ms). */
  readonly refreshSkewMs?: number | undefined;
  /**
   * Bind the agent's tokens for AuthFI to this process's key (DPoP, RFC 9449), so a stolen token is of no
   * use. On by default; `false` leaves them Bearer, which the gateways refuse for a bound agent.
   */
  readonly dpop?: boolean | undefined;
  /** Signs in by instance attestation in place of a key. Made by `InstanceAuth`, never set by hand. */
  readonly instance?: InstanceSignIn | undefined;
}

/** A poll interval the caller gave: finite and above zero, or a {@link ConfigurationError}. */
function pollIntervalOf(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value <= 0) {
    throw new ConfigurationError('pollIntervalMs must be a finite number of milliseconds above zero');
  }
  return value;
}

/** A CIBA request: the person has been asked and has not yet answered. */
export interface CibaRequest {
  /** The handle to redeem; treat it as a secret. */
  readonly authReqId: Secret;
  /** When the request lapses. */
  readonly expiresAt: Date;
  /** How long to wait between polls, in milliseconds. */
  readonly intervalMs: number;
}

/** A frozen description of one high-risk action (AuthFI's transaction token, not the IETF draft). */
export interface TransactionToken {
  readonly token: Secret;
  /** The transaction id. */
  readonly txn: string;
  readonly expiresAt: Date;
  readonly action: string;
  readonly resource: string | undefined;
  readonly context: Readonly<Record<string, unknown>> | undefined;
}

/** The action gate's decision. `approval_required` means a person must approve first. */
export interface ActionDecision {
  readonly decision: 'allow' | 'deny' | 'approval_required';
  readonly approvalId: string | undefined;
  readonly reason: string | undefined;
}

/** An approval a person decides on one action. No token results from it. */
export interface Approval {
  readonly id: string;
  /** `pending`, `approved`, `denied` or `expired` (open: the platform may add states). */
  readonly status: 'pending' | 'approved' | 'denied' | 'expired' | (string & {});
  readonly action: string;
  readonly context: unknown;
  readonly createdAt: Date | undefined;
  readonly expiresAt: Date | undefined;
  readonly resolvedAt: Date | undefined;
}

interface AgentConfiguration {
  readonly requestApproval: string;
  readonly approval: string;
}

interface CachedToken {
  readonly response: TokenResponse;
  readonly renewAt: number;
  /** The key the token is bound to, or undefined for a Bearer token. */
  readonly bound: DPoPSigner | undefined;
}

interface Minted {
  readonly response: TokenResponse;
  readonly bound: DPoPSigner | undefined;
}

const AGENT_API = '/apis/regional/v1/ai/auth';
const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const MAX_MANDATE_SECONDS = 30 * 24 * 3600;

/** The 400 `authorization_pending` that holds a mandate for a person's approval, or undefined. */
function pendingMandateOf(res: HttpResponse): MandatePending | undefined {
  if (res.status !== 400) return undefined;
  let body: Record<string, unknown> | undefined;
  try {
    body = jsonOf(res) as Record<string, unknown> | undefined;
  } catch {
    return undefined;
  }
  if (body?.error !== 'authorization_pending') return undefined;
  const { auth_req_id: authReqId, authfi_mandate_id: mandateId, interval, approval_url: url } = body;
  if (
    typeof authReqId !== 'string' ||
    authReqId === '' ||
    typeof mandateId !== 'string' ||
    mandateId === ''
  ) {
    throw new OAuthError(
      'invalid_response',
      'the token endpoint held the mandate without a request to wait on',
      contextOf(res),
    );
  }
  return {
    authReqId: new Secret(authReqId),
    mandateId,
    intervalMs: (typeof interval === 'number' && interval > 0 ? interval : 5) * 1000,
    approvalUrl: typeof url === 'string' && url !== '' ? url : undefined,
  };
}
const SLOW_DOWN_MS = 5000;

function date(value: unknown): Date | undefined {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value)) ? new Date(value) : undefined;
}

function approvalOf(data: unknown, url: string): Approval {
  const d = data as Record<string, unknown> | null;
  if (typeof d?.approval_id !== 'string' || typeof d.status !== 'string') {
    throw new TransportError('response_invalid', `${url} answered no approval`, { retryable: false });
  }
  return {
    id: d.approval_id,
    status: d.status,
    action: typeof d.requesting_action === 'string' ? d.requesting_action : '',
    context: d.context,
    createdAt: date(d.created_at),
    expiresAt: date(d.expires_at),
    resolvedAt: date(d.resolved_at),
  };
}

/**
 * An AI agent's identity at one project: a key it holds (RFC 7523), its own token (client
 * credentials), a person's consent without a browser (CIBA), acting for a signed-in person (token
 * exchange), the action gate and approvals. Made by `af.agent()`.
 *
 * It is a {@link TokenSource} for its own token, which goes only to AuthFI (the issuer and the API
 * origin); `forResource` makes one for a customer API. Every endpoint comes from the project's
 * discovery, and the deprecated agent token route is never called.
 *
 * @example
 * const agent = af.agent({ agentId: 'agt_…', key: await readAgentKey('/run/secrets/agent.pem', { kid: 'k1' }) });
 * const res = await agent.fetch(`${af.issuer}/mcp`, { method: 'POST', body });
 */
export class AgentAuth extends BaseTokenSource {
  readonly agentId: string;
  readonly #af: AuthFI;
  readonly #core: Core;
  readonly #signer: Signer;
  readonly #resource: string | undefined;
  readonly #skew: number;
  readonly #tokens = new Map<string, CachedToken>();
  readonly #flight = new SingleFlight<string, Minted>();
  readonly #agentConfig: CachedDocument<AgentConfiguration>;
  readonly #dpop: boolean;
  readonly #instance: InstanceSignIn | undefined;
  #gateway: Gateway | undefined;

  /** Use `af.agent()`. */
  constructor(af: AuthFI, options: AgentOptions) {
    const core = coreOf(af);
    super(core.fetch);
    if (typeof options.agentId !== 'string' || options.agentId.trim() === '')
      throw new ConfigurationError('agentId is required');
    const key = options.key as Partial<Signer> | undefined;
    if (typeof key?.sign !== 'function' || typeof key.kid !== 'string' || typeof key.alg !== 'string') {
      throw new ConfigurationError(
        'key must be an AgentKey (or a Signer): an agent authenticates with a key it holds, never a secret',
      );
    }
    if (options.resource !== undefined && !this.#isOwn(af, options.resource)) {
      throw new ConfigurationError(
        `resource ${options.resource} is not AuthFI's own: use agent.forResource('${options.resource}', { sendTo: [...] }) for a customer API`,
      );
    }
    const skew = options.refreshSkewMs ?? 60_000;
    if (!Number.isFinite(skew) || skew < 0)
      throw new ConfigurationError('refreshSkewMs must be a non-negative number');
    this.agentId = options.agentId.trim();
    this.#af = af;
    this.#core = core;
    this.#signer = options.key;
    this.#resource = options.resource;
    this.#skew = skew;
    this.#dpop = options.dpop !== false;
    this.#instance = options.instance;
    this.#agentConfig = new CachedDocument(() => this.#loadAgentConfiguration(), core.clock);
  }

  #isOwn(af: AuthFI, resource: string): boolean {
    return isAtOrUnder(resource, af.issuer) || isAtOrUnder(resource, af.apiOrigin);
  }

  /** The project this agent belongs to. */
  get project(): AuthFI {
    return this.#af;
  }

  /** AuthFI's own origins: the issuer's and the API origin. */
  get sendTo(): readonly string[] {
    return [...new Set([new URL(this.#af.issuer).origin, this.#af.apiOrigin])];
  }

  protected override async ready(signal?: AbortSignal): Promise<void> {
    await this.#core.metadata({ signal });
  }

  #auth(): ClientAuth {
    return {
      method: 'private_key_jwt',
      clientId: this.agentId,
      assertion: (audience) => clientAssertion(this.#signer, this.agentId, audience, this.#core.clock),
    };
  }

  /**
   * The agent's own access token (client credentials with its key), cached per resource and minted
   * again `refreshSkewMs` before expiry. Concurrent callers share one mint; every attempt signs a
   * fresh assertion.
   */
  async token(options: TokenOptions & { resource?: string | undefined } = {}): Promise<string> {
    return (await this.#tokenFor(options.resource ?? this.#resource, options)).response.accessToken.reveal();
  }

  async #tokenFor(resource: string | undefined, options: TokenOptions = {}): Promise<CachedToken> {
    const key = resource ?? '';
    const now = this.#core.clock.now();
    const cached = this.#tokens.get(key);
    if (options.force !== true && cached !== undefined && now < cached.renewAt) return cached;
    const { response, bound } = await this.#flight.run(key, () => this.#mint(resource), options.signal);
    const entry = { response, bound, renewAt: response.expiresAt - this.#skew };
    this.#tokens.set(key, entry);
    return entry;
  }

  /**
   * The key to bind a token for `resource` to: this process's, when the project accepts its algorithm.
   * Only a token for AuthFI itself is bound. One for a customer's API stays Bearer: that API verifies it,
   * and a verifier built on this SDK takes no proof.
   */
  async #keyFor(meta: ServerMetadata, resource: string | undefined): Promise<DPoPSigner | undefined> {
    if (!this.#dpop || (resource !== undefined && !this.#isOwn(this.#af, resource))) return undefined;
    const algs = meta.dpop_signing_alg_values_supported;
    if (Array.isArray(algs) && algs.length > 0 && !algs.includes('ES256')) {
      this.#core.warnOnce(
        'dpop-alg',
        'the project accepts no proof-of-possession algorithm this SDK signs (ES256): agent tokens stay Bearer',
      );
      return undefined;
    }
    return this.#core.dpop();
  }

  /** The shared mint belongs to no caller, so it takes no caller's signal. */
  async #mint(resource: string | undefined): Promise<Minted> {
    const meta = await this.#core.metadata();
    // An instance's token is bound to its key for any resource: the attestation names the key.
    const signer =
      this.#instance === undefined
        ? await this.#keyFor(meta, resource)
        : this.#dpop
          ? await this.#core.dpop()
          : undefined;
    if (this.#instance !== undefined) {
      if (signer === undefined) {
        throw new ConfigurationError(
          'an instance signs in by attestation, which binds its token to the instance key: dpop cannot be off',
        );
      }
      const response = await this.#instance.mint({ meta, resource, signer });
      return { response, bound: this.#boundBy(response, signer) };
    }
    this.#requireAgentAuth(
      meta.token_endpoint_auth_methods_supported,
      meta.token_endpoint_auth_signing_alg_values_supported,
    );
    const response = await requestToken(
      this.#core.transport,
      {
        tokenEndpoint: meta.token_endpoint,
        params: { grant_type: GRANT.clientCredentials, resource },
        auth: this.#auth(),
        retry: 'safe',
        dpop: signer,
      },
      () => this.#core.clock.now(),
    );
    return { response, bound: this.#boundBy(response, signer) };
  }

  /** The key a token answer is bound to: `signer` when it is, undefined when the platform left it Bearer. */
  #boundBy(response: TokenResponse, signer: DPoPSigner | undefined): DPoPSigner | undefined {
    return signer !== undefined && isBoundTo(response.tokenType, response.accessToken, signer)
      ? signer
      : undefined;
  }

  /** The key the agent's current token for its default resource is bound to, if it is bound. */
  override get dpop(): DPoPSigner | undefined {
    return this.#tokens.get(this.#resource ?? '')?.bound;
  }

  /** The token and the key it is bound to, for a request this class sends itself. */
  async #own(signal?: AbortSignal): Promise<{ token: Secret; signer: DPoPSigner | undefined }> {
    const cached = await this.#tokenFor(this.#resource, { signal });
    return { token: cached.response.accessToken, signer: cached.bound };
  }

  #requireAgentAuth(methods: readonly string[] | undefined, algs: readonly string[] | undefined): void {
    if (methods !== undefined && !methods.includes('private_key_jwt')) {
      throw new NotSupportedError(
        'private_key_jwt',
        'This AuthFI project does not accept key-based authentication',
      );
    }
    if (algs !== undefined && !algs.includes(this.#signer.alg)) {
      throw new NotSupportedError(
        this.#signer.alg,
        `This AuthFI project does not accept ${this.#signer.alg} assertions`,
      );
    }
  }

  async #requireGrant(grant: string, feature: string, signal?: AbortSignal) {
    const meta = await this.#core.metadata({ signal });
    if (meta.grant_types_supported !== undefined && !meta.grant_types_supported.includes(grant)) {
      throw new NotSupportedError(feature, `This AuthFI project does not offer ${feature}`);
    }
    return meta;
  }

  /** The capabilities granted to the agent, as its token answer lists them. */
  async capabilities(
    options: { resource?: string | undefined; signal?: AbortSignal | undefined } = {},
  ): Promise<ReadonlySet<string>> {
    const { response } = await this.#tokenFor(options.resource ?? this.#resource, options);
    const listed = response.extra.capabilities;
    return new Set(
      Array.isArray(listed) ? listed.filter((c): c is string => typeof c === 'string') : response.scope,
    );
  }

  /**
   * A token source for one resource. For a customer API (its client id), `sendTo` names the API's
   * exact origins and the token goes nowhere else; for AuthFI's own resources it may be left out.
   */
  forResource(resource: string, options: { sendTo?: readonly string[] | undefined } = {}): TokenSource {
    if (typeof resource !== 'string' || resource === '') throw new ConfigurationError('resource is required');
    const sendTo = this.#sendToFor(resource, options.sendTo);
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const agent = this;
    return new (class AgentResourceToken extends BaseTokenSource {
      get sendTo(): readonly string[] {
        return sendTo ?? agent.sendTo;
      }
      protected override async ready(signal?: AbortSignal): Promise<void> {
        if (sendTo === undefined) await agent.#core.metadata({ signal });
      }
      override get dpop(): DPoPSigner | undefined {
        return agent.#tokens.get(resource)?.bound;
      }
      token(opts: TokenOptions = {}): Promise<string> {
        return agent.token({ ...opts, resource });
      }
      override toString(): string {
        return `AgentAuth(${agent.agentId} for ${resource})`;
      }
    })(this.#core.fetch);
  }

  #sendToFor(
    resource: string | undefined,
    given: readonly string[] | undefined,
  ): readonly string[] | undefined {
    const own = resource === undefined || this.#isOwn(this.#af, resource);
    const sendTo = given === undefined ? [] : checkSendTo(given);
    if (!own && sendTo.length === 0) {
      throw new ConfigurationError(
        `sendTo is required for ${resource}: the exact https origin(s) of that API`,
      );
    }
    return sendTo.length > 0 ? sendTo : undefined;
  }

  /**
   * Asks a person to let the agent act for them, on their own device (OpenID CIBA). They read
   * `bindingMessage` ("Refund order 4411") and approve or refuse; the agent never sees a code or a
   * credential of theirs. Sent once: a retry would ask the person twice.
   */
  async requestUserToken(request: {
    loginHint: string;
    bindingMessage: string;
    scope?: readonly string[] | undefined;
    expiresInSeconds?: number | undefined;
    signal?: AbortSignal | undefined;
  }): Promise<CibaRequest> {
    if (typeof request.loginHint !== 'string' || request.loginHint === '')
      throw new ConfigurationError('loginHint is required: the person to ask');
    if (typeof request.bindingMessage !== 'string' || request.bindingMessage.trim() === '') {
      throw new ConfigurationError(
        'bindingMessage is required: it is what the person reads, such as "Refund order 4411"',
      );
    }
    this.#needsKey();
    const meta = await this.#requireGrant(GRANT.ciba, 'ciba', request.signal);
    const endpoint = meta.backchannel_authentication_endpoint;
    if (endpoint === undefined)
      throw new NotSupportedError('ciba', 'This AuthFI project does not offer CIBA');
    this.#requireAgentAuth(
      meta.token_endpoint_auth_methods_supported,
      meta.token_endpoint_auth_signing_alg_values_supported,
    );
    const res = await this.#core.transport.send({
      method: 'POST',
      url: endpoint,
      retry: 'unsafe',
      signal: request.signal,
      prepare: async () => {
        const form = new URLSearchParams({
          login_hint: request.loginHint,
          binding_message: request.bindingMessage,
        });
        if (request.scope !== undefined && request.scope.length > 0)
          form.set('scope', request.scope.join(' '));
        if (request.expiresInSeconds !== undefined)
          form.set('requested_expiry', String(Math.floor(request.expiresInSeconds)));
        form.set('client_id', this.agentId);
        form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        form.set(
          'client_assertion',
          (await clientAssertion(this.#signer, this.agentId, meta.token_endpoint, this.#core.clock)).reveal(),
        );
        return { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form.toString() };
      },
    });
    if (res.status !== 200) throw oauthErrorOf(res);
    const body = jsonOf(res) as { auth_req_id?: unknown; expires_in?: unknown; interval?: unknown } | null;
    if (typeof body?.auth_req_id !== 'string' || body.auth_req_id === '') {
      throw new TransportError('response_invalid', `${endpoint} answered no auth_req_id`, {
        ...contextOf(res),
        retryable: false,
      });
    }
    const expiresIn = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 300;
    const interval = typeof body.interval === 'number' && body.interval > 0 ? body.interval : 5;
    return {
      authReqId: new Secret(body.auth_req_id),
      expiresAt: new Date(this.#core.clock.now() + expiresIn * 1000),
      intervalMs: interval * 1000,
    };
  }

  /**
   * Waits for the person's decision on a CIBA request, without blocking, and returns the token the
   * agent holds for them. The first poll waits the interval; `slow_down` adds five seconds. A refusal
   * is {@link ConsentDenied}, and a request that lapsed before the person decided {@link ConsentExpired}.
   * When the caller's `timeoutMs` passes first it is {@link WaitTimeout}, and the request stays open:
   * waiting on it again continues it.
   */
  async awaitUserToken(
    request: CibaRequest,
    options: {
      timeoutMs?: number | undefined;
      /**
       * How long to wait between polls. Never below the platform's `interval` for the request (a smaller
       * value is raised to it); defaults to it. Finite and above zero.
       */
      pollIntervalMs?: number | undefined;
      signal?: AbortSignal | undefined;
      resource?: string | undefined;
      sendTo?: readonly string[] | undefined;
    } = {},
  ): Promise<DelegatedToken> {
    const sendTo = this.#sendToFor(options.resource ?? this.#resource, options.sendTo);
    const clock = this.#core.clock;
    const requestDeadline = clock.monotonic() + Math.max(0, request.expiresAt.getTime() - clock.now());
    const { response, bound } = await this.#poll({
      authReqId: request.authReqId,
      intervalMs: Math.max(request.intervalMs, pollIntervalOf(options.pollIntervalMs) ?? 0),
      requestDeadline,
      timeoutMs: options.timeoutMs,
      resource: options.resource ?? this.#resource,
      signal: options.signal,
    });
    return this.#delegated('ciba', response, sendTo, undefined, bound);
  }

  /**
   * Polls the token endpoint for a CIBA request until the person decides (CIBA §7.3): the first poll waits
   * the interval, `authorization_pending` waits on, `slow_down` adds five seconds. The grant is redeemed
   * under the agent's key, and bound to this process's key when `resource` is AuthFI's own.
   */
  async #poll(args: {
    authReqId: Secret;
    intervalMs: number;
    requestDeadline: number;
    timeoutMs: number | undefined;
    resource: string | undefined;
    signal: AbortSignal | undefined;
  }): Promise<Minted> {
    const clock = this.#core.clock;
    const meta = await this.#core.metadata({ signal: args.signal });
    const signer = await this.#keyFor(meta, args.resource);
    const waitDeadline = clock.monotonic() + (args.timeoutMs ?? 300_000);
    const requestDeadline = args.requestDeadline;
    let interval = args.intervalMs;
    for (;;) {
      if (clock.monotonic() + interval > Math.min(waitDeadline, requestDeadline)) {
        if (requestDeadline <= waitDeadline) {
          throw new ConsentExpired('expired_token', 'the request ran out before the person decided');
        }
        throw new WaitTimeout(
          'the person had not decided in time; the request is still open, and waiting on it again continues it',
        );
      }
      await clock.sleep(interval, args.signal);
      try {
        const response = await requestToken(
          this.#core.transport,
          {
            tokenEndpoint: meta.token_endpoint,
            params: {
              grant_type: GRANT.ciba,
              auth_req_id: args.authReqId.reveal(),
              resource: args.resource,
            },
            auth: this.#auth(),
            retry: 'unsafe',
            signal: args.signal,
            dpop: signer,
          },
          () => clock.now(),
        );
        return { response, bound: this.#boundBy(response, signer) };
      } catch (e) {
        if (!(e instanceof OAuthError)) throw e;
        if (e.code === 'authorization_pending') continue;
        if (e.code === 'slow_down') {
          interval += SLOW_DOWN_MS;
          continue;
        }
        if (e.code === 'access_denied')
          throw new ConsentDenied(e.code, e.description, {
            status: e.status,
            requestId: e.requestId,
            cause: e,
          });
        if (e.code === 'expired_token')
          throw new ConsentExpired(e.code, e.description, {
            status: e.status,
            requestId: e.requestId,
            cause: e,
          });
        throw e;
      }
    }
  }

  /** {@link requestUserToken}, then {@link awaitUserToken}. */
  async tokenAsUser(request: {
    loginHint: string;
    bindingMessage: string;
    scope?: readonly string[] | undefined;
    expiresInSeconds?: number | undefined;
    timeoutMs?: number | undefined;
    pollIntervalMs?: number | undefined;
    signal?: AbortSignal | undefined;
    resource?: string | undefined;
    sendTo?: readonly string[] | undefined;
  }): Promise<DelegatedToken> {
    const ciba = await this.requestUserToken(request);
    return this.awaitUserToken(ciba, request);
  }

  /**
   * Exchanges the token of a person signed in to your app for one the agent holds for them (RFC
   * 8693): its subject is the person and its actor this agent. The project must allow this agent to
   * act for them. The request carries no client authentication: the agent is the `actor_token`.
   */
  async exchange(
    subjectToken: TokenSource | Secret,
    options: {
      resource?: string | undefined;
      scope?: readonly string[] | undefined;
      sendTo?: readonly string[] | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<DelegatedToken> {
    if (!isSecret(subjectToken) && typeof (subjectToken as Partial<TokenSource>).token !== 'function') {
      throw new ConfigurationError(
        'subjectToken must be a TokenSource or a Secret: wrap a raw token as new Secret(token)',
      );
    }
    const sendTo = this.#sendToFor(options.resource, options.sendTo);
    const meta = await this.#requireGrant(GRANT.tokenExchange, 'token_exchange', options.signal);
    const signer = await this.#keyFor(meta, options.resource ?? this.#resource);
    const exchangeOnce = async (signal?: AbortSignal): Promise<Minted> => {
      const subject = isSecret(subjectToken)
        ? subjectToken
        : new Secret(await subjectToken.token({ signal }));
      if (isSecret(subjectToken) && this.#expired(subject)) {
        throw new ConsentExpired(
          'expired_token',
          "the person's token has expired; the agent cannot act for them until they sign in again",
        );
      }
      const response = await requestToken(
        this.#core.transport,
        {
          tokenEndpoint: meta.token_endpoint,
          params: {
            grant_type: GRANT.tokenExchange,
            subject_token: subject.reveal(),
            subject_token_type: ACCESS_TOKEN_TYPE,
            actor_token: await this.token({ signal }),
            actor_token_type: ACCESS_TOKEN_TYPE,
            resource: options.resource,
            scope:
              options.scope !== undefined && options.scope.length > 0 ? options.scope.join(' ') : undefined,
          },
          retry: 'unsafe',
          signal,
          dpop: signer,
        },
        () => this.#core.clock.now(),
      );
      return { response, bound: this.#boundBy(response, signer) };
    };
    const first = await exchangeOnce(options.signal);
    return this.#delegated('exchange', first.response, sendTo, exchangeOnce, first.bound);
  }

  /** Refuses a call that signs with the agent's key when this is an instance, which has none. */
  #needsKey(): void {
    if (this.#instance !== undefined) throw noAssertion();
  }

  /** The key that holds a mandate: this process's, or a refusal naming why none can. */
  async #mandateKey(meta: ServerMetadata): Promise<DPoPSigner> {
    if (!this.#dpop) {
      throw new ConfigurationError(
        "a mandate is held by this process's key: dpop cannot be off for an agent that uses one",
      );
    }
    const signer = await this.#keyFor(meta, undefined);
    if (signer === undefined) {
      throw new NotSupportedError(
        'dpop',
        'This AuthFI project accepts no DPoP key this process can make, so it cannot hold a mandate.',
      );
    }
    return signer;
  }

  /**
   * Asks for a mandate: a person's authority for one job, bounded by a template of the project's.
   * `subjectToken` is the person's token from an app linked to this agent (a {@link TokenSource}, or their
   * access token as a {@link Secret}). The answer is the {@link Mandate}, or a {@link MandatePending} when
   * the person must approve first: show them `approvalUrl` and wait with {@link awaitMandate}. A mandate is
   * one level deep: this is refused inside {@link withMandate}. Sent once: a retry would ask twice.
   */
  async requestMandate(
    template: string,
    options: {
      subjectToken: TokenSource | Secret;
      params?: Readonly<Record<string, unknown>> | undefined;
      ttlSeconds?: number | undefined;
      signal?: AbortSignal | undefined;
    },
  ): Promise<Mandate | MandatePending> {
    refuseNested();
    this.#needsKey();
    if (typeof template !== 'string' || template.trim() === '')
      throw new ConfigurationError("template is required: it is the mandate's name, such as support.refund");
    const { subjectToken } = options;
    if (!isSecret(subjectToken) && typeof (subjectToken as Partial<TokenSource>).token !== 'function') {
      throw new ConfigurationError(
        'subjectToken must be a TokenSource or a Secret: wrap a raw token as new Secret(token)',
      );
    }
    const ttl = options.ttlSeconds;
    if (ttl !== undefined && !(ttl > 0 && ttl <= MAX_MANDATE_SECONDS)) {
      throw new ConfigurationError('ttlSeconds must be from 1 second to 30 days');
    }
    let details: string;
    try {
      details = JSON.stringify([
        {
          type: MANDATE_DETAIL_TYPE,
          template: template.trim(),
          params: options.params ?? {},
          ...(ttl === undefined ? {} : { ttl_seconds: Math.floor(ttl) }),
        },
      ]);
    } catch {
      throw new ConfigurationError('params must be JSON: strings, numbers, booleans, lists and objects');
    }
    const meta = await this.#requireGrant(GRANT.tokenExchange, 'token_exchange', options.signal);
    const signer = await this.#mandateKey(meta);
    const subject = isSecret(subjectToken)
      ? subjectToken
      : new Secret(await subjectToken.token({ signal: options.signal }));
    const res = await sendTokenRequest(this.#core.transport, {
      tokenEndpoint: meta.token_endpoint,
      params: {
        grant_type: GRANT.tokenExchange,
        subject_token: subject.reveal(),
        subject_token_type: ACCESS_TOKEN_TYPE,
        actor_token_type: JWT_TOKEN_TYPE,
        authorization_details: details,
      },
      retry: 'unsafe',
      signal: options.signal,
      dpop: signer,
      // The actor token is the agent's own signed assertion, new for every attempt, naming the key that
      // will hold the mandate; there is no client authentication beside it.
      attempt: async () => ({
        params: {
          actor_token: (
            await clientAssertion(this.#signer, this.agentId, meta.token_endpoint, this.#core.clock, {
              jkt: signer.thumbprint,
            })
          ).reveal(),
        },
      }),
    });
    const pending = pendingMandateOf(res);
    if (pending !== undefined) {
      this.#core.logger.info('an agent asked a person to approve a mandate', {
        agent_id: this.agentId,
        mandate_id: pending.mandateId,
      });
      return pending;
    }
    if (res.status !== 200) throw oauthErrorOf(res);
    return this.#held(parseTokenResponse(res, this.#core.clock.now()), signer);
  }

  #held(response: TokenResponse, signer: DPoPSigner): Mandate {
    if (this.#boundBy(response, signer) === undefined) {
      throw new OAuthError(
        'invalid_response',
        'the token endpoint answered a mandate that no key holds: it is not usable',
        { status: 200 },
      );
    }
    const mandate = new Mandate({
      core: this.#core,
      agentId: this.agentId,
      sendTo: this.sendTo,
      response,
      signer,
    });
    this.#core.logger.info('an agent holds a mandate', {
      agent_id: this.agentId,
      mandate_id: mandate.mandateId,
    });
    return mandate;
  }

  /**
   * Waits for the person's decision on a mandate, then returns it. As {@link awaitUserToken}:
   * {@link ConsentDenied} when they refuse, {@link ConsentExpired} when it ran out, {@link WaitTimeout} when
   * `timeoutMs` passes first (the request stays open, and waiting again continues it).
   */
  async awaitMandate(
    pending: MandatePending,
    options: {
      timeoutMs?: number | undefined;
      pollIntervalMs?: number | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<Mandate> {
    refuseNested();
    const meta = await this.#core.metadata({ signal: options.signal });
    const signer = await this.#mandateKey(meta);
    const { response } = await this.#poll({
      authReqId: pending.authReqId,
      intervalMs: Math.max(pending.intervalMs, pollIntervalOf(options.pollIntervalMs) ?? 0),
      requestDeadline: Number.POSITIVE_INFINITY,
      timeoutMs: options.timeoutMs,
      resource: undefined,
      signal: options.signal,
    });
    return this.#held(response, signer);
  }

  /** {@link requestMandate}, then {@link awaitMandate} when the person must approve. */
  async mandate(
    template: string,
    options: {
      subjectToken: TokenSource | Secret;
      params?: Readonly<Record<string, unknown>> | undefined;
      ttlSeconds?: number | undefined;
      timeoutMs?: number | undefined;
      pollIntervalMs?: number | undefined;
      signal?: AbortSignal | undefined;
    },
  ): Promise<Mandate> {
    const started = await this.requestMandate(template, options);
    return started instanceof Mandate ? started : this.awaitMandate(started, options);
  }

  /**
   * Runs `work` with a mandate and forgets it when `work` ends, however it ends. Inside `work` a second
   * mandate is refused (a mandate is one level deep). Hand the mandate to an adapter in place of the agent:
   * the gateway then holds every call to it.
   *
   * @example
   * await agent.withMandate('support.refund', { subjectToken: person, params: { order: '4411' } }, async (m) => {
   *   const authfi = createVercelAI({ source: m, approvalSecret });
   *   // ...
   * });
   */
  async withMandate<T>(
    template: string,
    options: Parameters<AgentAuth['mandate']>[1],
    work: (mandate: Mandate) => Promise<T> | T,
  ): Promise<T> {
    const mandate = await this.mandate(template, options);
    try {
      return await runInMandate(() => work(mandate));
    } finally {
      mandate.close();
    }
  }

  /** Cloud credentials through the gateway: `agent.cloud.credentials({ account, role })`. */
  get cloud(): CloudAccess {
    return this.gateway().cloud;
  }

  #expired(token: Secret): boolean {
    try {
      const { exp } = decodeUnverified(token.reveal()).payload;
      return typeof exp === 'number' && exp * 1000 <= this.#core.clock.now();
    } catch {
      return false;
    }
  }

  #delegated(
    via: 'ciba' | 'exchange',
    response: TokenResponse,
    sendTo: readonly string[] | undefined,
    renew: ((signal?: AbortSignal) => Promise<Minted>) | undefined,
    bound: DPoPSigner | undefined,
  ): DelegatedToken {
    return new DelegatedToken({
      core: this.#core,
      via,
      response,
      bound,
      sendTo,
      ownOrigins: () => this.sendTo,
      refreshSkewMs: this.#skew,
      renew,
    });
  }

  /**
   * Freezes one high-risk action, its resource and parameters into a 60-second transaction token.
   * The project's constraints are checked before it is minted. This is AuthFI's action gate, named
   * after the IETF Transaction Tokens draft but not following it.
   */
  async transactionToken(
    action: string,
    options: {
      resource?: string | undefined;
      context?: Readonly<Record<string, unknown>> | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<TransactionToken> {
    if (typeof action !== 'string' || action.trim() === '')
      throw new ConfigurationError('action is required');
    const url = `${await this.#core.apiOrigin(options.signal)}${AGENT_API}/transaction-token`;
    const { token, signer } = await this.#own(options.signal);
    const res = await this.#core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal: options.signal,
      ...(signer === undefined ? {} : { dpop: { signer, accessToken: token } }),
      headers: {
        authorization: `${signer === undefined ? 'Bearer' : 'DPoP'} ${token.reveal()}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ action, resource: options.resource, context: options.context }),
    });
    if (res.status !== 200) throw apiErrorOf(res);
    const data = dataOf(res) as { transaction_token?: unknown; txn?: unknown; expires_in?: unknown } | null;
    if (typeof data?.transaction_token !== 'string' || typeof data.txn !== 'string') {
      throw new TransportError('response_invalid', `${url} answered no transaction token`, {
        ...contextOf(res),
        retryable: false,
      });
    }
    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 60;
    return {
      token: new Secret(data.transaction_token),
      txn: data.txn,
      expiresAt: new Date(this.#core.clock.now() + expiresIn * 1000),
      action,
      resource: options.resource,
      context: options.context,
    };
  }

  /** Asks the action gate about a frozen action. It refuses when anything differs from what was frozen. */
  async authorizeAction(
    txn: TransactionToken,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<ActionDecision> {
    const url = `${await this.#core.apiOrigin(options.signal)}${AGENT_API}/authorize`;
    const res = await this.#core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal: options.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agent_id: this.agentId,
        transaction_token: txn.token.reveal(),
        action: txn.action,
        resource: txn.resource,
        context: txn.context,
      }),
    });
    if (res.status !== 200) throw apiErrorOf(res);
    const data = dataOf(res) as { decision?: unknown; approval_id?: unknown; reason?: unknown } | null;
    const decision = data?.decision;
    if (decision !== 'allow' && decision !== 'deny' && decision !== 'approval_required') {
      throw new TransportError('response_invalid', `${url} answered no decision`, {
        ...contextOf(res),
        retryable: false,
      });
    }
    return {
      decision,
      approvalId:
        typeof data?.approval_id === 'string' && data.approval_id !== '' ? data.approval_id : undefined,
      reason: typeof data?.reason === 'string' && data.reason !== '' ? data.reason : undefined,
    };
  }

  async #loadAgentConfiguration() {
    const url = `${this.#core.issuer}/.well-known/agent-configuration`;
    const res = await this.#core.transport.send({ method: 'GET', url, retry: 'safe', maxBytes: 256 * 1024 });
    if (res.status !== 200)
      throw new DiscoveryError('discovery_failed', `${url} answered HTTP ${res.status}`, contextOf(res));
    const doc = jsonOf(res) as { issuer?: unknown; endpoints?: Record<string, unknown> } | null;
    if (doc?.issuer !== this.#core.issuer)
      throw new DiscoveryError('issuer_mismatch', `${url} names another issuer`, contextOf(res));
    const own = await this.#core.ownOrigins();
    const endpoint = (name: string): string => {
      const value = doc.endpoints?.[name];
      const origin = typeof value === 'string' ? originOf(value.replace('{id}', 'x')) : undefined;
      if (typeof value !== 'string' || origin === undefined || !own.includes(origin)) {
        throw new DiscoveryError(
          'discovery_failed',
          `${url} has no usable endpoints.${name}`,
          contextOf(res),
        );
      }
      return value;
    };
    return {
      value: { requestApproval: endpoint('request_approval'), approval: endpoint('approval') },
      maxAgeMs: maxAgeOf(res.headers.get('cache-control')),
    };
  }

  /**
   * Asks a person to approve one action ("Refund order 4411"). They decide in the console or by the
   * link they are sent; no token results. Sent once: a retry would open a second approval.
   */
  async requestApproval(
    action: string,
    options: {
      context?: Readonly<Record<string, unknown>> | undefined;
      expiresInSeconds?: number | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<Approval> {
    if (typeof action !== 'string' || action.trim() === '')
      throw new ConfigurationError('action is required');
    this.#needsKey();
    const { requestApproval } = await this.#agentConfig.get({ signal: options.signal });
    const meta = await this.#core.metadata({ signal: options.signal });
    const res = await this.#core.transport.send({
      method: 'POST',
      url: requestApproval,
      retry: 'unsafe',
      signal: options.signal,
      prepare: async () => ({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          agent_id: this.agentId,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: (
            await clientAssertion(this.#signer, this.agentId, meta.token_endpoint, this.#core.clock)
          ).reveal(),
          requesting_action: action,
          context: options.context,
          timeout_seconds: options.expiresInSeconds ?? 300,
        }),
      }),
    });
    if (res.status !== 202 && res.status !== 200) throw apiErrorOf(res);
    return approvalOf(dataOf(res), requestApproval);
  }

  /**
   * Reads an approval's state with the agent's own token. A project that does not open approval
   * status to agents answers 403 on that route, which is {@link NotSupportedError}
   * (`agent_approval_status`); the method works without an SDK release once the project does.
   */
  async approval(approvalId: string, options: { signal?: AbortSignal | undefined } = {}): Promise<Approval> {
    const { approval } = await this.#agentConfig.get({ signal: options.signal });
    const url = approval.replace('{id}', encodeURIComponent(approvalId));
    const { token, signer } = await this.#own(options.signal);
    const res = await this.#core.transport.send({
      method: 'GET',
      url,
      retry: 'safe',
      signal: options.signal,
      ...(signer === undefined ? {} : { dpop: { signer, accessToken: token } }),
      headers: { authorization: `${signer === undefined ? 'Bearer' : 'DPoP'} ${token.reveal()}` },
    });
    if (res.status === 403) {
      throw new NotSupportedError(
        'agent_approval_status',
        'This AuthFI project does not offer approval status to agents',
        contextOf(res),
      );
    }
    if (res.status !== 200) throw apiErrorOf(res);
    return approvalOf(dataOf(res), url);
  }

  /**
   * Polls {@link approval} every `pollIntervalMs` until the approval is no longer pending, and returns it
   * whatever the person decided. When `timeoutMs` passes first it throws {@link WaitTimeout} carrying
   * the approval's id; the approval stays open, and waiting on it again continues.
   */
  async waitForApproval(
    approvalId: string,
    options: {
      timeoutMs?: number | undefined;
      pollIntervalMs?: number | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<Approval> {
    const clock = this.#core.clock;
    const deadline = clock.monotonic() + (options.timeoutMs ?? 300_000);
    const interval = pollIntervalOf(options.pollIntervalMs) ?? 3000;
    for (;;) {
      const current = await this.approval(approvalId, options);
      if (current.status !== 'pending') return current;
      if (clock.monotonic() + interval > deadline) {
        throw new WaitTimeout(
          `approval ${approvalId} is still pending: the person had not decided in time, and it stays open`,
          approvalId,
        );
      }
      await clock.sleep(interval, options.signal);
    }
  }

  /** The project's MCP and AI gateways, with this agent's own token. */
  gateway(): Gateway {
    this.#gateway ??= new Gateway(this.#core, this, this.agentId);
    return this.#gateway;
  }

  /** The agent id and key id only. */
  override toString(): string {
    return `AgentAuth(${this.agentId}, ${this.#signer.alg} ${this.#signer.kid})`;
  }

  toJSON(): { agentId: string; issuer: string; kid: string } {
    return { agentId: this.agentId, issuer: this.#af.issuer, kid: this.#signer.kid };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
