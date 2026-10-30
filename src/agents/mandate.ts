import { ConfigurationError, ConsentExpired, OAuthError } from '../core/errors.js';
import type { DPoPSigner } from '../core/dpop.js';
import type { TokenResponse } from '../core/oauth.js';
import type { Core } from '../core/project.js';
import type { Secret } from '../core/secret.js';
import { BaseTokenSource, type TokenOptions } from '../core/token-source.js';
import { Gateway, type CloudAccess } from '../gateway/gateway.js';

/** RFC 9396 `type` of the one `authorization_details` entry that asks for a mandate. */
export const MANDATE_DETAIL_TYPE = 'authfi_mandate';

/** What the platform granted for a mandate: the `authfi_mandate` entry of the token answer. */
export interface MandateDetails {
  readonly mandateId: string;
  /** The template it was made from, such as `support.refund@3`. */
  readonly template: string;
  readonly tools: readonly string[];
  readonly budgets: Readonly<Record<string, number>>;
  readonly expiresAt: string | undefined;
}

/**
 * A mandate a person must approve first. Show them `approvalUrl` and wait with `agent.awaitMandate`.
 * `authReqId` is a bearer handle, held as a {@link Secret}.
 */
export interface MandatePending {
  readonly authReqId: Secret;
  readonly mandateId: string;
  readonly intervalMs: number;
  readonly approvalUrl: string | undefined;
}

function isEntry(entry: unknown): entry is Record<string, unknown> {
  return (
    typeof entry === 'object' && entry !== null && (entry as { type?: unknown }).type === MANDATE_DETAIL_TYPE
  );
}

/** The `authfi_mandate` entry of a mandate's token answer (RFC 9396 section 7), or an error. */
export function mandateDetailsOf(response: TokenResponse): MandateDetails {
  const entries = response.extra.authorization_details;
  const found = Array.isArray(entries) ? (entries as unknown[]).find(isEntry) : undefined;
  if (found === undefined) {
    throw new OAuthError(
      'invalid_response',
      'the token endpoint answered a mandate without its authorization_details',
      { status: 200 },
    );
  }
  const budgets: Record<string, number> = {};
  if (typeof found.budgets === 'object' && found.budgets !== null) {
    for (const [k, v] of Object.entries(found.budgets)) {
      if (typeof v === 'number' && Number.isInteger(v)) budgets[k] = v;
    }
  }
  return {
    mandateId: typeof found.mandate_id === 'string' ? found.mandate_id : '',
    template: typeof found.template === 'string' ? found.template : '',
    tools: Array.isArray(found.tools)
      ? (found.tools as unknown[]).filter((t): t is string => typeof t === 'string')
      : [],
    budgets: Object.freeze(budgets),
    expiresAt: typeof found.expires_at === 'string' && found.expires_at !== '' ? found.expires_at : undefined,
  };
}

/** What a mandate is made from; internal to the SDK. */
export interface MandateInit {
  readonly core: Core;
  readonly agentId: string;
  readonly sendTo: readonly string[];
  readonly response: TokenResponse;
  readonly signer: DPoPSigner;
}

/**
 * A mandate: the authority a person gave an agent for one job, narrowed from the agent's ceiling. It is a
 * credential, like the agent's own token: hand it to an adapter in place of the agent and the gateway holds
 * each call to it. A tool outside it, a spend over its budget and an ended mandate are refused, and the
 * refusal says what the agent can still do.
 *
 * Nothing swaps the agent's own token for the mandate's behind your back. A framework may keep an MCP
 * session open from before the mandate, and a call through it would carry the agent's own, wider, token: so
 * the mandate is passed in, and a session is made with it.
 *
 * A mandate is one level deep. Nothing a mandate does can widen it or start another. Only a person gives
 * one. {@link Mandate.close} (or leaving `agent.withMandate`) forgets the credential. It is held by the
 * process's key, so it cannot be used elsewhere, and it is never serialised.
 */
export class Mandate extends BaseTokenSource {
  readonly agentId: string;
  /** The mandate's id, which the platform's record of it carries. */
  readonly mandateId: string;
  /** The template the mandate was made from, such as `support.refund@3`. */
  readonly template: string;
  /** The tools it allows. */
  readonly tools: readonly string[];
  /** Its budgets, by name. */
  readonly budgets: Readonly<Record<string, number>>;
  readonly #core: Core;
  readonly #sendTo: readonly string[];
  readonly #signer: DPoPSigner;
  readonly #expiresAt: number;
  #root: Secret | undefined;
  #gateway: Gateway | undefined;

  /** Use `agent.mandate()`. */
  constructor(init: MandateInit) {
    super(init.core.fetch);
    const details = mandateDetailsOf(init.response);
    this.agentId = init.agentId;
    this.mandateId = details.mandateId;
    this.template = details.template;
    this.tools = details.tools;
    this.budgets = details.budgets;
    this.#core = init.core;
    this.#sendTo = init.sendTo;
    this.#signer = init.signer;
    this.#root = init.response.accessToken;
    this.#expiresAt = init.response.expiresAt;
  }

  /** AuthFI's own origins, as the agent's own token. */
  get sendTo(): readonly string[] {
    return this.#sendTo;
  }

  /** When the mandate's credential expires. */
  get expiresAt(): Date {
    return new Date(this.#expiresAt);
  }

  override get dpop(): DPoPSigner | undefined {
    return this.#signer;
  }

  /** The mandate's root token. A reveal point: keep it brief. */
  token(_options: TokenOptions = {}): Promise<string> {
    if (this.#root === undefined) {
      return Promise.reject(
        new ConfigurationError('this mandate is closed: its credential was forgotten when its use ended'),
      );
    }
    if (this.#core.clock.now() >= this.#expiresAt) {
      return Promise.reject(
        new ConsentExpired(
          'expired_token',
          'the mandate has run out; only a person can give the agent another',
        ),
      );
    }
    return Promise.resolve(this.#root.reveal());
  }

  /** Forgets the credential. The platform's record of the mandate ends with its deadline or a person's decision. */
  close(): void {
    this.#root = undefined;
  }

  [Symbol.dispose](): void {
    this.close();
  }

  /** The gateways (tools, models, cloud credentials) with this mandate as the credential. */
  gateway(): Gateway {
    this.#gateway ??= new Gateway(this.#core, this, this.agentId);
    return this.#gateway;
  }

  /** Cloud credentials held to this mandate: `mandate.cloud.credentials({ account, role })`. */
  get cloud(): CloudAccess {
    return this.gateway().cloud;
  }

  override toString(): string {
    return `Mandate(${this.mandateId}, ${this.template})`;
  }

  toJSON(): { kind: 'mandate'; mandateId: string; template: string } {
    return { kind: 'mandate', mandateId: this.mandateId, template: this.template };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
