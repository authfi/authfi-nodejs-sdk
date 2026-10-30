/**
 * A2A 1.0 client helpers: trust a remote agent's card, call it with this agent's token, read its task state.
 *
 * @example
 * const remote = await a2a.remote(agent, 'https://research.partner.example', { trustRoots: [R1_PEM] });
 * const status = await remote.send('Summarise the Q3 incidents');
 * if (status.needsInput) { ... } // TASK_STATE_INPUT_REQUIRED: a person must answer
 * if (status.needsAuth) { ... } // TASK_STATE_AUTH_REQUIRED: consent or credentials are missing
 *
 * - **The card is verified or refused.** `trustRoots` are the roots you trust (an AuthFI agent's chain ends at
 *   Root R1); `keys` are public JWKs by `kid` for agents that sign with a plain key. A card with no valid
 *   signature is refused unless you pass `allowUnsigned: true`, which says so in its name.
 * - **The token goes where the card says, and only there.** The agent's DPoP-bound token (or its Bearer token,
 *   for a credential that is not bound) is sent to the card's own origin, or to an origin you list in
 *   `allowOrigins`; a card that points elsewhere is refused. The token is for `resource` (the interface's
 *   origin unless you name another).
 * - **The card's security scheme must be one this SDK speaks:** OAuth 2, OpenID Connect or HTTP bearer.
 * - {@link statusFor} and {@link statusForOutcome} turn an AuthFI decision into the state a remote caller
 *   reads.
 *
 * The field names are the specification's (a2a-protocol.org/latest/specification): `supportedInterfaces` with
 * `url`, `protocolBinding` and `protocolVersion`; `securitySchemes`; `signatures` of `protected`, `signature`
 * and `header`; `TASK_STATE_*`; `ROLE_USER` and `ROLE_AGENT`; `parts` of `{ text }`.
 *
 * @packageDocumentation
 */

import { compactVerify, importJWK, importX509, type JWK } from 'jose';
import type { AgentAuth } from '../agents/agent.js';
import { base64url, fromBase64, fromBase64urlStrict, fromUtf8, utf8 } from '../core/bytes.js';
import { asksForNonce } from '../core/dpop.js';
import { AuthFIError, ConfigurationError } from '../core/errors.js';
import { coreOf } from '../core/project.js';
import { jsonOf, MAX_DOCUMENT_BYTES, textOf, type HttpResponse } from '../core/transport.js';
import type { TokenSource } from '../core/token-source.js';
import { originOf } from '../core/urls.js';
import type { ToolOutcome } from '../gateway/gateway.js';
import type { Certificate } from '../verify/der.js';
import { certificatesFromPem, issued } from '../verify/chain.js';
import { parseCertificate } from '../verify/der.js';

/** The `certificatePolicies` arc of an AuthFI agent-custody certificate. */
export const AGENT_CUSTODY_POLICY = '1.3.6.1.4.1.67322.1.4';
const WELL_KNOWN = '/.well-known/agent-card.json';
const VERSION = '1.0';
const ALGORITHMS = ['EdDSA', 'ES256', 'PS256'] as const;

/** `TASK_STATE_INPUT_REQUIRED`: a person must answer or approve. */
export const INPUT_REQUIRED = 'TASK_STATE_INPUT_REQUIRED';
/** `TASK_STATE_AUTH_REQUIRED`: consent or credentials are missing. */
export const AUTH_REQUIRED = 'TASK_STATE_AUTH_REQUIRED';
/** `TASK_STATE_REJECTED`: the agent declined the task. */
export const REJECTED = 'TASK_STATE_REJECTED';
/** `TASK_STATE_FAILED`: an execution error, never a refusal. */
export const FAILED = 'TASK_STATE_FAILED';
/** `TASK_STATE_COMPLETED`. */
export const COMPLETED = 'TASK_STATE_COMPLETED';
/** `TASK_STATE_WORKING`. */
export const WORKING = 'TASK_STATE_WORKING';
const STATES = new Set([
  'TASK_STATE_SUBMITTED',
  WORKING,
  COMPLETED,
  FAILED,
  'TASK_STATE_CANCELED',
  INPUT_REQUIRED,
  REJECTED,
  AUTH_REQUIRED,
]);
const SPOKEN = ['oauth2SecurityScheme', 'openIdConnectSecurityScheme', 'httpAuthSecurityScheme'];

/** Refusal codes that mean "a person's consent or credentials are missing", not "no". */
const AUTH_CODES = new Set([
  'consent_required',
  'credentials_required',
  'connection_required',
  'authorization_required',
  'auth_required',
  'interaction_required',
  'login_required',
]);

/** An A2A call or card the SDK refused. `code` says which, the message says what to do. */
export class A2AError extends AuthFIError {
  override readonly name: string = 'A2AError';
  constructor(code: string, message: string, status?: number) {
    super(code, message, status === undefined ? {} : { status });
  }
}

/** The agent card's signature did not verify, or the card has none. */
export class CardUnverified extends A2AError {
  override readonly name: string = 'CardUnverified';
  constructor(message: string) {
    super('card_unverified', message);
  }
}

// --- RFC 8785 -----------------------------------------------------------------------------------

/**
 * RFC 8785 (JCS): members sorted by UTF-16 code units, no space, the shortest string escapes, UTF-8.
 * JavaScript's own number and string serialisation is the one the RFC specifies. A non-finite number, or a
 * value JSON cannot hold, is refused.
 */
export function canonicalJson(value: unknown): Uint8Array<ArrayBuffer> {
  const emit = (v: unknown): string => {
    if (v === null) return 'null';
    if (typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new RangeError('a card number must be finite');
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) return `[${(v as unknown[]).map(emit).join(',')}]`;
    if (typeof v === 'object') {
      const entries = Object.entries(v as Record<string, unknown>)
        .filter(([, x]) => x !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${emit(x)}`).join(',')}}`;
    }
    throw new RangeError(`${typeof v} is not JSON`);
  };
  return utf8(emit(value));
}

// --- the card -------------------------------------------------------------------------------------

/** One `AgentInterface`: where and how the agent is called. */
export interface Interface {
  readonly url: string;
  readonly binding: string;
  readonly version: string;
}

/** A fetched agent card. `verified` says whether its signature was checked; `signer` names the key. */
export interface AgentCard {
  readonly raw: Readonly<Record<string, unknown>>;
  readonly name: string;
  readonly interfaces: readonly Interface[];
  readonly schemes: readonly string[];
  readonly verified: boolean;
  readonly signer: string | undefined;
}

/** The interface to call: HTTP+JSON first, then JSON-RPC. Others (gRPC) this SDK does not speak. */
export function interfaceOf(card: AgentCard): Interface {
  for (const wanted of ['HTTP+JSON', 'JSONRPC']) {
    const found = card.interfaces.find((i) => i.binding === wanted);
    if (found !== undefined) return found;
  }
  throw new A2AError(
    'no_interface',
    `${card.name} offers only ${JSON.stringify([...new Set(card.interfaces.map((i) => i.binding))])}; this SDK speaks HTTP+JSON and JSONRPC`,
  );
}

/** The card, unverified. */
export function parseCard(res: HttpResponse): AgentCard {
  if (res.status !== 200)
    throw new A2AError('card_unavailable', `the agent card answered HTTP ${String(res.status)}`, res.status);
  let body: unknown;
  try {
    body = jsonOf(res);
  } catch {
    body = undefined;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body))
    throw new A2AError('card_invalid', 'the agent card is not a JSON object');
  const card = body as Record<string, unknown>;
  const interfaces: Interface[] = [];
  if (
    typeof card.name !== 'string' ||
    !Array.isArray(card.supportedInterfaces) ||
    card.supportedInterfaces.length === 0
  )
    throw new A2AError('card_invalid', 'the agent card has no name or supportedInterfaces');
  for (const item of card.supportedInterfaces as unknown[]) {
    if (typeof item !== 'object' || item === null) continue;
    const { url, protocolBinding: binding, protocolVersion: version } = item as Record<string, unknown>;
    if ([url, binding, version].every((x) => typeof x === 'string' && x !== '')) {
      interfaces.push({ url: url as string, binding: binding as string, version: version as string });
    }
  }
  const schemes: string[] = [];
  if (typeof card.securitySchemes === 'object' && card.securitySchemes !== null) {
    for (const scheme of Object.values(card.securitySchemes)) {
      if (typeof scheme === 'object' && scheme !== null) schemes.push(...Object.keys(scheme as object));
    }
  }
  return { raw: card, name: card.name, interfaces, schemes, verified: false, signer: undefined };
}

// --- verification -----------------------------------------------------------------------------------

function pemOf(der: Uint8Array): string {
  const body = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

/**
 * The leaf of `x5c` (leaf first, base64 DER), after checking it leads to a trusted root. Every link is
 * signed by the next; every issuer is a CA; every certificate is valid now; the last one is the root or
 * issued by one of `roots`; the leaf is no CA and carries certificate policy `policy`.
 */
export async function verifyChain(
  x5c: readonly string[],
  roots: readonly string[],
  now: number,
  policy: string = AGENT_CUSTODY_POLICY,
): Promise<{ leaf: Certificate; der: Uint8Array }> {
  if (x5c.length === 0 || roots.length === 0)
    throw new CardUnverified('a chain and a trusted root are both needed to verify a card by certificate');
  let chain: Certificate[];
  let ders: Uint8Array[];
  let trusted: Certificate[];
  try {
    ders = x5c.map((c) => {
      const der = fromBase64(c);
      if (der === undefined) throw new RangeError('not base64');
      return der;
    });
    chain = ders.map((d) => parseCertificate(d));
    trusted = roots.flatMap((r) => certificatesFromPem(r));
  } catch {
    throw new CardUnverified('a certificate in the chain or the trusted roots cannot be read');
  }
  for (const cert of chain)
    if (now < cert.notBefore || now > cert.notAfter)
      throw new CardUnverified('a certificate in the chain is not valid now');
  for (let i = 0; i + 1 < chain.length; i++) {
    const [cert, next] = [chain[i], chain[i + 1]];
    if (cert === undefined || next === undefined || !(await issued(cert, next)) || !next.isCA)
      throw new CardUnverified("the chain's links do not each lead to the next certificate authority");
  }
  const top = chain[chain.length - 1];
  const topDer = ders[ders.length - 1];
  let anchored = false;
  for (const root of trusted) {
    const same = root.der.length === topDer?.length && root.der.every((b, i) => b === topDer[i]);
    if (same || (top !== undefined && (await issued(top, root)))) {
      if (!same && (!root.isCA || now < root.notBefore || now > root.notAfter))
        throw new CardUnverified('the trusted root is not a valid certificate authority now');
      anchored = true;
      break;
    }
  }
  if (!anchored) throw new CardUnverified('the chain does not lead to a root you trust');
  const leaf = chain[0];
  const leafDer = ders[0];
  if (leaf === undefined || leafDer === undefined) throw new CardUnverified('the chain is empty');
  if (leaf.isCA && chain.length > 1)
    throw new CardUnverified('the signing certificate is a certificate authority');
  if (!leaf.policies.includes(policy))
    throw new CardUnverified(`the signing certificate does not carry the agent-custody policy ${policy}`);
  return { leaf, der: leafDer };
}

/** What a card is verified with. */
export interface VerifyOptions {
  /** PEM certificates you trust as roots. An AuthFI agent's chain ends at Root R1. */
  readonly trustRoots?: readonly string[] | undefined;
  /** Public JWKs by `kid`, for an agent that signs with a plain key. */
  readonly keys?: Readonly<Record<string, JsonWebKey>> | undefined;
  /** The time to check certificates at, in epoch milliseconds (default now). */
  readonly now?: number | undefined;
}

/**
 * `card` with `verified` set, after at least one of its signatures checks; else {@link CardUnverified}. The
 * signature is a JWS over the card without its `signatures`, canonicalised with RFC 8785. A signature whose
 * protected header has an `x5c` chain is checked with the chain's leaf, which must lead to one of
 * `trustRoots`. Otherwise the key is `keys[kid]` (a public JWK you obtained and trust).
 */
export async function verifyCard(card: AgentCard, options: VerifyOptions = {}): Promise<AgentCard> {
  const { signatures, ...rest } = card.raw as { signatures?: unknown } & Record<string, unknown>;
  if (!Array.isArray(signatures) || signatures.length === 0)
    throw new CardUnverified(`${card.name}'s agent card carries no signature, so it cannot be trusted`);
  let payload: string;
  try {
    payload = base64url(canonicalJson(rest));
  } catch (cause) {
    throw new CardUnverified(
      `the card cannot be canonicalised (${cause instanceof Error ? cause.message : ''})`,
    );
  }
  const problems: string[] = [];
  for (const entry of signatures as unknown[]) {
    try {
      const signer = await checkSignature(entry, payload, options);
      return { ...card, verified: true, signer };
    } catch (error) {
      if (!(error instanceof CardUnverified)) throw error;
      problems.push(error.message);
    }
  }
  throw new CardUnverified(`${card.name}'s agent card did not verify: ${problems.join('; ')}`);
}

async function checkSignature(entry: unknown, payload: string, options: VerifyOptions): Promise<string> {
  const { protected: protectedHeader, signature } = (entry ?? {}) as Record<string, unknown>;
  if (typeof protectedHeader !== 'string' || typeof signature !== 'string')
    throw new CardUnverified('a signature lacks protected or signature');
  let parsed: unknown;
  try {
    const bytes = fromBase64urlStrict(protectedHeader);
    parsed = JSON.parse(bytes === undefined ? '' : fromUtf8(bytes));
  } catch {
    throw new CardUnverified("a signature's protected header is not JSON");
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
    throw new CardUnverified("a signature's protected header is not an object");
  const head = parsed as Record<string, unknown>;
  const { alg, kid, x5c } = head;
  if (typeof alg !== 'string' || !(ALGORITHMS as readonly string[]).includes(alg))
    throw new CardUnverified(
      `signature algorithm ${JSON.stringify(alg)} is not one of ${ALGORITHMS.join(', ')}`,
    );
  if (typeof kid !== 'string' || kid === '') throw new CardUnverified('a signature names no kid');
  let key: Awaited<ReturnType<typeof importJWK>>;
  let name: string;
  if (Array.isArray(x5c) && x5c.length > 0) {
    const { der } = await verifyChain(x5c as string[], options.trustRoots ?? [], options.now ?? Date.now());
    key = await importX509(pemOf(der), alg);
    name = `${kid} (agent certificate)`;
  } else if (options.keys?.[kid] !== undefined) {
    key = await importJWK(options.keys[kid] as JWK, alg);
    name = kid;
  } else {
    throw new CardUnverified(
      `no certificate chain in the signature and no key given for kid ${JSON.stringify(kid)}`,
    );
  }
  try {
    await compactVerify(`${protectedHeader}.${payload}.${signature}`, key, { algorithms: [alg] });
  } catch {
    throw new CardUnverified('the signature does not match the card');
  }
  return name;
}

// --- messages and tasks --------------------------------------------------------------------------------

/** A task's state (`TASK_STATE_*`) and the words the agent gave with it. */
export interface TaskStatus {
  readonly state: string;
  readonly text: string | undefined;
  readonly taskId: string | undefined;
  readonly contextId: string | undefined;
  /** A person's answer or approval is awaited. */
  readonly needsInput: boolean;
  /** Consent or credentials are awaited. */
  readonly needsAuth: boolean;
  /** The agent declined the task. */
  readonly rejected: boolean;
  readonly raw: Readonly<Record<string, unknown>>;
}

function taskStatus(
  state: string,
  text?: string,
  ids: { taskId?: string | undefined; contextId?: string | undefined } = {},
  raw: Readonly<Record<string, unknown>> = {},
): TaskStatus {
  return {
    state,
    text,
    taskId: ids.taskId,
    contextId: ids.contextId,
    needsInput: state === INPUT_REQUIRED,
    needsAuth: state === AUTH_REQUIRED,
    rejected: state === REJECTED,
    raw,
  };
}

/** A `TaskStatus` object for a response: `state` and, if there are words, an agent `message`. */
export function toStatusObject(status: TaskStatus): Record<string, unknown> {
  return {
    state: status.state,
    ...(status.text === undefined || status.text === ''
      ? {}
      : {
          message: { messageId: crypto.randomUUID(), role: 'ROLE_AGENT', parts: [{ text: status.text }] },
        }),
  };
}

function textIn(message: unknown): string | undefined {
  const parts = (message as { parts?: unknown } | undefined)?.parts;
  if (!Array.isArray(parts)) return undefined;
  const texts = (parts as unknown[])
    .map((p) => (p as { text?: unknown } | null)?.text)
    .filter((t): t is string => typeof t === 'string');
  return texts.length === 0 ? undefined : texts.join('\n');
}

const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

/** The task (or the reply message) a `SendMessage` answered; a refusal is the typed error. */
export function parseTask(res: HttpResponse): TaskStatus {
  if (res.status === 401 || res.status === 403) {
    const challenge = res.headers.get('www-authenticate');
    throw new A2AError(
      'remote_refused',
      `the A2A agent refused the credential (HTTP ${String(res.status)}${challenge === null ? '' : `, ${challenge}`}); check the remote agent accepts this project's tokens for the resource you named`,
      res.status,
    );
  }
  if (res.status < 200 || res.status >= 300)
    throw new A2AError('remote_error', `the A2A agent answered HTTP ${String(res.status)}`, res.status);
  let body: Record<string, unknown>;
  try {
    body = (jsonOf(res) as Record<string, unknown> | undefined) ?? {};
  } catch {
    throw new A2AError('response_invalid', 'the A2A agent answered no JSON');
  }
  const error = body.error as { message?: unknown; code?: unknown } | null | undefined;
  if (typeof error === 'object' && error !== null)
    throw new A2AError(
      'remote_error',
      `the A2A agent answered an error: ${String(error.message ?? error.code)}`,
    );
  const result: unknown = body.result ?? body;
  if (typeof result !== 'object' || result === null)
    throw new A2AError('response_invalid', 'the A2A agent answered neither a task nor a message');
  const answer = result as Record<string, unknown>;
  const nested = answer.task;
  const task =
    typeof nested === 'object' && nested !== null
      ? (nested as Record<string, unknown>)
      : typeof answer.status === 'object' && answer.status !== null
        ? answer
        : undefined;
  if (task !== undefined) {
    const status = (task.status ?? {}) as Record<string, unknown>;
    const state = status.state;
    if (typeof state !== 'string' || !STATES.has(state))
      throw new A2AError(
        'response_invalid',
        `the A2A agent answered an unknown task state ${JSON.stringify(state)}`,
      );
    return taskStatus(
      state,
      textIn(status.message),
      { taskId: str(task.id), contextId: str(task.contextId) },
      answer,
    );
  }
  const message = answer.message;
  if (typeof message === 'object' && message !== null) {
    const m = message as Record<string, unknown>;
    return taskStatus(COMPLETED, textIn(m), { taskId: str(m.taskId), contextId: str(m.contextId) }, answer);
  }
  throw new A2AError('response_invalid', 'the A2A agent answered neither a task nor a message');
}

// --- AuthFI decisions as task states -------------------------------------------------------------------------

/**
 * The task state for a policy decision. `needs_approval` is `INPUT_REQUIRED` (a person must decide);
 * `needs_consent`, `needs_credentials` or `auth_required`, or a deny whose `code` says consent or
 * credentials are missing, is `AUTH_REQUIRED`; `deny` is `REJECTED` with the reason; `allow` is `WORKING`.
 * Anything else is `FAILED`: an answer this SDK does not know is no yes.
 */
export function statusFor(decision: string, reason?: string, code?: string): TaskStatus {
  if (decision === 'allow') return taskStatus(WORKING);
  if (decision === 'needs_approval')
    return taskStatus(INPUT_REQUIRED, reason ?? 'A person must approve this action.');
  if (
    decision === 'needs_consent' ||
    decision === 'needs_credentials' ||
    decision === 'auth_required' ||
    (decision === 'deny' && code !== undefined && AUTH_CODES.has(code))
  )
    return taskStatus(AUTH_REQUIRED, reason ?? 'Consent or credentials are needed to continue.');
  if (decision === 'deny') return taskStatus(REJECTED, reason ?? 'Denied by policy.');
  return taskStatus(FAILED, reason ?? 'The decision could not be read.');
}

/** {@link statusFor} for what the gateway did with a tool call. */
export function statusForOutcome(outcome: ToolOutcome): TaskStatus {
  if (outcome.kind === 'allowed') return statusFor('allow');
  if (outcome.kind === 'approval_required') return statusFor('needs_approval');
  const code = outcome.code ?? outcome.error;
  return statusFor('deny', outcome.reason === '' ? code : outcome.reason, code);
}

// --- calling a remote agent ---------------------------------------------------------------------------------

/** The URL a `SendMessage` goes to, which the token's DPoP proof must name. */
export function messageUrl(i: Interface): string {
  return i.binding === 'HTTP+JSON' ? `${i.url.replace(/\/+$/, '')}/message:send` : i.url;
}

/** A remote A2A agent whose card was verified. Made by {@link remote}. */
export class RemoteAgent {
  readonly card: AgentCard;
  readonly interface: Interface;
  readonly #agent: AgentAuth;
  readonly #source: TokenSource;

  constructor(agent: AgentAuth, card: AgentCard, iface: Interface, source: TokenSource) {
    this.#agent = agent;
    this.card = card;
    this.interface = iface;
    this.#source = source;
  }

  /** Sends one text message; returns the task's state and the agent's words. Sent once. */
  async send(
    text: string,
    options: { contextId?: string; taskId?: string; signal?: AbortSignal } = {},
  ): Promise<TaskStatus> {
    const core = coreOf(this.#agent.project);
    const message: Record<string, unknown> = {
      messageId: crypto.randomUUID(),
      role: 'ROLE_USER',
      parts: [{ text }],
      ...(options.contextId ? { contextId: options.contextId } : {}),
      ...(options.taskId ? { taskId: options.taskId } : {}),
    };
    const url = messageUrl(this.interface);
    const http = this.interface.binding === 'HTTP+JSON';
    const body = JSON.stringify(
      http
        ? { message }
        : { jsonrpc: '2.0', id: crypto.randomUUID(), method: 'SendMessage', params: { message } },
    );
    const sendOnce = async (): Promise<HttpResponse> =>
      core.transport.send({
        method: 'POST',
        url,
        retry: 'unsafe',
        signal: options.signal,
        headers: {
          'a2a-version': VERSION,
          accept: 'application/a2a+json, application/json',
          'content-type': http ? 'application/a2a+json' : 'application/json',
          ...(await this.#source.headers('POST', url)),
        },
        body,
      });
    let res = await sendOnce();
    const key = this.#source.dpop;
    // The remote asked for its nonce: once more, with it.
    if (
      key !== undefined &&
      asksForNonce(res.status, res.headers, textOf(res)) &&
      key.rememberNonce(url, res.headers)
    )
      res = await sendOnce();
    return parseTask(res);
  }

  toString(): string {
    return `RemoteAgent(${JSON.stringify(this.card.name)}, verified=${String(this.card.verified)})`;
  }
}

/** How {@link remote} trusts and reaches the remote agent. */
export interface RemoteOptions extends VerifyOptions {
  /** Take a card with no signature. Say so in the name: nothing proves whose it is. */
  readonly allowUnsigned?: boolean | undefined;
  /** Origins besides the card's own that its interface may point at. */
  readonly allowOrigins?: readonly string[] | undefined;
  /** The resource the token is for (default: the interface's origin). */
  readonly resource?: string | undefined;
  readonly signal?: AbortSignal | undefined;
}

/** Fetches and verifies the card at `url`'s origin, and returns the agent to call. */
export async function remote(
  agent: AgentAuth,
  url: string,
  options: RemoteOptions = {},
): Promise<RemoteAgent> {
  const origin = originOf(url);
  if (origin === undefined) throw new ConfigurationError(`${url} is not a URL`);
  const core = coreOf(agent.project);
  const res = await core.transport.send({
    method: 'GET',
    url: origin + WELL_KNOWN,
    retry: 'safe',
    signal: options.signal,
    maxBytes: MAX_DOCUMENT_BYTES,
  });
  let card = parseCard(res);
  if (!(options.allowUnsigned === true && !card.raw.signatures)) card = await verifyCard(card, options);
  const iface = interfaceOf(card);
  const target = originOf(iface.url);
  if (target === undefined || (target !== origin && !(options.allowOrigins ?? []).includes(target))) {
    throw new A2AError(
      'interface_origin',
      `${card.name}'s card points its interface at ${target ?? iface.url}, not ${origin}. Pass allowOrigins: [${JSON.stringify(target)}] if you trust that, or the token will not be sent.`,
    );
  }
  if (!card.schemes.some((s) => SPOKEN.includes(s))) {
    throw new A2AError(
      'no_scheme',
      `${card.name} accepts ${card.schemes.length === 0 ? 'no declared authentication' : JSON.stringify(card.schemes)}; this SDK presents an OAuth 2 or HTTP bearer token`,
    );
  }
  const source = agent.forResource(options.resource ?? target, { sendTo: [target] });
  return new RemoteAgent(agent, card, iface, source);
}
