/**
 * SAML 2.0 sign-in for a standard app: AuthFI is the identity provider, your app the service provider.
 * Install the optional peers (`@node-saml/node-saml` and `@xmldom/xmldom`), register the app in the
 * project with its entity id and assertion consumer URL, and read the project's metadata:
 *
 * @example
 * const af = new AuthFI({ issuer: process.env.AUTHFI_ISSUER! });
 * const sp = await SamlServiceProvider.fromProject(af, {
 *   spEntityId: 'https://app.example.com/saml',
 *   acsUrl: 'https://app.example.com/saml/acs',
 * });
 *
 * // GET /login
 * const pending = await sp.startSignIn('/dashboard');
 * req.session.saml = pending.dump();
 * res.redirect(pending.url);
 *
 * // POST /saml/acs
 * const signedIn = await sp.finishSignIn(req.body.SAMLResponse, PendingSamlSignIn.load(req.session.saml));
 * signedIn.user.sub; signedIn.user.email;
 *
 * Only a signed assertion is accepted, signed by a key in the project's metadata. The audience, the
 * recipient, `InResponseTo`, the issuer and the validity window are checked against what you configured,
 * never against the request that arrived. An assertion is accepted once.
 *
 * @packageDocumentation
 */

import {
  SAML,
  ValidateInResponseTo,
  type CacheItem,
  type CacheProvider,
  type SamlConfig,
} from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import { randomBytes } from '../core/bytes.js';
import { AuthFIError, ConfigurationError, DiscoveryError } from '../core/errors.js';
import { coreOf, type AuthFI } from '../core/project.js';
import { contextOf, MAX_DOCUMENT_BYTES, textOf } from '../core/transport.js';
import type { IdTokenClaims } from '../signin/id-token.js';

/** The project's IdP metadata, relative to its origin. */
export const METADATA_PATH = '/saml/metadata';
/** The largest SAMLResponse read, in characters. */
export const RESPONSE_LIMIT = 1024 * 1024;
/** How long a started sign-in may be finished, as the platform keeps its request ids (10 minutes). */
export const PENDING_LIFETIME_MS = 600_000;
const MAX_LEEWAY_MS = 300_000;

const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const POST_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const SIGNATURE_METHOD = /<(?:[\w.-]+:)?SignatureMethod\s[^>]*?Algorithm\s*=\s*"([^"]+)"/g;
const DIGEST_METHOD = /<(?:[\w.-]+:)?DigestMethod\s[^>]*?Algorithm\s*=\s*"([^"]+)"/g;
const STRONG_SIGNATURES = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
]);
const STRONG_DIGESTS = new Set([
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384',
  'http://www.w3.org/2001/04/xmlenc#sha512',
]);

/** Attribute names read for each field of the user, first match wins. Pass `attributes` to change them. */
export const DEFAULT_ATTRIBUTES: Readonly<Record<'email' | 'name' | 'groups' | 'roles', readonly string[]>> =
  {
    email: ['email', 'mail', 'emailAddress'],
    name: ['name', 'full_name', 'displayName'],
    groups: ['groups'],
    roles: ['roles'],
  };

/**
 * A SAML response was refused, or a SAML sign-in could not be restored. `code` names why:
 * `saml_signature_missing`, `saml_signature_invalid`, `saml_audience_mismatch`, `saml_issuer_mismatch`,
 * `saml_in_response_to_mismatch`, `saml_recipient_mismatch`, `saml_assertion_expired`,
 * `saml_assertion_not_yet_valid`, `saml_assertion_replayed`, `saml_unsolicited`, `saml_xml_invalid`,
 * `saml_pending_expired`, `saml_pending_malformed` and the other `saml_` codes. The message never carries
 * the assertion.
 */
export class SamlAssertionRefused extends AuthFIError {
  override readonly name: string = 'SamlAssertionRefused';
  constructor(code: string, detail: string) {
    super(code, `The SAML response was refused (${code}): ${detail}`, { status: 401 });
  }
}

/** The project as a SAML identity provider, read from its metadata. */
export interface SamlIdp {
  readonly entityId: string;
  readonly ssoUrl: string;
  /** The signing certificates (base64 DER). Only these may sign an assertion. */
  readonly signingCerts: readonly string[];
}

/** Remembers what was used, so it is accepted once. Share one across processes (Redis, a database). */
export interface ReplayStore {
  /** Records `key` until `expiresAtMs` and resolves `true`; resolves `false` when it is already held. */
  remember(key: string, expiresAtMs: number, nowMs: number): boolean | Promise<boolean>;
}

/** A replay store for one process. Full of live entries, it refuses rather than forget one. */
export class InMemoryReplayStore implements ReplayStore {
  readonly #max: number;
  #seen = new Map<string, number>();

  constructor(maxEntries = 100_000) {
    this.#max = maxEntries;
  }

  remember(key: string, expiresAtMs: number, nowMs: number): boolean {
    const held = this.#seen.get(key);
    if (held !== undefined && held > nowMs) return false;
    if (this.#seen.size >= this.#max) {
      for (const [k, v] of this.#seen) if (v <= nowMs) this.#seen.delete(k);
      if (this.#seen.size >= this.#max) {
        throw new SamlAssertionRefused('saml_replay_store_full', 'the replay store holds only live entries');
      }
    }
    this.#seen.set(key, expiresAtMs);
    return true;
  }
}

/** A started sign-in: where to send the browser, and what the response must answer. */
export class PendingSamlSignIn {
  readonly url: string;
  readonly requestId: string;
  readonly relayState: string | undefined;
  /** Epoch milliseconds. */
  readonly expiresAt: number;

  constructor(url: string, requestId: string, relayState: string | undefined, expiresAt: number) {
    this.url = url;
    this.requestId = requestId;
    this.relayState = relayState;
    this.expiresAt = expiresAt;
  }

  /** A string to keep in the server-side session between the redirect and the response. */
  dump(): string {
    return JSON.stringify({
      id: this.requestId,
      rs: this.relayState ?? null,
      exp: this.expiresAt,
      url: this.url,
    });
  }

  /** The pending sign-in {@link PendingSamlSignIn.dump} made; anything else is a {@link SamlAssertionRefused}. */
  static load(text: string): PendingSamlSignIn {
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      throw new SamlAssertionRefused('saml_pending_malformed', 'the pending sign-in is not one');
    }
    const d = data as Record<string, unknown> | null;
    if (
      typeof d !== 'object' ||
      d === null ||
      typeof d.id !== 'string' ||
      d.id === '' ||
      typeof d.url !== 'string' ||
      !(d.rs === null || typeof d.rs === 'string') ||
      typeof d.exp !== 'number' ||
      !Number.isFinite(d.exp)
    ) {
      throw new SamlAssertionRefused('saml_pending_malformed', 'the pending sign-in is not one');
    }
    return new PendingSamlSignIn(d.url, d.id, d.rs ?? undefined, d.exp);
  }

  toString(): string {
    return `PendingSamlSignIn(${this.url.split('?')[0] ?? ''})`;
  }
}

/** A finished SAML sign-in. */
export interface SamlSignIn {
  /** Who signed in. `sub` is the assertion's NameID; `emailVerified` is never claimed. */
  readonly user: IdTokenClaims;
  readonly assertionId: string;
  readonly sessionIndex: string | undefined;
  /** The `RelayState` you passed to `startSignIn`; undefined for an IdP-initiated one. */
  readonly relayState: string | undefined;
  /** When the IdP session ends, if it said. */
  readonly sessionNotOnOrAfter: Date | undefined;
}

/** Options of {@link SamlServiceProvider}. */
export interface SamlServiceProviderOptions {
  /** The entity id the app is registered under in the project; the audience of its assertions. */
  readonly spEntityId: string;
  /** The app's assertion consumer URL, registered in the project. The recipient is checked against this value. */
  readonly acsUrl: string;
  /** Seconds of clock skew allowed on the validity window, in milliseconds (0 to 300 000). */
  readonly leewayMs?: number | undefined;
  /** The clock in epoch milliseconds, for tests. */
  readonly now?: (() => number) | undefined;
  /** Where used assertions are remembered. One per process by default. */
  readonly replayStore?: ReplayStore | undefined;
  /**
   * Accept a response that answers no request of yours. Off by default; turn it on only for an app
   * launched from the AuthFI portal, and never rely on `RelayState` then.
   */
  readonly allowIdpInitiated?: boolean | undefined;
  /** Attribute names per user field, replacing {@link DEFAULT_ATTRIBUTES}. */
  readonly attributes?: Partial<Record<keyof typeof DEFAULT_ATTRIBUTES, readonly string[]>> | undefined;
}

function textOfNode(node: Element): string {
  return node.textContent.replace(/\s+/g, '');
}

/** The {@link SamlIdp} described by `xml`, which must name `expectedEntityId`. */
export function parseIdpMetadata(xml: string, expectedEntityId: string): SamlIdp {
  const bad = (message: string): DiscoveryError => new DiscoveryError('discovery_failed', message);
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw bad('The SAML metadata declares a DTD.');
  let doc: Document;
  try {
    const refuse = (): never => {
      throw new Error('malformed');
    };
    doc = new DOMParser({
      errorHandler: { warning: () => undefined, error: refuse, fatalError: refuse },
    }).parseFromString(xml, 'text/xml');
  } catch {
    throw bad('The SAML metadata is not valid XML.');
  }
  const root = doc.documentElement as Element | null;
  if (root?.localName !== 'EntityDescriptor' || root.namespaceURI !== MD) {
    throw bad('The SAML metadata is not one EntityDescriptor.');
  }
  const entityId = root.getAttribute('entityID');
  if (entityId !== expectedEntityId) {
    throw bad(
      `The SAML metadata names ${JSON.stringify(entityId)}, not ${JSON.stringify(expectedEntityId)}: it is not this project's.`,
    );
  }
  const idps = [...Array.from(root.childNodes)].filter(
    (n): n is Element => n.nodeType === 1 && (n as Element).localName === 'IDPSSODescriptor',
  );
  const idp = idps.length === 1 ? idps[0] : undefined;
  if (idp === undefined) throw bad('The SAML metadata has no identity provider role.');
  const children = (parent: Element, name: string, ns: string): Element[] =>
    Array.from(parent.childNodes).filter(
      (n): n is Element =>
        n.nodeType === 1 && (n as Element).localName === name && (n as Element).namespaceURI === ns,
    );
  const sso = new Map<string, string>();
  for (const s of children(idp, 'SingleSignOnService', MD)) {
    sso.set(s.getAttribute('Binding') ?? '', s.getAttribute('Location') ?? '');
  }
  const redirect = sso.get(REDIRECT);
  const ssoUrl = redirect !== undefined && redirect !== '' ? redirect : sso.get(POST_BINDING);
  if (ssoUrl === undefined || !/^https?:\/\//.test(ssoUrl))
    throw bad('The SAML metadata has no sign-on URL.');
  const certs: string[] = [];
  for (const key of children(idp, 'KeyDescriptor', MD)) {
    const use = key.getAttribute('use');
    if (use !== null && use !== '' && use !== 'signing') continue;
    const data = key.getElementsByTagNameNS(DS, 'X509Certificate')[0];
    if (data !== undefined && textOfNode(data) !== '') certs.push(textOfNode(data));
  }
  if (certs.length === 0) throw bad('The SAML metadata has no signing certificate.');
  return { entityId, ssoUrl, signingCerts: Object.freeze(certs) };
}

/** One request id, held for the single response that may answer it. */
class OneRequest implements CacheProvider {
  #held: string | null;
  constructor(requestId: string | null) {
    this.#held = requestId;
  }
  saveAsync(_key: string, value: string): Promise<CacheItem | null> {
    return Promise.resolve({ value, createdAt: 0 });
  }
  getAsync(key: string): Promise<string | null> {
    // The library reads the value as the time the request was made.
    return Promise.resolve(key === this.#held ? new Date().toISOString() : null);
  }
  removeAsync(key: string | null): Promise<string | null> {
    if (key !== null && key === this.#held) {
      this.#held = null;
      return Promise.resolve(new Date().toISOString());
    }
    return Promise.resolve(null);
  }
  consumeAsync(key: string): Promise<string | null> {
    return this.removeAsync(key);
  }
}

type Xml = Record<string, unknown>;

function first(value: unknown): Xml | undefined {
  return Array.isArray(value) && typeof value[0] === 'object' && value[0] !== null
    ? (value[0] as Xml)
    : undefined;
}

function list(value: unknown): Xml[] {
  return Array.isArray(value) ? value.filter((v): v is Xml => typeof v === 'object' && v !== null) : [];
}

function attrOf(node: Xml | undefined, name: string): string | undefined {
  const attrs = node?.$;
  if (typeof attrs !== 'object' || attrs === null) return undefined;
  const v = (attrs as Record<string, unknown>)[name];
  return typeof v === 'string' ? v : undefined;
}

function textValue(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'object' && value !== null && typeof (value as Xml)._ === 'string') {
    return (value as Xml)._ as string;
  }
  return undefined;
}

function times(node: Xml | undefined, name: string): number | undefined {
  const v = attrOf(node, name);
  if (v === undefined) return undefined;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? undefined : ms;
}

function refusal(error: unknown): SamlAssertionRefused {
  if (error instanceof SamlAssertionRefused) return error;
  const message = error instanceof Error ? error.message : '';
  const table: [RegExp, string][] = [
    [/multiple assertions/i, 'saml_assertion_count'],
    [/Invalid (document )?signature|Cannot obtain assertion/i, 'saml_signature_invalid'],
    [/audience/i, 'saml_audience_mismatch'],
    [/not yet valid/i, 'saml_assertion_not_yet_valid'],
    [/expired/i, 'saml_assertion_expired'],
    [/InResponseTo/i, 'saml_in_response_to_mismatch'],
    [/issuer/i, 'saml_issuer_mismatch'],
    [/subject confirmation/i, 'saml_recipient_mismatch'],
    [/Missing SAML assertion|SAML provider returned/i, 'saml_status_not_success'],
  ];
  for (const [pattern, code] of table)
    if (pattern.test(message)) return new SamlAssertionRefused(code, message.slice(0, 200));
  return new SamlAssertionRefused('saml_assertion_invalid', 'the response could not be validated');
}

/** Your app as a service provider of one AuthFI project. */
export class SamlServiceProvider {
  readonly #idp: SamlIdp;
  readonly #o: {
    readonly spEntityId: string;
    readonly acsUrl: string;
    readonly leewayMs: number;
    readonly now: () => number;
    readonly allowIdpInitiated: boolean;
  };
  readonly #replay: ReplayStore;
  readonly #attributes: Record<keyof typeof DEFAULT_ATTRIBUTES, readonly string[]>;

  constructor(idp: SamlIdp, options: SamlServiceProviderOptions) {
    if (typeof options.spEntityId !== 'string' || options.spEntityId.trim() === '') {
      throw new ConfigurationError('spEntityId is required');
    }
    let acs: URL;
    try {
      acs = new URL(options.acsUrl);
    } catch {
      throw new ConfigurationError('acsUrl must be a URL');
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(acs.hostname);
    if (acs.protocol !== 'https:' && !(acs.protocol === 'http:' && loopback)) {
      throw new ConfigurationError('acsUrl must be an https URL (plain http only for loopback)');
    }
    const leewayMs = options.leewayMs ?? 60_000;
    if (!Number.isFinite(leewayMs) || leewayMs < 0 || leewayMs > MAX_LEEWAY_MS) {
      throw new ConfigurationError('leewayMs must be from 0 to 300000');
    }
    this.#idp = idp;
    this.#o = {
      spEntityId: options.spEntityId,
      acsUrl: options.acsUrl,
      leewayMs,
      now: options.now ?? (() => Date.now()),
      allowIdpInitiated: options.allowIdpInitiated ?? false,
    };
    this.#replay = options.replayStore ?? new InMemoryReplayStore();
    this.#attributes = { ...DEFAULT_ATTRIBUTES, ...options.attributes };
  }

  /** Reads the project's metadata from `<origin>/saml/metadata` and builds the provider. */
  static async fromProject(af: AuthFI, options: SamlServiceProviderOptions): Promise<SamlServiceProvider> {
    const core = coreOf(af);
    const url = new URL(af.issuer).origin + METADATA_PATH;
    const res = await core.transport.send({
      method: 'GET',
      url,
      retry: 'safe',
      maxBytes: MAX_DOCUMENT_BYTES,
      headers: { accept: 'application/samlmetadata+xml, application/xml' },
    });
    if (res.status !== 200) {
      throw new DiscoveryError(
        'discovery_failed',
        `The SAML metadata at ${url} answered HTTP ${String(res.status)}`,
        contextOf(res),
      );
    }
    const idp = parseIdpMetadata(textOf(res), url);
    return new SamlServiceProvider(idp, {
      leewayMs: core.leewayMs,
      now: () => core.clock.now(),
      ...options,
    });
  }

  /** The identity provider this provider trusts. */
  get idp(): SamlIdp {
    return this.#idp;
  }

  #saml(cache: CacheProvider, mode: ValidateInResponseTo, requestId?: string): SAML {
    return new SAML({
      callbackUrl: this.#o.acsUrl,
      entryPoint: this.#idp.ssoUrl,
      issuer: this.#o.spEntityId,
      idpIssuer: this.#idp.entityId,
      idpCert: [...this.#idp.signingCerts],
      audience: this.#o.spEntityId,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      // -1 turns the library's time checks off: the window is checked by `#check`, with this provider's
      // leeway, so every refusal of it carries the same code as the Python SDK's.
      acceptedClockSkewMs: -1,
      validateInResponseTo: mode,
      cacheProvider: cache,
      disableRequestedAuthnContext: true,
      identifierFormat: null,
      signatureAlgorithm: 'sha256',
      ...(requestId === undefined ? {} : { generateUniqueId: () => requestId }),
    } satisfies SamlConfig);
  }

  /** The redirect that sends the browser to AuthFI, and the request id the response must answer. */
  async startSignIn(relayState?: string): Promise<PendingSamlSignIn> {
    const requestId = '_' + Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, '0')).join('');
    const url = await this.#saml(
      new OneRequest(requestId),
      ValidateInResponseTo.always,
      requestId,
    ).getAuthorizeUrlAsync(relayState ?? '', undefined, {});
    return new PendingSamlSignIn(url, requestId, relayState, this.#o.now() + PENDING_LIFETIME_MS);
  }

  /**
   * Validates the `SAMLResponse` form field of the POST to your ACS and returns who signed in. `pending` is
   * what {@link SamlServiceProvider.startSignIn} returned for this browser; `undefined` accepts an
   * unsolicited (IdP-initiated) response, and only when `allowIdpInitiated` is set. Throws
   * {@link SamlAssertionRefused} with the reason, whatever is wrong.
   */
  async finishSignIn(samlResponse: string, pending: PendingSamlSignIn | undefined): Promise<SamlSignIn> {
    const now = this.#o.now();
    if (pending === undefined) {
      if (!this.#o.allowIdpInitiated) {
        throw new SamlAssertionRefused('saml_unsolicited', 'no sign-in was started for this response');
      }
    } else if (now > pending.expiresAt) {
      throw new SamlAssertionRefused('saml_pending_expired', 'the sign-in was started too long ago');
    }
    const text = this.#decode(samlResponse);
    const saml = this.#saml(
      new OneRequest(pending?.requestId ?? null),
      pending === undefined ? ValidateInResponseTo.ifPresent : ValidateInResponseTo.always,
    );
    let profile: Awaited<ReturnType<SAML['validatePostResponseAsync']>>['profile'];
    try {
      ({ profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse }));
    } catch (error) {
      throw refusal(error);
    }
    const assertion = (profile?.getAssertion?.() as Xml | undefined)?.Assertion as Xml | undefined;
    if (profile === null || assertion === undefined) {
      throw new SamlAssertionRefused('saml_assertion_invalid', 'the response carries no assertion');
    }
    this.#checkAlgorithms(text);
    const { assertionId, notOnOrAfter } = this.#check(assertion, pending, now);
    const signedIn = this.#signIn(assertion, assertionId, pending);
    const expires = notOnOrAfter + this.#o.leewayMs;
    const keys = [`assertion:${assertionId}`, ...(pending ? [`request:${pending.requestId}`] : [])];
    for (const key of keys) {
      if (!(await this.#replay.remember(key, expires, now))) {
        throw new SamlAssertionRefused('saml_assertion_replayed', 'this response was already used');
      }
    }
    return signedIn;
  }

  #decode(samlResponse: string): string {
    const given: unknown = samlResponse;
    if (typeof given !== 'string' || given === '' || given.length > RESPONSE_LIMIT) {
      throw new SamlAssertionRefused('saml_xml_invalid', 'the SAMLResponse is empty or too large');
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(given) || given.length % 4 !== 0) {
      throw new SamlAssertionRefused('saml_xml_invalid', 'the SAMLResponse is not base64');
    }
    const text = atob(given);
    if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
      throw new SamlAssertionRefused('saml_xml_invalid', 'the SAMLResponse declares a DTD');
    }
    return text;
  }

  /**
   * Every signature and digest algorithm the response names must be a strong one. The library hands back the
   * assertion without its signature, so the response as received is read: a weak decoy only makes it refuse.
   */
  #checkAlgorithms(text: string): void {
    const methods = [...text.matchAll(SIGNATURE_METHOD)].map((m) => m[1]);
    const digests = [...text.matchAll(DIGEST_METHOD)].map((m) => m[1]);
    if (
      methods.length === 0 ||
      digests.length === 0 ||
      !methods.every((m) => m !== undefined && STRONG_SIGNATURES.has(m)) ||
      !digests.every((d) => d !== undefined && STRONG_DIGESTS.has(d))
    ) {
      throw new SamlAssertionRefused(
        'saml_algorithm_rejected',
        'the response is not signed with SHA-256 or stronger',
      );
    }
  }

  /** The checks the library leaves to its next major version, and the time window with this provider's leeway. */
  #check(
    assertion: Xml,
    pending: PendingSamlSignIn | undefined,
    now: number,
  ): { assertionId: string; notOnOrAfter: number } {
    const assertionId = attrOf(assertion, 'ID');
    if (assertionId === undefined || assertionId === '') {
      throw new SamlAssertionRefused('saml_id_missing', 'the assertion has no ID');
    }
    // @node-saml 5.0 does not compare the assertion's Issuer when only the assertion is signed.
    if (
      textValue(Array.isArray(assertion.Issuer) ? (assertion.Issuer as unknown[])[0] : undefined) !==
      this.#idp.entityId
    ) {
      throw new SamlAssertionRefused('saml_issuer_mismatch', 'the assertion is from another issuer');
    }
    const conditions = first(assertion.Conditions);
    const ends = times(conditions, 'NotOnOrAfter');
    if (ends === undefined) {
      throw new SamlAssertionRefused('saml_assertion_expired', 'the assertion has no usable validity window');
    }
    if (now - this.#o.leewayMs >= ends) {
      throw new SamlAssertionRefused(
        'saml_assertion_expired',
        'the assertion is outside its validity window',
      );
    }
    const begins = times(conditions, 'NotBefore');
    if (begins !== undefined && now + this.#o.leewayMs < begins) {
      throw new SamlAssertionRefused('saml_assertion_not_yet_valid', 'the assertion is not valid yet');
    }
    const confirmations = list(first(assertion.Subject)?.SubjectConfirmation).filter(
      (c) => attrOf(c, 'Method') === BEARER,
    );
    const data = confirmations.map((c) => first(c.SubjectConfirmationData));
    const named = data.filter((d) => attrOf(d, 'Recipient') === this.#o.acsUrl);
    if (named.length === 0) {
      throw new SamlAssertionRefused('saml_recipient_mismatch', 'no bearer confirmation names this ACS');
    }
    const timely = named.some((d) => {
      const until = times(d, 'NotOnOrAfter');
      return until !== undefined && now - this.#o.leewayMs < until;
    });
    if (!timely) {
      throw new SamlAssertionRefused('saml_assertion_expired', 'the signed confirmation has expired');
    }
    return { assertionId, notOnOrAfter: ends };
  }

  #signIn(assertion: Xml, assertionId: string, pending: PendingSamlSignIn | undefined): SamlSignIn {
    const nameNode = (first(assertion.Subject)?.NameID as unknown[] | undefined)?.[0];
    const sub = textValue(nameNode);
    if (sub === undefined || sub === '') {
      throw new SamlAssertionRefused('saml_name_id_missing', 'the assertion names nobody');
    }
    const format = attrOf(typeof nameNode === 'object' ? (nameNode as Xml) : undefined, 'Format');
    const attributes = new Map<string, string[]>();
    for (const statement of list(assertion.AttributeStatement)) {
      for (const attribute of list(statement.Attribute)) {
        const name = attrOf(attribute, 'Name');
        if (name === undefined) continue;
        if (attributes.has(name)) {
          throw new SamlAssertionRefused(
            'saml_attribute_duplicated',
            'the assertion repeats an attribute name',
          );
        }
        attributes.set(
          name,
          (Array.isArray(attribute.AttributeValue) ? (attribute.AttributeValue as unknown[]) : [])
            .map(textValue)
            .filter((v): v is string => v !== undefined && v !== ''),
        );
      }
    }
    const pick = (field: keyof typeof DEFAULT_ATTRIBUTES): string[] => {
      for (const name of this.#attributes[field]) {
        const values = attributes.get(name);
        if (values !== undefined && values.length > 0) return values;
      }
      return [];
    };
    const emails = pick('email');
    const email = emails[0] ?? (format === EMAIL_FORMAT && sub.includes('@') ? sub : undefined);
    const authn = first(assertion.AuthnStatement);
    const context = textValue(
      (first(authn?.AuthnContext)?.AuthnContextClassRef as unknown[] | undefined)?.[0],
    );
    const instant = times(authn, 'AuthnInstant');
    const claims: Record<string, unknown> = Object.freeze({
      sub,
      ...(email === undefined ? {} : { email }),
      saml_attributes: Object.fromEntries(attributes),
    });
    const user: IdTokenClaims = Object.freeze({
      sub,
      email,
      emailVerified: undefined,
      name: pick('name')[0],
      acr: context,
      amr: Object.freeze(['saml']),
      authTime: instant === undefined ? undefined : new Date(instant),
      sid: undefined,
      groups: Object.freeze(pick('groups')),
      roles: Object.freeze(pick('roles')),
      claims,
    });
    const sessionEnds = times(authn, 'SessionNotOnOrAfter');
    return {
      user,
      assertionId,
      sessionIndex: attrOf(authn, 'SessionIndex'),
      relayState: pending?.relayState,
      sessionNotOnOrAfter: sessionEnds === undefined ? undefined : new Date(sessionEnds),
    };
  }
}
