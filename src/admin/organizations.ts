import { ConfigurationError, TransportError } from '../core/errors.js';
import { isSecret, Secret } from '../core/secret.js';
import {
  eachItem,
  fromWire,
  pageOf,
  segment,
  toWire,
  type AdminHttp,
  type CallOptions,
  type ListOptions,
  type Page,
} from './http.js';

/** A business customer of the project (a B2B organization). */
export interface Organization {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  /** The business details captured at sign-up or edited since; always an object. */
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateOrganization {
  /** The URL-safe handle, unique in the project. */
  readonly slug: string;
  readonly displayName: string;
}

export interface UpdateOrganization {
  readonly displayName?: string | undefined;
  /** Replaces the whole business-details object. */
  readonly attributes?: Readonly<Record<string, unknown>> | undefined;
}

/** A user's place in an organization. The role is the organization's own (such as `member`, `admin`), not a PDP role. */
export interface OrganizationMember {
  readonly userId: string;
  readonly role: string;
  readonly createdAt: string;
}

export interface AddMember {
  readonly userId: string;
  /** Defaults to `member`. */
  readonly role?: string | undefined;
}

/** An invitation to join an organization. */
export interface Invitation {
  readonly id: string;
  readonly orgId: string;
  readonly email: string;
  readonly role: string;
  /** The one-time accept token; email it to the invitee. A {@link Secret}, so it never reaches a log. */
  readonly token: Secret;
  /** The existing user whose email matches, when there is one. */
  readonly userId: string | undefined;
  readonly status: string;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export interface CreateInvitation {
  readonly email: string;
  /** Defaults to `member`. */
  readonly role?: string | undefined;
  /** The user id of the administrator inviting, for the audit trail. */
  readonly invitedBy?: string | undefined;
}

/** A request by a person to join an organization. */
export interface JoinRequest {
  readonly id: string;
  readonly orgId: string;
  readonly orgName: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string;
  readonly status: string;
  readonly createdAt: string;
  readonly decidedAt: string | null;
  readonly decidedBy: string;
}

/** An email domain an organization owns. */
export interface OrganizationDomain {
  readonly domain: string;
  readonly claimedVia: string;
  readonly claimedBy: string;
  readonly createdAt: string;
}

const organization = (raw: Record<string, unknown>): Organization => fromWire<Organization>(raw);
const member = (raw: Record<string, unknown>): OrganizationMember => fromWire<OrganizationMember>(raw);
const joinRequest = (raw: Record<string, unknown>): JoinRequest => fromWire<JoinRequest>(raw);
const domainOf = (raw: Record<string, unknown>): OrganizationDomain => fromWire<OrganizationDomain>(raw);

function invitation(raw: Record<string, unknown>): Invitation {
  const { token, ...rest } = fromWire<Record<string, unknown>>(raw);
  if (typeof token !== 'string' || token === '') {
    throw new TransportError('response_invalid', 'the platform answered an invitation without its token', {
      retryable: false,
    });
  }
  return { ...rest, token: new Secret(token) } as unknown as Invitation;
}

/** The members of one organization: `admin.organizations.members`. */
export class OrganizationMembers {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  /** The organization's members and their organization role. */
  async list(orgId: string, options: CallOptions = {}): Promise<Page<OrganizationMember>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: `/organizations/${segment(orgId, 'orgId')}/members`,
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      member,
    );
  }

  /** Adds a user (or changes their role when they are already a member, as the platform decides). */
  async add(orgId: string, input: AddMember, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'POST',
      path: `/organizations/${segment(orgId, 'orgId')}/members`,
      body: toWire({ userId: input.userId, role: input.role }),
      ok: [200],
      retry: 'unsafe',
      signal: options.signal,
    });
  }

  async remove(orgId: string, userId: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'DELETE',
      path: `/organizations/${segment(orgId, 'orgId')}/members/${segment(userId, 'userId')}`,
      ok: [200],
      retry: 'unsafe',
      signal: options.signal,
    });
  }
}

/** The invitations of one organization: `admin.organizations.invitations`. */
export class OrganizationInvitations {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  /** Creates a pending invitation. The platform does not email it: send `token` to the invitee yourself. */
  async create(orgId: string, input: CreateInvitation, options: CallOptions = {}): Promise<Invitation> {
    return invitation(
      await this.#http.object({
        method: 'POST',
        path: `/organizations/${segment(orgId, 'orgId')}/invitations`,
        body: toWire({ email: input.email, role: input.role, invitedBy: input.invitedBy }),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  async list(orgId: string, options: CallOptions = {}): Promise<Page<Invitation>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: `/organizations/${segment(orgId, 'orgId')}/invitations`,
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      invitation,
    );
  }

  async revoke(orgId: string, invitationId: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'DELETE',
      path: `/organizations/${segment(orgId, 'orgId')}/invitations/${segment(invitationId, 'invitationId')}`,
      ok: [204],
      retry: 'unsafe',
      signal: options.signal,
    });
  }

  /**
   * Accepts an invitation. Call it with the INVITEE's own credential (their access token in a
   * `Secret`), not an administrator's or a machine client's: the platform adds `userId` only when the
   * caller is that user and the invitation is addressed to them.
   */
  async accept(
    input: { readonly token: Secret; readonly userId: string },
    options: CallOptions = {},
  ): Promise<Invitation> {
    if (!isSecret(input.token)) {
      throw new ConfigurationError('the invitation token must be a Secret: new Secret(tokenFromTheLink)');
    }
    return invitation(
      await this.#http.object({
        method: 'POST',
        path: '/organizations/invitations/accept',
        body: toWire({ token: input.token.reveal(), userId: input.userId }),
        ok: [200],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }
}

/**
 * People asking to join an organization. The platform lets only the organization's own owners and
 * admins list and decide them, and only the person themselves see or withdraw theirs, so these calls
 * need a PERSON's credential. A machine client is refused (403). Asking to join happens at sign-up
 * and is not part of the public API.
 */
export class OrganizationJoinRequests {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  /** The organization's requests; `status` filters, such as `pending`. */
  async list(
    orgId: string,
    options: CallOptions & { readonly status?: string | undefined } = {},
  ): Promise<readonly JoinRequest[]> {
    const rows = await this.#http.array({
      method: 'GET',
      path: `/organizations/${segment(orgId, 'orgId')}/join-requests`,
      query: { status: options.status },
      ok: [200],
      retry: 'safe',
      signal: options.signal,
    });
    return rows.map(joinRequest);
  }

  approve(orgId: string, requestId: string, options: CallOptions = {}): Promise<JoinRequest> {
    return this.#decide('approve', orgId, requestId, options);
  }

  decline(orgId: string, requestId: string, options: CallOptions = {}): Promise<JoinRequest> {
    return this.#decide('decline', orgId, requestId, options);
  }

  /** The signed-in person's own requests. */
  async mine(options: CallOptions = {}): Promise<readonly JoinRequest[]> {
    const rows = await this.#http.array({
      method: 'GET',
      path: '/organizations/join-requests/mine',
      ok: [200],
      retry: 'safe',
      signal: options.signal,
    });
    return rows.map(joinRequest);
  }

  /** The signed-in person withdraws their own pending request. */
  async withdraw(requestId: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'POST',
      path: `/organizations/join-requests/${segment(requestId, 'requestId')}/withdraw`,
      ok: [204],
      retry: 'unsafe',
      signal: options.signal,
    });
  }

  async #decide(
    verb: 'approve' | 'decline',
    orgId: string,
    requestId: string,
    options: CallOptions,
  ): Promise<JoinRequest> {
    return joinRequest(
      await this.#http.object({
        method: 'POST',
        path: `/organizations/${segment(orgId, 'orgId')}/join-requests/${segment(requestId, 'requestId')}/${verb}`,
        ok: [200],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }
}

/**
 * Organizations: `admin.organizations`. Needs the project's plan to include organizations and the
 * credential to hold `read:organizations` / `manage:organizations`.
 */
export class Organizations {
  readonly members: OrganizationMembers;
  readonly invitations: OrganizationInvitations;
  readonly joinRequests: OrganizationJoinRequests;
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
    this.members = new OrganizationMembers(http);
    this.invitations = new OrganizationInvitations(http);
    this.joinRequests = new OrganizationJoinRequests(http);
  }

  async create(input: CreateOrganization, options: CallOptions = {}): Promise<Organization> {
    return organization(
      await this.#http.object({
        method: 'POST',
        path: '/organizations',
        body: toWire({ slug: input.slug, displayName: input.displayName }),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  async get(id: string, options: CallOptions = {}): Promise<Organization> {
    return organization(
      await this.#http.object({
        method: 'GET',
        path: `/organizations/${segment(id, 'id')}`,
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
    );
  }

  /** One page of organizations. */
  async list(options: ListOptions = {}): Promise<Page<Organization>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: '/organizations',
        query: { limit: options.limit, cursor: options.cursor },
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      organization,
    );
  }

  /** Every organization, a page at a time: `for await (const org of admin.organizations.all())`. */
  all(options: ListOptions = {}): AsyncGenerator<Organization, void, undefined> {
    return eachItem((cursor) => this.list({ ...options, cursor }), options.cursor);
  }

  async update(id: string, input: UpdateOrganization, options: CallOptions = {}): Promise<Organization> {
    return organization(
      await this.#http.object({
        method: 'PATCH',
        path: `/organizations/${segment(id, 'id')}`,
        body: toWire({ displayName: input.displayName, attributes: input.attributes }),
        ok: [200],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  async delete(id: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'DELETE',
      path: `/organizations/${segment(id, 'id')}`,
      ok: [204],
      retry: 'unsafe',
      signal: options.signal,
    });
  }

  /** The email domains the organization owns. Needs a person who is an owner or admin of it. */
  async domains(id: string, options: CallOptions = {}): Promise<readonly OrganizationDomain[]> {
    const rows = await this.#http.array({
      method: 'GET',
      path: `/organizations/${segment(id, 'id')}/domains`,
      ok: [200],
      retry: 'safe',
      signal: options.signal,
    });
    return rows.map(domainOf);
  }
}
