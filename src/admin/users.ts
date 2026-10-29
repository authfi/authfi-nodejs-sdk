import { ConfigurationError } from '../core/errors.js';
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

/** The profile fields a user can carry. Each is absent until set. Dates are `YYYY-MM-DD`. */
export interface UserProfile {
  readonly givenName?: string | undefined;
  readonly familyName?: string | undefined;
  readonly middleName?: string | undefined;
  readonly nickname?: string | undefined;
  readonly honorificPrefix?: string | undefined;
  readonly honorificSuffix?: string | undefined;
  readonly pictureUrl?: string | undefined;
  readonly phoneNumber?: string | undefined;
  readonly profileUrl?: string | undefined;
  readonly title?: string | undefined;
  readonly userType?: string | undefined;
  readonly preferredLanguage?: string | undefined;
  readonly locale?: string | undefined;
  readonly timezone?: string | undefined;
  readonly streetAddress?: string | undefined;
  readonly locality?: string | undefined;
  readonly region?: string | undefined;
  readonly postalCode?: string | undefined;
  readonly country?: string | undefined;
  readonly employeeId?: string | undefined;
  readonly costCenter?: string | undefined;
  readonly organization?: string | undefined;
  readonly division?: string | undefined;
  readonly department?: string | undefined;
  readonly hireDate?: string | undefined;
  /** The manager's user id. */
  readonly managerId?: string | undefined;
  readonly birthdate?: string | undefined;
  readonly gender?: string | undefined;
  /** The project's own extensible fields; a JSON object. */
  readonly attributes?: Readonly<Record<string, unknown>> | undefined;
}

/** `active`, `invited` or `suspended`. A suspended user cannot sign in. */
export type UserStatus = 'active' | 'invited' | 'suspended';

/** A person in the project's directory. */
export interface User extends UserProfile {
  readonly id: string;
  /** The identity subject this user signs in as, once linked. */
  readonly subjectId?: string | undefined;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly phoneVerified: boolean;
  readonly displayName: string;
  readonly status: UserStatus | (string & {});
  readonly createdAt: string;
  readonly updatedAt: string;
  /** Absent when the user has never signed in. */
  readonly lastLoginAt?: string | undefined;
}

/**
 * What creating a user takes. There is no `emailVerified` or `phoneVerified`: only the sign-in
 * service proves either, and the platform refuses (403) a call that claims one.
 */
export interface CreateUser extends UserProfile {
  readonly email: string;
  readonly displayName: string;
  /** Links the user to an existing identity subject; leave out to create an unlinked user. */
  readonly subjectId?: string | undefined;
}

/** What updating a user takes: only the fields given change. At least one is required. */
export interface UpdateUser extends UserProfile {
  readonly displayName?: string | undefined;
  readonly status?: UserStatus | undefined;
  /** Removes the reporting line (`managerId: undefined` means leave it alone). */
  readonly clearManager?: boolean | undefined;
}

/** Options for listing users. */
export interface ListUsersOptions extends ListOptions {
  /** A search term, matched by the platform across the directory (not just the page). */
  readonly query?: string | undefined;
}

/** The request body, refusing early the two claims only the sign-in service may make. */
function bodyOf(input: object): Record<string, unknown> {
  for (const claim of ['emailVerified', 'phoneVerified']) {
    if (claim in input) {
      throw new ConfigurationError(
        `${claim} cannot be set through the admin API: only the sign-in service proves an email or a phone`,
      );
    }
  }
  return toWire(input);
}

const user = (raw: Record<string, unknown>): User => fromWire<User>(raw);

/**
 * Users: `admin.users`. The credential needs `read:users` / `manage:users`. Every plan has users, so
 * there is no plan gate.
 */
export class Users {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  async create(input: CreateUser, options: CallOptions = {}): Promise<User> {
    return user(
      await this.#http.object({
        method: 'POST',
        path: '/users',
        body: bodyOf(input),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  async get(id: string, options: CallOptions = {}): Promise<User> {
    return user(
      await this.#http.object({
        method: 'GET',
        path: `/users/${segment(id, 'id')}`,
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
    );
  }

  /** One page of users. */
  async list(options: ListUsersOptions = {}): Promise<Page<User>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: '/users',
        query: { limit: options.limit, cursor: options.cursor, q: options.query },
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      user,
    );
  }

  /** Every user, a page at a time: `for await (const u of admin.users.all({ query: 'ada' }))`. */
  all(options: ListUsersOptions = {}): AsyncGenerator<User, void, undefined> {
    return eachItem((cursor) => this.list({ ...options, cursor }), options.cursor);
  }

  async update(id: string, input: UpdateUser, options: CallOptions = {}): Promise<User> {
    return user(
      await this.#http.object({
        method: 'PATCH',
        path: `/users/${segment(id, 'id')}`,
        body: bodyOf(input),
        ok: [200],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  async delete(id: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'DELETE',
      path: `/users/${segment(id, 'id')}`,
      ok: [204],
      retry: 'unsafe',
      signal: options.signal,
    });
  }
}
