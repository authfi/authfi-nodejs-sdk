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

/** A named set of permissions. */
export interface Role {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  /** A seeded role (such as Owner) that cannot be renamed or deleted. */
  readonly system: boolean;
  readonly createdAt: string;
}

export interface CreateRole {
  /** Unique in the project. */
  readonly name: string;
  readonly description?: string | undefined;
}

/** One `action:resource` capability, such as `read` on `document`. */
export interface Permission {
  readonly id: string;
  readonly action: string;
  readonly resource: string;
  readonly description: string;
  readonly createdAt: string;
}

export interface CreatePermission {
  readonly action: string;
  readonly resource: string;
  readonly description?: string | undefined;
}

/** A role held by a subject. */
export interface Binding {
  readonly id: string;
  /** `user:<id>`, `app:<client id>`, `agent:<agent id>` or `group:<id>`. */
  readonly subject: string;
  readonly roleId: string;
  readonly roleName?: string | undefined;
  readonly roleSystem?: boolean | undefined;
  /** RFC 3339; absent for a binding that does not expire. */
  readonly expiresAt?: string | undefined;
  readonly createdAt: string;
}

export interface AssignBinding {
  /** `user:<id>`, `app:<client id>`, `agent:<agent id>` or `group:<id>`. */
  readonly subject: string;
  readonly roleId: string;
  /** RFC 3339. Leave out for a binding that never expires. */
  readonly expiresAt?: string | undefined;
}

/** Which bindings to list: those a subject holds, or the subjects holding a role. Exactly one. */
export type BindingQuery =
  | { readonly subject: string; readonly role?: undefined }
  | { readonly role: string; readonly subject?: undefined };

const role = (raw: Record<string, unknown>): Role => fromWire<Role>(raw);
const permission = (raw: Record<string, unknown>): Permission => fromWire<Permission>(raw);
const binding = (raw: Record<string, unknown>): Binding => fromWire<Binding>(raw);

/**
 * Roles: `admin.roles`. Reading needs `read:policy`, changing needs `manage:roles`. The platform
 * offers create and the permission set on its public API; renaming and deleting a role are console
 * actions. Roles are tenant-wide: an organization's member role (`admin.organizations`) is a
 * different thing.
 */
export class Roles {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  async list(options: ListOptions = {}): Promise<Page<Role>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: '/roles',
        query: { limit: options.limit, cursor: options.cursor },
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      role,
    );
  }

  /** Every role, a page at a time. */
  all(options: ListOptions = {}): AsyncGenerator<Role, void, undefined> {
    return eachItem((cursor) => this.list({ ...options, cursor }), options.cursor);
  }

  async create(input: CreateRole, options: CallOptions = {}): Promise<Role> {
    return role(
      await this.#http.object({
        method: 'POST',
        path: '/roles',
        body: toWire({ name: input.name, description: input.description }),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  /** The permissions the role grants. */
  async permissions(roleId: string, options: CallOptions = {}): Promise<readonly Permission[]> {
    const rows = await this.#http.array({
      method: 'GET',
      path: `/roles/${segment(roleId, 'roleId')}/permissions`,
      ok: [200],
      retry: 'safe',
      signal: options.signal,
    });
    return rows.map(permission);
  }

  /** Replaces the role's whole permission set with these permission ids. An empty list clears it. */
  async setPermissions(
    roleId: string,
    permissionIds: readonly string[],
    options: CallOptions = {},
  ): Promise<void> {
    await this.#http.call({
      method: 'PUT',
      path: `/roles/${segment(roleId, 'roleId')}/permissions`,
      body: toWire({ permissionIds: [...permissionIds] }),
      ok: [204],
      retry: 'safe',
      signal: options.signal,
    });
  }
}

/** Permissions: `admin.permissions`. Reading needs `read:policy`, creating needs `manage:roles`. */
export class Permissions {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  async list(options: ListOptions = {}): Promise<Page<Permission>> {
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: '/permissions',
        query: { limit: options.limit, cursor: options.cursor },
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      permission,
    );
  }

  all(options: ListOptions = {}): AsyncGenerator<Permission, void, undefined> {
    return eachItem((cursor) => this.list({ ...options, cursor }), options.cursor);
  }

  async create(input: CreatePermission, options: CallOptions = {}): Promise<Permission> {
    return permission(
      await this.#http.object({
        method: 'POST',
        path: '/permissions',
        body: toWire({ action: input.action, resource: input.resource, description: input.description }),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }
}

/** Role bindings: `admin.bindings`. Reading needs `read:policy`, changing needs `manage:roles`. */
export class Bindings {
  readonly #http: AdminHttp;

  constructor(http: AdminHttp) {
    this.#http = http;
  }

  /** Gives a subject a role. */
  async assign(input: AssignBinding, options: CallOptions = {}): Promise<Binding> {
    return binding(
      await this.#http.object({
        method: 'POST',
        path: '/bindings',
        body: toWire({ subject: input.subject, roleId: input.roleId, expiresAt: input.expiresAt }),
        ok: [201],
        retry: 'unsafe',
        signal: options.signal,
      }),
    );
  }

  /** One page of the roles a subject holds (`{ subject }`), or of the subjects holding a role (`{ role }`). */
  async list(query: BindingQuery, options: ListOptions = {}): Promise<Page<Binding>> {
    if ((query.subject === undefined) === (query.role === undefined)) {
      throw new ConfigurationError('list bindings by exactly one of subject or role');
    }
    return pageOf(
      await this.#http.page({
        method: 'GET',
        path: '/bindings',
        query: { subject: query.subject, role: query.role, limit: options.limit, cursor: options.cursor },
        ok: [200],
        retry: 'safe',
        signal: options.signal,
      }),
      binding,
    );
  }

  all(query: BindingQuery, options: ListOptions = {}): AsyncGenerator<Binding, void, undefined> {
    return eachItem((cursor) => this.list(query, { ...options, cursor }), options.cursor);
  }

  /** Takes a role away from a subject. */
  async revoke(subject: string, roleId: string, options: CallOptions = {}): Promise<void> {
    await this.#http.call({
      method: 'DELETE',
      path: `/bindings/${segment(subject, 'subject')}/${segment(roleId, 'roleId')}`,
      ok: [204],
      retry: 'unsafe',
      signal: options.signal,
    });
  }
}
