import { coreOf, type AuthFI } from '../core/project.js';
import type { Secret } from '../core/secret.js';
import type { TokenSource } from '../core/token-source.js';
import { Bindings, Permissions, Roles } from './access.js';
import { AdminHttp } from './http.js';
import { Organizations } from './organizations.js';
import { Users } from './users.js';

/**
 * The project's administration API: organizations, invitations, users, roles, permissions and role
 * bindings, on `<origin>/apis/regional/v1`.
 *
 * The credential decides what is allowed, not the SDK: the platform gates each call on a permission
 * (`manage:organizations`, `manage:users`, `manage:roles`, `read:policy`...) and on the project's plan,
 * and a refusal arrives as an `APIError` carrying the status (401, 402, 403) and the platform's code.
 *
 * A machine app needs two things set up in AuthFI first:
 * 1. `authfi-console` is in the app's allowed audiences, and the token is requested with
 *    `resource: 'authfi-console'` (and `sendTo` the project's origin).
 * 2. `app:<client_id>` holds a role with `manage:organizations` / `manage:users` (and `manage:roles`
 *    for roles and bindings).
 *
 * Calls only a person can make stay refused for a machine app: accepting an invitation (pass the
 * invitee's own token in a `Secret`) and the join-request calls.
 *
 * @example
 * import { AuthFI, Secret } from '@authfi/sdk';
 * import { AdminClient } from '@authfi/sdk/admin';
 *
 * const af = new AuthFI({ issuer: 'https://acme.authfi.io' });
 * const m2m = af.clientCredentials({
 *   clientId: 'app_…', clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET!),
 *   resource: 'authfi-console', sendTo: [af.apiOrigin],
 * });
 * const admin = new AdminClient(af, m2m);
 * const org = await admin.organizations.create({ slug: 'initech', displayName: 'Initech' });
 * const invite = await admin.organizations.invitations.create(org.id, { email: 'ada@initech.example', role: 'admin' });
 */
export class AdminClient {
  readonly organizations: Organizations;
  readonly users: Users;
  readonly roles: Roles;
  readonly permissions: Permissions;
  readonly bindings: Bindings;

  /**
   * @param af the project.
   * @param credential a {@link TokenSource} (a machine client, an agent), or an access token in a
   * `Secret`, such as a signed-in person's for the calls only a person can make.
   */
  constructor(af: AuthFI, credential: TokenSource | Secret) {
    const http = new AdminHttp(coreOf(af), credential);
    this.organizations = new Organizations(http);
    this.users = new Users(http);
    this.roles = new Roles(http);
    this.permissions = new Permissions(http);
    this.bindings = new Bindings(http);
  }
}
