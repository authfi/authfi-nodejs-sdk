/**
 * The project's administration API: organizations, invitations, users, roles and bindings.
 *
 * @packageDocumentation
 */

export { AdminClient } from './client.js';
export type { CallOptions, ListOptions, Page } from './http.js';
export {
  Organizations,
  OrganizationInvitations,
  OrganizationJoinRequests,
  OrganizationMembers,
  type AddMember,
  type CreateInvitation,
  type CreateOrganization,
  type Invitation,
  type JoinRequest,
  type Organization,
  type OrganizationDomain,
  type OrganizationMember,
  type UpdateOrganization,
} from './organizations.js';
export {
  Users,
  type CreateUser,
  type ListUsersOptions,
  type UpdateUser,
  type User,
  type UserProfile,
  type UserStatus,
} from './users.js';
export {
  Bindings,
  Permissions,
  Roles,
  type AssignBinding,
  type Binding,
  type BindingQuery,
  type CreatePermission,
  type CreateRole,
  type Permission,
  type Role,
} from './access.js';
