// The one table of guard cases every adapter runs (design §2.2.2): each rule both ways.

import type { Requirements } from '../../src/verify/answer.js';

export interface GuardCase {
  readonly name: string;
  readonly requirements: Requirements;
  readonly claims: Record<string, unknown>;
  readonly status: 200 | 403;
}

const has = { permissions: ['a', 'b'], roles: ['r1'], scope: 'x y' };

export const GUARD_CASES: readonly GuardCase[] = [
  { name: 'all permissions present', requirements: { permissions: ['a', 'b'] }, claims: has, status: 200 },
  { name: 'one permission missing', requirements: { permissions: ['a', 'c'] }, claims: has, status: 403 },
  {
    name: 'any permission, one present',
    requirements: { anyPermission: ['c', 'b'] },
    claims: has,
    status: 200,
  },
  {
    name: 'any permission, none present',
    requirements: { anyPermission: ['c', 'd'] },
    claims: has,
    status: 403,
  },
  { name: 'a role of several present', requirements: { roles: ['r0', 'r1'] }, claims: has, status: 200 },
  { name: 'no role present', requirements: { roles: ['r0'] }, claims: has, status: 403 },
  { name: 'all scopes present', requirements: { scopes: ['x', 'y'] }, claims: has, status: 200 },
  { name: 'a scope missing', requirements: { scopes: ['x', 'z'] }, claims: has, status: 403 },
  {
    name: 'every kind passes (AND)',
    requirements: { permissions: ['a'], roles: ['r1'], scopes: ['x'] },
    claims: has,
    status: 200,
  },
  {
    name: 'one kind fails (AND)',
    requirements: { permissions: ['a'], roles: ['r9'], scopes: ['x'] },
    claims: has,
    status: 403,
  },
  { name: 'no requirement', requirements: {}, claims: {}, status: 200 },
];
