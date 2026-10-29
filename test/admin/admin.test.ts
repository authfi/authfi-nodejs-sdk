import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { AdminClient } from '../../src/admin/index.js';
import { ConfigurationError, isAuthFIError } from '../../src/core/errors.js';
import { AuthFI } from '../../src/core/project.js';
import { Secret } from '../../src/core/secret.js';
import { json } from '../support/fake-fetch.js';
import { API, ISSUER, TestClock, TestIssuer } from '../support/issuer.js';

const V1 = `${ISSUER}/apis/regional/v1`;
const ORG = '6f0c1d52-1f55-4a0e-9d0b-6a1d6a7c9e11';
const USER = '0b8d0c8c-5f3e-4f6a-8d1c-2a9a0a9b1c22';

const orgWire = (over: Record<string, unknown> = {}) => ({
  id: ORG,
  slug: 'initech',
  display_name: 'Initech',
  attributes: { tax_id: 'X-1', nested: { snake_case: true } },
  created_at: '2026-10-20T10:00:00Z',
  updated_at: '2026-10-20T10:00:00Z',
  ...over,
});

const invWire = (over: Record<string, unknown> = {}) => ({
  id: 'inv-1',
  org_id: ORG,
  email: 'ada@initech.example',
  role: 'admin',
  token: 'invite-token-secret',
  status: 'pending',
  expires_at: '2026-10-27T10:00:00Z',
  created_at: '2026-10-20T10:00:00Z',
  ...over,
});

const page = (items: unknown[], next = '') =>
  json({ data: { data: items, next_cursor: next, has_more: next !== '' } });

async function setup() {
  const t = await TestIssuer.create();
  const clock = new TestClock();
  const af = new AuthFI({
    issuer: t.issuer,
    fetch: t.fake.fetch,
    clock,
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
    json({ access_token: 'at-m2m', token_type: 'Bearer', expires_in: 900 }),
  );
  const m2m = af.clientCredentials({ clientId: 'app_admin', clientSecret: new Secret('s3cret') });
  return { t, af, m2m, admin: new AdminClient(af, m2m) };
}

const refusal = async (p: Promise<unknown>) => {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(e).toBeDefined();
  return e as { code: string; status: number; message: string; name: string };
};

describe('organizations', () => {
  it('creates in the platform spelling and reads camelCase, leaving attributes as written', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/organizations`, () => json({ data: orgWire() }, 201));
    const org = await admin.organizations.create({ slug: 'initech', displayName: 'Initech' });
    const sent = t.fake.to(`${V1}/organizations`)[0]!;
    expect(sent.headers.get('authorization')).toBe('Bearer at-m2m');
    expect(sent.headers.get('content-type')).toBe('application/json');
    expect(JSON.parse(sent.body)).toEqual({ slug: 'initech', display_name: 'Initech' });
    expect(org.displayName).toBe('Initech');
    expect(org.attributes).toEqual({ tax_id: 'X-1', nested: { snake_case: true } });
  });

  it('gets, updates with only the fields given, and deletes', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations/${ORG}`, () => json({ data: orgWire() }));
    t.fake.on('PATCH', `${V1}/organizations/${ORG}`, () =>
      json({ data: orgWire({ display_name: 'Initech 2' }) }),
    );
    t.fake.on('DELETE', `${V1}/organizations/${ORG}`, () => new Response(null, { status: 204 }));
    expect((await admin.organizations.get(ORG)).slug).toBe('initech');
    const updated = await admin.organizations.update(ORG, { displayName: 'Initech 2' });
    expect(updated.displayName).toBe('Initech 2');
    expect(JSON.parse(t.fake.requests.find((r) => r.method === 'PATCH')!.body)).toEqual({
      display_name: 'Initech 2',
    });
    await expect(admin.organizations.delete(ORG)).resolves.toBeUndefined();
  });

  it('lists a page and follows the cursor across pages', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations`, (r) => {
      const cursor = new URL(r.url).searchParams.get('cursor');
      return cursor === null ? page([orgWire({ id: 'a' })], 'c2') : page([orgWire({ id: 'b' })]);
    });
    const first = await admin.organizations.list({ limit: 1 });
    expect(first).toMatchObject({ hasMore: true, nextCursor: 'c2' });
    expect(new URL(t.fake.requests.at(-1)!.url).searchParams.get('limit')).toBe('1');
    const ids: string[] = [];
    for await (const org of admin.organizations.all({ limit: 1 })) ids.push(org.id);
    expect(ids).toEqual(['a', 'b']);
  });

  it('stops rather than loop when the platform repeats a cursor', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations`, () => page([orgWire()], 'same'));
    const seen: string[] = [];
    const run = (async () => {
      for await (const org of admin.organizations.all()) seen.push(org.id);
    })();
    expect((await refusal(run)).code).toBe('response_invalid');
    expect(seen.length).toBeLessThanOrEqual(3);
    expect(t.fake.to(`${V1}/organizations`).length).toBeLessThanOrEqual(3);
  });

  it('manages members', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations/${ORG}/members`, () =>
      page([{ user_id: USER, role: 'owner', created_at: '2026-10-20T10:00:00Z' }]),
    );
    t.fake.on('POST', `${V1}/organizations/${ORG}/members`, () => json({ data: { ok: true } }));
    t.fake.on('DELETE', `${V1}/organizations/${ORG}/members/${USER}`, () => json({ data: { ok: true } }));
    const members = await admin.organizations.members.list(ORG);
    expect(members.items).toEqual([{ userId: USER, role: 'owner', createdAt: '2026-10-20T10:00:00Z' }]);
    await admin.organizations.members.add(ORG, { userId: USER, role: 'admin' });
    expect(
      JSON.parse(t.fake.requests.find((r) => r.method === 'POST' && r.url.endsWith('/members'))!.body),
    ).toEqual({
      user_id: USER,
      role: 'admin',
    });
    await admin.organizations.members.remove(ORG, USER);
  });

  it('creates, lists and revokes invitations, keeping the accept token out of logs', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/organizations/${ORG}/invitations`, () =>
      json({ data: invWire({ user_id: USER }) }, 201),
    );
    t.fake.on('GET', `${V1}/organizations/${ORG}/invitations`, () => page([invWire()]));
    t.fake.on(
      'DELETE',
      `${V1}/organizations/${ORG}/invitations/inv-1`,
      () => new Response(null, { status: 204 }),
    );
    const inv = await admin.organizations.invitations.create(ORG, {
      email: 'ada@initech.example',
      role: 'admin',
      invitedBy: USER,
    });
    expect(
      JSON.parse(t.fake.requests.find((r) => r.url.endsWith('/invitations') && r.method === 'POST')!.body),
    ).toEqual({
      email: 'ada@initech.example',
      role: 'admin',
      invited_by: USER,
    });
    expect(inv.token.reveal()).toBe('invite-token-secret');
    expect(inv.userId).toBe(USER);
    for (const text of [inspect(inv), JSON.stringify(inv), String(inv.token)]) {
      expect(text).not.toContain('invite-token-secret');
    }
    expect((await admin.organizations.invitations.list(ORG)).items).toHaveLength(1);
    await admin.organizations.invitations.revoke(ORG, 'inv-1');
  });

  it('refuses an invitation the platform answered without its token', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/organizations/${ORG}/invitations`, () =>
      json({ data: invWire({ token: '' }) }, 201),
    );
    expect((await refusal(admin.organizations.invitations.create(ORG, { email: 'a@b.example' }))).code).toBe(
      'response_invalid',
    );
  });

  it("accepts an invitation with the invitee's own token and a Secret invite token", async () => {
    const { t, af } = await setup();
    t.fake.on('POST', `${V1}/organizations/invitations/accept`, () =>
      json({ data: invWire({ status: 'accepted' }) }),
    );
    const asInvitee = new AdminClient(af, new Secret('invitee-access-token'));
    const accepted = await asInvitee.organizations.invitations.accept({
      token: new Secret('invite-token-secret'),
      userId: USER,
    });
    expect(accepted.status).toBe('accepted');
    const sent = t.fake.requests.find((r) => r.url.endsWith('/invitations/accept'))!;
    expect(sent.headers.get('authorization')).toBe('Bearer invitee-access-token');
    expect(JSON.parse(sent.body)).toEqual({ token: 'invite-token-secret', user_id: USER });
    await expect(
      asInvitee.organizations.invitations.accept({ token: 'plain' as unknown as Secret, userId: USER }),
    ).rejects.toThrow(ConfigurationError);
  });

  it('lists, decides, and withdraws join requests, and lists domains', async () => {
    const { t, admin } = await setup();
    const jr = (status: string) => ({
      id: 'jr-1',
      org_id: ORG,
      org_name: 'Initech',
      user_id: USER,
      email: 'bob@initech.example',
      display_name: 'Bob',
      status,
      created_at: '2026-10-20T10:00:00Z',
      decided_at: status === 'pending' ? null : '2026-10-20T11:00:00Z',
      decided_by: status === 'pending' ? '' : 'user:u1',
    });
    t.fake.on('GET', `${V1}/organizations/${ORG}/join-requests`, () => json({ data: [jr('pending')] }));
    t.fake.on('POST', `${V1}/organizations/${ORG}/join-requests/jr-1/approve`, () =>
      json({ data: jr('approved') }),
    );
    t.fake.on('POST', `${V1}/organizations/${ORG}/join-requests/jr-1/decline`, () =>
      json({ data: jr('declined') }),
    );
    t.fake.on('GET', `${V1}/organizations/join-requests/mine`, () => json({ data: [jr('pending')] }));
    t.fake.on(
      'POST',
      `${V1}/organizations/join-requests/jr-1/withdraw`,
      () => new Response(null, { status: 204 }),
    );
    t.fake.on('GET', `${V1}/organizations/${ORG}/domains`, () =>
      json({
        data: [{ domain: 'initech.example', claimed_via: 'signup', claimed_by: 'user:u1', created_at: 'x' }],
      }),
    );
    const pending = await admin.organizations.joinRequests.list(ORG, { status: 'pending' });
    expect(
      new URL(t.fake.requests.find((r) => r.url.includes('join-requests?'))!.url).searchParams.get('status'),
    ).toBe('pending');
    expect(pending[0]).toMatchObject({ orgName: 'Initech', decidedAt: null });
    expect((await admin.organizations.joinRequests.approve(ORG, 'jr-1')).status).toBe('approved');
    expect((await admin.organizations.joinRequests.decline(ORG, 'jr-1')).status).toBe('declined');
    expect(await admin.organizations.joinRequests.mine()).toHaveLength(1);
    await admin.organizations.joinRequests.withdraw('jr-1');
    expect((await admin.organizations.domains(ORG))[0]).toMatchObject({
      domain: 'initech.example',
      claimedVia: 'signup',
    });
  });

  it('shows a machine client the platform refusing the person-only join-request calls', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations/${ORG}/join-requests`, () =>
      json(
        { error: 'forbidden', error_description: 'only an owner or admin of this organization can do this' },
        403,
      ),
    );
    const e = await refusal(admin.organizations.joinRequests.list(ORG));
    expect(e).toMatchObject({ name: 'APIError', status: 403, code: 'forbidden' });
  });
});

describe('refusals', () => {
  it('raises the platform refusal as an APIError with status and code: a missing permission, the plan gate, no token', async () => {
    const { t, admin } = await setup();
    for (const [status, code] of [
      [403, 'forbidden'],
      [402, 'feature_not_in_plan'],
      [401, 'invalid_token'],
    ] as const) {
      t.fake.on('GET', `${V1}/organizations/${ORG}`, () =>
        json({ error: code, error_description: 'no' }, status),
      );
      const e = await refusal(admin.organizations.get(ORG));
      expect(isAuthFIError(e, 'APIError')).toBe(true);
      expect(e).toMatchObject({ status, code });
    }
  });

  it('retries a read that failed with 503 and never a write', async () => {
    const { t, admin } = await setup();
    let reads = 0;
    t.fake.on('GET', `${V1}/organizations/${ORG}`, () => {
      reads += 1;
      return reads < 2 ? json({ error: 'unavailable' }, 503) : json({ data: orgWire() });
    });
    expect((await admin.organizations.get(ORG)).id).toBe(ORG);
    expect(reads).toBe(2);
    let writes = 0;
    t.fake.on('POST', `${V1}/organizations`, () => {
      writes += 1;
      return json({ error: 'unavailable' }, 503);
    });
    expect((await refusal(admin.organizations.create({ slug: 's', displayName: 'd' }))).status).toBe(503);
    expect(writes).toBe(1);
  });

  it('raises a success status the contract does not name, and data of the wrong shape', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/organizations`, () => json({ data: orgWire() }, 200));
    expect((await refusal(admin.organizations.create({ slug: 's', displayName: 'd' }))).code).toBe(
      'response_invalid',
    );
    t.fake.on('GET', `${V1}/organizations/${ORG}`, () => json({ data: [1] }));
    expect((await refusal(admin.organizations.get(ORG))).code).toBe('response_invalid');
    t.fake.on('GET', `${V1}/organizations`, () => json({ data: { data: 'nope' } }));
    expect((await refusal(admin.organizations.list())).code).toBe('response_invalid');
  });

  it('never sends a machine client token outside its origins', async () => {
    const t = await TestIssuer.create();
    const af = new AuthFI({
      issuer: t.issuer,
      fetch: t.fake.fetch,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
      json({ access_token: 'at', token_type: 'Bearer', expires_in: 900 }),
    );
    const orders = af.clientCredentials({
      clientId: 'app_o',
      clientSecret: new Secret('s'),
      resource: API,
      sendTo: ['https://api.example.com'],
    });
    const admin = new AdminClient(af, orders);
    await expect(admin.users.list()).rejects.toThrow(/refusing to send/);
    expect(t.fake.requests.some((r) => r.url.includes('/apis/regional/'))).toBe(false);
  });

  it('works with the documented setup: the token is for authfi-console and goes to the project origin', async () => {
    const t = await TestIssuer.create();
    const af = new AuthFI({
      issuer: t.issuer,
      fetch: t.fake.fetch,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
      json({ access_token: 'at-console', token_type: 'Bearer', expires_in: 900 }),
    );
    t.fake.on('GET', `${V1}/organizations`, () => page([orgWire()]));
    const m2m = af.clientCredentials({
      clientId: 'app_admin',
      clientSecret: new Secret('s'),
      resource: 'authfi-console',
      sendTo: [af.apiOrigin],
    });
    await new AdminClient(af, m2m).organizations.list();
    const tokenRequest = t.fake.to(`${ISSUER}/oauth/token`)[0]!;
    expect(new URLSearchParams(tokenRequest.body).get('resource')).toBe('authfi-console');
    expect(t.fake.to(`${V1}/organizations`)[0]!.headers.get('authorization')).toBe('Bearer at-console');
  });

  it('refuses a credential that is not one', async () => {
    const { af } = await setup();
    expect(() => new AdminClient(af, 'token' as unknown as Secret)).toThrow(ConfigurationError);
  });

  it('encodes an id so it cannot add a path segment or a query', async () => {
    const { t, admin } = await setup();
    t.fake.on(
      'GET',
      (u) => u.includes('/apis/regional/'),
      () => json({ data: orgWire() }),
    );
    await admin.organizations.get('../users?x=1');
    const url = t.fake.requests.at(-1)!.url;
    expect(url).toBe(`${V1}/organizations/..%2Fusers%3Fx%3D1`);
    await expect(admin.organizations.get('')).rejects.toThrow(ConfigurationError);
  });

  it('passes the caller abort signal through', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/organizations/${ORG}`, () => new Promise<Response>(() => undefined));
    const c = new AbortController();
    const p = admin.organizations.get(ORG, { signal: c.signal });
    await new Promise((r) => setTimeout(r, 10));
    c.abort(new Error('stop'));
    await expect(p).rejects.toThrow('stop');
  });
});

describe('users', () => {
  const userWire = (over: Record<string, unknown> = {}) => ({
    id: USER,
    email: 'ada@initech.example',
    email_verified: true,
    display_name: 'Ada',
    given_name: 'Ada',
    phone_verified: false,
    attributes: { cost_center: 'c-1' },
    status: 'active',
    created_at: '2026-10-20T10:00:00Z',
    updated_at: '2026-10-20T10:00:00Z',
    ...over,
  });

  it('creates with profile fields in the platform spelling', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/users`, () => json({ data: userWire() }, 201));
    const u = await admin.users.create({
      email: 'ada@initech.example',
      displayName: 'Ada',
      givenName: 'Ada',
      pictureUrl: 'https://img.example/a.png',
      hireDate: '2026-01-05',
      attributes: { cost_center: 'c-1' },
    });
    expect(
      JSON.parse(t.fake.requests.find((r) => r.method === 'POST' && r.url.endsWith('/users'))!.body),
    ).toEqual({
      email: 'ada@initech.example',
      display_name: 'Ada',
      given_name: 'Ada',
      picture_url: 'https://img.example/a.png',
      hire_date: '2026-01-05',
      attributes: { cost_center: 'c-1' },
    });
    expect(u).toMatchObject({ id: USER, displayName: 'Ada', emailVerified: true, status: 'active' });
    expect(u.attributes).toEqual({ cost_center: 'c-1' });
  });

  it('refuses early to claim a verified email or phone, which only the sign-in service may', async () => {
    const { t, admin } = await setup();
    await expect(
      admin.users.create({ email: 'a@b.example', displayName: 'A', emailVerified: true } as never),
    ).rejects.toThrow(/only the sign-in service/);
    await expect(admin.users.update(USER, { phoneVerified: true } as never)).rejects.toThrow(
      ConfigurationError,
    );
    expect(t.fake.requests.some((r) => r.url.includes('/users'))).toBe(false);
  });

  it('shows the platform refusing a verification claim anyway', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/users`, () =>
      json(
        {
          error: 'forbidden',
          error_description: 'email_verified and phone_verified are set only by the identity service',
        },
        403,
      ),
    );
    expect(await refusal(admin.users.create({ email: 'a@b.example', displayName: 'A' }))).toMatchObject({
      status: 403,
    });
  });

  it('gets, searches across pages, updates (suspending) and deletes', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/users/${USER}`, () => json({ data: userWire() }));
    t.fake.on('GET', `${V1}/users`, (r) =>
      new URL(r.url).searchParams.get('cursor') === null
        ? page([userWire({ id: 'u1' })], 'n1')
        : page([userWire({ id: 'u2' })]),
    );
    t.fake.on('PATCH', `${V1}/users/${USER}`, () => json({ data: userWire({ status: 'suspended' }) }));
    t.fake.on('DELETE', `${V1}/users/${USER}`, () => new Response(null, { status: 204 }));
    expect((await admin.users.get(USER)).email).toBe('ada@initech.example');
    const ids: string[] = [];
    for await (const u of admin.users.all({ query: 'ada', limit: 1 })) ids.push(u.id);
    expect(ids).toEqual(['u1', 'u2']);
    const search = new URL(t.fake.requests.find((r) => r.url.includes('/users?'))!.url).searchParams;
    expect(search.get('q')).toBe('ada');
    expect((await admin.users.update(USER, { status: 'suspended', clearManager: true })).status).toBe(
      'suspended',
    );
    expect(JSON.parse(t.fake.requests.find((r) => r.method === 'PATCH')!.body)).toEqual({
      status: 'suspended',
      clear_manager: true,
    });
    await admin.users.delete(USER);
  });
});

describe('roles, permissions and bindings', () => {
  const ROLE = '3d0f8c5e-7a43-4c47-a1ee-7a2e3b9f0d33';
  const roleWire = { id: ROLE, name: 'billing', description: '', system: false, created_at: 'x' };
  const permWire = { id: 'p1', action: 'read', resource: 'invoice', description: '', created_at: 'x' };
  const bindWire = {
    id: 'b1',
    subject: 'user:u1',
    role_id: ROLE,
    role_name: 'billing',
    expires_at: '2027-01-01T00:00:00Z',
    created_at: 'x',
  };

  it('lists and creates roles, reads and replaces a role permission set', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/roles`, () => page([roleWire]));
    t.fake.on('POST', `${V1}/roles`, () => json({ data: roleWire }, 201));
    t.fake.on('GET', `${V1}/roles/${ROLE}/permissions`, () => json({ data: [permWire] }));
    t.fake.on('PUT', `${V1}/roles/${ROLE}/permissions`, () => new Response(null, { status: 204 }));
    expect((await admin.roles.list()).items[0]).toMatchObject({ name: 'billing', system: false });
    const all: string[] = [];
    for await (const r of admin.roles.all()) all.push(r.id);
    expect(all).toEqual([ROLE]);
    await admin.roles.create({ name: 'billing', description: 'invoices' });
    expect(
      JSON.parse(t.fake.requests.find((r) => r.method === 'POST' && r.url.endsWith('/roles'))!.body),
    ).toEqual({
      name: 'billing',
      description: 'invoices',
    });
    expect((await admin.roles.permissions(ROLE))[0]).toMatchObject({ action: 'read', resource: 'invoice' });
    await admin.roles.setPermissions(ROLE, ['p1']);
    expect(JSON.parse(t.fake.requests.find((r) => r.method === 'PUT')!.body)).toEqual({
      permission_ids: ['p1'],
    });
    await admin.roles.setPermissions(ROLE, []);
    expect(JSON.parse(t.fake.requests.filter((r) => r.method === 'PUT').at(-1)!.body)).toEqual({
      permission_ids: [],
    });
  });

  it('lists and creates permissions', async () => {
    const { t, admin } = await setup();
    t.fake.on('GET', `${V1}/permissions`, () => page([permWire]));
    t.fake.on('POST', `${V1}/permissions`, () => json({ data: permWire }, 201));
    expect((await admin.permissions.list()).items).toHaveLength(1);
    const ids: string[] = [];
    for await (const p of admin.permissions.all()) ids.push(p.id);
    expect(ids).toEqual(['p1']);
    expect((await admin.permissions.create({ action: 'read', resource: 'invoice' })).id).toBe('p1');
  });

  it('assigns, lists both ways, and revokes a binding', async () => {
    const { t, admin } = await setup();
    t.fake.on('POST', `${V1}/bindings`, () => json({ data: bindWire }, 201));
    t.fake.on('GET', `${V1}/bindings`, () => page([bindWire]));
    t.fake.on('DELETE', `${V1}/bindings/user:u1/${ROLE}`, () => new Response(null, { status: 204 }));
    const b = await admin.bindings.assign({
      subject: 'user:u1',
      roleId: ROLE,
      expiresAt: '2027-01-01T00:00:00Z',
    });
    expect(
      JSON.parse(t.fake.requests.find((r) => r.method === 'POST' && r.url.endsWith('/bindings'))!.body),
    ).toEqual({
      subject: 'user:u1',
      role_id: ROLE,
      expires_at: '2027-01-01T00:00:00Z',
    });
    expect(b).toMatchObject({ roleId: ROLE, roleName: 'billing' });
    await admin.bindings.list({ subject: 'user:u1' });
    await admin.bindings.list({ role: ROLE }, { limit: 5 });
    const listed = t.fake.requests
      .filter((r) => r.method === 'GET' && r.url.includes('/bindings?'))
      .map((r) => new URL(r.url).searchParams);
    expect(listed[0]!.get('subject')).toBe('user:u1');
    expect(listed[1]!.get('role')).toBe(ROLE);
    expect(listed[1]!.get('limit')).toBe('5');
    const subjects: string[] = [];
    for await (const x of admin.bindings.all({ subject: 'user:u1' })) subjects.push(x.subject);
    expect(subjects).toEqual(['user:u1']);
    await admin.bindings.revoke('user:u1', ROLE);
  });

  it('refuses a bindings list that names neither or both of subject and role, and shows the permission refusal', async () => {
    const { t, admin } = await setup();
    await expect(admin.bindings.list({} as never)).rejects.toThrow(ConfigurationError);
    await expect(admin.bindings.list({ subject: 'user:u1', role: ROLE } as never)).rejects.toThrow(
      ConfigurationError,
    );
    t.fake.on('POST', `${V1}/bindings`, () =>
      json({ error: 'forbidden', error_description: 'manage:roles' }, 403),
    );
    expect(await refusal(admin.bindings.assign({ subject: 'user:u1', roleId: ROLE }))).toMatchObject({
      status: 403,
      code: 'forbidden',
    });
  });
});
