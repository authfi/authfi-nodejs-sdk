const { describe, it, mock, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const authfi = require('./index');

const { ISSUER, AUDIENCE, issuerKey, sign, claims, fakeIssuer } = require('./test/helpers');

// --- Test helpers ---

// tenant 'acme' resolves to the issuer https://acme.authfi.io, which the fake issuer serves.
function setup(extra = {}) {
  const key = issuerKey('RS256', 'test-key-1');
  const server = fakeIssuer({ keys: [key] });
  const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', audience: AUDIENCE, fetch: server.fetch, ...extra });
  return { key, server, auth };
}

function mockRes() {
  let statusCode = 200;
  let body = null;
  return {
    status(code) { statusCode = code; return this; },
    json(data) { body = data; },
    get statusCode() { return statusCode; },
    get body() { return body; },
  };
}

// --- Tests ---

describe('authfi()', () => {
  it('returns an object with expected methods', () => {
    const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
    assert.equal(typeof auth.require, 'function');
    assert.equal(typeof auth.requireRole, 'function');
    assert.equal(typeof auth.authenticate, 'function');
    assert.equal(typeof auth.verifyToken, 'function');
    assert.equal(typeof auth.start, 'function');
    assert.equal(typeof auth.registerPermission, 'function');
    assert.equal(typeof auth.syncPermissions, 'function');
    assert.equal(typeof auth.cloud, 'object');
  });
});

describe('verifyToken()', () => {
  it('verifies a valid RS256 token', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({
      sub: 'usr_123',
      email: 'jane@acme.com',
      name: 'Jane Smith',
      roles: ['admin', 'editor'],
      permissions: ['read:users', 'write:users'],
      tenant_id: 'tnt_456',
      org_slug: 'acme-corp',
    }), { header: { typ: 'JWT' } });

    const out = await auth.verifyToken(token);
    assert.equal(out.sub, 'usr_123');
    assert.equal(out.email, 'jane@acme.com');
    assert.deepEqual(out.roles, ['admin', 'editor']);
    assert.deepEqual(out.permissions, ['read:users', 'write:users']);
    assert.equal(out.org_slug, 'acme-corp');
    assert.equal(out.iss, ISSUER);
  });

  it('rejects expired token', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ exp: Math.floor(Date.now() / 1000) - 3600 }));
    await assert.rejects(() => auth.verifyToken(token), { message: 'Token expired' });
  });

  it('rejects invalid signature', async () => {
    const { auth } = setup();
    const other = issuerKey('RS256', 'test-key-1');
    await assert.rejects(() => auth.verifyToken(sign(other, claims())), { message: 'Invalid signature' });
  });

  it('rejects unknown kid', async () => {
    const { auth } = setup();
    const other = issuerKey('RS256', 'unknown-kid');
    await assert.rejects(() => auth.verifyToken(sign(other, claims())), { message: 'Unknown signing key' });
  });
});

describe('require() middleware', () => {
  it('passes with valid token and permission', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ sub: 'usr_123', permissions: ['read:users'] }));
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockRes();
    let nextCalled = false;

    await auth.require('read:users')(req, res, () => { nextCalled = true; });

    assert.ok(nextCalled, 'next() should be called');
    assert.equal(req.user.sub, 'usr_123');
  });

  it('rejects missing permission', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ sub: 'usr_123', permissions: ['read:users'] }));
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockRes();
    let nextCalled = false;

    await auth.require('delete:users')(req, res, () => { nextCalled = true; });

    assert.ok(!nextCalled, 'next() should not be called');
    assert.equal(res.statusCode, 403);
    assert.deepEqual(res.body.missing, ['delete:users']);
  });

  it('rejects a token for another audience with 401', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ aud: 'https://other.example', permissions: ['read:users'] }));
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockRes();
    let nextCalled = false;

    await auth.require('read:users')(req, res, () => { nextCalled = true; });

    assert.ok(!nextCalled);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'audience_mismatch');
  });

  it('rejects missing auth header', async () => {
    const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });

    const req = { headers: {} };
    const res = mockRes();
    let nextCalled = false;

    await auth.require('read:users')(req, res, () => { nextCalled = true; });

    assert.ok(!nextCalled);
    assert.equal(res.statusCode, 401);
  });
});

describe('requireRole() middleware', () => {
  it('passes with matching role', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ sub: 'usr_123', roles: ['editor'] }));
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockRes();
    let nextCalled = false;

    await auth.requireRole('admin', 'editor')(req, res, () => { nextCalled = true; });

    assert.ok(nextCalled);
  });

  it('rejects missing role', async () => {
    const { key, auth } = setup();
    const token = sign(key, claims({ sub: 'usr_123', roles: ['viewer'] }));
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockRes();
    let nextCalled = false;

    await auth.requireRole('admin')(req, res, () => { nextCalled = true; });

    assert.ok(!nextCalled);
    assert.equal(res.statusCode, 403);
  });
});

describe('registerPermission()', () => {
  it('registers permissions', () => {
    const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
    // Should not throw
    auth.registerPermission('read:users', 'Read user data');
    auth.registerPermission('write:users');
  });
});

describe('syncPermissions()', () => {
  it('sends permissions to API', async () => {
    let received = null;
    const originalFetch = global.fetch;
    global.fetch = async (url, opts) => {
      if (url.includes('/permissions/sync')) {
        received = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ synced: 2, total: 2 }) };
      }
      return { ok: true, json: async () => ({ keys: [] }) };
    };

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', autoSync: false });
      auth.registerPermission('read:users', 'Read');
      auth.registerPermission('write:users', 'Write');
      await auth.syncPermissions();

      assert.ok(received);
      assert.equal(received.permissions.length, 2);
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('skips sync when no permissions registered', async () => {
    let fetchCalled = false;
    const originalFetch = global.fetch;
    global.fetch = async () => { fetchCalled = true; };

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', autoSync: false });
      await auth.syncPermissions();
      assert.ok(!fetchCalled, 'fetch should not be called for empty sync');
    } finally {
      global.fetch = originalFetch;
    }
  });
});
