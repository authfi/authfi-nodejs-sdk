const { describe, it, mock, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const authfi = require('./index');

// --- Test helpers ---

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function signToken(privateKey, payload, kid = 'test-key-1') {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signedData = `${header}.${body}`;
  const signature = crypto.sign('sha256', Buffer.from(signedData), privateKey);
  return `${signedData}.${signature.toString('base64url')}`;
}

function exportJWK(publicKeyPem, kid = 'test-key-1') {
  const key = crypto.createPublicKey(publicKeyPem);
  const jwk = key.export({ format: 'jwk' });
  return { ...jwk, kid, use: 'sig', alg: 'RS256' };
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
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    // Mock fetch for JWKS
    const originalFetch = global.fetch;
    global.fetch = async (url) => {
      if (url.includes('.well-known/jwks.json')) {
        return { ok: true, json: async () => ({ keys: [jwk] }) };
      }
      return originalFetch(url);
    };

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });

      const token = signToken(privateKey, {
        sub: 'usr_123',
        email: 'jane@acme.com',
        name: 'Jane Smith',
        roles: ['admin', 'editor'],
        permissions: ['read:users', 'write:users'],
        tenant_id: 'tnt_456',
        org_slug: 'acme-corp',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: 'https://acme.authfi.io',
      });

      const claims = await auth.verifyToken(token);
      assert.equal(claims.sub, 'usr_123');
      assert.equal(claims.email, 'jane@acme.com');
      assert.deepEqual(claims.roles, ['admin', 'editor']);
      assert.deepEqual(claims.permissions, ['read:users', 'write:users']);
      assert.equal(claims.org_slug, 'acme-corp');
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects expired token', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        exp: Math.floor(Date.now() / 1000) - 3600, // expired
      });

      await assert.rejects(() => auth.verifyToken(token), { message: 'Token expired' });
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects invalid signature', async () => {
    const { publicKey } = generateKeyPair();
    const { privateKey: otherKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(otherKey, {
        sub: 'usr_123',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      await assert.rejects(() => auth.verifyToken(token), { message: 'Invalid signature' });
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects unknown kid', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey, 'different-kid');

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }, 'unknown-kid');

      await assert.rejects(() => auth.verifyToken(token), { message: 'Unknown signing key' });
    } finally {
      global.fetch = originalFetch;
    }
  });
});

describe('require() middleware', () => {
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

  it('passes with valid token and permission', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        permissions: ['read:users'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const req = { headers: { authorization: `Bearer ${token}` } };
      const res = mockRes();
      let nextCalled = false;

      await auth.require('read:users')(req, res, () => { nextCalled = true; });

      assert.ok(nextCalled, 'next() should be called');
      assert.equal(req.user.sub, 'usr_123');
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects missing permission', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        permissions: ['read:users'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const req = { headers: { authorization: `Bearer ${token}` } };
      const res = mockRes();
      let nextCalled = false;

      await auth.require('delete:users')(req, res, () => { nextCalled = true; });

      assert.ok(!nextCalled, 'next() should not be called');
      assert.equal(res.statusCode, 403);
      assert.deepEqual(res.body.missing, ['delete:users']);
    } finally {
      global.fetch = originalFetch;
    }
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

  it('passes with matching role', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        roles: ['editor'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const req = { headers: { authorization: `Bearer ${token}` } };
      const res = mockRes();
      let nextCalled = false;

      await auth.requireRole('admin', 'editor')(req, res, () => { nextCalled = true; });

      assert.ok(nextCalled);
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects missing role', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const jwk = exportJWK(publicKey);

    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

    try {
      const auth = authfi({ tenant: 'acme', apiKey: 'sk_test' });
      const token = signToken(privateKey, {
        sub: 'usr_123',
        roles: ['viewer'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const req = { headers: { authorization: `Bearer ${token}` } };
      const res = mockRes();
      let nextCalled = false;

      await auth.requireRole('admin')(req, res, () => { nextCalled = true; });

      assert.ok(!nextCalled);
      assert.equal(res.statusCode, 403);
    } finally {
      global.fetch = originalFetch;
    }
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
