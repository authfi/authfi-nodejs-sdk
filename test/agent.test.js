'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const util = require('util');
const { AgentKey, AgentAuth, AgentAuthError } = require('..');
const { fakeAS, ISSUER, TOKEN_ENDPOINT, BACKCHANNEL, TX, CIBA, decode } = require('./fake-as');

const ALGS = ['EdDSA', 'ES256', 'PS256'];
const noWait = async () => {};

function agentFor(alg, opts = {}) {
  const as = fakeAS(opts.as);
  const key = AgentKey.generate(alg);
  as.register('agt_1', key);
  const agent = new AgentAuth({ issuer: ISSUER, agentId: 'agt_1', key, fetch: as.fetch, ...opts.agent });
  return { as, key, agent };
}

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authfi-sdk-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, { mode: 0o600 });
  return file;
}

describe('AgentKey', () => {
  for (const alg of ALGS) {
    it(`${alg}: signs an assertion the platform's rules accept, with the claims it requires`, () => {
      const key = AgentKey.generate(alg);
      const assertion = key.clientAssertion('agt_1', TOKEN_ENDPOINT);
      const [h, c, s] = assertion.split('.');
      const header = decode(h);
      const claims = decode(c);
      assert.deepEqual(header, { alg, typ: 'JWT', kid: key.kid });
      assert.equal(claims.iss, 'agt_1');
      assert.equal(claims.sub, 'agt_1');
      assert.equal(claims.aud, TOKEN_ENDPOINT);
      assert.ok(claims.exp - claims.iat <= 300 && claims.exp - claims.iat > 0);
      assert.match(claims.jti, /^[0-9a-f-]{36}$/);
      assert.notEqual(decode(key.clientAssertion('agt_1', TOKEN_ENDPOINT).split('.')[1]).jti, claims.jti, 'every assertion has a fresh jti');

      const pub = crypto.createPublicKey({ key: key.publicJwk(), format: 'jwk' });
      const input = Buffer.from(`${h}.${c}`);
      const sig = Buffer.from(s, 'base64url');
      const ok = alg === 'EdDSA' ? crypto.verify(null, input, pub, sig)
        : alg === 'ES256' ? crypto.verify('sha256', input, { key: pub, dsaEncoding: 'ieee-p1363' }, sig)
          : crypto.verify('sha256', input, { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
      assert.ok(ok, 'the signature verifies with the public JWK');
    });

    it(`${alg}: loads from PEM, JWK and file, and keeps the same public key`, () => {
      const key = AgentKey.generate(alg, { kid: 'k1' });
      const fromPem = AgentKey.fromPem(key.privatePem(), { kid: 'k1' });
      const privJwk = { ...crypto.createPrivateKey(key.privatePem()).export({ format: 'jwk' }), kid: 'k1' };
      const fromJwk = AgentKey.fromJwk(privJwk);
      const fromPemFile = AgentKey.fromFile(tmpFile('k.pem', key.privatePem()), { kid: 'k1' });
      const fromJwkFile = AgentKey.fromFile(tmpFile('k.json', JSON.stringify(privJwk)));
      for (const k of [fromPem, fromJwk, fromPemFile, fromJwkFile]) {
        assert.equal(k.alg, alg);
        assert.equal(k.kid, 'k1');
        assert.deepEqual(k.publicJwk(), key.publicJwk());
      }
    });
  }

  it('publishes a public JWK with alg, use and kid and no private member', () => {
    for (const alg of ALGS) {
      const jwk = AgentKey.generate(alg, { kid: 'k' }).publicJwk();
      assert.equal(jwk.alg, alg);
      assert.equal(jwk.use, 'sig');
      assert.equal(jwk.kid, 'k');
      for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi']) assert.equal(jwk[m], undefined);
    }
  });

  it('defaults the kid of a generated key to its RFC 7638 thumbprint', () => {
    const key = AgentKey.generate('EdDSA');
    const { crv, kty, x } = key.publicJwk();
    const expected = crypto.createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest('base64url');
    assert.equal(key.kid, expected);
    assert.equal(key.thumbprint(), expected);
  });

  it('never shows the private key when serialized or inspected', () => {
    const key = AgentKey.generate('ES256', { kid: 'k' });
    const d = crypto.createPrivateKey(key.privatePem()).export({ format: 'jwk' }).d;
    assert.ok(!JSON.stringify(key).includes(d));
    assert.ok(!util.inspect(key, { depth: 5 }).includes('PRIVATE'));
    assert.deepEqual(JSON.parse(JSON.stringify(key)), { kid: 'k', alg: 'ES256' });
  });

  describe('refuses keys the platform would refuse', () => {
    const refused = {
      'EC P-384': () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey,
      'EC secp256k1': () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey,
      'Ed448': () => crypto.generateKeyPairSync('ed448').privateKey,
      'RSA 1024': () => crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey,
      'RSA e=3': () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 3 }).privateKey,
      'a public key': () => crypto.generateKeyPairSync('ed25519').publicKey,
    };
    for (const [name, make] of Object.entries(refused)) {
      it(name, () => {
        assert.throws(() => new AgentKey(make(), 'k'), { name: 'AgentAuthError', error: 'invalid_key' });
      });
    }

    it('a key with no kid', () => {
      const pem = AgentKey.generate('EdDSA').privatePem();
      assert.throws(() => AgentKey.fromPem(pem), { error: 'invalid_key', message: /kid is required/ });
    });

    it('a public key PEM, naming what it is', () => {
      const pem = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
      assert.throws(() => AgentKey.fromPem(pem, { kid: 'k' }), { error: 'invalid_key', message: /PUBLIC KEY/ });
    });

    it('an encrypted PEM', () => {
      const pem = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' });
      assert.throws(() => AgentKey.fromPem(pem, { kid: 'k' }), { error: 'invalid_key' });
    });

    it('a public JWK given as the private key', () => {
      assert.throws(() => AgentKey.fromJwk(AgentKey.generate('EdDSA').publicJwk()), { error: 'invalid_key', message: /no private component/ });
    });

    it('an assertion lifetime over five minutes', () => {
      assert.throws(() => AgentKey.generate('EdDSA').clientAssertion('agt_1', TOKEN_ENDPOINT, { lifetime: 301 }), { error: 'invalid_request' });
    });
  });
});

describe('AgentAuth: discovery', () => {
  it('has no default issuer', () => {
    assert.throws(() => new AgentAuth({ agentId: 'agt_1', key: AgentKey.generate() }), { error: 'invalid_request', message: /issuer is required/ });
  });

  it('refuses a secret in place of a key', () => {
    assert.throws(() => new AgentAuth({ issuer: ISSUER, agentId: 'agt_1', key: 'secret' }), { error: 'invalid_key' });
  });

  it('takes the token endpoint from the authorization-server metadata', async () => {
    const { as, agent } = agentFor('EdDSA');
    await agent.token();
    assert.equal(as.requests[0].url, `${ISSUER}/.well-known/oauth-authorization-server`);
    assert.equal(as.tokenRequests().length, 1);
    assert.equal(as.assertions[0].claims.aud, TOKEN_ENDPOINT);
  });

  it('refuses metadata that names another issuer', async () => {
    const { agent } = agentFor('EdDSA', { as: { docIssuer: 'https://other.authfi.io' } });
    await assert.rejects(agent.token(), /names issuer/);
  });

  it('refuses a deployment that does not take private_key_jwt', async () => {
    const { agent } = agentFor('EdDSA', { as: { metadata: { token_endpoint_auth_methods_supported: ['client_secret_basic'] } } });
    await assert.rejects(agent.token(), { error: 'unsupported_auth_method' });
  });

  it('refuses a key whose algorithm the deployment does not advertise', async () => {
    const { agent } = agentFor('PS256', { as: { metadata: { token_endpoint_auth_signing_alg_values_supported: ['EdDSA'] } } });
    await assert.rejects(agent.token(), { error: 'unsupported_alg' });
  });
});

describe('AgentAuth: the agent\'s own token', () => {
  for (const alg of ALGS) {
    it(`${alg}: mints with client_credentials and private_key_jwt`, async () => {
      const { as, agent } = agentFor(alg);
      const tok = await agent.token();
      assert.equal(decode(tok.split('.')[1]).sub, 'agt_1');
      const form = as.tokenRequests()[0].form;
      assert.equal(form.get('grant_type'), 'client_credentials');
      assert.equal(form.get('client_id'), 'agt_1');
      assert.equal(form.get('client_assertion_type'), 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      assert.equal(form.get('client_secret'), null);
      assert.deepEqual(await agent.capabilities(), ['mcp:read']);
    });
  }

  it('surfaces a refused key as invalid_client and does not retry it', async () => {
    const as = fakeAS();
    as.register('agt_1', AgentKey.generate('EdDSA', { kid: 'k1' }));
    const impostor = AgentKey.generate('EdDSA', { kid: 'k1' });
    const agent = new AgentAuth({ issuer: ISSUER, agentId: 'agt_1', key: impostor, fetch: as.fetch });
    await assert.rejects(agent.token(), (e) => e instanceof AgentAuthError && e.error === 'invalid_client' && e.status === 401);
    assert.equal(as.tokenRequests().length, 1);
  });

  it('refuses a key registered for another agent', async () => {
    const as = fakeAS();
    const key = AgentKey.generate('ES256');
    as.register('agt_other', key);
    const agent = new AgentAuth({ issuer: ISSUER, agentId: 'agt_1', key, fetch: as.fetch });
    await assert.rejects(agent.token(), { error: 'invalid_client' });
  });

  it('sends resource and keeps one token per resource', async () => {
    const { as, agent } = agentFor('EdDSA', { agent: { resource: 'https://api.acme.example' } });
    const a = await agent.token();
    const b = await agent.token({ resource: 'https://other.acme.example' });
    assert.notEqual(a, b);
    assert.equal(decode(a.split('.')[1]).aud, 'https://api.acme.example');
    assert.deepEqual(as.tokenRequests().map((r) => r.form.get('resource')), ['https://api.acme.example', 'https://other.acme.example']);
    assert.equal(await agent.token(), a);
  });

  it('caches the token, refreshes it before expiry, and shares one request between concurrent callers', async () => {
    const { as, agent } = agentFor('EdDSA');
    const [a, b, c] = await Promise.all([agent.token(), agent.token(), agent.token()]);
    assert.equal(a, b);
    assert.equal(b, c);
    assert.equal(as.tokenRequests().length, 1);
    assert.equal(await agent.token(), a);
    const realNow = Date.now;
    Date.now = () => realNow() + (as.tokenTtl - 59) * 1000;
    try {
      assert.notEqual(await agent.token(), a, 'inside the refresh skew a new token is minted');
    } finally {
      Date.now = realNow;
    }
    assert.equal(as.tokenRequests().length, 2);
  });

  it('takes the expiry from the token when the response has no expires_in', async () => {
    const { as, agent } = agentFor('EdDSA');
    as.omitExpiresIn = true;
    const a = await agent.token();
    assert.equal(await agent.token(), a);
    assert.equal(as.tokenRequests().length, 1);
  });

  it('reports a Deprecation header once', async () => {
    const seen = [];
    const { as, agent } = agentFor('EdDSA', { agent: { onDeprecation: (d) => seen.push(d) } });
    as.headers = { deprecation: '@1792000000', link: `<${TOKEN_ENDPOINT}>; rel="successor-version"` };
    await agent.token();
    await agent.token({ force: true });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, TOKEN_ENDPOINT);
    assert.match(seen[0].link, /successor-version/);
  });
});

describe('AgentAuth.fetch', () => {
  it('sets the current token on every request and drops x-api-key', async () => {
    const { as, agent } = agentFor('EdDSA');
    const seen = [];
    as.other = async (url, init) => {
      seen.push(new Headers(init.headers));
      return new Response('{}', { status: 200 });
    };
    const res = await agent.fetch(`${ISSUER}/mcp/v1/messages`, { method: 'POST', headers: { 'x-api-key': 'placeholder', authorization: 'Bearer stale' } });
    assert.equal(res.status, 200);
    assert.equal(seen[0].get('authorization'), `Bearer ${await agent.token()}`);
    assert.equal(seen[0].get('x-api-key'), null);
  });

  it('refuses to send the token to another origin', async () => {
    const { as, agent } = agentFor('EdDSA');
    await assert.rejects(agent.fetch('https://api.anthropic.com/v1/messages'), { error: 'invalid_target' });
    assert.equal(as.requests.length, 0, 'not even a token was minted');
  });

  it('sends to an origin it was told to', async () => {
    const { as, agent } = agentFor('EdDSA', { agent: { allowedOrigins: ['https://gw.acme.example'] } });
    let auth = null;
    as.other = async (url, init) => { auth = new Headers(init.headers).get('authorization'); return new Response('{}'); };
    await agent.fetch('https://gw.acme.example/mcp');
    assert.match(auth, /^Bearer /);
  });
});

describe('AgentAuth: acting for a person (CIBA)', () => {
  it('asks with an assertion and a login hint, waits through pending and slow_down, and returns the delegated token', async () => {
    const { as, agent } = agentFor('ES256');
    as.pollScript = ['authorization_pending', 'slow_down', 'authorization_pending'];
    const waits = [];
    const approval = await agent.requestUserApproval({ loginHint: 'p@example.com', bindingMessage: 'Read your wiki topics', scope: 'mcp:read' });
    const back = as.requests.find((r) => r.url === BACKCHANNEL).form;
    assert.equal(back.get('login_hint'), 'p@example.com');
    assert.equal(back.get('binding_message'), 'Read your wiki topics');
    assert.equal(back.get('client_id'), 'agt_1');
    assert.ok(back.get('client_assertion'));
    const dt = await agent.awaitUserToken(approval, { sleep: async (ms) => { waits.push(ms); } });
    assert.deepEqual(waits, [2000, 2000, 7000, 7000]);
    assert.equal(dt.claims.sub, 'user:p@example.com');
    assert.equal(dt.claims.act.sub, 'agent:agt_1');
    const polls = as.tokenRequests().filter((r) => r.form.get('grant_type') === CIBA);
    assert.equal(polls.length, 4);
    assert.equal(new Set(polls.map((p) => p.form.get('client_assertion'))).size, 4, 'a fresh assertion every poll');
  });

  it('throws a refusal at once instead of polling on', async () => {
    const { as, agent } = agentFor('EdDSA');
    as.pollScript = ['access_denied', 'authorization_pending'];
    const approval = await agent.requestUserApproval({ loginHint: 'p@example.com' });
    await assert.rejects(agent.awaitUserToken(approval, { sleep: noWait }), { error: 'access_denied' });
    assert.equal(as.tokenRequests().filter((r) => r.form.get('grant_type') === CIBA).length, 1);
  });

  it('gives up at the deadline', async () => {
    const { as, agent } = agentFor('EdDSA');
    as.pollScript = Array(50).fill('authorization_pending');
    const approval = await agent.requestUserApproval({ loginHint: 'p@example.com' });
    const realNow = Date.now;
    let skew = 0;
    Date.now = () => realNow() + skew;
    try {
      const advance = async (ms) => { skew += ms; };
      await assert.rejects(agent.awaitUserToken(approval, { timeout: 5000, sleep: advance }), { error: 'authorization_pending', status: 408 });
    } finally {
      Date.now = realNow;
    }
    assert.equal(as.tokenRequests().filter((r) => r.form.get('grant_type') === CIBA).length, 2);
  });

  it('stops when aborted', async () => {
    const { agent } = agentFor('EdDSA');
    const approval = await agent.requestUserApproval({ loginHint: 'p@example.com' });
    const ctl = new AbortController();
    ctl.abort(new Error('run cancelled'));
    await assert.rejects(agent.awaitUserToken(approval, { signal: ctl.signal }), /run cancelled/);
  });

  it('does not pretend a CIBA token can be renewed', async () => {
    const { agent } = agentFor('EdDSA');
    const approval = await agent.requestUserApproval({ loginHint: 'p@example.com' });
    const dt = await agent.awaitUserToken(approval, { sleep: noWait });
    assert.equal(await dt.token(), dt.accessToken);
    dt.expiresAt = Date.now() - 1;
    await assert.rejects(dt.token(), { error: 'expired_token' });
  });

  it('requires a login hint', async () => {
    const { agent } = agentFor('EdDSA');
    await assert.rejects(agent.requestUserApproval({}), { error: 'invalid_request' });
  });
});

describe('AgentAuth: token exchange (RFC 8693)', () => {
  const personToken = `e30.${Buffer.from(JSON.stringify({ sub: 'user:p@example.com' })).toString('base64url')}.s`;

  it('exchanges a person\'s token with its own token as the actor, and no client credentials', async () => {
    const { as, agent } = agentFor('PS256');
    const dt = await agent.exchangeToken({ subjectToken: personToken, resource: `${ISSUER}/mcp`, scope: 'mcp:read' });
    assert.equal(dt.claims.sub, 'user:p@example.com');
    assert.equal(dt.claims.act.sub, 'agt_1');
    const form = as.tokenRequests().find((r) => r.form.get('grant_type') === TX).form;
    assert.equal(form.get('subject_token'), personToken);
    assert.equal(form.get('subject_token_type'), 'urn:ietf:params:oauth:token-type:access_token');
    assert.equal(form.get('actor_token'), await agent.token());
    assert.equal(form.get('actor_token_type'), 'urn:ietf:params:oauth:token-type:access_token');
    assert.equal(form.get('client_id'), null);
    assert.equal(form.get('client_assertion'), null);
  });

  it('renews the delegated token by exchanging again', async () => {
    const { as, agent } = agentFor('EdDSA');
    const dt = await agent.exchangeToken({ subjectToken: personToken });
    const first = dt.accessToken;
    assert.equal(await dt.token(), first);
    dt.expiresAt = Date.now() + 10000;
    const second = await dt.token();
    assert.notEqual(second, first);
    assert.equal(as.tokenRequests().filter((r) => r.form.get('grant_type') === TX).length, 2);
  });

  it('surfaces a refused delegation as access_denied', async () => {
    const { as, agent } = agentFor('EdDSA');
    as.exchangeAllowed = false;
    await assert.rejects(agent.exchangeToken({ subjectToken: personToken }), { error: 'access_denied', status: 403 });
  });

  it('sends the delegated token through its own fetch', async () => {
    const { as, agent } = agentFor('EdDSA');
    const dt = await agent.exchangeToken({ subjectToken: personToken });
    let auth = null;
    as.other = async (url, init) => { auth = new Headers(init.headers).get('authorization'); return new Response('{}'); };
    await dt.fetch(`${ISSUER}/mcp`, { method: 'POST' });
    assert.equal(auth, `Bearer ${dt.accessToken}`);
  });
});

describe('AgentAuth.fromEnv', () => {
  it('builds from a key file', async () => {
    const as = fakeAS();
    const key = AgentKey.generate('ES256', { kid: 'k1' });
    as.register('agt_1', key);
    const agent = AgentAuth.fromEnv({
      AUTHFI_ISSUER: ISSUER, AUTHFI_AGENT_ID: 'agt_1', AUTHFI_AGENT_KID: 'k1', AUTHFI_AGENT_KEY_FILE: tmpFile('a.pem', key.privatePem()),
    }, { fetch: as.fetch });
    assert.ok(await agent.token());
  });

  it('needs a key and an issuer', () => {
    assert.throws(() => AgentAuth.fromEnv({ AUTHFI_ISSUER: ISSUER, AUTHFI_AGENT_ID: 'agt_1' }), { error: 'invalid_key' });
    const pem = AgentKey.generate('EdDSA').privatePem();
    assert.throws(() => AgentAuth.fromEnv({ AUTHFI_AGENT_ID: 'agt_1', AUTHFI_AGENT_KID: 'k', AUTHFI_AGENT_KEY_FILE: tmpFile('b.pem', pem) }), { message: /issuer is required/ });
  });
});
