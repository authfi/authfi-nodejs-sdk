'use strict';

// Live test against a real AuthFI project. Skipped unless these are set:
//
//   AUTHFI_LIVE_ISSUER               the project's origin, e.g. a testing project's
//   AUTHFI_LIVE_CONSOLE_TOKEN(_FILE) a console access token of an administrator of that project
//                                    (a test user: the test also asks them, as the person, to
//                                    approve a CIBA request and to be acted for by token exchange)
//   AUTHFI_LIVE_USER_AUDIENCE        the aud of that console token (default authfi-console)
//   AUTHFI_LIVE_OTHER_ISSUER         optional: another project, whose public keys must not verify
//                                    this project's tokens (only its discovery and JWKS are read)
//
// It registers one agent per key type through the console API, and removes them again (delete,
// and the delegation it granted) whatever the outcome. No token or key is printed.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const authfi = require('..');
const { AgentKey, AgentAuth } = authfi;

const ISSUER = process.env.AUTHFI_LIVE_ISSUER;
const CONSOLE_TOKEN = process.env.AUTHFI_LIVE_CONSOLE_TOKEN
  || (process.env.AUTHFI_LIVE_CONSOLE_TOKEN_FILE && fs.readFileSync(process.env.AUTHFI_LIVE_CONSOLE_TOKEN_FILE, 'utf8').trim());
const USER_AUDIENCE = process.env.AUTHFI_LIVE_USER_AUDIENCE || 'authfi-console';
const OTHER_ISSUER = process.env.AUTHFI_LIVE_OTHER_ISSUER;
const skip = !(ISSUER && CONSOLE_TOKEN) && 'set AUTHFI_LIVE_ISSUER and AUTHFI_LIVE_CONSOLE_TOKEN to run against a real project';

const RUN = crypto.randomBytes(3).toString('hex');
const ALGS = ['EdDSA', 'ES256', 'PS256'];

async function gql(query, variables = {}) {
  const res = await fetch(`${ISSUER}/graphql`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${CONSOLE_TOKEN}` },
    body: JSON.stringify({ query, variables }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.errors) throw new Error(`console API ${res.status}: ${JSON.stringify(body.errors || body).slice(0, 300)}`);
  return body.data;
}

const claimsOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'));
const headerOf = (t) => JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString('utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('live: agent identity and verifyToken against a real project', { skip, timeout: 300000 }, () => {
  const agents = {}; // alg -> {id, key, auth}
  const delegations = [];
  let me;
  let person; // the person principal, as their own token names it
  const api = () => authfi({ issuer: ISSUER, audience: `${ISSUER}/mcp` });

  before(async () => {
    me = (await gql('{ me { id email } }')).me;
    const sub = claimsOf(CONSOLE_TOKEN).sub;
    person = String(sub).startsWith('user:') ? sub : `user:${sub}`;
    for (const alg of ALGS) {
      const key = AgentKey.generate(alg, { kid: `sdk-live-${RUN}-${alg.toLowerCase()}` });
      const out = await gql(
        'mutation($i:RegisterAgentInput!){ registerAgent(input:$i){ id type } }',
        { i: { name: `sdk-live-${RUN}-${alg}`, type: 'delegated', publicJwk: JSON.stringify(key.publicJwk()), jwkKid: key.kid, ownerUserId: me.id } },
      );
      agents[alg] = { id: out.registerAgent.id, key, auth: new AgentAuth({ issuer: ISSUER, agentId: out.registerAgent.id, key }) };
    }
  });

  after(async () => {
    for (const [agentId, object] of delegations) {
      await gql('mutation($a:ID!,$o:String!){ revokeXaaDelegation(agentId:$a, object:$o) }', { a: agentId, o: object }).catch((e) => console.error('cleanup:', e.message));
    }
    for (const a of Object.values(agents)) {
      await gql('mutation($id:ID!){ deleteAgent(id:$id) }', { id: a.id }).catch((e) => console.error('cleanup:', e.message));
    }
  });

  for (const alg of ALGS) {
    it(`${alg} agent: own token by private_key_jwt, verified by verifyToken`, async () => {
      const { id, auth } = agents[alg];
      const token = await auth.token();
      const claims = await api().verifyToken(token);
      assert.equal(claims.sub, id);
      assert.equal(claims.iss, ISSUER);
      assert.equal(headerOf(token).alg, 'EdDSA', 'agent tokens are signed EdDSA by the project');
      assert.equal(await auth.token(), token, 'the cached token is reused');
    });
  }

  it('a key the project never registered is refused', async () => {
    const impostor = new AgentAuth({ issuer: ISSUER, agentId: agents.EdDSA.id, key: AgentKey.generate('EdDSA', { kid: agents.EdDSA.key.kid }) });
    await assert.rejects(impostor.token(), { error: 'invalid_client' });
  });

  it('verifyToken refuses an agent token for another audience, with alg changed, or from another project', async () => {
    const token = await agents.ES256.auth.token();
    await assert.rejects(authfi({ issuer: ISSUER, audience: 'https://not-this-api.example' }).verifyToken(token), { code: 'audience_mismatch' });
    const [, p, s] = token.split('.');
    const forged = `${Buffer.from(JSON.stringify({ ...headerOf(token), alg: 'RS256' })).toString('base64url')}.${p}.${s}`;
    await assert.rejects(api().verifyToken(forged), { code: 'alg_mismatch' });
    if (OTHER_ISSUER) {
      // Another project's keys do not include this project's kid, and its iss is not this one.
      await assert.rejects(authfi({ issuer: OTHER_ISSUER, audience: `${ISSUER}/mcp` }).verifyToken(token), (e) => ['kid_unknown', 'issuer_mismatch'].includes(e.code));
    }
  });

  it('verifyToken verifies a person\'s RS256 token with the same keys', async () => {
    const claims = await authfi({ issuer: ISSUER, audience: USER_AUDIENCE }).verifyToken(CONSOLE_TOKEN);
    assert.equal(headerOf(CONSOLE_TOKEN).alg, 'RS256');
    assert.equal(claims.iss, ISSUER);
  });

  it('token exchange: refused without a delegation, then sub = the person and act.sub = the agent', async () => {
    const { id, auth } = agents.EdDSA;
    await assert.rejects(auth.exchangeToken({ subjectToken: CONSOLE_TOKEN, resource: `${ISSUER}/mcp` }), { error: 'access_denied' });
    await gql('mutation($a:ID!,$o:String!){ grantXaaDelegation(agentId:$a, object:$o) }', { a: id, o: person });
    delegations.push([id, person]);
    await sleep(2000);
    const delegated = await auth.exchangeToken({ subjectToken: CONSOLE_TOKEN, resource: `${ISSUER}/mcp` });
    const claims = await api().verifyToken(await delegated.token());
    assert.equal(`user:${String(claims.sub).replace(/^user:/, '')}`, person);
    assert.match(String(claims.act && claims.act.sub), new RegExp(`${id}$`));
  });

  it('CIBA: the person approves in their own sign-in, the agent gets a token naming both', async () => {
    const { id, auth } = agents.PS256;
    const bindingMessage = `SDK live test ${RUN}: let the test agent act for you`;
    const approval = await auth.requestUserApproval({ loginHint: me.email, bindingMessage, requestedExpiry: 300 });
    assert.ok(approval.auth_req_id);
    const waiting = auth.awaitUserToken(approval, { timeout: 120000 });
    let decided = false;
    for (let i = 0; i < 20 && !decided; i += 1) {
      await sleep(1500);
      const reqs = (await gql('{ myAgentRequests { authReqId agentId bindingMessage status } }')).myAgentRequests;
      const mine = reqs.find((r) => r.agentId === id && r.bindingMessage === bindingMessage);
      if (mine) {
        await gql('mutation($id:ID!,$d:ApprovalDecision!){ decideMyAgentRequest(authReqId:$id, decision:$d){ status } }', { id: mine.authReqId, d: 'APPROVE' });
        decided = true;
      }
    }
    assert.ok(decided, 'the request reached the person');
    const delegated = await waiting;
    const claims = await api().verifyToken(await delegated.token());
    assert.equal(claims.sub, `user:${me.email}`);
    assert.equal(claims.act.sub, `agent:${id}`);
  });

  it('CIBA: a person who says no is a refusal, not a timeout', async () => {
    const { id, auth } = agents.ES256;
    const bindingMessage = `SDK live test ${RUN}: deny this one`;
    const approval = await auth.requestUserApproval({ loginHint: me.email, bindingMessage, requestedExpiry: 300 });
    const waiting = auth.awaitUserToken(approval, { timeout: 120000 });
    for (let i = 0; i < 20; i += 1) {
      await sleep(1500);
      const reqs = (await gql('{ myAgentRequests { authReqId agentId bindingMessage status } }')).myAgentRequests;
      const mine = reqs.find((r) => r.agentId === id && r.bindingMessage === bindingMessage);
      if (mine) {
        await gql('mutation($id:ID!,$d:ApprovalDecision!){ decideMyAgentRequest(authReqId:$id, decision:$d){ status } }', { id: mine.authReqId, d: 'DENY' });
        break;
      }
    }
    await assert.rejects(waiting, { error: 'access_denied' });
  });
});
