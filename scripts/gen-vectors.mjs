#!/usr/bin/env node
// Generates conformance/vectors.json: access tokens signed by fresh test keys, each with the outcome
// and refusal code every AuthFI SDK must produce (design §6.2). The private keys are discarded; the
// file holds the public key set, the tokens and the expectations, so any language can run it.
//
//   node scripts/gen-vectors.mjs           writes the file and its checksum
//   node scripts/gen-vectors.mjs --check   checks the file against its checksum

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'conformance');
const FILE = resolve(DIR, 'vectors.json');
const SUM = resolve(DIR, 'vectors.json.sha256');

const ISSUER = 'https://vectors.authfi.io';
const AUDIENCE = ['api_orders'];
const TENANT = '4e46e0c4-ec26-48e1-b5bb-04a1ec3ff358';
const NOW = 1_792_497_600; // 2026-10-20T00:00:00Z

function step(message) {
  process.stdout.write(`gen-vectors: ${message}\n`);
}

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

if (process.argv.includes('--check')) {
  const text = readFileSync(FILE, 'utf8');
  const recorded = readFileSync(SUM, 'utf8').trim().split(/\s+/)[0];
  if (sha256(text) !== recorded) {
    process.stderr.write('gen-vectors: FAILED: conformance/vectors.json does not match its checksum\n');
    process.exit(1);
  }
  step('vectors.json matches its checksum');
  process.exit(0);
}

async function key(alg, kid) {
  const pair =
    alg === 'EdDSA'
      ? await generateKeyPair('Ed25519', { extractable: true })
      : await generateKeyPair(alg, { extractable: true });
  return {
    alg,
    kid,
    privateKey: pair.privateKey,
    jwk: { ...(await exportJWK(pair.publicKey)), kid, alg, use: 'sig' },
  };
}

const keys = {
  RS256: await key('RS256', 'rsa-v1'),
  EdDSA: await key('EdDSA', 'okp-v1'),
  ES256: await key('ES256', 'ec-v1'),
};
const other = await key('RS256', 'rsa-v1');

async function sign(claims = {}, { alg = 'RS256', header = {}, signer } = {}) {
  const k = signer ?? keys[alg];
  const body = {
    iss: ISSUER,
    sub: 'usr_1',
    aud: AUDIENCE,
    exp: NOW + 900,
    iat: NOW,
    tenant_id: TENANT,
    client_id: 'app_web',
    ...claims,
  };
  for (const [k2, v] of Object.entries(body)) if (v === null) delete body[k2];
  return new SignJWT(body)
    .setProtectedHeader({ alg, typ: 'at+jwt', kid: k.kid, ...header })
    .sign(k.privateKey);
}

function unsigned(header, payload) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b(header)}.${b(payload)}.c2ln`;
}

// `extra` adds what a vector pins beyond who the token is for: `client_id` and `scopes`.
const ok = (principal, tokenKind, actor = null, extra = {}) => ({
  valid: true,
  principal,
  token_kind: tokenKind,
  actor,
  ...extra,
});
const no = (code) => ({ valid: false, code });

const vectors = [
  ['person, RS256', await sign(), ok('user:usr_1', 'person')],
  [
    'machine client, RS256',
    await sign({ sub: 'app_m2m', client_id: 'app_m2m' }),
    ok('app:app_m2m', 'machine'),
  ],
  [
    'agent, EdDSA',
    await sign({ sub: 'agt_1', client_id: 'agt_1', aud: 'api_orders' }, { alg: 'EdDSA' }),
    ok('agent:agt_1', 'agent'),
  ],
  [
    'agent, ES256',
    await sign({ sub: 'agt_2', client_id: 'agt_2' }, { alg: 'ES256' }),
    ok('agent:agt_2', 'agent'),
  ],
  [
    'delegated by CIBA, EdDSA',
    await sign({ sub: 'user:usr_1', act: { sub: 'agent:agt_1' }, client_id: 'agt_1' }, { alg: 'EdDSA' }),
    ok('user:usr_1', 'delegated', 'agent:agt_1'),
  ],
  [
    'delegated by exchange, RS256',
    await sign({ sub: 'usr_1', act: { sub: 'agt_1' }, client_id: 'agt_1' }),
    ok('user:usr_1', 'delegated', 'agent:agt_1'),
  ],
  [
    'typ application/at+jwt',
    await sign({}, { header: { typ: 'application/at+jwt' } }),
    ok('user:usr_1', 'person'),
  ],
  ['expired within the leeway', await sign({ exp: NOW - 30 }), ok('user:usr_1', 'person')],
  // The boundary: a token is expired from `exp` plus the leeway (RFC 7519 section 4.1.4).
  ['one second inside the leeway', await sign({ exp: NOW - 59 }), ok('user:usr_1', 'person')],
  ['exactly at exp plus the leeway', await sign({ exp: NOW - 60 }), no('token_expired')],
  // Who a token is for, read the same by every SDK (design section 2.2.2).
  [
    'typed agent with an actor keeps its own kind',
    await sign({ sub: 'agent:agt_1', act: { sub: 'agt_2' }, client_id: 'agt_1' }),
    ok('agent:agt_1', 'agent', 'agent:agt_2'),
  ],
  [
    'typed app with an actor keeps its own kind',
    await sign({ sub: 'app:app_1', act: { sub: 'agt_1' }, client_id: 'app_1' }),
    ok('app:app_1', 'machine', 'agent:agt_1'),
  ],
  ['typed app alone', await sign({ sub: 'app:app_1', client_id: 'app_1' }), ok('app:app_1', 'machine')],
  [
    'azp is not the client id',
    await sign({ sub: 'app_1', client_id: null, azp: 'app_1' }),
    ok('user:app_1', 'person', null, { client_id: '' }),
  ],
  [
    'scope is read, and scp is not',
    await sign({ scope: 'orders:read orders:write', scp: ['other'] }),
    ok('user:usr_1', 'person', null, { client_id: 'app_web', scopes: ['orders:read', 'orders:write'] }),
  ],
  [
    'scp alone gives no scopes',
    await sign({ scp: ['orders:read'] }),
    ok('user:usr_1', 'person', null, { scopes: [] }),
  ],
  [
    'a bound token is refused before its actor chain is looked at',
    await sign({ cnf: { jkt: 'abc' }, act: { sub: 'agent:agt_1', act: { sub: 'agent:agt_2' } } }),
    no('token_dpop_proof_required'),
  ],
  ['JWE', 'a.b.c.d.e', no('token_malformed')],
  ['two parts', 'a.b', no('token_malformed')],
  [
    'alg none',
    unsigned({ alg: 'none', typ: 'at+jwt', kid: 'rsa-v1' }, { iss: ISSUER }),
    no('token_signature_invalid'),
  ],
  [
    'HS256',
    unsigned({ alg: 'HS256', typ: 'at+jwt', kid: 'rsa-v1' }, { iss: ISSUER }),
    no('token_signature_invalid'),
  ],
  ['ID token (typ JWT)', await sign({}, { header: { typ: 'JWT' } }), no('token_not_access_token')],
  ['transaction token', await sign({}, { header: { typ: 'txn_token+jwt' } }), no('token_not_access_token')],
  [
    'unknown kid',
    unsigned({ alg: 'RS256', typ: 'at+jwt', kid: 'nope' }, { iss: ISSUER }),
    no('token_key_unknown'),
  ],
  [
    'alg disagrees with the key',
    unsigned({ alg: 'EdDSA', typ: 'at+jwt', kid: 'rsa-v1' }, { iss: ISSUER }),
    no('token_key_unknown'),
  ],
  [
    'signed by another key under a published kid',
    await sign({}, { signer: other }),
    no('token_signature_invalid'),
  ],
  ['another issuer', await sign({ iss: 'https://evil.authfi.io' }), no('token_issuer_not_accepted')],
  ['issuer with a trailing slash', await sign({ iss: `${ISSUER}/` }), no('token_issuer_not_accepted')],
  ['no exp', await sign({ exp: null }), no('token_claims_invalid')],
  ['expired', await sign({ exp: NOW - 120 }), no('token_expired')],
  ['nbf in the future', await sign({ nbf: NOW + 600 }), no('token_claims_invalid')],
  ['another audience', await sign({ aud: ['api_other'] }), no('token_audience_mismatch')],
  ['the gateway audience', await sign({ aud: `${ISSUER}/mcp` }), no('token_audience_mismatch')],
  ['no sub', await sign({ sub: null }), no('token_claims_invalid')],
  ['no tenant', await sign({ tenant_id: null }), no('token_no_tenant')],
  ['bound token as Bearer', await sign({ cnf: { jkt: 'abc' } }), no('token_dpop_proof_required')],
  [
    'nested act',
    await sign({ sub: 'user:usr_1', act: { sub: 'agent:agt_1', act: { sub: 'agent:agt_2' } } }),
    no('token_act_chain_unsupported'),
  ],
].map(([name, token, expect]) => ({ name, token, expect }));

const doc = {
  description: 'AuthFI SDK conformance vectors: verify each token as a Bearer credential at `now`.',
  issuer: ISSUER,
  audience: AUDIENCE,
  tenant_id: TENANT,
  now: NOW,
  leeway_seconds: 60,
  jwks: { keys: Object.values(keys).map((k) => k.jwk) },
  vectors,
};
const text = `${JSON.stringify(doc, null, 2)}\n`;
writeFileSync(FILE, text);
writeFileSync(SUM, `${sha256(text)}  vectors.json\n`);
step(`wrote ${vectors.length} vectors to ${FILE}`);
