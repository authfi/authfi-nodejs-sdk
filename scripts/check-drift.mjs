#!/usr/bin/env node
// Fetches a live project's public documents and checks every field the SDK depends on, so a platform
// change that would break the SDK is seen in a weekly run rather than by a customer. No credentials.
//
//   node scripts/check-drift.mjs [issuer]     (default https://platform-beta.authfi.io)

const issuer = process.argv[2] ?? process.env.AUTHFI_DRIFT_ISSUER ?? 'https://platform-beta.authfi.io';
const failures = [];

function step(message) {
  process.stdout.write(`check-drift: ${message}\n`);
}

function expect(ok, what) {
  if (ok) step(`ok   ${what}`);
  else {
    failures.push(what);
    process.stdout.write(`check-drift: FAIL ${what}\n`);
  }
}

async function get(path) {
  const res = await fetch(issuer + path, {
    headers: { accept: 'application/json', 'user-agent': 'authfi-node-drift-check' },
  });
  if (!res.ok) throw new Error(`${path} answered HTTP ${res.status}`);
  return res.json();
}

step(`reading ${issuer}`);
const meta = await get('/.well-known/openid-configuration');
expect(meta.issuer === issuer, 'discovery names the issuer exactly');
expect(meta.token_endpoint === `${issuer}/oauth/token`, 'token_endpoint is <issuer>/oauth/token');
expect(typeof meta.jwks_uri === 'string', 'jwks_uri is present');
expect(typeof meta.authorization_endpoint === 'string', 'authorization_endpoint is present');
expect(
  typeof meta.revocation_endpoint === 'string',
  'revocation_endpoint is present (sign-out revokes the refresh token)',
);
expect(typeof meta.end_session_endpoint === 'string', 'end_session_endpoint is present');
for (const g of [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:token-exchange',
  'urn:openid:params:grant-type:ciba',
]) {
  expect(meta.grant_types_supported?.includes(g), `grant ${g} is advertised`);
}
expect(
  meta.token_endpoint_auth_methods_supported?.includes('private_key_jwt'),
  'private_key_jwt is advertised',
);
expect(meta.code_challenge_methods_supported?.includes('S256'), 'PKCE S256 is advertised');
expect(
  meta.id_token_signing_alg_values_supported?.every((a) => ['RS256', 'ES256', 'EdDSA'].includes(a)),
  'ID tokens are signed with an algorithm the SDK verifies',
);
expect(typeof meta.backchannel_authentication_endpoint === 'string', 'the CIBA endpoint is advertised');

const jwks = await get(new URL(meta.jwks_uri).pathname);
const kinds = (jwks.keys ?? []).map((k) => `${k.kty}/${k.crv ?? k.alg}`);
expect(kinds.includes('OKP/Ed25519'), 'the key set holds an Ed25519 key (agent tokens)');
expect(
  kinds.some((k) => k.startsWith('RSA/')),
  'the key set holds an RSA key (people and machine tokens)',
);
expect(
  (jwks.keys ?? []).every((k) => k.d === undefined),
  'no published key carries a private member',
);

const agent = await get('/.well-known/agent-configuration');
expect(typeof agent.endpoints?.request_approval === 'string', 'agent-configuration names request_approval');
expect(
  typeof agent.endpoints?.approval === 'string' && agent.endpoints.approval.includes('{id}'),
  'agent-configuration names the approval URL template',
);

if (failures.length > 0) {
  process.stderr.write(
    `check-drift: FAILED: ${failures.length} check(s) failed against ${issuer}; read the lines above, then fix the SDK or file the platform change\n`,
  );
  process.exit(1);
}
step(`all checks passed against ${issuer}`);
