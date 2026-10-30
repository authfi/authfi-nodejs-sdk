import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeJwt } from 'jose';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentAuth } from '../../src/agents/agent.js';
import { InstanceAuth } from '../../src/agents/instance.js';
import { AuthFI } from '../../src/core/project.js';
import { connect, findEvidence, generateAgentKeyFile, instanceFromEnv } from '../../src/node/index.js';
import { AGENT, CONFIG, FakePlatform } from '../support/fake-platform.js';
import { call, quiet } from '../support/platform-setup.js';
import { TestClock, unsignedJwt } from '../support/issuer.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'authfi-instance-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

let serial = 0;
/** A projected service-account token: a JWT for the audience, with its own `jti`. */
function sa(aud: string | string[], jti = `sa-${String(++serial)}`): string {
  return unsignedJwt({ alg: 'RS256' }, { aud, jti, sub: 'system:serviceaccount:agents:refund-bot' });
}

async function setup() {
  const clock = new TestClock();
  clock.wall = Date.UTC(2026, 9, 30, 12, 0, 0);
  const p = await FakePlatform.create(clock);
  const warns: string[] = [];
  const file = join(dir, 'token');
  await writeFile(file, sa(p.origin));
  const env = {
    AUTHFI_ISSUER: p.issuer,
    AUTHFI_AGENT_ID: AGENT,
    AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE: file,
    AUTHFI_CONFIG_VERSION: String(CONFIG.version),
    AUTHFI_CONFIG_DIGEST: CONFIG.digest,
  };
  const options = {
    fetch: p.fetch,
    clock,
    retries: 0,
    logger: { ...quiet, warn: (m: string) => warns.push(m) },
  };
  return { clock, p, warns, file, env, options };
}

describe('connect() signs in as an instance on a bound workload', () => {
  it('finds its evidence itself, makes its key, and trades them for an attested, bound token', async () => {
    const { env, options, p } = await setup();
    const agent = await connect(env, options);
    expect(agent).toBeInstanceOf(InstanceAuth);
    const token = await agent.token();
    const claims = decodeJwt(token);
    expect(claims.instance_id).toMatch(/^inst_[0-9a-f]{32}$/);
    expect(claims.cnf).toEqual({ jkt: agent.dpop!.thumbprint });
    expect((agent as InstanceAuth).instanceId).toBe(claims.instance_id);
    expect(p.attestations).toBe(1);
    expect(p.refusals).toEqual([]);
    // challenge, attest, token: the token request carried all three proofs
    const mint = p.t.fake.to(`${p.issuer}/oauth/token`).at(-1)!;
    expect(mint.headers.get('oauth-client-attestation')).toMatch(/^eyJ/);
    expect(mint.headers.get('oauth-client-attestation-pop')).toMatch(/^eyJ/);
    expect(mint.headers.get('dpop')).toMatch(/^eyJ/);
    const form = new URLSearchParams(mint.body);
    expect(form.get('client_id')).toBe(AGENT);
    expect(form.has('client_assertion')).toBe(false);
    // the attest request carried the instance's public key and configuration, and no private member
    const attest = JSON.parse(p.t.fake.to(`${p.origin}/apis/regional/v1/ai/agents/attest`)[0]!.body);
    expect(attest.config).toEqual(CONFIG);
    expect(attest.instance_key.d).toBeUndefined();
    expect(attest.evidence.kind).toBe('k8s');
  });

  it('carries the proof on the gateway, the exporter door and customer APIs', async () => {
    const { env, options, p } = await setup();
    const agent = await connect(env, options);
    const res = await agent
      .gateway()
      .fetch(`${p.issuer}/mcp`, { method: 'POST', body: call('billing__lookup') });
    expect(res.status).toBe(200);
    const headers = await (agent as InstanceAuth)
      .forResource('api_orders', { sendTo: ['https://orders.example.com'] })
      .headers('GET', 'https://orders.example.com/v1/orders');
    expect(headers.authorization).toMatch(/^DPoP /);
    expect(headers.dpop).toMatch(/^eyJ/);
  });

  it('reuses the attestation between mints, and attests again before it expires with a rotated token', async () => {
    const { env, options, p, clock, file } = await setup();
    p.tokenLifetime = 300;
    const agent = await connect(env, options);
    await agent.token();
    clock.advance(p.tokenLifetime * 1000);
    await agent.token();
    expect(p.attestations).toBe(1);
    expect(p.mints).toBe(2);
    clock.advance((p.attestLifetime - p.tokenLifetime) * 1000 - 30_000);
    // The service-account token has not rotated yet: the SDK says so rather than spend it twice.
    await expect(agent.token({ force: true })).rejects.toThrow(/has not rotated/);
    await writeFile(file, sa(p.origin));
    await agent.token({ force: true });
    expect(p.attestations).toBe(2);
  });

  it('is refused by the platform for a service-account token it saw before, and says where the reason is', async () => {
    const { env, options, p, file } = await setup();
    const jti = 'same-jti';
    await writeFile(file, sa(p.origin, jti));
    await (await connect(env, options)).token();
    await writeFile(file, sa(p.origin, jti)); // new bytes, same jti
    const second = await connect(env, options);
    await expect(second.token()).rejects.toThrow(/audit tape \(agent\.attest\.refused\)/);
    expect(p.refusals.at(-1)).toContain('evidence replayed');
  });

  it('names the fix for an audience that is not the project, an empty or unreadable file, and no configuration', async () => {
    const { env, options, file, p } = await setup();
    await writeFile(file, sa('https://elsewhere.example'));
    await expect((await connect(env, options)).token()).rejects.toThrow(
      /is for https:\/\/elsewhere\.example, not https:\/\/acme\.authfi\.io\. Project one with audience/,
    );
    await writeFile(file, '');
    await expect((await connect(env, options)).token()).rejects.toThrow(/is empty/);
    await writeFile(file, 'not a jwt');
    await expect((await connect(env, options)).token()).rejects.toThrow(
      /does not hold a service-account JWT/,
    );
    await rm(file);
    await expect((await connect(env, options)).token()).rejects.toThrow(/cannot read the evidence file/);
    const noConfig = { ...env, AUTHFI_CONFIG_VERSION: '', AUTHFI_CONFIG_DIGEST: '' };
    await writeFile(file, sa(p.origin));
    await expect(connect(noConfig, options)).rejects.toThrow(/AUTHFI_CONFIG_VERSION/);
    await expect(connect({ ...env, AUTHFI_CONFIG_VERSION: 'seven' }, options)).rejects.toThrow(
      /AUTHFI_CONFIG_VERSION is the approved version number/,
    );
    await expect(connect({ ...env, AUTHFI_IMAGE_DIGEST: 'latest' }, options)).rejects.toThrow(
      /AUTHFI_IMAGE_DIGEST is sha256/,
    );
    expect(p.attestations).toBe(0);
  });

  it('is refused for a configuration the platform has not approved', async () => {
    const { env, options, p } = await setup();
    const agent = await connect({ ...env, AUTHFI_CONFIG_VERSION: '8' }, options);
    await expect(agent.token()).rejects.toThrow(/refuses every failed sign-in the same way/);
    expect(p.refusals.at(-1)).toContain('config_not_approved');
  });

  it('is told to sign in again when the platform could not decide', async () => {
    const { env, options, p } = await setup();
    p.t.fake.on(
      'POST',
      `${p.origin}/apis/regional/v1/ai/agents/attest`,
      () => new Response(JSON.stringify({ error: 'temporarily_unavailable' }), { status: 503 }),
    );
    await expect((await connect(env, options)).token()).rejects.toThrow(/Sign in again/);
  });

  it('refuses an attestation that names another agent, another key, or a longer life than the platform signs', async () => {
    for (const [tamper, why] of [
      [(c: Record<string, unknown>) => (c.sub = 'agt_other'), /is for "agt_other"/],
      [
        (c: Record<string, unknown>) => (c.cnf = { jwk: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' } }),
        /different key/,
      ],
      [(c: Record<string, unknown>) => (c.exp = (c.iat as number) + 3600), /lives longer than 900 seconds/],
      [
        (c: Record<string, unknown>) => (c.authfi_instance = { instance_id: 'inst_x' }),
        /names no instance_id/,
      ],
      [(c: Record<string, unknown>) => (c.exp = (c.iat as number) - 5), /already expired/],
    ] as const) {
      const { env, options, p } = await setup();
      p.tamper = tamper;
      await expect((await connect(env, options)).token()).rejects.toThrow(why);
    }
  });

  it('refuses a platform that answers an attestation of the wrong type or none', async () => {
    const { env, options, p } = await setup();
    p.t.fake.on(
      'POST',
      `${p.origin}/apis/regional/v1/ai/agents/attest`,
      () => new Response(JSON.stringify({ attestation: unsignedJwt({ typ: 'JWT' }, { sub: AGENT }) })),
    );
    await expect((await connect(env, options)).token()).rejects.toThrow(/has typ "JWT"/);
    p.t.fake.on('POST', `${p.origin}/apis/regional/v1/ai/agents/attest`, () => new Response('{}'));
    await expect((await connect(env, options)).token()).rejects.toThrow(/answered no attestation/);
    p.t.fake.on('POST', `${p.origin}/apis/regional/v1/ai/agents/attest/challenge`, () => new Response('{}'));
    await expect((await connect(env, options)).token()).rejects.toThrow(/answered no nonce/);
  });

  it('acts for a person by token exchange, bound to the instance key, but not by CIBA, approval or mandate', async () => {
    const { env, options, p, clock } = await setup();
    const agent = (await connect(env, options)) as InstanceAuth;
    const now = Math.floor(clock.now() / 1000);
    const { Secret } = await import('../../src/core/secret.js');
    const subject = new Secret(await p.t.sign({ sub: 'usr_9', exp: now + 3600 }, { nowSeconds: now }));
    const delegated = await agent.exchange(subject);
    expect(delegated.dpop?.thumbprint).toBe(agent.dpop!.thumbprint);
    for (const refused of [
      () => agent.requestUserToken({ loginHint: 'a@b.c', bindingMessage: 'Refund' }),
      () => agent.requestApproval('refund'),
      () => agent.requestMandate('support.refund', { subjectToken: subject }),
    ]) {
      await expect(refused()).rejects.toMatchObject({
        name: 'NotSupportedError',
        feature: 'instance_assertion',
      });
    }
    expect(String(agent)).toBe(`InstanceAuth(${AGENT})`);
  });
});

describe('connect() chooses how to sign in', () => {
  it('takes a device key as evidence, bound to the instance key', async () => {
    const { env, options, p } = await setup();
    const path = join(dir, 'device.pem');
    const device = await generateAgentKeyFile(path, 'EdDSA', { kid: 'device-1' });
    p.devices.set('device-1', device.publicJwk());
    const { AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE: _unused, ...rest } = env;
    const agent = await connect(
      { ...rest, AUTHFI_DEVICE_KEY_FILE: path, AUTHFI_DEVICE_KEY_KID: 'device-1' },
      options,
    );
    expect(agent).toBeInstanceOf(InstanceAuth);
    await agent.token();
    expect(p.refusals).toEqual([]);
    const attest = JSON.parse(p.t.fake.to(`${p.origin}/apis/regional/v1/ai/agents/attest`)[0]!.body);
    expect(attest.evidence.kind).toBe('device');
  });

  it('refuses a device key the device was not bound with', async () => {
    const { env, options, p } = await setup();
    const path = join(dir, 'device.pem');
    const real = await generateAgentKeyFile(path, 'EdDSA', { kid: 'device-1' });
    const other = await generateAgentKeyFile(join(dir, 'other.pem'), 'EdDSA', { kid: 'device-1' });
    p.devices.set('device-1', other.publicJwk());
    expect(real.kid).toBe('device-1');
    const agent = await connect(
      { ...env, AUTHFI_DEVICE_KEY_FILE: path, AUTHFI_DEVICE_KEY_KID: 'device-1' },
      options,
    );
    await expect(agent.token()).rejects.toThrow(/audit tape/);
    expect(p.refusals.at(-1)).toContain('device signature');
    const missing = await connect(
      { ...env, AUTHFI_DEVICE_KEY_FILE: join(dir, 'nope.pem'), AUTHFI_DEVICE_KEY_KID: 'device-1' },
      options,
    );
    await expect(missing.token()).rejects.toThrow(/cannot use the device key/);
  });

  it('keeps a key file named with no configuration as the legacy agent key, and says so once', async () => {
    const { env, options, warns, p } = await setup();
    const path = join(dir, 'agent.pem');
    await generateAgentKeyFile(path, 'ES256', { kid: 'k1' });
    const { AUTHFI_CONFIG_VERSION: _v, AUTHFI_CONFIG_DIGEST: _d, ...rest } = env;
    const agent = await connect({ ...rest, AUTHFI_AGENT_KEY_FILE: path, AUTHFI_AGENT_KID: 'k1' }, options);
    expect(agent).toBeInstanceOf(AgentAuth);
    expect(agent).not.toBeInstanceOf(InstanceAuth);
    expect(warns.filter((w) => w.includes('legacy'))).toHaveLength(1);
    expect(p.attestations).toBe(0);
  });

  it('prefers the instance when evidence and configuration are both named, key file or not', async () => {
    const { env, options } = await setup();
    const path = join(dir, 'agent.pem');
    await generateAgentKeyFile(path, 'ES256', { kid: 'k1' });
    expect(
      await connect({ ...env, AUTHFI_AGENT_KEY_FILE: path, AUTHFI_AGENT_KID: 'k1' }, options),
    ).toBeInstanceOf(InstanceAuth);
  });

  it('names what is missing when an agent has no way in', async () => {
    const { options, p } = await setup();
    await expect(
      connect({ AUTHFI_ISSUER: p.issuer, AUTHFI_AGENT_ID: AGENT }, { ...options }),
    ).rejects.toThrow(/has no way to sign in/);
    await expect(
      instanceFromEnv(new AuthFI({ issuer: p.issuer, fetch: p.fetch }), { AUTHFI_AGENT_ID: AGENT }),
    ).rejects.toThrow(/shows no evidence/);
    await expect(instanceFromEnv(new AuthFI({ issuer: p.issuer, fetch: p.fetch }), {})).rejects.toThrow(
      /AUTHFI_AGENT_ID is not set/,
    );
    expect(await findEvidence({})).toBeUndefined();
  });
});

describe('the rest of the instance sign-in', () => {
  it('passes a refusal the attest route gives for a bad request through unchanged', async () => {
    const { env, options, p } = await setup();
    p.t.fake.on(
      'POST',
      `${p.origin}/apis/regional/v1/ai/agents/attest`,
      () => new Response(JSON.stringify({ error: 'invalid_body' }), { status: 400 }),
    );
    const failed = await (await connect(env, options)).token().catch((e: unknown) => e as Error);
    expect(failed).toMatchObject({ code: 'invalid_body' });
    expect((failed as Error).message).not.toMatch(/audit tape/);
  });

  it('refuses a challenge that is refused, an attestation that is not a JWT, and one with no lifetime', async () => {
    const a = await setup();
    a.p.t.fake.on(
      'POST',
      `${a.p.origin}/apis/regional/v1/ai/agents/attest/challenge`,
      () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 }),
    );
    await expect((await connect(a.env, a.options)).token()).rejects.toThrow(/audit tape/);
    const b = await setup();
    b.p.t.fake.on(
      'POST',
      `${b.p.origin}/apis/regional/v1/ai/agents/attest`,
      () => new Response(JSON.stringify({ attestation: 'garbage' })),
    );
    await expect((await connect(b.env, b.options)).token()).rejects.toThrow(/attestation is not a JWT/);
    const c = await setup();
    c.p.tamper = (claims) => {
      delete claims.exp;
    };
    await expect((await connect(c.env, c.options)).token()).rejects.toThrow(/has no lifetime/);
  });

  it('sends the image it runs, and checks it first', async () => {
    const { env, options, p } = await setup();
    const image = `sha256:${'b'.repeat(64)}`;
    await (await connect({ ...env, AUTHFI_IMAGE_DIGEST: image }, options)).token();
    expect(
      JSON.parse(p.t.fake.to(`${p.origin}/apis/regional/v1/ai/agents/attest`)[0]!.body).image_digest,
    ).toBe(image);
  });

  it('does not sign in at a project that offers no client credentials', async () => {
    const { env, options, p } = await setup();
    p.t.metadataExtra = { grant_types_supported: ['authorization_code'] };
    await expect((await connect(env, options)).token()).rejects.toMatchObject({
      name: 'NotSupportedError',
      feature: 'client_credentials',
    });
  });

  it('cannot run without DPoP: its token is bound by the attestation', async () => {
    const { env, options, p } = await setup();
    const af = AuthFI.fromEnv(env, options);
    const agent = await instanceFromEnv(af, env);
    expect(agent.toJSON()).toEqual({ agentId: AGENT, issuer: p.issuer, kid: 'instance' });
    const off = new InstanceAuth(af, {
      agentId: AGENT,
      evidence: (await findEvidence(env))!,
      config: CONFIG,
    });
    expect(off.instanceId).toBeUndefined();
  });
});
