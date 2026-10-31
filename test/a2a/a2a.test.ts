import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { CompactSign, exportJWK, importJWK, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  A2AError,
  AGENT_CUSTODY_POLICY,
  AUTH_REQUIRED,
  canonicalJson,
  CardUnverified,
  FAILED,
  INPUT_REQUIRED,
  parseCard,
  REJECTED,
  remote,
  statusFor,
  statusForOutcome,
  toStatusObject,
  verifyCard,
  WORKING,
  type AgentCard,
} from '../../src/a2a/index.js';
import { base64url } from '../../src/core/bytes.js';
import type { HttpResponse } from '../../src/core/transport.js';
import { buildCert, KU, PEN_POLICY, PEN_POLICY_2 } from '../containment/certs.js';
import { json } from '../support/fake-fetch.js';
import { call, platform } from '../support/platform-setup.js';
import { AGENT, FakePlatform } from '../support/fake-platform.js';
import { TestClock } from '../support/issuer.js';
import { InstanceAuth } from '../../src/agents/instance.js';
import { AuthFI } from '../../src/core/project.js';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unsignedJwt } from '../support/issuer.js';
import { instanceFromEnv } from '../../src/node/index.js';
import { CONFIG } from '../support/fake-platform.js';

const ORIGIN = 'https://research.partner.example';
const NOW = Date.UTC(2026, 9, 30, 12, 0, 0);
const YEAR = 365 * 86_400_000;

const ed = () => generateKeyPairSync('ed25519');
const pem = (der: Buffer): string =>
  `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----`;

/** Root R1 > region intermediate > project CA > agent leaf, as an AuthFI agent's card is signed. */
function chain(
  options: {
    leafPolicy?: string;
    leafCA?: boolean;
    expired?: boolean;
    breakLink?: boolean;
  } = {},
) {
  const root = ed();
  const inter = ed();
  const project = ed();
  const agent = ed();
  const stranger = ed();
  const span = { notBefore: NOW - YEAR, notAfter: NOW + YEAR };
  const caKu = KU.keyCertSign | KU.cRLSign;
  const rootDer = buildCert({
    subject: 'R1',
    issuer: 'R1',
    subjectKey: root.publicKey,
    signerKey: root.privateKey,
    ...span,
    ca: true,
    keyUsage: caKu,
    policies: [PEN_POLICY],
  });
  const interDer = buildCert({
    subject: 'region',
    issuer: 'R1',
    subjectKey: inter.publicKey,
    signerKey: root.privateKey,
    ...span,
    ca: true,
    keyUsage: caKu,
    policies: [PEN_POLICY, PEN_POLICY_2],
  });
  const projectDer = buildCert({
    subject: 'project',
    issuer: 'region',
    subjectKey: project.publicKey,
    signerKey: inter.privateKey,
    ...span,
    ca: true,
    keyUsage: caKu,
    policies: [PEN_POLICY],
  });
  const leafDer = buildCert({
    subject: 'agent',
    issuer: 'project',
    subjectKey: agent.publicKey,
    signerKey: options.breakLink ? stranger.privateKey : project.privateKey,
    notBefore: NOW - YEAR,
    notAfter: options.expired ? NOW - 1000 : NOW + YEAR,
    ca: options.leafCA === true,
    keyUsage: options.leafCA === true ? caKu : KU.digitalSignature,
    policies: [options.leafPolicy ?? AGENT_CUSTODY_POLICY],
  });
  return {
    leafKey: agent.privateKey,
    x5c: [leafDer, projectDer, interDer].map((d) => d.toString('base64')),
    root: pem(rootDer),
    other: pem(
      buildCert({
        subject: 'R9',
        issuer: 'R9',
        subjectKey: stranger.publicKey,
        signerKey: stranger.privateKey,
        ...span,
        ca: true,
        keyUsage: caKu,
        policies: [PEN_POLICY],
      }),
    ),
  };
}

const baseCard = (origin = ORIGIN) => ({
  name: 'Research agent',
  description: 'Reads the web',
  version: '1.0.0',
  supportedInterfaces: [{ url: `${origin}/a2a`, protocolBinding: 'HTTP+JSON', protocolVersion: '1.0' }],
  securitySchemes: { oauth: { oauth2SecurityScheme: { flows: {} } } },
  skills: [{ id: 'research', name: 'Research', tags: ['web'] }],
});

/** The card with a `signatures` member: a JWS over the RFC 8785 form of everything else. */
async function sign(
  card: Record<string, unknown>,
  key: KeyObject,
  header: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const payload = canonicalJson(card);
  const jws = await new CompactSign(payload).setProtectedHeader(header as never).sign(key);
  const [protectedHeader, , signature] = jws.split('.');
  return { ...card, signatures: [{ protected: protectedHeader, signature }] };
}

const parsed = (card: unknown): AgentCard =>
  parseCard({
    status: 200,
    body: new TextEncoder().encode(JSON.stringify(card)),
    url: ORIGIN,
  } as HttpResponse);

describe('RFC 8785 canonical JSON', () => {
  it('sorts members by UTF-16 code units, with no space, as the RFC example shows', () => {
    const sample = {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      דּ: 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\u{1f600}': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      ö: 'Latin Small Letter O With Diaeresis',
    };
    const text = new TextDecoder().decode(canonicalJson(sample));
    expect(text).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","\u{1f600}":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it('writes numbers, literals and nesting the way the RFC does', () => {
    const text = (v: unknown) => new TextDecoder().decode(canonicalJson(v));
    expect(
      text({ numbers: [333333333.3333333, 1e30, 4.5, 0.002, 1e-27], literals: [null, true, false] }),
    ).toBe('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}');
    expect(text({ b: { y: 1, x: [3, { b: 1, a: 2 }] }, a: 'é"\\\n' })).toBe(
      '{"a":"é\\"\\\\\\n","b":{"x":[3,{"a":2,"b":1}],"y":1}}',
    );
    expect(text({ a: undefined, b: 1 })).toBe('{"b":1}');
  });

  it('refuses what JSON cannot hold', () => {
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(RangeError);
    expect(() => canonicalJson({ n: Infinity })).toThrow(RangeError);
    expect(() => canonicalJson({ f: () => 1 })).toThrow(RangeError);
    expect(() => canonicalJson({ n: 1n })).toThrow(RangeError);
  });
});

describe('an agent card is verified or it is not trusted', () => {
  it("verifies an AuthFI agent's card by its certificate chain to a root you trust", async () => {
    const c = chain();
    const card = parsed(await sign(baseCard(), c.leafKey, { alg: 'EdDSA', kid: 'agent-1', x5c: c.x5c }));
    const verified = await verifyCard(card, { trustRoots: [c.root], now: NOW });
    expect(verified.verified).toBe(true);
    expect(verified.signer).toContain('agent-1');
    expect(card.verified).toBe(false);
  });

  it('verifies a card signed with a key you name by kid', async () => {
    const { publicKey, privateKey } = ed();
    const jwk = await exportJWK(await importJWK(publicKey.export({ format: 'jwk' }) as JWK, 'EdDSA'));
    const card = parsed(await sign(baseCard(), privateKey, { alg: 'EdDSA', kid: 'k1' }));
    expect((await verifyCard(card, { keys: { k1: jwk } })).signer).toBe('k1');
  });

  it('refuses a card with no signature, a changed card, and a signature that is not the key named', async () => {
    const { publicKey, privateKey } = ed();
    const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;
    const unsigned = parsed(baseCard());
    await expect(verifyCard(unsigned, { keys: { k1: jwk } })).rejects.toThrow(/carries no signature/);
    const signed = await sign(baseCard(), privateKey, { alg: 'EdDSA', kid: 'k1' });
    const changed = parsed({ ...signed, name: 'Research agent, now with more access' });
    await expect(verifyCard(changed, { keys: { k1: jwk } })).rejects.toThrow(/does not match the card/);
    const other = ed().publicKey.export({ format: 'jwk' }) as JsonWebKey;
    await expect(verifyCard(parsed(signed), { keys: { k1: other } })).rejects.toThrow(
      /does not match the card/,
    );
    await expect(verifyCard(parsed(signed), { keys: {} })).rejects.toThrow(/no key given for kid "k1"/);
    await expect(verifyCard(parsed(signed))).rejects.toBeInstanceOf(CardUnverified);
  });

  it('refuses an unsupported algorithm, no kid, and a protected header that is not JSON', async () => {
    const { privateKey, publicKey } = ed();
    const keys = { k1: publicKey.export({ format: 'jwk' }) as JsonWebKey };
    const good = await sign(baseCard(), privateKey, { alg: 'EdDSA', kid: 'k1' });
    const entry = (good.signatures as { protected: string; signature: string }[])[0]!;
    const withHeader = (h: unknown) =>
      parsed({
        ...baseCard(),
        signatures: [
          {
            ...entry,
            protected: base64url(new TextEncoder().encode(typeof h === 'string' ? h : JSON.stringify(h))),
          },
        ],
      });
    await expect(verifyCard(withHeader({ alg: 'HS256', kid: 'k1' }), { keys })).rejects.toThrow(
      /algorithm "HS256"/,
    );
    await expect(verifyCard(withHeader({ alg: 'none', kid: 'k1' }), { keys })).rejects.toThrow(
      /algorithm "none"/,
    );
    await expect(verifyCard(withHeader({ alg: 'EdDSA' }), { keys })).rejects.toThrow(/names no kid/);
    await expect(verifyCard(withHeader('not json'), { keys })).rejects.toThrow(/not JSON/);
    await expect(verifyCard(withHeader('[1]'), { keys })).rejects.toThrow(/not an object/);
    await expect(verifyCard(withHeader('null'), { keys })).rejects.toThrow(/not an object/);
    await expect(
      verifyCard(parsed({ ...baseCard(), signatures: [{ protected: 5 }] }), { keys }),
    ).rejects.toThrow(/lacks protected or signature/);
    await expect(verifyCard(parsed({ ...baseCard(), signatures: [] }), { keys })).rejects.toThrow(
      /carries no signature/,
    );
  });

  it('refuses a chain that does not lead to a root you trust, or has a bad link, an expired certificate', async () => {
    const c = chain();
    const signedCard = async (cc: ReturnType<typeof chain>) =>
      parsed(await sign(baseCard(), cc.leafKey, { alg: 'EdDSA', kid: 'a', x5c: cc.x5c }));
    await expect(verifyCard(await signedCard(c), { trustRoots: [c.other], now: NOW })).rejects.toThrow(
      /does not lead to a root you trust/,
    );
    await expect(verifyCard(await signedCard(c), { trustRoots: [], now: NOW })).rejects.toThrow(
      /a chain and a trusted root are both needed/,
    );
    const broken = chain({ breakLink: true });
    await expect(
      verifyCard(await signedCard(broken), { trustRoots: [broken.root], now: NOW }),
    ).rejects.toThrow(/links do not each lead/);
    const old = chain({ expired: true });
    await expect(verifyCard(await signedCard(old), { trustRoots: [old.root], now: NOW })).rejects.toThrow(
      /not valid now/,
    );
    await expect(verifyCard(await signedCard(c), { trustRoots: ['not a pem'], now: NOW })).rejects.toThrow(
      /cannot be read/,
    );
    await expect(
      verifyCard(parsed(await sign(baseCard(), c.leafKey, { alg: 'EdDSA', kid: 'a', x5c: ['@@@@'] })), {
        trustRoots: [c.root],
        now: NOW,
      }),
    ).rejects.toThrow(/cannot be read/);
  });

  it('refuses a signing certificate without the agent-custody policy, or that is itself a CA', async () => {
    const plain = chain({ leafPolicy: PEN_POLICY });
    await expect(
      verifyCard(parsed(await sign(baseCard(), plain.leafKey, { alg: 'EdDSA', kid: 'a', x5c: plain.x5c })), {
        trustRoots: [plain.root],
        now: NOW,
      }),
    ).rejects.toThrow(/agent-custody policy 1\.3\.6\.1\.4\.1\.67322\.1\.4/);
    const ca = chain({ leafCA: true });
    await expect(
      verifyCard(parsed(await sign(baseCard(), ca.leafKey, { alg: 'EdDSA', kid: 'a', x5c: ca.x5c })), {
        trustRoots: [ca.root],
        now: NOW,
      }),
    ).rejects.toThrow(/is a certificate authority/);
  });

  it('accepts a second signature when the first does not verify', async () => {
    const good = ed();
    const bad = ed();
    const keys = { good: good.publicKey.export({ format: 'jwk' }) as JsonWebKey };
    const first = await sign(baseCard(), bad.privateKey, { alg: 'EdDSA', kid: 'good' });
    const second = await sign(baseCard(), good.privateKey, { alg: 'EdDSA', kid: 'good' });
    const card = parsed({
      ...baseCard(),
      signatures: [...(first.signatures as unknown[]), ...(second.signatures as unknown[])],
    });
    expect((await verifyCard(card, { keys })).verified).toBe(true);
  });
});

describe('parsing a card', () => {
  it('refuses a card that is not a card', () => {
    const res = (status: number, body: unknown) =>
      ({
        status,
        body: new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body)),
        url: ORIGIN,
        headers: new Headers(),
      }) as HttpResponse;
    expect(() => parseCard(res(404, {}))).toThrow(/answered HTTP 404/);
    expect(() => parseCard(res(200, '[1]'))).toThrow(/not a JSON object/);
    expect(() => parseCard(res(200, 'nope'))).toThrow(/not a JSON object/);
    expect(() => parseCard(res(200, { name: 'x' }))).toThrow(/no name or supportedInterfaces/);
    expect(() => parseCard(res(200, { name: 'x', supportedInterfaces: [] }))).toThrow(/no name/);
  });
});

/** The remote agent: its card, and the A2A door that checks the credential it was given. */
async function partner(options: { signed?: 'chain' | 'none'; points?: string; schemes?: unknown } = {}) {
  const c = chain();
  const clock = new TestClock();
  clock.wall = NOW;
  const platformFor = await FakePlatform.create(clock);
  const seen: { authorization: string | null; dpop: string | null; body: unknown; url: string }[] = [];
  const state = {
    reply: 'TASK_STATE_COMPLETED',
    nonce: undefined as string | undefined,
    status: 200,
    binding: 'HTTP+JSON',
  };
  const card = {
    ...baseCard(),
    supportedInterfaces: [
      { url: `${options.points ?? ORIGIN}/a2a`, protocolBinding: state.binding, protocolVersion: '1.0' },
    ],
    ...(options.schemes === undefined ? {} : { securitySchemes: options.schemes }),
  };
  const served =
    options.signed === 'none'
      ? card
      : await sign(card, c.leafKey, { alg: 'EdDSA', kid: 'agent-1', x5c: c.x5c });
  platformFor.t.fake.on('GET', `${ORIGIN}/.well-known/agent-card.json`, () => json(served));
  platformFor.t.fake.on(
    'POST',
    (u) => u.startsWith(`${ORIGIN}/a2a`),
    async (r) => {
      seen.push({
        authorization: r.headers.get('authorization'),
        dpop: r.headers.get('dpop'),
        body: JSON.parse(r.body),
        url: r.url,
      });
      if (state.nonce !== undefined) {
        const proof = r.headers.get('dpop');
        const claims =
          proof === null
            ? {}
            : (JSON.parse(Buffer.from(proof.split('.')[1]!, 'base64url').toString()) as { nonce?: string });
        if (claims.nonce !== state.nonce)
          return json({ error: 'use_dpop_nonce' }, 401, {
            'dpop-nonce': state.nonce,
            'www-authenticate': 'DPoP error="use_dpop_nonce"',
          });
      }
      if (state.status !== 200)
        return json({ error: 'nope' }, state.status, { 'www-authenticate': 'Bearer realm="a2a"' });
      return json({
        task: {
          id: 'task-1',
          contextId: 'ctx-1',
          status: {
            state: state.reply,
            message: { role: 'ROLE_AGENT', parts: [{ text: 'Q3 had two incidents.' }] },
          },
        },
      });
    },
  );
  return { c, clock, p: platformFor, seen, state };
}

describe("calling a remote agent with the agent's token", () => {
  async function connectTo(remoteOptions: Parameters<typeof partner>[0] = {}) {
    const s = await partner(remoteOptions);
    const af = new AuthFI({ issuer: s.p.issuer, fetch: s.p.fetch, clock: s.clock, retries: 0 });
    const agent = af.agent({ agentId: AGENT, key: s.p.agentKey });
    return { ...s, af, agent };
  }

  it('fetches and verifies the card, sends one message, and reads the task and the words', async () => {
    const s = await connectTo();
    const remoteAgent = await remote(s.agent, ORIGIN, { trustRoots: [s.c.root] });
    expect(remoteAgent.card.verified).toBe(true);
    const status = await remoteAgent.send('Summarise the Q3 incidents', { contextId: 'ctx-1' });
    expect(status).toMatchObject({
      state: 'TASK_STATE_COMPLETED',
      text: 'Q3 had two incidents.',
      taskId: 'task-1',
      needsInput: false,
    });
    const sent = s.seen[0]!;
    expect(sent.url).toBe(`${ORIGIN}/a2a/message:send`);
    expect(sent.body).toMatchObject({
      message: { role: 'ROLE_USER', parts: [{ text: 'Summarise the Q3 incidents' }], contextId: 'ctx-1' },
    });
    expect(String(remoteAgent)).toBe('RemoteAgent("Research agent", verified=true)');
  });

  it('sends a customer-resource token as Bearer for an agent key, and DPoP for an instance', async () => {
    const s = await connectTo();
    await (await remote(s.agent, ORIGIN, { trustRoots: [s.c.root] })).send('hello');
    expect(s.seen[0]!.authorization).toMatch(/^Bearer eyJ/);
    expect(s.seen[0]!.dpop).toBeNull();

    const dir = await mkdtemp(join(tmpdir(), 'authfi-a2a-'));
    try {
      const file = join(dir, 'sa');
      await writeFile(file, unsignedJwt({ alg: 'RS256' }, { aud: s.p.origin, jti: 'a2a-sa-1' }));
      const instance = await instanceFromEnv(s.af, {
        AUTHFI_AGENT_ID: AGENT,
        AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE: file,
        AUTHFI_CONFIG_VERSION: String(CONFIG.version),
        AUTHFI_CONFIG_DIGEST: CONFIG.digest,
      });
      expect(instance).toBeInstanceOf(InstanceAuth);
      s.seen.length = 0;
      await (await remote(instance, ORIGIN, { trustRoots: [s.c.root] })).send('hello');
      expect(s.seen[0]!.authorization).toMatch(/^DPoP eyJ/);
      expect(s.seen[0]!.dpop).toMatch(/^eyJ/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("answers the remote's nonce once", async () => {
    const s = await connectTo();
    const dir = await mkdtemp(join(tmpdir(), 'authfi-a2a-'));
    try {
      const file = join(dir, 'sa');
      await writeFile(file, unsignedJwt({ alg: 'RS256' }, { aud: s.p.origin, jti: 'a2a-sa-2' }));
      const instance = await instanceFromEnv(s.af, {
        AUTHFI_AGENT_ID: AGENT,
        AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE: file,
        AUTHFI_CONFIG_VERSION: String(CONFIG.version),
        AUTHFI_CONFIG_DIGEST: CONFIG.digest,
      });
      s.state.nonce = 'remote-nonce';
      const status = await (await remote(instance, ORIGIN, { trustRoots: [s.c.root] })).send('hello');
      expect(status.state).toBe('TASK_STATE_COMPLETED');
      expect(s.seen).toHaveLength(2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reads the states a remote answers: input required, auth required, rejected', async () => {
    const s = await connectTo();
    const remoteAgent = await remote(s.agent, ORIGIN, { trustRoots: [s.c.root] });
    s.state.reply = INPUT_REQUIRED;
    expect((await remoteAgent.send('x')).needsInput).toBe(true);
    s.state.reply = AUTH_REQUIRED;
    expect((await remoteAgent.send('x')).needsAuth).toBe(true);
    s.state.reply = REJECTED;
    expect((await remoteAgent.send('x')).rejected).toBe(true);
    s.state.reply = 'TASK_STATE_MADE_UP';
    await expect(remoteAgent.send('x')).rejects.toThrow(/unknown task state/);
  });

  it('refuses a remote that refuses the credential, errors, or answers nonsense', async () => {
    const s = await connectTo();
    const remoteAgent = await remote(s.agent, ORIGIN, { trustRoots: [s.c.root] });
    s.state.status = 401;
    await expect(remoteAgent.send('x')).rejects.toMatchObject({ code: 'remote_refused' });
    s.state.status = 500;
    await expect(remoteAgent.send('x')).rejects.toMatchObject({ code: 'remote_error' });
  });

  it('refuses a card it cannot verify, and takes an unsigned one only when told to say so', async () => {
    const s = await connectTo({ signed: 'none' });
    await expect(remote(s.agent, ORIGIN, { trustRoots: [s.c.root] })).rejects.toThrow(/carries no signature/);
    const unsigned = await remote(s.agent, ORIGIN, { allowUnsigned: true });
    expect(unsigned.card.verified).toBe(false);
    const signed = await connectTo();
    await expect(remote(signed.agent, ORIGIN, { trustRoots: [chain().other] })).rejects.toBeInstanceOf(
      CardUnverified,
    );
    // allowUnsigned does not excuse a card that has a bad signature
    await expect(
      remote(signed.agent, ORIGIN, { allowUnsigned: true, trustRoots: [chain().other] }),
    ).rejects.toBeInstanceOf(CardUnverified);
  });

  it('does not send the token where the card points beyond its own origin, unless told it may', async () => {
    const s = await connectTo({ points: 'https://elsewhere.example' });
    await expect(remote(s.agent, ORIGIN, { trustRoots: [s.c.root] })).rejects.toMatchObject({
      code: 'interface_origin',
    });
    expect(s.seen).toHaveLength(0);
    const allowed = await remote(s.agent, ORIGIN, {
      trustRoots: [s.c.root],
      allowOrigins: ['https://elsewhere.example'],
    });
    expect(allowed.interface.url).toBe('https://elsewhere.example/a2a');
  });

  it('refuses a card whose security scheme is not one it speaks, or whose interface it cannot call', async () => {
    const s = await connectTo({ schemes: { key: { apiKeySecurityScheme: {} } } });
    await expect(remote(s.agent, ORIGIN, { trustRoots: [s.c.root] })).rejects.toMatchObject({
      code: 'no_scheme',
    });
    const none = await connectTo({ schemes: {} });
    await expect(remote(none.agent, ORIGIN, { trustRoots: [none.c.root] })).rejects.toThrow(
      /no declared authentication/,
    );
    await expect(remote(s.agent, 'not a url')).rejects.toThrow(/is not a URL/);
  });

  it('refuses a card at an address that answers nothing', async () => {
    const s = await connectTo();
    await expect(remote(s.agent, 'https://nowhere.example')).rejects.toBeInstanceOf(A2AError);
    expect(call).toBeDefined();
    expect((await platform()).agent).toBeDefined();
  });
});

describe('AuthFI decisions as A2A task states', () => {
  it('maps approval to INPUT_REQUIRED, consent or credentials to AUTH_REQUIRED, deny to REJECTED with the reason', () => {
    expect(statusFor('allow').state).toBe(WORKING);
    expect(statusFor('needs_approval')).toMatchObject({ state: INPUT_REQUIRED, needsInput: true });
    expect(statusFor('needs_approval', 'Refund 4411').text).toBe('Refund 4411');
    for (const d of ['needs_consent', 'needs_credentials', 'auth_required']) {
      expect(statusFor(d)).toMatchObject({ state: AUTH_REQUIRED, needsAuth: true });
    }
    expect(statusFor('deny', 'Over the limit')).toMatchObject({
      state: REJECTED,
      text: 'Over the limit',
      rejected: true,
    });
    expect(statusFor('deny', undefined, 'connection_required').state).toBe(AUTH_REQUIRED);
    expect(statusFor('deny', undefined, 'EMDT005').state).toBe(REJECTED);
    expect(statusFor('deny').text).toBe('Denied by policy.');
  });

  it('never reads an answer it does not know as a yes', () => {
    expect(statusFor('maybe').state).toBe(FAILED);
    expect(statusFor('').state).toBe(FAILED);
    expect(statusFor('ALLOW').state).toBe(FAILED);
  });

  it('maps what the gateway did with a tool call', () => {
    expect(statusForOutcome({ kind: 'allowed', result: {} }).state).toBe(WORKING);
    expect(statusForOutcome({ kind: 'approval_required', approvalId: 'a', code: 'c' }).state).toBe(
      INPUT_REQUIRED,
    );
    const refused = (code: string | undefined, reason = 'no') =>
      statusForOutcome({
        kind: 'refused',
        result: {},
        reason,
        code,
        error: undefined,
        requiredScope: undefined,
        why: 'refused',
        nextStep: undefined,
        modelText: '',
      });
    expect(refused('EMDT005', 'outside')).toMatchObject({ state: REJECTED, text: 'outside' });
    expect(refused('connection_required').state).toBe(AUTH_REQUIRED);
  });

  it('writes the status object a response carries', () => {
    expect(toStatusObject(statusFor('allow'))).toEqual({ state: WORKING });
    const out = toStatusObject(statusFor('deny', 'No')) as {
      state: string;
      message: { role: string; parts: unknown[] };
    };
    expect(out.state).toBe(REJECTED);
    expect(out.message).toMatchObject({ role: 'ROLE_AGENT', parts: [{ text: 'No' }] });
  });
});
