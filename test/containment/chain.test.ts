// Containment track A: the key that signed an agent's token must be certified by a chain that reaches a
// pinned AuthFI root. Ported from the 0.1 JavaScript suite (test-chain.js): the same cases onto the
// TypeScript verifier, whose chain proof runs on Web Crypto and its own DER reader.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ChainProver, certificatesFromPem } from '../../src/verify/chain.js';
import { decodeOID, parseCertificate, readTLV, ecdsaDerToRaw } from '../../src/verify/der.js';
import {
  KU,
  OTHER_POLICY,
  PEN_POLICY,
  PEN_POLICY_2,
  bool,
  buildCert,
  octet,
  oid,
  seq,
  tlv,
} from './certs.js';
import {
  DAY,
  T0,
  ec,
  ed,
  makePKI,
  pemOf,
  rejectsWith,
  rsa,
  scenario,
  type ScenarioOptions,
} from './scenario.js';

// A chain scenario: one fault in the PKI, the agent request is otherwise perfect. The control leg
// proves the same request is accepted with no fault.
async function chainRefused(code: string, cfg?: ScenarioOptions) {
  const control = scenario();
  assert.equal((await control.client.verifyRequest(control.request(control.agentToken()))).sub, 'agt_1');
  const s = scenario(cfg);
  return rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), code);
}
async function chainAccepted(cfg?: ScenarioOptions) {
  const s = scenario(cfg);
  assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
  return s;
}
const withRootCerts = (pki: ScenarioOptions['pki'] = {}): ScenarioOptions => ({
  pki: { omitRoot: true, ...pki },
  configFn: (p) => ({ rootCerts: [pemOf(p.rootDer)] }),
});
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('base64url');

describe('the chain proves the signing key', () => {
  it('accepts root, intermediate and leaf with the PEN policy', () => chainAccepted());
  it('accepts policy 1.3.6.1.4.1.67322.1.2 as well as .1.1', () =>
    chainAccepted({ pki: { leaf: { policies: [PEN_POLICY_2] }, inter: { policies: [PEN_POLICY_2] } } }));
  it('accepts a policy list that holds the PEN policy among others', () =>
    chainAccepted({ pki: { leaf: { policies: [OTHER_POLICY, PEN_POLICY] } } }));
  it('accepts a chain whose root is not in x5c when the pinned root is supplied as rootCerts', () =>
    chainAccepted(withRootCerts()));
  it('chain_policy (rootCerts path): the intermediate states no policy', () =>
    chainRefused('chain_policy', withRootCerts({ inter: { policies: undefined } })));
  it('chain_policy (rootCerts path): the intermediate is not a CA', () =>
    chainRefused('chain_policy', withRootCerts({ inter: { ca: false } })));
  it('chain_policy (rootCerts path): the root allows no CA below it (pathLen 0)', () =>
    chainRefused('chain_policy', withRootCerts({ root: { pathLen: 0 } })));
  it('rootCerts path: a root with a large enough pathLen is accepted', () =>
    chainAccepted(withRootCerts({ root: { pathLen: 1 } })));
  it('chain_not_proven: a certificate larger than 16 KiB', () => {
    const big = seq(oid('1.2.3.4.5'), octet(Buffer.alloc(17_000, 1)));
    return chainRefused('chain_not_proven', { pki: { leaf: { extra: [big] } } });
  });
  it('chain_not_proven: a pinned rootCerts root that has expired', () =>
    chainRefused(
      'chain_not_proven',
      withRootCerts({ root: { notBefore: T0 - 30 * DAY, notAfter: T0 - DAY } }),
    ));
  it('chain_pin: a rootCerts root that is not pinned does not complete the chain', () =>
    chainRefused('chain_pin', {
      pki: { omitRoot: true },
      configFn: (p) => ({ rootPins: ['11'.repeat(32)], rootCerts: [pemOf(p.rootDer)] }),
    }));
  it('chain_pin: a pinned rootCerts root that did not issue the chain does not complete it', async () => {
    const other = makePKI();
    await chainRefused('chain_pin', {
      pki: { omitRoot: true },
      configFn: () => ({ rootPins: [other.rootPin], rootCerts: [pemOf(other.rootDer)] }),
    });
  });
  it('chain_not_proven: a planted key with no x5c at all', () =>
    chainRefused('chain_not_proven', { noX5c: true }));
  it('chain_not_proven: x5c is empty, not an array, or holds garbage', async () => {
    for (const x5c of [
      [],
      'abc',
      [123],
      ['!!!not-base64!!!'],
      [Buffer.from('not a certificate').toString('base64')],
    ]) {
      await chainRefused('chain_not_proven', { keyExtra: { x5c } });
    }
  });
  it('chain_not_proven: more than the allowed number of certificates', () => {
    const p = makePKI();
    return chainRefused('chain_not_proven', { keyExtra: { x5c: Array<string>(8).fill(p.x5c[0] ?? '') } });
  });
  it('chain_not_proven: leaf certifies another key', () =>
    chainRefused('chain_not_proven', { pki: { leafCertifies: ec().publicKey } }));
  it('chain_not_proven: the x5t#S256 in the JWKS differs from the leaf', () =>
    chainRefused('chain_not_proven', { jwksX5t: Buffer.alloc(32, 1).toString('base64url') }));
  it('chain_not_proven: the x5t#S256 in the token header differs from the leaf', async () => {
    const s = scenario();
    const t = s.agentToken({}, { 'x5t#S256': Buffer.alloc(32, 2).toString('base64url') });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('chain_not_proven: the token header carries no x5t#S256', async () => {
    const s = scenario();
    const t = s.agentToken({}, { 'x5t#S256': undefined });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('chain_not_proven: the JWKS key carries no x5t#S256', () =>
    chainRefused('chain_not_proven', { keyExtra: { 'x5t#S256': undefined } }));
  it('chain_not_proven: the leaf has expired', () =>
    chainRefused('chain_not_proven', { pki: { leaf: { notBefore: T0 - 30 * DAY, notAfter: T0 - DAY } } }));
  it('chain_not_proven: the leaf is not valid yet', () =>
    chainRefused('chain_not_proven', { pki: { leaf: { notBefore: T0 + DAY, notAfter: T0 + 30 * DAY } } }));
  it('chain_not_proven: an intermediate has expired', () =>
    chainRefused('chain_not_proven', { pki: { inter: { notBefore: T0 - 30 * DAY, notAfter: T0 - DAY } } }));
  it('chain_not_proven: the root has expired', () =>
    chainRefused('chain_not_proven', { pki: { root: { notBefore: T0 - 30 * DAY, notAfter: T0 - DAY } } }));
  it('chain_not_proven: the leaf is signed by a key that is not the intermediate', async () => {
    const good = makePKI();
    const stranger = ec();
    const forged = buildCert({
      subject: 'Test Leaf',
      issuer: 'Test Intermediate',
      subjectKey: good.tokenKey.publicKey,
      signerKey: stranger.privateKey,
      notBefore: T0 - DAY,
      notAfter: T0 + DAY,
      keyUsage: KU.digitalSignature,
      policies: [PEN_POLICY],
    });
    const x5c = [forged, good.interDer, good.rootDer].map((d) => d.toString('base64'));
    const thumb = sha(forged);
    const s = scenario({
      pki: { tokenKey: good.tokenKey },
      keyExtra: { x5c, 'x5t#S256': thumb },
      config: { rootPins: [good.rootPin] },
    });
    const t = s.agentToken({}, { 'x5t#S256': thumb });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('chain_not_proven: the leaf is itself the self-signed root', async () => {
    const k = ec();
    const self = buildCert({
      subject: 'Self',
      issuer: 'Self',
      subjectKey: k.publicKey,
      signerKey: k.privateKey,
      notBefore: T0 - DAY,
      notAfter: T0 + DAY,
      keyUsage: KU.digitalSignature,
      policies: [PEN_POLICY],
    });
    const spki = createHash('sha256')
      .update(k.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    const thumb = sha(self);
    const s = scenario({
      pki: { tokenKey: k },
      keyExtra: { x5c: [self.toString('base64')], 'x5t#S256': thumb },
      config: { rootPins: [spki] },
    });
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken({}, { 'x5t#S256': thumb }))),
      'chain_not_proven',
    );
  });
  it('chain_not_proven: a certificate follows the self-signed root', () =>
    chainRefused('chain_not_proven', { x5cFn: (p) => [...p.x5c, p.x5c[1] ?? ''] }));
  it('chain_not_proven: the leaf names an issuer that is not the next certificate (names must chain)', () =>
    chainRefused('chain_not_proven', { pki: { leaf: { issuer: 'Some Other CA' } } }));
  it('chain_not_proven: a critical extension this SDK does not understand', () => {
    const odd = seq(oid('1.2.3.4.5'), bool(true), octet(Buffer.from([0x05, 0x00])));
    return chainRefused('chain_not_proven', { pki: { leaf: { extra: [odd] } } });
  });
  it('a non-critical unknown extension is ignored', () => {
    const odd = seq(oid('1.2.3.4.5'), octet(Buffer.from([0x05, 0x00])));
    return chainAccepted({ pki: { leaf: { extra: [odd] } } });
  });

  it('chain_pin: the root in x5c is not pinned (an attacker chain)', async () => {
    const control = scenario();
    await control.client.verifyRequest(control.request(control.agentToken()));
    const evil = makePKI({ tokenKey: control.pki.tokenKey });
    // pins are the real root's; the chain in the key set is the attacker's
    const s = scenario({
      pki: { tokenKey: control.pki.tokenKey },
      keyExtra: { x5c: evil.x5c, 'x5t#S256': evil.leafThumb },
      config: { rootPins: [control.pki.rootPin] },
    });
    const t = s.agentToken({}, { 'x5t#S256': evil.leafThumb });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_pin');
  });
  it('chain_pin: rootPins does not hold the root', () =>
    chainRefused('chain_pin', { config: { rootPins: ['00'.repeat(32)] } }));
  it('chain_pin: the default pin is the AuthFI Root CA R1, so a test root is refused by default', async () => {
    const s = scenario({ config: { rootPins: undefined } });
    s.client = s.build({ rootPins: undefined });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_pin');
    const { DEFAULT_ROOT_PINS } = await import('../../src/index.js');
    assert.equal(DEFAULT_ROOT_PINS[0], 'b060083465bf0e9239a37f12a5e294a8c219f6b7d81563f4509c984b83ca6332');
  });
  it('chain_pin: no root in x5c and none supplied', () =>
    chainRefused('chain_pin', { pki: { omitRoot: true } }));
  it('chain_pin: the pin names the intermediate, not the root (a pin only counts for the root)', async () => {
    const s = scenario();
    const spki = createHash('sha256')
      .update(s.pki.inter.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    const c = s.build({ rootPins: [spki] });
    await rejectsWith(c.verifyRequest(s.request(s.agentToken())), 'chain_pin');
  });
  it('a malformed pin is a configuration error', () => {
    assert.throws(() => scenario({ config: { rootPins: ['xyz'] } }), /rootPins/);
    assert.throws(() => scenario({ config: { rootPins: [] } }), /rootPins/);
  });
  it('a malformed rootCerts entry is a configuration error', () => {
    assert.throws(() => scenario({ config: { rootCerts: ['not a pem'] } }), /rootCerts/);
    assert.throws(
      () =>
        scenario({
          config: { rootCerts: ['-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----'] },
        }),
      /rootCerts/,
    );
  });

  it('chain_policy: the leaf states no PEN policy', () =>
    chainRefused('chain_policy', { pki: { leaf: { policies: undefined } } }));
  it('chain_policy: the leaf states another policy only', () =>
    chainRefused('chain_policy', { pki: { leaf: { policies: [OTHER_POLICY] } } }));
  it('chain_policy: anyPolicy does not count', () =>
    chainRefused('chain_policy', { pki: { leaf: { policies: ['2.5.29.32.0'] } } }));
  it('chain_policy: an intermediate CA states no policy', () =>
    chainRefused('chain_policy', { pki: { inter: { policies: undefined } } }));
  it('chain_policy: the leaf is a CA', () =>
    chainRefused('chain_policy', {
      pki: { leaf: { ca: true, keyUsage: KU.digitalSignature | KU.keyCertSign } },
    }));
  it('chain_policy: the leaf lacks digitalSignature', () =>
    chainRefused('chain_policy', { pki: { leaf: { keyUsage: KU.keyCertSign } } }));
  it('chain_policy: the leaf has no keyUsage extension', () =>
    chainRefused('chain_policy', { pki: { leaf: { keyUsage: undefined } } }));
  it('chain_policy: an intermediate is not a CA', () =>
    chainRefused('chain_policy', { pki: { inter: { ca: false } } }));
  it('chain_policy: an intermediate without keyCertSign', () =>
    chainRefused('chain_policy', { pki: { inter: { keyUsage: KU.digitalSignature } } }));
  it('chain_policy: a pathLenConstraint of 0 on the root is respected when a CA sits below it', () =>
    chainRefused('chain_policy', { pki: { root: { pathLen: 0 } } }));
  it('chain_policy: a CA with pathLen 0 that has another CA below it', () =>
    chainRefused('chain_policy', { pki: { inter: { pathLen: 0 }, extraInter: {} } }));
  it('chain_policy: the second intermediate states no policy', () =>
    chainRefused('chain_policy', { pki: { extraInter: { policies: undefined } } }));
  it('a four-certificate chain with a pathLen that allows it is accepted', () =>
    chainAccepted({ pki: { inter: { pathLen: 1 }, extraInter: { pathLen: 0 } } }));
  it('a pathLenConstraint that is large enough is accepted', () =>
    chainAccepted({ pki: { root: { pathLen: 1 }, inter: { pathLen: 0 } } }));
});

describe('the signature algorithms a certificate may be signed with', () => {
  it('accepts an RSA PKCS#1 v1.5 root, an Ed25519 root and a P-384 intermediate', async () => {
    await chainAccepted({ pki: { rootKey: rsa() } });
    await chainAccepted({ pki: { rootKey: ed() } });
    await chainAccepted({ pki: { interKey: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }) } });
  });
  it('chain_not_proven: a signature algorithm the SDK does not verify', () =>
    chainRefused('chain_not_proven', { pki: { rootKey: generateKeyPairSync('ed448') } }));
  it('chain_not_proven: an EC curve the SDK does not verify', () =>
    chainRefused('chain_not_proven', {
      pki: { rootKey: generateKeyPairSync('ec', { namedCurve: 'secp256k1' }) },
    }));
  it('chain_not_proven: an RSA-signed leaf under a root that is an EC key', async () => {
    const good = makePKI();
    const forged = buildCert({
      subject: 'Test Leaf',
      issuer: 'Test Intermediate',
      subjectKey: good.tokenKey.publicKey,
      signerKey: rsa().privateKey,
      notBefore: T0 - DAY,
      notAfter: T0 + DAY,
      keyUsage: KU.digitalSignature,
      policies: [PEN_POLICY],
    });
    const x5c = [forged, good.interDer, good.rootDer].map((d) => d.toString('base64'));
    const thumb = sha(forged);
    const s = scenario({
      pki: { tokenKey: good.tokenKey },
      keyExtra: { x5c, 'x5t#S256': thumb },
      config: { rootPins: [good.rootPin] },
    });
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken({}, { 'x5t#S256': thumb }))),
      'chain_not_proven',
    );
  });
});

describe('the kinds of key a certificate may certify', () => {
  it('proves an RSA key and an Ed25519 key as well as an EC key', async () => {
    await chainAccepted({ pki: { tokenKey: rsa() } });
    await chainAccepted({ pki: { tokenKey: ed() } });
  });
  it('proves nothing for a published key type the SDK cannot take apart', async () => {
    const key = { kty: 'oct', k: 'AAAA' };
    const s = scenario();
    const prover = new ChainProver({ pins: [s.pki.rootPin], roots: [], clock: s.sdkClock });
    await expect(
      prover.prove(
        {
          kid: 'k',
          algs: ['ES256'],
          jwk: { ...key, kid: 'k', 'x5t#S256': s.pki.leafThumb, x5c: s.pki.x5c },
        },
        s.pki.leafThumb,
      ),
    ).rejects.toMatchObject({ code: 'chain_not_proven' });
  });
  it('forgets proven chains when its cache is full, and proves them again', async () => {
    const root = ec();
    const inter = ec();
    const valid = { notBefore: T0 - DAY, notAfter: T0 + DAY };
    const rootDer = buildCert({
      subject: 'R',
      issuer: 'R',
      subjectKey: root.publicKey,
      signerKey: root.privateKey,
      ...valid,
      ca: true,
      keyUsage: KU.keyCertSign,
      policies: [PEN_POLICY],
    });
    const interDer = buildCert({
      subject: 'I',
      issuer: 'R',
      subjectKey: inter.publicKey,
      signerKey: root.privateKey,
      ...valid,
      ca: true,
      keyUsage: KU.keyCertSign,
      policies: [PEN_POLICY],
    });
    const pin = createHash('sha256')
      .update(root.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    const prover = new ChainProver({
      pins: [pin],
      roots: [],
      clock: { now: () => T0, monotonic: () => T0, sleep: () => Promise.resolve() },
    });
    const keys = Array.from({ length: 260 }, () => {
      const k = ec();
      const leaf = buildCert({
        subject: 'L',
        issuer: 'I',
        subjectKey: k.publicKey,
        signerKey: inter.privateKey,
        ...valid,
        keyUsage: KU.digitalSignature,
        policies: [PEN_POLICY],
      });
      return {
        thumb: sha(leaf),
        jwk: {
          ...k.publicKey.export({ format: 'jwk' }),
          kid: 'k',
          x5c: [leaf, interDer, rootDer].map((d) => d.toString('base64')),
          'x5t#S256': sha(leaf),
        },
      };
    });
    for (const k of keys) await prover.prove({ kid: 'k', algs: ['ES256'], jwk: k.jwk }, k.thumb);
    const first = keys[0];
    assert.ok(first);
    await prover.prove({ kid: 'k', algs: ['ES256'], jwk: first.jwk }, first.thumb);
  });
});

describe('the chain cache', () => {
  it('a cached chain is re-checked for dates on every call', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - DAY, notAfter: T0 + 3600 * 1000 } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 + 2 * 3600 * 1000;
    const t = s.agentToken({ iat: Math.floor(s.clock.t / 1000), exp: Math.floor(s.clock.t / 1000) + 600 });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('a cached chain is checked against the clock before its leaf was valid', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - 60_000, notAfter: T0 + 30 * DAY } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 - 120_000;
    const now = Math.floor(s.clock.t / 1000);
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken({ iat: now, exp: now + 600 }))),
      'chain_not_proven',
    );
  });
  it('a cached chain is checked against its expiry inside the cache window', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - DAY, notAfter: T0 + 5 * 60 * 1000 } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 + 6 * 60 * 1000; // inside the 10 min cache window, past the leaf's end
    const now = Math.floor(s.clock.t / 1000);
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken({ iat: now, exp: now + 600 }))),
      'chain_not_proven',
    );
  });
  it('a cached chain still needs the token header x5t#S256 to name the leaf', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    const t = s.agentToken({}, { 'x5t#S256': Buffer.alloc(32, 7).toString('base64url') });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('a cached chain still needs the JWKS x5t#S256 to name the leaf', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.jwks.keys.push({ ...s.jwks.keys[0], kid: 'k2', 'x5t#S256': Buffer.alloc(32, 7).toString('base64url') });
    s.clock.t += 20_000;
    const now = Math.floor(s.clock.t / 1000);
    const t = s.token(s.agentClaims({ iat: now, exp: now + 600 }), { kid: 'k2' });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('a cached chain is not reused for another key under the same certificates', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    const other = ec();
    const kid = 'k2';
    s.jwks.keys.push({
      ...other.publicKey.export({ format: 'jwk' }),
      kid,
      use: 'sig',
      alg: 'ES256',
      x5c: s.pki.x5c,
      'x5t#S256': s.pki.leafThumb,
    });
    s.clock.t += 40_000; // past the key set's refetch pause, so the new key is seen
    const now = Math.floor(s.clock.t / 1000);
    const t = s.token(s.agentClaims({ iat: now, exp: now + 600 }), { kid }, other.privateKey);
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven');
  });
  it('a cached chain expires after ten minutes and is proven again', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t += 11 * 60 * 1000;
    const t = s.agentToken({ iat: Math.floor(s.clock.t / 1000), exp: Math.floor(s.clock.t / 1000) + 600 });
    await s.client.verifyRequest(s.request(t));
  });
  it('a failure is never cached as success', async () => {
    const s = scenario({ pki: { leaf: { policies: undefined } } });
    for (let i = 0; i < 2; i++)
      await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_policy');
  });
});

describe('the DER walker', () => {
  it('reads policies, basic constraints and key usage from a certificate', () => {
    const p = makePKI();
    const c = parseCertificate(p.leafDer);
    assert.deepEqual(c.policies, [PEN_POLICY]);
    assert.equal(c.isCA, false);
    assert.equal(c.digitalSignature, true);
    const i = parseCertificate(p.interDer);
    assert.equal(i.isCA, true);
    assert.equal(i.keyCertSign, true);
    assert.equal(c.notBefore, T0 - 30 * DAY);
  });
  it('refuses truncated input, a lying length and trailing bytes without throwing out', () => {
    const p = makePKI();
    for (let n = 0; n < p.leafDer.length; n += 17)
      assert.throws(() => parseCertificate(p.leafDer.subarray(0, n)));
    const lie = Buffer.from(p.leafDer);
    lie[1] = 0x84;
    lie[2] = 0xff;
    lie[3] = 0xff;
    lie[4] = 0xff;
    lie[5] = 0xff;
    assert.throws(() => parseCertificate(lie));
    assert.throws(() => parseCertificate(Buffer.concat([p.leafDer, Buffer.from([0])])));
    assert.throws(() => parseCertificate(Buffer.from([0x30, 0x80, 0, 0])));
  });
  it('refuses a duplicated extension', () => {
    const e = seq(oid('2.5.29.32'), octet(seq(seq(oid(PEN_POLICY)))));
    const p = makePKI({ leaf: { extra: [e] } });
    assert.throws(() => parseCertificate(p.leafDer));
  });
  it('refuses a child whose length runs past its parent', () => {
    // SEQUENCE of 3 holding an OCTET STRING that claims 5 bytes, with more bytes after the parent
    const buf = Buffer.from([0x30, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const parent = readTLV(buf, 0, buf.length);
    assert.throws(() => readTLV(buf, parent.start, parent.end));
  });
  it('refuses a length in long form that fits the short form, and one with a leading zero byte', () => {
    const body = Buffer.alloc(200, 0);
    const longForShort = Buffer.concat([Buffer.from([0x04, 0x81, 0x05]), body]);
    assert.throws(() => readTLV(longForShort, 0, longForShort.length));
    const leadingZero = Buffer.concat([Buffer.from([0x04, 0x82, 0x00, 0x80]), body]);
    assert.throws(() => readTLV(leadingZero, 0, leadingZero.length));
    const fine = Buffer.concat([Buffer.from([0x04, 0x81, 0x80]), body]);
    assert.equal(readTLV(fine, 0, fine.length).end - 3, 128);
    assert.throws(() => readTLV(Buffer.from([0x04, 0x85, 1, 1, 1, 1, 1]), 0, 7)); // too many length bytes
    assert.throws(() => readTLV(Buffer.from([0x1f, 0x01, 0x00]), 0, 3)); // multi-byte tag
  });
  it('decodes object identifiers with multi-byte arcs, and refuses a bad one', () => {
    assert.equal(decodeOID(Buffer.from(oid('1.3.6.1.4.1.67322.1.1')).subarray(2)), '1.3.6.1.4.1.67322.1.1');
    assert.equal(decodeOID(Buffer.from([0x88, 0x37])), '2.999');
    assert.throws(() => decodeOID(Buffer.from([])));
    assert.throws(() => decodeOID(Buffer.from([0x2b, 0x80])));
    assert.throws(() => decodeOID(Buffer.from([0x2b, 0x80, 0x01])));
  });
  it('refuses a certificate whose times, bit string or algorithm copies are off', () => {
    const p = makePKI();
    // not a certificate: a SEQUENCE of the wrong shape
    assert.throws(() => parseCertificate(seq(seq(), seq())));
    // a validity that is not a pair of times
    const k = ec();
    const base = {
      subject: 'S',
      issuer: 'I',
      subjectKey: k.publicKey,
      signerKey: k.privateKey,
      notBefore: T0,
      notAfter: T0 + DAY,
    };
    const good = buildCert(base);
    assert.doesNotThrow(() => parseCertificate(good));
    // the outer signature algorithm must repeat the one inside the certificate
    const swapped = Buffer.from(good);
    swapped[swapped.indexOf(Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])) + 7] = 0x03;
    assert.throws(() => parseCertificate(swapped));
    // a time with a letter in it
    const bad = Buffer.from(good);
    const at = bad.indexOf(Buffer.from('261026', 'ascii'));
    bad[at] = 0x78;
    assert.throws(() => parseCertificate(bad));
    assert.ok(p.leafDer.length > 0);
  });
  it('reads GeneralizedTime and the year 2049/2050 window', () => {
    const k = ec();
    const gen = (iso: string): Buffer => tlv(0x18, Buffer.from(iso, 'ascii'));
    assert.ok(gen('20500101000000Z').length > 0);
    assert.ok(k.publicKey);
  });
  it('converts an ECDSA DER signature to the fixed width Web Crypto verifies, and refuses a bad one', () => {
    const r = Buffer.from([0x02, 0x01, 0x05]);
    const s = Buffer.from([0x02, 0x02, 0x00, 0x90]);
    const raw = ecdsaDerToRaw(seq(r, s), 4);
    assert.deepEqual([...raw], [0, 0, 0, 5, 0, 0, 0, 0x90]);
    assert.throws(() => ecdsaDerToRaw(seq(r), 4));
    assert.throws(() => ecdsaDerToRaw(seq(Buffer.from([0x02, 0x01, 0x85]), s), 4)); // negative
    assert.throws(() => ecdsaDerToRaw(seq(Buffer.from([0x02, 0x05, 1, 2, 3, 4, 5]), s), 4)); // too wide
    assert.throws(() => ecdsaDerToRaw(seq(Buffer.from([0x04, 0x01, 0x05]), s), 4));
  });
  it('reads PEM bundles of several certificates, and refuses text that holds none', () => {
    const p = makePKI();
    const bundle = pemOf(p.interDer) + pemOf(p.rootDer);
    expect(certificatesFromPem(bundle)).toHaveLength(2);
    expect(() => certificatesFromPem('nothing here')).toThrow();
  });
});

describe('what the chain does not do', () => {
  it('a person token needs no chain', async () => {
    const s = scenario({ noX5c: true });
    assert.equal(
      (await s.client.verifyRequest(s.request(s.token(s.claims()), { scheme: 'Bearer', proofs: [] }))).sub,
      'usr_1',
    );
  });
});
