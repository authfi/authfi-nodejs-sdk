'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const authfi = require('./index');
const { scenario, makePKI, rejectsWith, ec, DAY, T0, ISSUER, AUD, PUBLIC } = require('./test-helpers/fixture');
const { KU, PEN_POLICY, PEN_POLICY_2, OTHER_POLICY, oid, seq, octet, bool, buildCert } = require('./test-helpers/certs');
const der = require('./lib/der');

// A chain scenario: one fault in the PKI, the agent request is otherwise perfect. The control leg
// proves the same request is accepted with no fault.
async function chainRefused(code, cfg) {
  const control = scenario();
  assert.equal((await control.client.verifyRequest(control.request(control.agentToken()))).sub, 'agt_1');
  const s = scenario(cfg);
  return rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), code, assert);
}
async function chainAccepted(cfg) {
  const s = scenario(cfg);
  assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
  return s;
}

describe('the chain proves the signing key', () => {
  it('accepts root, intermediate and leaf with the PEN policy', () => chainAccepted());
  it('accepts policy 1.3.6.1.4.1.67322.1.2 as well as .1.1', () =>
    chainAccepted({ pki: { leaf: { policies: [PEN_POLICY_2] }, inter: { policies: [PEN_POLICY_2] } } }));
  it('accepts a policy list that holds the PEN policy among others', () =>
    chainAccepted({ pki: { leaf: { policies: [OTHER_POLICY, PEN_POLICY] } } }));
  it('accepts a chain whose root is not in x5c when the pinned root is supplied as rootCerts', () =>
    chainAccepted({ pki: { omitRoot: true }, configFn: (p) => ({ rootCerts: [new crypto.X509Certificate(p.rootDer).toString()] }) }));
  const withRootCerts = (pki) => ({ pki: { omitRoot: true, ...pki }, configFn: (p) => ({ rootCerts: [new crypto.X509Certificate(p.rootDer).toString()] }) });
  it('chain_policy (rootCerts path): the intermediate states no policy', () => chainRefused('chain_policy', withRootCerts({ inter: { policies: undefined } })));
  it('chain_policy (rootCerts path): the intermediate is not a CA', () => chainRefused('chain_policy', withRootCerts({ inter: { ca: false } })));
  it('chain_policy (rootCerts path): the root allows no CA below it (pathLen 0)', () => chainRefused('chain_policy', withRootCerts({ root: { pathLen: 0 } })));
  it('rootCerts path: a root with a large enough pathLen is accepted', () => chainAccepted(withRootCerts({ root: { pathLen: 1 } })));
  it('chain_not_proven: a certificate larger than 16 KiB', () => {
    const big = seq(oid('1.2.3.4.5'), octet(Buffer.alloc(17000, 1)));
    return chainRefused('chain_not_proven', { pki: { leaf: { extra: [big] } } });
  });
  it('chain_not_proven: a pinned rootCerts root that has expired', () =>
    chainRefused('chain_not_proven', { pki: { omitRoot: true, root: { notBefore: T0 - 30 * DAY, notAfter: T0 - DAY } }, configFn: (p) => ({ rootCerts: [new crypto.X509Certificate(p.rootDer).toString()] }) }));
  it('chain_pin: a rootCerts root that is not pinned does not complete the chain', () =>
    chainRefused('chain_pin', { pki: { omitRoot: true }, configFn: (p) => ({ rootPins: ['11'.repeat(32)], rootCerts: [new crypto.X509Certificate(p.rootDer).toString()] }) }));
  it('chain_pin: a pinned rootCerts root that did not issue the chain does not complete it', async () => {
    const other = makePKI();
    await chainRefused('chain_pin', { pki: { omitRoot: true }, configFn: () => ({ rootPins: [other.rootPin], rootCerts: [new crypto.X509Certificate(other.rootDer).toString()] }) });
  });
  it('chain_not_proven: a planted key with no x5c at all', () => chainRefused('chain_not_proven', { noX5c: true }));
  it('chain_not_proven: x5c is empty, not an array, or holds garbage', async () => {
    for (const x5c of [[], 'abc', [123], ['!!!not-base64!!!'], [Buffer.from('not a certificate').toString('base64')]]) {
      await chainRefused('chain_not_proven', { keyExtra: { x5c } });
    }
  });
  it('chain_not_proven: more than the allowed number of certificates', () => {
    const p = makePKI();
    return chainRefused('chain_not_proven', { keyExtra: { x5c: Array(8).fill(p.x5c[0]) } });
  });
  it('chain_not_proven: leaf certifies another key', () =>
    chainRefused('chain_not_proven', { pki: { leafCertifies: ec().publicKey } }));
  it('chain_not_proven: the x5t#S256 in the JWKS differs from the leaf', () =>
    chainRefused('chain_not_proven', { jwksX5t: Buffer.alloc(32, 1).toString('base64url') }));
  it('chain_not_proven: the x5t#S256 in the token header differs from the leaf', async () => {
    const s = scenario();
    const t = s.agentToken({}, { 'x5t#S256': Buffer.alloc(32, 2).toString('base64url') });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
  });
  it('chain_not_proven: the token header carries no x5t#S256', async () => {
    const s = scenario();
    const t = s.agentToken({}, { 'x5t#S256': undefined });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
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
      subject: 'Test Leaf', issuer: 'Test Intermediate', subjectKey: good.tokenKey.publicKey, signerKey: stranger.privateKey,
      notBefore: T0 - DAY, notAfter: T0 + DAY, keyUsage: KU.digitalSignature, policies: [PEN_POLICY],
    });
    const x5c = [forged, good.interDer, good.rootDer].map((d) => d.toString('base64'));
    const thumb = crypto.createHash('sha256').update(forged).digest('base64url');
    const s = scenario({ pki: { tokenKey: good.tokenKey }, keyExtra: { x5c, 'x5t#S256': thumb } });
    const t = s.agentToken({}, { 'x5t#S256': thumb });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
  });
  it('chain_not_proven: the leaf is itself the self-signed root', async () => {
    const k = ec();
    const self = buildCert({
      subject: 'Self', issuer: 'Self', subjectKey: k.publicKey, signerKey: k.privateKey,
      notBefore: T0 - DAY, notAfter: T0 + DAY, keyUsage: KU.digitalSignature, policies: [PEN_POLICY],
    });
    const spki = crypto.createHash('sha256').update(k.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const thumb = crypto.createHash('sha256').update(self).digest('base64url');
    const s = scenario({ pki: { tokenKey: k }, keyExtra: { x5c: [self.toString('base64')], 'x5t#S256': thumb }, config: { rootPins: [spki] } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken({}, { 'x5t#S256': thumb }))), 'chain_not_proven', assert);
  });
  it('chain_not_proven: a certificate follows the self-signed root', () =>
    chainRefused('chain_not_proven', { x5cFn: (p) => [...p.x5c, p.x5c[1]] }));
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
    const s = scenario({ pki: { tokenKey: control.pki.tokenKey }, keyExtra: { x5c: evil.x5c, 'x5t#S256': evil.leafThumb } });
    // pins are the real root's; the chain in the JWKS is the attacker's
    s.client = authfi({ ...s.config, rootPins: [control.pki.rootPin] });
    const t = s.agentToken({}, { 'x5t#S256': evil.leafThumb });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_pin', assert);
  });
  it('chain_pin: rootPins does not hold the root', () =>
    chainRefused('chain_pin', { config: { rootPins: ['00'.repeat(32)] } }));
  it('chain_pin: the default pin is the AuthFI Root CA R1, so a test root is refused by default', async () => {
    const s = scenario({ config: { rootPins: undefined } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_pin', assert);
    assert.equal(authfi.DEFAULT_ROOT_PINS[0], 'b060083465bf0e9239a37f12a5e294a8c219f6b7d81563f4509c984b83ca6332');
  });
  it('chain_pin: no root in x5c and none supplied', () =>
    chainRefused('chain_pin', { pki: { omitRoot: true } }));
  it('chain_pin: the pin names the intermediate, not the root (a pin only counts for the root)', async () => {
    const s = scenario();
    const spki = crypto.createHash('sha256').update(s.pki.inter.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    s.client = authfi({ ...s.config, rootPins: [spki] });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_pin', assert);
  });
  it('a malformed pin is a configuration error', async () => {
    const s = scenario({ config: { rootPins: ['xyz'] } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'sdk_not_configured', assert);
  });

  it('chain_policy: the leaf states no PEN policy', () => chainRefused('chain_policy', { pki: { leaf: { policies: undefined } } }));
  it('chain_policy: the leaf states another policy only', () => chainRefused('chain_policy', { pki: { leaf: { policies: [OTHER_POLICY] } } }));
  it('chain_policy: anyPolicy does not count', () => chainRefused('chain_policy', { pki: { leaf: { policies: ['2.5.29.32.0'] } } }));
  it('chain_policy: an intermediate CA states no policy', () => chainRefused('chain_policy', { pki: { inter: { policies: undefined } } }));
  it('chain_policy: the leaf is a CA', () => chainRefused('chain_policy', { pki: { leaf: { ca: true, keyUsage: KU.digitalSignature | KU.keyCertSign } } }));
  it('chain_policy: the leaf lacks digitalSignature', () => chainRefused('chain_policy', { pki: { leaf: { keyUsage: KU.keyCertSign } } }));
  it('chain_policy: the leaf has no keyUsage extension', () => chainRefused('chain_policy', { pki: { leaf: { keyUsage: undefined } } }));
  it('chain_policy: an intermediate is not a CA', () => chainRefused('chain_policy', { pki: { inter: { ca: false } } }));
  it('chain_policy: an intermediate without keyCertSign', () => chainRefused('chain_policy', { pki: { inter: { keyUsage: KU.digitalSignature } } }));
  it('chain_policy: an intermediate pathLenConstraint of 0 is respected when another CA sits below it', async () => {
    // root(pathLen 0) -> intermediate -> leaf: the intermediate is a CA below a pathLen 0 root.
    await chainRefused('chain_policy', { pki: { root: { pathLen: 0 } } });
  });
  it('chain_policy: a CA with pathLen 0 that has another CA below it', () =>
    chainRefused('chain_policy', { pki: { inter: { pathLen: 0 }, extraInter: {} } }));
  it('chain_policy: the second intermediate states no policy', () =>
    chainRefused('chain_policy', { pki: { extraInter: { policies: undefined } } }));
  it('a four-certificate chain with a pathLen that allows it is accepted', () =>
    chainAccepted({ pki: { inter: { pathLen: 1 }, extraInter: { pathLen: 0 } } }));
  it('a pathLenConstraint that is large enough is accepted', () => chainAccepted({ pki: { root: { pathLen: 1 }, inter: { pathLen: 0 } } }));
});

describe('the chain cache', () => {
  it('a cached chain is re-checked for dates on every call', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - DAY, notAfter: T0 + 3600 * 1000 } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 + 2 * 3600 * 1000;
    const t = s.agentToken({ iat: Math.floor(s.clock.t / 1000), exp: Math.floor(s.clock.t / 1000) + 600 });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
  });
  it('a cached chain is checked against the clock before its leaf was valid', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - 60000, notAfter: T0 + 30 * DAY } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 - 120000;
    const now = Math.floor(s.clock.t / 1000);
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken({ iat: now, exp: now + 600 }))), 'chain_not_proven', assert);
  });
  it('a cached chain is checked against its expiry inside the cache window', async () => {
    const s = scenario({ pki: { leaf: { notBefore: T0 - DAY, notAfter: T0 + 5 * 60 * 1000 } } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t = T0 + 6 * 60 * 1000; // inside the 10 min cache window, past the leaf's end
    const now = Math.floor(s.clock.t / 1000);
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken({ iat: now, exp: now + 600 }))), 'chain_not_proven', assert);
  });
  it('a cached chain still needs the token header x5t#S256 to name the leaf', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    const t = s.agentToken({}, { 'x5t#S256': Buffer.alloc(32, 7).toString('base64url') });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
  });
  it('a cached chain still needs the JWKS x5t#S256 to name the leaf', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.jwks.keys.push({ ...s.jwks.keys[0], kid: 'k2', 'x5t#S256': Buffer.alloc(32, 7).toString('base64url') });
    s.clock.t += 20000;
    const now = Math.floor(s.clock.t / 1000);
    const t = s.token(s.agentClaims({ iat: now, exp: now + 600 }), { kid: 'k2' });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
  });
  it('a cached chain is not reused for another key under the same certificates', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken()));
    const other = ec();
    const kid = 'k2';
    s.jwks.keys.push({ ...other.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'ES256', x5c: s.pki.x5c, 'x5t#S256': s.pki.leafThumb });
    s.clock.t += 20000; // past the key set's refetch pause, so the new key is seen
    const now = Math.floor(s.clock.t / 1000);
    const t = s.token(s.agentClaims({ iat: now, exp: now + 600 }), { kid }, other.privateKey);
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'chain_not_proven', assert);
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
    for (let i = 0; i < 2; i++) await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_policy', assert);
  });
});

describe('the DER walker', () => {
  it('reads policies, basic constraints and key usage from a certificate', () => {
    const p = makePKI();
    const c = der.parseCertificate(p.leafDer);
    assert.deepEqual(c.policies, [PEN_POLICY]);
    assert.equal(c.isCA, false);
    assert.equal(c.digitalSignature, true);
    const i = der.parseCertificate(p.interDer);
    assert.equal(i.isCA, true);
    assert.equal(i.keyCertSign, true);
  });
  it('refuses truncated input, a lying length and trailing bytes without throwing out', () => {
    const p = makePKI();
    for (let n = 0; n < p.leafDer.length; n += 17) assert.throws(() => der.parseCertificate(p.leafDer.subarray(0, n)));
    const lie = Buffer.from(p.leafDer); lie[1] = 0x84; lie[2] = 0xff; lie[3] = 0xff; lie[4] = 0xff; lie[5] = 0xff;
    assert.throws(() => der.parseCertificate(lie));
    assert.throws(() => der.parseCertificate(Buffer.concat([p.leafDer, Buffer.from([0])])));
    assert.throws(() => der.parseCertificate(Buffer.from([0x30, 0x80, 0, 0])));
  });
  it('refuses a duplicated extension', () => {
    const e = seq(oid('2.5.29.32'), octet(seq(seq(oid(PEN_POLICY)))));
    const p = makePKI({ leaf: { extra: [e] } });
    assert.throws(() => der.parseCertificate(p.leafDer));
  });
  it('refuses a child whose length runs past its parent', () => {
    // SEQUENCE of 3 holding an OCTET STRING that claims 5 bytes, with more bytes after the parent
    const buf = Buffer.from([0x30, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const parent = der.readTLV(buf, 0, buf.length);
    assert.throws(() => der.readTLV(buf, parent.start, parent.end));
  });
  it('refuses a length in long form that fits the short form, and one with a leading zero byte', () => {
    const body = Buffer.alloc(200, 0);
    const longForShort = Buffer.concat([Buffer.from([0x04, 0x81, 0x05]), body]);
    assert.throws(() => der.readTLV(longForShort, 0, longForShort.length));
    const leadingZero = Buffer.concat([Buffer.from([0x04, 0x82, 0x00, 0x80]), body]);
    assert.throws(() => der.readTLV(leadingZero, 0, leadingZero.length));
    const fine = Buffer.concat([Buffer.from([0x04, 0x81, 0x80]), body]);
    assert.equal(der.readTLV(fine, 0, fine.length).end - 3, 128);
  });
  it('decodes object identifiers with multi-byte arcs', () => {
    assert.equal(der.decodeOID(Buffer.from(oid('1.3.6.1.4.1.67322.1.1')).subarray(2)), '1.3.6.1.4.1.67322.1.1');
  });
});

describe('what the chain does not do', () => {
  it('a person token needs no chain', async () => {
    const s = scenario({ noX5c: true });
    assert.equal((await s.client.verifyRequest(s.request(s.token(s.claims()), { scheme: 'Bearer', proofs: [] }))).sub, 'usr_1');
  });
  it('the issuer and audience stay what the test configured', () => {
    assert.equal(ISSUER, 'https://acme.authfi.io');
    assert.equal(AUD, 'orders-api');
    assert.equal(PUBLIC, 'https://api.example.com');
  });
});
