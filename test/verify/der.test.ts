// The DER reader behind the chain proof reads bytes anyone can put in a key set, so every way a
// certificate can be malformed must be refused with MalformedDer and nothing else.

import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import {
  MalformedDer,
  decodeOID,
  parseCertificate,
  signatureOID,
  spkiAlgorithm,
} from '../../src/verify/der.js';
import { PEN_POLICY, bitString, bool, int, name, octet, oid, seq, time, tlv } from '../containment/certs.js';
import { buildCert } from '../containment/certs.js';
import { ec } from '../containment/scenario.js';

const T = Date.parse('2026-10-26T12:00:00Z');
const key = ec();
const SIG_ALG = seq(oid('1.2.840.10045.4.3.2'));
const ascii = (s: string): Buffer => Buffer.from(s, 'ascii');

interface Parts {
  version?: Buffer | null;
  serial?: Buffer;
  sigAlg?: Buffer;
  issuer?: Buffer;
  validity?: Buffer;
  subject?: Buffer;
  spki?: Buffer;
  extras?: Buffer[];
  outerAlg?: Buffer;
  signature?: Buffer;
  trailer?: Buffer[];
}

/** A certificate assembled from raw parts, each of which a test may replace with something wrong. */
function cert(p: Parts = {}): Buffer {
  const tbs = seq(
    ...(p.version === null ? [] : [p.version ?? tlv(0xa0, int(2))]),
    p.serial ?? int(7),
    p.sigAlg ?? SIG_ALG,
    p.issuer ?? name('I'),
    p.validity ?? seq(time(T), time(T + 1000)),
    p.subject ?? name('S'),
    p.spki ?? key.publicKey.export({ type: 'spki', format: 'der' }),
    ...(p.extras ?? []),
  );
  return seq(
    tbs,
    p.outerAlg ?? p.sigAlg ?? SIG_ALG,
    p.signature ?? bitString(Buffer.alloc(8, 1)),
    ...(p.trailer ?? []),
  );
}
const extensions = (...exts: Buffer[]): Buffer => tlv(0xa3, seq(...exts));
const ext = (oidText: string, value: Buffer, critical?: Buffer): Buffer =>
  seq(oid(oidText), ...(critical ? [critical] : []), octet(value));
const refused = (der: Buffer): void => {
  assert.throws(() => parseCertificate(der), MalformedDer);
};
const BC = '2.5.29.19';
const KUSAGE = '2.5.29.15';
const POLICIES = '2.5.29.32';

describe('a certificate built from raw parts', () => {
  it('reads the control, with and without a version, and unique identifiers', () => {
    const c = parseCertificate(cert());
    assert.equal(c.notBefore, T);
    assert.equal(c.hasBasicConstraints, false);
    assert.equal(c.keyUsage, null);
    assert.equal(c.digitalSignature, false);
    assert.doesNotThrow(() => parseCertificate(cert({ version: null })));
    assert.doesNotThrow(() =>
      parseCertificate(cert({ extras: [tlv(0x81, Buffer.from([0, 1])), tlv(0x82, Buffer.from([0, 1]))] })),
    );
  });

  it('refuses the wrong shape at the top and in the to-be-signed part', () => {
    refused(seq(seq(), seq(), bitString(Buffer.alloc(1)), seq()));
    refused(seq(cert().subarray(0, 4)));
    refused(seq(tlv(0x04, Buffer.alloc(1)), SIG_ALG, bitString(Buffer.alloc(1))));
    refused(cert({ serial: octet(Buffer.from([1])) }));
    refused(cert({ sigAlg: octet(Buffer.from([1])) }));
    refused(cert({ issuer: octet(Buffer.from([1])) }));
    refused(cert({ spki: octet(Buffer.from([1])) }));
    refused(cert({ signature: octet(Buffer.from([1])) }));
    refused(cert({ signature: bitString(Buffer.alloc(4), 3) })); // unused bits in a signature
    refused(cert({ signature: tlv(0x03, Buffer.alloc(0)) }));
    refused(cert({ outerAlg: seq(oid('1.2.840.10045.4.3.3')) })); // not the algorithm inside
  });

  it('refuses a validity that is not two well-formed times', () => {
    const utc = (text: string): Buffer => tlv(0x17, ascii(text));
    const gen = (text: string): Buffer => tlv(0x18, ascii(text));
    const ok = utc('261026120000Z');
    refused(cert({ validity: seq(ok) }));
    refused(cert({ validity: seq(ok, ok, ok) }));
    refused(cert({ validity: seq(ok, tlv(0x04, ascii('x'))) }));
    refused(cert({ validity: seq(ok, utc('2610261200Z')) })); // too short
    refused(cert({ validity: seq(ok, utc('261026120000+')) })); // no Z
    refused(cert({ validity: seq(ok, utc('26102612000AZ')) })); // not digits
    refused(cert({ validity: seq(ok, utc('261326120000Z')) })); // month 13
    refused(cert({ validity: seq(ok, utc('261026240000Z')) })); // hour 24
    refused(cert({ validity: seq(ok, utc('261032120000Z')) })); // day 32
    refused(cert({ validity: seq(ok, gen('2026102612000Z')) })); // too short
    refused(cert({ validity: seq(ok, gen('20261026120000+')) }));
    // the year window of UTCTime and the long form of GeneralizedTime
    const c = parseCertificate(cert({ validity: seq(utc('990101000000Z'), gen('20510101000000Z')) }));
    assert.equal(c.notBefore, Date.UTC(1999, 0, 1));
    assert.equal(c.notAfter, Date.UTC(2051, 0, 1));
    assert.equal(
      parseCertificate(cert({ validity: seq(utc('490101000000Z'), ok) })).notBefore,
      Date.UTC(2049, 0, 1),
    );
  });

  it('refuses a malformed extensions block', () => {
    refused(cert({ extras: [tlv(0xa4, seq())] })); // not [3]
    refused(cert({ extras: [extensions(), tlv(0x81, Buffer.alloc(1))] })); // [3] not last
    refused(cert({ extras: [tlv(0xa3, octet(Buffer.alloc(1)))] })); // not a SEQUENCE inside
    refused(cert({ extras: [extensions(octet(Buffer.alloc(1)))] })); // an extension that is not a SEQUENCE
    refused(cert({ extras: [extensions(seq(oid(BC)))] })); // one field
    refused(cert({ extras: [extensions(seq(oid(BC), bool(true), bool(true), octet(Buffer.alloc(0))))] })); // four
    refused(cert({ extras: [extensions(seq(octet(Buffer.alloc(1)), octet(Buffer.alloc(1))))] })); // no OID
    refused(cert({ extras: [extensions(seq(oid(BC), int(1), octet(Buffer.alloc(0))))] })); // critical flag of the wrong type
    refused(
      cert({ extras: [extensions(seq(oid(BC), tlv(0x01, Buffer.from([0, 0])), octet(Buffer.alloc(0))))] }),
    );
    refused(cert({ extras: [extensions(seq(oid(BC), int(1)))] })); // the value is not an OCTET STRING
    refused(cert({ extras: [extensions(ext('1.2.3.4', Buffer.alloc(0)), ext('1.2.3.4', Buffer.alloc(0)))] })); // duplicate
  });

  it('reads basic constraints, and refuses malformed ones', () => {
    const bc = (...parts: Buffer[]): Buffer => cert({ extras: [extensions(ext(BC, seq(...parts)))] });
    assert.equal(parseCertificate(bc()).isCA, false);
    assert.equal(parseCertificate(bc(bool(true))).isCA, true);
    assert.equal(parseCertificate(bc(bool(false), int(5))).pathLen, 5);
    assert.equal(parseCertificate(bc(bool(true), int(300))).pathLen, 300);
    refused(bc(tlv(0x01, Buffer.from([1, 1])))); // a BOOLEAN of two bytes
    refused(bc(tlv(0x02, Buffer.alloc(0)))); // an empty INTEGER
    refused(bc(tlv(0x02, Buffer.from([0x80])))); // negative
    refused(bc(tlv(0x02, Buffer.from([1, 2, 3])))); // too wide
    refused(bc(octet(Buffer.alloc(1)))); // a field that does not belong
    refused(cert({ extras: [extensions(ext(BC, octet(Buffer.alloc(0))))] })); // not a SEQUENCE
    refused(cert({ extras: [extensions(ext(BC, Buffer.concat([seq(), Buffer.from([0])])))] })); // trailing byte
  });

  it('reads key usage and policies, and refuses malformed ones', () => {
    const ku = (value: Buffer): Buffer => cert({ extras: [extensions(ext(KUSAGE, value))] });
    const c = parseCertificate(ku(bitString(Buffer.from([0x84]), 1)));
    assert.equal(c.digitalSignature, true);
    assert.equal(c.keyCertSign, true);
    refused(ku(octet(Buffer.alloc(2)))); // not a BIT STRING
    refused(ku(bitString(Buffer.alloc(0), 0).subarray(0, 3))); // too short
    refused(ku(Buffer.concat([bitString(Buffer.from([0x80]), 1), Buffer.from([0])]))); // trailing byte
    const pol = (value: Buffer): Buffer => cert({ extras: [extensions(ext(POLICIES, value))] });
    assert.deepEqual(parseCertificate(pol(seq(seq(oid(PEN_POLICY)), seq(oid('2.5.29.32.0'))))).policies, [
      PEN_POLICY,
      '2.5.29.32.0',
    ]);
    refused(pol(octet(Buffer.alloc(1)))); // not a SEQUENCE
    refused(pol(seq(octet(Buffer.alloc(1))))); // an info that is not a SEQUENCE
    refused(pol(seq(seq(octet(Buffer.alloc(1)))))); // a policy that is not an OID
    refused(pol(Buffer.concat([seq(), Buffer.from([0])])));
  });

  it('flags a critical extension it does not understand, and honours the ones it does', () => {
    const critical = bool(true);
    assert.equal(
      parseCertificate(cert({ extras: [extensions(ext('1.2.3.4', Buffer.alloc(0), critical))] }))
        .unknownCritical,
      true,
    );
    assert.equal(
      parseCertificate(cert({ extras: [extensions(ext('1.2.3.4', Buffer.alloc(0)))] })).unknownCritical,
      false,
    );
    assert.equal(
      parseCertificate(cert({ extras: [extensions(ext('2.5.29.14', octet(Buffer.alloc(1)), critical))] }))
        .unknownCritical,
      false,
    );
  });

  it('bounds the number of children it will walk', () => {
    refused(
      cert({ extras: [extensions(...Array.from({ length: 4200 }, () => ext('1.2.3.4', Buffer.alloc(0))))] }),
    );
    refused(seq(...Array.from({ length: 4200 }, () => seq())));
  });
});

describe('object identifiers, keys and signature algorithms', () => {
  it('refuses an arc too large to hold', () => {
    assert.throws(
      () => decodeOID(Buffer.from([0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])),
      MalformedDer,
    );
    assert.equal(decodeOID(Buffer.from([0x2b, 0x06, 0x01])), '1.3.6.1');
  });
  it('reads the algorithm of a SubjectPublicKeyInfo and a signature, and refuses a malformed one', () => {
    const spki = key.publicKey.export({ type: 'spki', format: 'der' });
    assert.deepEqual(spkiAlgorithm(spki), { oid: '1.2.840.10045.2.1', curve: '1.2.840.10045.3.1.7' });
    assert.equal(spkiAlgorithm(seq(seq(oid('1.3.101.112')), bitString(Buffer.alloc(32)))).curve, '');
    assert.throws(() => spkiAlgorithm(Buffer.concat([spki, Buffer.from([0])])), MalformedDer);
    assert.throws(() => spkiAlgorithm(seq(octet(Buffer.alloc(1)))), MalformedDer);
    assert.throws(() => spkiAlgorithm(seq(seq(octet(Buffer.alloc(1))))), MalformedDer);
    assert.equal(signatureOID(SIG_ALG), '1.2.840.10045.4.3.2');
    assert.throws(() => signatureOID(octet(Buffer.alloc(1))), MalformedDer);
    assert.throws(() => signatureOID(seq(octet(Buffer.alloc(1)))), MalformedDer);
  });
});

describe('a certificate with one byte changed', () => {
  it('is either read or refused as MalformedDer, never anything else', () => {
    const good = buildCert({
      subject: 'S',
      issuer: 'I',
      subjectKey: key.publicKey,
      signerKey: key.privateKey,
      notBefore: T,
      notAfter: T + 1000,
      ca: true,
      keyUsage: 0x84,
      policies: [PEN_POLICY],
      pathLen: 1,
    });
    let refusedCount = 0;
    for (let i = 0; i < good.length; i++) {
      for (const value of [0x00, 0x01, 0x30, 0x7f, 0x80, 0xff]) {
        const bad = Buffer.from(good);
        bad[i] = value;
        try {
          parseCertificate(bad);
        } catch (e) {
          assert.ok(e instanceof MalformedDer, `byte ${String(i)} set to ${String(value)}: ${String(e)}`);
          refusedCount++;
        }
      }
    }
    assert.ok(refusedCount > good.length, 'most changes should be refused');
  });
});
