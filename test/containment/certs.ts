// A tiny X.509 builder for tests: DER-encode a certificate and sign it with node:crypto. It exists
// because node can parse certificates but not create them. Test use only; never shipped logic.

import { constants, sign, type KeyObject } from 'node:crypto';

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const b: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
}

export const tlv = (tag: number, ...parts: Buffer[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
};
export const seq = (...p: Buffer[]): Buffer => tlv(0x30, ...p);
const set = (...p: Buffer[]): Buffer => tlv(0x31, ...p);
export const octet = (b: Buffer): Buffer => tlv(0x04, b);
export const bool = (v: boolean): Buffer => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
export const int = (n: number): Buffer => {
  let h = n.toString(16);
  if (h.length % 2 === 1) h = `0${h}`;
  let b = Buffer.from(h, 'hex');
  if ((b[0] ?? 0) & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
};
export const bitString = (bytes: Buffer, unused = 0): Buffer => tlv(0x03, Buffer.from([unused]), bytes);
const utf8 = (s: string): Buffer => tlv(0x0c, Buffer.from(s, 'utf8'));
export function oid(s: string): Buffer {
  const p = s.split('.').map(Number);
  const out = [(p[0] ?? 0) * 40 + (p[1] ?? 0)];
  for (const v of p.slice(2)) {
    const t = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) t.unshift(0x80 | (x & 0x7f));
    out.push(...t);
  }
  return tlv(0x06, Buffer.from(out));
}
export function time(ms: number): Buffer {
  const d = new Date(ms);
  const p = (n: number): string => String(n).padStart(2, '0');
  const y = d.getUTCFullYear();
  const body = `${p(y % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(body, 'ascii'));
}
export const name = (cn: string): Buffer => seq(set(seq(oid('2.5.4.3'), utf8(cn))));

export const PEN_POLICY = '1.3.6.1.4.1.67322.1.1';
export const PEN_POLICY_2 = '1.3.6.1.4.1.67322.1.2';
export const OTHER_POLICY = '1.3.6.1.4.1.99999.1.1';

export const KU = { digitalSignature: 0x80, keyCertSign: 0x04, cRLSign: 0x02 };

let serial = 1000;

/** What one certificate is built from; `undefined` for policies or keyUsage leaves the extension out. */
export interface CertSpec {
  subject: string;
  issuer: string;
  subjectKey: KeyObject;
  signerKey: KeyObject;
  notBefore: number;
  notAfter: number;
  ca?: boolean | undefined;
  pathLen?: number | undefined;
  keyUsage?: number | undefined;
  policies?: string[] | undefined;
  noBasicConstraints?: boolean | undefined;
  extra?: Buffer[] | undefined;
}

/** Returns a DER certificate. The signer is an EC P-256, Ed25519 or RSA private key. */
export function buildCert(spec: CertSpec): Buffer {
  const { subject, issuer, subjectKey, signerKey, notBefore, notAfter, ca = false, pathLen, keyUsage } = spec;
  const type = signerKey.asymmetricKeyType;
  const curve = signerKey.asymmetricKeyDetails?.namedCurve;
  const eddsa = type === 'ed25519' || type === 'ed448';
  const rsa = type === 'rsa';
  const p384 = curve === 'secp384r1';
  const sigAlg = eddsa
    ? seq(oid(type === 'ed25519' ? '1.3.101.112' : '1.3.101.113'))
    : rsa
      ? seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]))
      : seq(oid(p384 ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2'));
  const exts: Buffer[] = [];
  if (spec.noBasicConstraints !== true) {
    exts.push(
      seq(
        oid('2.5.29.19'),
        bool(true),
        octet(seq(...(ca ? [bool(true)] : []), ...(pathLen === undefined ? [] : [int(pathLen)]))),
      ),
    );
  }
  if (keyUsage !== undefined)
    exts.push(seq(oid('2.5.29.15'), bool(true), octet(bitString(Buffer.from([keyUsage]), 1))));
  if (spec.policies) exts.push(seq(oid('2.5.29.32'), octet(seq(...spec.policies.map((p) => seq(oid(p)))))));
  exts.push(...(spec.extra ?? []));
  const tbs = seq(
    tlv(0xa0, int(2)),
    int(serial++),
    sigAlg,
    name(issuer),
    seq(time(notBefore), time(notAfter)),
    name(subject),
    subjectKey.export({ type: 'spki', format: 'der' }),
    tlv(0xa3, seq(...exts)),
  );
  const sig = sign(
    eddsa ? null : p384 ? 'sha384' : 'sha256',
    tbs,
    rsa ? { key: signerKey, padding: constants.RSA_PKCS1_PADDING } : signerKey,
  );
  return seq(tbs, sigAlg, bitString(sig));
}
