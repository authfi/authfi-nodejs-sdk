'use strict';
// A tiny X.509 builder for tests: DER-encode a certificate and sign it with node:crypto. It exists
// because node can parse certificates but not create them. Test use only; never shipped logic.
const crypto = require('node:crypto');

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
}
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const octet = (b) => tlv(0x04, b);
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const int = (n) => {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = Buffer.from(h, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
};
const bitString = (bytes, unused = 0) => tlv(0x03, Buffer.from([unused]), bytes);
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
function oid(s) {
  const p = s.split('.').map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const v of p.slice(2)) {
    const t = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) t.unshift(0x80 | (x & 0x7f));
    out.push(...t);
  }
  return tlv(0x06, Buffer.from(out));
}
function time(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  const y = d.getUTCFullYear();
  const body = `${p(y % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(body, 'ascii'));
}
const name = (cn) => seq(set(seq(oid('2.5.4.3'), utf8(cn))));

const PEN_POLICY = '1.3.6.1.4.1.67322.1.1';
const PEN_POLICY_2 = '1.3.6.1.4.1.67322.1.2';
const OTHER_POLICY = '1.3.6.1.4.1.99999.1.1';

const KU = { digitalSignature: 0x80, keyCertSign: 0x04, cRLSign: 0x02 };

let serial = 1000;

// buildCert returns a DER Buffer. subjectKey is the certified public KeyObject; signerKey the
// signer's private KeyObject (EC P-256 or Ed25519).
function buildCert({
  subject, issuer, subjectKey, signerKey, notBefore, notAfter,
  ca = false, pathLen, keyUsage, policies, noBasicConstraints = false, extra = [],
}) {
  const ed = signerKey.asymmetricKeyType === 'ed25519';
  const sigAlg = ed ? seq(oid('1.3.101.112')) : seq(oid('1.2.840.10045.4.3.2'));
  const exts = [];
  if (!noBasicConstraints) {
    exts.push(seq(oid('2.5.29.19'), bool(true), octet(seq(...(ca ? [bool(true)] : []), ...(pathLen === undefined ? [] : [int(pathLen)])))));
  }
  if (keyUsage !== undefined) exts.push(seq(oid('2.5.29.15'), bool(true), octet(bitString(Buffer.from([keyUsage]), 1))));
  if (policies) exts.push(seq(oid('2.5.29.32'), octet(seq(...policies.map((p) => seq(oid(p)))))));
  exts.push(...extra);
  const tbs = seq(
    tlv(0xa0, int(2)), int(serial++), sigAlg, name(issuer),
    seq(time(notBefore), time(notAfter)), name(subject),
    subjectKey.export({ type: 'spki', format: 'der' }),
    tlv(0xa3, seq(...exts)),
  );
  const sig = crypto.sign(ed ? null : 'sha256', tbs, signerKey);
  return seq(tbs, sigAlg, bitString(sig));
}

module.exports = { buildCert, seq, oid, octet, bool, tlv, int, KU, PEN_POLICY, PEN_POLICY_2, OTHER_POLICY };
