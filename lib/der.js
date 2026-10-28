'use strict';
// A small, bounds-checked ASN.1 DER reader. Node's X509Certificate exposes no certificate
// policies, no basic constraints path length and no key usage bits, so they are read from the
// certificate DER here. Every read is checked against the enclosing length; malformed input throws.

const MAX_DEPTH_NODES = 4096;

function bad() { throw new Error('malformed DER'); }

function readTLV(buf, off, end) {
  if (off + 2 > end) bad();
  const tag = buf[off];
  if ((tag & 0x1f) === 0x1f) bad(); // multi-byte tag numbers do not occur in a certificate
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > end) bad(); // indefinite or oversized length
    if (buf[p] === 0) bad(); // not minimal
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    if (len < 0x80) bad(); // long form for a short length is not DER
  }
  if (len > end - p) bad();
  return { tag, start: p, end: p + len, next: p + len };
}

function children(buf, node) {
  const out = [];
  let p = node.start;
  while (p < node.end) {
    const t = readTLV(buf, p, node.end);
    out.push(t);
    p = t.next;
    if (out.length > MAX_DEPTH_NODES) bad();
  }
  return out;
}

function decodeOID(content) {
  if (content.length === 0 || content[content.length - 1] & 0x80) bad();
  const arcs = [];
  let v = 0;
  let first = true;
  for (let i = 0; i < content.length; i++) {
    const b = content[i];
    if (v === 0 && b === 0x80) bad(); // leading zero group
    v = v * 128 + (b & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER / 256) bad();
    if (b & 0x80) continue;
    if (first) {
      const a = v < 80 ? Math.floor(v / 40) : 2;
      arcs.push(a, v - a * 40);
      first = false;
    } else arcs.push(v);
    v = 0;
  }
  return arcs.join('.');
}

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_POLICIES = '2.5.29.32';
// Extensions this SDK understands well enough that a critical flag on them can be honoured.
const KNOWN_EXTENSIONS = new Set([OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_POLICIES, '2.5.29.14', '2.5.29.35', '2.5.29.37']);

function parseBasicConstraints(buf, value) {
  const seq = readTLV(buf, value.start, value.end);
  if (seq.tag !== 0x30 || seq.next !== value.end) bad();
  let isCA = false;
  let pathLen;
  for (const c of children(buf, seq)) {
    if (c.tag === 0x01) {
      if (c.end - c.start !== 1) bad();
      isCA = buf[c.start] !== 0;
    } else if (c.tag === 0x02) {
      if (c.end - c.start < 1 || c.end - c.start > 2 || buf[c.start] & 0x80) bad();
      pathLen = buf[c.start] * (c.end - c.start === 2 ? 256 : 1) + (c.end - c.start === 2 ? buf[c.start + 1] : 0);
    } else bad();
  }
  return { isCA, pathLen };
}

function parseKeyUsage(buf, value) {
  const bits = readTLV(buf, value.start, value.end);
  if (bits.tag !== 0x03 || bits.next !== value.end || bits.end - bits.start < 2) bad();
  return buf[bits.start + 1]; // first byte of flags: bit 0 digitalSignature (0x80), keyCertSign (0x04)
}

function parsePolicies(buf, value) {
  const seq = readTLV(buf, value.start, value.end);
  if (seq.tag !== 0x30 || seq.next !== value.end) bad();
  const out = [];
  for (const info of children(buf, seq)) {
    if (info.tag !== 0x30) bad();
    const first = readTLV(buf, info.start, info.end);
    if (first.tag !== 0x06) bad();
    out.push(decodeOID(buf.subarray(first.start, first.end)));
  }
  return out;
}

// parseCertificate reads the facts the chain proof needs. It throws on anything malformed.
function parseCertificate(buf) {
  const top = readTLV(buf, 0, buf.length);
  if (top.tag !== 0x30 || top.next !== buf.length) bad();
  const parts = children(buf, top);
  if (parts.length !== 3 || parts[0].tag !== 0x30 || parts[1].tag !== 0x30 || parts[2].tag !== 0x03) bad();
  const tbs = children(buf, parts[0]);
  let i = 0;
  if (tbs[i] && tbs[i].tag === 0xa0) i++; // version
  // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
  const want = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30];
  for (const tag of want) {
    if (!tbs[i] || tbs[i].tag !== tag) bad();
    i++;
  }
  const out = { policies: [], isCA: false, pathLen: undefined, hasBasicConstraints: false, keyUsage: null, unknownCritical: false };
  const seen = new Set();
  for (; i < tbs.length; i++) {
    const t = tbs[i];
    if (t.tag === 0x81 || t.tag === 0x82) continue; // unique identifiers
    if (t.tag !== 0xa3 || i !== tbs.length - 1) bad();
    const list = readTLV(buf, t.start, t.end);
    if (list.tag !== 0x30 || list.next !== t.end) bad();
    for (const ext of children(buf, list)) {
      if (ext.tag !== 0x30) bad();
      const f = children(buf, ext);
      if (f.length < 2 || f.length > 3 || f[0].tag !== 0x06) bad();
      const oid = decodeOID(buf.subarray(f[0].start, f[0].end));
      let critical = false;
      if (f.length === 3) {
        if (f[1].tag !== 0x01 || f[1].end - f[1].start !== 1) bad();
        critical = buf[f[1].start] !== 0;
      }
      const v = f[f.length - 1];
      if (v.tag !== 0x04) bad();
      if (seen.has(oid)) bad(); // a duplicated extension is ambiguous
      seen.add(oid);
      if (oid === OID_BASIC_CONSTRAINTS) {
        const bc = parseBasicConstraints(buf, v);
        Object.assign(out, { isCA: bc.isCA, pathLen: bc.pathLen, hasBasicConstraints: true });
      } else if (oid === OID_KEY_USAGE) out.keyUsage = parseKeyUsage(buf, v);
      else if (oid === OID_POLICIES) out.policies = parsePolicies(buf, v);
      else if (critical && !KNOWN_EXTENSIONS.has(oid)) out.unknownCritical = true;
    }
  }
  out.digitalSignature = out.keyUsage !== null && (out.keyUsage & 0x80) !== 0;
  out.keyCertSign = out.keyUsage !== null && (out.keyUsage & 0x04) !== 0;
  return out;
}

module.exports = { parseCertificate, decodeOID, readTLV };
