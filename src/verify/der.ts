// A small, bounds-checked ASN.1 DER reader for the one job the chain proof needs: the facts of an
// X.509 certificate (names, validity, key, signature, policies, basic constraints, key usage).
// Every read is checked against the enclosing length; malformed input throws `MalformedDer`.

const MAX_NODES = 4096;

/** Thrown for any byte sequence that is not the DER the reader expects. */
export class MalformedDer extends Error {
  constructor() {
    super('malformed DER');
    this.name = 'MalformedDer';
  }
}

/**
 *
 */
export interface DerNode {
  readonly tag: number;
  /** Where the header starts. */
  readonly head: number;
  readonly start: number;
  readonly end: number;
}

function byteAt(buf: Uint8Array, i: number): number {
  const b = buf[i];
  if (b === undefined) throw new MalformedDer();
  return b;
}

/**
 *
 */
export function readTLV(buf: Uint8Array, off: number, end: number): DerNode {
  if (off + 2 > end) throw new MalformedDer();
  const tag = byteAt(buf, off);
  if ((tag & 0x1f) === 0x1f) throw new MalformedDer(); // multi-byte tag numbers do not occur in a certificate
  let len = byteAt(buf, off + 1);
  let p = off + 2;
  if ((len & 0x80) !== 0) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > end) throw new MalformedDer(); // indefinite or oversized length
    if (byteAt(buf, p) === 0) throw new MalformedDer(); // not minimal
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + byteAt(buf, p++);
    if (len < 0x80) throw new MalformedDer(); // long form for a short length is not DER
  }
  if (len > end - p) throw new MalformedDer();
  return { tag, head: off, start: p, end: p + len };
}

function children(buf: Uint8Array, node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let p = node.start;
  while (p < node.end) {
    const t = readTLV(buf, p, node.end);
    out.push(t);
    p = t.end;
    if (out.length > MAX_NODES) throw new MalformedDer();
  }
  return out;
}

function content(buf: Uint8Array, node: DerNode): Uint8Array {
  return buf.subarray(node.start, node.end);
}

function whole(buf: Uint8Array, node: DerNode): Uint8Array {
  return buf.subarray(node.head, node.end);
}

/** Decodes the content bytes of an OBJECT IDENTIFIER to its dotted form. */
export function decodeOID(bytes: Uint8Array): string {
  if (bytes.length === 0 || (byteAt(bytes, bytes.length - 1) & 0x80) !== 0) throw new MalformedDer();
  const arcs: number[] = [];
  let v = 0;
  let first = true;
  for (const b of bytes) {
    if (v === 0 && b === 0x80) throw new MalformedDer(); // leading zero group
    v = v * 128 + (b & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER / 256) throw new MalformedDer();
    if ((b & 0x80) !== 0) continue;
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
// Extensions this SDK understands well enough that a critical flag on them can be honoured:
// subject key id, authority key id, extended key usage.
const KNOWN_EXTENSIONS = new Set([
  OID_BASIC_CONSTRAINTS,
  OID_KEY_USAGE,
  OID_POLICIES,
  '2.5.29.14',
  '2.5.29.35',
  '2.5.29.37',
]);

function parseBasicConstraints(
  buf: Uint8Array,
  value: DerNode,
): { isCA: boolean; pathLen: number | undefined } {
  const seq = readTLV(buf, value.start, value.end);
  if (seq.tag !== 0x30 || seq.end !== value.end) throw new MalformedDer();
  let isCA = false;
  let pathLen: number | undefined;
  for (const c of children(buf, seq)) {
    const size = c.end - c.start;
    if (c.tag === 0x01) {
      if (size !== 1) throw new MalformedDer();
      isCA = byteAt(buf, c.start) !== 0;
    } else if (c.tag === 0x02) {
      if (size < 1 || size > 2 || (byteAt(buf, c.start) & 0x80) !== 0) throw new MalformedDer();
      pathLen = size === 2 ? byteAt(buf, c.start) * 256 + byteAt(buf, c.start + 1) : byteAt(buf, c.start);
    } else throw new MalformedDer();
  }
  return { isCA, pathLen };
}

function parseKeyUsage(buf: Uint8Array, value: DerNode): number {
  const bits = readTLV(buf, value.start, value.end);
  if (bits.tag !== 0x03 || bits.end !== value.end || bits.end - bits.start < 2) throw new MalformedDer();
  return byteAt(buf, bits.start + 1); // first byte of flags: digitalSignature is 0x80, keyCertSign 0x04
}

function parsePolicies(buf: Uint8Array, value: DerNode): string[] {
  const seq = readTLV(buf, value.start, value.end);
  if (seq.tag !== 0x30 || seq.end !== value.end) throw new MalformedDer();
  const out: string[] = [];
  for (const info of children(buf, seq)) {
    if (info.tag !== 0x30) throw new MalformedDer();
    const first = readTLV(buf, info.start, info.end);
    if (first.tag !== 0x06) throw new MalformedDer();
    out.push(decodeOID(content(buf, first)));
  }
  return out;
}

function digits(text: string, from: number, count: number): number {
  const part = text.slice(from, from + count);
  if (!/^\d+$/.test(part)) throw new MalformedDer();
  return Number(part);
}

/** Reads a UTCTime or GeneralizedTime in the DER form (`Z`, seconds present) to epoch milliseconds. */
function parseTime(buf: Uint8Array, node: DerNode): number {
  const text = new TextDecoder('ascii').decode(content(buf, node));
  let year: number;
  let at: number;
  if (node.tag === 0x17) {
    if (text.length !== 13) throw new MalformedDer();
    const yy = digits(text, 0, 2);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    at = 2;
  } else if (node.tag === 0x18) {
    if (text.length !== 15) throw new MalformedDer();
    year = digits(text, 0, 4);
    at = 4;
  } else throw new MalformedDer();
  if (!text.endsWith('Z')) throw new MalformedDer();
  const month = digits(text, at, 2);
  const day = digits(text, at + 2, 2);
  const hour = digits(text, at + 4, 2);
  const minute = digits(text, at + 6, 2);
  const second = digits(text, at + 8, 2);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59)
    throw new MalformedDer();
  return Date.UTC(year, month - 1, day, hour, minute, second);
}

/** What the chain proof reads from one certificate. */
export interface Certificate {
  /** The DER of the whole certificate. */
  readonly der: Uint8Array;
  /** The to-be-signed bytes the signature covers. */
  readonly tbs: Uint8Array;
  /** The DER of the signature algorithm identifier (the same in the TBS and outside it). */
  readonly signatureAlgorithm: Uint8Array;
  /** The signature value, the bit string without its unused-bits byte. */
  readonly signature: Uint8Array;
  /** The DER of the issuer name. */
  readonly issuer: Uint8Array;
  /** The DER of the subject name. */
  readonly subject: Uint8Array;
  /** The DER of the SubjectPublicKeyInfo. */
  readonly spki: Uint8Array;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly policies: readonly string[];
  readonly isCA: boolean;
  readonly pathLen: number | undefined;
  readonly hasBasicConstraints: boolean;
  /** The first byte of the key usage flags, or null when the extension is absent. */
  readonly keyUsage: number | null;
  readonly unknownCritical: boolean;
  readonly digitalSignature: boolean;
  readonly keyCertSign: boolean;
}

/** The algorithm of a SubjectPublicKeyInfo: its OID and, for an EC key, the curve OID (empty otherwise). */
export function spkiAlgorithm(spki: Uint8Array): { oid: string; curve: string } {
  const top = readTLV(spki, 0, spki.length);
  if (top.tag !== 0x30 || top.end !== spki.length) throw new MalformedDer();
  const [alg] = children(spki, top);
  if (alg?.tag !== 0x30) throw new MalformedDer();
  const [oid, param] = children(spki, alg);
  if (oid?.tag !== 0x06) throw new MalformedDer();
  return {
    oid: decodeOID(content(spki, oid)),
    curve: param?.tag === 0x06 ? decodeOID(content(spki, param)) : '',
  };
}

/** The OID of a signature AlgorithmIdentifier. */
export function signatureOID(algorithm: Uint8Array): string {
  const seq = readTLV(algorithm, 0, algorithm.length);
  const [oid] = children(algorithm, seq);
  if (seq.tag !== 0x30 || oid?.tag !== 0x06) throw new MalformedDer();
  return decodeOID(content(algorithm, oid));
}

/** Converts an ECDSA signature in DER (`SEQUENCE { r, s }`) to the fixed-width `r || s` WebCrypto verifies. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array<ArrayBuffer> {
  const seq = readTLV(der, 0, der.length);
  if (seq.tag !== 0x30 || seq.end !== der.length) throw new MalformedDer();
  const parts = children(der, seq);
  if (parts.length !== 2) throw new MalformedDer();
  const out = new Uint8Array(size * 2);
  parts.forEach((p, i) => {
    if (p.tag !== 0x02) throw new MalformedDer();
    let int = content(der, p);
    if (int.length === 0 || (byteAt(int, 0) & 0x80) !== 0) throw new MalformedDer(); // empty or negative
    while (int.length > 1 && byteAt(int, 0) === 0) int = int.subarray(1);
    if (int.length > size) throw new MalformedDer();
    out.set(int, i * size + size - int.length);
  });
  return out;
}

/** Reads the facts the chain proof needs from a certificate. Throws {@link MalformedDer} on anything off. */
export function parseCertificate(buf: Uint8Array): Certificate {
  const top = readTLV(buf, 0, buf.length);
  if (top.tag !== 0x30 || top.end !== buf.length) throw new MalformedDer();
  const parts = children(buf, top);
  const [tbsNode, algNode, sigNode] = parts;
  if (parts.length !== 3 || tbsNode?.tag !== 0x30 || algNode?.tag !== 0x30 || sigNode?.tag !== 0x03)
    throw new MalformedDer();
  const tbs = children(buf, tbsNode);
  let i = 0;
  if (tbs[i]?.tag === 0xa0) i++; // version
  // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
  const want = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30];
  for (const tag of want) {
    if (tbs[i]?.tag !== tag) throw new MalformedDer();
    i++;
  }
  const [, innerAlg, issuer, validity, subject, spki] = tbs.slice(i - 6) as [
    DerNode,
    DerNode,
    DerNode,
    DerNode,
    DerNode,
    DerNode,
  ];
  const innerBytes = whole(buf, innerAlg);
  const outerBytes = whole(buf, algNode);
  if (innerBytes.length !== outerBytes.length || innerBytes.some((b, k) => b !== outerBytes[k]))
    throw new MalformedDer();
  const times = children(buf, validity);
  const [from, to] = times;
  if (times.length !== 2 || from === undefined || to === undefined) throw new MalformedDer();
  const notBefore = parseTime(buf, from);
  const notAfter = parseTime(buf, to);
  if (sigNode.end - sigNode.start < 1 || byteAt(buf, sigNode.start) !== 0) throw new MalformedDer();

  let policies: string[] = [];
  let isCA = false;
  let pathLen: number | undefined;
  let hasBasicConstraints = false;
  let keyUsage: number | null = null;
  let unknownCritical = false;
  const seen = new Set<string>();
  for (; i < tbs.length; i++) {
    const t = tbs[i];
    if (t === undefined) throw new MalformedDer();
    if (t.tag === 0x81 || t.tag === 0x82) continue; // unique identifiers
    if (t.tag !== 0xa3 || i !== tbs.length - 1) throw new MalformedDer();
    const list = readTLV(buf, t.start, t.end);
    if (list.tag !== 0x30 || list.end !== t.end) throw new MalformedDer();
    for (const ext of children(buf, list)) {
      if (ext.tag !== 0x30) throw new MalformedDer();
      const f = children(buf, ext);
      const [oidNode, second] = f;
      if (f.length < 2 || f.length > 3 || oidNode?.tag !== 0x06 || second === undefined)
        throw new MalformedDer();
      const oid = decodeOID(content(buf, oidNode));
      let critical = false;
      if (f.length === 3) {
        if (second.tag !== 0x01 || second.end - second.start !== 1) throw new MalformedDer();
        critical = byteAt(buf, second.start) !== 0;
      }
      const v = f[f.length - 1];
      if (v?.tag !== 0x04) throw new MalformedDer();
      if (seen.has(oid)) throw new MalformedDer(); // a duplicated extension is ambiguous
      seen.add(oid);
      if (oid === OID_BASIC_CONSTRAINTS) {
        const bc = parseBasicConstraints(buf, v);
        isCA = bc.isCA;
        pathLen = bc.pathLen;
        hasBasicConstraints = true;
      } else if (oid === OID_KEY_USAGE) keyUsage = parseKeyUsage(buf, v);
      else if (oid === OID_POLICIES) policies = parsePolicies(buf, v);
      else if (critical && !KNOWN_EXTENSIONS.has(oid)) unknownCritical = true;
    }
  }
  return {
    der: buf,
    tbs: whole(buf, tbsNode),
    signatureAlgorithm: outerBytes,
    signature: buf.subarray(sigNode.start + 1, sigNode.end),
    issuer: whole(buf, issuer),
    subject: whole(buf, subject),
    spki: whole(buf, spki),
    notBefore,
    notAfter,
    policies,
    isCA,
    pathLen,
    hasBasicConstraints,
    keyUsage,
    unknownCritical,
    digitalSignature: keyUsage !== null && (keyUsage & 0x80) !== 0,
    keyCertSign: keyUsage !== null && (keyUsage & 0x04) !== 0,
  };
}
