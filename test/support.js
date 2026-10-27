'use strict';

// Shared builders for the receiver tests: a fake issuer that serves a key set and signs, and a rig
// that wires a client, a store and a receiver to a real HTTP server.

const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('http');
const authfi = require('../index');

const STREAM_AUD = 'stream-aud-1';
const API_AUD = 'api-orders';
const AGENT = 'agent:agt_42';
const EV = {
  revoked: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  claims: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
  purged: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  compromise: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
};
const SECEVENT = 'application/secevent+jwt';

const b64 = (buf) => Buffer.from(buf).toString('base64url');

/** A fake issuer: serves a key set over HTTP and signs with the keys in it. */
class Issuer {
  constructor() {
    this.nowMs = Date.UTC(2026, 9, 26, 12, 0, 0);
    this.keys = new Map();
    this.jwksHits = 0;
    this.jwksStatus = 200;
    const ed = crypto.generateKeyPairSync('ed25519');
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.add('ed1', 'EdDSA', ed);
    this.add('rs1', 'RS256', rsa);
    this.add('ps1', 'PS256', rsa);
    this.add('es1', 'ES256', ec);
  }

  add(kid, alg, pair) {
    this.keys.set(kid, { kid, alg, pair });
  }

  async listen() {
    this.server = http.createServer((req, res) => {
      if (req.url !== '/.well-known/jwks.json') {
        res.statusCode = 404;
        res.end();
        return;
      }
      this.jwksHits += 1;
      res.statusCode = this.jwksStatus;
      res.setHeader('Content-Type', 'application/json');
      const keys = [...this.keys.values()].map((k) => ({ ...k.pair.publicKey.export({ format: 'jwk' }), kid: k.kid, use: 'sig', alg: k.alg }));
      if (this.kidless) keys.push({ ...this.keys.get('ed1').pair.publicKey.export({ format: 'jwk' }), use: 'sig', alg: 'EdDSA' });
      res.end(JSON.stringify({ keys }));
    });
    await new Promise((r) => this.server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${this.server.address().port}`;
    return this;
  }

  close() {
    this.server.closeAllConnections();
    this.server.close();
  }

  clock() {
    return this.nowMs;
  }

  seconds() {
    return Math.floor(this.nowMs / 1000);
  }

  advance(ms) {
    this.nowMs += ms;
  }

  sign(kid, header, payload) {
    const k = this.keys.get(kid);
    const h = b64(JSON.stringify({ alg: k.alg, typ: 'secevent+jwt', kid, ...header }));
    const p = b64(JSON.stringify(payload));
    const data = Buffer.from(`${h}.${p}`);
    let sig;
    switch (k.alg) {
      case 'EdDSA':
        sig = crypto.sign(null, data, k.pair.privateKey);
        break;
      case 'RS256':
        sig = crypto.sign('sha256', data, k.pair.privateKey);
        break;
      case 'PS256':
        sig = crypto.sign('sha256', data, { key: k.pair.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
        break;
      default:
        sig = crypto.sign('sha256', data, { key: k.pair.privateKey, dsaEncoding: 'ieee-p1363' });
    }
    return `${h}.${p}.${b64(sig)}`;
  }

  setClaims(event = EV.revoked, detail = {}) {
    return {
      iss: this.url,
      jti: crypto.randomUUID(),
      iat: this.seconds(),
      aud: STREAM_AUD,
      sub_id: { format: 'opaque', id: AGENT },
      events: { [event]: { event_timestamp: this.seconds(), ...detail } },
    };
  }

  set({ kid = 'ed1', header, claims, drop = [] } = {}) {
    const c = { ...(claims || this.setClaims()) };
    for (const d of drop) delete c[d];
    return this.sign(kid, header, c);
  }

  /** An access token as the platform mints it. */
  token(sub, iat, extra = {}) {
    const payload = { iss: this.url, sub, aud: API_AUD, tenant_id: 't1', iat, exp: this.seconds() + 3600, ...extra };
    return this.sign('ed1', { typ: 'at+jwt' }, payload);
  }
}

const open = [];

async function rig({ store, receiver = {}, client = {} } = {}) {
  const issuer = await new Issuer().listen();
  const revocations = store || authfi.createRevocationStore({ clock: () => issuer.clock() });
  const signals = [];
  const logs = [];
  const logger = { info: (m, f) => logs.push(['info', m, f]), warn: (m, f) => logs.push(['warn', m, f]) };
  const auth = authfi({ tenant: 'acme', apiKey: 'sk_test', issuer: issuer.url, revocations, clock: () => issuer.clock(), logger, ...client });
  const handler = auth.receiver({ audience: STREAM_AUD, onSignal: (s) => signals.push(s), ...receiver });
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/ssf/push`;
  open.push(() => {
    server.closeAllConnections();
    server.close();
    issuer.close();
  });
  const push = (body, headers = {}, method = 'POST') =>
    fetch(url, { method, headers: { 'Content-Type': SECEVENT, ...headers }, body: method === 'POST' ? body : undefined }).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }));
  return { issuer, auth, store: revocations, signals, logs, push, url };
}

const err = (r) => JSON.parse(r.text).err;
const refused = async (promise, code) => {
  await assert.rejects(promise, (e) => e.code === code || e.message === code, `expected ${code}`);
};

module.exports = { STREAM_AUD, API_AUD, AGENT, EV, SECEVENT, b64, Issuer, open, rig, err, refused };
