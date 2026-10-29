// Builders for the receiver tests: a fake issuer that serves discovery and a key set over HTTP and
// signs with the keys in it, and a rig that wires a client, a store and a receiver to a real HTTP server.

import assert from 'node:assert/strict';
import { constants, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach } from 'vitest';
import type { Clock } from '../../src/core/clock.js';
import type { Logger } from '../../src/core/logger.js';
import { AuthFI } from '../../src/core/project.js';
import {
  createReceiver,
  createRevocationStore,
  type MemoryRevocationStore,
  type PushRequest,
  type PushResponse,
  type ReceiverOptions,
  type Signal,
} from '../../src/signals/index.js';
import type { TokenVerifier, VerifierOptions } from '../../src/verify/verifier.js';

export const STREAM_AUD = 'stream-aud-1';
export const API_AUD = 'api-orders';
export const AGENT = 'agent:agt_42';
export const EV = {
  revoked: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  claims: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
  purged: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  compromise: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
};
export const SECEVENT = 'application/secevent+jwt';

export const b64 = (buf: Uint8Array | string): string => Buffer.from(buf).toString('base64url');

interface Key {
  kid: string;
  alg: string;
  pair: { publicKey: KeyObject; privateKey: KeyObject };
}

export type Claims = Record<string, unknown>;

/** A fake issuer: serves discovery and a key set over HTTP and signs with the keys in it. */
export class Issuer {
  nowMs = Date.UTC(2026, 9, 26, 12, 0, 0);
  readonly keys = new Map<string, Key>();
  jwksHits = 0;
  jwksStatus = 200;
  kidless = false;
  server!: Server;
  url = '';

  constructor() {
    const ed = generateKeyPairSync('ed25519');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.add('ed1', 'EdDSA', ed);
    this.add('rs1', 'RS256', rsa);
    this.add('ps1', 'PS256', rsa);
    this.add('es1', 'ES256', ec);
  }

  add(kid: string, alg: string, pair: Key['pair']): void {
    this.keys.set(kid, { kid, alg, pair });
  }

  async listen(): Promise<this> {
    this.server = createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/.well-known/openid-configuration') {
        res.end(
          JSON.stringify({
            issuer: this.url,
            token_endpoint: `${this.url}/oauth/token`,
            jwks_uri: `${this.url}/.well-known/jwks.json`,
          }),
        );
        return;
      }
      if (req.url !== '/.well-known/jwks.json') {
        res.statusCode = 404;
        res.end();
        return;
      }
      this.jwksHits += 1;
      res.statusCode = this.jwksStatus;
      const keys: Record<string, unknown>[] = [...this.keys.values()].map((k) => ({
        ...k.pair.publicKey.export({ format: 'jwk' }),
        kid: k.kid,
        use: 'sig',
        alg: k.alg,
      }));
      const first = this.keys.get('ed1');
      if (this.kidless && first)
        keys.push({ ...first.pair.publicKey.export({ format: 'jwk' }), use: 'sig', alg: 'EdDSA' });
      res.end(JSON.stringify({ keys }));
    });
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${String((this.server.address() as AddressInfo).port)}`;
    return this;
  }

  close(): void {
    this.server.closeAllConnections();
    this.server.close();
  }

  clock(): number {
    return this.nowMs;
  }

  /** A clock for the SDK that follows this issuer's time. */
  sdkClock(): Clock {
    return {
      now: () => this.nowMs,
      monotonic: () => this.nowMs,
      sleep: () => Promise.resolve(),
    };
  }

  seconds(): number {
    return Math.floor(this.nowMs / 1000);
  }

  advance(ms: number): void {
    this.nowMs += ms;
  }

  sign(kid: string, header: Claims | undefined, payload: Claims): string {
    const k = this.keys.get(kid);
    if (!k) throw new Error(`no key ${kid}`);
    const h = b64(JSON.stringify({ alg: k.alg, typ: 'secevent+jwt', kid, ...header }));
    const p = b64(JSON.stringify(payload));
    const data = Buffer.from(`${h}.${p}`);
    let sig: Buffer;
    switch (k.alg) {
      case 'EdDSA':
        sig = sign(null, data, k.pair.privateKey);
        break;
      case 'RS256':
        sig = sign('sha256', data, k.pair.privateKey);
        break;
      case 'PS256':
        sig = sign('sha256', data, {
          key: k.pair.privateKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        });
        break;
      default:
        sig = sign('sha256', data, { key: k.pair.privateKey, dsaEncoding: 'ieee-p1363' });
    }
    return `${h}.${p}.${b64(sig)}`;
  }

  setClaims(event: string = EV.revoked, detail: Claims = {}): Claims {
    return {
      iss: this.url,
      jti: randomUUID(),
      iat: this.seconds(),
      aud: STREAM_AUD,
      sub_id: { format: 'opaque', id: AGENT },
      events: { [event]: { event_timestamp: this.seconds(), ...detail } },
    };
  }

  set({
    kid = 'ed1',
    header,
    claims,
    drop = [],
  }: { kid?: string; header?: Claims; claims?: Claims; drop?: string[] } = {}): string {
    const c = { ...(claims ?? this.setClaims()) };
    for (const d of drop) delete c[d];
    return this.sign(kid, header, c);
  }

  /** An access token as the platform mints it. */
  token(sub: string, iat: number, extra: Claims = {}): string {
    const payload = {
      iss: this.url,
      sub,
      aud: API_AUD,
      tenant_id: 't1',
      iat,
      exp: this.seconds() + 3600,
      ...extra,
    };
    return this.sign('ed1', { typ: 'at+jwt' }, payload);
  }
}

export const open: (() => void)[] = [];
/** Call once in a test file: closes every server the rigs opened. */
export function closeAfterEach(): void {
  afterEach(() => {
    while (open.length > 0) open.pop()?.();
  });
}

export interface Rig {
  issuer: Issuer;
  af: AuthFI;
  verifier: TokenVerifier;
  store: MemoryRevocationStore;
  signals: Signal[];
  logs: [string, string, unknown][];
  push: (
    body: string | undefined,
    headers?: Record<string, string>,
    method?: string,
  ) => Promise<{ status: number; text: string; headers: Headers }>;
  url: string;
  handler: (req: PushRequest, res: PushResponse) => Promise<void>;
}

export async function rig({
  store,
  receiver = {},
  verifier: verifierOptions = {},
}: {
  store?: MemoryRevocationStore;
  receiver?: Partial<ReceiverOptions>;
  verifier?: Partial<VerifierOptions>;
} = {}): Promise<Rig> {
  const issuer = await new Issuer().listen();
  const revocations = store ?? createRevocationStore({ clock: () => issuer.clock() });
  const signals: Signal[] = [];
  const logs: [string, string, unknown][] = [];
  const logger: Logger = {
    debug: () => undefined,
    info: (m, f) => logs.push(['info', m, f]),
    warn: (m, f) => logs.push(['warn', m, f]),
    error: (m, f) => logs.push(['error', m, f]),
  };
  const af = new AuthFI({ issuer: issuer.url, clock: issuer.sdkClock(), logger });
  const verifier = af.verifier({ audience: API_AUD, revocations, ...verifierOptions });
  const handler = createReceiver(af, {
    revocations,
    audience: STREAM_AUD,
    onSignal: (s) => {
      signals.push(s);
    },
    ...receiver,
  });
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}/ssf/push`;
  open.push(() => {
    server.closeAllConnections();
    server.close();
    issuer.close();
  });
  const push: Rig['push'] = (body, headers = {}, method = 'POST') =>
    fetch(url, {
      method,
      headers: { 'Content-Type': SECEVENT, ...headers },
      ...(method === 'POST' && body !== undefined ? { body } : {}),
    }).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }));
  return { issuer, af, verifier, store: revocations, signals, logs, push, url, handler };
}

export const err = (r: { text: string }): string => (JSON.parse(r.text) as { err: string }).err;

export async function refused(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(
    promise,
    (e: { code?: string; message?: string }) => e.code === code || e.message === code,
    `expected ${code}`,
  );
}

/** Starts a plain HTTP server for a test and closes it afterwards. */
export async function serve(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer(handler);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  open.push(() => {
    server.closeAllConnections();
    server.close();
  });
  return `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
}
