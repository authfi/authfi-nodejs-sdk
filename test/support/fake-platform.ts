// A fake platform faithful to the agent doors that bind to a key. It re-derives every check from the
// bytes of the request, as the platform does: a DPoP proof's `typ`, algorithm, key, `htm`, `htu`, `iat`,
// single-use `jti`, `ath` and server nonce; the client assertion of an agent key; an instance
// attestation (its `typ`, signature, `cnf`, lifetime), its proof of possession and the DPoP key that must
// equal `cnf`; a mandate's actor assertion (its `cnf.jkt` must equal the request's proof key); a bound
// token sent as Bearer is refused. It serves the token endpoint, the gateway, the cloud door by handle and
// the attest routes, and shares none of the older fakes' code.

import { createHash, randomBytes } from 'node:crypto';
import {
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from 'jose';
import { AgentKey } from '../../src/agents/agent-key.js';
import type { Clock } from '../../src/core/clock.js';
import { json, type Recorded } from './fake-fetch.js';
import { TestIssuer } from './issuer.js';

export const AGENT = 'agt_plat1';
export const CONFIG = { version: 7, digest: `sha256:${'a'.repeat(64)}` };

const b64 = (b: Buffer | Uint8Array): string => Buffer.from(b).toString('base64url');
const sha = (s: string): string => b64(createHash('sha256').update(s).digest());

export type Surface = 'token' | 'gateway' | 'cloud';

interface Handle {
  jkt: string;
  readonly expires: number;
  spent: boolean;
}

/** The AI gateway's model routes. */
const MODEL_ROUTE = /^\/mcp\/v1\/(messages|chat\/completions|responses)$/;

export class FakePlatform {
  readonly seen = new Set<string>();
  /** Each refusal's reason, which the real attest route keeps for the audit tape only. */
  readonly refusals: string[] = [];
  /** The gateway's MCP_MODEL_PROOF_CHECK=enforce: a model call whose token is bound to nothing is refused (EMODEL020). */
  modelProof = false;
  /** The path of each model call refused for its holder. */
  readonly unprovenModelCalls: string[] = [];
  /** The DPoP nonce each surface demands; undefined demands none. */
  nonce: Partial<Record<Surface, string>> = {};
  /** Hand a token out Bearer even when a proof was sent (a project that does not bind). */
  bind = true;
  /** Bind tokens to this thumbprint instead of the proof's key. */
  bindTo: string | undefined;
  /** A new nonce after each challenge: a server that keeps asking. */
  rotate = false;
  tokenLifetime = 900;
  attestLifetime = 900;
  attestations = 0;
  mints = 0;
  /** What the attestation's claims are changed to, for the client-side checks. */
  tamper: ((claims: Record<string, unknown>) => void) | undefined;
  ended = new Set<string>();
  cibaScript: ('pending' | 'slow_down' | 'approve' | 'deny' | 'expire')[] = ['approve'];
  mandateScript: ('pending' | 'approve' | 'deny' | 'expire')[] = ['approve'];
  readonly handles = new Map<string, Handle>();
  readonly calls: { name: string; mandate: string | undefined; authorization: string | null }[] = [];
  devices = new Map<string, JWK>();
  private readonly challenges = new Map<string, number>();
  private attestPrivate!: CryptoKey;
  attestPublic!: JWK;

  private constructor(
    readonly t: TestIssuer,
    readonly agentKey: AgentKey,
    readonly clock: Clock,
  ) {}

  static async create(clock: Clock, agentKey?: AgentKey): Promise<FakePlatform> {
    const t = await TestIssuer.create();
    t.metadataExtra = { dpop_signing_alg_values_supported: ['ES256', 'EdDSA'] };
    const p = new FakePlatform(t, agentKey ?? (await AgentKey.generate('ES256')), clock);
    const pair = await generateKeyPair('EdDSA', { extractable: true });
    p.attestPrivate = pair.privateKey;
    p.attestPublic = { ...(await exportJWK(pair.publicKey)), kid: 'attest-1', alg: 'EdDSA' };
    p.serve();
    return p;
  }

  get issuer(): string {
    return this.t.issuer;
  }

  get origin(): string {
    return new URL(this.t.issuer).origin;
  }

  get fetch(): typeof fetch {
    return this.t.fake.fetch;
  }

  private now(): number {
    return Math.floor(this.clock.now() / 1000);
  }

  private once(key: string): boolean {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }

  // --- DPoP --------------------------------------------------------------------------------

  /** A bound token's proof, checked as the kernel does; the proof key's thumbprint, or the refusal. */
  async proof(r: Recorded, surface: Surface, token?: string): Promise<{ jkt: string } | Response> {
    const refuse = (error: string, description: string, nonce?: string): Response => {
      const wire = surface === 'token' ? 400 : 401;
      const headers: Record<string, string> = nonce === undefined ? {} : { 'dpop-nonce': nonce };
      if (surface !== 'token') headers['www-authenticate'] = `DPoP error="${error}"`;
      this.refusals.push(`${surface}:${error}:${description}`);
      if (nonce !== undefined && this.rotate) this.nonce[surface] = b64(randomBytes(8));
      return json({ error, error_description: description }, wire, headers);
    };
    const proofs = r.headers.get('dpop');
    if (proofs === null) return refuse('invalid_dpop_proof', 'no proof');
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(proofs);
    } catch {
      return refuse('invalid_dpop_proof', 'not a JWT');
    }
    if (header.typ !== 'dpop+jwt') return refuse('invalid_dpop_proof', 'typ');
    if (header.alg !== 'ES256' || header.jwk?.kty !== 'EC') return refuse('invalid_dpop_proof', 'alg or key');
    if ('d' in header.jwk) return refuse('invalid_dpop_proof', 'private key in header');
    let claims: Record<string, unknown>;
    try {
      const key = await importJWK(header.jwk, 'ES256');
      ({ payload: claims } = await jwtVerify(proofs, key, { algorithms: ['ES256'], typ: 'dpop+jwt' }));
    } catch {
      return refuse('invalid_dpop_proof', 'signature');
    }
    if (claims.htm !== r.method) return refuse('invalid_dpop_proof', 'htm');
    const url = new URL(r.url);
    if (claims.htu !== `${url.origin}${url.pathname}`) return refuse('invalid_dpop_proof', 'htu');
    const iat = claims.iat;
    if (typeof iat !== 'number' || Math.abs(iat - this.now()) > 60)
      return refuse('invalid_dpop_proof', 'iat');
    if (token !== undefined && claims.ath !== sha(token)) return refuse('invalid_dpop_proof', 'ath');
    const wanted = this.nonce[surface];
    if (wanted !== undefined && claims.nonce !== wanted) return refuse('use_dpop_nonce', 'nonce', wanted);
    if (typeof claims.jti !== 'string' || !this.once(`dpop:${claims.jti}`))
      return refuse('invalid_dpop_proof', 'jti replayed');
    return { jkt: await calculateJwkThumbprint(header.jwk) };
  }

  /** The gateway's door: `DPoP` scheme and a proof for a bound token, Bearer refused, and the claims. */
  private async door(
    r: Recorded,
    surface: Surface,
  ): Promise<{ claims: Record<string, unknown>; jkt: string | undefined; token: string } | Response> {
    const auth = r.headers.get('authorization') ?? '';
    const m = /^(Bearer|DPoP) (\S+)$/.exec(auth);
    const unauthorized = (why: string): Response => {
      this.refusals.push(`${surface}:${why}`);
      return json({ error: 'invalid_token', error_description: why }, 401);
    };
    if (m === null) return unauthorized('no credential');
    const [, scheme, token] = m as unknown as [string, string, string];
    let claims: Record<string, unknown>;
    try {
      claims = decodeJwt(token);
    } catch {
      return unauthorized('not a token');
    }
    const cnf = claims.cnf as { jkt?: string } | undefined;
    if (cnf?.jkt === undefined) {
      if (scheme !== 'Bearer') return unauthorized('an unbound token is Bearer');
      return { claims, jkt: undefined, token };
    }
    if (scheme !== 'DPoP') return unauthorized('a bound token is not Bearer');
    const proved = await this.proof(r, surface, token);
    if (proved instanceof Response) return proved;
    if (proved.jkt !== cnf.jkt) return unauthorized('the proof is not of the key the token is bound to');
    return { claims, jkt: proved.jkt, token };
  }

  // --- tokens ------------------------------------------------------------------------------

  private async access(claims: Record<string, unknown>, jkt: string | undefined): Promise<Response> {
    this.mints += 1;
    const token = await this.t.sign(
      {
        sub: AGENT,
        client_id: AGENT,
        aud: `${this.issuer}/mcp`,
        scope: 'mcp:docs.read',
        n: this.mints,
        ...(jkt === undefined || !this.bind ? {} : { cnf: { jkt: this.bindTo ?? jkt } }),
        ...claims,
      },
      { nowSeconds: this.now() },
    );
    return json({
      access_token: token,
      token_type: jkt !== undefined && this.bind ? 'DPoP' : 'Bearer',
      expires_in: this.tokenLifetime,
      scope: 'mcp:docs.read',
      ...(claims.authorization_details === undefined
        ? { capabilities: ['mcp:docs.read'] }
        : { authorization_details: claims.authorization_details }),
    });
  }

  private async clientAssertion(form: URLSearchParams): Promise<boolean> {
    const assertion = form.get('client_assertion') ?? '';
    try {
      const key = await importJWK(this.agentKey.publicJwk() as JWK, this.agentKey.alg);
      const { payload } = await jwtVerify(assertion, key, {
        issuer: AGENT,
        subject: AGENT,
        audience: `${this.issuer}/oauth/token`,
        currentDate: new Date(this.clock.now()),
      });
      return (
        payload.exp! - payload.iat! <= 300 &&
        form.get('client_id') === AGENT &&
        this.once(`jti:${payload.jti}`)
      );
    } catch {
      return false;
    }
  }

  private async token(r: Recorded): Promise<Response> {
    const form = new URLSearchParams(r.body);
    const grant = form.get('grant_type');
    // A proof, when the request carries one, is checked at the token endpoint (with its nonce).
    let jkt: string | undefined;
    if (r.headers.has('dpop')) {
      const proved = await this.proof(r, 'token');
      if (proved instanceof Response) return proved;
      jkt = proved.jkt;
    }
    if (grant === 'client_credentials' && r.headers.has('oauth-client-attestation')) {
      return this.attested(r, form, jkt);
    }
    if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') return this.exchange(form, jkt);
    if (!(await this.clientAssertion(form))) return json({ error: 'invalid_client' }, 401);
    if (grant === 'client_credentials') {
      return this.access(form.has('resource') ? { aud: form.get('resource') } : {}, jkt);
    }
    if (grant === 'urn:openid:params:grant-type:ciba') return this.poll(form, jkt);
    return json({ error: 'unsupported_grant_type' }, 400);
  }

  private async poll(form: URLSearchParams, jkt: string | undefined): Promise<Response> {
    const id = form.get('auth_req_id');
    const mandate = id === 'mreq-1';
    if (id !== 'req-1' && !mandate) return json({ error: 'invalid_grant' }, 400);
    const script = mandate ? this.mandateScript : this.cibaScript;
    const next = script.shift() ?? 'pending';
    if (next === 'pending') return json({ error: 'authorization_pending' }, 400);
    if (next === 'slow_down') return json({ error: 'slow_down' }, 400);
    if (next === 'deny') return json({ error: 'access_denied' }, 403);
    if (next === 'expire') return json({ error: 'expired_token' }, 400);
    if (mandate) {
      if (jkt === undefined)
        return json({ error: 'invalid_request', error_description: 'a mandate needs a key' }, 400);
      return this.access(mandateClaims(), jkt);
    }
    return this.access(
      { sub: 'user:usr_9', act: { sub: `agent:${AGENT}` }, scope: 'mcp:refunds.create' },
      jkt,
    );
  }

  private async exchange(form: URLSearchParams, jkt: string | undefined): Promise<Response> {
    if (form.has('client_id') || form.has('client_assertion'))
      return json({ error: 'invalid_client', error_description: 'routed to agent-identity' }, 401);
    const details = form.get('authorization_details');
    const actor = form.get('actor_token') ?? '';
    if (details !== null) return this.startMandate(form, details, actor, jkt);
    if (!actor.startsWith('eyJ')) return json({ error: 'invalid_grant' }, 400);
    return this.access(
      { sub: 'usr_9', act: { sub: AGENT }, aud: [form.get('resource') ?? `${this.issuer}/mcp`] },
      jkt,
    );
  }

  private async startMandate(
    form: URLSearchParams,
    details: string,
    actor: string,
    jkt: string | undefined,
  ): Promise<Response> {
    if (jkt === undefined)
      return json({ error: 'invalid_request', error_description: 'a mandate needs a key' }, 400);
    try {
      const key = await importJWK(this.agentKey.publicJwk() as JWK, this.agentKey.alg);
      const { payload } = await jwtVerify(actor, key, {
        issuer: AGENT,
        audience: `${this.issuer}/oauth/token`,
        currentDate: new Date(this.clock.now()),
      });
      if ((payload.cnf as { jkt?: string } | undefined)?.jkt !== jkt) {
        this.refusals.push('mandate:actor not bound to the proof key');
        return json(
          { error: 'invalid_grant', error_description: 'the actor assertion names another key' },
          400,
        );
      }
      if (!this.once(`jti:${payload.jti}`)) return json({ error: 'invalid_grant' }, 400);
    } catch {
      return json({ error: 'invalid_grant', error_description: 'actor assertion' }, 400);
    }
    if (form.get('actor_token_type') !== 'urn:ietf:params:oauth:token-type:jwt')
      return json({ error: 'invalid_request' }, 400);
    const [entry] = JSON.parse(details) as { type: string; template: string }[];
    if (entry?.type !== 'authfi_mandate') return json({ error: 'invalid_request' }, 400);
    if (entry.template === 'not.allowed') return json({ error: 'access_denied' }, 403);
    if (entry.template === 'needs.approval') {
      return json(
        {
          error: 'authorization_pending',
          auth_req_id: 'mreq-1',
          authfi_mandate_id: 'mnd_2',
          approval_url: `${this.issuer}/approve/mnd_2`,
          interval: 1,
        },
        400,
      );
    }
    return this.access(mandateClaims(), jkt);
  }

  // --- instance sign-in -------------------------------------------------------------------------

  private async attested(r: Recorded, form: URLSearchParams, jkt: string | undefined): Promise<Response> {
    const refuse = (why: string): Response => {
      this.refusals.push(`attested:${why}`);
      return json({ error: 'invalid_client', error_description: why }, 401);
    };
    const attestation = r.headers.get('oauth-client-attestation') ?? '';
    const pop = r.headers.get('oauth-client-attestation-pop') ?? '';
    let claims: Record<string, unknown>;
    try {
      const key = await importJWK(this.attestPublic, 'EdDSA');
      const verified = await jwtVerify(attestation, key, {
        algorithms: ['EdDSA'],
        typ: 'oauth-client-attestation+jwt',
        currentDate: new Date(this.clock.now()),
      });
      claims = verified.payload;
    } catch {
      return refuse('attestation');
    }
    if (claims.sub !== form.get('client_id')) return refuse('client_id is not the attested agent');
    const cnf = (claims.cnf as { jwk?: JWK } | undefined)?.jwk;
    if (cnf === undefined) return refuse('no cnf');
    try {
      const key = await importJWK(cnf, 'ES256');
      const { payload } = await jwtVerify(pop, key, {
        algorithms: ['ES256'],
        typ: 'oauth-client-attestation-pop+jwt',
        issuer: String(claims.sub),
        audience: this.issuer,
        currentDate: new Date(this.clock.now()),
      });
      if (payload.exp! - payload.iat! > 60) return refuse('pop lifetime');
      if (!this.once(`pop:${payload.jti}`)) return refuse('pop replayed');
    } catch {
      return refuse('pop');
    }
    if (jkt === undefined || jkt !== (await calculateJwkThumbprint(cnf)))
      return refuse('the DPoP key is not the attested key');
    const instance = (claims.authfi_instance as { instance_id?: string }).instance_id;
    return this.access({ instance_id: instance, config_version: CONFIG.version }, jkt);
  }

  private async attest(r: Recorded): Promise<Response> {
    const refuse = (why: string): Response => {
      this.refusals.push(`attest:${why}`);
      return json({ error: 'unauthorized' }, 401);
    };
    const body = JSON.parse(r.body) as {
      agent_id?: string;
      evidence?: { kind?: string; token?: string };
      instance_key?: JWK;
      config?: { version?: number; digest?: string };
      image_digest?: string;
      proof?: string;
      [k: string]: unknown;
    };
    const known = ['agent_id', 'evidence', 'instance_key', 'config', 'image_digest', 'proof'];
    if (Object.keys(body).some((k) => !known.includes(k))) return json({ error: 'invalid_body' }, 400);
    if (body.agent_id !== AGENT || body.instance_key === undefined || body.proof === undefined)
      return refuse('agent or key');
    let proof: Record<string, unknown>;
    try {
      const key = await importJWK(body.instance_key, 'ES256');
      ({ payload: proof } = await jwtVerify(body.proof, key, {
        algorithms: ['ES256'],
        typ: 'authfi-instance-proof+jwt',
        currentDate: new Date(this.clock.now()),
      }));
    } catch {
      return refuse('proof');
    }
    const issuedAt = this.challenges.get(String(proof.nonce));
    if (issuedAt === undefined || this.clock.now() - issuedAt > 60_000) return refuse('nonce');
    this.challenges.delete(String(proof.nonce));
    if (proof.agent_id !== AGENT || proof.aud !== this.issuer) return refuse('proof claims');
    if (body.config?.version !== CONFIG.version || body.config.digest !== CONFIG.digest)
      return refuse('config_not_approved');
    if (body.image_digest !== undefined && !/^sha256:[0-9a-f]{64}$/.test(body.image_digest))
      return refuse('image digest');
    const evidence = body.evidence;
    if (evidence?.kind === 'k8s') {
      let sa: Record<string, unknown>;
      try {
        sa = decodeJwt(evidence.token ?? '');
      } catch {
        return refuse('evidence');
      }
      const aud = Array.isArray(sa.aud) ? sa.aud : [sa.aud];
      if (!aud.includes(this.origin) && !aud.includes(this.issuer)) return refuse('evidence audience');
      if (!this.once(`sa:${String(sa.jti)}`)) return refuse('evidence replayed');
    } else if (evidence?.kind === 'device') {
      const device = this.devices.get('device-1');
      if (device === undefined) return refuse('no device');
      const thumbprint = await calculateJwkThumbprint(body.instance_key);
      const message = `authfi-agent-attest\n${String(proof.nonce)}\n${AGENT}\n${thumbprint}`;
      const { verify } = await import('node:crypto');
      const { createPublicKey } = await import('node:crypto');
      const ok = verify(
        null,
        Buffer.from(message),
        createPublicKey({ key: device as never, format: 'jwk' }),
        Buffer.from(evidence.token ?? '', 'base64url'),
      );
      if (!ok) return refuse('device signature');
    } else {
      return refuse('evidence kind');
    }
    this.attestations += 1;
    const iat = this.now();
    const claims: Record<string, unknown> = {
      iss: `spiffe://${new URL(this.issuer).host}/ai/agent/${AGENT}`,
      sub: AGENT,
      iat,
      exp: iat + this.attestLifetime,
      jti: crypto.randomUUID(),
      cnf: { jwk: body.instance_key },
      authfi_instance: {
        instance_id: `inst_${randomBytes(16).toString('hex')}`,
        config: CONFIG,
        custody: 'software',
        environment: 'np',
      },
    };
    this.tamper?.(claims);
    const attestation = await new SignJWT(claims)
      .setProtectedHeader({ typ: 'oauth-client-attestation+jwt', alg: 'EdDSA', kid: 'attest-1' })
      .sign(this.attestPrivate);
    return json({ attestation, expires_in: this.attestLifetime });
  }

  // --- the gateway -------------------------------------------------------------------------------

  private async mcp(r: Recorded): Promise<Response> {
    const seen = await this.door(r, 'gateway');
    if (seen instanceof Response) return seen;
    const path = new URL(r.url).pathname;
    if (this.modelProof && MODEL_ROUTE.test(path) && seen.jkt === undefined) {
      this.unprovenModelCalls.push(path);
      return json({ error: { type: 'permission_error', code: 'EMODEL020', message: 'unproven' } }, 403);
    }
    const rpc = JSON.parse(r.body || '{}') as {
      id?: number;
      method?: string;
      params?: { name?: string; arguments?: Record<string, unknown> };
    };
    if (rpc.method === 'tools/call') {
      const name = rpc.params?.name ?? '';
      const mandate = seen.claims.mandate_id as string | undefined;
      this.calls.push({ name, mandate, authorization: r.headers.get('authorization') });
      const refused = (code: string, reason: string) =>
        json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            isError: true,
            content: [{ type: 'text', text: `gateway text for ${code}` }],
            _meta: {
              'io.authfi/refusal': { code, reason, error: 'refused' },
              'io.authfi/decision': { mandate_id: mandate },
            },
          },
        });
      if (mandate !== undefined) {
        if (this.ended.has(mandate)) return refused('EMDT004', 'the mandate has ended');
        const tools = seen.claims.mandate_tools as string[];
        if (!tools.includes(name)) return refused('EMDT005', `${name} is outside the mandate`);
        const amount = Number(rpc.params?.arguments?.amount ?? 0);
        if (amount > 5000) return refused('EMDT006', 'over the budget');
      }
      return json({
        jsonrpc: '2.0',
        id: rpc.id,
        result: { content: [{ type: 'text', text: `ran ${name}` }] },
      });
    }
    return json({ jsonrpc: '2.0', id: rpc.id, result: { tools: [] } });
  }

  private async cloud(r: Recorded): Promise<Response> {
    const seen = await this.door(r, 'cloud');
    if (seen instanceof Response) return seen;
    const id = `cred_${this.handles.size + 1}`;
    this.handles.set(id, {
      jkt: seen.jkt ?? '',
      expires: this.clock.now() + 900_000,
      spent: false,
    });
    return json(
      {
        data: {
          credential_id: id,
          account: 'acct',
          role: 'reader',
          expires_at: new Date(this.clock.now() + 900_000).toISOString(),
          scope: 'cloud.credentials',
        },
      },
      201,
    );
  }

  private async secret(r: Recorded): Promise<Response> {
    const seen = await this.door(r, 'cloud');
    if (seen instanceof Response) return seen;
    const id = new URL(r.url).pathname.split('/').at(-2) ?? '';
    const handle = this.handles.get(id);
    const err = (code: string, status: number) => json({ error: code, error_description: code }, status);
    if (handle === undefined) return err('ECLOUDCRED013', 404);
    if (seen.jkt === undefined || seen.jkt !== handle.jkt) return err('ECLOUDCRED012', 403);
    if (handle.spent) return err('ECLOUDCRED014', 409);
    if (this.clock.now() >= handle.expires) return err('ECLOUDCRED015', 410);
    handle.spent = true;
    return json({
      data: {
        provider: 'aws',
        credential_id: id,
        access_key_id: 'AKIAFAKEFAKEFAKE1234',
        secret_access_key: 'the-secret-key',
        session_token: 'the-session-token',
        expiration: new Date(handle.expires).toISOString(),
      },
    });
  }

  serve(): void {
    const { fake } = this.t;
    fake.on('POST', `${this.issuer}/oauth/token`, (r) => this.token(r));
    fake.on('POST', `${this.issuer}/apis/regional/v1/ai/auth/backchannel-authorize`, async (r) => {
      const form = new URLSearchParams(r.body);
      if (!(await this.clientAssertion(form))) return json({ error: 'invalid_client' }, 401);
      return json({ auth_req_id: 'req-1', expires_in: 120, interval: 2 });
    });
    fake.on('POST', `${this.issuer}/mcp`, (r) => this.mcp(r));
    fake.on('POST', `${this.issuer}/mcp/v1/messages`, (r) => this.mcp(r));
    fake.on('POST', `${this.issuer}/mcp/v1/chat/completions`, (r) => this.mcp(r));
    fake.on('POST', `${this.issuer}/mcp/v1/responses`, (r) => this.mcp(r));
    fake.on('POST', `${this.origin}/mcp/v1/cloud/credentials`, (r) => this.cloud(r));
    fake.on(
      'POST',
      (u) => /\/mcp\/v1\/cloud\/credentials\/[^/]+\/secret$/.test(u),
      (r) => this.secret(r),
    );
    fake.on('POST', `${this.origin}/apis/regional/v1/ai/agents/attest/challenge`, () => {
      const nonce = b64(randomBytes(18));
      this.challenges.set(nonce, this.clock.now());
      return json({ nonce });
    });
    fake.on('POST', `${this.origin}/apis/regional/v1/ai/agents/attest`, (r) => this.attest(r));
  }
}

function mandateClaims(): Record<string, unknown> {
  return {
    sub: 'usr_9',
    act: { sub: AGENT },
    mandate_id: 'mnd_1',
    mandate_tools: ['billing__refund'],
    authorization_details: [
      {
        type: 'authfi_mandate',
        mandate_id: 'mnd_1',
        template: 'support.refund@3',
        tools: ['billing__refund'],
        budgets: { spend: 5000 },
      },
    ],
  };
}
