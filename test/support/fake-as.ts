// A fake authorization server faithful to the platform's agent routes: it checks every client
// assertion as the kernel does (signature with the registered key, aud, five-minute lifetime, kid,
// single-use jti), serves CIBA, token exchange without client authentication, the transaction token
// and gate, agent-configuration and approvals.

import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import type { AgentKey } from '../../src/agents/agent-key.js';
import { json, type Recorded } from './fake-fetch.js';
import { TestIssuer } from './issuer.js';

export const AGENT_ID = 'agt_test1';
export const CIBA = '/apis/regional/v1/ai/auth/backchannel-authorize';

export interface CibaState {
  answers: ('pending' | 'slow_down' | 'approve' | 'deny' | 'expire')[];
  redeemed: boolean;
}

export class FakeAS {
  readonly seenJti = new Set<string>();
  readonly assertions: { aud: unknown; exp: number; iat: number; jti: string; kid: string | undefined }[] =
    [];
  ciba: CibaState = { answers: ['approve'], redeemed: false };
  /** Answer for GET approvals/{id}: 403 (the platform today) or a status. */
  approvalStatus: 'forbidden' | 'pending' | 'approved' = 'forbidden';
  approvalPolls = 0;
  tokenLifetime = 900;
  minted = 0;
  exchangeAllowed = true;

  private constructor(
    readonly t: TestIssuer,
    readonly key: AgentKey,
  ) {}

  static async create(key: AgentKey): Promise<FakeAS> {
    const t = await TestIssuer.create();
    const as = new FakeAS(t, key);
    as.serve();
    return as;
  }

  get issuer(): string {
    return this.t.issuer;
  }

  async checkAssertion(form: URLSearchParams): Promise<string | undefined> {
    if (form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
      return 'invalid_client';
    const assertion = form.get('client_assertion') ?? '';
    const header = decodeProtectedHeader(assertion);
    if (header.kid !== this.key.kid) return 'invalid_client';
    const pub = await importJWK(this.key.publicJwk() as JWK, this.key.alg);
    try {
      const { payload } = await jwtVerify(assertion, pub, {
        issuer: AGENT_ID,
        subject: AGENT_ID,
        audience: `${this.issuer}/oauth/token`,
      });
      this.assertions.push({
        aud: payload.aud,
        exp: payload.exp!,
        iat: payload.iat!,
        jti: payload.jti!,
        kid: header.kid,
      });
      if (payload.exp! - payload.iat! > 300) return 'invalid_client';
      if (this.seenJti.has(payload.jti!)) return 'invalid_client';
      this.seenJti.add(payload.jti!);
    } catch {
      return 'invalid_client';
    }
    if (form.get('client_id') !== AGENT_ID) return 'invalid_client';
    return undefined;
  }

  async agentToken(claims: Record<string, unknown> = {}): Promise<string> {
    this.minted += 1;
    return this.t.sign(
      {
        sub: AGENT_ID,
        client_id: AGENT_ID,
        aud: `${this.issuer}/mcp`,
        scope: 'mcp:docs.read',
        n: this.minted,
        ...claims,
      },
      { alg: 'EdDSA' },
    );
  }

  serve(): void {
    const { fake } = this.t;
    const tokenUrl = `${this.issuer}/oauth/token`;
    fake.on('POST', tokenUrl, async (r: Recorded) => {
      const form = new URLSearchParams(r.body);
      const grant = form.get('grant_type');
      if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
        if (form.has('client_id') || form.has('client_assertion'))
          return json({ error: 'invalid_client', error_description: 'routed to agent-identity' }, 401);
        if (!this.exchangeAllowed) return json({ error: 'access_denied' }, 403);
        const actor = form.get('actor_token') ?? '';
        if (!actor.startsWith('eyJ')) return json({ error: 'invalid_grant' }, 400);
        return json({
          access_token: await this.t.sign({
            sub: 'usr_9',
            act: { sub: AGENT_ID },
            client_id: AGENT_ID,
            aud: [form.get('resource') ?? `${this.issuer}/mcp`],
          }),
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: this.tokenLifetime,
          scope: form.get('scope') ?? 'mcp:docs.read',
        });
      }
      const refusal = await this.checkAssertion(form);
      if (refusal !== undefined) return json({ error: refusal }, 401);
      if (grant === 'client_credentials') {
        return json({
          access_token: await this.agentToken(form.has('resource') ? { aud: form.get('resource') } : {}),
          token_type: 'Bearer',
          expires_in: this.tokenLifetime,
          scope: 'mcp:docs.read',
          capabilities: ['mcp:docs.read', 'mcp:docs.write'],
        });
      }
      if (grant === 'urn:openid:params:grant-type:ciba') {
        if (form.get('auth_req_id') !== 'req-1') return json({ error: 'invalid_grant' }, 400);
        if (this.ciba.redeemed)
          return json({ error: 'invalid_grant', error_description: 'already redeemed' }, 400);
        const next = this.ciba.answers.shift() ?? 'pending';
        if (next === 'pending') return json({ error: 'authorization_pending' }, 400);
        if (next === 'slow_down') return json({ error: 'slow_down' }, 400);
        if (next === 'deny') return json({ error: 'access_denied' }, 403);
        if (next === 'expire') return json({ error: 'expired_token' }, 400);
        this.ciba.redeemed = true;
        return json({
          access_token: await this.t.sign(
            {
              sub: 'user:usr_9',
              act: { sub: `agent:${AGENT_ID}` },
              client_id: AGENT_ID,
              aud: `${this.issuer}/mcp`,
              scope: 'mcp:refunds.create',
            },
            { alg: 'EdDSA' },
          ),
          token_type: 'Bearer',
          expires_in: this.tokenLifetime,
        });
      }
      return json({ error: 'unsupported_grant_type' }, 400);
    });
    fake.on('POST', `${this.issuer}${CIBA}`, async (r) => {
      const form = new URLSearchParams(r.body);
      const refusal = await this.checkAssertion(form);
      if (refusal !== undefined) return json({ error: refusal }, 401);
      if (!form.get('binding_message')) return json({ error: 'invalid_request' }, 400);
      return json({ auth_req_id: 'req-1', expires_in: 120, interval: 2 });
    });
    fake.on('GET', `${this.issuer}/.well-known/agent-configuration`, () =>
      json({
        issuer: this.issuer,
        endpoints: {
          request_approval: `${this.issuer}/apis/regional/v1/ai/auth/request-approval`,
          approval: `${this.issuer}/apis/regional/v1/ai/auth/approvals/{id}`,
          token: `${this.issuer}/apis/regional/v1/ai/auth/token`,
        },
      }),
    );
    fake.on('POST', `${this.issuer}/apis/regional/v1/ai/auth/request-approval`, async (r) => {
      const body = JSON.parse(r.body) as Record<string, string>;
      const form = new URLSearchParams({
        client_id: body.agent_id ?? '',
        client_assertion_type: body.client_assertion_type ?? '',
        client_assertion: body.client_assertion ?? '',
      });
      const refusal = await this.checkAssertion(form);
      if (refusal !== undefined) return json({ error: 'unauthorized' }, 401);
      return json(
        {
          data: {
            approval_id: 'apr-1',
            status: 'pending',
            requesting_action: body.requesting_action,
            context: body.context,
            created_at: '2026-10-20T10:00:00Z',
            expires_at: '2026-10-20T10:05:00Z',
          },
        },
        202,
      );
    });
    fake.on(
      'GET',
      (u) => u.startsWith(`${this.issuer}/apis/regional/v1/ai/auth/approvals/`),
      (r) => {
        this.approvalPolls += 1;
        if (!r.headers.get('authorization')?.startsWith('Bearer '))
          return json({ error: 'unauthorized' }, 401);
        if (this.approvalStatus === 'forbidden') return json({ error: 'forbidden' }, 403);
        const status = this.approvalStatus === 'approved' && this.approvalPolls >= 2 ? 'approved' : 'pending';
        return json({
          data: {
            approval_id: 'apr-1',
            status,
            requesting_action: 'refund',
            resolved_at: status === 'approved' ? '2026-10-20T10:01:00Z' : undefined,
          },
        });
      },
    );
    fake.on('POST', `${this.issuer}/apis/regional/v1/ai/auth/transaction-token`, (r) => {
      if (!r.headers.get('authorization')?.startsWith('Bearer eyJ'))
        return json({ error: 'unauthorized' }, 401);
      const body = JSON.parse(r.body) as { action?: string };
      if (!body.action) return json({ error: 'invalid_body' }, 400);
      return json({
        data: {
          transaction_token: `txn-token-for-${body.action}`,
          txn: 'txn-1',
          token_type: 'N_A',
          expires_in: 60,
        },
      });
    });
    fake.on('POST', `${this.issuer}/apis/regional/v1/ai/auth/authorize`, (r) => {
      const body = JSON.parse(r.body) as { transaction_token?: string; action?: string; agent_id?: string };
      if (body.transaction_token !== `txn-token-for-${body.action}`)
        return json({ data: { decision: 'deny', reason: 'mismatch' } });
      if (body.action === 'refund.large')
        return json({ data: { decision: 'approval_required', approval_id: 'apr-9' } });
      return json({ data: { decision: 'allow', approval_id: '', reason: '' } });
    });
  }
}
