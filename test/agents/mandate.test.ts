import { describe, expect, it } from 'vitest';
import { decodeJwt } from 'jose';
import { Mandate } from '../../src/agents/mandate.js';
import { HoldGuard, RunGateway, textOf } from '../../src/adapters/shared.js';
import { call, person, platform } from '../support/platform-setup.js';

const mcp = (p: { issuer: string }) => `${p.issuer}/mcp`;

async function held() {
  const s = await platform();
  const mandate = await s.agent.mandate('support.refund', {
    subjectToken: await person(s.p, s.clock),
    params: { order: '4411' },
  });
  return { ...s, mandate };
}

async function result(res: Response) {
  return ((await res.json()) as { result: { isError?: boolean; content: { text: string }[] } }).result;
}

describe('a mandate is the authority for one job, held by the key', () => {
  it('starts as a token exchange whose actor assertion names the key that holds it', async () => {
    const { mandate, agent, p } = await held();
    expect(mandate).toBeInstanceOf(Mandate);
    expect(mandate.mandateId).toBe('mnd_1');
    expect(mandate.template).toBe('support.refund@3');
    expect(mandate.tools).toEqual(['billing__refund']);
    expect(mandate.budgets).toEqual({ spend: 5000 });
    await agent.token();
    expect(decodeJwt(await mandate.token()).cnf).toEqual({ jkt: agent.dpop!.thumbprint });
    const start = p.t.fake
      .to(`${p.issuer}/oauth/token`)
      .find((r) => r.body.includes('authorization_details'))!;
    const form = new URLSearchParams(start.body);
    expect(form.has('client_id')).toBe(false);
    expect(form.has('client_assertion')).toBe(false);
    expect(JSON.parse(form.get('authorization_details')!)).toEqual([
      { type: 'authfi_mandate', template: 'support.refund', params: { order: '4411' } },
    ]);
    expect(start.headers.get('dpop')).toMatch(/^eyJ/);
    expect(p.refusals).toEqual([]);
  });

  it('holds each call to it: the allowed tool runs, a tool outside it is refused with what to do next', async () => {
    const { mandate, p } = await held();
    const gateway = mandate.gateway();
    const ok = gateway.readResult(
      await result(
        await gateway.fetch(mcp(p), { method: 'POST', body: call('billing__refund', { amount: 10 }) }),
      ),
    );
    expect(ok.kind).toBe('allowed');
    const outside = gateway.readResult(
      await result(await gateway.fetch(mcp(p), { method: 'POST', body: call('admin__delete') })),
    );
    if (outside.kind !== 'refused') throw new Error('expected a refusal');
    expect(outside.why).toBe('outside_mandate');
    expect(outside.nextStep).toMatch(/outside the mandate you were given/);
    expect(outside.modelText).toContain('Refused by AuthFI (EMDT005)');
    expect(outside.modelText).toContain(outside.nextStep!);
    expect(outside.modelText).not.toMatch(/new mandate|wider|ask for more/i);
    // every call carried the mandate's token, proven by the key
    expect(p.calls.map((c) => c.mandate)).toEqual(['mnd_1', 'mnd_1']);
    expect(p.calls.every((c) => c.authorization?.startsWith('DPoP '))).toBe(true);
  });

  it('refuses a spend over its budget and an ended mandate, each with its own next step', async () => {
    const { mandate, p } = await held();
    const gateway = mandate.gateway();
    const over = gateway.readResult(
      await result(
        await gateway.fetch(mcp(p), { method: 'POST', body: call('billing__refund', { amount: 9000 }) }),
      ),
    );
    expect(over).toMatchObject({ kind: 'refused', why: 'over_budget' });
    p.ended.add('mnd_1');
    const ended = gateway.readResult(
      await result(await gateway.fetch(mcp(p), { method: 'POST', body: call('billing__refund') })),
    );
    expect(ended).toMatchObject({ kind: 'refused', why: 'mandate_ended' });
    if (ended.kind === 'refused') expect(ended.nextStep).toMatch(/Stop, and tell the person/);
  });

  it("says the same to the model in an adapter's answer", async () => {
    const { mandate, p } = await held();
    const run = new RunGateway({ source: mandate });
    const guard = new HoldGuard(run, async (key, input) =>
      result(await run.fetch(mcp(p), { method: 'POST', body: call(key, input as Record<string, unknown>) })),
    );
    const answer = await guard.answer('c1', 'admin__delete', {});
    expect(textOf(answer)).toContain('outside the mandate you were given');
    expect(textOf(answer)).not.toContain('gateway text for');
    expect(answer.isError).toBe(true);
  });

  it("does not swap the agent's own token in: a session opened before the mandate stays the agent's", async () => {
    const { mandate, agent, p } = await held();
    const before = agent.gateway();
    await before.fetch(mcp(p), { method: 'POST', body: call('admin__delete') });
    await mandate.gateway().fetch(mcp(p), { method: 'POST', body: call('billing__refund') });
    expect(p.calls.map((c) => c.mandate)).toEqual([undefined, 'mnd_1']);
  });

  it('forgets the credential when closed, and runs out with its deadline', async () => {
    const { mandate, clock, p } = await held();
    clock.advance(p.tokenLifetime * 1000 + 1);
    await expect(mandate.token()).rejects.toMatchObject({ name: 'ConsentExpired' });
    const fresh = await held();
    fresh.mandate.close();
    await expect(fresh.mandate.token()).rejects.toThrow(/mandate is closed/);
    await expect(
      fresh.mandate.gateway().fetch(mcp(fresh.p), { method: 'POST', body: call('billing__refund') }),
    ).rejects.toThrow(/closed/);
  });

  it('is never printed or serialised with its token', async () => {
    const { mandate } = await held();
    const token = await mandate.token();
    expect(String(mandate)).not.toContain(token);
    expect(JSON.stringify(mandate)).not.toContain(token);
    expect(JSON.stringify(mandate)).toContain('mnd_1');
  });
});

describe('a mandate a person must approve first', () => {
  async function pending() {
    const s = await platform();
    s.p.mandateScript = ['pending', 'approve'];
    const started = await s.agent.requestMandate('needs.approval', {
      subjectToken: await person(s.p, s.clock),
    });
    if (started instanceof Mandate) throw new Error('expected a pending mandate');
    return { ...s, started };
  }

  it('answers the link to show the person, then collects the mandate under the same key', async () => {
    const { started, agent } = await pending();
    expect(started.mandateId).toBe('mnd_2');
    expect(started.approvalUrl).toMatch(/\/approve\/mnd_2$/);
    expect(String(started.authReqId)).not.toContain('mreq-1');
    const mandate = await agent.awaitMandate(started);
    expect(mandate.mandateId).toBe('mnd_1');
  });

  it('a person who refuses, or lets it run out, ends the wait with the typed error', async () => {
    const denied = await pending();
    denied.p.mandateScript = ['deny'];
    await expect(denied.agent.awaitMandate(denied.started)).rejects.toMatchObject({ name: 'ConsentDenied' });
    const expired = await pending();
    expired.p.mandateScript = ['pending', 'expire'];
    await expect(expired.agent.awaitMandate(expired.started)).rejects.toMatchObject({
      name: 'ConsentExpired',
    });
  });

  it('a wait that outlasts the caller is a WaitTimeout, and waiting again continues the same request', async () => {
    const { agent, started, p } = await pending();
    p.mandateScript = ['pending', 'pending', 'pending', 'approve'];
    await expect(
      agent.awaitMandate(started, { timeoutMs: 1500, pollIntervalMs: 1000 }),
    ).rejects.toMatchObject({
      name: 'WaitTimeout',
    });
    p.mandateScript = ['approve'];
    expect((await agent.awaitMandate(started)).mandateId).toBe('mnd_1');
  });

  it('mandate() waits for the approval itself', async () => {
    const s = await platform();
    s.p.mandateScript = ['pending', 'approve'];
    const mandate = await s.agent.mandate('needs.approval', { subjectToken: await person(s.p, s.clock) });
    expect(mandate.mandateId).toBe('mnd_1');
  });
});

describe('a mandate is asked for correctly or not at all', () => {
  it('is refused for a template the agent may not use', async () => {
    const s = await platform();
    await expect(
      s.agent.requestMandate('not.allowed', { subjectToken: await person(s.p, s.clock) }),
    ).rejects.toMatchObject({ code: 'access_denied' });
  });

  it('is refused before anything is sent for a missing template, token or a bad lifetime or params', async () => {
    const s = await platform();
    const subjectToken = await person(s.p, s.clock);
    await expect(s.agent.requestMandate('', { subjectToken })).rejects.toThrow(/template is required/);
    await expect(s.agent.requestMandate('support.refund', { subjectToken: 'raw' as never })).rejects.toThrow(
      /subjectToken must be/,
    );
    await expect(
      s.agent.requestMandate('support.refund', { subjectToken, ttlSeconds: 31 * 86_400 }),
    ).rejects.toThrow(/ttlSeconds/);
    await expect(s.agent.requestMandate('support.refund', { subjectToken, ttlSeconds: 0 })).rejects.toThrow(
      /ttlSeconds/,
    );
    await expect(
      s.agent.requestMandate('support.refund', { subjectToken, params: { n: 1n } }),
    ).rejects.toThrow(/params must be JSON/);
    expect(s.p.t.fake.to(`${s.p.issuer}/oauth/token`)).toHaveLength(0);
  });

  it('a platform that answers a mandate no key holds, or a held request with nothing to wait on, is refused', async () => {
    const s = await platform();
    s.p.bind = false;
    await expect(
      s.agent.requestMandate('support.refund', { subjectToken: await person(s.p, s.clock) }),
    ).rejects.toMatchObject({ code: 'invalid_response' });
    const t = await platform();
    t.fake.on(
      'POST',
      `${t.p.issuer}/oauth/token`,
      () => new Response(JSON.stringify({ error: 'authorization_pending' }), { status: 400 }),
    );
    await expect(
      t.agent.requestMandate('support.refund', { subjectToken: await person(t.p, t.clock) }),
    ).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('a mandate whose answer lacks its authorization_details is refused', async () => {
    const s = await platform();
    await s.agent.token();
    const jkt = s.agent.dpop!.thumbprint;
    s.fake.on('POST', `${s.p.issuer}/oauth/token`, async (r) =>
      r.body.includes('authorization_details') && !r.body.includes('client_assertion')
        ? new Response(
            JSON.stringify({
              access_token: await s.p.t.sign({
                cnf: { jkt },
              }),
              token_type: 'DPoP',
              expires_in: 300,
            }),
            { headers: { 'content-type': 'application/json' } },
          )
        : new Response('{}', { status: 400 }),
    );
    await expect(
      s.agent.requestMandate('support.refund', { subjectToken: await person(s.p, s.clock) }),
    ).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('cannot be off DPoP: a mandate is held by a key', async () => {
    const s = await platform();
    const agent = s.af.agent({ agentId: 'agt_plat1', key: s.key, dpop: false });
    await expect(
      agent.requestMandate('support.refund', { subjectToken: await person(s.p, s.clock) }),
    ).rejects.toThrow(/dpop cannot be off/);
  });

  it('cannot be had from a project that accepts no key this SDK holds', async () => {
    const s = await platform();
    s.p.t.metadataExtra = { dpop_signing_alg_values_supported: ['EdDSA'] };
    await expect(
      s.agent.requestMandate('support.refund', { subjectToken: await person(s.p, s.clock) }),
    ).rejects.toMatchObject({ name: 'NotSupportedError', feature: 'dpop' });
  });
});

describe('a mandate is one level deep', () => {
  it('withMandate hands the mandate to the work and forgets it after, however the work ends', async () => {
    const s = await platform();
    const subjectToken = await person(s.p, s.clock);
    let seen: Mandate | undefined;
    const answer = await s.agent.withMandate('support.refund', { subjectToken }, (m) => {
      seen = m;
      return 'done';
    });
    expect(answer).toBe('done');
    await expect(seen!.token()).rejects.toThrow(/closed/);
    let again: Mandate | undefined;
    await expect(
      s.agent.withMandate('support.refund', { subjectToken }, (m) => {
        again = m;
        throw new Error('the work failed');
      }),
    ).rejects.toThrow('the work failed');
    await expect(again!.token()).rejects.toThrow(/closed/);
  });

  it('refuses a second mandate inside the work, and allows the next after it', async () => {
    const s = await platform();
    const subjectToken = await person(s.p, s.clock);
    await s.agent.withMandate('support.refund', { subjectToken }, async () => {
      await expect(s.agent.mandate('support.refund', { subjectToken })).rejects.toThrow(/one level deep/);
      await expect(s.agent.requestMandate('support.refund', { subjectToken })).rejects.toThrow(
        /one level deep/,
      );
      await expect(
        s.agent.awaitMandate({
          authReqId: subjectToken,
          mandateId: 'x',
          intervalMs: 1,
          approvalUrl: undefined,
        }),
      ).rejects.toThrow(/one level deep/);
    });
    const next = await s.agent.mandate('support.refund', { subjectToken });
    expect(next.mandateId).toBe('mnd_1');
  });

  it('does not leak into work running beside it', async () => {
    const s = await platform();
    const subjectToken = await person(s.p, s.clock);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const inside = s.agent.withMandate('support.refund', { subjectToken }, () => gate);
    // Not inside the work, so not refused.
    const beside = await s.agent.mandate('support.refund', { subjectToken });
    expect(beside.mandateId).toBe('mnd_1');
    release();
    await inside;
  });
});
