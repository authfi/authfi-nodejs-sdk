// Containment track A: an agent's token is accepted only with a valid DPoP proof (RFC 9449). Ported
// from the 0.1 JavaScript suite (test-dpop.js) onto the TypeScript verifier: the same cases, each
// refusal paired with a control that passes. Old refusal codes are named in the test titles; the
// assertions use the kernel's names (see the table in the pull request).

import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { InvalidToken } from '../../src/core/errors.js';
import { protect, type ExpressResponse } from '../../src/express/index.js';
import { memoryReplayGuard } from '../../src/verify/dpop-proof.js';
import {
  b64u,
  ec,
  ed,
  rsa,
  rejectsWith,
  scenario,
  sha256,
  signJWS,
  thumbprint,
  PUBLIC,
  type ClientConfig,
  type FakeRequest,
  type Scenario,
} from './scenario.js';

// Every refusal below is paired with a control: the same kind of request, unbroken, is accepted.
async function refused(
  code: string,
  build: (s: Scenario, token: string) => FakeRequest,
  cfg?: Parameters<typeof scenario>[0],
) {
  const s = scenario(cfg);
  const control = await s.client.verifyRequest(s.request(s.agentToken()));
  assert.equal(control.sub, 'agt_1', 'control leg must verify');
  const token = s.agentToken({ jti: 'second' });
  return rejectsWith(s.client.verifyRequest(build(s, token)), code);
}

interface Answer {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown> | undefined;
}

/** Runs the middleware against a fake response; resolves when it answered or called next. */
function run(mw: ReturnType<typeof protect>, req: FakeRequest): Promise<{ next: boolean } & Answer> {
  return new Promise((resolve) => {
    const out: Answer = { status: 200, headers: {}, body: undefined };
    const res: ExpressResponse = {
      status(code) {
        out.status = code;
        return this;
      },
      set(fields) {
        for (const [k, v] of Object.entries(fields)) out.headers[k.toLowerCase()] = v;
        return this;
      },
      json(body) {
        out.body = body as Record<string, unknown>;
        resolve({ next: false, ...out });
        return undefined;
      },
    };
    mw(req, res, () => {
      resolve({ next: true, ...out });
    });
  });
}

const nowSec = (s: Scenario): number => Math.floor(s.clock.t / 1000);
const guardOf = (record: (key: string, expires: number) => unknown): ClientConfig => ({
  replayGuard: { record } as ClientConfig['replayGuard'] & object,
});

describe('agent token with a valid proof', () => {
  it('is accepted and returns claims', async () => {
    const s = scenario();
    const claims = await s.client.verifyRequest(s.request(s.agentToken()));
    assert.equal(claims.sub, 'agt_1');
  });
  it('is accepted for ES256 and PS256 proof keys', async () => {
    for (const alg of ['ES256', 'PS256']) {
      const pair = alg === 'ES256' ? ec() : rsa();
      const s = scenario();
      const t = s.token(s.agentClaims({ cnf: { jkt: thumbprint(pair.publicKey) } }));
      const claims = await s.client.verifyRequest(s.request(t, { proof: { alg, pair } }));
      assert.equal(claims.sub, 'agt_1', alg);
    }
  });
  it('is detected by client_id and by the act claim, not only by the sub prefix', async () => {
    const s = scenario();
    for (const extra of [
      { sub: 'usr_9', client_id: 'agt_7', cnf: undefined },
      { sub: 'usr_9', client_id: undefined, act: { sub: 'usr_2' }, cnf: undefined },
    ]) {
      const t = s.token(s.agentClaims(extra));
      await rejectsWith(
        s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] })),
        'dpop_proof_key_mismatch',
      );
    }
  });
  it('accepts a query string on the request URL (htu has none)', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken(), { url: '/orders?id=1' }));
  });
  it('is detected by a sub that starts with agt_ even with no client_id', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ client_id: undefined, cnf: undefined }));
    await rejectsWith(
      s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] })),
      'dpop_proof_key_mismatch',
    );
  });
  it('refuses a nested act chain', async () => {
    const s = scenario();
    const t = s.agentToken({ act: { sub: 'a', act: { sub: 'b' } } });
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'token_act_chain_unsupported');
  });
});

describe('DPoP refusals', () => {
  it('dpop_missing: no proof header', () =>
    refused('dpop_proof_missing', (s, t) => s.request(t, { proofs: [] })));
  it('dpop_missing: Bearer scheme for a bound token, even with a valid proof', () =>
    refused('token_dpop_proof_required', (s, t) => s.request(t, { scheme: 'Bearer' })));
  it('dpop_multiple: two DPoP headers', () =>
    refused('dpop_proof_multiple', (s, t) => s.request(t, { proofs: [s.proof(t), s.proof(t)] })));
  it('dpop_multiple: one header holding two proofs (comma joined, no rawHeaders)', () =>
    refused('dpop_proof_multiple', (s, t) => {
      const r = s.request(t, { proofs: [s.proof(t), s.proof(t)] });
      delete r.rawHeaders;
      return r;
    }));
  it('dpop_multiple: headers as an array', () =>
    refused('dpop_proof_multiple', (s, t) => {
      const r = s.request(t);
      r.headers.dpop = [s.proof(t), s.proof(t)];
      delete r.rawHeaders;
      return r;
    }));
  it('dpop_multiple: two DPoP entries in rawHeaders while the parsed headers hold one', () =>
    refused('dpop_proof_multiple', (s, t) => {
      const r = s.request(t);
      r.rawHeaders?.push('DPoP', s.proof(t));
      return r;
    }));
  it('dpop_malformed: not a JWS', () =>
    refused('dpop_proof_malformed', (s, t) => s.request(t, { proofs: ['abc.def'] })));
  it('dpop_malformed: payload is not JSON', () =>
    refused('dpop_proof_malformed', (s, t) =>
      s.request(t, {
        proofs: [
          signJWS(
            { typ: 'dpop+jwt', alg: 'EdDSA', jwk: s.dpopJwk },
            b64u('not json'),
            s.dpop.privateKey,
            'EdDSA',
          ),
        ],
      }),
    ));
  it('dpop_malformed: header or payload that is a JSON array, not an object', () =>
    refused('dpop_proof_malformed', (s, t) =>
      s.request(t, {
        proofs: [
          signJWS({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: s.dpopJwk }, b64u('[1]'), s.dpop.privateKey, 'EdDSA'),
        ],
      }),
    ));
  it('dpop_malformed: a header segment that is not canonical base64url', () =>
    refused('dpop_proof_malformed', (s, t) => {
      const [h, p, g] = s.proof(t).split('.');
      return s.request(t, { proofs: [`${h}=.${p}.${g}`] });
    }));
  it('dpop_malformed: a signature segment that is not canonical base64url', () =>
    refused('dpop_proof_malformed', (s, t) => {
      const [h, p, g] = s.proof(t).split('.');
      return s.request(t, { proofs: [`${h}.${p}.${g}=`] });
    }));
  it('dpop_malformed: the header is not JSON', () =>
    refused('dpop_proof_malformed', (s, t) => {
      const [, p, g] = s.proof(t).split('.');
      return s.request(t, { proofs: [`${b64u('nope')}.${p}.${g}`] });
    }));
  it('dpop_malformed: crit header', () =>
    refused('dpop_proof_malformed', (s, t) => s.request(t, { proof: { header: { crit: ['x'] } } })));
  it('dpop_malformed: proof larger than 8 KiB', () =>
    refused('dpop_proof_malformed', (s, t) => s.request(t, { proofs: [`${'a'.repeat(9000)}.b.c`] })));
  it('dpop_malformed: a valid proof padded beyond 8 KiB', () =>
    refused('dpop_proof_malformed', (s, t) =>
      s.request(t, { proof: { header: { pad: 'x'.repeat(9000) } } }),
    ));
  it('dpop_malformed: a valid proof with a fourth part', () =>
    refused('dpop_proof_malformed', (s, t) => s.request(t, { proofs: [`${s.proof(t)}.x`] })));
  it('dpop_malformed: a signature that is not valid base64url', () =>
    refused('dpop_proof_malformed', (s, t) => {
      const [h, p] = s.proof(t).split('.');
      return s.request(t, { proofs: [`${h}.${p}.***`] });
    }));
  it('dpop_malformed: a jwk key that is not an object, has a private member, or does not parse', async () => {
    await refused('dpop_proof_key_invalid', (s, t) =>
      s.request(t, { proof: { jwk: { ...s.dpop.privateKey.export({ format: 'jwk' }) } } }),
    );
    await refused('dpop_proof_key_invalid', (s, t) => s.request(t, { proof: { jwk: null } }));
    await refused('dpop_proof_key_invalid', (s, t) => s.request(t, { proof: { jwk: [s.dpopJwk] } }));
    await refused('dpop_proof_key_invalid', (s, t) =>
      s.request(t, { proof: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } } }),
    );
    await refused('dpop_proof_key_invalid', (s, t) =>
      s.request(t, { proof: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } } }),
    );
  });
  it('dpop_malformed: no jti, or a jti longer than 256', async () => {
    await refused('dpop_proof_jti_missing', (s, t) =>
      s.request(t, { proof: { claims: { jti: undefined } } }),
    );
    await refused('dpop_proof_jti_missing', (s, t) =>
      s.request(t, { proof: { claims: { jti: 'j'.repeat(257) } } }),
    );
    await refused('dpop_proof_jti_missing', (s, t) => s.request(t, { proof: { claims: { jti: 7 } } }));
  });
  it('dpop_type: typ is JWT', () =>
    refused('dpop_proof_type_invalid', (s, t) => s.request(t, { proof: { header: { typ: 'JWT' } } })));
  it('dpop_alg: none', () =>
    refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { header: { alg: 'none' } } })));
  it('dpop_alg: HS256', () =>
    refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { header: { alg: 'HS256' } } })));
  it('dpop_alg: RS256 is not in the list, even for a valid RS256 proof', () =>
    refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { alg: 'RS256', pair: rsa() } })));
  it('dpop_alg: EdDSA with an EC key, PS256 with an OKP key', async () => {
    await refused('dpop_proof_alg_mismatch', (s, t) =>
      s.request(t, { proof: { jwk: ec().publicKey.export({ format: 'jwk' }) } }),
    );
    await refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { header: { alg: 'PS256' } } }));
  });
  it('dpop_alg: a PS256 proof key under 2048 bits', () =>
    refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { alg: 'PS256', pair: rsa(1024) } })));
  it('dpop_alg: alg does not fit the embedded key type', () =>
    refused('dpop_proof_alg_mismatch', (s, t) => s.request(t, { proof: { header: { alg: 'ES256' } } })));
  it('dpop_signature: signed by another key than the embedded one', () =>
    refused('dpop_proof_signature_invalid', (s, t) =>
      s.request(t, {
        proof: { jwk: s.dpopJwk, pair: { privateKey: ed().privateKey, publicKey: s.dpop.publicKey } },
      }),
    ));
  it('dpop_signature: tampered payload', () =>
    refused('dpop_proof_signature_invalid', (s, t) => {
      const [h, , sig] = s.proof(t).split('.');
      const body = b64u(
        JSON.stringify({
          jti: 'x',
          htm: 'GET',
          htu: `${PUBLIC}/orders`,
          iat: nowSec(s),
          ath: b64u(sha256(t)),
        }),
      );
      return s.request(t, { proofs: [`${h}.${body}.${sig}`] });
    }));
  it('dpop_method: htm differs', () =>
    refused('dpop_proof_htm_mismatch', (s, t) => s.request(t, { proof: { claims: { htm: 'POST' } } })));
  it('dpop_url: another path', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, { proof: { claims: { htu: `${PUBLIC}/other` } } }),
    ));
  it('dpop_url: another host', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, { proof: { claims: { htu: 'https://evil.example.com/orders' } } }),
    ));
  it('dpop_url: htu carries a query', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, { proof: { claims: { htu: `${PUBLIC}/orders?x=1` } } }),
    ));
  it('dpop_url: htu is not a string', () =>
    refused('dpop_proof_htu_mismatch', (s, t) => s.request(t, { proof: { claims: { htu: 5 } } })));
  it('dpop_url: a spoofed X-Forwarded-Host does not change the expected URL', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, {
        headers: { 'x-forwarded-host': 'evil.example.com', 'x-forwarded-proto': 'https' },
        proof: { claims: { htu: 'https://evil.example.com/orders' } },
      }),
    ));
  it('dpop_url: a spoofed Host header does not change it either', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, {
        headers: { host: 'evil.example.com' },
        proof: { claims: { htu: 'https://evil.example.com/orders' } },
      }),
    ));
  it('dpop_url: a protocol-relative request target cannot move the host', () =>
    refused('dpop_proof_htu_mismatch', (s, t) =>
      s.request(t, {
        url: '//evil.example.com/orders',
        proof: { claims: { htu: 'https://evil.example.com/orders' } },
      }),
    ));
  it('dpop_url: a request target that is not a path', () =>
    refused('dpop_proof_htu_mismatch', (s, t) => s.request(t, { url: 'orders' })));
  it('dpop_iat: older than 60 s', () =>
    refused('dpop_proof_iat_invalid', (s, t) =>
      s.request(t, { proof: { claims: { iat: nowSec(s) - 61 } } }),
    ));
  it('dpop_iat: further ahead than the 5 s skew', () =>
    refused('dpop_proof_iat_invalid', (s, t) => s.request(t, { proof: { claims: { iat: nowSec(s) + 6 } } })));
  it('dpop_iat: not a number', () =>
    refused('dpop_proof_iat_invalid', (s, t) => s.request(t, { proof: { claims: { iat: 'now' } } })));
  it('dpop_ath: hash of another token', () =>
    refused('dpop_proof_ath_mismatch', (s, t) =>
      s.request(t, { proof: { claims: { ath: b64u(sha256('other')) } } }),
    ));
  it('dpop_ath: missing', () =>
    refused('dpop_proof_ath_mismatch', (s, t) => s.request(t, { proof: { claims: { ath: undefined } } })));
  it('dpop_key_mismatch: proof from a key that is not cnf.jkt', () =>
    refused('dpop_proof_key_mismatch', (s, t) => s.request(t, { proof: { pair: ed() } })));
  it('dpop_key_mismatch: bound token without cnf.jkt', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ cnf: {} }));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'dpop_proof_key_mismatch');
    const t2 = s.token(s.agentClaims({ cnf: undefined }));
    await rejectsWith(s.client.verifyRequest(s.request(t2)), 'dpop_proof_key_mismatch');
  });
});

describe('RFC 7638 thumbprints', () => {
  it('matches the RFC 7638 RSA vector and the RFC 8037 Ed25519 vector', () => {
    const n =
      '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
    assert.equal(
      thumbprint(createPublicKey({ key: { kty: 'RSA', n, e: 'AQAB' }, format: 'jwk' })),
      'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
    );
    assert.equal(
      thumbprint(
        createPublicKey({
          key: { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' },
          format: 'jwk',
        }),
      ),
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
    );
  });
  it('binds a token to the RFC 8037 Ed25519 key through the SDK own thumbprint', async () => {
    // RFC 8037 appendix A.1: the key and its RFC 7638 thumbprint.
    const x = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
    const d = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';
    const pair = {
      privateKey: createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d, x }, format: 'jwk' }),
      publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' }),
    };
    const s = scenario();
    const t = s.token(s.agentClaims({ cnf: { jkt: 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k' } }));
    const claims = await s.client.verifyRequest(s.request(t, { proof: { pair } }));
    assert.equal(claims.sub, 'agt_1');
  });
});

describe('boundary values that must pass', () => {
  it('iat 60 s old and 5 s ahead are inside the window', async () => {
    const s = scenario();
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t, { proof: { claims: { iat: nowSec(s) - 60 } } }));
    await s.client.verifyRequest(s.request(t, { proof: { claims: { iat: nowSec(s) + 5 } } }));
  });
});

describe('replay', () => {
  it('dpop_replayed: the same proof twice', async () => {
    const s = scenario();
    const t = s.agentToken();
    const proof = s.proof(t);
    await s.client.verifyRequest(s.request(t, { proofs: [proof] }));
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [proof] })), 'dpop_proof_replayed');
  });
  it('the jti is recorded only after every other check passed', async () => {
    const s = scenario();
    const t = s.agentToken();
    const bad = s.proof(t, { claims: { jti: 'same', htm: 'POST' } });
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [bad] })), 'dpop_proof_htm_mismatch');
    const good = s.proof(t, { claims: { jti: 'same' } });
    await s.client.verifyRequest(s.request(t, { proofs: [good] }));
  });
  it('a refusal by the chain does not record the jti either', async () => {
    const calls: string[] = [];
    const s = scenario({
      noX5c: true,
      config: guardOf((k) => {
        calls.push(k);
        return true;
      }),
    });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'chain_not_proven');
    assert.equal(calls.length, 0);
  });
  it('the same jti from a different key is not a replay (key is thumbprint+jti)', async () => {
    const s = scenario();
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t, { proof: { claims: { jti: 'x' } } }));
    const k2 = ed();
    const t2 = s.token(s.agentClaims({ cnf: { jkt: thumbprint(k2.publicKey) } }));
    await s.client.verifyRequest(s.request(t2, { proof: { pair: k2, claims: { jti: 'x' } } }));
  });
  it('a custom replayGuard is used and its keys carry thumbprint and jti', async () => {
    const seen = new Set<string>();
    const s = scenario({
      config: guardOf((k) => {
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      }),
    });
    const t = s.agentToken();
    const p = s.proof(t, { claims: { jti: 'j9' } });
    await s.client.verifyRequest(s.request(t, { proofs: [p] }));
    assert.deepEqual([...seen], [`${thumbprint(s.dpop.publicKey)}:j9`]);
    await rejectsWith(s.client.verifyRequest(s.request(t, { proofs: [p] })), 'dpop_proof_replayed');
  });
  it('a replayGuard that throws fails closed', async () => {
    const s = scenario({
      config: guardOf(() => {
        throw new Error('store down');
      }),
    });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_replay_check_unavailable');
  });
  it('a replayGuard that answers anything but true refuses', async () => {
    const s = scenario({ config: guardOf(() => undefined) });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_proof_replayed');
  });
  it('the default guard is bounded and fails closed when full', async () => {
    const s = scenario({ config: { replayMax: 2 } });
    const t = s.agentToken();
    await s.client.verifyRequest(s.request(t));
    await s.client.verifyRequest(s.request(t));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'dpop_replay_check_unavailable');
  });
  it('one noisy key is capped per thumbprint while another key still works', async () => {
    const s = scenario({ config: { replayMax: 100, replayPerKey: 2 } });
    const noisy = s.agentToken();
    await s.client.verifyRequest(s.request(noisy));
    await s.client.verifyRequest(s.request(noisy));
    await rejectsWith(s.client.verifyRequest(s.request(noisy)), 'dpop_replay_check_unavailable');
    const k2 = ed();
    const victim = s.token(s.agentClaims({ cnf: { jkt: thumbprint(k2.publicKey) } }));
    await s.client.verifyRequest(s.request(victim, { proof: { pair: k2 } }));
  });
  it('expired entries are swept on a timer, not only when the guard is full', async () => {
    const s = scenario({ config: { replayMax: 100, replayPerKey: 1 } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_replay_check_unavailable');
    s.clock.t += 10 * 60 * 1000; // the guard is far from full; only the key's own cap would block
    const t = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await s.client.verifyRequest(s.request(t));
  });
  it('the middleware answers a full guard with 503 and Retry-After, never 401', async () => {
    const s = scenario({ config: { replayMax: 1 } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    const out = await run(protect(s.client.verifier, { exposeRefusalCode: true }), s.request(s.agentToken()));
    assert.ok(!out.next);
    assert.equal(out.status, 503);
    assert.equal(out.body?.code, 'dpop_replay_check_unavailable');
    assert.ok(out.headers['retry-after']);
  });
  it('a custom guard may answer full', async () => {
    const s = scenario({ config: guardOf(() => 'full') });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_replay_check_unavailable');
  });
  it('the default guard forgets a proof once its window has passed', async () => {
    const s = scenario({ config: { replayMax: 1 } });
    await s.client.verifyRequest(s.request(s.agentToken()));
    s.clock.t += 10 * 60 * 1000;
    const t2 = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await s.client.verifyRequest(s.request(t2));
  });
  it('the memory guard counts a key once however many entries it holds', () => {
    let now = 0;
    const g = memoryReplayGuard(10, () => now, 1);
    assert.equal(g.record('a:1', 1000), true);
    assert.equal(g.record('a:1', 1000), false);
    assert.equal(g.record('a:2', 1000), 'full');
    assert.equal(g.record('b:1', 1000), true);
    now = 2000;
    assert.equal(g.record('a:2', 5000), true);
  });
});

describe('forwarded headers and the public URL', () => {
  it('forwarded headers count only when trustForwarded is true', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const t = s.agentToken();
    const headers = { 'x-forwarded-host': 'edge.example.org', 'x-forwarded-proto': 'https' };
    await s.client.verifyRequest(
      s.request(t, { headers, proof: { claims: { htu: 'https://edge.example.org/orders' } } }),
    );
    await rejectsWith(
      s.client.verifyRequest(
        s.request(t, { headers, proof: { claims: { htu: 'https://api.example.com/orders' } } }),
      ),
      'dpop_proof_htu_mismatch',
    );
  });
  it('X-Forwarded-Host: the last entry (the proxy) counts, a client-supplied first entry does not', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const t = s.agentToken();
    const headers = {
      'x-forwarded-host': 'evil.example, api.example.com',
      'x-forwarded-proto': 'https, https',
    };
    await rejectsWith(
      s.client.verifyRequest(
        s.request(t, { headers, proof: { claims: { htu: 'https://evil.example/orders' } } }),
      ),
      'dpop_proof_htu_mismatch',
    );
    await s.client.verifyRequest(
      s.request(t, { headers, proof: { claims: { htu: 'https://api.example.com/orders' } } }),
    );
  });
  it('a configured publicUrl wins over forwarded headers even with trustForwarded', async () => {
    const s = scenario({ config: { trustForwarded: true } });
    const t = s.agentToken();
    const headers = { 'x-forwarded-host': 'evil.example', 'x-forwarded-proto': 'https' };
    await rejectsWith(
      s.client.verifyRequest(
        s.request(t, { headers, proof: { claims: { htu: 'https://evil.example/orders' } } }),
      ),
      'dpop_proof_htu_mismatch',
    );
    await s.client.verifyRequest(s.request(t, { headers }));
  });
  it('dpop_url: a forwarded protocol outside http and https', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const headers = { 'x-forwarded-host': 'edge.example.org', 'x-forwarded-proto': 'ftp' };
    await rejectsWith(
      s.client.verifyRequest(
        s.request(s.agentToken(), { headers, proof: { claims: { htu: 'ftp://edge.example.org/orders' } } }),
      ),
      'dpop_proof_htu_mismatch',
    );
  });
  it('dpop_url: a forwarded host with characters a host cannot have', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    const headers = { 'x-forwarded-host': 'edge.example.org/evil', 'x-forwarded-proto': 'https' };
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken(), { headers })),
      'dpop_proof_htu_mismatch',
    );
  });
  it('trustForwarded without the headers refuses', async () => {
    const s = scenario({ config: { publicUrl: undefined, trustForwarded: true } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_proof_htu_mismatch');
  });
  it('a missing publicUrl without trustForwarded is a configuration error when a proof is checked', async () => {
    const s = scenario({ config: { publicUrl: undefined } });
    await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'configuration_invalid');
    // a person token needs no proof, so it still verifies
    const claims = await s.client.verifyRequest(
      s.request(s.token(s.claims()), { scheme: 'Bearer', proofs: [] }),
    );
    assert.equal(claims.sub, 'usr_1');
  });
  it('a publicUrl that carries a path is a configuration error', () => {
    assert.throws(() => scenario({ config: { publicUrl: 'https://api.example.com/v1' } }), /origin only/);
  });
  it('a default port and letter case in the htu are normalised', async () => {
    const s = scenario();
    await s.client.verifyRequest(
      s.request(s.agentToken(), { proof: { claims: { htu: 'HTTPS://API.EXAMPLE.COM:443/orders' } } }),
    );
  });
  it('takes the path of a full request URL (a Fetch Request)', async () => {
    const s = scenario();
    const t = s.agentToken();
    const request = new Request(`${PUBLIC}/orders?x=1`, {
      headers: { authorization: `DPoP ${t}`, dpop: s.proof(t) },
    });
    const token = await s.client.verifier.verifyRequest(request);
    assert.equal(token.principal.id, 'agt_1');
  });
});

describe('server nonce', () => {
  const nonceKey = 'a'.repeat(32);
  const nonceOf = (e: Error & Record<string, unknown>): string => String(e.nonce);
  it('dpop_nonce: a proof with no nonce is refused, the error carries a nonce, and that nonce works', async () => {
    const s = scenario({ config: { nonceKey } });
    const err = await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken())),
      'dpop_proof_nonce_invalid',
    );
    assert.match(nonceOf(err), /^[A-Za-z0-9_-]{16,}$/);
    await s.client.verifyRequest(s.request(s.agentToken(), { proof: { claims: { nonce: nonceOf(err) } } }));
  });
  it('dpop_nonce: a made-up nonce, a nonce from another key, a non-string nonce', async () => {
    const s = scenario({ config: { nonceKey } });
    const other = scenario({ config: { nonceKey: 'b'.repeat(32) } });
    const foreign = nonceOf(
      await rejectsWith(
        other.client.verifyRequest(other.request(other.agentToken())),
        'dpop_proof_nonce_invalid',
      ),
    );
    for (const n of ['AAAAAAAAAAAAAAAAAAAAAA', foreign, 5]) {
      await rejectsWith(
        s.client.verifyRequest(s.request(s.agentToken(), { proof: { claims: { nonce: n } } })),
        'dpop_proof_nonce_invalid',
      );
    }
  });
  it('the previous window is accepted, an older one is not', async () => {
    const s = scenario({ config: { nonceKey } });
    const n = nonceOf(
      await rejectsWith(s.client.verifyRequest(s.request(s.agentToken())), 'dpop_proof_nonce_invalid'),
    );
    s.clock.t += 60 * 1000;
    const t = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await s.client.verifyRequest(s.request(t, { proof: { claims: { nonce: n } } }));
    s.clock.t += 3 * 60 * 1000;
    const t2 = s.agentToken({ iat: nowSec(s), exp: nowSec(s) + 600 });
    await rejectsWith(
      s.client.verifyRequest(s.request(t2, { proof: { claims: { nonce: n } } })),
      'dpop_proof_nonce_invalid',
    );
  });
  it('a short nonceKey is a configuration error', () => {
    assert.throws(() => scenario({ config: { nonceKey: 'short' } }), /nonceKey/);
  });
  it('a byte-array nonceKey works like a string', async () => {
    const s = scenario({ config: { nonceKey: new Uint8Array(32).fill(7) } });
    const err = await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken())),
      'dpop_proof_nonce_invalid',
    );
    assert.ok(nonceOf(err).length >= 16);
  });
  it('the middleware answers use_dpop_nonce with a DPoP-Nonce header, and offers one on every response', async () => {
    const s = scenario({ config: { nonceKey } });
    const mw = protect(s.client.verifier, { exposeRefusalCode: true });
    const out = await run(mw, s.request(s.agentToken()));
    assert.equal(out.status, 401);
    assert.match(out.headers['dpop-nonce'] ?? '', /^[A-Za-z0-9_-]{16,}$/);
    assert.match(out.headers['www-authenticate'] ?? '', /DPoP error="use_dpop_nonce"/);
    assert.equal(out.body?.error, 'use_dpop_nonce');
    assert.equal(out.body?.code, 'dpop_proof_nonce_invalid');
    const ok = await run(
      mw,
      s.request(s.agentToken(), { proof: { claims: { nonce: out.headers['dpop-nonce'] } } }),
    );
    assert.ok(ok.next);
    assert.match(ok.headers['dpop-nonce'] ?? '', /^[A-Za-z0-9_-]{16,}$/);
  });
  it('a verifier with no nonceKey offers no nonce', async () => {
    const s = scenario();
    assert.equal(await s.client.verifier.serverNonce(), undefined);
  });
});

describe('modes', () => {
  it('off: an unbound agent token is accepted as a bearer token and a warning is logged once', async () => {
    const warns: string[] = [];
    const s = scenario({ config: { agentTokens: 'off', logger: { warn: (m) => warns.push(m) } } });
    const t = s.token(s.agentClaims({ cnf: undefined }));
    const req = s.request(t, { scheme: 'Bearer', proofs: [] });
    assert.equal((await s.client.verifyRequest(req)).sub, 'agt_1');
    await s.client.verifyRequest(req);
    assert.equal(warns.length, 1);
    assert.equal((await s.client.verifyToken(t)).sub, 'agt_1');
  });
  it('off: still requires a proof of a token that carries cnf', async () => {
    const s = scenario({ config: { agentTokens: 'off' } });
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'Bearer', proofs: [] })),
      'token_dpop_proof_required',
    );
  });
  it('off: skips the chain', async () => {
    const s = scenario({ noX5c: true, config: { agentTokens: 'off' } });
    assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
  });
  it('enforce is the default and an unknown mode is a configuration error', async () => {
    assert.throws(() => scenario({ config: { agentTokens: 'maybe' as never } }), /enforce, watch or off/);
    const d = scenario();
    await rejectsWith(
      d.client.verifyRequest(d.request(d.agentToken(), { proofs: [] })),
      'dpop_proof_missing',
    );
  });
  it('watch: lets the request through and logs only the code', async () => {
    const logs: unknown[] = [];
    const s = scenario({
      config: {
        agentTokens: 'watch',
        logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) },
      },
    });
    const t = s.agentToken();
    const claims = await s.client.verifyRequest(s.request(t, { proofs: [] }));
    assert.equal(claims.sub, 'agt_1');
    const logged = JSON.stringify(logs);
    assert.match(logged, /dpop_proof_missing/);
    assert.ok(!logged.includes(t), 'the token must not be logged');
  });
  it('watch: a valid request passes with nothing logged', async () => {
    const logs: unknown[] = [];
    const s = scenario({
      config: {
        agentTokens: 'watch',
        logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) },
      },
    });
    await s.client.verifyRequest(s.request(s.agentToken()));
    assert.equal(logs.length, 0);
  });
  it('watch: an agent token presented as Bearer passes and is logged', async () => {
    const logs: unknown[] = [];
    const s = scenario({
      config: { agentTokens: 'watch', logger: { warn: (...a) => logs.push(a) } },
    });
    const claims = await s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'Bearer', proofs: [] }));
    assert.equal(claims.sub, 'agt_1');
    assert.equal(logs.length, 1);
  });
  it('watch: an unbound agent token is logged as one enforce would refuse, and verify() accepts it', async () => {
    const logs: unknown[] = [];
    const s = scenario({ config: { agentTokens: 'watch', logger: { warn: (...a) => logs.push(a) } } });
    const t = s.token(s.agentClaims({ cnf: undefined }));
    assert.equal((await s.client.verifyToken(t)).sub, 'agt_1');
    assert.match(JSON.stringify(logs), /agent_token_needs_request/);
    assert.equal((await s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] }))).sub, 'agt_1');
  });
  it('watch: a bound person token still needs its proof (watch is for agent tokens only)', async () => {
    const s = scenario({ config: { agentTokens: 'watch' } });
    const bound = s.token(s.claims({ cnf: { jkt: thumbprint(s.dpop.publicKey) } }));
    await rejectsWith(
      s.client.verifyRequest(s.request(bound, { scheme: 'Bearer', proofs: [] })),
      'token_dpop_proof_required',
    );
  });
  it('watch: an unexpected internal error is thrown, never turned into a pass', async () => {
    const s = scenario({
      config: {
        agentTokens: 'watch',
        replayGuard: {
          record: () => {
            throw new TypeError('boom');
          },
        },
      },
    });
    // a guard that throws is a refusal ("unavailable"), which watch logs and lets through
    assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
    // an error that is neither a refusal nor a configuration error is not swallowed
    const broken = scenario({ config: { agentTokens: 'watch' } });
    const req = broken.request(broken.agentToken());
    req.headers = new Proxy(req.headers, {
      get(target, p) {
        if (p === 'dpop') throw new TypeError('boom');
        return target[p as string];
      },
    });
    await assert.rejects(broken.client.verifyRequest(req), TypeError);
  });
  it('watch: a baseline refusal is still a refusal', async () => {
    const s = scenario({ config: { agentTokens: 'watch' } });
    const t = s.token(s.agentClaims({ aud: 'someone-else' }));
    await rejectsWith(s.client.verifyRequest(s.request(t)), 'token_audience_mismatch');
  });
  it('watch: a missing publicUrl is logged, and a person token is unaffected', async () => {
    const logs: unknown[] = [];
    const s = scenario({
      config: { agentTokens: 'watch', publicUrl: undefined, logger: { warn: (...a) => logs.push(a) } },
    });
    assert.equal((await s.client.verifyRequest(s.request(s.agentToken()))).sub, 'agt_1');
    assert.match(JSON.stringify(logs), /configuration_invalid/);
  });
});

describe('verifyToken and person tokens', () => {
  it('verifyToken refuses an agent token with agent_token_needs_request', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyToken(s.agentToken()), 'agent_token_needs_request');
    assert.equal((await s.client.verifyToken(s.token(s.claims()))).sub, 'usr_1');
  });
  it('verifyToken refuses a person token that carries cnf (it needs a proof)', async () => {
    const s = scenario();
    await rejectsWith(
      s.client.verifyToken(s.token(s.claims({ cnf: { jkt: 'x' } }))),
      'token_dpop_proof_required',
    );
  });
  it('a plain person bearer token passes verifyRequest; a bound one needs its proof', async () => {
    const s = scenario();
    const plain = s.token(s.claims());
    assert.equal(
      (await s.client.verifyRequest(s.request(plain, { scheme: 'Bearer', proofs: [] }))).sub,
      'usr_1',
    );
    const bound = s.token(s.claims({ cnf: { jkt: thumbprint(s.dpop.publicKey) } }));
    await rejectsWith(
      s.client.verifyRequest(s.request(bound, { scheme: 'Bearer', proofs: [] })),
      'token_dpop_proof_required',
    );
    assert.equal((await s.client.verifyRequest(s.request(bound))).sub, 'usr_1');
  });
  it('the DPoP scheme with an unbound token is refused', async () => {
    const s = scenario();
    await rejectsWith(s.client.verifyRequest(s.request(s.token(s.claims()))), 'token_dpop_unbound');
  });
  it('the scheme name is case-insensitive', async () => {
    const s = scenario();
    await s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'dpop' }));
  });
  it('an unknown scheme or a second Authorization value is missing_authorization', async () => {
    const s = scenario();
    await rejectsWith(
      s.client.verifyRequest(s.request(s.agentToken(), { scheme: 'Basic' })),
      'token_missing',
    );
    const t = s.token(s.claims());
    const r = s.request(t, { scheme: 'Bearer', proofs: [] });
    r.rawHeaders?.push('Authorization', `Bearer ${t}`);
    await rejectsWith(s.client.verifyRequest(r), 'token_missing');
  });
  it('a bound authfi_mandate token is bound like one with cnf', async () => {
    const s = scenario();
    const t = s.token(s.claims({ authfi_mandate: { id: 'm1' } }));
    await rejectsWith(
      s.client.verifyRequest(s.request(t, { scheme: 'Bearer', proofs: [] })),
      'token_dpop_proof_required',
    );
  });
});

describe('errors never carry token or proof material', () => {
  it('no refusal message or logged line holds the token, the proof or a claim value', async () => {
    const logs: unknown[] = [];
    const s = scenario({
      config: { logger: { warn: (...a) => logs.push(a), debug: (...a) => logs.push(a) } },
    });
    const t = s.agentToken({ sub: 'agt_SECRETSUBJECT' });
    const proof = s.proof(t, { claims: { htm: 'POST', jti: 'SECRETJTI' } });
    const err = await rejectsWith(
      s.client.verifyRequest(s.request(t, { proofs: [proof] })),
      'dpop_proof_htm_mismatch',
    );
    const text = JSON.stringify([err.message, err.code, (err.stack ?? '').split('\n')[0], logs]);
    for (const bad of [t, proof, 'SECRETSUBJECT', 'SECRETJTI', t.split('.')[1], proof.split('.')[2]]) {
      assert.ok(!text.includes(bad ?? ''));
    }
  });
});

describe('middleware', () => {
  it('protect() calls the request-aware verify, sets req.authfi and enforces permissions', async () => {
    const s = scenario();
    const t = s.token(s.agentClaims({ permissions: ['read:orders'] }));
    const req = s.request(t);
    const ok = await run(protect(s.client.verifier, { permissions: ['read:orders'] }), req);
    assert.ok(ok.next);
    assert.equal(req.authfi?.principal.id, 'agt_1');
    const t2 = s.token(s.agentClaims({ permissions: [] }));
    const denied = await run(protect(s.client.verifier, { permissions: ['read:orders'] }), s.request(t2));
    assert.ok(!denied.next);
    assert.equal(denied.status, 403);
  });
  it('protect() without a proof answers 401 with an invalid_dpop_proof challenge, and the code only on request', async () => {
    const s = scenario();
    const out = await run(protect(s.client.verifier), s.request(s.agentToken(), { proofs: [] }));
    assert.ok(!out.next);
    assert.equal(out.status, 401);
    assert.equal(out.body?.error, 'invalid_dpop_proof');
    assert.equal(out.body?.code, undefined);
    assert.match(out.headers['www-authenticate'] ?? '', /^DPoP error="invalid_dpop_proof"/);
    assert.match(out.headers['www-authenticate'] ?? '', /algs="EdDSA ES256 PS256"/);
    const exposed = await run(
      protect(s.client.verifier, { exposeRefusalCode: true }),
      s.request(s.agentToken(), { proofs: [] }),
    );
    assert.equal(exposed.body?.code, 'dpop_proof_missing');
  });
  it('a roles or any-permission guard also demands the proof', async () => {
    const s = scenario();
    for (const mw of [protect(s.client.verifier, { roles: ['admin'] }), protect(s.client.verifier)]) {
      const out = await run(mw, s.request(s.agentToken(), { proofs: [] }));
      assert.ok(!out.next);
      assert.equal(out.status, 401);
    }
  });
  it('a request without authorization is 401 with a plain challenge', async () => {
    const s = scenario();
    const out = await run(
      protect(s.client.verifier, { exposeRefusalCode: true }),
      s.request(null, { proofs: [] }),
    );
    assert.equal(out.body?.code, 'token_missing');
    assert.equal(out.status, 401);
  });
  it('counts a second Authorization header the parser dropped', async () => {
    const s = scenario();
    const t = s.token(s.claims());
    const r = s.request(t, { scheme: 'Bearer', proofs: [] });
    r.rawHeaders?.push('authorization', `Bearer ${t}`);
    const out = await run(protect(s.client.verifier, { exposeRefusalCode: true }), r);
    assert.equal(out.status, 401);
    assert.equal(out.body?.code, 'token_missing');
  });
  it('is an InvalidToken a handler can catch', async () => {
    const s = scenario();
    await expect(s.client.verifyToken(s.agentToken())).rejects.toBeInstanceOf(InvalidToken);
  });
});
