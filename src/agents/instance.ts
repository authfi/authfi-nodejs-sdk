import { base64url } from '../core/bytes.js';
import { jwkThumbprint, type DPoPSigner } from '../core/dpop.js';
import {
  APIError,
  ConfigurationError,
  NotSupportedError,
  OAuthError,
  type AuthFIError,
} from '../core/errors.js';
import type { ServerMetadata } from '../core/metadata.js';
import { GRANT, apiErrorOf, requestToken, type TokenResponse } from '../core/oauth.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { Secret } from '../core/secret.js';
import { contextOf, jsonOf, type HttpResponse } from '../core/transport.js';
import { decodeUnverified } from '../verify/verifier.js';
import { AgentAuth, type InstanceSignIn } from './agent.js';
import type { AgentAlgorithm, Signer } from './agent-key.js';
import { noAssertion } from './no-assertion.js';

/** Where an instance of the agent runs, and how it proves it: the Attester's evidence (RFC 9334). */
export interface Evidence {
  /** `k8s` (a projected service-account token) or `device` (a bound device key). */
  readonly kind: 'k8s' | 'device';
  /**
   * The evidence token for one attestation. `nonce` is the platform's challenge, `thumbprint` the instance
   * key's: a device key signs over both, so a captured signature cannot be spent for another key.
   */
  token(request: { nonce: string; agentId: string; thumbprint: string; issuer: string }): Promise<string>;
}

/** The signed configuration an instance runs: its approved version and digest. */
export interface Configuration {
  readonly version: number;
  readonly digest: string;
}

/** The longest an attestation may live (contract C2). */
export const MAX_ATTESTATION_SECONDS = 900;
const POP_SECONDS = 60;
const ATTEST_PATH = '/apis/regional/v1/ai/agents/attest';
/** The `typ` of the instance attestation. */
export const ATTESTATION_TYP = 'oauth-client-attestation+jwt';
/** The `typ` of the proof of possession that goes with it at the token endpoint. */
export const POP_TYP = 'oauth-client-attestation-pop+jwt';
/** The `typ` of the proof an instance signs over the platform's challenge. */
export const PROOF_TYP = 'authfi-instance-proof+jwt';
/** The header that carries the attestation. */
export const ATTESTATION_HEADER = 'OAuth-Client-Attestation';
/** The header that carries the proof of possession. */
export const POP_HEADER = 'OAuth-Client-Attestation-PoP';
const INSTANCE_ID = /^inst_[0-9a-f]{32}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * What the person reading a refusal can do. The attest route gives every refusal the same 401 (it must not
 * say which agents exist, what they are bound to, or which part of the evidence was wrong), so this cannot
 * name the cause; the reason is on the project's audit tape as `agent.attest.refused`.
 */
const REFUSED =
  'The platform refuses every failed sign-in the same way. Its reason is on the audit tape ' +
  "(agent.attest.refused): the binding of the agent's workload, the evidence kind, a service-account token " +
  'used once or older than 600 seconds, the approved configuration version and digest, and a pod the cluster ' +
  'does not report running are the causes to check.';
const UNAVAILABLE =
  'The platform could not decide just now. Sign in again: the SDK asks for a new challenge, and a ' +
  'service-account token that may have been spent needs the pod to have rotated to a fresh one.';

/** The instance key as an agent signer: it names the key, and signs nothing an agent key would. */
export class InstanceSigner implements Signer {
  readonly kid = 'instance';
  readonly alg: AgentAlgorithm = 'ES256';

  sign(): Promise<Uint8Array<ArrayBuffer>> {
    return Promise.reject(noAssertion());
  }

  publicJwk(): JsonWebKey {
    return {};
  }
}

function refusalWithFix(res: HttpResponse): AuthFIError {
  const error = apiErrorOf(res);
  const hint = res.status === 401 ? REFUSED : res.status === 503 ? UNAVAILABLE : undefined;
  if (hint === undefined) return error;
  return new APIError(
    error.code,
    `${error.description === undefined ? '' : `${error.description}. `}${hint}`,
    {
      ...contextOf(res),
    },
  );
}

interface Attestation {
  readonly token: Secret;
  readonly instanceId: string;
  /** Epoch seconds. */
  readonly expiresAt: number;
  readonly thumbprint: string;
}

/** What a client can check of an attestation: that it names this agent and this key, and its lifetime. */
async function attestationProblem(
  raw: string,
  agentId: string,
  signer: DPoPSigner,
  nowSeconds: number,
): Promise<{ problem: string } | { attestation: Attestation }> {
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    ({ header, payload: claims } = decodeUnverified(raw));
  } catch {
    return { problem: 'is not a JWT' };
  }
  if (header.typ !== ATTESTATION_TYP)
    return { problem: `has typ ${JSON.stringify(header.typ)}, not ${ATTESTATION_TYP}` };
  if (claims.sub !== agentId) return { problem: `is for ${JSON.stringify(claims.sub)}, not ${agentId}` };
  const cnf = claims.cnf as { jwk?: unknown } | undefined;
  if ((await jwkThumbprint(cnf?.jwk)) !== signer.thumbprint)
    return { problem: "is bound to a different key than this instance's" };
  const instance = claims.authfi_instance as { instance_id?: unknown } | undefined;
  const instanceId = instance?.instance_id;
  if (typeof instanceId !== 'string' || !INSTANCE_ID.test(instanceId))
    return { problem: 'names no instance_id (inst_ and 32 hex digits)' };
  const { iat, exp } = claims;
  if (typeof iat !== 'number' || typeof exp !== 'number') return { problem: 'has no lifetime' };
  if (exp - iat > MAX_ATTESTATION_SECONDS)
    return { problem: `lives longer than ${String(MAX_ATTESTATION_SECONDS)} seconds` };
  if (exp <= nowSeconds) return { problem: 'has already expired (is the clock right?)' };
  return {
    attestation: { token: new Secret(raw), instanceId, expiresAt: exp, thumbprint: signer.thumbprint },
  };
}

/** Everything an instance needs to sign in; see {@link InstanceAuth}. */
export interface InstanceOptions {
  readonly agentId: string;
  readonly evidence: Evidence;
  /** The approved configuration this instance runs. The platform attests no instance without one. */
  readonly config: Configuration;
  /** The image the instance runs, `sha256:` and 64 lowercase hex digits. */
  readonly imageDigest?: string | undefined;
  readonly resource?: string | undefined;
  /** Attest again this long before the attestation expires (default 60 000 ms). */
  readonly refreshSkewMs?: number | undefined;
}

/** Signs in by challenge, attest and the attested token request. */
class Attestor implements InstanceSignIn {
  readonly #core: Core;
  readonly #issuer: string;
  readonly #options: InstanceOptions;
  readonly #skew: number;
  #held: Attestation | undefined;

  constructor(af: AuthFI, options: InstanceOptions) {
    this.#core = coreOf(af);
    this.#issuer = af.issuer;
    this.#options = options;
    this.#skew = options.refreshSkewMs ?? 60_000;
  }

  get instanceId(): string | undefined {
    return this.#held?.instanceId;
  }

  async #attest(signer: DPoPSigner, signal?: AbortSignal): Promise<Attestation> {
    const core = this.#core;
    const now = core.clock.now();
    const held = this.#held;
    if (held?.thumbprint === signer.thumbprint && held.expiresAt * 1000 - now > this.#skew) {
      return held;
    }
    const origin = await core.apiOrigin(signal);
    const challengeUrl = `${origin}${ATTEST_PATH}/challenge`;
    const challenge = await core.transport.send({
      method: 'POST',
      url: challengeUrl,
      retry: 'safe',
      signal,
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    if (challenge.status !== 200) throw refusalWithFix(challenge);
    const nonce = (jsonOf(challenge) as { nonce?: unknown } | undefined)?.nonce;
    if (typeof nonce !== 'string' || nonce === '')
      throw new OAuthError(
        'invalid_response',
        'the attestation challenge answered no nonce',
        contextOf(challenge),
      );
    const { agentId, evidence, config, imageDigest } = this.#options;
    const proof = await signer.signJwt(
      {
        nonce,
        agent_id: agentId,
        aud: this.#issuer,
        iat: Math.floor(now / 1000),
        jti: crypto.randomUUID(),
      },
      PROOF_TYP,
    );
    const token = await evidence.token({
      nonce,
      agentId,
      thumbprint: signer.thumbprint,
      issuer: this.#issuer,
    });
    const url = `${origin}${ATTEST_PATH}`;
    // Sent once: the evidence works once, so a retry after it may have arrived would be refused.
    const res = await core.transport.send({
      method: 'POST',
      url,
      retry: 'unsafe',
      signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agent_id: agentId,
        evidence: { kind: evidence.kind, token },
        instance_key: signer.publicJwk,
        config: { version: config.version, digest: config.digest },
        proof,
        ...(imageDigest === undefined ? {} : { image_digest: imageDigest }),
      }),
    });
    if (res.status !== 200) throw refusalWithFix(res);
    const raw = (jsonOf(res) as { attestation?: unknown } | undefined)?.attestation;
    if (typeof raw !== 'string' || raw === '')
      throw new OAuthError('invalid_response', 'the attest route answered no attestation', contextOf(res));
    const checked = await attestationProblem(raw, agentId, signer, core.clock.now() / 1000);
    if ('problem' in checked)
      throw new OAuthError('invalid_response', `the attestation ${checked.problem}`, contextOf(res));
    this.#held = checked.attestation;
    core.logger.debug('an instance of an agent was attested', {
      agent_id: agentId,
      instance_id: checked.attestation.instanceId,
    });
    return checked.attestation;
  }

  async mint(request: {
    meta: ServerMetadata;
    resource: string | undefined;
    signer: DPoPSigner;
    signal?: AbortSignal | undefined;
  }): Promise<TokenResponse> {
    const { meta, resource, signer, signal } = request;
    if (
      meta.grant_types_supported !== undefined &&
      !meta.grant_types_supported.includes(GRANT.clientCredentials)
    ) {
      throw new NotSupportedError(
        'client_credentials',
        'This AuthFI project does not offer the client credentials grant',
      );
    }
    const attestation = await this.#attest(signer, signal);
    const agentId = this.#options.agentId;
    return requestToken(
      this.#core.transport,
      {
        tokenEndpoint: meta.token_endpoint,
        params: { grant_type: GRANT.clientCredentials, client_id: agentId, resource },
        // Not sent again after it may have arrived: its proof carries a single-use jti.
        retry: 'unsafe',
        signal,
        dpop: signer,
        attempt: async () => ({
          headers: {
            [ATTESTATION_HEADER]: attestation.token.reveal(),
            [POP_HEADER]: await signer.signJwt(
              {
                iss: agentId,
                aud: this.#issuer,
                jti: crypto.randomUUID(),
                iat: Math.floor(this.#core.clock.now() / 1000),
                exp: Math.floor(this.#core.clock.now() / 1000) + POP_SECONDS,
              },
              POP_TYP,
            ),
          },
        }),
      },
      () => this.#core.clock.now(),
    );
  }
}

/**
 * An agent instance that signs in by attestation: the credential `connect()` returns on a bound workload.
 * An agent has no long-lived secret here. Each execution (an instance) makes a key in memory, shows where
 * it runs, and trades that for a 15-minute attestation and a token bound to its key. Every call then
 * carries `Authorization: DPoP` and a fresh proof; `headers()` does that, and the gateway and the exporters
 * call it. The attestation is renewed before it expires.
 *
 * Acting for a person by CIBA, an approval request and starting a mandate still authenticate with an agent
 * key and are refused here with the fix; token exchange works.
 */
export class InstanceAuth extends AgentAuth {
  readonly #attestor: Attestor;

  constructor(af: AuthFI, options: InstanceOptions) {
    const { agentId, config, imageDigest } = options;
    if (
      typeof config.version !== 'number' ||
      !Number.isInteger(config.version) ||
      config.version < 1 ||
      !/^sha256:[0-9a-f]+$/.test(config.digest)
    ) {
      throw new ConfigurationError(
        'an instance runs one approved configuration: set AUTHFI_CONFIG_VERSION and AUTHFI_CONFIG_DIGEST (sha256:<hex>), or pass config: { version, digest }. The platform attests no instance without one.',
      );
    }
    if (imageDigest !== undefined && !IMAGE_DIGEST.test(imageDigest)) {
      throw new ConfigurationError(
        `AUTHFI_IMAGE_DIGEST is sha256: and 64 lowercase hex digits; got ${JSON.stringify(imageDigest)}`,
      );
    }
    const attestor = new Attestor(af, options);
    super(af, {
      agentId,
      key: new InstanceSigner(),
      resource: options.resource,
      refreshSkewMs: options.refreshSkewMs,
      instance: attestor,
    });
    this.#attestor = attestor;
  }

  /** The id the platform gave this instance, once it has signed in. */
  get instanceId(): string | undefined {
    return this.#attestor.instanceId;
  }

  override toString(): string {
    return `InstanceAuth(${this.agentId})`;
  }

  override toJSON(): { agentId: string; issuer: string; kid: string } {
    return { ...super.toJSON(), kid: 'instance' };
  }
}

/** A device key's evidence: its signature over the nonce, the agent and the instance key, base64url. */
export async function deviceSignature(
  device: Signer,
  request: { nonce: string; agentId: string; thumbprint: string },
): Promise<string> {
  const message = `authfi-agent-attest\n${request.nonce}\n${request.agentId}\n${request.thumbprint}`;
  return base64url(await device.sign(new TextEncoder().encode(message)));
}
