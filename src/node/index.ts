/**
 * Node-only helpers: the agent's key file and building an agent from the environment. Everything
 * else in the SDK runs in edge runtimes and browsers too; this module reads the file system.
 *
 * @packageDocumentation
 */

/// <reference types="node" />

import { calculateJwkThumbprint, exportJWK, exportPKCS8 } from 'jose';
import { open, readFile, stat } from 'node:fs/promises';
import { AgentKey, generatePair, type AgentAlgorithm } from '../agents/agent-key.js';
import type { AgentAuth } from '../agents/agent.js';
import { deviceSignature, InstanceAuth, type Configuration, type Evidence } from '../agents/instance.js';
import { ConfigurationError } from '../core/errors.js';
import { consoleLogger, warnOnce } from '../core/logger.js';
import { AuthFI, coreOf, type AuthFIOptions } from '../core/project.js';
import { ClientCredentials } from '../machine/client-credentials.js';
import { Secret } from '../core/secret.js';
import type { OpenTelemetryApi } from '../core/transport.js';
import { decodeUnverified } from '../verify/verifier.js';

const POSIX = process.platform !== 'win32';
const WINDOWS_ACL =
  'the agent key file permission check is POSIX-only; on Windows, keep the key file readable by this account alone';
const warned = new Set<string>();

/**
 * Reads an agent's private key from a file: a PKCS#8 PEM (give `kid`, the key id registered with
 * it) or a private JWK (its own `kid` is used unless one is given).
 *
 * On POSIX it refuses a file that group or others can read: `chmod 600` it. Node has no ACL API on
 * Windows, so there the check is skipped and a warning says so once: on the project's logger when
 * `af` is given, else on the console.
 *
 * The file is opened once and the permissions are read from that open file, so a path replaced
 * between the check and the read cannot slip another file past the check.
 */
export async function readAgentKey(
  path: string,
  options: { kid?: string; af?: AuthFI } = {},
): Promise<AgentKey> {
  const file = await open(path, 'r');
  let text: string;
  try {
    const info = await file.stat();
    if (POSIX && (info.mode & 0o077) !== 0) {
      throw new ConfigurationError(
        `the agent key file ${path} is readable by others (mode ${(info.mode & 0o777).toString(8)}); run: chmod 600 ${path}`,
      );
    }
    if (!POSIX) {
      if (options.af !== undefined) coreOf(options.af).warnOnce('key-file-acl', WINDOWS_ACL);
      else warnOnce(consoleLogger, warned, 'key-file-acl', WINDOWS_ACL);
    }
    text = (await file.readFile('utf8')).trim();
  } finally {
    await file.close();
  }
  if (text === '') throw new ConfigurationError(`the agent key file ${path} is empty`);
  if (text.startsWith('{')) {
    let jwk: JsonWebKey & { kid?: string };
    try {
      jwk = JSON.parse(text) as JsonWebKey & { kid?: string };
    } catch {
      throw new ConfigurationError(`the agent key file ${path} is neither a PEM nor a JWK`);
    }
    return AgentKey.fromJwk(jwk, options.kid === undefined ? {} : { kid: options.kid });
  }
  if (options.kid === undefined || options.kid === '') {
    throw new ConfigurationError(
      `kid is required for the PEM key ${path}: the key id registered with its public key`,
    );
  }
  return AgentKey.fromPem(new Secret(text), { kid: options.kid });
}

/**
 * Makes a new agent key and writes its private half to `path`, a new file readable by its owner only
 * (mode 0600). It refuses to overwrite an existing file. The key it returns can sign and cannot be
 * written again: this is the one way a private key leaves the SDK, and it leaves into the file and
 * nowhere else. Register the returned key's `publicJwk()` in the console.
 *
 * @param options.kid The key id to register; defaults to the RFC 7638 thumbprint of the public key.
 */
export async function generateAgentKeyFile(
  path: string,
  alg: AgentAlgorithm = 'EdDSA',
  options: { kid?: string } = {},
): Promise<AgentKey> {
  const pair = await generatePair(alg);
  const kid = options.kid ?? (await calculateJwkThumbprint(await exportJWK(pair.publicKey), 'sha256'));
  const pem = new Secret(await exportPKCS8(pair.privateKey));
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(pem.reveal(), 'utf8');
  } finally {
    await file.close();
  }
  return AgentKey.fromPem(pem, { kid });
}

const set = (v: string | undefined): v is string => v !== undefined && v !== '';

/** The environment `agentFromEnv` reads. */
export interface AgentEnv {
  readonly AUTHFI_AGENT_ID?: string | undefined;
  readonly AUTHFI_AGENT_KID?: string | undefined;
  readonly AUTHFI_AGENT_KEY_FILE?: string | undefined;
  readonly AUTHFI_AGENT_PRIVATE_KEY?: string | undefined;
  readonly AUTHFI_AGENT_RESOURCE?: string | undefined;
}

/**
 * Builds the agent from the environment, on a project from `AuthFI.fromEnv()`:
 *
 * - `AUTHFI_AGENT_ID`, and `AUTHFI_AGENT_KID` for a PEM key;
 * - `AUTHFI_AGENT_KEY_FILE`, the path of the key file (the default, and the documented way);
 * - `AUTHFI_AGENT_PRIVATE_KEY`, the PEM itself, only for a runtime with no file system. An
 *   environment variable is inherited by child processes and copied into crash dumps, so reading it
 *   warns once. When both are set, the file wins;
 * - `AUTHFI_AGENT_RESOURCE`, optional.
 */
export async function agentFromEnv(af: AuthFI, env: AgentEnv = process.env): Promise<AgentAuth> {
  const agentId = env.AUTHFI_AGENT_ID;
  if (agentId === undefined || agentId === '') throw new ConfigurationError('AUTHFI_AGENT_ID is not set');
  const kid = env.AUTHFI_AGENT_KID === '' ? undefined : env.AUTHFI_AGENT_KID;
  let key: AgentKey;
  if (env.AUTHFI_AGENT_KEY_FILE !== undefined && env.AUTHFI_AGENT_KEY_FILE !== '') {
    key = await readAgentKey(env.AUTHFI_AGENT_KEY_FILE, kid === undefined ? { af } : { kid, af });
  } else if (env.AUTHFI_AGENT_PRIVATE_KEY !== undefined && env.AUTHFI_AGENT_PRIVATE_KEY !== '') {
    coreOf(af).warnOnce(
      'key-in-env',
      'AUTHFI_AGENT_PRIVATE_KEY puts the private key in the environment, where child processes and crash dumps see it; mount it as a 0600 file and set AUTHFI_AGENT_KEY_FILE',
    );
    if (kid === undefined)
      throw new ConfigurationError('AUTHFI_AGENT_KID is required with AUTHFI_AGENT_PRIVATE_KEY');
    key = await AgentKey.fromPem(new Secret(env.AUTHFI_AGENT_PRIVATE_KEY), { kid });
  } else {
    throw new ConfigurationError(
      "no agent key: set AUTHFI_AGENT_KEY_FILE to the path of the agent's private key",
    );
  }
  const resource = env.AUTHFI_AGENT_RESOURCE === '' ? undefined : env.AUTHFI_AGENT_RESOURCE;
  return af.agent({ agentId, key, resource });
}

/** Where a Kubernetes pod finds its projected service-account token. */
export const K8S_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';

/** The environment an instance signs in from; see {@link instanceFromEnv}. */
export interface InstanceEnv {
  readonly AUTHFI_AGENT_ID?: string | undefined;
  readonly AUTHFI_AGENT_RESOURCE?: string | undefined;
  /** The projected service-account token, when it is not at the standard path. */
  readonly AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE?: string | undefined;
  /** The device key file the device was bound with, and its key id. */
  readonly AUTHFI_DEVICE_KEY_FILE?: string | undefined;
  readonly AUTHFI_DEVICE_KEY_KID?: string | undefined;
  /** The signed configuration the instance runs: its approved version and `sha256:<hex>` digest. */
  readonly AUTHFI_CONFIG_VERSION?: string | undefined;
  readonly AUTHFI_CONFIG_DIGEST?: string | undefined;
  /** The image the instance runs, `sha256:<hex>`. */
  readonly AUTHFI_IMAGE_DIGEST?: string | undefined;
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function audiencesOf(token: string): string[] {
  const aud = decodeUnverified(token).payload.aud;
  if (typeof aud === 'string') return [aud];
  return Array.isArray(aud) ? (aud as unknown[]).filter((a): a is string => typeof a === 'string') : [];
}

/** Evidence from a projected service-account token: the file is read again for every attestation. */
function kubernetesEvidence(path: string): Evidence {
  let last: string | undefined;
  return {
    kind: 'k8s',
    async token({ issuer }) {
      let token: string;
      try {
        token = (await readFile(path, 'utf8')).trim();
      } catch (cause) {
        throw new ConfigurationError(
          `cannot read the evidence file ${path} (${cause instanceof Error ? cause.message : String(cause)}). On Kubernetes project a service-account token there (audience ${new URL(issuer).origin}, expirationSeconds 600), or set AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE to where it is.`,
        );
      }
      if (token === '') throw new ConfigurationError(`the evidence file ${path} is empty`);
      let audiences: string[];
      try {
        audiences = audiencesOf(token);
      } catch {
        throw new ConfigurationError(`${path} does not hold a service-account JWT`);
      }
      if (!audiences.some((a) => a === issuer || a === new URL(issuer).origin)) {
        throw new ConfigurationError(
          `the service-account token in ${path} is for ${audiences.length === 0 ? 'no audience' : audiences.join(', ')}, not ${new URL(issuer).origin}. Project one with audience ${new URL(issuer).origin}.`,
        );
      }
      if (token === last) {
        throw new ConfigurationError(
          `the service-account token in ${path} has not rotated since it was used, and it works once. Project it with expirationSeconds: 600 so the kubelet renews it every 8 minutes.`,
        );
      }
      last = token;
      return token;
    },
  };
}

/** Evidence from a device key: its signature over the nonce, the agent and the instance key. */
function deviceEvidence(path: string, kid: string | undefined): Evidence {
  return {
    kind: 'device',
    async token(request) {
      let device: AgentKey;
      try {
        device = await readAgentKey(path, kid === undefined ? {} : { kid });
      } catch (cause) {
        throw new ConfigurationError(
          `cannot use the device key ${path}: ${cause instanceof Error ? cause.message : String(cause)}. Set AUTHFI_DEVICE_KEY_FILE to the key file the device was bound with and AUTHFI_DEVICE_KEY_KID to its key id.`,
        );
      }
      return deviceSignature(device, request);
    },
  };
}

/**
 * The evidence this process can show of where it runs, or undefined: the device key if
 * `AUTHFI_DEVICE_KEY_FILE` names one, else the projected service-account token at the standard path (or
 * `AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE`).
 */
export async function findEvidence(env: InstanceEnv = process.env): Promise<Evidence | undefined> {
  if (set(env.AUTHFI_DEVICE_KEY_FILE)) {
    return deviceEvidence(
      env.AUTHFI_DEVICE_KEY_FILE,
      set(env.AUTHFI_DEVICE_KEY_KID) ? env.AUTHFI_DEVICE_KEY_KID : undefined,
    );
  }
  if (set(env.AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE))
    return kubernetesEvidence(env.AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE);
  return (await isFile(K8S_TOKEN_PATH)) ? kubernetesEvidence(K8S_TOKEN_PATH) : undefined;
}

function configurationOf(env: InstanceEnv): Configuration | undefined {
  const version = env.AUTHFI_CONFIG_VERSION?.trim() ?? '';
  const digest = env.AUTHFI_CONFIG_DIGEST?.trim() ?? '';
  if (version === '' && digest === '') return undefined;
  if (!/^\d+$/.test(version) || !digest.startsWith('sha256:')) {
    throw new ConfigurationError(
      `AUTHFI_CONFIG_VERSION is the approved version number and AUTHFI_CONFIG_DIGEST is sha256:<hex>; got ${JSON.stringify(version)} and ${JSON.stringify(digest)}`,
    );
  }
  return { version: Number(version), digest };
}

const NO_EVIDENCE = `this agent shows no evidence of where it runs: on Kubernetes project a service-account token at ${K8S_TOKEN_PATH} (or name it in AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE); on a device set AUTHFI_DEVICE_KEY_FILE`;

/**
 * The agent instance the environment names, signing in by attestation: `AUTHFI_AGENT_ID`, the evidence
 * ({@link findEvidence}), and the configuration it runs (`AUTHFI_CONFIG_VERSION`, `AUTHFI_CONFIG_DIGEST`;
 * `AUTHFI_IMAGE_DIGEST` for its image). It throws a {@link ConfigurationError} that names what is missing.
 */
export async function instanceFromEnv(af: AuthFI, env: InstanceEnv = process.env): Promise<InstanceAuth> {
  const agentId = env.AUTHFI_AGENT_ID?.trim() ?? '';
  if (agentId === '') throw new ConfigurationError('AUTHFI_AGENT_ID is not set');
  const evidence = await findEvidence(env);
  if (evidence === undefined) throw new ConfigurationError(NO_EVIDENCE);
  const config = configurationOf(env);
  if (config === undefined) {
    throw new ConfigurationError(
      'an instance runs one approved configuration: set AUTHFI_CONFIG_VERSION and AUTHFI_CONFIG_DIGEST (sha256:<hex>). The platform attests no instance without one.',
    );
  }
  const image = env.AUTHFI_IMAGE_DIGEST?.trim();
  const resource = env.AUTHFI_AGENT_RESOURCE?.trim();
  return new InstanceAuth(af, {
    agentId,
    evidence,
    config,
    imageDigest: image === undefined || image === '' ? undefined : image,
    resource: resource === undefined || resource === '' ? undefined : resource,
  });
}

/** The environment `connect` reads: the project, then an instance, an agent key or a client id and secret. */
export interface ConnectEnv extends AgentEnv, InstanceEnv {
  readonly AUTHFI_ISSUER?: string | undefined;
  readonly AUTHFI_API_ORIGIN?: string | undefined;
  readonly AUTHFI_CLIENT_ID?: string | undefined;
  readonly AUTHFI_CLIENT_SECRET?: string | undefined;
}

/** What {@link connect} returns: a credential with gateways, and the project it belongs to. */
export type Connection = AgentAuth | ClientCredentials;

/** The app's `@opentelemetry/api`, when installed: calls then carry the active trace to the gateway. */
async function optionalOtel(): Promise<OpenTelemetryApi | undefined> {
  try {
    return await import('@opentelemetry/api');
  } catch {
    return undefined;
  }
}

/**
 * One call from the environment to a credential the gateways accept, for the Vercel AI adapter and
 * `registerAuthFITelemetry`:
 *
 * - `AUTHFI_ISSUER` (and `AUTHFI_API_ORIGIN` when the APIs are on another origin), always;
 * - an agent, the default: `AUTHFI_AGENT_ID`. On a bound workload it signs in as an instance: it finds its
 *   evidence itself (the projected service-account token, or `AUTHFI_DEVICE_KEY_FILE`) and the configuration
 *   it runs (`AUTHFI_CONFIG_VERSION`, `AUTHFI_CONFIG_DIGEST`), as {@link instanceFromEnv} reads them, and holds
 *   no key to keep. Otherwise, legacy, with `AUTHFI_AGENT_KEY_FILE` (or `AUTHFI_AGENT_PRIVATE_KEY` and
 *   `AUTHFI_AGENT_KID`), as {@link agentFromEnv} reads them. An agent key file named with no configuration is
 *   the legacy key, as it always was, even on a pod that has a service-account token;
 * - else a machine client: `AUTHFI_CLIENT_ID` with `AUTHFI_CLIENT_SECRET`. Its calls reach the
 *   gateways as a client, with no agent id.
 *
 * When `@opentelemetry/api` is installed it is given to the project, so each gateway call carries the
 * active trace and a step exported by `registerAuthFITelemetry` joins the gateway's record of it.
 *
 * An agent id wins when both are set. With neither, or a client id and no secret, it throws a
 * {@link ConfigurationError} naming the variable that is missing.
 *
 * @example
 * const credential = await connect();
 * const authfi = createVercelAI({ source: credential, approvalSecret });
 */
export async function connect(
  env: ConnectEnv = process.env,
  options: Partial<AuthFIOptions> = {},
): Promise<Connection> {
  const otel = options.otel ?? (await optionalOtel());
  const af = AuthFI.fromEnv(
    { AUTHFI_ISSUER: env.AUTHFI_ISSUER, AUTHFI_API_ORIGIN: env.AUTHFI_API_ORIGIN },
    otel === undefined ? options : { ...options, otel },
  );
  if (set(env.AUTHFI_AGENT_ID)) {
    const names = set(env.AUTHFI_AGENT_KEY_FILE) || set(env.AUTHFI_AGENT_PRIVATE_KEY);
    const configured = set(env.AUTHFI_CONFIG_VERSION) || set(env.AUTHFI_CONFIG_DIGEST);
    if ((await findEvidence(env)) !== undefined && (configured || !names)) return instanceFromEnv(af, env);
    if (!names) {
      throw new ConfigurationError(
        'AUTHFI_AGENT_ID is set but the agent has no way to sign in: bind its workload and run it there (a projected service-account token, or AUTHFI_DEVICE_KEY_FILE), or, legacy, set AUTHFI_AGENT_KEY_FILE',
      );
    }
    coreOf(af).warnOnce(
      'legacy-agent-key',
      "signing in with a long-lived agent key (legacy): bind the agent's workload to sign in by instance attestation, with no key to keep",
    );
    return agentFromEnv(af, env);
  }
  if (set(env.AUTHFI_CLIENT_ID)) {
    if (!set(env.AUTHFI_CLIENT_SECRET))
      throw new ConfigurationError('AUTHFI_CLIENT_SECRET is not set (AUTHFI_CLIENT_ID is)');
    return new ClientCredentials(
      af,
      { clientId: env.AUTHFI_CLIENT_ID, clientSecret: new Secret(env.AUTHFI_CLIENT_SECRET) },
      { quiet: true },
    );
  }
  throw new ConfigurationError(
    'no credential: set AUTHFI_AGENT_ID with AUTHFI_AGENT_KEY_FILE, or AUTHFI_CLIENT_ID with AUTHFI_CLIENT_SECRET',
  );
}
