/**
 * Node-only helpers: the agent's key file and building an agent from the environment. Everything
 * else in the SDK runs in edge runtimes and browsers too; this module reads the file system.
 *
 * @packageDocumentation
 */

/// <reference types="node" />

import { calculateJwkThumbprint, exportJWK, exportPKCS8 } from 'jose';
import { open } from 'node:fs/promises';
import { AgentKey, generatePair, type AgentAlgorithm } from '../agents/agent-key.js';
import type { AgentAuth } from '../agents/agent.js';
import { ConfigurationError } from '../core/errors.js';
import { consoleLogger, warnOnce } from '../core/logger.js';
import { coreOf, type AuthFI } from '../core/project.js';
import { Secret } from '../core/secret.js';

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
