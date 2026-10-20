import { generateKeyPairSync } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { agentFromEnv, readAgentKey, writeAgentKey } from '../../src/node/index.js';
import { ISSUER } from '../support/issuer.js';

const POSIX = process.platform !== 'win32';
let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'authfi-key-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function project() {
  const warns: string[] = [];
  const af = new AuthFI({
    issuer: ISSUER,
    logger: { debug() {}, info() {}, warn: (m) => warns.push(m), error() {} },
  });
  return { af, warns };
}

describe('key files', () => {
  it('writes a generated key once, owner-only, and reads it back', async () => {
    const key = await AgentKey.generate('ES256', { kid: 'k1' });
    const path = join(dir, 'agent.pem');
    await writeAgentKey(path, key);
    if (POSIX) expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(await readFile(path, 'utf8')).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    await expect(writeAgentKey(path, key)).rejects.toMatchObject({ code: 'EEXIST' });
    const back = await readAgentKey(path, { kid: 'k1' });
    expect(back.publicJwk()).toEqual(key.publicJwk());
  });

  it.runIf(POSIX)('refuses a key file others can read', async () => {
    const path = join(dir, 'open.pem');
    await writeFile(path, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }));
    await chmod(path, 0o644);
    await expect(readAgentKey(path, { kid: 'k' })).rejects.toThrow(`chmod 600 ${path}`);
  });

  it.runIf(!POSIX)('warns once on Windows that the permission check is POSIX-only', async () => {
    const { af, warns } = project();
    const path = join(dir, 'k.pem');
    await writeFile(path, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }));
    await readAgentKey(path, { kid: 'k', af });
    await readAgentKey(path, { kid: 'k', af });
    expect(warns.filter((w) => w.includes('POSIX-only'))).toHaveLength(1);
  });

  it('reads a JWK file with its own kid, and refuses an empty file, a PEM without kid, and junk', async () => {
    const jwkPath = join(dir, 'k.json');
    const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
    await writeFile(jwkPath, JSON.stringify({ ...jwk, kid: 'from-file' }), { mode: 0o600 });
    expect((await readAgentKey(jwkPath)).kid).toBe('from-file');
    const empty = join(dir, 'empty.pem');
    await writeFile(empty, '', { mode: 0o600 });
    await expect(readAgentKey(empty)).rejects.toThrow('is empty');
    const pem = join(dir, 'nokid.pem');
    await writeFile(pem, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
    });
    await expect(readAgentKey(pem)).rejects.toThrow('kid is required');
    const junk = join(dir, 'junk.json');
    await writeFile(junk, '{not json', { mode: 0o600 });
    await expect(readAgentKey(junk)).rejects.toThrow('neither a PEM nor a JWK');
  });
});

describe('agentFromEnv', () => {
  it('reads the key file, which wins over the inline PEM', async () => {
    const { af, warns } = project();
    const path = join(dir, 'agent.pem');
    await writeAgentKey(path, await AgentKey.generate('EdDSA', { kid: 'file-kid' }));
    const agent = await agentFromEnv(af, {
      AUTHFI_AGENT_ID: 'agt_1',
      AUTHFI_AGENT_KID: 'file-kid',
      AUTHFI_AGENT_KEY_FILE: path,
      AUTHFI_AGENT_PRIVATE_KEY: 'ignored',
    });
    expect(agent.agentId).toBe('agt_1');
    expect(warns.some((w) => w.includes('AUTHFI_AGENT_PRIVATE_KEY'))).toBe(false);
  });

  it('warns once when the key is in the environment', async () => {
    const { af, warns } = project();
    const pem = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const env = {
      AUTHFI_AGENT_ID: 'agt_1',
      AUTHFI_AGENT_KID: 'k',
      AUTHFI_AGENT_PRIVATE_KEY: pem,
      AUTHFI_AGENT_RESOURCE: `${ISSUER}/mcp`,
    };
    await agentFromEnv(af, env);
    await agentFromEnv(af, env);
    expect(warns.filter((w) => w.includes('AUTHFI_AGENT_PRIVATE_KEY'))).toHaveLength(1);
    expect(warns.join()).not.toContain(pem.split('\n')[1]);
  });

  it('names what is missing', async () => {
    const { af } = project();
    await expect(agentFromEnv(af, {})).rejects.toThrow('AUTHFI_AGENT_ID');
    await expect(agentFromEnv(af, { AUTHFI_AGENT_ID: 'agt_1' })).rejects.toThrow('AUTHFI_AGENT_KEY_FILE');
    await expect(
      agentFromEnv(af, { AUTHFI_AGENT_ID: 'agt_1', AUTHFI_AGENT_PRIVATE_KEY: 'x' }),
    ).rejects.toThrow('AUTHFI_AGENT_KID');
  });
});
