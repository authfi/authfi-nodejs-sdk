import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const scriptPath = fileURLToPath(new URL('../../scripts/check-install-text.mjs', import.meta.url));
const dirs: string[] = [];

function check(files: Record<string, string>): { status: number | null; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), 'install-text-'));
  dirs.push(dir);
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  const r = spawnSync(process.execPath, [scriptPath, '--root', dir], { encoding: 'utf8' });
  return { status: r.status, stderr: r.stderr };
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('install text', () => {
  it('this repository tells people to install from git only', () => {
    expect(() => execFileSync(process.execPath, [scriptPath], { encoding: 'utf8' })).not.toThrow();
  });

  it.each([
    ['README.md', 'npm install @authfi/sdk\n'],
    ['examples/a/README.md', 'npm i @authfi/sdk express\n'],
    ['docs/x.md', 'pnpm add @authfi/sdk\n'],
    ['src/m.ts', "throw new Error('run: yarn add @authfi/sdk');\n"],
    ['README.md', 'npm install https://github.com/authfi/authfi-nodejs-sdk/releases/download/v1/a.tgz\n'],
  ])('refuses %s containing %j', (name, text) => {
    const r = check({ [name]: text });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(name);
  });

  it('accepts the git install', () => {
    expect(check({ 'README.md': 'npm install github:authfi/authfi-nodejs-sdk#v0.2.0 ai\n' }).status).toBe(0);
  });
});
