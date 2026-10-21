#!/usr/bin/env node
// Installs the oldest version each peer dependency range allows (without touching package.json), so
// CI can run the suite against the floor we claim to support, not only against what npm resolves today.
//
//   node scripts/install-lowest-peers.mjs          install them
//   node scripts/install-lowest-peers.mjs --print  print what would be installed

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

/** The lowest version a range such as `>=4.21 <6`, `^7.0.80` or `7.0.80` admits. */
export function lowestOf(range) {
  const m = /^\s*(?:>=|\^|~)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*(?:$|\s)/.exec(range);
  if (m === null) throw new Error(`cannot find the lowest version in the range "${range}"`);
  return `${m[1]}.${m[2] ?? '0'}.${m[3] ?? '0'}`;
}

const specs = Object.entries(pkg.peerDependencies ?? {}).map(([name, range]) => `${name}@${lowestOf(range)}`);

if (process.argv.includes('--print')) {
  process.stdout.write(`${specs.join('\n')}\n`);
} else if (specs.length > 0) {
  execFileSync('npm', ['install', '--no-save', '--legacy-peer-deps', '--no-audit', '--no-fund', ...specs], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
}
