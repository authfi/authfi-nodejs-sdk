#!/usr/bin/env node
// Fails when a README, doc, example or source message tells people to install from a release tarball nothing
// builds, or from a look-alike of the package name. The one install is `npm install @authfi/sdk`.
//
//   node scripts/check-install-text.mjs [--root <dir>]

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootArg = process.argv.indexOf('--root');
const root = rootArg === -1 ? fileURLToPath(new URL('..', import.meta.url)) : process.argv[rootArg + 1];
const SKIP = new Set(['node_modules', 'dist', 'coverage', '.git']);
const TEXT = /\.(md|mdx|txt|ts|mts|cts|js|mjs|cjs|json|yml|yaml)$/;
// This script and its test hold the bad examples on purpose.
const SELF = new Set(['scripts/check-install-text.mjs', 'test/scripts/install-text.test.ts']);

// A package manager's add/install verb followed, on the same line, by a name that is almost @authfi/sdk.
const LOOKALIKE =
  /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b[^\n]*?(?<![@\w/-])(?:authfi-sdk|authfi\/sdk|@authfi-sdk\/\w+)/;
const TARBALL = /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b[^\n]*(?:releases\/download|\.tgz)/;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else if (TEXT.test(name) && name !== 'package-lock.json') yield path;
  }
}

const problems = [];
for (const path of walk(root)) {
  const rel = relative(root, path).split(sep).join('/');
  if (SELF.has(rel)) continue;
  readFileSync(path, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      if (LOOKALIKE.test(line))
        problems.push(`${rel}:${i + 1}: installs a package that is not @authfi/sdk: ${line.trim()}`);
      else if (TARBALL.test(line))
        problems.push(`${rel}:${i + 1}: installs from a release tarball nothing builds: ${line.trim()}`);
    });
}

if (problems.length > 0) {
  process.stderr.write(`check-install-text: FAILED\n${problems.join('\n')}\n`);
  process.exit(1);
}
process.stdout.write('check-install-text: ok\n');
