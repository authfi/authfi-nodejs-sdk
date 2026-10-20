#!/usr/bin/env node
// Loads the ESM and the CommonJS build together, as an app does when one file `import`s the SDK and
// another `require`s it, and checks that what the SDK recognises by brand it recognises across the
// two copies. `instanceof` is false between them, so a class check would refuse a real Secret.

import { createRequire } from 'node:module';

const esm = await import(new URL('../dist/index.js', import.meta.url).href);
const cjs = createRequire(import.meta.url)('../dist/index.cjs');

let checks = 0;

function fail(message) {
  process.stderr.write(`check-dual-package: FAILED: ${message}\n`);
  process.exit(1);
}

function check(ok, message) {
  checks += 1;
  if (!ok) fail(message);
}

check(esm.Secret !== cjs.Secret, 'the two builds share one class; the check would prove nothing');
const fromCjs = new cjs.Secret('s3cret');
const fromEsm = new esm.Secret('s3cret');
check(!(fromCjs instanceof esm.Secret), 'instanceof crossed the builds; the check would prove nothing');
check(esm.isSecret(fromCjs), 'the ESM build does not recognise a Secret made by the CommonJS build');
check(cjs.isSecret(fromEsm), 'the CommonJS build does not recognise a Secret made by the ESM build');
check(!esm.isSecret({ reveal: () => 'x' }), 'a look-alike without the brand was taken for a Secret');

process.stdout.write(`check-dual-package: ok, ${String(checks)} checks across the two builds\n`);
