#!/usr/bin/env node
// Bundles every runtime-neutral entry for the browser and fails on any Node built-in, so a Node-only
// import cannot slip into the core, the verifier or the agent module unnoticed.

import { build } from 'esbuild';

const ENTRIES = ['src/index.ts', 'src/express/index.ts', 'src/signals/index.ts', 'src/vercel-ai/index.ts'];

process.stdout.write(`check-browser-bundle: bundling ${ENTRIES.join(', ')} for platform=browser\n`);
const result = await build({
  entryPoints: ENTRIES,
  bundle: true,
  write: false,
  platform: 'browser',
  format: 'esm',
  logLevel: 'silent',
  metafile: true,
  outdir: 'browser-check',
}).catch((e) => {
  process.stderr.write(`check-browser-bundle: FAILED: ${e.message}\n`);
  process.exit(1);
});
const nodeImports = Object.values(result.metafile.inputs)
  .flatMap((i) => i.imports)
  .filter((imp) => imp.path.startsWith('node:') || imp.external);
if (nodeImports.length > 0) {
  process.stderr.write(
    `check-browser-bundle: FAILED: Node built-ins in the bundle: ${nodeImports.map((i) => i.path).join(', ')}\n`,
  );
  process.exit(1);
}
const bytes = result.outputFiles.reduce((n, f) => n + f.contents.byteLength, 0);
process.stdout.write(`check-browser-bundle: ok, ${bytes} bytes, no Node built-ins\n`);
