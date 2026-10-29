import { appendFile } from 'node:fs/promises';
import { defineConfig } from 'tsup';

// One source, two module formats, generated types for each (so the types cannot drift from the code).
// `splitting` puts the core in shared chunks, so every subpath export uses the same classes.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    admin: 'src/admin/index.ts',
    express: 'src/express/index.ts',
    node: 'src/node/index.ts',
    signals: 'src/signals/index.ts',
    'vercel-ai': 'src/vercel-ai/index.ts',
    saml: 'src/saml/index.ts',
    langchain: 'src/langchain/index.ts',
    'openai-agents': 'src/openai-agents/index.ts',
    mastra: 'src/mastra/index.ts',
    otel: 'src/otel/index.ts',
  },
  format: ['esm', 'cjs'],
  target: 'es2022',
  platform: 'neutral',
  // node:* stays an import; only src/node uses it.
  esbuildOptions: (options) => {
    options.external = [...(options.external ?? []), 'node:*'];
  },
  // tsup sets baseUrl for its declaration build, which TypeScript 6 deprecates.
  dts: { compilerOptions: { ignoreDeprecations: '6.0' } },
  splitting: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['jose'],
  outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
  // 0.1 was used as `require('@authfi/sdk')(config)`. Keep that call working for one minor: the
  // CommonJS entry is the legacy factory, carrying every named export as a property.
  onSuccess: async () => {
    await appendFile(
      'dist/index.cjs',
      '\nmodule.exports = Object.assign(module.exports.default, module.exports);\n',
    );
  },
});
