import { defineConfig } from 'tsup';

// One source, two module formats, generated types for each (so the types cannot drift from the code).
// `splitting` keeps one copy of the core per format, so every subpath export shares its classes.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  target: 'es2022',
  platform: 'neutral',
  // tsup sets baseUrl for its declaration build, which TypeScript 6 deprecates.
  dts: { compilerOptions: { ignoreDeprecations: '6.0' } },
  splitting: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['jose'],
  outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
