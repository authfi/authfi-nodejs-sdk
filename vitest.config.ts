import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'node',
          include: ['test/**/*.test.ts'],
          exclude: ['test/live/**', 'test/edge/**'],
          environment: 'node',
        },
      },
      {
        extends: true,
        test: {
          name: 'edge',
          include: ['test/edge/**/*.test.ts'],
          environment: 'edge-runtime',
        },
      },
      {
        extends: true,
        test: {
          name: 'live',
          include: ['test/live/**/*.test.ts'],
          environment: 'node',
          testTimeout: 600_000,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts'],
      reporter: ['text', 'json-summary', 'html'],
      thresholds: {
        // Design §6.5: the verifier and the protocol code at 95% branches, the rest of the core at
        // 90% lines, adapters at 85% lines.
        'src/verify/**': { lines: 95, branches: 95 },
        'src/core/oauth.ts': { lines: 95, branches: 90 },
        'src/agents/**': { lines: 95, branches: 95 },
        'src/core/**': { lines: 90, branches: 85 },
        'src/node/**': { lines: 90 },
        'src/machine/**': { lines: 90, branches: 90 },
        'src/express/**': { lines: 85 },
        'src/gateway/**': { lines: 95, branches: 90 },
        'src/vercel-ai/**': { lines: 85 },
      },
    },
  },
});
