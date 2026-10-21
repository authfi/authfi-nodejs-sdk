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
        'src/core/**': { lines: 90, branches: 85 },
      },
    },
  },
});
