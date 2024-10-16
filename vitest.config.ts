import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  test: {
    silent: true,
    globals: true,
    include: ['**/*.test.ts', '**/*.spec.ts'],
    environment: 'node',
    globalSetup: ['./vitest.global-setup.ts'],
    setupFiles: ['./vitest.setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      exclude: ['**/node_modules/**', '**/*.test.ts']
    },
    sequence: {
      shuffle: false,
      concurrent: false
    },
    poolOptions: {
      forks: {
        singleFork: true
      }
    }
  }
});
