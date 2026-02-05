import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 180000, // 3 minutes for proof generation
    hookTimeout: 120000,  // 2 minutes for setup/teardown (Barretenberg WASM init)
    pool: 'forks', // Use forks to ensure clean process isolation
    poolOptions: {
      forks: {
        singleFork: true, // Run in a single fork to maintain state between tests
      },
    },
    // Don't transform @aztec/bb.js - it needs native ESM module resolution for WASM loading
    deps: {
      optimizer: {
        ssr: {
          exclude: ['@aztec/bb.js'],
        },
      },
    },
    server: {
      deps: {
        external: ['@aztec/bb.js'],
      },
    },
  },
});
