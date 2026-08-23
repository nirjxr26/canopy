import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    testTimeout: 20000,
    hookTimeout: 20000,
    // Safe since M-41: each worker owns a dedicated auuth_test_wN database.
    fileParallelism: true,
    // Keep the parallel DB burst reasonable for local Postgres instances.
    maxWorkers: 4,
  },
});
