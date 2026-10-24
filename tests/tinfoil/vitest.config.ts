import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const root = resolve(__dirname, "../..");

export default defineConfig({
  root,
  resolve: {
    alias: { "@": resolve(root, "src") },
  },
  test: {
    include: ["tests/tinfoil/**/*.test.ts"],
    environment: "node",
  },
});
