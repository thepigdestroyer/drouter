import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

export default defineConfig({
  root: repoRoot,
  resolve: {
    alias: [{ find: /^@\//, replacement: path.join(repoRoot, "src") + "/" }],
  },
  test: {
    environment: "node",
    include: ["src/components/audit/**/*.test.ts"],
  },
});
