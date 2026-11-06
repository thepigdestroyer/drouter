import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(__dirname, "../..");

function headingLevels(relPath: string): number[] {
  const source = fs.readFileSync(path.join(REPO_ROOT, relPath), "utf8");
  return [...source.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
}

describe("heading order on the public pages", () => {
  const PAGES = [
    "src/app/partners/page.tsx",
    "src/app/explain/page.tsx",
    "src/app/about/page.tsx",
    "src/components/landing/landing-page.tsx",
  ];

  it("starts with one h1 and never skips a level going down", () => {
    for (const page of PAGES) {
      const levels = headingLevels(page);
      expect(levels.filter((l) => l === 1), `${page} needs exactly one h1`).toHaveLength(1);
      expect(levels[0], `${page} must start with the h1`).toBe(1);
      for (let i = 1; i < levels.length; i++) {
        expect(
          levels[i],
          `${page}: heading ${i + 1} (h${levels[i]}) follows h${levels[i - 1]}`,
        ).toBeLessThanOrEqual(levels[i - 1] + 1);
      }
    }
  });
});
