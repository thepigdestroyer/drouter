import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(__dirname, "../..");

function read(relPath: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), "utf8");
}

function pageFiles(): string[] {
  const routes = fs
    .readdirSync(path.join(REPO_ROOT, "src/app"), {
      recursive: true,
      encoding: "utf8",
    })
    .filter((file) => /(^|[\\/])(page|not-found|error|global-error)\.tsx$/.test(file))
    .map((file) => path.posix.join("src/app", file.split(path.sep).join("/")));
  return [...routes, "src/components/landing/landing-page.tsx"];
}

describe("skip link", () => {
  it("jumps to #main-content", () => {
    const chrome = read("src/components/specimen-chrome.tsx");
    expect(chrome).toContain('href="#main-content"');
    expect(chrome).toContain('className="ep-skip-link"');
  });

  it("has a focusable <main id=\"main-content\"> on every page that shows the site header", () => {
    const files = pageFiles();
    const withHeader = files.filter((file) =>
      read(file).includes("<SpecimenHeader"),
    );
    const withMain = files.filter((file) => read(file).includes("<main"));

    // The ten sitemap routes, the home page component, the 404 and the error boundary.
    expect(withHeader.length).toBeGreaterThanOrEqual(12);
    for (const file of withHeader) {
      expect(withMain, `${file} shows the header but has no <main>`).toContain(
        file,
      );
    }

    for (const file of withMain) {
      const tags = [...read(file).matchAll(/<main\b[^>]*>/g)].map((m) => m[0]);
      for (const tag of tags) {
        expect(tag, `${file} <main> needs the skip link target id`).toContain(
          'id="main-content"',
        );
        expect(tag, `${file} <main> needs tabIndex={-1} to take focus`).toContain(
          "tabIndex={-1}",
        );
      }
    }
  });
});

describe("footer touch targets", () => {
  const chrome = read("src/components/specimen-chrome.tsx");
  const footer = chrome.slice(chrome.indexOf("export function SpecimenFooter"));

  it("gives every link in the footer navs the shared hit area class", () => {
    const navs = [...footer.matchAll(/<nav\b[\s\S]*?<\/nav>/g)].map((m) => m[0]);
    expect(navs).toHaveLength(2);
    for (const nav of navs) {
      const classNames = [
        ...nav.matchAll(/<(?:Link|a)\b[\s\S]*?className="([^"]*)"/g),
      ].map((m) => m[1]);
      expect(classNames.length).toBeGreaterThan(0);
      for (const className of classNames) {
        expect(className).toContain("ep-footer-link");
      }
    }
  });

  it("makes that hit area at least 24px tall (WCAG 2.5.8)", () => {
    const css = read("src/app/globals.css");
    const rule = css.match(/\.ep-footer-link\s*\{([^}]*)\}/)?.[1] ?? "";
    expect(rule).toMatch(/min-height:\s*(1\.5rem|24px)/);
  });
});

function allSourceFiles(): string[] {
  return fs
    .readdirSync(path.join(REPO_ROOT, "src"), { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".tsx"))
    .map((file) => path.posix.join("src", file.split(path.sep).join("/")));
}

describe("/explain game progress row", () => {
  const source = read("src/components/game/enclave-gauntlet.tsx");

  it("never gives a link an ARIA list role (not allowed on <a href>)", () => {
    for (const file of allSourceFiles()) {
      expect(read(file), file).not.toMatch(/<a\b[^>]*\brole="list(item)?"/);
    }
  });

  it("renders the rounds as a real list of links", () => {
    const row = source.match(
      /<ul\b[^>]*aria-label="Game rounds progress"[^>]*>([\s\S]*?)<\/ul>/,
    );
    expect(row, "progress row must be a <ul>").not.toBeNull();
    expect(row![1]).toMatch(/<li\b/);
    expect(row![1]).toMatch(/<a\b/);
    expect(row![1]).not.toMatch(/\brole="list(item)?"/);
  });
});

describe("failure chip text colour", () => {
  const css = read("src/app/globals.css");

  function token(name: string): string {
    const hex = css.match(new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6})`))?.[1];
    expect(hex, `--color-${name} must be a hex colour`).toBeDefined();
    return hex!.toLowerCase();
  }

  function channels(hex: string): [number, number, number] {
    return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];
  }

  function luminance(hex: string): number {
    const [r, g, b] = channels(hex).map((c) => {
      const s = c / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  function contrast(fg: string, bg: string): number {
    const [hi, lo] = [luminance(fg), luminance(bg)].sort((a, b) => b - a);
    return (hi + 0.05) / (lo + 0.05);
  }

  function hue(hex: string): number {
    const [r, g, b] = channels(hex).map((c) => c / 255);
    const max = Math.max(r, g, b);
    const delta = max - Math.min(r, g, b);
    if (delta === 0) return 0;
    const h =
      max === r ? ((g - b) / delta) % 6 : max === g ? (b - r) / delta + 2 : (r - g) / delta + 4;
    return (h * 60 + 360) % 360;
  }

  const rule = css.match(/\.ep-fail\s*\{([^}]*)\}/)?.[1] ?? "";

  it("keeps the accent orange for fills, borders and graphics", () => {
    expect(token("accent")).toBe("#d9531e");
    expect(token("accent-soft")).toBe("#f6e3d8");
    expect(rule).toMatch(/border:\s*1px solid var\(--color-accent\)/);
    expect(rule).toMatch(/background:\s*var\(--color-accent-soft\)/);
  });

  it("reaches 4.5:1 on the chip background with a text-only orange of the same hue", () => {
    const name = rule.match(/^\s*color:\s*var\(--color-([a-z-]+)\)/m)?.[1];
    expect(name, ".ep-fail needs a text colour token").toBeDefined();
    expect(name, "the base accent is too light for 11px text").not.toBe("accent");

    const text = token(name!);
    expect(contrast(text, token("accent-soft"))).toBeGreaterThanOrEqual(4.5);
    expect(Math.abs(hue(text) - hue(token("accent")))).toBeLessThanOrEqual(3);
  });
});
