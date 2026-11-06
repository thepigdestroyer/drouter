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
