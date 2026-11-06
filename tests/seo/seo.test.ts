import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import robots from "@/app/robots";
import sitemap from "@/app/sitemap";
import { SIGNED_OUT_NAV_ITEMS } from "@/components/specimen-chrome";
import {
  INDEXABLE_PAGES,
  INDEXNOW_KEY,
  PERSON_ID,
  SEO_PAGES,
  SITE_URL,
  canonicalUrl,
  homeJsonLd,
  pageMetadata,
  serializeJsonLd,
  subPageJsonLd,
} from "@/lib/seo";

const REPO_ROOT = path.resolve(__dirname, "../..");

function isNoindex(pagePath: string): boolean {
  const robotsMeta = pageMetadata(pagePath).robots;
  return (
    typeof robotsMeta === "object" &&
    robotsMeta !== null &&
    robotsMeta.index === false
  );
}

describe("page metadata", () => {
  it("gives every route a unique title and description inside the limits", () => {
    const titles = new Set<string>();
    const descriptions = new Set<string>();
    for (const page of SEO_PAGES) {
      expect(page.title.length, page.path).toBeLessThanOrEqual(60);
      expect(page.description.length, page.path).toBeGreaterThanOrEqual(140);
      expect(page.description.length, page.path).toBeLessThanOrEqual(160);
      expect(page.title.endsWith("| deRoute"), page.path).toBe(true);
      expect(`${page.title}${page.description}`).not.toMatch(/[\u2013\u2014]/);
      titles.add(page.title);
      descriptions.add(page.description);
    }
    expect(titles.size).toBe(SEO_PAGES.length);
    expect(descriptions.size).toBe(SEO_PAGES.length);
  });

  it("sets an absolute self-canonical and complete social tags", () => {
    for (const page of SEO_PAGES) {
      const meta = pageMetadata(page.path);
      const url = canonicalUrl(page.path);
      expect(url.startsWith(`${SITE_URL}/`) || url === SITE_URL).toBe(true);
      expect(meta.alternates?.canonical).toBe(url);
      expect(meta.openGraph).toMatchObject({
        url,
        siteName: "deRoute",
        locale: "en_GB",
        type: "website",
      });
      expect(meta.openGraph).toMatchObject({
        images: [
          {
            url: `${SITE_URL}/opengraph-image.png`,
            width: 1200,
            height: 630,
          },
        ],
      });
      expect(meta.twitter).toMatchObject({ card: "summary_large_image" });
    }
  });

  it("has an app layout for every non-home route that exports its metadata", () => {
    for (const page of SEO_PAGES.filter((p) => p.path !== "/")) {
      const file = path.join(REPO_ROOT, "src/app", page.path, "layout.tsx");
      const source = fs.readFileSync(file, "utf8");
      expect(source).toContain(`const PATH = "${page.path}"`);
      expect(source).toContain("pageMetadata(PATH)");
      expect(source).toContain("subPageJsonLd(PATH)");
    }
  });
});

describe("signed-out content", () => {
  it("renders a server-side heading and lead on every sign-in gated page", () => {
    for (const route of ["argon", "audit", "network", "account"]) {
      const source = fs.readFileSync(
        path.join(REPO_ROOT, "src/app", route, "page.tsx"),
        "utf8",
      );
      expect(source, route).toMatch(/<AuthGate\s+intro=/);
    }
    const gate = fs.readFileSync(
      path.join(REPO_ROOT, "src/components/auth/auth-gate.tsx"),
      "utf8",
    );
    expect(gate).toContain("<h1");
  });
});

describe("JSON-LD", () => {
  it("parses on the home page and references the person @id", () => {
    const raw = serializeJsonLd(homeJsonLd());
    const data = JSON.parse(raw);
    const graph: Array<Record<string, unknown>> = data["@graph"];
    const types = graph.map((node) => node["@type"]);
    expect(types).toEqual(
      expect.arrayContaining(["WebSite", "SoftwareApplication", "WebPage"]),
    );
    const app = graph.find((n) => n["@type"] === "SoftwareApplication")!;
    expect(app.name).toBe("deRoute");
    expect(app.applicationCategory).toBe("SecurityApplication");
    expect(app.operatingSystem).toBe("Web");
    expect(app.award).toBe("Winner, Agents That Ship track, Encode London 2026");
    expect(app.author).toMatchObject({ "@id": PERSON_ID, name: "Mrinal Joshi" });
    expect(app.creator).toMatchObject({ "@id": PERSON_ID });
    expect(raw).not.toMatch(/aggregateRating|offers|"price"/);
  });

  it("escapes angle brackets so the script tag cannot be closed early", () => {
    expect(serializeJsonLd({ a: "</script>" })).not.toContain("<");
  });

  it("describes every sub-page with WebPage and BreadcrumbList", () => {
    for (const page of SEO_PAGES.filter((p) => p.path !== "/")) {
      const data = JSON.parse(serializeJsonLd(subPageJsonLd(page.path)));
      const graph: Array<Record<string, unknown>> = data["@graph"];
      expect(graph.map((n) => n["@type"])).toEqual([
        "WebPage",
        "BreadcrumbList",
      ]);
      expect(graph[0].author).toMatchObject({ "@id": PERSON_ID });
    }
  });
});

describe("indexing hygiene", () => {
  // What each route serves to a crawler (live HTML, no JavaScript, 5 Nov 2026):
  // the public pages carry their full content; every other route serves a
  // heading and a sign-in card, because the real page needs a passkey session.
  const PUBLIC_PATHS = ["/", "/explain", "/about", "/partners"];
  const NOINDEX_PATHS = [
    "/app",
    "/argon",
    "/audit",
    "/network",
    "/login",
    "/account",
  ];

  it("accounts for every route exactly once", () => {
    expect([...PUBLIC_PATHS, ...NOINDEX_PATHS].sort()).toEqual(
      SEO_PAGES.map((p) => p.path).sort(),
    );
  });

  it("lists only the public pages in the sitemap", () => {
    expect(sitemap().map((e) => e.url)).toEqual(
      PUBLIC_PATHS.map((p) => canonicalUrl(p)),
    );
    expect(INDEXABLE_PAGES.map((p) => p.path)).toEqual(PUBLIC_PATHS);
  });

  it("serves noindex, follow on every sign-in gated and account screen", () => {
    for (const route of NOINDEX_PATHS) {
      expect(pageMetadata(route).robots, route).toEqual({
        index: false,
        follow: true,
      });
    }
  });

  it("leaves the public pages indexable", () => {
    for (const route of PUBLIC_PATHS) {
      expect(isNoindex(route), route).toBe(false);
      expect(pageMetadata(route).robots, route).toBeUndefined();
    }
  });

  it("never lists a noindex page in the sitemap", () => {
    const listed = new Set(sitemap().map((e) => e.url));
    for (const page of SEO_PAGES) {
      if (isNoindex(page.path)) {
        expect(listed.has(canonicalUrl(page.path)), page.path).toBe(false);
      }
    }
  });

  it("links every sitemap page from the header navigation every crawler gets", () => {
    const navPaths = new Set<string>(
      SIGNED_OUT_NAV_ITEMS.map((item) => item.href),
    );
    for (const page of INDEXABLE_PAGES) {
      expect(navPaths.has(page.path), page.path).toBe(true);
    }
  });
});

describe("crawl files", () => {
  it("lists every indexable route in the sitemap with a lastmod", () => {
    const entries = sitemap();
    expect(entries.map((e) => e.url)).toEqual(
      INDEXABLE_PAGES.map((p) => canonicalUrl(p.path)),
    );
    for (const entry of entries) {
      expect(String(entry.lastModified)).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it("keeps robots allowing the site, blocking the API and naming the sitemap", () => {
    const result = robots();
    expect(result.sitemap).toBe(`${SITE_URL}/sitemap.xml`);
    expect(result.rules).toMatchObject({
      userAgent: "*",
      allow: "/",
      disallow: ["/api/"],
    });
  });

  it("serves the IndexNow key as a plain file containing only the key", () => {
    const file = path.join(REPO_ROOT, "public", `${INDEXNOW_KEY}.txt`);
    expect(fs.readFileSync(file, "utf8")).toBe(INDEXNOW_KEY);
  });
});

describe("footer", () => {
  it("links to the portfolio with rel=author and the other sites", () => {
    const source = fs.readFileSync(
      path.join(REPO_ROOT, "src/components/specimen-chrome.tsx"),
      "utf8",
    );
    expect(source).toContain('rel="author"');
    expect(source).toContain("Built by");
    expect(source).toContain("MORE_BY_MRINAL");
  });
});
