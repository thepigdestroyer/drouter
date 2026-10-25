import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ARCHITECTURE_DOCS_GITHUB_URL,
  ATLAS_TECHNICAL_SPEC,
  BACKEND_PARTNERS,
  BACKEND_PARTNERS_INTRO,
  CONFIDENTIAL_SPACE_DOCS_GITHUB_URL,
  GOOGLE_EGRESS_CAPACITY_TABLE,
  SPLIT_KNOWLEDGE_EXPLAINER,
} from "@/app/about/page";
import {
  ATLAS_COLLECTION_NAME,
  ATLAS_TEXT_INDEX_NAME,
  ATLAS_VECTOR_INDEX_NAME,
} from "@/lib/atlas/hybrid-search";
import { HONEST_DATA_HANDLING_STATEMENT } from "@/lib/gemini/shared";
import { PRODUCTION_DB_NAME } from "@/lib/mongo/db-name";

const REPO_ROOT = path.resolve(__dirname, "../..");

const WAVE_4_BANNED_JARGON_TERMS = [
  "attestation",
  "attested",
  "enclave",
  "TEE",
  "SEV-SNP",
  "SNP",
  "TDX",
  "HPKE",
  "RFC",
  "Merkle",
  "nullifier",
  "RSA",
  "quorum",
  "Sigstore",
  "Rekor",
  "VCEK",
  "CKKS",
  "FHE",
  "homomorphic",
  "dm-verity",
  "measurement",
  "ciphertext",
  "hash",
  "digest",
  "ECDSA",
  "X25519",
  "PII",
  "OHTTP",
  "SPRT",
  "Arc testnet",
  "relay hop",
  "bucket bytes",
] as const;

const BANNED_JARGON_PATTERNS = [
  /\battestation\b/i,
  /\battested\b/i,
  /\benclaves?\b/i,
  /\bTEE\b/,
  /\bSEV-SNP\b/i,
  /\bSNP\b/,
  /\bTDX\b/,
  /\bHPKE\b/i,
  /\bRFC\b/,
  /\bMerkle\b/i,
  /\bnullifiers?\b/i,
  /\bRSA\b/,
  /\bquorums?\b/i,
  /\bSigstore\b/i,
  /\bRekor\b/i,
  /\bVCEK\b/i,
  /\bCKKS\b/i,
  /\bFHE\b/,
  /\bhomomorphic\b/i,
  /\bdm-verity\b/i,
  /\bmeasurements?\b/i,
  /\bciphertexts?\b/i,
  /\bhash(?:es)?\b/i,
  /\bdigests?\b/i,
  /\bECDSA\b/i,
  /\bX25519\b/i,
  /\bPII\b/,
  /\bOHTTP\b/i,
  /\bSPRT\b/,
  /\bArc testnet\b/i,
  /\brelay hop\b/i,
  /\bbucket bytes\b/i,
];

function expectNoBannedJargonOrEmDash(text: string, contextLabel: string) {
  expect(text, `${contextLabel} must not contain em dashes`).not.toContain(
    "\u2014",
  );
  expect(text, `${contextLabel} must not contain dRouter`).not.toMatch(
    /\bdRouter\b/,
  );

  for (const term of WAVE_4_BANNED_JARGON_TERMS) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\b`, "i");
    expect(
      re.test(text),
      `Expected ${contextLabel} not to contain banned jargon "${term}"`,
    ).toBe(false);
  }

  for (const pat of BANNED_JARGON_PATTERNS) {
    expect(text, `Expected ${contextLabel} not to match ${pat}`).not.toMatch(
      pat,
    );
  }
}

describe("Backend partners section (/about#backend-partners) and cross-links", () => {
  it("renders #backend-partners section on /about with Gemini 4 Argon, MongoDB Atlas, and split-knowledge explainer", () => {
    const aboutSource = fs.readFileSync(
      path.join(REPO_ROOT, "src/app/about/page.tsx"),
      "utf8",
    );

    expect(aboutSource).toContain('id="backend-partners"');
    expect(aboutSource).toContain('aria-label="Backend partners"');

    expect(BACKEND_PARTNERS).toHaveLength(2);
    const [gemini, atlas] = BACKEND_PARTNERS;

    expect(gemini.id).toBe("gemini-4-argon");
    expect(gemini.name).toBe("Gemini 4 Argon");
    expect(gemini.roleLabel).toBe("The planner");
    expect(gemini.plainPrivacyLine).toBe(
      "Gemini decides what to do. It never sees what you wrote.",
    );
    expect(gemini.howItWorks.join(" ")).toContain("67 bits");
    expect(gemini.howItWorks.join(" ")).toContain("$INPUT");
    expect(gemini.howItWorks.join(" ")).toContain("Interactions API");
    expect(gemini.honestNotes.join(" ")).toContain("chat");
    expect(gemini.honestNotes.join(" ")).toContain("Confidential Space");
    expect(gemini.honestNotes.join(" ")).toContain("not yet live");
    expect(gemini.visibilityRows.length).toBeGreaterThanOrEqual(3);

    expect(atlas.id).toBe("mongodb-atlas");
    expect(atlas.name).toBe("MongoDB Atlas");
    expect(atlas.roleLabel).toBe("The library and the public record");
    expect(atlas.plainPrivacyLine).toBe(
      "MongoDB holds public facts and anonymous receipts. Never your messages, names or IP address.",
    );
    expect(atlas.howItWorks.join(" ")).toContain("768-number embedding");
    expect(atlas.howItWorks.join(" ")).toContain("$vectorSearch");
    expect(atlas.howItWorks.join(" ")).toContain("$search");
    expect(atlas.howItWorks.join(" ")).toContain("$rankFusion");
    expect(atlas.howItWorks.join(" ")).toContain("one-time spend codes");
    expect(atlas.visibilityRows.length).toBeGreaterThanOrEqual(3);

    expect(SPLIT_KNOWLEDGE_EXPLAINER.heading).toBe(
      "Why not just send everything to one AI company?",
    );
    expect(SPLIT_KNOWLEDGE_EXPLAINER.body).toContain(
      "no single company ever sees both who you are and what you asked",
    );
  });

  it("contains zero banned jargon outside TechDetails and zero em dashes across all owned files", () => {
    const plainStrings: string[] = [
      BACKEND_PARTNERS_INTRO.eyebrow,
      BACKEND_PARTNERS_INTRO.heading,
      BACKEND_PARTNERS_INTRO.lead,
      SPLIT_KNOWLEDGE_EXPLAINER.eyebrow,
      SPLIT_KNOWLEDGE_EXPLAINER.heading,
      SPLIT_KNOWLEDGE_EXPLAINER.body,
    ];

    for (const partner of BACKEND_PARTNERS) {
      plainStrings.push(
        partner.name,
        partner.roleLabel,
        partner.plainPrivacyLine,
        partner.whyNeeded,
        ...partner.howItWorks,
        ...partner.honestNotes,
        ...partner.visibilityRows.flatMap((r) => [
          r.whatTheySee,
          r.whatTheyNeverSee,
        ]),
      );
    }

    expectNoBannedJargonOrEmDash(
      plainStrings.join("\n"),
      "BACKEND_PARTNERS plain copy",
    );

    const filesToCheck = [
      "src/app/about/page.tsx",
      "src/app/about/backend-partners-data.ts",
      "src/app/about/provider-catalog-client.tsx",
      "src/app/explain/page.tsx",
      "src/components/specimen-chrome.tsx",
    ];

    for (const relPath of filesToCheck) {
      const fullPath = path.join(REPO_ROOT, relPath);
      const source = fs.readFileSync(fullPath, "utf8");
      expect(source, `${relPath} must not contain em dashes`).not.toContain(
        "\u2014",
      );
    }

    for (const relPath of [
      "src/app/about/page.tsx",
      "src/app/explain/page.tsx",
      "src/components/specimen-chrome.tsx",
    ]) {
      const fullPath = path.join(REPO_ROOT, relPath);
      const source = fs.readFileSync(fullPath, "utf8");
      const withoutTechDetails = source.replace(
        /<TechDetails[\s\S]*?<\/TechDetails>/g,
        "",
      );
      const jsxMatches = Array.from(
        withoutTechDetails.matchAll(/\n  return \([\s\S]*?\n  \);/g),
      );
      expect(jsxMatches.length).toBeGreaterThan(0);
      const renderedTextOutsideTechDetails = jsxMatches
        .map((m) => m[0])
        .join("\n")
        .replace(/\{\/\*[\s\S]*?\*\/\}/g, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\{[^}]*\}/g, " ");

      expectNoBannedJargonOrEmDash(
        renderedTextOutsideTechDetails,
        `${relPath} JSX outside TechDetails`,
      );
    }
  });

  it("includes exact Google egress capacity bounds, Atlas indexes/stages, and working links in TechDetails, /explain, and footer", () => {
    expect(GOOGLE_EGRESS_CAPACITY_TABLE).toHaveLength(15);
    const descriptorRow = GOOGLE_EGRESS_CAPACITY_TABLE.find((r) =>
      r.messageKind.startsWith("taskDescriptor"),
    );
    const createReqRow = GOOGLE_EGRESS_CAPACITY_TABLE.find((r) =>
      r.messageKind.startsWith("createRequest"),
    );
    expect(descriptorRow?.maxCapacity).toContain("56.35 bits");
    expect(createReqRow?.maxCapacity).toContain("66.89 bits");
    expect(HONEST_DATA_HANDLING_STATEMENT.dataSentToGoogle).toBe(
      "content-free task descriptor only",
    );

    expect(ATLAS_TECHNICAL_SPEC.databaseName).toBe(PRODUCTION_DB_NAME);
    expect(ATLAS_TECHNICAL_SPEC.vectorIndexName).toBe(ATLAS_VECTOR_INDEX_NAME);
    expect(ATLAS_TECHNICAL_SPEC.textIndexName).toBe(ATLAS_TEXT_INDEX_NAME);
    expect(ATLAS_TECHNICAL_SPEC.pipelineStages).toEqual(
      expect.arrayContaining(["$vectorSearch", "$search", "$rankFusion"]),
    );
    expect(
      ATLAS_TECHNICAL_SPEC.collections.some(
        (c) => c.name === ATLAS_COLLECTION_NAME,
      ),
    ).toBe(true);

    expect(ARCHITECTURE_DOCS_GITHUB_URL).toBe(
      "https://github.com/thepigdestroyer/drouter/blob/main/docs/ARCHITECTURE.md",
    );
    expect(CONFIDENTIAL_SPACE_DOCS_GITHUB_URL).toBe(
      "https://github.com/thepigdestroyer/drouter/blob/main/docs/confidential-space.md",
    );
    expect(
      fs.existsSync(path.join(REPO_ROOT, "docs/ARCHITECTURE.md")),
    ).toBe(true);
    expect(
      fs.existsSync(path.join(REPO_ROOT, "docs/confidential-space.md")),
    ).toBe(true);

    const explainSource = fs.readFileSync(
      path.join(REPO_ROOT, "src/app/explain/page.tsx"),
      "utf8",
    );
    expect(explainSource).toContain('href="/about#backend-partners"');

    const footerSource = fs.readFileSync(
      path.join(REPO_ROOT, "src/components/specimen-chrome.tsx"),
      "utf8",
    );
    expect(footerSource).toContain('href="/about#backend-partners"');
    expect(footerSource).toContain("Backend partners");
  });
});
