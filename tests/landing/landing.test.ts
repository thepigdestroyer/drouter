import { describe, expect, it } from "vitest";
import {
  APP_PAGE_COPY,
  FAQ_ITEMS,
  HERO_COPY,
  LIVE_SCRUB_PRESETS,
  REASSURANCE_POINTS,
  STORY_STEPS,
  friendlyRedactionLabel,
  runLandingPromptPreview,
  tokenizeOutboundText,
} from "@/components/landing/landing-copy";

const BANNED_JARGON_TERMS = [
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
];

function collectDefaultVisibleStrings(): string[] {
  const strings: string[] = [
    HERO_COPY.eyebrow,
    HERO_COPY.headline,
    HERO_COPY.subheadline,
    HERO_COPY.primaryCtaLabel,
    HERO_COPY.secondaryCtaLabel,
    HERO_COPY.quickNote,
    APP_PAGE_COPY.eyebrow,
    APP_PAGE_COPY.heading,
  ];

  for (const step of STORY_STEPS) {
    strings.push(
      step.shortLabel,
      step.title,
      step.metaphor,
      step.body,
      step.takeaway
    );
  }

  for (const preset of LIVE_SCRUB_PRESETS) {
    strings.push(preset.label, preset.sample);
  }

  for (const point of REASSURANCE_POINTS) {
    strings.push(point.label, point.title, point.body);
  }

  for (const faq of FAQ_ITEMS) {
    strings.push(faq.question, faq.answer);
  }

  for (const kind of ["EMAIL", "PHONE", "SECRET", "ACCT", "IP", "ENTITY"]) {
    strings.push(friendlyRedactionLabel(kind));
  }

  return strings;
}

describe("landing copy and plain-language compliance", () => {
  it("contains zero banned jargon terms in default (unexpanded) views", () => {
    const corpus = collectDefaultVisibleStrings().join("\n");
    for (const term of BANNED_JARGON_TERMS) {
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(`\\b${escaped}\\b`, "i");
      expect(
        re.test(corpus),
        `Expected default visible copy not to contain banned jargon "${term}"`
      ).toBe(false);
    }
  });

  it("uses deRoute and never dRouter in user-visible strings", () => {
    const corpus = collectDefaultVisibleStrings().join("\n");
    expect(corpus).toContain("deRoute");
    expect(/dRouter/i.test(corpus)).toBe(false);
  });

  it("contains no em dashes or emoji anywhere in landing copy", () => {
    const allStrings = [
      ...collectDefaultVisibleStrings(),
      ...STORY_STEPS.flatMap((s) => [s.techSummary, s.techDetail]),
      ...REASSURANCE_POINTS.map((p) => p.techDetail),
      ...FAQ_ITEMS.map((f) => f.techDetail),
    ].join("\n");

    expect(allStrings.includes("\u2014")).toBe(false);
    expect(/\p{Extended_Pictographic}/u.test(allStrings)).toBe(false);
  });

  it("covers the four required FAQ questions with truthful answers", () => {
    const questions = FAQ_ITEMS.map((f) => f.question);
    expect(questions).toEqual([
      "Who can read my messages?",
      "Do I need an email?",
      "Is it free?",
      "What is the AI?",
    ]);

    const combinedAnswers = FAQ_ITEMS.map((f) => f.answer).join(" ");
    expect(combinedAnswers).toContain("anonymous tokens");
    expect(combinedAnswers).toContain("Tinfoil");
    expect(combinedAnswers).toContain("demo");
    expect(combinedAnswers).toContain("sealed computer");
    expect(combinedAnswers).toContain("checked every hour");
    expect(combinedAnswers.toLowerCase()).not.toContain("practice");

    const aiFaq = FAQ_ITEMS.find((f) => f.question === "What is the AI?")!;
    expect(aiFaq.techDetail.toLowerCase()).not.toContain("practice");
    expect(aiFaq.techDetail).not.toContain("sim-1");
  });

  it("links primary CTA to /login?next=/app and secondary CTA to /explain", () => {
    expect(HERO_COPY.primaryCtaLabel).toBe("Get started");
    expect(HERO_COPY.primaryCtaHref).toBe("/login?next=/app");
    expect(HERO_COPY.secondaryCtaLabel).toBe("See how it works");
    expect(HERO_COPY.secondaryCtaHref).toBe("/explain");
  });
});

describe("runLandingPromptPreview with preparePrompt", () => {
  it("hides fake email and phone in real time and restores them on reply", () => {
    const sample =
      "Please email alex.rivera@example.com or text 415-555-0199 today.";
    const preview = runLandingPromptPreview(sample);

    expect(preview.outboundText).not.toContain("alex.rivera@example.com");
    expect(preview.outboundText).not.toContain("415-555-0199");
    expect(preview.outboundText).toContain("[EMAIL_1]");
    expect(preview.outboundText).toContain("[PHONE_1]");
    expect(preview.hiddenCount).toBe(2);
    expect(preview.uniformSizeChars).toBeGreaterThanOrEqual(256);

    const placeholderSegments = preview.segments.filter(
      (s) => s.type === "placeholder"
    );
    expect(placeholderSegments).toHaveLength(2);
    expect(placeholderSegments[0].friendlyKind).toBe("Email address");
    expect(placeholderSegments[1].friendlyKind).toBe("Phone number");

    expect(preview.restoredModelReply).toContain("alex.rivera@example.com");
    expect(preview.restoredModelReply).toContain("415-555-0199");
  });

  it("handles empty or plain text without personal details", () => {
    const emptyPreview = runLandingPromptPreview("");
    expect(emptyPreview.hiddenCount).toBe(0);
    expect(emptyPreview.segments).toEqual([]);

    const plainPreview = runLandingPromptPreview("What is photosynthesis?");
    expect(plainPreview.hiddenCount).toBe(0);
    expect(plainPreview.outboundText).toBe("What is photosynthesis?");
    expect(tokenizeOutboundText(plainPreview.outboundText)).toEqual([
      { type: "text", value: "What is photosynthesis?" },
    ]);
  });
});
