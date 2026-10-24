import { describe, expect, it } from "vitest";
import { preparePrompt, type PreparedPrompt } from "@/lib/pipeline";

function synthKey(prefix: string, body: string): string {
  return `${prefix}${body}`;
}

describe("Interface I1: Browser-Safe Prompt Pipeline (preparePrompt)", () => {
  it("scrubs secrets, PII, and custom terms, computes riskBefore > riskAfter, reports bucketBytes, and restores full or streamed model replies", () => {
    const openAiKey = synthKey(["sk", "proj", ""].join("-"), "AbCdEf1234567890XyZ");
    const tinfoilKey = synthKey(["tk", "live", ""].join("_"), "9876543210fedcba");
    const email = ["dana.reyes", "northvale.org"].join("@");

    const rawPrompt = [
      `Please audit Project Nightfall for Dana Reyes (${email}).`,
      `The gateway failed with ${openAiKey} and ${tinfoilKey} on host 10.24.8.15.`,
      `Call +1 (415) 555-0199 if the check fails.`,
    ].join(" ");

    const prepared: PreparedPrompt = preparePrompt(rawPrompt, {
      customTerms: ["Project Nightfall", "Dana Reyes"],
    });

    expect(prepared.outboundText).not.toContain(openAiKey);
    expect(prepared.outboundText).not.toContain(tinfoilKey);
    expect(prepared.outboundText).not.toContain(email);
    expect(prepared.outboundText).not.toContain("Project Nightfall");
    expect(prepared.outboundText).not.toContain("Dana Reyes");
    expect(prepared.outboundText).not.toContain("10.24.8.15");
    expect(prepared.outboundText).not.toContain("555-0199");

    expect(prepared.bucketBytes).toBe(4096);
    expect(prepared.report.redactions.length).toBe(7);
    expect(prepared.report.riskBefore).toBeGreaterThan(50);
    expect(prepared.report.riskAfter).toBeLessThan(prepared.report.riskBefore);
    expect(prepared.report.riskAfter).toBe(0);
    expect(prepared.report.styleChanges).toBe(0);

    // Full reply restoration
    const modelReply =
      "Audit complete for [ENTITY_1] (owner [ENTITY_2] at [EMAIL_1]): rotated [SECRET_1] and [SECRET_2] on [IP_1] and texted [PHONE_1].";
    const restoredFull = prepared.restore(modelReply);
    expect(restoredFull).toContain("Project Nightfall");
    expect(restoredFull).toContain("Dana Reyes");
    expect(restoredFull).toContain(email);
    expect(restoredFull).toContain(openAiKey);
    expect(restoredFull).toContain(tinfoilKey);
    expect(restoredFull).toContain("10.24.8.15");
    expect(restoredFull).toContain("+1 (415) 555-0199");

    // Streamed cumulative chunk restoration
    const chunks = [
      " Rotating ",
      "[SECRET_",
      "1] for ",
      "[ENTITY_2]",
      " at [email_1].",
    ];
    let acc = "";
    let lastRestored = "";
    for (const delta of chunks) {
      acc += delta;
      lastRestored = prepared.restore(acc);
    }
    expect(lastRestored).toBe(` Rotating ${openAiKey} for Dana Reyes at ${email}.`);
  });

  it("applies optional stylometry normalization without corrupting placeholders and reports styleChanges", () => {
    const stripeKey = synthKey(["sk", "live", ""].join("_"), "51MpL3StR1p3K3y998877");
    const rawPrompt = [
      "Hi team,",
      "",
      `We need to analyse the colour behaviour and optimise the centre defence catalogue using key ${stripeKey} for Dana Reyes.  It\u2019s \u201ccritical\u201d \u2014 please prioritise!`,
      "",
      "Best regards,",
      "Sent from my iPhone",
    ].join("\n");

    const prepared = preparePrompt(rawPrompt, {
      customTerms: ["Dana Reyes"],
      normalizeStyle: true,
    });

    expect(prepared.outboundText).not.toContain(stripeKey);
    expect(prepared.outboundText).not.toContain("Dana Reyes");
    expect(prepared.outboundText).toContain("[SECRET_1]");
    expect(prepared.outboundText).toContain("[ENTITY_1]");

    // UK -> US spellings and typographic normalization applied
    expect(prepared.outboundText).toContain("analyze");
    expect(prepared.outboundText).toContain("color");
    expect(prepared.outboundText).toContain("behavior");
    expect(prepared.outboundText).toContain("optimize");
    expect(prepared.outboundText).not.toMatch(/Sent from my iPhone|Best regards/i);
    expect(prepared.report.styleChanges).toBeGreaterThan(0);

    // Placeholders still restore cleanly after stylometry normalization
    expect(prepared.restore("Updated [ENTITY_1] with [SECRET_1].")).toBe(
      `Updated Dana Reyes with ${stripeKey}.`,
    );
  });

  it("scales bucketBytes to 8192 when outbound prompt exceeds the 4096-byte base bucket and supports optional decoyCount", () => {
    const largeText = "Verify confidential enclave memory isolation invariants. ".repeat(110);
    const prepared = preparePrompt(largeText, { decoyCount: 4 });

    expect(prepared.bucketBytes).toBe(8192);
    expect(prepared.decoyBundle).toBeDefined();
    expect(prepared.decoyBundle?.k).toBe(4);
    expect(prepared.decoyBundle?.slots).toHaveLength(4);
    for (const slot of prepared.decoyBundle?.slots ?? []) {
      expect(slot.paddedBucketBytes).toBe(8192);
    }
  });

  it("supports opt-in mechanical: true to run fail-closed mechanicalRedact while keeping PreparedPrompt compatible", () => {
    const rawPrompt = [
      "Contact Dr. Evelyn Vance at https://horizon-clinic.org/intake on 2026-10-25",
      "regarding patient record 948201 at 742 Evergreen Terrace.",
    ].join(" ");

    const prepared = preparePrompt(rawPrompt, {
      mechanical: true,
      customTerms: ["Horizon Intake"],
    });

    expect(prepared.outboundText).not.toContain("Evelyn Vance");
    expect(prepared.outboundText).not.toContain("https://horizon-clinic.org/intake");
    expect(prepared.outboundText).not.toContain("2026-10-25");
    expect(prepared.outboundText).not.toContain("948201");
    expect(prepared.outboundText).not.toContain("742 Evergreen Terrace");
    expect(prepared.bucketBytes).toBe(4096);
    expect(prepared.report.redactions.length).toBeGreaterThanOrEqual(5);
    expect(prepared.report.riskBefore).toBeGreaterThan(prepared.report.riskAfter);
    expect(prepared.restore(prepared.outboundText)).toBe(rawPrompt);
  });
});
