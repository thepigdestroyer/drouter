import { describe, expect, it } from "vitest";
import {
  generalizePromptPapillon,
  rehydratePapillonAnswer,
  scorePromptPrivacyRisk,
} from "@/lib/risk/analyzer";

const AWS_STS_FIXTURE = ["ASIA", "IOSFODNN7EXAMPLE"].join("");

describe("Client-Side Privacy Exposure Scorer & PAPILLON Generalizer", () => {
  it("scores abstract math and coding questions as 0 ('low')", () => {
    const mathResult = scorePromptPrivacyRisk(
      "Prove that for any prime p > 3, p^2 - 1 is divisible by 24."
    );
    expect(mathResult.score).toBe(0);
    expect(mathResult.level).toBe("low");
    expect(mathResult.findings).toEqual([]);

    const codeResult = scorePromptPrivacyRisk(
      "Write a pure TypeScript function that implements Dijkstra's shortest path algorithm using a binary heap."
    );
    expect(codeResult.score).toBe(0);
    expect(codeResult.level).toBe("low");
    expect(codeResult.findings).toEqual([]);
  });

  it("scores prompts containing API keys, email, internal IP, and clinical/financial details >= 70 ('high' or 'critical')", () => {
    const sensitivePrompt = [
      "At my company, our internal billing service at 10.24.18.92:5432 and api.billing.internal",
      "is failing when authenticating with sk-live9876543210abcdef1234.",
      "Please email dr.alice@hospital.org regarding my patient's oncology biopsy and 15 mg/kg dosage",
      "scheduled on 2026-10-24 for the $125,000.00 claim.",
    ].join(" ");

    const assessment = scorePromptPrivacyRisk(sensitivePrompt);

    expect(assessment.score).toBeGreaterThanOrEqual(75);
    expect(["high", "critical"]).toContain(assessment.level);
    expect(assessment.level).toBe("critical");

    const categories = new Set(assessment.findings.map((f) => f.category));
    expect(categories.has("credentials")).toBe(true);
    expect(categories.has("pii")).toBe(true);
    expect(categories.has("infrastructure")).toBe(true);
    expect(categories.has("medical")).toBe(true);
    expect(categories.has("financial")).toBe(true);
    expect(categories.has("temporal")).toBe(true);
    expect(categories.has("first-person-context")).toBe(true);
  });

  it("generalizePromptPapillon replaces private details with symbolic variables, drops risk score significantly, and rehydratePapillonAnswer restores them", () => {
    const rawPrompt =
      "In my company, connecting to 192.168.10.45 with key sk-proj1234567890abcdef for my patient on 2026-11-15 costs $45,000 and alerts ops@acme.io.";

    const generalized = generalizePromptPapillon(rawPrompt);

    expect(generalized.riskBefore).toBeGreaterThanOrEqual(70);
    expect(generalized.riskAfter).toBeLessThan(generalized.riskBefore);
    expect(generalized.riskAfter).toBe(0);

    // Check symbolic variables are present in generalizedPrompt and localContextVault
    expect(generalized.generalizedPrompt).toContain("<CREDENTIAL_REDACTED>");
    expect(generalized.generalizedPrompt).toContain("<TARGET_SYSTEM>");
    expect(generalized.generalizedPrompt).toContain("<PATIENT_COHORT>");
    expect(generalized.generalizedPrompt).toContain("<AMOUNT_A>");
    expect(generalized.generalizedPrompt).toContain("<DATE_T0>");

    expect(generalized.generalizedPrompt).not.toContain("sk-proj1234567890abcdef");
    expect(generalized.generalizedPrompt).not.toContain("192.168.10.45");
    expect(generalized.generalizedPrompt).not.toContain("$45,000");
    expect(generalized.generalizedPrompt).not.toContain("2026-11-15");
    expect(generalized.generalizedPrompt).not.toContain("ops@acme.io");

    // Simulate remote model answering using the symbolic variables
    const remoteModelResponse =
      "To resolve the issue on <TARGET_SYSTEM> before <DATE_T0>, rotate <CREDENTIAL_REDACTED>, cap the <PATIENT_COHORT> budget at <AMOUNT_A>, and notify <PII_REDACTED>.";

    const rehydrated = rehydratePapillonAnswer(
      remoteModelResponse,
      generalized.localContextVault
    );

    expect(rehydrated).toContain("192.168.10.45");
    expect(rehydrated).toContain("2026-11-15");
    expect(rehydrated).toContain("sk-proj1234567890abcdef");
    expect(rehydrated).toContain("my patient");
    expect(rehydrated).toContain("$45,000");
    expect(rehydrated).toContain("ops@acme.io");
  });

  it("detects JWTs and AWS STS keys and prevents cross-placeholder injection during rehydratePapillonAnswer", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const promptWithJwt = `Authenticate with ${jwt} and ${AWS_STS_FIXTURE} on 10.0.0.1.`;
    const gen = generalizePromptPapillon(promptWithJwt);
    expect(gen.generalizedPrompt).not.toContain("eyJhbGci");
    expect(gen.generalizedPrompt).not.toContain(AWS_STS_FIXTURE);
    expect(gen.riskAfter).toBe(0);

    // Ensure single-pass rehydration does not double-substitute if a vault value contains another placeholder tag
    const vault = {
      "<CREDENTIAL_REDACTED>": "literal-<TARGET_SYSTEM>-inside-secret",
      "<TARGET_SYSTEM>": "10.0.0.1",
    };
    const reply = "Key=<CREDENTIAL_REDACTED> Host=<TARGET_SYSTEM>";
    expect(rehydratePapillonAnswer(reply, vault)).toBe(
      "Key=literal-<TARGET_SYSTEM>-inside-secret Host=10.0.0.1"
    );
  });
});
