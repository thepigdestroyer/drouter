import { describe, expect, it } from "vitest";
import { createSymmetryTransform, shiftIsoDate } from "@/lib/symmetry/homomorphism";

describe("Symmetry-Masking Homomorphism Engine", () => {
  it("shifts ISO dates forward by deltaDays, preserves relative intervals, and untransforms back exactly", () => {
    const sym = createSymmetryTransform({
      dateShiftDays: 47,
      numericScaleFactor: 2.5,
    });

    const input =
      "Phase 1 starts on 2026-03-10 and concludes on 2026-04-24 (45 days total).";
    const { transformed, applied } = sym.transform(input);

    const dateMasks = applied.filter((a) => a.kind === "date");
    expect(dateMasks).toEqual([
      { kind: "date", original: "2026-03-10", masked: "2026-04-26" },
      { kind: "date", original: "2026-04-24", masked: "2026-06-10" },
    ]);

    // Verify the relative gap between the two shifted dates is still 45 days
    const origStart = Date.parse("2026-03-10T00:00:00Z");
    const origEnd = Date.parse("2026-04-24T00:00:00Z");
    const maskedStart = Date.parse(`${dateMasks[0].masked}T00:00:00Z`);
    const maskedEnd = Date.parse(`${dateMasks[1].masked}T00:00:00Z`);
    expect((maskedEnd - maskedStart) / 86_400_000).toBe(
      (origEnd - origStart) / 86_400_000,
    );
    expect((maskedEnd - maskedStart) / 86_400_000).toBe(45);

    // Model computes midpoint or echoes schedule in shifted space
    const modelReply = `Confirmed: kickoff on ${dateMasks[0].masked}, milestone review on ${shiftIsoDate("2026-03-25", 47)}, and completion on ${dateMasks[1].masked}.`;
    const restored = sym.untransform(modelReply);

    expect(restored).toBe(
      "Confirmed: kickoff on 2026-03-10, milestone review on 2026-03-25, and completion on 2026-04-24.",
    );
  });

  it("scales currency amounts by scaleFactor, preserves ratios, and untransforms sums back cleanly", () => {
    const sym = createSymmetryTransform({
      dateShiftDays: 30,
      numericScaleFactor: 2.5,
    });

    const prompt =
      "Allocate $1,000.00 to compute and $2,500.00 to storage, then compute the total budget.";
    const { transformed, applied } = sym.transform(prompt);

    expect(transformed).toBe(
      "Allocate $2,500.00 to compute and $6,250.00 to storage, then compute the total budget.",
    );
    expect(applied).toEqual([
      { kind: "currency", original: "$1,000.00", masked: "$2,500.00" },
      { kind: "currency", original: "$2,500.00", masked: "$6,250.00" },
    ]);

    // Verify 1 : 2.5 ratio is preserved in masked space (2500 : 6250)
    expect(6250 / 2500).toBe(2500 / 1000);

    // Model sums the masked values ($2,500.00 + $6,250.00 = $8,750.00)
    const modelReply =
      "With $2,500.00 (28.57%) for compute and $6,250.00 (71.43%) for storage, the combined total is $8,750.00.";
    const restored = sym.untransform(modelReply);

    expect(restored).toBe(
      "With $1,000.00 (28.57%) for compute and $2,500.00 (71.43%) for storage, the combined total is $3,500.00.",
    );
  });

  it("supports multi-currency symbols and ISO codes (£, €, USD) and restores them cleanly", () => {
    const sym = createSymmetryTransform({
      dateShiftDays: 10,
      numericScaleFactor: 2,
    });

    const input = "Contracts: £45,000, €10,000, and USD 5000.";
    const { transformed } = sym.transform(input);
    expect(transformed).toBe("Contracts: £90,000, €20,000, and USD 10000.");
    expect(sym.untransform(transformed)).toBe(input);
  });

  it("replaces and restores natural-language entity aliases across multi-sentence replies", () => {
    const sym = createSymmetryTransform({
      dateShiftDays: 47,
      numericScaleFactor: 2.5,
      customEntities: {
        "Project Hyperion": "Project Halcyon",
        "Acme Bio": "Northwind Labs",
        "Dr. Aris Thorne": "Dr. Clara Vance",
      },
    });

    const input =
      "Under Project Hyperion, Acme Bio appointed Dr. Aris Thorne to lead the 2026-05-01 trial with a $1,200.50 grant.";
    const { transformed, applied } = sym.transform(input);

    expect(transformed).not.toContain("Project Hyperion");
    expect(transformed).not.toContain("Acme Bio");
    expect(transformed).not.toContain("Dr. Aris Thorne");
    expect(transformed).toContain("Project Halcyon");
    expect(transformed).toContain("Northwind Labs");
    expect(transformed).toContain("Dr. Clara Vance");
    expect(transformed).toContain("2026-06-17");
    expect(transformed).toContain("$3,001.25");
    expect(applied.filter((a) => a.kind === "entity")).toHaveLength(3);

    const modelReply = [
      "Northwind Labs should structure Project Halcyon into two milestones.",
      "Dr. Clara Vance will sign off on the $3,001.25 disbursement on 2026-06-17.",
      "If Project Halcyon expands, Northwind Labs can notify Dr. Clara Vance immediately.",
    ].join(" ");

    const restored = sym.untransform(modelReply);
    expect(restored).toBe(
      [
        "Acme Bio should structure Project Hyperion into two milestones.",
        "Dr. Aris Thorne will sign off on the $1,200.50 disbursement on 2026-05-01.",
        "If Project Hyperion expands, Acme Bio can notify Dr. Aris Thorne immediately.",
      ].join(" "),
    );
  });

  it("exposes active homomorphism parameters via parameters()", () => {
    const sym = createSymmetryTransform({
      dateShiftDays: 21,
      numericScaleFactor: 4,
      customEntities: { "Vault Alpha": "Harbor Nine" },
    });

    const params = sym.parameters();
    expect(params.dateShiftDays).toBe(21);
    expect(params.numericScaleFactor).toBe(4);
    expect(params.entityMap["Vault Alpha"]).toBe("Harbor Nine");
    expect(params.entityMap["Project Hyperion"]).toBe("Project Halcyon");
  });
});
