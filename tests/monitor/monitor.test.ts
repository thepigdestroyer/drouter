import { describe, expect, it } from "vitest";
import {
  restorePlaceholders,
  scrubWithPlaceholders,
} from "@/lib/monitor";

describe("Monitor placeholder scrubber", () => {
  it("scrubs emails and secrets into reversible placeholders and restores them", () => {
    const raw =
      "Email ops@drouter.io or backup@drouter.io using key sk-live-9876543210abcdefghij and token ghp_1234567890abcdefghijklmnopqrstuv.";
    const { scrubbedText, placeholders, redactionCount } = scrubWithPlaceholders(raw);

    expect(redactionCount).toBe(4);
    expect(scrubbedText).not.toContain("ops@drouter.io");
    expect(scrubbedText).not.toContain("backup@drouter.io");
    expect(scrubbedText).not.toContain("sk-live-9876543210abcdefghij");
    expect(scrubbedText).not.toContain("ghp_1234567890abcdefghijklmnopqrstuv");
    expect(scrubbedText).toContain("[[DROUTER_EMAIL_1]]");
    expect(scrubbedText).toContain("[[DROUTER_EMAIL_2]]");
    expect(scrubbedText).toContain("[[DROUTER_SECRET_1]]");
    expect(scrubbedText).toContain("[[DROUTER_SECRET_2]]");

    const restored = restorePlaceholders(scrubbedText, placeholders);
    expect(restored).toBe(raw);
  });
});
