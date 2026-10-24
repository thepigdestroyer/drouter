import { describe, expect, it } from "vitest";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import {
  bucketForTokens,
  estimateTokens,
  minimizeHistory,
} from "@/lib/privacy/padding";

describe("Subsystem 5: Client-Side Privacy Guard", () => {
  describe("SessionScrubber (reversible PII & secret placeholder substitution)", () => {
    it("replaces emails, API keys (tk_..., sk-...), phone numbers, IPv4s, 0x addresses, and custom terms with numbered placeholders", () => {
      const scrubber = createSessionScrubber(["Project Nightfall", "Acme Bio"]);

      const prompt = [
        "Contact alice@acme.com or bob@example.org.",
        "Keys: tk_live_9876543210abcdef and sk-proj-abcdef1234567890.",
        "Call +1 (415) 555-0199 or +44 20 7946 0958.",
        "Server IP is 192.168.10.42.",
        "Payout wallet: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.",
        "Confidential context for Project Nightfall at Acme Bio.",
      ].join(" ");

      const { scrubbed, replacements } = scrubber.scrub(prompt);

      expect(scrubbed).not.toContain("alice@acme.com");
      expect(scrubbed).not.toContain("bob@example.org");
      expect(scrubbed).not.toContain("tk_live_9876543210abcdef");
      expect(scrubbed).not.toContain("sk-proj-abcdef1234567890");
      expect(scrubbed).not.toContain("415");
      expect(scrubbed).not.toContain("7946 0958");
      expect(scrubbed).not.toContain("192.168.10.42");
      expect(scrubbed).not.toContain("0x71C7656EC7ab88b098defB751B7401B5f6d8976F");
      expect(scrubbed).not.toContain("Project Nightfall");
      expect(scrubbed).not.toContain("Acme Bio");

      expect(scrubbed).toContain("[EMAIL_1]");
      expect(scrubbed).toContain("[EMAIL_2]");
      expect(scrubbed).toContain("[SECRET_1]");
      expect(scrubbed).toContain("[SECRET_2]");
      expect(scrubbed).toContain("[PHONE_1]");
      expect(scrubbed).toContain("[PHONE_2]");
      expect(scrubbed).toContain("[IP_1]");
      expect(scrubbed).toContain("[ACCT_1]");
      expect(scrubbed).toContain("[ENTITY_1]");
      expect(scrubbed).toContain("[ENTITY_2]");

      expect(replacements.length).toBe(10);

      const entries = scrubber.entries();
      const emailEntry = entries.find((e) => e.placeholder === "[EMAIL_1]");
      expect(emailEntry).toBeDefined();
      expect(emailEntry?.preview).toBe("al***@acme.com");
    });

    it("maps repeated occurrences of the same email across turns to the same [EMAIL_1]", () => {
      const scrubber = createSessionScrubber();

      const turn1 = scrubber.scrub("Please email alice@acme.com with the summary.");
      const turn2 = scrubber.scrub("Forward a copy to alice@acme.com and charlie@acme.com.");
      const turn3 = scrubber.scrub("Confirming ALICE@acme.com received the report.");

      expect(turn1.scrubbed).toBe("Please email [EMAIL_1] with the summary.");
      expect(turn2.scrubbed).toBe("Forward a copy to [EMAIL_1] and [EMAIL_2].");
      expect(turn3.scrubbed).toBe("Confirming [EMAIL_1] received the report.");
      expect(scrubber.entries().filter((e) => e.kind === "EMAIL")).toHaveLength(2);
    });

    it("accurately restores all placeholders in model replies", () => {
      const scrubber = createSessionScrubber(["Dr. Evelyn Vance"]);
      scrubber.addCustomTerm("Horizon Clinic");

      const userPrompt =
        "Send results for Dr. Evelyn Vance at Horizon Clinic to evelyn@horizon.org (IP 10.24.0.9, wallet 0x1234567890abcdef1234567890abcdef12345678, phone +1-212-555-0147, token tk_secret_token_998877).";
      const { scrubbed } = scrubber.scrub(userPrompt);

      expect(scrubbed).toBe(
        "Send results for [ENTITY_1] at [ENTITY_2] to [EMAIL_1] (IP [IP_1], wallet [ACCT_1], phone [PHONE_1], token [SECRET_1]).",
      );

      const modelReply =
        "I have prepared the summary for [ENTITY_1] at [ENTITY_2]. It will be sent to [EMAIL_1] from host [IP_1], billed to [ACCT_1], and verified via SMS to [PHONE_1] using key [SECRET_1].";

      const restored = scrubber.restore(modelReply);
      expect(restored).toBe(
        "I have prepared the summary for Dr. Evelyn Vance at Horizon Clinic. It will be sent to evelyn@horizon.org from host 10.24.0.9, billed to 0x1234567890abcdef1234567890abcdef12345678, and verified via SMS to +1-212-555-0147 using key tk_secret_token_998877.",
      );

      scrubber.clear();
      expect(scrubber.entries()).toHaveLength(0);
    });
  });

  describe("Upload Bucket Padding & Token Estimation (Spec §6)", () => {
    it("estimates tokens using UTF-8 byte / 4 heuristic with min 1 for non-empty text", () => {
      expect(estimateTokens("")).toBe(0);
      expect(estimateTokens("hi")).toBe(1);
      expect(estimateTokens("12345678")).toBe(2);
    });

    it("computes power-of-two 1024-token buckets and 50 ms frame cadence", () => {
      const b50 = bucketForTokens(50);
      expect(b50.bucketTokens).toBe(1024);
      expect(b50.exponent).toBe(0);
      expect(b50.padTokens).toBe(974);
      expect(b50.frameCadenceMs).toBe(50);

      const b1024 = bucketForTokens(1024);
      expect(b1024.bucketTokens).toBe(1024);
      expect(b1024.exponent).toBe(0);
      expect(b1024.padTokens).toBe(0);
      expect(b1024.overheadPct).toBe(0);

      const b1025 = bucketForTokens(1025);
      expect(b1025.bucketTokens).toBe(2048);
      expect(b1025.exponent).toBe(1);
      expect(b1025.padTokens).toBe(1023);

      const b5000 = bucketForTokens(5000);
      expect(b5000.bucketTokens).toBe(8192);
      expect(b5000.exponent).toBe(3);
      expect(b5000.padTokens).toBe(3192);
      expect(b5000.frameCadenceMs).toBe(50);
    });
  });

  describe("Local Context Minimizer", () => {
    it("respects maxTokensBudget, preserves chronological order, and prioritizes turns sharing keywords with query", () => {
      const messages: { role: "user" | "assistant"; content: string; id: number }[] = [
        {
          id: 0,
          role: "user",
          content: "System boot: initialize workspace session.",
        },
        {
          id: 1,
          role: "assistant",
          content: "Unrelated discussion about CSS flexbox button padding and colors.",
        },
        {
          id: 2,
          role: "user",
          content: "We configured the PostgreSQL migration schema and index partitioning.",
        },
        {
          id: 3,
          role: "assistant",
          content: "Unrelated discussion about coffee machines and office plants.",
        },
        {
          id: 4,
          role: "user",
          content: "The PostgreSQL migration failed on the partitioning step.",
        },
        {
          id: 5,
          role: "assistant",
          content: "Let me inspect the latest logs for you.",
        },
        {
          id: 6,
          role: "user",
          content: "How do we fix the PostgreSQL migration partitioning error?",
        },
      ];

      // Calculate token budget that fits pinned messages (0, 5, 6) + 2 middle messages (2 and 4)
      const pinnedTokens =
        estimateTokens(messages[0].content) +
        estimateTokens(messages[5].content) +
        estimateTokens(messages[6].content);
      const relevantMiddleTokens =
        estimateTokens(messages[2].content) + estimateTokens(messages[4].content);
      const budget = pinnedTokens + relevantMiddleTokens;

      const result = minimizeHistory(
        messages,
        "PostgreSQL migration partitioning schema",
        budget,
      );

      expect(result.tokensAfter).toBeLessThanOrEqual(budget);
      expect(result.tokensBefore).toBeGreaterThan(result.tokensAfter);
      expect(result.droppedCount).toBe(2);

      const selectedIds = result.selected.map((m) => m.id);
      // Preserves chronological order and keeps first (0), relevant middle (2, 4), and last two (5, 6)
      expect(selectedIds).toEqual([0, 2, 4, 5, 6]);
    });
  });
});
