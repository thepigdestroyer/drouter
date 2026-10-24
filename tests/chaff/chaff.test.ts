import { describe, expect, it } from "vitest";
import {
  computePaddedBucketBytes,
  createDecoyBundle,
  DECOY_DOMAINS,
} from "@/lib/chaff/decoys";

describe("k-Anonymity Decoy Bundling & Chaff Cover Traffic", () => {
  it("produces 4 bucket-matched slots for k=4 with exact entropy, guess probability, and reply extraction", () => {
    const prompt = "What are the contraindications for mixing MAOIs with SSRIs in elderly patients?";
    const bundle = createDecoyBundle(prompt, 4);

    expect(bundle.k).toBe(4);
    expect(bundle.slots).toHaveLength(4);
    expect(bundle.adversaryGuessProbability).toBe(0.25);
    expect(bundle.entropyBits).toBe(2);
    expect(bundle.realSlotIndex).toBeGreaterThanOrEqual(0);
    expect(bundle.realSlotIndex).toBeLessThan(4);

    const realSlots = bundle.slots.filter((s) => !s.isDecoy);
    const decoySlots = bundle.slots.filter((s) => s.isDecoy);
    expect(realSlots).toHaveLength(1);
    expect(decoySlots).toHaveLength(3);

    expect(bundle.slots[bundle.realSlotIndex].isDecoy).toBe(false);
    expect(bundle.slots[bundle.realSlotIndex].prompt).toBe(prompt);
    expect(bundle.slots[bundle.realSlotIndex].slotIndex).toBe(bundle.realSlotIndex);

    // All 4 slots must have identical paddedBucketBytes (1024 tokens * 4 bytes = 4096)
    const firstBucketBytes = bundle.slots[0].paddedBucketBytes;
    expect(firstBucketBytes).toBe(4096);
    for (let i = 0; i < bundle.slots.length; i++) {
      expect(bundle.slots[i].slotIndex).toBe(i);
      expect(bundle.slots[i].paddedBucketBytes).toBe(firstBucketBytes);
    }

    // Decoy domains should be drawn from the diverse catalog and distinct when k - 1 <= DECOY_DOMAINS.length
    const usedDecoyDomains = new Set(decoySlots.map((s) => s.domain));
    expect(usedDecoyDomains.size).toBe(3);
    for (const decoy of decoySlots) {
      expect(DECOY_DOMAINS).toContain(decoy.domain);
      expect(decoy.prompt.length).toBeGreaterThan(40);
    }

    // Inter-request exponential jitter schedule is monotonically non-decreasing
    for (let i = 1; i < bundle.slots.length; i++) {
      expect(bundle.slots[i].jitterMs).toBeGreaterThan(bundle.slots[i - 1].jitterMs);
    }

    // extractRealReply returns the exact reply at realSlotIndex
    const mockReplies = [
      { id: "reply-0", text: "Decoy response 0" },
      { id: "reply-1", text: "Decoy response 1" },
      { id: "reply-2", text: "Decoy response 2" },
      { id: "reply-3", text: "Decoy response 3" },
    ];
    mockReplies[bundle.realSlotIndex] = { id: "real-reply", text: "Serotonin syndrome risk." };

    const extracted = bundle.extractRealReply(mockReplies);
    expect(extracted).toBe(mockReplies[bundle.realSlotIndex]);
    expect(extracted.id).toBe("real-reply");
  });

  it("scales decoy prompts to match higher 2^j * 1024 token buckets when the real prompt is large", () => {
    // ~1,500 tokens (~6,000 bytes) -> 2,048-token bucket -> 8,192 paddedBucketBytes
    const largePrompt = "Confidential merger analysis: ".repeat(220);
    const bundle = createDecoyBundle(largePrompt, 4);

    expect(bundle.slots[0].paddedBucketBytes).toBe(8192);
    for (const slot of bundle.slots) {
      expect(slot.paddedBucketBytes).toBe(8192);
      // Verify every generated decoy prompt also resolves to the 8192-byte bucket independently
      expect(computePaddedBucketBytes(slot.prompt).paddedBucketBytes).toBe(8192);
    }
  });

  it("shuffles the real prompt across all k positions using CSPRNG Fisher-Yates", () => {
    const seenPositions = new Set<number>();
    for (let trial = 0; trial < 48; trial++) {
      const bundle = createDecoyBundle("Test prompt for slot permutation", 4);
      seenPositions.add(bundle.realSlotIndex);
    }
    expect(seenPositions.size).toBe(4);
  });

  it("matches exact power-of-two byte buckets across boundary sizes (0B, 1B, 4095B, 4096B, 4097B, 32KB) and rejects invalid k", () => {
    expect(() => createDecoyBundle("test", 0)).toThrow();
    expect(() => createDecoyBundle("test", -2)).toThrow();

    const boundaryLengths = [0, 1, 4095, 4096, 4097, 8191, 8192, 8193, 32768];
    for (const len of boundaryLengths) {
      const prompt = "A".repeat(len);
      const bundle = createDecoyBundle(prompt, 4);
      const expectedBucket = computePaddedBucketBytes(prompt).paddedBucketBytes;
      for (const slot of bundle.slots) {
        expect(slot.paddedBucketBytes).toBe(expectedBucket);
        expect(computePaddedBucketBytes(slot.prompt).paddedBucketBytes).toBe(expectedBucket);
      }
    }
  });
});
