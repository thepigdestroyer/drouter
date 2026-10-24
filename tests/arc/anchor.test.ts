import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST as postAnchor } from "@/app/api/anchor/route";
import { createRateLimiter, isHex32, parseAnchorBody } from "@/lib/arc/anchor-input";
import { nodeIdFor } from "@/lib/arc/nodes";
import { setArcClientDepsForTests } from "@/lib/arc/registry";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";

const h = (c: string) => `0x${c.repeat(64)}`;

beforeEach(() => {
  resetRateLimitStateForTests();
});

afterEach(() => {
  setArcClientDepsForTests(null);
  vi.unstubAllEnvs();
});

describe("isHex32", () => {
  it("accepts 32-byte hex in any case", () => {
    expect(isHex32(h("a"))).toBe(true);
    expect(isHex32(h("F"))).toBe(true);
    expect(isHex32(`0x${"0123456789abcdef".repeat(4)}`)).toBe(true);
  });
  it("rejects malformed values", () => {
    expect(isHex32("0x1234")).toBe(false);
    expect(isHex32(h("a").slice(2))).toBe(false);
    expect(isHex32(`${h("a")}0`)).toBe(false);
    expect(isHex32(h("g"))).toBe(false);
    expect(isHex32(`0X${"a".repeat(64)}`)).toBe(false);
    expect(isHex32(123)).toBe(false);
    expect(isHex32(null)).toBe(false);
  });
});

describe("parseAnchorBody", () => {
  it("accepts a minimal body", () => {
    const r = parseAnchorBody({ receiptHash: h("a"), nodeId: h("b") });
    expect(r).toEqual({ ok: true, value: { receiptHash: h("a"), nodeId: h("b") } });
  });
  it("accepts optional ok and evidenceHash", () => {
    const r = parseAnchorBody({ receiptHash: h("a"), nodeId: h("b"), ok: false, evidenceHash: h("c") });
    expect(r).toEqual({
      ok: true,
      value: { receiptHash: h("a"), nodeId: h("b"), ok: false, evidenceHash: h("c") },
    });
  });
  it("rejects non-objects", () => {
    for (const bad of [null, undefined, "x", 1, [], true]) {
      expect(parseAnchorBody(bad).ok).toBe(false);
    }
  });
  it("rejects malformed hashes", () => {
    expect(parseAnchorBody({ receiptHash: "0x12", nodeId: h("b") }).ok).toBe(false);
    expect(parseAnchorBody({ receiptHash: h("a"), nodeId: "nope" }).ok).toBe(false);
    expect(parseAnchorBody({ receiptHash: h("a") }).ok).toBe(false);
    expect(parseAnchorBody({ receiptHash: h("a"), nodeId: h("b"), evidenceHash: "0x1" }).ok).toBe(false);
  });
  it("rejects non-boolean ok", () => {
    expect(parseAnchorBody({ receiptHash: h("a"), nodeId: h("b"), ok: "yes" }).ok).toBe(false);
  });
});

describe("createRateLimiter", () => {
  it("allows 30 per minute per key then blocks, and recovers", () => {
    let now = 1_000_000;
    const limit = createRateLimiter({ max: 30, windowMs: 60_000, now: () => now });
    for (let i = 0; i < 30; i++) expect(limit("1.1.1.1")).toBe(true);
    expect(limit("1.1.1.1")).toBe(false);
    expect(limit("2.2.2.2")).toBe(true);
    now += 60_001;
    expect(limit("1.1.1.1")).toBe(true);
  });
});

describe("POST /api/anchor with mocked viem client", () => {
  it("anchors receipt and records verification, returning txHash, explorerUrl, and onChain=true", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", "0xbc8085c2b6fe6e0db05f169925c0b841828f4481");
    let seq = 0;
    setArcClientDepsForTests({
      readContract: vi.fn(async () => BigInt(0)),
      writeContract: vi.fn(async () => {
        seq += 1;
        return `0x${String(seq).padStart(64, "a")}` as `0x${string}`;
      }),
    });

    const req = new Request("http://localhost/api/anchor", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.5" },
      body: JSON.stringify({
        receiptHash: h("1"),
        nodeId: nodeIdFor("sim-1"),
        ok: true,
        evidenceHash: h("2"),
      }),
    });

    const res = await postAnchor(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.onChain).toBe(true);
    expect(json.anchorTx).toBe(`0x${"a".repeat(63)}1`);
    expect(json.verificationTx).toBe(`0x${"a".repeat(63)}2`);
    expect(json.txHash).toBe(json.verificationTx);
    expect(json.explorerUrl).toContain(json.verificationTx);
  });
});
