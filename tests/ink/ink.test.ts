import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  clamp,
  createInitialInkBlots,
  inkFieldToRgba,
  renderInkFrame,
  sampleMetaballField,
  smoothstep,
  stepInkBlotPosition,
} from "@/components/ink/ink-math";

const ROOT = resolve(__dirname, "../..");

describe("deRoute Living Ink Math", () => {
  it("computes smoothstep and clamp accurately across boundaries", () => {
    expect(clamp(5, 0, 10)).toBe(5);
    expect(clamp(-2, 0, 10)).toBe(0);
    expect(clamp(99, 0, 10)).toBe(10);

    expect(smoothstep(0, 1, -0.5)).toBe(0);
    expect(smoothstep(0, 1, 0)).toBe(0);
    expect(smoothstep(0, 1, 0.5)).toBe(0.5);
    expect(smoothstep(0, 1, 1)).toBe(1);
    expect(smoothstep(0, 1, 2)).toBe(1);
    expect(smoothstep(1, 1, 1)).toBe(1);
    expect(smoothstep(1, 1, 0.5)).toBe(0);
  });

  it("creates a deterministic set of 6 black ink blots and 1 rare orange droplet", () => {
    const a = createInitialInkBlots();
    const b = createInitialInkBlots();
    expect(a).toEqual(b);

    const inkBlots = a.filter((item) => item.kind === "ink");
    const droplets = a.filter((item) => item.kind === "droplet");
    expect(inkBlots.length).toBe(6);
    expect(droplets.length).toBe(1);
    expect(droplets[0].radius).toBeLessThan(0.03);
  });

  it("steps blot positions smoothly with time, pointer attraction/repulsion, and scroll", () => {
    const blots = createInitialInkBlots();
    const inkBlot = blots[0];
    const droplet = blots.find((b) => b.kind === "droplet")!;

    const inactivePointer = { x: 0.5, y: 0.5, active: false };
    const posT0 = stepInkBlotPosition(inkBlot, 0, inactivePointer, 0);
    const posT3 = stepInkBlotPosition(inkBlot, 3.5, inactivePointer, 0);
    expect(posT0.x).not.toBe(posT3.x);
    expect(posT0.y).not.toBe(posT3.y);

    // Active pointer pulls black ink blots gently toward cursor
    const pointerRight = { x: posT0.x + 0.15, y: posT0.y, active: true };
    const pulled = stepInkBlotPosition(inkBlot, 0, pointerRight, 0);
    expect(pulled.x).toBeGreaterThan(posT0.x);

    // Active pointer gently pushes the rare orange droplet away from cursor
    const dropletT0 = stepInkBlotPosition(droplet, 0, inactivePointer, 0);
    const pointerNearDroplet = {
      x: dropletT0.x - 0.12,
      y: dropletT0.y,
      active: true,
    };
    const pushedDroplet = stepInkBlotPosition(droplet, 0, pointerNearDroplet, 0);
    expect(pushedDroplet.x).toBeGreaterThan(dropletT0.x);

    // Scroll offset shifts positions while staying clamped on screen
    const scrolled = stepInkBlotPosition(inkBlot, 0, inactivePointer, 1.2);
    expect(scrolled.y).not.toBe(posT0.y);
    expect(scrolled.x).toBeGreaterThanOrEqual(0.04);
    expect(scrolled.x).toBeLessThanOrEqual(0.96);
    expect(scrolled.y).toBeGreaterThanOrEqual(0.05);
    expect(scrolled.y).toBeLessThanOrEqual(0.95);
  });

  it("evaluates gooey metaball merging and keeps RGBA contrast WCAG AA safe", () => {
    const blots = createInitialInkBlots().map((b) =>
      stepInkBlotPosition(b, 0, { x: 0.5, y: 0.5, active: false }, 0),
    );

    const primary = blots[0];
    const atCenter = sampleMetaballField(primary.x, primary.y, blots, 1.5);
    expect(atCenter.inkField).toBeGreaterThan(1.5);

    const droplet = blots.find((b) => b.kind === "droplet")!;
    const atDroplet = sampleMetaballField(droplet.x, droplet.y, blots, 1.5);
    expect(atDroplet.dropletField).toBeGreaterThan(1.0);

    // Empty space produces 0 alpha
    expect(inkFieldToRgba(0.1, 0)).toEqual([21, 21, 21, 0]);

    // Filled ink blot increases smoothly from outer meniscus to core, and max ink alpha stays <= 20 (~7.8%)
    const [, , , washAlpha] = inkFieldToRgba(0.85, 0);
    const [, , , meniscusAlpha] = inkFieldToRgba(1.25, 0);
    const [, , , coreAlpha] = inkFieldToRgba(2.5, 0);
    expect(washAlpha).toBeGreaterThan(0);
    expect(meniscusAlpha).toBeGreaterThan(washAlpha);
    expect(coreAlpha).toBeGreaterThanOrEqual(meniscusAlpha);
    expect(coreAlpha).toBeLessThanOrEqual(20);

    // Orange droplet uses #d9531e (217, 83, 30)
    const [dr, dg, db, da] = inkFieldToRgba(0.1, 1.3);
    expect([dr, dg, db]).toEqual([217, 83, 30]);
    expect(da).toBeGreaterThan(30);
  });

  it("renders a full 144x96 reduced-resolution frame well within the 3ms budget", () => {
    const width = 144;
    const height = 96;
    const buffer = new Uint8ClampedArray(width * height * 4);
    const blots = createInitialInkBlots().map((b) =>
      stepInkBlotPosition(b, 1.2, { x: 0.4, y: 0.4, active: true }, 0.3),
    );

    // Warm up JIT
    renderInkFrame(buffer, width, height, blots, 1.5);

    const iterations = 20;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      renderInkFrame(buffer, width, height, blots, 1.5);
    }
    const avgMs = (performance.now() - start) / iterations;
    expect(avgMs).toBeLessThan(3);

    // Ensure non-zero ink pixels and orange droplet pixels were drawn
    let inkPixels = 0;
    let orangePixels = 0;
    for (let i = 0; i < buffer.length; i += 4) {
      if (buffer[i + 3] > 0) {
        if (buffer[i] === 217) orangePixels++;
        else if (buffer[i] === 21) inkPixels++;
      }
    }
    expect(inkPixels).toBeGreaterThan(100);
    expect(orangePixels).toBeGreaterThan(0);
  });

  it("keeps U1 owned UI files free of banned jargon, em-dashes, and legacy dRouter display strings", () => {
    const u1Files = [
      "src/app/layout.tsx",
      "src/app/manifest.ts",
      "src/app/not-found.tsx",
      "src/app/error.tsx",
      "src/app/global-error.tsx",
      "src/components/specimen-chrome.tsx",
      "src/components/auth-pill.tsx",
      "src/components/ink/ink-field.tsx",
      "src/components/ink/ink-button.tsx",
      "src/components/ink/ink-reveal.tsx",
      "src/components/ink/tech-details.tsx",
    ];

    const bannedTerms = [
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

    for (const relPath of u1Files) {
      const content = readFileSync(resolve(ROOT, relPath), "utf8");
      expect(content, `${relPath} must not contain em-dash`).not.toContain("—");
      expect(content, `${relPath} must not contain legacy dRouter brand`).not.toContain("dRouter");
      for (const term of bannedTerms) {
        const regex = new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
        expect(regex.test(content), `${relPath} must not contain "${term}"`).toBe(false);
      }
    }
  });
});
