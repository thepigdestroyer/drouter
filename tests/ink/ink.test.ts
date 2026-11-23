import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  clamp,
  computeContentMask,
  computePeriodicBlooms,
  createInitialInkBlots,
  createTapDrop,
  createTrailDrop,
  inkFieldToRgba,
  renderInkFrame,
  sampleInkEdgeNoise,
  sampleMetaballField,
  samplePaperGrain,
  smoothstep,
  stepInkBlotPosition,
  stepTransientDrops,
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

  it("steps blot positions with tendrils, pointer attraction/repulsion, and scroll stretch", () => {
    const blots = createInitialInkBlots();
    const inkBlot = blots[0];
    const droplet = blots.find((b) => b.kind === "droplet")!;

    const inactivePointer = { x: 0.5, y: 0.5, active: false };
    const posT0 = stepInkBlotPosition(inkBlot, 0, inactivePointer, 0, 0, 1.5);
    const posT2 = stepInkBlotPosition(inkBlot, 2.0, inactivePointer, 0, 0, 1.5);
    expect(posT0.x).not.toBe(posT2.x);
    expect(posT0.y).not.toBe(posT2.y);

    // Tendrils and spatter beads are generated for organic wet-ink silhouette
    expect(posT0.tendrils).toBeDefined();
    expect(posT0.tendrils!.length).toBe(2);
    expect(posT0.tendrils![0].spatterRadius).toBeGreaterThan(0);

    // Active pointer pulls black ink blots gently toward cursor
    const pointerRight = { x: posT0.x + 0.15, y: posT0.y, active: true };
    const pulled = stepInkBlotPosition(inkBlot, 0, pointerRight, 0, 0, 1.5);
    expect(pulled.x).toBeGreaterThan(posT0.x);

    // Active pointer gently pushes the rare orange droplet away from cursor
    const dropletT0 = stepInkBlotPosition(droplet, 0, inactivePointer, 0, 0, 1.5);
    const pointerNearDroplet = {
      x: dropletT0.x - 0.12,
      y: dropletT0.y,
      active: true,
    };
    const pushedDroplet = stepInkBlotPosition(
      droplet,
      0,
      pointerNearDroplet,
      0,
      0,
      1.5,
    );
    expect(pushedDroplet.x).toBeGreaterThan(dropletT0.x);

    // Scroll offset & scroll velocity stretch blots slightly in the scroll direction
    expect(posT0.stretchY).toBeCloseTo(1.0, 5);
    const scrolled = stepInkBlotPosition(inkBlot, 0, inactivePointer, 0.8, 0.9, 1.5);
    expect(scrolled.y).not.toBe(posT0.y);
    expect(scrolled.stretchY).toBeGreaterThan(1.15);
    expect(scrolled.stretchX).toBeLessThan(1.0);
    expect(scrolled.x).toBeGreaterThanOrEqual(0.025);
    expect(scrolled.x).toBeLessThanOrEqual(0.975);
    expect(scrolled.y).toBeGreaterThanOrEqual(0.035);
    expect(scrolled.y).toBeLessThanOrEqual(0.97);
  });

  it("models periodic drop-and-bloom, 1s dissolving pointer trail, and tap-to-drop blots", () => {
    const bloomsT0 = computePeriodicBlooms(0.5, 1.5);
    const bloomsT2 = computePeriodicBlooms(2.5, 1.5);
    expect(bloomsT0.length).toBeGreaterThanOrEqual(1);
    expect(bloomsT2.length).toBeGreaterThanOrEqual(1);
    // Drop blooms outward as time advances from 0.5s to 2.5s
    expect(bloomsT2[0].radius).toBeGreaterThan(bloomsT0[0].radius);

    // Pointer trail drop dissolves over 1.0 second
    const trail = createTrailDrop(0.1, 0.3, 1.0, 1);
    const tap = createTapDrop(0.08, 0.5, 1.0, 2);
    const atEarly = stepTransientDrops([trail, tap], 1.2);
    expect(atEarly.length).toBe(2);

    const atMid = stepTransientDrops([trail, tap], 1.7);
    const midTrail = atMid.find((d) => d.kind === "trail")!;
    expect(midTrail.strength).toBeLessThan(trail.strength);
    expect(midTrail.radius).toBeGreaterThan(trail.radius);

    // After 1.05s, the trail drop has dissolved while the tap-dropped blot persists and has bloomed
    const afterOneSec = stepTransientDrops([trail, tap], 2.1);
    expect(afterOneSec.some((d) => d.kind === "trail")).toBe(false);
    const activeTap = afterOneSec.find((d) => d.kind === "tap")!;
    expect(activeTap).toBeDefined();
    expect(activeTap.radius).toBeGreaterThan(atEarly.find((d) => d.kind === "tap")!.radius);
  });

  it("masks content column for WCAG AA contrast while rendering bold dark-core sumi ink in margins", () => {
    const blots = createInitialInkBlots().map((b) =>
      stepInkBlotPosition(b, 0, { x: 0.5, y: 0.5, active: false }, 0),
    );

    const primary = blots[0];
    const atCenter = sampleMetaballField(primary.x, primary.y, blots, 1.5);
    expect(atCenter.inkField).toBeGreaterThan(1.5);

    const droplet = blots.find((b) => b.kind === "droplet")!;
    const atDroplet = sampleMetaballField(droplet.x, droplet.y, blots, 1.5);
    expect(atDroplet.dropletField).toBeGreaterThan(1.0);

    // Content column mask is low (~0.115) under text and 1.0 in outer side margins
    const textColumnMask = computeContentMask(0.5, 0.5, 1.5);
    const leftMarginMask = computeContentMask(0.05, 0.5, 1.5);
    expect(textColumnMask).toBeLessThanOrEqual(0.13);
    expect(leftMarginMask).toBeCloseTo(1.0, 3);

    // Edge noise and paper grain stay bounded and deterministic
    const noiseA = sampleInkEdgeNoise(0.1, 0.2, 1.5, 1.0);
    const noiseB = sampleInkEdgeNoise(0.1, 0.2, 1.5, 1.0);
    expect(noiseA).toBe(noiseB);
    expect(Math.abs(noiseA)).toBeLessThan(0.25);
    expect(Math.abs(samplePaperGrain(0.15, 0.25, 1.5))).toBeLessThanOrEqual(1);

    // Empty space produces 0 alpha
    expect(inkFieldToRgba(0.1, 0)).toEqual([21, 21, 21, 0]);

    // Under text column (default mask = 0.115), max ink alpha stays <= 20 (~7.8%, WCAG AA safe)
    const [, , , washAlpha] = inkFieldToRgba(0.85, 0, textColumnMask);
    const [, , , meniscusAlpha] = inkFieldToRgba(1.25, 0, textColumnMask);
    const [, , , coreAlpha] = inkFieldToRgba(2.5, 0, textColumnMask);
    expect(washAlpha).toBeGreaterThan(0);
    expect(meniscusAlpha).toBeGreaterThan(washAlpha);
    expect(coreAlpha).toBeGreaterThanOrEqual(meniscusAlpha);
    expect(coreAlpha).toBeLessThanOrEqual(20);

    // In open margins (mask = 1.0), ink has a bold wash/rim and a distinctly darker sumi core
    const [, , , marginRimAlpha] = inkFieldToRgba(0.88, 0, leftMarginMask);
    const [, , , marginCoreAlpha] = inkFieldToRgba(2.5, 0, leftMarginMask);
    expect(marginRimAlpha).toBeGreaterThan(80);
    expect(marginCoreAlpha).toBeGreaterThan(marginRimAlpha + 25);

    // Orange droplet uses #d9531e (217, 83, 30)
    const [dr, dg, db, da] = inkFieldToRgba(0.1, 1.3);
    expect([dr, dg, db]).toEqual([217, 83, 30]);
    expect(da).toBeGreaterThan(30);
  });

  it("renders a full reduced-resolution frame well within the 3ms budget", () => {
    const width = 240;
    const height = 160;
    const buffer = new Uint8ClampedArray(width * height * 4);
    const blots = createInitialInkBlots().map((b) =>
      stepInkBlotPosition(b, 1.2, { x: 0.4, y: 0.4, active: true }, 0.3, 0.4, 1.5),
    );
    const transientDrops = [
      createTrailDrop(0.12, 0.25, 1.0, 1),
      createTapDrop(0.08, 0.52, 0.8, 2),
    ];

    // Warm up JIT
    renderInkFrame(buffer, width, height, blots, 1.5, {
      timeSec: 1.2,
      transientDrops,
    });

    const iterations = 20;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      renderInkFrame(buffer, width, height, blots, 1.5, {
        timeSec: 1.2,
        transientDrops,
      });
    }
    const avgMs = (performance.now() - start) / iterations;
    expect(avgMs).toBeLessThan(3);

    // Ensure non-zero ink pixels (including bold margin core pixels > 100 alpha) and orange droplet pixels were drawn
    let inkPixels = 0;
    let boldMarginInkPixels = 0;
    let orangePixels = 0;
    for (let i = 0; i < buffer.length; i += 4) {
      if (buffer[i + 3] > 0) {
        if (buffer[i] === 217) orangePixels++;
        else if (buffer[i] === 21) {
          inkPixels++;
          if (buffer[i + 3] > 100) boldMarginInkPixels++;
        }
      }
    }
    expect(inkPixels).toBeGreaterThan(100);
    expect(boldMarginInkPixels).toBeGreaterThan(30);
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
