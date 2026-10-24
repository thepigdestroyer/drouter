export interface InkBlot {
  id: number;
  kind: "ink" | "droplet";
  baseX: number;
  baseY: number;
  radius: number;
  freqX: number;
  freqY: number;
  phaseX: number;
  phaseY: number;
  driftAmpX: number;
  driftAmpY: number;
  lobeRadiusRatio: number;
  lobeOrbitRadius: number;
  lobeSpeed: number;
  lobePhase: number;
  scrollFactor: number;
}

export interface PointerState {
  x: number;
  y: number;
  active: boolean;
}

export interface InkTendril {
  midX: number;
  midY: number;
  midRadius: number;
  tipX: number;
  tipY: number;
  tipRadius: number;
  spatterX: number;
  spatterY: number;
  spatterRadius: number;
}

export interface PositionedInkBlot {
  id: number;
  kind: "ink" | "droplet";
  x: number;
  y: number;
  radius: number;
  lobeX: number;
  lobeY: number;
  lobeRadius: number;
  stretchX?: number;
  stretchY?: number;
  tendrils?: ReadonlyArray<InkTendril>;
}

export interface InkTransientDrop {
  id: number;
  kind: "bloom" | "trail" | "tap";
  x: number;
  y: number;
  radius: number;
  strength: number;
  bornAtSec: number;
  durationSec: number;
  seed: number;
}

export interface RenderInkFrameOptions {
  timeSec?: number;
  transientDrops?: ReadonlyArray<InkTransientDrop>;
  includePeriodicBlooms?: boolean;
}

// Fast precomputed sine lookup table for allocation-free inner-loop liquid contour noise
const SIN_BITS = 11;
const SIN_SIZE = 1 << SIN_BITS; // 2048
const SIN_MASK = SIN_SIZE - 1;
const RAD_TO_LUT = SIN_SIZE / (Math.PI * 2);
const SIN_LUT = new Float32Array(SIN_SIZE);
for (let i = 0; i < SIN_SIZE; i++) {
  SIN_LUT[i] = Math.sin((i / SIN_SIZE) * Math.PI * 2);
}

function fastSin(rad: number): number {
  return SIN_LUT[((rad * RAD_TO_LUT) | 0) & SIN_MASK];
}

function fastCos(rad: number): number {
  return SIN_LUT[(((rad + 1.5707963267948966) * RAD_TO_LUT) | 0) & SIN_MASK];
}

export function smoothstep(edge0: number, edge1: number, x: number): number {
  if (edge1 <= edge0) {
    return x >= edge0 ? 1 : 0;
  }
  const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/**
 * Deterministic initial configuration of 6 organic black sumi-ink blots and 1 rare small signal-orange droplet.
 * Positioned in the outer side margins and open spaces so they render boldly with zero text interference.
 * Does not call Math.random() or Date.now() so SSR and reduced-motion frames are 100% reproducible.
 */
export function createInitialInkBlots(): InkBlot[] {
  return [
    {
      id: 0,
      kind: "ink",
      baseX: 0.056,
      baseY: 0.16,
      radius: 0.024,
      freqX: 0.45,
      freqY: 0.38,
      phaseX: 0.2,
      phaseY: 1.1,
      driftAmpX: 0.016,
      driftAmpY: 0.036,
      lobeRadiusRatio: 0.76,
      lobeOrbitRadius: 0.02,
      lobeSpeed: 0.68,
      lobePhase: 0.4,
      scrollFactor: 0.9,
    },
    {
      id: 1,
      kind: "ink",
      baseX: 0.072,
      baseY: 0.22,
      radius: 0.021,
      freqX: 0.52,
      freqY: 0.43,
      phaseX: 2.3,
      phaseY: 0.5,
      driftAmpX: 0.017,
      driftAmpY: 0.034,
      lobeRadiusRatio: 0.72,
      lobeOrbitRadius: 0.018,
      lobeSpeed: -0.62,
      lobePhase: 1.9,
      scrollFactor: 1.15,
    },
    {
      id: 2,
      kind: "ink",
      baseX: 0.918,
      baseY: 0.18,
      radius: 0.026,
      freqX: 0.41,
      freqY: 0.48,
      phaseX: 1.5,
      phaseY: 2.7,
      driftAmpX: 0.02,
      driftAmpY: 0.038,
      lobeRadiusRatio: 0.74,
      lobeOrbitRadius: 0.022,
      lobeSpeed: 0.58,
      lobePhase: 2.6,
      scrollFactor: -0.85,
    },
    {
      id: 3,
      kind: "ink",
      baseX: 0.936,
      baseY: 0.245,
      radius: 0.021,
      freqX: 0.49,
      freqY: 0.39,
      phaseX: 4.0,
      phaseY: 1.4,
      driftAmpX: 0.018,
      driftAmpY: 0.034,
      lobeRadiusRatio: 0.68,
      lobeOrbitRadius: 0.018,
      lobeSpeed: -0.66,
      lobePhase: 0.9,
      scrollFactor: -1.05,
    },
    {
      id: 4,
      kind: "ink",
      baseX: 0.068,
      baseY: 0.65,
      radius: 0.027,
      freqX: 0.38,
      freqY: 0.44,
      phaseX: 3.1,
      phaseY: 4.2,
      driftAmpX: 0.019,
      driftAmpY: 0.036,
      lobeRadiusRatio: 0.76,
      lobeOrbitRadius: 0.022,
      lobeSpeed: 0.62,
      lobePhase: 3.5,
      scrollFactor: 0.75,
    },
    {
      id: 5,
      kind: "ink",
      baseX: 0.928,
      baseY: 0.67,
      radius: 0.028,
      freqX: 0.42,
      freqY: 0.36,
      phaseX: 5.0,
      phaseY: 2.1,
      driftAmpX: 0.019,
      driftAmpY: 0.036,
      lobeRadiusRatio: 0.72,
      lobeOrbitRadius: 0.023,
      lobeSpeed: -0.56,
      lobePhase: 4.8,
      scrollFactor: -0.7,
    },
    {
      id: 6,
      kind: "droplet",
      baseX: 0.935,
      baseY: 0.095,
      radius: 0.0095,
      freqX: 0.44,
      freqY: 0.51,
      phaseX: 0.8,
      phaseY: 3.3,
      driftAmpX: 0.012,
      driftAmpY: 0.014,
      lobeRadiusRatio: 0.62,
      lobeOrbitRadius: 0.006,
      lobeSpeed: 0.75,
      lobePhase: 1.2,
      scrollFactor: 0.6,
    },
  ];
}

// Mobile (narrow viewport) anchors so ink stays at top/bottom edges and peeking from section edges on 390px screens
const MOBILE_ANCHORS: ReadonlyArray<{ x: number; y: number; scale: number }> = [
  { x: 0.88, y: 0.064, scale: 1.05 }, // Top-right edge above headline
  { x: 0.93, y: 0.425, scale: 1.05 }, // Section divider right A
  { x: 0.89, y: 0.46, scale: 0.95 }, // Section divider right B (merges with A)
  { x: 0.065, y: 0.445, scale: 1.0 }, // Section divider left edge
  { x: 0.16, y: 0.962, scale: 1.1 }, // Bottom edge left
  { x: 0.85, y: 0.958, scale: 1.1 }, // Bottom edge right
  { x: 0.94, y: 0.048, scale: 1.15 }, // Rare orange droplet top-right corner
];

/**
 * Computes the instantaneous normalized position, scroll-stretch, reshaping lobe, and organic tendrils
 * of a single ink blot given elapsed time (seconds), pointer state, and scroll state.
 */
export function stepInkBlotPosition(
  blot: InkBlot,
  timeSec: number,
  pointer: PointerState,
  scrollOffsetNorm: number,
  scrollVelocity = 0,
  aspect = 1.5,
): PositionedInkBlot {
  const t = Number.isFinite(timeSec) ? timeSec : 0;
  const scroll = Number.isFinite(scrollOffsetNorm) ? scrollOffsetNorm : 0;
  const vel = Number.isFinite(scrollVelocity) ? scrollVelocity : 0;
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1.5;
  const isMobile = safeAspect < 0.58;

  const anchor =
    isMobile && blot.id >= 0 && blot.id < MOBILE_ANCHORS.length
      ? MOBILE_ANCHORS[blot.id]
      : null;

  const baseX = anchor ? anchor.x : blot.baseX;
  const baseY = anchor ? anchor.y : blot.baseY;
  const radiusScale = anchor ? anchor.scale : 1;

  // Two-harmonic organic drift so motion is lively and non-repetitive
  const driftX =
    (Math.sin(t * blot.freqX + blot.phaseX) * 0.76 +
      Math.cos(t * (blot.freqX * 1.65) + blot.phaseY) * 0.24) *
    blot.driftAmpX *
    (isMobile ? 0.65 : 1);
  const driftY =
    (Math.cos(t * blot.freqY + blot.phaseY) * 0.76 +
      Math.sin(t * (blot.freqY * 1.55) + blot.phaseX) * 0.24) *
    blot.driftAmpY *
    (isMobile ? 0.5 : 1);

  const scrollShiftX =
    Math.cos(scroll * 0.85 + blot.phaseX) * 0.012 * blot.scrollFactor;
  const scrollShiftY =
    Math.sin(scroll * 0.95 + blot.phaseY) * 0.038 * blot.scrollFactor;

  let x = baseX + driftX + scrollShiftX;
  let y = baseY + driftY + scrollShiftY;

  if (pointer.active && Number.isFinite(pointer.x) && Number.isFinite(pointer.y)) {
    const dx = pointer.x - x;
    const dy = pointer.y - y;
    const distSq = dx * dx + dy * dy;
    const dist = Math.sqrt(distSq);
    if (dist > 0.0001) {
      // Gentle bell-shaped attraction for black ink blots; shy repulsion for the rare orange droplet.
      const direction = blot.kind === "droplet" ? -1 : 1;
      const pull = clamp((dist / (distSq + 0.04)) * 0.018, 0, 0.045);
      x += (dx / dist) * pull * direction;
      y += (dy / dist) * pull * direction;
    }
  }

  x = clamp(x, 0.025, 0.975);
  y = clamp(y, 0.035, 0.97);

  // Scroll stretches blots slightly in the vertical scroll direction while preserving area
  const scrollStretchMag = clamp(
    Math.abs(vel) * 0.28 + Math.abs(Math.sin(scroll * 1.15)) * 0.16,
    0,
    0.38,
  );
  const stretchY = 1 + scrollStretchMag;
  const stretchX = 1 / Math.sqrt(stretchY);

  // Breathing radius & reshaping secondary lobe
  const radius =
    blot.radius * radiusScale * (1 + 0.08 * Math.sin(t * 0.56 + blot.phaseY));
  const lobeAngle = t * blot.lobeSpeed + blot.lobePhase + scroll * 0.45;
  const pulse = 1 + 0.28 * Math.sin(t * 0.72 + blot.phaseX);
  const orbit = blot.lobeOrbitRadius * radiusScale * pulse;

  const yAspectFactor = safeAspect >= 0.58 ? safeAspect : 0.65;
  const lobeX = clamp(x + Math.cos(lobeAngle) * orbit * stretchX, 0.015, 0.985);
  const lobeY = clamp(
    y + Math.sin(lobeAngle) * orbit * yAspectFactor * stretchY - vel * 0.008,
    0.015,
    0.985,
  );
  const lobeRadius =
    radius *
    blot.lobeRadiusRatio *
    (1 + 0.14 * Math.cos(t * 0.78 + blot.lobePhase));

  // Build slender organic tendrils & distinct satellite spatter beads
  const tendrils: InkTendril[] = [];
  const tendrilCount = blot.kind === "droplet" ? 1 : 2;
  for (let k = 0; k < tendrilCount; k++) {
    const baseAngle =
      blot.phaseX +
      k * 2.45 +
      t * (blot.lobeSpeed * 0.48) +
      0.55 * Math.sin(t * 0.68 + blot.phaseY + k * 1.9);
    const curlAngle =
      baseAngle + 0.52 * Math.cos(t * 0.86 + blot.lobePhase + k * 2.1);
    const extension =
      0.5 + 0.5 * Math.sin(t * 0.82 + blot.phaseX * 1.3 + k * 2.4);

    // Reach extends beyond the compact kernel boundary so tendrils & spatter dots are visibly distinct
    const reachMid = radius * (0.95 + 0.45 * extension);
    const reachTip = radius * (1.55 + 0.72 * extension);
    const reachSpatter = radius * (2.35 + 0.65 * extension);

    const midX = clamp(
      x + Math.cos(baseAngle) * reachMid * stretchX,
      0.01,
      0.99,
    );
    const midY = clamp(
      y + Math.sin(baseAngle) * reachMid * yAspectFactor * stretchY,
      0.01,
      0.99,
    );

    const tipX = clamp(
      x + Math.cos(curlAngle) * reachTip * stretchX,
      0.01,
      0.99,
    );
    const tipY = clamp(
      y + Math.sin(curlAngle) * reachTip * yAspectFactor * stretchY,
      0.01,
      0.99,
    );

    const spatterAngle = curlAngle + 0.28 * (k === 0 ? 1 : -1);
    const spatterX = clamp(
      x + Math.cos(spatterAngle) * reachSpatter * stretchX,
      0.01,
      0.99,
    );
    const spatterY = clamp(
      y + Math.sin(spatterAngle) * reachSpatter * yAspectFactor * stretchY,
      0.01,
      0.99,
    );

    tendrils.push({
      midX,
      midY,
      midRadius: radius * (0.52 + 0.1 * extension),
      tipX,
      tipY,
      tipRadius: radius * (0.36 + 0.08 * extension),
      spatterX,
      spatterY,
      spatterRadius: blot.kind === "droplet" ? 0 : radius * 0.25,
    });
  }

  return {
    id: blot.id,
    kind: blot.kind,
    x,
    y,
    radius,
    lobeX,
    lobeY,
    lobeRadius,
    stretchX,
    stretchY,
    tendrils,
  };
}

// Deterministic margin drop locations for periodic drop-and-bloom cycles
const DESKTOP_BLOOM_SITES: ReadonlyArray<{ x: number; y: number; r: number }> = [
  { x: 0.068, y: 0.42, r: 0.021 },
  { x: 0.926, y: 0.44, r: 0.02 },
  { x: 0.062, y: 0.84, r: 0.022 },
  { x: 0.932, y: 0.83, r: 0.021 },
  { x: 0.825, y: 0.13, r: 0.019 },
  { x: 0.075, y: 0.48, r: 0.02 },
];

const MOBILE_BLOOM_SITES: ReadonlyArray<{ x: number; y: number; r: number }> = [
  { x: 0.93, y: 0.33, r: 0.02 },
  { x: 0.065, y: 0.72, r: 0.02 },
  { x: 0.52, y: 0.965, r: 0.022 },
  { x: 0.82, y: 0.058, r: 0.019 },
];

/**
 * Generates deterministic periodic "drop-and-bloom" ink drops that land every ~9-11 seconds,
 * rapidly bloom outward on the paper, linger, and dissolve before the next drop lands.
 */
export function computePeriodicBlooms(
  timeSec: number,
  aspect = 1.5,
): InkTransientDrop[] {
  const t = Math.max(0, Number.isFinite(timeSec) ? timeSec : 0);
  const sites = aspect < 0.58 ? MOBILE_BLOOM_SITES : DESKTOP_BLOOM_SITES;
  const results: InkTransientDrop[] = [];

  // Two staggered periodic drop streams (periods 9.5s and 11.5s, within the 8-15s cadence)
  const streams = [
    { period: 9.5, offset: 0.35, idBase: 1000 },
    { period: 11.5, offset: 5.6, idBase: 2000 },
  ];

  for (let s = 0; s < streams.length; s++) {
    const stream = streams[s];
    const shifted = t + stream.offset;
    const cycleIndex = Math.floor(shifted / stream.period);
    const tau = shifted - cycleIndex * stream.period;
    const duration = stream.period - 0.6;

    if (tau >= 0 && tau <= duration) {
      const siteIdx = (cycleIndex * 2 + s) % sites.length;
      const site = sites[siteIdx];

      // Rapid initial drop impact + wet outward bloom, then slow soak fade
      const bloomProgress = 1 - Math.exp(-tau * 1.35);
      const radius = site.r * (0.36 + 0.64 * bloomProgress);
      const fadeIn = smoothstep(0, 0.1, tau);
      const fadeOut = 1 - smoothstep(duration - 2.2, duration, tau);
      const strength = fadeIn * fadeOut * 1.25;

      if (strength > 0.02) {
        results.push({
          id: stream.idBase + cycleIndex,
          kind: "bloom",
          x: site.x,
          y: site.y,
          radius,
          strength,
          bornAtSec: t - tau,
          durationSec: duration,
          seed: (cycleIndex + 1) * 1.73 + s * 3.1,
        });
      }
    }
  }

  return results;
}

/**
 * Creates a dissolving pointer-trail ink bead that fades over ~1.0 second.
 */
export function createTrailDrop(
  nx: number,
  ny: number,
  bornAtSec: number,
  idSeed = 0,
): InkTransientDrop {
  return {
    id: 3000 + idSeed,
    kind: "trail",
    x: clamp(nx, 0.01, 0.99),
    y: clamp(ny, 0.01, 0.99),
    radius: 0.01,
    strength: 0.95,
    bornAtSec,
    durationSec: 1.0,
    seed: idSeed * 1.37 + 0.5,
  };
}

/**
 * Creates a tap-to-drop ink blot when the user clicks or taps empty space.
 */
export function createTapDrop(
  nx: number,
  ny: number,
  bornAtSec: number,
  idSeed = 0,
): InkTransientDrop {
  return {
    id: 5000 + idSeed,
    kind: "tap",
    x: clamp(nx, 0.02, 0.98),
    y: clamp(ny, 0.02, 0.98),
    radius: 0.019,
    strength: 1.25,
    bornAtSec,
    durationSec: 11.0,
    seed: idSeed * 2.19 + 1.1,
  };
}

/**
 * Steps and filters active pointer-trail and tap-dropped ink blots at `timeSec`.
 */
export function stepTransientDrops(
  drops: ReadonlyArray<InkTransientDrop>,
  timeSec: number,
): InkTransientDrop[] {
  const t = Number.isFinite(timeSec) ? timeSec : 0;
  const active: InkTransientDrop[] = [];

  for (let i = 0; i < drops.length; i++) {
    const d = drops[i];
    const age = t - d.bornAtSec;
    if (age < 0 || age > d.durationSec) continue;

    if (d.kind === "trail") {
      // Dissolves in ~1 second while spreading slightly
      const progress = age / d.durationSec;
      const fade = 1 - smoothstep(0, 1.0, progress);
      if (fade <= 0.02) continue;
      active.push({
        ...d,
        radius: d.radius * (0.85 + 0.35 * progress),
        strength: d.strength * fade,
      });
    } else if (d.kind === "tap") {
      // Rapid initial bloom on tap, then lingers and slowly dissolves
      const bloom = 0.38 + 0.62 * (1 - Math.exp(-age * 6.5));
      const fade = 1 - smoothstep(d.durationSec - 2.5, d.durationSec, age);
      if (fade <= 0.02) continue;
      active.push({
        ...d,
        radius: d.radius * bloom,
        strength: d.strength * fade,
      });
    } else {
      active.push(d);
    }
  }

  return active;
}

/**
 * Computes the spatial opacity mask in [0.115, 1.0] so ink is bold and clearly visible
 * in the side margins and open areas, while fading down BEFORE the main text column
 * (`nx` in [0.15, 0.85]) to preserve strict WCAG AA contrast for all body text.
 */
export function computeContentMask(
  nx: number,
  ny: number,
  aspect = 1.5,
): number {
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1.5;

  // Mobile / narrow viewport (< 390-500px wide): keep ink bold only at top/bottom/outer edges,
  // and WCAG AA safe (mask <= 0.22 -> alpha <= 34/255) anywhere text could sit or shift when menu opens
  if (safeAspect < 0.58) {
    const topRightCorner =
      (1 - smoothstep(0.05, 0.088, ny)) * smoothstep(0.76, 0.88, nx);
    const bottomEdge = smoothstep(0.94, 0.975, ny);
    const outerSideRim = Math.max(
      1 - smoothstep(0.012, 0.042, nx),
      smoothstep(0.955, 0.985, nx),
    );
    // Gentle boost between sections & near side margins, strictly capped so text stays WCAG AA (> 4.8:1)
    const sectionBand =
      smoothstep(0.415, 0.43, ny) *
      (1 - smoothstep(0.448, 0.465, ny)) *
      0.16;
    const nearSideMargin =
      Math.max(
        1 - smoothstep(0.04, 0.11, nx),
        smoothstep(0.88, 0.955, nx),
      ) * 0.22;

    const safeZone = Math.max(
      topRightCorner * 0.88,
      bottomEdge * 0.9,
      outerSideRim * 0.82,
      sectionBand,
      nearSideMargin,
    );
    return 0.115 + 0.835 * clamp(safeZone, 0, 1);
  }

  // Desktop / tablet viewport: max-w-5xl centered container text starts at nx ~ 0.161 on 1440px.
  // Keep full ink strength across the margin (0..0.132) and fade down across 0.132..0.165 before text!
  const leftMargin = 1 - smoothstep(0.132, 0.165, nx);
  const rightMargin = smoothstep(0.835, 0.868, nx);

  // Upper-right hero area is open paper because hero text is left-aligned max-w-3xl (ends at nx ~ 0.69)
  const heroRightOpen =
    smoothstep(0.74, 0.82, nx) *
    smoothstep(0.05, 0.08, ny) *
    (1 - smoothstep(0.22, 0.28, ny));

  // Top & bottom page margins
  const extremeVertical = Math.max(
    (1 - smoothstep(0.02, 0.045, ny)) * 0.5,
    smoothstep(0.955, 0.985, ny) * 0.65,
  );

  const marginStrength = Math.max(
    leftMargin,
    rightMargin,
    heroRightOpen * 0.88,
    extremeVertical,
  );

  // 0.115 under central text column (max alpha <= 20/255, WCAG AA safe), 1.0 in open margins
  return 0.115 + 0.885 * clamp(marginStrength, 0, 1);
}

/**
 * Smooth liquid-surface-tension contour displacement for organic, non-circular wet ink outlines.
 */
export function sampleInkEdgeNoise(
  nx: number,
  ny: number,
  aspect = 1.5,
  timeSec = 0,
): number {
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1.5;
  const u = nx;
  const v = ny / Math.max(0.45, safeAspect);
  const t = Number.isFinite(timeSec) ? timeSec : 0;

  // Smooth organic lobes (no blocky sawtooth frequencies)
  const n1 =
    fastSin(u * 42 + v * 34 + t * 0.52) *
    fastCos(u * 38 - v * 46 - t * 0.38) *
    0.12;
  const n2 = fastSin(u * 86 - v * 72 + t * 0.34) * 0.055;
  const n3 = fastCos(u * 145 + v * 130 - t * 0.2) * 0.025;
  return n1 + n2 + n3;
}

/**
 * Non-periodic cotton paper fiber micro-grain in [-1, 1] using a fast spatial hash (no waffle grid!).
 */
export function samplePaperGrain(nx: number, ny: number, aspect = 1.5): number {
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1.5;
  const ix = ((nx * 1024) | 0) + 17;
  const iy = (((ny / Math.max(0.45, safeAspect)) * 1024) | 0) + 31;
  let h = (ix * 374761393 + iy * 668265263) | 0;
  h = ((h ^ (h >>> 13)) * 1274126177) | 0;
  h = h ^ (h >>> 16);
  return (h & 0xffff) / 32768 - 1;
}

/**
 * Compact quartic metaball kernel: returns > 1.5 at center, ~1.0 at radius `r`,
 * and strictly 0 beyond `1.85 * r` so there is zero long-tail fog halo.
 */
function evalCompactKernel(
  dx: number,
  dy: number,
  r: number,
  weight: number,
): number {
  const supportR = r * 1.85;
  const d2 = dx * dx + dy * dy;
  const s2 = supportR * supportR;
  if (d2 >= s2 || s2 <= 0) return 0;
  const q = 1 - d2 / s2;
  const q2 = q * q;
  // At d = 0 -> q = 1 -> 3.0 * weight
  // At d = r -> q = 1 - 1/3.4225 = 0.7078 -> q^3 = 0.354 -> 1.06 * weight
  return weight * q2 * q * 3.0;
}

/**
 * Evaluates the gooey metaball scalar field at normalized coordinates (nx, ny) in [0, 1].
 * Includes main blot bodies, reshaping lobes, curving tendrils, spatter beads, and optional transient drops.
 */
export function sampleMetaballField(
  nx: number,
  ny: number,
  blots: ReadonlyArray<PositionedInkBlot>,
  aspect = 1.6,
  transientDrops?: ReadonlyArray<InkTransientDrop>,
): { inkField: number; dropletField: number } {
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1;
  const xScale = safeAspect >= 0.58 ? 1 : safeAspect / 0.58;
  const yScale = safeAspect >= 0.58 ? 1 / safeAspect : 1 / 0.58;

  let inkField = 0;
  let dropletField = 0;

  for (let i = 0; i < blots.length; i++) {
    const b = blots[i];
    const invStretchX = 1 / (b.stretchX ?? 1);
    const invStretchY = 1 / (b.stretchY ?? 1);

    const dx1 = (nx - b.x) * xScale * invStretchX;
    const dy1 = (ny - b.y) * yScale * invStretchY;
    const term1 = evalCompactKernel(dx1, dy1, b.radius, 1.0);

    const dx2 = (nx - b.lobeX) * xScale * invStretchX;
    const dy2 = (ny - b.lobeY) * yScale * invStretchY;
    const term2 = evalCompactKernel(
      dx2,
      dy2,
      b.lobeRadius,
      b.kind === "droplet" ? 0.7 : 0.95,
    );

    let tendrilSum = 0;
    if (b.tendrils) {
      for (let k = 0; k < b.tendrils.length; k++) {
        const td = b.tendrils[k];
        const dmx = (nx - td.midX) * xScale;
        const dmy = (ny - td.midY) * yScale;
        tendrilSum += evalCompactKernel(dmx, dmy, td.midRadius, 0.78);

        const dtx = (nx - td.tipX) * xScale;
        const dty = (ny - td.tipY) * yScale;
        tendrilSum += evalCompactKernel(dtx, dty, td.tipRadius, 0.72);

        if (td.spatterRadius > 0) {
          const dsx = (nx - td.spatterX) * xScale;
          const dsy = (ny - td.spatterY) * yScale;
          tendrilSum += evalCompactKernel(dsx, dsy, td.spatterRadius, 0.85);
        }
      }
    }

    if (b.kind === "droplet") {
      dropletField += term1 + term2 + tendrilSum * 0.6;
    } else {
      inkField += term1 + term2 + tendrilSum;
    }
  }

  if (transientDrops) {
    for (let i = 0; i < transientDrops.length; i++) {
      const d = transientDrops[i];
      const dx = (nx - d.x) * xScale;
      const dy = (ny - d.y) * yScale;
      inkField += evalCompactKernel(dx, dy, d.radius, d.strength);
    }
  }

  return { inkField, dropletField };
}

/**
 * Converts scalar metaball field strengths into an RGBA tuple [r, g, b, a] on warm e-paper.
 * - Default `mask = 0.115` represents the text-column safe mask (capping black ink alpha at <= 20
 *   so body text over any blot always exceeds WCAG AA contrast).
 * - In side margins and open areas (`mask` up to 1.0), produces crisp sumi ink with a defined
 *   feathered outline (no outer grey halo!), wet capillary rim, subtle paper grain, and a darker core.
 */
export function inkFieldToRgba(
  inkField: number,
  dropletField: number,
  mask = 0.115,
  grain = 0,
): [number, number, number, number] {
  const safeMask = clamp(Number.isFinite(mask) ? mask : 0.115, 0.08, 1);
  const marginBoost = 1 + (safeMask - 0.115) * 7.2; // 1.0 under text column, up to ~7.37x in open margins

  if (dropletField >= 0.62) {
    // Signal orange (#d9531e -> 217, 83, 30) rare small droplet with crisp edge and rich core
    const edge = smoothstep(0.62, 0.82, dropletField);
    const core = smoothstep(1.15, 2.2, dropletField);
    const baseAlpha = edge * 44 + core * 22;
    const alpha = clamp(
      Math.round(baseAlpha * (0.85 + 0.15 * marginBoost)),
      0,
      190,
    );
    return [217, 83, 30, alpha];
  }

  if (inkField <= 0.62) {
    return [21, 21, 21, 0];
  }

  // Crisp, narrow feathered edge (0.62 -> 0.78) that rises directly into rich sumi wash (no pale halo!)
  // then deepens smoothly into the darker sumi core (1.15 -> 2.40).
  const edge = smoothstep(0.62, 0.78, inkField);
  const body = smoothstep(0.78, 1.25, inkField);
  const core = smoothstep(1.25, 2.45, inkField);
  // Subtle capillary waterline rim right inside the crisp outline
  const capillaryRim =
    smoothstep(0.72, 0.86, inkField) * (1 - smoothstep(0.92, 1.18, inkField));
  const grainMod = 1 + clamp(grain, -1, 1) * 0.045;

  // At default mask (0.115, under text):
  //   inkField = 0.85 -> edge ~ 1, body ~ 0.15 -> alpha ~ 12
  //   inkField = 1.25 -> edge = 1, body = 1 -> alpha ~ 16
  //   inkField >= 2.5 -> edge = 1, body = 1, core = 1 -> alpha = 20 (strictly <= 20, WCAG AA safe!)
  // In open margins (mask = 1.0, marginBoost ~ 7.37):
  //   outer rim/wash starts crisply at ~88-105 alpha, and darker core reaches ~150 alpha!
  const unmasked =
    (edge * 11.2 + body * 4.4 + capillaryRim * 1.4 + core * 4.2) * grainMod;
  const maxAllowed = safeMask <= 0.15 ? 20 : 162;
  const alpha = clamp(Math.round(unmasked * marginBoost), 0, maxAllowed);
  return [21, 21, 21, alpha];
}

// Preallocated Scratch Buffers for Tile-Accelerated Rendering (Zero Per-Frame Allocations)
const MAX_PRIMS = 128;
const primX = new Float32Array(MAX_PRIMS);
const primY = new Float32Array(MAX_PRIMS);
const primSupportR = new Float32Array(MAX_PRIMS);
const primInvSupportR2 = new Float32Array(MAX_PRIMS);
const primWeight = new Float32Array(MAX_PRIMS);
const primInvStretchX = new Float32Array(MAX_PRIMS);
const primInvStretchY = new Float32Array(MAX_PRIMS);
const primKind = new Uint8Array(MAX_PRIMS); // 0 = ink, 1 = orange droplet
const activeIdx = new Int32Array(MAX_PRIMS);

/**
 * Renders a full reduced-resolution RGBA buffer in a tight allocation-free tile-culled loop (< 0.5 ms per frame).
 * Evaluates crisp noise-displaced metaball outlines, tendrils, periodic drop-and-blooms, pointer trails,
 * tap drops, subtle cotton paper grain, and the content-column readability mask.
 */
export function renderInkFrame(
  buffer: Uint8ClampedArray,
  width: number,
  height: number,
  blots: ReadonlyArray<PositionedInkBlot>,
  aspect = width / Math.max(1, height),
  options?: RenderInkFrameOptions,
): void {
  if (width <= 0 || height <= 0 || buffer.length < width * height * 4) {
    return;
  }

  // Fast 32-bit zero clear
  const pixelCount = width * height;
  if (
    buffer.byteOffset % 4 === 0 &&
    buffer.buffer.byteLength >= buffer.byteOffset + pixelCount * 4
  ) {
    new Uint32Array(buffer.buffer, buffer.byteOffset, pixelCount).fill(0);
  } else {
    buffer.fill(0, 0, pixelCount * 4);
  }

  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1.5;
  const xScale = safeAspect >= 0.58 ? 1 : safeAspect / 0.58;
  const yScale = safeAspect >= 0.58 ? 1 / safeAspect : 1 / 0.58;
  const invXScale = 1 / xScale;
  const invYScale = 1 / yScale;
  const invW = 1 / width;
  const invH = 1 / height;
  const timeSec = options?.timeSec ?? 0;

  let primCount = 0;
  const addPrim = (
    x: number,
    y: number,
    r: number,
    weight: number,
    sx: number,
    sy: number,
    kind: number,
  ) => {
    if (primCount >= MAX_PRIMS || r <= 0.0008 || weight <= 0.01) return;
    const support = r * 1.85;
    const support2 = support * support;
    primX[primCount] = x;
    primY[primCount] = y;
    primSupportR[primCount] = support;
    primInvSupportR2[primCount] = 1 / support2;
    primWeight[primCount] = weight * 3.0;
    primInvStretchX[primCount] = 1 / sx;
    primInvStretchY[primCount] = 1 / sy;
    primKind[primCount] = kind;
    primCount++;
  };

  for (let i = 0; i < blots.length; i++) {
    const b = blots[i];
    const sx = b.stretchX ?? 1;
    const sy = b.stretchY ?? 1;
    const k = b.kind === "droplet" ? 1 : 0;

    addPrim(b.x, b.y, b.radius, 1.0, sx, sy, k);
    addPrim(
      b.lobeX,
      b.lobeY,
      b.lobeRadius,
      b.kind === "droplet" ? 0.7 : 0.95,
      sx,
      sy,
      k,
    );

    if (b.tendrils) {
      const scaleW = b.kind === "droplet" ? 0.6 : 1.0;
      for (let j = 0; j < b.tendrils.length; j++) {
        const td = b.tendrils[j];
        addPrim(td.midX, td.midY, td.midRadius, 0.78 * scaleW, 1, 1, k);
        addPrim(td.tipX, td.tipY, td.tipRadius, 0.72 * scaleW, 1, 1, k);
        if (td.spatterRadius > 0) {
          addPrim(
            td.spatterX,
            td.spatterY,
            td.spatterRadius,
            0.85 * scaleW,
            1,
            1,
            k,
          );
        }
      }
    }
  }

  // Include periodic blooms (unless disabled) and any active pointer trail / tap drops
  const includeBlooms = options?.includePeriodicBlooms ?? true;
  if (includeBlooms) {
    const blooms = computePeriodicBlooms(timeSec, safeAspect);
    for (let i = 0; i < blooms.length; i++) {
      const bl = blooms[i];
      addPrim(bl.x, bl.y, bl.radius, bl.strength, 1, 1, 0);
      // Asymmetric bloom lobe + distinct satellite spatter droplet
      const ang1 = bl.seed;
      const ang2 = bl.seed + 2.35;
      const reach1 = bl.radius * 0.92;
      const reach2 = bl.radius * 2.15;
      addPrim(
        bl.x + Math.cos(ang1) * reach1 * invXScale,
        bl.y + Math.sin(ang1) * reach1 * invYScale,
        bl.radius * 0.68,
        bl.strength * 0.85,
        1,
        1,
        0,
      );
      addPrim(
        bl.x + Math.cos(ang2) * reach2 * invXScale,
        bl.y + Math.sin(ang2) * reach2 * invYScale,
        bl.radius * 0.28,
        bl.strength * 0.9,
        1,
        1,
        0,
      );
    }
  }

  const extraDrops = options?.transientDrops;
  if (extraDrops) {
    for (let i = 0; i < extraDrops.length; i++) {
      const d = extraDrops[i];
      addPrim(d.x, d.y, d.radius, d.strength, 1, 1, 0);
      if (d.kind === "tap") {
        // Satellite spatter bead beside tap-dropped ink blot
        const ang = d.seed;
        const reach = d.radius * 2.1;
        addPrim(
          d.x + Math.cos(ang) * reach * invXScale,
          d.y + Math.sin(ang) * reach * invYScale,
          d.radius * 0.3,
          d.strength * 0.9,
          1,
          1,
          0,
        );
      }
    }
  }

  if (primCount === 0) return;

  // Tile-accelerated rasterization (8x8 pixel tiles)
  const TILE = 8;
  for (let ty = 0; ty < height; ty += TILE) {
    const tyEnd = Math.min(height, ty + TILE);
    const tileMinY = ty * invH;
    const tileMaxY = tyEnd * invH;
    const tileCenterY = 0.5 * (tileMinY + tileMaxY);
    const tileHalfH = 0.5 * (tileMaxY - tileMinY);

    for (let tx = 0; tx < width; tx += TILE) {
      const txEnd = Math.min(width, tx + TILE);
      const tileMinX = tx * invW;
      const tileMaxX = txEnd * invW;
      const tileCenterX = 0.5 * (tileMinX + tileMaxX);
      const tileHalfW = 0.5 * (tileMaxX - tileMinX);

      let activeCount = 0;
      for (let i = 0; i < primCount; i++) {
        const supX =
          primSupportR[i] * invXScale * (1 / primInvStretchX[i]) + tileHalfW;
        const supY =
          primSupportR[i] * invYScale * (1 / primInvStretchY[i]) + tileHalfH;
        const adx = Math.abs(tileCenterX - primX[i]);
        const ady = Math.abs(tileCenterY - primY[i]);
        if (adx <= supX && ady <= supY) {
          activeIdx[activeCount++] = i;
        }
      }

      if (activeCount === 0) continue;

      for (let py = ty; py < tyEnd; py++) {
        const ny = (py + 0.5) * invH;
        let rowOffset = (py * width + tx) * 4;

        for (let px = tx; px < txEnd; px++) {
          const nx = (px + 0.5) * invW;
          let inkField = 0;
          let dropletField = 0;

          for (let a = 0; a < activeCount; a++) {
            const idx = activeIdx[a];
            const dx = (nx - primX[idx]) * xScale * primInvStretchX[idx];
            const dy = (ny - primY[idx]) * yScale * primInvStretchY[idx];
            const d2 = dx * dx + dy * dy;
            const q = 1 - d2 * primInvSupportR2[idx];
            if (q > 0) {
              const q2 = q * q;
              const term = primWeight[idx] * q2 * q;
              if (primKind[idx] === 1) {
                dropletField += term;
              } else {
                inkField += term;
              }
            }
          }

          // Fast reject before noise/grain/mask when outside any blot outline
          if (inkField < 0.42 && dropletField < 0.48) {
            rowOffset += 4;
            continue;
          }

          const edgeNoise = sampleInkEdgeNoise(nx, ny, safeAspect, timeSec);
          const displacedInk = inkField + edgeNoise;
          const displacedDroplet = dropletField + edgeNoise * 0.5;

          if (displacedDroplet >= 0.62) {
            const mask = computeContentMask(nx, ny, safeAspect);
            const [, , , alpha] = inkFieldToRgba(0, displacedDroplet, mask, 0);
            if (alpha > 0) {
              buffer[rowOffset] = 217;
              buffer[rowOffset + 1] = 83;
              buffer[rowOffset + 2] = 30;
              buffer[rowOffset + 3] = alpha;
            }
          } else if (displacedInk > 0.62) {
            const mask = computeContentMask(nx, ny, safeAspect);
            const grain = samplePaperGrain(nx, ny, safeAspect);
            const [, , , alpha] = inkFieldToRgba(displacedInk, 0, mask, grain);
            if (alpha > 0) {
              buffer[rowOffset] = 21;
              buffer[rowOffset + 1] = 21;
              buffer[rowOffset + 2] = 21;
              buffer[rowOffset + 3] = alpha;
            }
          }

          rowOffset += 4;
        }
      }
    }
  }
}
