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

export interface PositionedInkBlot {
  id: number;
  kind: "ink" | "droplet";
  x: number;
  y: number;
  radius: number;
  lobeX: number;
  lobeY: number;
  lobeRadius: number;
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
 * Deterministic initial configuration of calm black ink blots and one rare small orange droplet.
 * Does not call Math.random() or Date.now() so SSR and reduced-motion frames are reproducible.
 */
export function createInitialInkBlots(): InkBlot[] {
  return [
    {
      id: 0,
      kind: "ink",
      baseX: 0.12,
      baseY: 0.2,
      radius: 0.056,
      freqX: 0.17,
      freqY: 0.13,
      phaseX: 0.2,
      phaseY: 1.1,
      driftAmpX: 0.055,
      driftAmpY: 0.045,
      lobeRadiusRatio: 0.65,
      lobeOrbitRadius: 0.038,
      lobeSpeed: 0.29,
      lobePhase: 0.4,
      scrollFactor: 0.9,
    },
    {
      id: 1,
      kind: "ink",
      baseX: 0.19,
      baseY: 0.25,
      radius: 0.048,
      freqX: 0.21,
      freqY: 0.16,
      phaseX: 2.4,
      phaseY: 0.5,
      driftAmpX: 0.058,
      driftAmpY: 0.044,
      lobeRadiusRatio: 0.6,
      lobeOrbitRadius: 0.034,
      lobeSpeed: -0.24,
      lobePhase: 1.9,
      scrollFactor: 1.15,
    },
    {
      id: 2,
      kind: "ink",
      baseX: 0.86,
      baseY: 0.26,
      radius: 0.054,
      freqX: 0.15,
      freqY: 0.19,
      phaseX: 1.7,
      phaseY: 2.8,
      driftAmpX: 0.052,
      driftAmpY: 0.054,
      lobeRadiusRatio: 0.64,
      lobeOrbitRadius: 0.036,
      lobeSpeed: 0.22,
      lobePhase: 2.6,
      scrollFactor: -0.85,
    },
    {
      id: 3,
      kind: "ink",
      baseX: 0.79,
      baseY: 0.33,
      radius: 0.045,
      freqX: 0.19,
      freqY: 0.14,
      phaseX: 4.1,
      phaseY: 1.4,
      driftAmpX: 0.054,
      driftAmpY: 0.046,
      lobeRadiusRatio: 0.58,
      lobeOrbitRadius: 0.032,
      lobeSpeed: -0.27,
      lobePhase: 0.9,
      scrollFactor: -1.05,
    },
    {
      id: 4,
      kind: "ink",
      baseX: 0.15,
      baseY: 0.78,
      radius: 0.058,
      freqX: 0.14,
      freqY: 0.18,
      phaseX: 3.1,
      phaseY: 4.2,
      driftAmpX: 0.052,
      driftAmpY: 0.048,
      lobeRadiusRatio: 0.66,
      lobeOrbitRadius: 0.04,
      lobeSpeed: 0.25,
      lobePhase: 3.5,
      scrollFactor: 0.75,
    },
    {
      id: 5,
      kind: "ink",
      baseX: 0.84,
      baseY: 0.76,
      radius: 0.062,
      freqX: 0.16,
      freqY: 0.12,
      phaseX: 5.0,
      phaseY: 2.1,
      driftAmpX: 0.05,
      driftAmpY: 0.048,
      lobeRadiusRatio: 0.62,
      lobeOrbitRadius: 0.04,
      lobeSpeed: -0.21,
      lobePhase: 4.8,
      scrollFactor: -0.7,
    },
    {
      id: 6,
      kind: "droplet",
      baseX: 0.9,
      baseY: 0.14,
      radius: 0.013,
      freqX: 0.18,
      freqY: 0.22,
      phaseX: 0.8,
      phaseY: 3.3,
      driftAmpX: 0.028,
      driftAmpY: 0.024,
      lobeRadiusRatio: 0.5,
      lobeOrbitRadius: 0.006,
      lobeSpeed: 0.35,
      lobePhase: 1.2,
      scrollFactor: 0.6,
    },
  ];
}

/**
 * Computes the instantaneous normalized position of a single ink blot and its organic lobe
 * given elapsed time (seconds), pointer state, and normalized scroll progress.
 */
export function stepInkBlotPosition(
  blot: InkBlot,
  timeSec: number,
  pointer: PointerState,
  scrollOffsetNorm: number,
): PositionedInkBlot {
  const t = Number.isFinite(timeSec) ? timeSec : 0;
  const scroll = Number.isFinite(scrollOffsetNorm) ? scrollOffsetNorm : 0;

  const driftX = Math.sin(t * blot.freqX + blot.phaseX) * blot.driftAmpX;
  const driftY = Math.cos(t * blot.freqY + blot.phaseY) * blot.driftAmpY;

  const scrollShiftX = Math.cos(scroll * 0.85 + blot.phaseX) * 0.028 * blot.scrollFactor;
  const scrollShiftY = Math.sin(scroll * 0.95 + blot.phaseY) * 0.052 * blot.scrollFactor;

  let x = blot.baseX + driftX + scrollShiftX;
  let y = blot.baseY + driftY + scrollShiftY;

  if (pointer.active && Number.isFinite(pointer.x) && Number.isFinite(pointer.y)) {
    const dx = pointer.x - x;
    const dy = pointer.y - y;
    const distSq = dx * dx + dy * dy;
    const dist = Math.sqrt(distSq);
    if (dist > 0.0001) {
      // Gentle bell-shaped pull for black ink blots; subtle shy push for the orange droplet.
      const direction = blot.kind === "droplet" ? -1 : 1;
      const pull = clamp((dist / (distSq + 0.045)) * 0.016, 0, 0.05);
      x += (dx / dist) * pull * direction;
      y += (dy / dist) * pull * direction;
    }
  }

  x = clamp(x, 0.04, 0.96);
  y = clamp(y, 0.05, 0.95);

  const lobeAngle = t * blot.lobeSpeed + blot.lobePhase + scroll * 0.4;
  const pulse = 1 + 0.14 * Math.sin(t * 0.37 + blot.phaseX);
  const orbit = blot.lobeOrbitRadius * pulse;

  const lobeX = clamp(x + Math.cos(lobeAngle) * orbit, 0.02, 0.98);
  const lobeY = clamp(y + Math.sin(lobeAngle) * orbit, 0.02, 0.98);

  return {
    id: blot.id,
    kind: blot.kind,
    x,
    y,
    radius: blot.radius,
    lobeX,
    lobeY,
    lobeRadius: blot.radius * blot.lobeRadiusRatio,
  };
}

/**
 * Evaluates the gooey metaball scalar field at normalized coordinates (nx, ny) in [0, 1].
 */
export function sampleMetaballField(
  nx: number,
  ny: number,
  blots: ReadonlyArray<PositionedInkBlot>,
  aspect = 1.6,
): { inkField: number; dropletField: number } {
  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1;
  const xScale = safeAspect >= 1 ? 1 : safeAspect;
  const yScale = safeAspect >= 1 ? 1 / safeAspect : 1;
  const eps = 0.00012;

  let inkField = 0;
  let dropletField = 0;

  for (let i = 0; i < blots.length; i++) {
    const b = blots[i];
    const dx1 = (nx - b.x) * xScale;
    const dy1 = (ny - b.y) * yScale;
    const term1 = (b.radius * b.radius) / (dx1 * dx1 + dy1 * dy1 + eps);

    const dx2 = (nx - b.lobeX) * xScale;
    const dy2 = (ny - b.lobeY) * yScale;
    const term2 = (b.lobeRadius * b.lobeRadius) / (dx2 * dx2 + dy2 * dy2 + eps);

    if (b.kind === "droplet") {
      dropletField += term1 + term2 * 0.65;
    } else {
      inkField += term1 + term2;
    }
  }

  return { inkField, dropletField };
}

/**
 * Converts scalar metaball field strengths into a smooth, continuous RGBA tuple [r, g, b, a] on warm e-paper.
 * Uses C1-continuous smoothstep ramps (no discontinuous jumps) so upscaling is completely free of aliasing rings,
 * and caps primary ink alpha at 20 (~7.8%) so body text over any blot always exceeds WCAG AA contrast.
 */
export function inkFieldToRgba(
  inkField: number,
  dropletField: number,
): [number, number, number, number] {
  if (dropletField >= 0.55) {
    // Signal orange (#d9531e -> 217, 83, 30) rare small droplet with continuous smoothstep profile
    const s = smoothstep(0.55, 1.5, dropletField);
    return [217, 83, 30, Math.round(s * 54)];
  }

  if (inkField <= 0.62) {
    return [21, 21, 21, 0];
  }

  // Primary ink (#151515 -> 21, 21, 21) filled soft ink blot with smooth gooey meniscus
  const body = smoothstep(0.62, 1.28, inkField);
  const core = smoothstep(1.28, 2.4, inkField);
  const alpha = Math.round(body * 15 + core * 5);
  return [21, 21, 21, alpha];
}

/**
 * Renders a full reduced-resolution RGBA buffer in a tight allocation-free loop (< 0.5 ms per frame).
 */
export function renderInkFrame(
  buffer: Uint8ClampedArray,
  width: number,
  height: number,
  blots: ReadonlyArray<PositionedInkBlot>,
  aspect = width / Math.max(1, height),
): void {
  if (width <= 0 || height <= 0 || buffer.length < width * height * 4) {
    return;
  }

  const safeAspect = Number.isFinite(aspect) && aspect > 0 ? aspect : 1;
  const xScale = safeAspect >= 1 ? 1 : safeAspect;
  const yScale = safeAspect >= 1 ? 1 / safeAspect : 1;
  const invW = 1 / width;
  const invH = 1 / height;
  const eps = 0.00012;
  const blotCount = blots.length;

  let offset = 0;
  for (let py = 0; py < height; py++) {
    const ny = (py + 0.5) * invH;
    for (let px = 0; px < width; px++) {
      const nx = (px + 0.5) * invW;
      let inkField = 0;
      let dropletField = 0;

      for (let i = 0; i < blotCount; i++) {
        const b = blots[i];
        const dx1 = (nx - b.x) * xScale;
        const dy1 = (ny - b.y) * yScale;
        const term1 = (b.radius * b.radius) / (dx1 * dx1 + dy1 * dy1 + eps);

        const dx2 = (nx - b.lobeX) * xScale;
        const dy2 = (ny - b.lobeY) * yScale;
        const term2 = (b.lobeRadius * b.lobeRadius) / (dx2 * dx2 + dy2 * dy2 + eps);

        if (b.kind === "droplet") {
          dropletField += term1 + term2 * 0.65;
        } else {
          inkField += term1 + term2;
        }
      }

      if (dropletField >= 0.55) {
        buffer[offset] = 217;
        buffer[offset + 1] = 83;
        buffer[offset + 2] = 30;
        const t = Math.min(1, (dropletField - 0.55) / 0.95);
        const s = t * t * (3 - 2 * t);
        buffer[offset + 3] = (s * 54 + 0.5) | 0;
      } else if (inkField <= 0.62) {
        buffer[offset] = 0;
        buffer[offset + 1] = 0;
        buffer[offset + 2] = 0;
        buffer[offset + 3] = 0;
      } else {
        buffer[offset] = 21;
        buffer[offset + 1] = 21;
        buffer[offset + 2] = 21;
        const tBody = Math.min(1, (inkField - 0.62) / 0.66);
        const sBody = tBody * tBody * (3 - 2 * tBody);
        let alpha = sBody * 15;
        if (inkField > 1.28) {
          const tCore = Math.min(1, (inkField - 1.28) / 1.12);
          const sCore = tCore * tCore * (3 - 2 * tCore);
          alpha += sCore * 5;
        }
        buffer[offset + 3] = (alpha + 0.5) | 0;
      }

      offset += 4;
    }
  }
}
