"use client";

import React, { useEffect, useRef } from "react";
import {
  clamp,
  createInitialInkBlots,
  createTapDrop,
  createTrailDrop,
  renderInkFrame,
  stepInkBlotPosition,
  stepTransientDrops,
  type InkTransientDrop,
  type PointerState,
  type PositionedInkBlot,
} from "./ink-math";

const BASE_GRID_WIDTH = 320;
const BASE_GRID_HEIGHT = 220;
const MAX_TRANSIENT_DROPS = 32;
const FRAME_INTERVAL_MS = 33; // ~30 fps, < 0.8 ms CPU per frame

function computeCanvasGridSize(vw: number, vh: number): { width: number; height: number } {
  const aspect = vw / Math.max(1, vh);
  if (aspect >= 1) {
    const width = clamp(Math.round(vw / 2.6), 280, 560);
    const height = clamp(Math.round(width / aspect), 220, 540);
    return { width, height };
  }
  const height = clamp(Math.round(vh / 2.6), 280, 620);
  const width = clamp(Math.round(height * aspect), 200, 540);
  return { width, height };
}

function isInteractiveTarget(target: EventTarget | null): boolean {
  if (!target || !(target instanceof Element)) return false;
  return Boolean(
    target.closest(
      "a, button, input, textarea, select, summary, label, [role='button'], [role='tab'], [role='dialog'], [contenteditable='true']",
    ),
  );
}

export function InkField(): React.JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let gridWidth = BASE_GRID_WIDTH;
    let gridHeight = BASE_GRID_HEIGHT;
    canvas.width = gridWidth;
    canvas.height = gridHeight;

    const blots = createInitialInkBlots();
    const positioned: PositionedInkBlot[] = new Array(blots.length);
    let imageData = ctx.createImageData(gridWidth, gridHeight);
    let buffer = imageData.data;

    const pointer: PointerState = {
      x: 0.5,
      y: 0.5,
      active: false,
    };

    let transientDrops: InkTransientDrop[] = [];
    let dropSeedCounter = 1;
    let lastTrailX = -1;
    let lastTrailY = -1;
    let lastElapsedSec = 0;

    let scrollOffsetNorm = 0;
    let lastScrollOffsetNorm = 0;
    let scrollVelocity = 0;
    let viewportAspect =
      typeof window !== "undefined" && window.innerHeight > 0
        ? window.innerWidth / window.innerHeight
        : 1.5;

    const syncCanvasResolution = (vw: number, vh: number) => {
      const next = computeCanvasGridSize(vw, vh);
      if (next.width !== gridWidth || next.height !== gridHeight) {
        gridWidth = next.width;
        gridHeight = next.height;
        canvas.width = gridWidth;
        canvas.height = gridHeight;
        imageData = ctx.createImageData(gridWidth, gridHeight);
        buffer = imageData.data;
      }
    };

    const updateScrollAndViewport = () => {
      if (typeof window === "undefined") return;
      const vh = Math.max(1, window.innerHeight);
      const vw = Math.max(1, window.innerWidth);
      viewportAspect = vw / vh;
      syncCanvasResolution(vw, vh);
      const nextScroll = window.scrollY / vh;
      const delta = nextScroll - lastScrollOffsetNorm;
      lastScrollOffsetNorm = nextScroll;
      scrollOffsetNorm = nextScroll;
      scrollVelocity = clamp(scrollVelocity * 0.6 + delta * 3.2, -1.6, 1.6);
    };

    const drawAtTime = (timeSec: number) => {
      lastElapsedSec = timeSec;
      scrollVelocity *= 0.86;
      if (Math.abs(scrollVelocity) < 0.005) {
        scrollVelocity = 0;
      }

      if (transientDrops.length > 0) {
        transientDrops = stepTransientDrops(transientDrops, timeSec);
      }

      for (let i = 0; i < blots.length; i++) {
        positioned[i] = stepInkBlotPosition(
          blots[i],
          timeSec,
          pointer,
          scrollOffsetNorm,
          scrollVelocity,
          viewportAspect,
        );
      }

      renderInkFrame(buffer, gridWidth, gridHeight, positioned, viewportAspect, {
        timeSec,
        transientDrops,
        includePeriodicBlooms: true,
      });
      ctx.putImageData(imageData, 0, 0);
    };

    updateScrollAndViewport();
    drawAtTime(0);

    const motionQuery =
      typeof window !== "undefined" && typeof window.matchMedia === "function"
        ? window.matchMedia("(prefers-reduced-motion: reduce)")
        : null;

    let reducedMotion = Boolean(motionQuery?.matches);
    let rafId: number | null = null;
    let startTimestamp: number | null = null;
    let lastFrameTimestamp = 0;

    const loop = (timestamp: number) => {
      if (reducedMotion || (typeof document !== "undefined" && document.hidden)) {
        rafId = null;
        return;
      }

      if (startTimestamp === null) {
        startTimestamp = timestamp;
      }

      if (timestamp - lastFrameTimestamp >= FRAME_INTERVAL_MS) {
        lastFrameTimestamp = timestamp;
        const elapsedSec = (timestamp - startTimestamp) * 0.001;
        drawAtTime(elapsedSec);
      }

      rafId = window.requestAnimationFrame(loop);
    };

    const startLoopIfAllowed = () => {
      if (reducedMotion) {
        if (rafId !== null) {
          window.cancelAnimationFrame(rafId);
          rafId = null;
        }
        transientDrops = [];
        scrollVelocity = 0;
        drawAtTime(0);
        return;
      }
      if (typeof document !== "undefined" && document.hidden) {
        if (rafId !== null) {
          window.cancelAnimationFrame(rafId);
          rafId = null;
        }
        return;
      }
      if (rafId === null) {
        rafId = window.requestAnimationFrame(loop);
      }
    };

    const onPointerMove = (e: PointerEvent) => {
      const vw = Math.max(1, window.innerWidth);
      const vh = Math.max(1, window.innerHeight);
      const nx = e.clientX / vw;
      const ny = e.clientY / vh;
      pointer.x = nx;
      pointer.y = ny;
      pointer.active = true;

      if (!reducedMotion) {
        const dx = nx - lastTrailX;
        const dy = ny - lastTrailY;
        if (lastTrailX < 0 || dx * dx + dy * dy >= 0.00028) {
          lastTrailX = nx;
          lastTrailY = ny;
          dropSeedCounter = (dropSeedCounter + 1) % 10000;
          transientDrops.push(
            createTrailDrop(nx, ny, lastElapsedSec, dropSeedCounter),
          );
          if (transientDrops.length > MAX_TRANSIENT_DROPS) {
            transientDrops.shift();
          }
        }
      }
    };

    const onPointerDown = (e: PointerEvent) => {
      if (reducedMotion || e.button !== 0) return;
      if (isInteractiveTarget(e.target)) return;

      const vw = Math.max(1, window.innerWidth);
      const vh = Math.max(1, window.innerHeight);
      const nx = e.clientX / vw;
      const ny = e.clientY / vh;
      dropSeedCounter = (dropSeedCounter + 1) % 10000;
      transientDrops.push(
        createTapDrop(nx, ny, lastElapsedSec, dropSeedCounter),
      );
      if (transientDrops.length > MAX_TRANSIENT_DROPS) {
        transientDrops.shift();
      }
    };

    const onPointerLeave = () => {
      pointer.active = false;
      lastTrailX = -1;
      lastTrailY = -1;
    };

    const onScroll = () => {
      updateScrollAndViewport();
      if (reducedMotion) {
        drawAtTime(0);
      }
    };

    const onResize = () => {
      updateScrollAndViewport();
      if (reducedMotion) {
        drawAtTime(0);
      }
    };

    const onVisibilityChange = () => {
      startLoopIfAllowed();
    };

    const onMotionChange = (e: MediaQueryListEvent) => {
      reducedMotion = e.matches;
      startLoopIfAllowed();
    };

    window.addEventListener("pointermove", onPointerMove, { passive: true });
    window.addEventListener("pointerdown", onPointerDown, { passive: true });
    window.addEventListener("pointerleave", onPointerLeave, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    document.addEventListener("visibilitychange", onVisibilityChange);
    motionQuery?.addEventListener?.("change", onMotionChange);

    startLoopIfAllowed();

    return () => {
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
      }
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointerleave", onPointerLeave);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      motionQuery?.removeEventListener?.("change", onMotionChange);
    };
  }, []);

  return (
    <div
      aria-hidden="true"
      data-ink-field="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none"
    >
      <canvas
        ref={canvasRef}
        className="block h-full w-full"
        style={{
          imageRendering: "auto",
        }}
      />
    </div>
  );
}

export default InkField;
