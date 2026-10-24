"use client";

import React, { useEffect, useRef } from "react";
import {
  createInitialInkBlots,
  renderInkFrame,
  stepInkBlotPosition,
  type PointerState,
  type PositionedInkBlot,
} from "./ink-math";

const GRID_WIDTH = 192;
const GRID_HEIGHT = 128;
const FRAME_INTERVAL_MS = 33; // ~30 fps, < 0.5 ms CPU per frame

export function InkField(): React.JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width = GRID_WIDTH;
    canvas.height = GRID_HEIGHT;

    const blots = createInitialInkBlots();
    const positioned: PositionedInkBlot[] = new Array(blots.length);
    const imageData = ctx.createImageData(GRID_WIDTH, GRID_HEIGHT);
    const buffer = imageData.data;

    const pointer: PointerState = {
      x: 0.5,
      y: 0.5,
      active: false,
    };

    let scrollOffsetNorm = 0;
    let viewportAspect =
      typeof window !== "undefined" && window.innerHeight > 0
        ? window.innerWidth / window.innerHeight
        : 1.5;

    const updateScrollAndViewport = () => {
      if (typeof window === "undefined") return;
      const vh = Math.max(1, window.innerHeight);
      const vw = Math.max(1, window.innerWidth);
      viewportAspect = vw / vh;
      scrollOffsetNorm = window.scrollY / vh;
    };

    const drawAtTime = (timeSec: number) => {
      for (let i = 0; i < blots.length; i++) {
        positioned[i] = stepInkBlotPosition(
          blots[i],
          timeSec,
          pointer,
          scrollOffsetNorm,
        );
      }
      renderInkFrame(buffer, GRID_WIDTH, GRID_HEIGHT, positioned, viewportAspect);
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
      pointer.x = e.clientX / vw;
      pointer.y = e.clientY / vh;
      pointer.active = true;
    };

    const onPointerLeave = () => {
      pointer.active = false;
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
