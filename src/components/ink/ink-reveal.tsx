"use client";

import React, { useEffect, useRef, useState } from "react";

export interface InkRevealProps {
  children: React.ReactNode;
  delayMs?: number;
  className?: string;
}

export function InkReveal({
  children,
  delayMs = 0,
  className = "",
}: InkRevealProps): React.JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  const [phase, setPhase] = useState<"ssr" | "pending" | "visible">("ssr");

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const reducedMotion =
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reducedMotion || typeof IntersectionObserver === "undefined") {
      setPhase("visible");
      return;
    }

    const rect = el.getBoundingClientRect();
    const vh = window.innerHeight || 800;
    const alreadyInView = rect.top < vh * 0.92 && rect.bottom > 0;

    if (alreadyInView) {
      setPhase("pending");
      const raf = window.requestAnimationFrame(() => {
        setPhase("visible");
      });
      return () => window.cancelAnimationFrame(raf);
    }

    setPhase("pending");

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setPhase("visible");
            observer.disconnect();
            break;
          }
        }
      },
      {
        threshold: 0.08,
        rootMargin: "0px 0px -20px 0px",
      },
    );

    observer.observe(el);

    // Safety fallback so full-page headless captures never leave below-fold sections hidden
    const fallbackTimer = window.setTimeout(
      () => {
        setPhase("visible");
        observer.disconnect();
      },
      Math.min(1800, Math.max(600, delayMs + 700)),
    );

    return () => {
      observer.disconnect();
      window.clearTimeout(fallbackTimer);
    };
  }, [delayMs]);

  const style: React.CSSProperties | undefined =
    delayMs > 0 ? { transitionDelay: `${delayMs}ms` } : undefined;

  return (
    <div
      ref={ref}
      data-ink-reveal={phase}
      style={style}
      className={`ep-ink-reveal ${className}`.trim()}
    >
      {children}
    </div>
  );
}

export default InkReveal;
