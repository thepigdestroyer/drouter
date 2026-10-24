"use client";

import React, { useEffect, useState } from "react";
import { TechDetails } from "@/components/ink/tech-details";
import { STORY_STEPS } from "./landing-copy";

function StepIllustration({ step }: { step: number }) {
  return (
    <div
      aria-hidden="true"
      className="ep-inset relative flex min-h-[210px] w-full flex-col items-center justify-center overflow-hidden p-5"
    >
      <svg
        viewBox="0 0 420 160"
        className="h-auto w-full max-w-[420px]"
        role="presentation"
      >
        {/* Subtle paper ruled guide lines */}
        <line
          x1="24"
          y1="136"
          x2="396"
          y2="136"
          stroke="#d6d2c8"
          strokeWidth="1"
          strokeDasharray="3 3"
        />

        {step === 1 && (
          <g className="transition-opacity duration-300">
            {/* Browser page card */}
            <rect
              x="36"
              y="22"
              width="148"
              height="96"
              rx="6"
              fill="#f3f1ec"
              stroke="#151515"
              strokeWidth="1.5"
            />
            <text
              x="48"
              y="42"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              YOUR DEVICE
            </text>
            <line
              x1="48"
              y1="56"
              x2="146"
              y2="56"
              stroke="#3f3e3b"
              strokeWidth="3"
              strokeLinecap="round"
            />
            {/* Redacted ink block over personal detail */}
            <rect
              x="48"
              y="68"
              width="92"
              height="16"
              rx="3"
              fill="#151515"
            />
            <text
              x="54"
              y="79"
              fill="#f3f1ec"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              [EMAIL_1]
            </text>
            <rect
              x="48"
              y="90"
              width="86"
              height="16"
              rx="3"
              fill="#151515"
            />
            <text
              x="54"
              y="101"
              fill="#f3f1ec"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              [PHONE_1]
            </text>

            {/* Ink flow connector */}
            <path
              d="M 192 70 C 212 70, 218 70, 236 70"
              stroke="#151515"
              strokeWidth="1.75"
               fill="none"
            />
            <polygon points="236,66 244,70 236,74" fill="#151515" />

            {/* Safe note card */}
            <rect
              x="252"
              y="28"
              width="132"
              height="84"
              rx="6"
              fill="#ebe8e1"
              stroke="#151515"
              strokeWidth="1.5"
            />
            <text
              x="264"
              y="48"
              fill="#151515"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              DETAILS HIDDEN
            </text>
            <text
              x="264"
              y="68"
              fill="#3f3e3b"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Real names and
            </text>
            <text
              x="264"
              y="82"
              fill="#3f3e3b"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              numbers stay here
            </text>
            <circle cx="364" cy="45" r="5" fill="#151515" />
          </g>
        )}

        {step === 2 && (
          <g className="transition-opacity duration-300">
            {/* Browser inspecting */}
            <rect
              x="36"
              y="32"
              width="116"
              height="76"
              rx="6"
              fill="#f3f1ec"
              stroke="#151515"
              strokeWidth="1.5"
            />
            <text
              x="48"
              y="54"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              YOUR BROWSER
            </text>
            <text
              x="48"
              y="74"
              fill="#151515"
              fontSize="11"
              fontWeight="600"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Checking seal...
            </text>
            <text
              x="48"
              y="92"
              fill="#3f3e3b"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              SEAL INTACT
            </text>

            {/* Dotted inspection line */}
            <line
              x1="158"
              y1="70"
              x2="232"
              y2="70"
              stroke="#151515"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
            <circle cx="195" cy="70" r="14" fill="#f3f1ec" stroke="#151515" strokeWidth="1.5" />
            <path
              d="M 189 70 L 193 74 L 201 66"
              fill="none"
              stroke="#151515"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />

            {/* Sealed computer box with double border and wax/ink seal */}
            <rect
              x="240"
              y="22"
              width="144"
              height="96"
              rx="8"
              fill="#f3f1ec"
              stroke="#151515"
              strokeWidth="2"
            />
            <rect
              x="246"
              y="28"
              width="132"
              height="84"
              rx="5"
              fill="none"
              stroke="#151515"
              strokeWidth="1"
              strokeDasharray="2 2"
            />
            <text
              x="258"
              y="48"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              SEALED COMPUTER
            </text>
            <circle cx="312" cy="78" r="18" fill="#151515" />
            <path
              d="M 305 78 L 310 83 L 320 73"
              fill="none"
              stroke="#f3f1ec"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </g>
        )}

        {step === 3 && (
          <g className="transition-opacity duration-300">
            {/* Uniform Locked Envelope */}
            <rect
              x="44"
              y="26"
              width="160"
              height="88"
              rx="6"
              fill="#151515"
            />
            {/* Envelope flap */}
            <path
              d="M 48 30 L 124 72 L 200 30"
              fill="none"
              stroke="#f3f1ec"
              strokeWidth="1.5"
            />
            <rect
              x="112"
              y="58"
              width="24"
              height="20"
              rx="3"
              fill="#f3f1ec"
            />
            <circle cx="124" cy="68" r="3" fill="#151515" />
            <text
              x="58"
              y="102"
              fill="#f3f1ec"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              LOCKED · UNIFORM SIZE
            </text>

            {/* Arrow into sealed computer */}
            <line
              x1="212"
              y1="70"
              x2="256"
              y2="70"
              stroke="#151515"
              strokeWidth="1.75"
            />
            <polygon points="256,66 264,70 256,74" fill="#151515" />

            {/* Sealed computer */}
            <rect
              x="270"
              y="26"
              width="114"
              height="88"
              rx="6"
              fill="#f3f1ec"
              stroke="#151515"
              strokeWidth="2"
            />
            <text
              x="282"
              y="48"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              ONLY KEY INSIDE
            </text>
            <text
              x="282"
              y="72"
              fill="#151515"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Opens inside the
            </text>
            <text
              x="282"
              y="86"
              fill="#151515"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              sealed computer
            </text>
          </g>
        )}

        {step === 4 && (
          <g className="transition-opacity duration-300">
            {/* Restored on your screen */}
            <rect
              x="36"
              y="26"
              width="148"
              height="88"
              rx="6"
              fill="#f3f1ec"
              stroke="#151515"
              strokeWidth="1.5"
            />
            <text
              x="48"
              y="46"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              YOUR SCREEN ONLY
            </text>
            <text
              x="48"
              y="68"
              fill="#151515"
              fontSize="10"
              fontWeight="600"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Details restored for you
            </text>
            <text
              x="48"
              y="86"
              fill="#3f3e3b"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              alex.rivera@example.com
            </text>

            {/* Dissolving slate on the right */}
            <rect
              x="236"
              y="26"
              width="148"
              height="88"
              rx="6"
              fill="#ebe8e1"
              stroke="#6e6c67"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
            <text
              x="248"
              y="46"
              fill="#6e6c67"
              fontSize="9"
              fontFamily="ui-monospace, monospace"
            >
              WHEN YOU LEAVE
            </text>
            <text
              x="248"
              y="70"
              fill="#151515"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Memory wiped clean.
            </text>
            <text
              x="248"
              y="86"
              fill="#3f3e3b"
              fontSize="10"
              fontFamily="ui-sans-serif, sans-serif"
            >
              Nothing left behind.
            </text>
            <circle cx="352" cy="96" r="3" fill="#6e6c67" />
            <circle cx="364" cy="92" r="2" fill="#a19e97" />
            <circle cx="372" cy="100" r="1.5" fill="#a19e97" />
          </g>
        )}

        {/* Step progress dots at bottom of canvas */}
        {[1, 2, 3, 4].map((idx) => (
          <circle
            key={idx}
            cx={186 + (idx - 1) * 16}
            cy="148"
            r={step === idx ? 4 : 2.5}
            fill={step === idx ? "#151515" : "#b9b4a8"}
          />
        ))}
      </svg>
    </div>
  );
}

export function StoryStepper() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [autoPlay, setAutoPlay] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    if (mq.matches) {
      setAutoPlay(false);
    }
    const onChange = (e: MediaQueryListEvent) => {
      setReducedMotion(e.matches);
      if (e.matches) setAutoPlay(false);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    if (!autoPlay || reducedMotion) return;
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.hidden) return;
      setActiveIndex((prev) => (prev + 1) % STORY_STEPS.length);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [autoPlay, reducedMotion]);

  const current = STORY_STEPS[activeIndex] ?? STORY_STEPS[0];

  return (
    <div className="ep-card p-5 sm:p-7">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule pb-4">
        <div
          role="tablist"
          aria-label="How deRoute protects a message in four steps"
          className="flex flex-wrap items-center gap-2"
        >
          {STORY_STEPS.map((item, idx) => {
            const isSelected = idx === activeIndex;
            return (
              <button
                key={item.step}
                type="button"
                role="tab"
                aria-selected={isSelected}
                onClick={() => {
                  setAutoPlay(false);
                  setActiveIndex(idx);
                }}
                className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                  isSelected
                    ? "bg-ink text-paper"
                    : "bg-paper-2 text-ink-2 hover:bg-paper-3 hover:text-ink"
                }`}
              >
                <span className="font-mono text-[11px] opacity-80">
                  {item.step}.
                </span>{" "}
                {item.shortLabel}
              </button>
            );
          })}
        </div>

        {!reducedMotion && (
          <button
            type="button"
            onClick={() => setAutoPlay((prev) => !prev)}
            aria-pressed={autoPlay}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {autoPlay ? "Pause story" : "Play story"}
          </button>
        )}
      </div>

      <div className="mt-6 grid grid-cols-1 items-center gap-6 lg:grid-cols-12">
        <div className="lg:col-span-6">
          <StepIllustration step={current.step} />
        </div>

        <div className="flex flex-col justify-between space-y-4 lg:col-span-6">
          <div>
            <div className="ep-label">
              Step {current.step} of {STORY_STEPS.length}
            </div>
            <h3 className="ep-display mt-1.5 text-2xl sm:text-3xl">
              {current.title}
            </h3>
            <p className="mt-2 rounded border border-rule bg-paper-2 px-3 py-2 text-xs font-medium text-ink-2">
              Everyday picture: {current.metaphor}
            </p>
            <p className="mt-3 text-sm leading-relaxed text-ink-2">
              {current.body}
            </p>
            <p className="mt-3 text-xs font-semibold text-ink">
              Key point: {current.takeaway}
            </p>
          </div>

          <div className="pt-1">
            <TechDetails label="Show technical details for this step">
              <div className="space-y-1.5 text-xs leading-relaxed text-ink-2">
                <p className="font-mono text-[11px] font-medium text-ink">
                  {current.techSummary}
                </p>
                <p>{current.techDetail}</p>
              </div>
            </TechDetails>
          </div>

          <div className="flex items-center justify-between border-t border-rule pt-3">
            <button
              type="button"
              onClick={() => {
                setAutoPlay(false);
                setActiveIndex(
                  (prev) => (prev - 1 + STORY_STEPS.length) % STORY_STEPS.length
                );
              }}
              className="ep-btn-ghost px-3 py-1 text-xs"
            >
              Previous step
            </button>
            <span className="font-mono text-xs text-ink-3">
              {current.step} / {STORY_STEPS.length}
            </span>
            <button
              type="button"
              onClick={() => {
                setAutoPlay(false);
                setActiveIndex((prev) => (prev + 1) % STORY_STEPS.length);
              }}
              className="ep-btn-ghost px-3 py-1 text-xs"
            >
              Next step
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
