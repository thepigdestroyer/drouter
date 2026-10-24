"use client";

import React, { useId, useMemo, useState } from "react";
import { TechDetails } from "@/components/ink/tech-details";
import {
  LIVE_SCRUB_PRESETS,
  runLandingPromptPreview,
} from "./landing-copy";

export function LiveScrubDemo() {
  const inputId = useId();
  const [text, setText] = useState<string>(LIVE_SCRUB_PRESETS[0].sample);

  const preview = useMemo(() => runLandingPromptPreview(text), [text]);

  return (
    <div className="ep-card p-5 sm:p-7">
      <div className="flex flex-col justify-between gap-3 border-b border-rule pb-4 sm:flex-row sm:items-center">
        <div>
          <div className="ep-label">Try it right now in your browser</div>
          <h3 className="ep-display mt-1 text-xl sm:text-2xl">
            Type a fake email or phone number and watch it disappear
          </h3>
        </div>
        <span className="ep-pass self-start sm:self-center">
          Runs on your device · Nothing is sent
        </span>
      </div>

      {/* Quick preset buttons */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-ink-3">Quick examples:</span>
        {LIVE_SCRUB_PRESETS.map((preset) => {
          const isActive = text === preset.sample;
          return (
            <button
              key={preset.id}
              type="button"
              onClick={() => setText(preset.sample)}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                isActive
                  ? "bg-ink text-paper"
                  : "bg-paper-2 text-ink-2 hover:bg-paper-3 hover:text-ink"
              }`}
            >
              {preset.label}
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => setText("")}
          className="rounded border border-rule px-2.5 py-1 text-xs text-ink-3 hover:bg-paper-2 hover:text-ink"
        >
          Clear
        </button>
      </div>

      {/* Side-by-side interactive comparison */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Left: What you type */}
        <div className="flex flex-col justify-between rounded border border-rule bg-paper p-4">
          <div>
            <label
              htmlFor={inputId}
              className="block font-mono text-xs uppercase tracking-wider text-ink-3"
            >
              1. What you type on your screen
            </label>
            <textarea
              id={inputId}
              rows={4}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Type a sentence with a fake email like sam@example.com or a phone number like 415-555-0142..."
              className="ep-input mt-2.5 resize-y text-sm leading-relaxed"
            />
          </div>
          <p className="mt-3 text-xs text-ink-3">
            Try typing any fake email address, phone number, street address, or account number.
          </p>
        </div>

        {/* Right: What leaves your device */}
        <div className="flex flex-col justify-between rounded border border-rule bg-paper-2 p-4">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs uppercase tracking-wider text-ink-3">
                2. What gets locked and sent to the AI
              </span>
              <span className="ep-muted-chip">
                {preview.hiddenCount === 1
                  ? "1 personal detail hidden"
                  : `${preview.hiddenCount} personal details hidden`}
              </span>
            </div>

            <div
              aria-live="polite"
              className="mt-2.5 min-h-[96px] rounded border border-rule bg-paper p-3 text-sm leading-relaxed text-ink"
            >
              {preview.segments.length === 0 ? (
                <span className="text-ink-4">
                  Start typing on the left to see what leaves your browser...
                </span>
              ) : (
                preview.segments.map((seg, idx) =>
                  seg.type === "placeholder" ? (
                    <mark
                      key={`${seg.value}-${idx}`}
                      title={`Hidden ${seg.friendlyKind ?? "personal detail"}`}
                      className="mx-0.5 inline-flex items-center gap-1 rounded bg-ink px-1.5 py-0.5 font-mono text-xs font-medium text-paper"
                    >
                      <span>{seg.value}</span>
                    </mark>
                  ) : (
                    <span key={idx}>{seg.value}</span>
                  )
                )
              )}
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-ink-2">
            <span>
              Every message looks the same size from outside ({preview.uniformSizeChars.toLocaleString()} characters).
            </span>
            {preview.hiddenItems.length > 0 && (
              <span className="font-mono text-[11px] text-ink-3">
                Hidden:{" "}
                {preview.hiddenItems
                  .map((item) => `${item.friendlyKind} -> ${item.placeholder}`)
                  .join(", ")}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Step 3 of preview: How the reply restores your words */}
      <div className="mt-4 rounded border border-rule bg-paper-2 px-4 py-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-xs text-ink-2">
            <span className="font-mono uppercase tracking-wider text-ink-3">
              3. When the AI replies:{" "}
            </span>
            <span>{preview.restoredModelReply}</span>
          </div>
          <span className="font-mono text-[11px] text-ink-3">
            Restored on your screen only
          </span>
        </div>
      </div>

      {/* Optional technical details disclosure */}
      <div className="mt-4">
        <TechDetails label="Show technical details for this preview">
          <div className="space-y-2 text-xs text-ink-2">
            <p>
              This box calls <code className="font-mono">preparePrompt(text)</code> from{" "}
              <code className="font-mono">@/lib/pipeline</code> directly in your browser.
            </p>
            <div className="grid grid-cols-1 gap-2 font-mono text-[11px] sm:grid-cols-3">
              <div className="rounded border border-rule bg-paper p-2">
                PII risk score before: {preview.rawPrepared.report.riskBefore}/100
              </div>
              <div className="rounded border border-rule bg-paper p-2">
                PII risk score after: {preview.rawPrepared.report.riskAfter}/100
              </div>
              <div className="rounded border border-rule bg-paper p-2">
                Padded bucket bytes: {preview.rawPrepared.bucketBytes} B
              </div>
            </div>
          </div>
        </TechDetails>
      </div>
    </div>
  );
}
