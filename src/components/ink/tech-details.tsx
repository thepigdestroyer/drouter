"use client";

import React, { useState } from "react";

export interface TechDetailsProps {
  label?: string;
  summary?: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

export function TechDetails({
  label,
  summary,
  children,
  defaultOpen = false,
}: TechDetailsProps): React.JSX.Element {
  const [open, setOpen] = useState<boolean>(Boolean(defaultOpen));
  const resolvedLabel = label ?? "Show technical details";

  const handleSummaryClick = (e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault();
    setOpen((prev) => !prev);
  };

  return (
    <details
      open={open}
      data-tech-details={open ? "open" : "closed"}
      className="ep-tech-details rounded border border-rule bg-paper/85 text-ink transition-colors"
    >
      <summary
        onClick={handleSummaryClick}
        aria-expanded={open}
        className="ep-tech-summary flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-3.5 py-2.5 text-xs font-medium text-ink-2 select-none hover:bg-paper-2/70 hover:text-ink"
      >
        <span className="inline-flex items-center gap-2">
          <span
            aria-hidden="true"
            className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-rule-2 font-mono text-[10px] leading-none text-ink-2 transition-transform"
          >
            {open ? "-" : "+"}
          </span>
          <span className="font-mono text-xs text-ink">{resolvedLabel}</span>
          {summary ? (
            <span className="text-xs font-normal text-ink-2">{summary}</span>
          ) : null}
        </span>

        <span className="font-mono text-[11px] text-ink-3">
          {open ? "Hide" : "Expand"}
        </span>
      </summary>

      {open ? (
        <div className="ep-tech-body border-t border-rule bg-paper-2/90 p-3.5 text-xs leading-relaxed text-ink-2 sm:p-4">
          {children}
        </div>
      ) : null}
    </details>
  );
}

export default TechDetails;
