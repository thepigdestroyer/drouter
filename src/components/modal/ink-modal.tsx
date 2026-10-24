"use client";

import React, { useEffect, useId, useRef } from "react";
import {
  FOCUSABLE_SELECTOR,
  MODAL_PLAIN_SUMMARY,
  resolveFocusTrapTarget,
  resolveNextTabId,
} from "@/components/modal/modal-a11y";

export interface InkModalTab<T extends string = string> {
  id: T;
  label: string;
}

export interface InkModalProps<T extends string = string> {
  open: boolean;
  onClose: () => void;
  titleId: string;
  eyebrow: string;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  tabs: ReadonlyArray<InkModalTab<T>>;
  activeTab: T;
  onSelectTab: (tabId: T) => void;
  tabListLabel?: string;
  maxWidthClass?: string;
  summaryText?: string;
  summaryNote?: React.ReactNode;
  children: React.ReactNode;
}

const INK_BLOOM_CSS = `
@keyframes ep-ink-backdrop-fade {
  from { opacity: 0; }
  to { opacity: 1; }
}
@keyframes ep-ink-modal-bloom {
  0% {
    opacity: 0;
    transform: scale(0.955) translateY(8px);
  }
  65% {
    opacity: 1;
    transform: scale(1.004) translateY(0);
  }
  100% {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}
@keyframes ep-ink-drop-spread {
  0% {
    opacity: 0;
    transform: scale(0.35);
  }
  100% {
    opacity: 0.08;
    transform: scale(1);
  }
}
@media (prefers-reduced-motion: no-preference) {
  .ep-ink-backdrop-anim {
    animation: ep-ink-backdrop-fade 180ms ease-out both;
  }
  .ep-ink-surface-anim {
    animation: ep-ink-modal-bloom 250ms cubic-bezier(0.16, 1, 0.3, 1) both;
  }
  .ep-ink-blot-anim {
    animation: ep-ink-drop-spread 420ms cubic-bezier(0.16, 1, 0.3, 1) both;
  }
}
@media (prefers-reduced-motion: reduce) {
  .ep-ink-backdrop-anim,
  .ep-ink-surface-anim,
  .ep-ink-blot-anim {
    animation: none !important;
    transition: none !important;
    transform: none !important;
  }
}
`;

export function InkModal<T extends string>({
  open,
  onClose,
  titleId,
  eyebrow,
  title,
  subtitle,
  tabs,
  activeTab,
  onSelectTab,
  tabListLabel = "Modal sections",
  maxWidthClass = "max-w-5xl",
  summaryText = MODAL_PLAIN_SUMMARY,
  summaryNote,
  children,
}: InkModalProps<T>) {
  const instanceId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  // Reset body scroll to top when switching tabs and keep active tab centered in horizontal tablist
  useEffect(() => {
    if (!open) return;
    if (bodyRef.current) {
      bodyRef.current.scrollTop = 0;
    }
    const syncActiveTabScroll = () => {
      const activeTabBtn = tabRefs.current[activeTab];
      if (activeTabBtn && typeof activeTabBtn.scrollIntoView === "function") {
        activeTabBtn.scrollIntoView({ block: "nearest", inline: "center" });
      }
    };
    syncActiveTabScroll();
    window.addEventListener("resize", syncActiveTabScroll);
    return () => {
      window.removeEventListener("resize", syncActiveTabScroll);
    };
  }, [open, activeTab]);

  // Focus capture, initial focus, Escape & Tab trap, body scroll lock, and return focus on close
  useEffect(() => {
    if (!open) return;

    if (
      typeof document !== "undefined" &&
      document.activeElement instanceof HTMLElement
    ) {
      previousFocusRef.current = document.activeElement;
    }

    const prevOverflow =
      typeof document !== "undefined" ? document.body.style.overflow : "";
    if (typeof document !== "undefined") {
      document.body.style.overflow = "hidden";
    }

    const focusTimer = window.setTimeout(() => {
      closeButtonRef.current?.focus();
    }, 0);

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current();
        return;
      }

      if (event.key === "Tab" && dialogRef.current) {
        const nodes = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
        ).filter(
          (el) =>
            !el.hasAttribute("disabled") &&
            el.getAttribute("aria-hidden") !== "true",
        );

        const activeEl =
          document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null;
        const wrapTarget = resolveFocusTrapTarget(
          nodes,
          activeEl,
          event.shiftKey,
        );
        if (wrapTarget) {
          event.preventDefault();
          wrapTarget.focus();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("keydown", handleKeyDown);
      if (typeof document !== "undefined") {
        document.body.style.overflow = prevOverflow;
      }
      const toRestore = previousFocusRef.current;
      if (toRestore && typeof toRestore.focus === "function") {
        try {
          toRestore.focus();
        } catch {
          // Ignore focus restoration errors if element was unmounted
        }
      }
    };
  }, [open]);

  if (!open) return null;

  const handleBackdropClick = (event: React.MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) {
      onClose();
    }
  };

  const handleTabKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const tabIds = tabs.map((t) => t.id);
    const nextId = resolveNextTabId(tabIds, activeTab, event.key);
    if (nextId) {
      event.preventDefault();
      onSelectTab(nextId);
      tabRefs.current[nextId]?.focus();
    }
  };

  const activePanelId = `${instanceId}-panel-${activeTab}`;
  const activeTabDomId = `${instanceId}-tab-${activeTab}`;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      data-testid="ink-modal-backdrop"
      onClick={handleBackdropClick}
      className="ep-ink-backdrop-anim fixed inset-0 z-50 flex items-center justify-center bg-ink/50 p-2.5 sm:p-5"
    >
      <style dangerouslySetInnerHTML={{ __html: INK_BLOOM_CSS }} />

      <div
        ref={dialogRef}
        data-testid="ink-modal-surface"
        className={`ep-card ep-ink-surface-anim relative z-10 flex max-h-[calc(100dvh-1.25rem)] w-full ${maxWidthClass} flex-col overflow-hidden border border-ink bg-paper text-ink shadow-xl sm:max-h-[calc(100dvh-2.5rem)]`}
      >
        {/* Fixed Header: never shrinks, never overlaps tabs */}
        <header
          data-testid="ink-modal-header"
          className="relative z-20 flex shrink-0 items-start justify-between gap-3 overflow-hidden border-b border-rule bg-paper-2 px-4 py-3.5 sm:px-6 sm:py-4"
        >
          {/* Decorative ink bloom blot in top-right corner */}
          <svg
            aria-hidden="true"
            viewBox="0 0 160 160"
            className="ep-ink-blot-anim pointer-events-none absolute -top-12 -right-10 h-36 w-36 text-ink opacity-[0.06]"
          >
            <path
              fill="currentColor"
              d="M83.5,14C108,15.5,134,31,142.5,54.5C151,78,141.5,109,120.5,126.5C99.5,144,67,148,43.5,133.5C20,119,5.5,86,12.5,58.5C19.5,31,59,12.5,83.5,14Z"
            />
          </svg>

          <div className="relative z-10 min-w-0 flex-1">
            <div className="ep-label">{eyebrow}</div>
            <h2
              id={titleId}
              className="ep-display mt-0.5 text-lg leading-snug sm:text-2xl"
            >
              {title}
            </h2>
            {subtitle && (
              <div className="mt-1 text-xs leading-relaxed text-ink-2">
                {subtitle}
              </div>
            )}
          </div>

          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close window"
            className="ep-btn-ghost relative z-10 shrink-0 px-3 py-1.5 text-xs font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink"
          >
            Close
          </button>
        </header>

        {/* Non-clipping, non-shrinking Tab Bar */}
        <div
          data-testid="ink-modal-tabbar"
          className="relative z-20 shrink-0 border-b border-rule bg-paper"
        >
          <div
            role="tablist"
            aria-label={tabListLabel}
            onKeyDown={handleTabKeyDown}
            className="flex items-center gap-1.5 overflow-x-auto overscroll-x-contain px-3 py-2.5 sm:px-6"
            style={{ scrollbarWidth: "thin" }}
          >
            {tabs.map((t) => {
              const active = activeTab === t.id;
              const tabDomId = `${instanceId}-tab-${t.id}`;
              const panelDomId = `${instanceId}-panel-${t.id}`;
              return (
                <button
                  key={t.id}
                  ref={(el) => {
                    tabRefs.current[t.id] = el;
                  }}
                  id={tabDomId}
                  role="tab"
                  type="button"
                  aria-selected={active}
                  aria-controls={panelDomId}
                  onClick={() => onSelectTab(t.id)}
                  className={`shrink-0 whitespace-nowrap rounded px-3 py-1.5 text-xs font-medium leading-normal transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink ${
                    active
                      ? "border border-ink bg-ink text-paper"
                      : "border border-rule bg-paper-2/70 text-ink-2 hover:border-ink hover:bg-paper-2 hover:text-ink"
                  }`}
                >
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Separately Scrolling Body */}
        <div
          ref={bodyRef}
          id={activePanelId}
          role="tabpanel"
          aria-labelledby={activeTabDomId}
          tabIndex={0}
          data-testid="ink-modal-body"
          className="min-h-0 flex-1 space-y-5 overflow-y-auto overscroll-contain p-4 text-sm focus-visible:outline-none sm:p-6"
        >
          {/* Plain-language summary before the raw records */}
          <div
            data-testid="ink-modal-plain-summary"
            className="rounded border border-rule-2 bg-paper-2 px-3.5 py-3 text-xs leading-relaxed text-ink sm:px-4 sm:py-3.5 sm:text-sm"
          >
            <p className="font-medium text-ink">{summaryText}</p>
            {summaryNote && (
              <p className="mt-1 text-xs text-ink-2">{summaryNote}</p>
            )}
          </div>

          {children}
        </div>
      </div>
    </div>
  );
}

export { MODAL_PLAIN_SUMMARY } from "@/components/modal/modal-a11y";
