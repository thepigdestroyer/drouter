export const MODAL_PLAIN_SUMMARY =
  "What this shows: the sealed computer's signed proof that it runs the published code. You do not need to read this; it is here so experts can check our work.";

export const FOCUSABLE_SELECTOR = [
  "button:not([disabled])",
  "a[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

/**
 * Determines whether Tab / Shift+Tab needs to wrap focus inside the modal.
 * Returns the element that should receive focus when at the boundary (or when
 * focus is currently outside the modal), or `null` when native Tab movement
 * stays inside the modal.
 */
export function resolveFocusTrapTarget<T>(
  focusableItems: readonly T[],
  activeItem: T | null,
  shiftKey: boolean,
): T | null {
  if (focusableItems.length === 0) return null;
  const idx = activeItem !== null ? focusableItems.indexOf(activeItem) : -1;

  if (!shiftKey) {
    if (idx === -1 || idx === focusableItems.length - 1) {
      return focusableItems[0] ?? null;
    }
    return null;
  }

  if (idx <= 0) {
    return focusableItems[focusableItems.length - 1] ?? null;
  }
  return null;
}

/**
 * Computes the next tab ID for horizontal WAI-ARIA tablist keyboard navigation
 * (ArrowRight, ArrowLeft, Home, End).
 */
export function resolveNextTabId<T extends string>(
  tabIds: readonly T[],
  currentTabId: T,
  key: string,
): T | null {
  if (tabIds.length === 0) return null;
  const currentIndex = Math.max(0, tabIds.indexOf(currentTabId));

  if (key === "ArrowRight") {
    return tabIds[(currentIndex + 1) % tabIds.length] ?? null;
  }
  if (key === "ArrowLeft") {
    return (
      tabIds[(currentIndex - 1 + tabIds.length) % tabIds.length] ?? null
    );
  }
  if (key === "Home") {
    return tabIds[0] ?? null;
  }
  if (key === "End") {
    return tabIds[tabIds.length - 1] ?? null;
  }
  return null;
}
