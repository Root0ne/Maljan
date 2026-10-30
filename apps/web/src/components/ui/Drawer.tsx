"use client";

import { useEffect, useId, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

/**
 * A detail panel that slides over the right edge of the page.
 *
 * Details open here instead of nesting a third level into the page: the
 * table a reader came from stays where it was, and closing the panel
 * (Escape, the close button, or a click on the dimmed page) puts focus back
 * on the control that opened it. It is a modal dialog while open: Tab stays
 * inside it, and everything else on the page is `inert`, so neither a
 * screen reader's virtual cursor nor a pointer reaches what is behind it.
 * Full width on a phone, a fixed column on a wider screen. The dimming is a
 * flat colour: no blur (styleRules).
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

/**
 * Makes every element outside `keep` inert: the siblings of `keep` and of
 * each of its ancestors up to <body>. Returns the undo, which restores only
 * what this call changed.
 */
export function inertOutside(keep: Element): () => void {
  const changed: Element[] = [];
  for (let node: Element | null = keep; node && node !== document.body; node = node.parentElement) {
    const parent: Element | null = node.parentElement;
    if (!parent) break;
    for (const sibling of Array.from(parent.children)) {
      if (sibling === node || sibling.hasAttribute("inert") || sibling.tagName === "SCRIPT") continue;
      sibling.setAttribute("inert", "");
      changed.push(sibling);
    }
  }
  return () => changed.forEach((el) => el.removeAttribute("inert"));
}

/** Where Tab goes from `active` inside `panel`, or null to let the browser move it. */
export function trappedFocus(panel: Element, active: Element | null, backwards: boolean): HTMLElement | null {
  const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (focusable.length === 0) return null;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (backwards && (active === first || !panel.contains(active))) return last;
  if (!backwards && (active === last || !panel.contains(active))) return first;
  return null;
}

export default function Drawer({
  open,
  title,
  onClose,
  returnFocusTo,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  /** The control that opened the panel (the click's `currentTarget`); focus
   *  goes back to it on close. Without one, whatever had focus at opening. */
  returnFocusTo?: HTMLElement | null;
  children?: ReactNode;
}) {
  const titleId = useId();
  const root = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  /* Read through refs so a parent that passes new values each render does
   * not re-run the effect, which would move focus back to the close button
   * and forget which control opened the panel. */
  const closeHandler = useRef(onClose);
  const returnTarget = useRef(returnFocusTo);
  useEffect(() => {
    closeHandler.current = onClose;
    returnTarget.current = returnFocusTo;
  }, [onClose, returnFocusTo]);

  useEffect(() => {
    if (!open) return;
    const opener = returnTarget.current ?? document.activeElement;
    const restoreInert = root.current ? inertOutside(root.current) : () => {};
    closeButton.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        closeHandler.current();
        return;
      }
      if (e.key !== "Tab" || !panel.current) return;
      const next = trappedFocus(panel.current, document.activeElement, e.shiftKey);
      if (next) {
        e.preventDefault();
        next.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      restoreInert();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div ref={root} className="fixed inset-0 z-50 flex justify-end">
      <div aria-hidden="true" className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="relative flex h-full w-full flex-col border-l border-border bg-bg-surface shadow-xl sm:w-[30rem]"
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <h2 id={titleId} className="text-base font-semibold text-text-primary">
            {title}
          </h2>
          <button
            ref={closeButton}
            type="button"
            onClick={onClose}
            aria-label="Close details"
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-text-secondary hover:bg-bg-hover hover:text-text-primary"
          >
            <X aria-hidden="true" className="h-4 w-4" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">{children}</div>
      </div>
    </div>
  );
}
