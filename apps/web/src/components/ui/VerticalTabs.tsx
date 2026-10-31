"use client";

import { useRef, type KeyboardEvent } from "react";
import CountBadge from "./CountBadge";

/**
 * A column of tabs over one panel: one part of a thing shown at a time.
 *
 * The ARIA tabs pattern, so a keyboard reaches it the way a screen reader
 * announces it: Tab lands on the selected tab only (a roving tab index),
 * Up and Down move to the previous and next tab and select it, Home and End
 * to the first and last. Stacked as a row on a phone, where Left and Right
 * do the same. The panel is the caller's, under `panelId`.
 */
export interface VerticalTabItem<K extends string> {
  key: K;
  label: string;
  count?: number | null;
}

/** The tab a key press moves to from `index`, or null for a key the tabs ignore. */
export function nextTabIndex(key: string, index: number, total: number): number | null {
  if (total === 0) return null;
  switch (key) {
    case "ArrowDown":
    case "ArrowRight":
      return (index + 1) % total;
    case "ArrowUp":
    case "ArrowLeft":
      return (index - 1 + total) % total;
    case "Home":
      return 0;
    case "End":
      return total - 1;
    default:
      return null;
  }
}

export default function VerticalTabs<K extends string>({
  items,
  selected,
  onSelect,
  label,
  panelId,
  idPrefix,
}: {
  items: readonly VerticalTabItem<K>[];
  selected: K;
  onSelect: (key: K) => void;
  /** The tab list's accessible name. */
  label: string;
  panelId: string;
  /** Prefix of each tab's id, which the panel is labelled by (`${idPrefix}-${key}`). */
  idPrefix: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const index = items.findIndex((t) => t.key === selected);
    const next = nextTabIndex(e.key, Math.max(0, index), items.length);
    if (next === null) return;
    e.preventDefault();
    onSelect(items[next].key);
    refs.current[next]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      aria-orientation="vertical"
      onKeyDown={onKeyDown}
      /* `relative` so the badges' screen-reader text, absolutely positioned,
       * is clipped here instead of widening the page. */
      className="relative flex shrink-0 gap-1 overflow-x-auto sm:w-40 sm:flex-col"
    >
      {items.map((t, i) => {
        const current = t.key === selected;
        return (
          <button
            key={t.key}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-${t.key}`}
            aria-selected={current}
            aria-controls={panelId}
            tabIndex={current ? 0 : -1}
            onClick={() => onSelect(t.key)}
            className={`flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-left text-xs ${
              current ? "bg-bg-active font-medium text-text-primary" : "text-text-secondary hover:bg-bg-hover hover:text-text-primary"
            }`}
          >
            {t.label}
            {t.count != null && <CountBadge count={t.count} label="items" />}
          </button>
        );
      })}
    </div>
  );
}
