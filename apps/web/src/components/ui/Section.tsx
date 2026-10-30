"use client";

import { useId, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import CountBadge from "./CountBadge";

/**
 * A titled block of a page: a card with a header and a body.
 *
 * Its place on the page never moves. A section with nothing to show stays
 * where it is, greyed, collapsed and saying "Not found", so a reader learns
 * the layout once and an absence reads as an answer rather than as a section
 * that silently went missing. `count` puts the number beside the title;
 * `collapsible` makes the header the toggle.
 */
export interface SectionProps {
  title: string;
  /** How many items the body holds; drawn as a badge beside the title. */
  count?: number | null;
  /** True when there is nothing to show: the section draws its empty state. */
  empty?: boolean;
  /** What the empty state says; "Not found" by default. */
  emptyText?: string;
  collapsible?: boolean;
  /** Open on first render. An empty section starts closed whatever this says. */
  defaultOpen?: boolean;
  /** Controls beside the title (a copy-all, a "show all"). */
  actions?: ReactNode;
  className?: string;
  children?: ReactNode;
}

/** Whether a section starts open: an empty one never does. */
export function sectionStartsOpen(empty: boolean, collapsible: boolean, defaultOpen: boolean): boolean {
  if (empty) return false;
  return collapsible ? defaultOpen : true;
}

export default function Section({
  title,
  count,
  empty = false,
  emptyText = "Not found",
  collapsible = false,
  defaultOpen = true,
  actions,
  className = "",
  children,
}: SectionProps) {
  const [open, setOpen] = useState(() => sectionStartsOpen(empty, collapsible, defaultOpen));
  const headingId = useId();
  const bodyId = useId();
  const showBody = !empty && open;

  const titleRow = (
    <span className="flex items-center gap-2 min-w-0">
      {collapsible && !empty && (
        <ChevronRight
          aria-hidden="true"
          className={`h-3.5 w-3.5 shrink-0 text-text-muted ${open ? "rotate-90" : ""}`}
        />
      )}
      <span className={`truncate ${empty ? "text-text-muted" : "text-text-primary"}`}>{title}</span>
      {count != null && !empty && <CountBadge count={count} />}
      {empty && (
        <span className="rounded border border-border px-1.5 text-[11px] font-normal text-text-muted">
          {emptyText}
        </span>
      )}
    </span>
  );

  return (
    <section
      aria-labelledby={headingId}
      data-empty={empty ? "true" : undefined}
      className={`rounded-md border border-border ${empty ? "bg-bg-deep" : "bg-bg-surface"} ${className}`.trim()}
    >
      <div className="flex items-center justify-between gap-3 px-4 py-2.5">
        <h2 id={headingId} className="text-sm font-semibold min-w-0">
          {collapsible && !empty ? (
            <button
              type="button"
              aria-expanded={open}
              aria-controls={bodyId}
              onClick={() => setOpen((v) => !v)}
              className="flex items-center text-left hover:underline"
            >
              {titleRow}
            </button>
          ) : (
            titleRow
          )}
        </h2>
        {actions && !empty && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {showBody && (
        <div id={bodyId} className="border-t border-border-light px-4 py-3">
          {children}
        </div>
      )}
    </section>
  );
}
