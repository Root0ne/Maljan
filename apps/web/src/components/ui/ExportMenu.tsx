"use client";

import { useEffect, useId, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { getErrorMessage } from "@/lib/errors";
import { buttonClass } from "./Button";
import type { ExportGroup, ExportItem } from "./exportActions";

/**
 * The one way out of a page: a labelled "Export" button that opens a menu
 * grouped by intent (`exportActions`).
 *
 * One entry point instead of a row of equal buttons, and visible and
 * labelled rather than an unnamed "…". The menu follows the menu-button
 * pattern: Enter, Space or the arrow keys open it, arrows move between items,
 * Escape and a click outside close it and return focus to the button. An
 * item busy downloading says so in place; a failed one says what failed
 * inside the menu and focus returns to its first item.
 *
 * An item that cannot be used is `aria-disabled`, not `disabled`: it stays
 * in the arrow-key walk and its reason is its description, so a keyboard or
 * screen-reader user learns why it is unavailable, not only that it is.
 */

/** Every item, in the order the arrow keys walk them. */
export function walkableItems(groups: readonly ExportGroup[]): ExportItem[] {
  return groups.flatMap((g) => g.items);
}

/** The items a click does something for. */
export function usableItems(groups: readonly ExportGroup[]): ExportItem[] {
  return walkableItems(groups).filter((i) => !i.unavailable);
}

export default function ExportMenu({
  groups,
  label = "Export",
}: {
  groups: readonly ExportGroup[];
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const items = () =>
    Array.from(menu.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? []);

  useEffect(() => {
    if (!open) return;
    items()[0]?.focus();
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const close = () => {
    setOpen(false);
    button.current?.focus();
  };

  const onMenuKey = (e: React.KeyboardEvent) => {
    const list = items();
    const at = list.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape" || e.key === "Tab") {
      if (e.key === "Escape") e.preventDefault();
      close();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      list[(at + 1) % list.length]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      list[(at - 1 + list.length) % list.length]?.focus();
    } else if (e.key === "Home") {
      e.preventDefault();
      list[0]?.focus();
    } else if (e.key === "End") {
      e.preventDefault();
      list[list.length - 1]?.focus();
    }
  };

  const run = async (item: ExportItem) => {
    // aria-disabled does not stop a click, so the guard does.
    if (item.unavailable || busy !== null) return;
    setBusy(item.key);
    setError(null);
    try {
      await item.run();
      close();
    } catch (err) {
      setError(`Could not export ${item.label}: ${getErrorMessage(err)}`);
      items()[0]?.focus();
    } finally {
      setBusy(null);
    }
  };

  return (
    <div ref={root} className="relative inline-block">
      <button
        ref={button}
        type="button"
        data-variant="secondary"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && !open) {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className={buttonClass("secondary", "sm")}
      >
        {label}
        <ChevronDown aria-hidden="true" className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div
          ref={menu}
          id={menuId}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKey}
          // The menu opens from the sticky header, which the page does not
          // scroll: a menu taller than the window scrolls itself, so its last
          // items stay reachable.
          className="absolute right-0 z-40 mt-1 max-h-[calc(100vh-8rem)] w-72 max-w-[calc(100vw-2rem)] overflow-y-auto rounded-md border border-border bg-bg-surface py-1 shadow-lg"
        >
          {groups.map((group) => (
            <div key={group.key} role="group" aria-labelledby={`${menuId}-${group.key}`} className="py-1">
              <div id={`${menuId}-${group.key}`} className="px-3 pb-1 pt-1.5 text-[11px] font-semibold text-text-muted">
                {group.label}
              </div>
              {group.items.map((item) => {
                const inactive = Boolean(item.unavailable) || busy !== null;
                const noteId = `${menuId}-${item.key}-note`;
                const note = item.unavailable ?? item.hint;
                return (
                  <button
                    key={item.key}
                    type="button"
                    role="menuitem"
                    aria-disabled={inactive || undefined}
                    aria-describedby={note ? noteId : undefined}
                    onClick={() => void run(item)}
                    className="flex w-full flex-col items-start px-3 py-1.5 text-left hover:bg-bg-hover focus:bg-bg-hover aria-disabled:cursor-not-allowed"
                  >
                    <span className={`text-sm ${item.unavailable ? "text-text-disabled" : "text-text-primary"}`}>
                      {busy === item.key ? `Preparing ${item.label}…` : item.label}
                    </span>
                    {note && (
                      <span id={noteId} className="text-[11px] text-text-muted">
                        {note}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
          {error && (
            <div role="alert" className="mx-2 mb-1 mt-1 rounded border border-status-red/30 px-2 py-1.5 text-xs text-status-red">
              {error}
            </div>
          )}
        </div>
      )}
      {error && !open && (
        <div
          role="alert"
          className="absolute right-0 z-30 mt-1 w-72 max-w-[calc(100vw-2rem)] rounded border border-status-red/30 bg-bg-surface px-2 py-1.5 text-xs text-status-red"
        >
          {error}
        </div>
      )}
    </div>
  );
}
