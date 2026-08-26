"use client";

import { useEffect, useRef, useState } from "react";
import { useAuth } from "@/lib/auth";
import SearchPalette from "@/components/layout/SearchPalette";

export default function Header() {
  const { user, logout } = useAuth();
  const [value, setValue] = useState("");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  /* Global Cmd/Ctrl+K shortcut to focus the search and open the palette. */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isK = e.key === "k" || e.key === "K";
      if (!isK) return;
      if (!(e.metaKey || e.ctrlKey)) return;
      e.preventDefault();
      setPaletteOpen(true);
      inputRef.current?.focus();
      inputRef.current?.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <header className="h-12 flex items-center justify-between px-4 border-b border-border bg-bg-surface">
      {/* Search */}
      <div className="flex items-center flex-1 max-w-2xl">
        <div className="relative w-full">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted"
            width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          <input
            ref={inputRef}
            id="global-search"
            name="global-search"
            type="text"
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setPaletteOpen(true);
            }}
            onFocus={() => setPaletteOpen(true)}
            onKeyDown={() => setPaletteOpen(true)}
            placeholder="Search for files, hashes, IPs, or malware families..."
            className="w-full h-8 pl-9 pr-12 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
            // The input drives a popup palette, so it is an ARIA combobox.
            // aria-expanded/aria-controls are only allowed on that role — without
            // it Lighthouse flags aria-allowed-attr. id/name silence the
            // "form field should have an id or name" DevTools issue; aria-label
            // names the field for screen readers (placeholder is not a name).
            role="combobox"
            aria-label="Search files, hashes, IPs, or malware families"
            aria-autocomplete="list"
            aria-haspopup="listbox"
            aria-expanded={paletteOpen}
            aria-controls="global-search-palette"
          />
          <span className="hidden sm:flex absolute right-2 top-1/2 -translate-y-1/2 items-center gap-1 text-[11px] text-text-muted pointer-events-none">
            <kbd className="px-1 py-px border border-border rounded bg-bg-surface">Ctrl</kbd>
            <kbd className="px-1 py-px border border-border rounded bg-bg-surface">K</kbd>
          </span>
          <SearchPalette
            open={paletteOpen}
            query={value}
            onClose={() => setPaletteOpen(false)}
            onSelect={() => setValue("")}
          />
        </div>
      </div>

      {/* User */}
      <div className="flex items-center gap-3 ml-4">
        {user && (
          <>
            <span className="text-xs text-text-secondary">{user.email}</span>
            <button
              onClick={logout}
              className="text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              Sign out
            </button>
          </>
        )}
      </div>
    </header>
  );
}
