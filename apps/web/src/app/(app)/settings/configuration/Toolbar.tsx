"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { useSettingsContext } from "./SettingsContext";

const SEARCH_PATH = "/settings/configuration/search";

/** Triggers a browser download of `text` as `filename` — no server round trip
 * beyond the fetch already made; the viewer never sees a bare data: link. */
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function DownloadIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="w-3.5 h-3.5"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M8 2v8" />
      <path d="M4.5 7.5 8 11l3.5-3.5" />
      <path d="M2.5 13h11" />
    </svg>
  );
}

/**
 * The strip above every settings page: search, the "only changed" filter, the
 * override export, and the two banners that belong to the whole console (the
 * read-only-secrets warning and the last failed action).
 */
export default function Toolbar() {
  const s = useSettingsContext();
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const onSearchPage = pathname === SEARCH_PATH;
  const urlQuery = onSearchPage ? (searchParams.get("q") ?? "") : "";

  const [query, setQuery] = useState(urlQuery);
  const [toast, setToast] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // The box mirrors `?q` on the search page and is empty everywhere else, so
  // picking a group in the rail clears the query it navigated away from. The
  // adjustment happens during render rather than in an effect: the box must
  // never paint the previous page's query for a frame.
  const [mirrored, setMirrored] = useState(urlQuery);
  if (mirrored !== urlQuery) {
    setMirrored(urlQuery);
    setQuery(urlQuery);
  }

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed || trimmed === urlQuery) return;
    const t = setTimeout(() => {
      router.push(`${SEARCH_PATH}?q=${encodeURIComponent(trimmed)}`);
    }, 300);
    return () => clearTimeout(t);
  }, [query, urlQuery, router]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(t);
  }, [toast]);

  return (
    <div className="mb-4">
      <form
        className="flex items-center gap-3 flex-wrap"
        onSubmit={(e) => {
          e.preventDefault();
          const trimmed = query.trim();
          if (trimmed) router.push(`${SEARCH_PATH}?q=${encodeURIComponent(trimmed)}`);
        }}
      >
        <div className="flex-1 min-w-[240px]">
          <label htmlFor="settings-search" className="sr-only">
            Search settings
          </label>
          <input
            id="settings-search"
            type="search"
            placeholder="Search settings (key, title, description)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-bg-deep border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          />
        </div>
        <span className="flex items-center gap-2 text-xs text-text-secondary shrink-0">
          <button
            type="button"
            role="switch"
            aria-checked={s.onlyChanged}
            aria-label="Only changed"
            onClick={() => s.setOnlyChanged(!s.onlyChanged)}
            className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              s.onlyChanged ? "bg-accent" : "bg-border"
            }`}
          >
            <span
              className={`inline-block h-4 w-4 mt-0.5 rounded-full bg-white transition-transform ${
                s.onlyChanged ? "translate-x-4" : "translate-x-0.5"
              }`}
            />
          </button>
          <span>Only changed</span>
        </span>
        <button
          type="button"
          className="flex items-center gap-1.5 text-xs text-accent-strong shrink-0"
          onClick={async () => {
            setExportError(null);
            try {
              const text = await api.exportSettings();
              downloadText("maljan-settings.env", text);
              setToast("Overrides downloaded as maljan-settings.env");
            } catch (e) {
              setExportError(getErrorMessage(e));
            }
          }}
        >
          <DownloadIcon />
          Export overrides
        </button>
      </form>

      {s.schema && !s.schema.secrets_available && (
        <div
          className="w-full text-[11px] text-status-orange bg-status-orange/10 border border-status-orange/20 rounded px-3 py-2 mt-3"
          role="status"
        >
          SETTINGS_ENCRYPTION_KEY is not set: secrets are read-only
        </div>
      )}
      {exportError && (
        <div className="text-xs text-status-red mt-3" role="alert">
          {exportError}
        </div>
      )}
      {s.actionError && (
        <div
          className="flex items-center justify-between gap-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-3 py-2 mt-3"
          role="alert"
        >
          <span>{s.actionError}</span>
          <button
            type="button"
            aria-label="Dismiss error"
            className="text-status-red/80 hover:text-status-red shrink-0"
            onClick={s.clearActionError}
          >
            &times;
          </button>
        </div>
      )}
      {toast && (
        <div className="text-xs text-text-secondary mt-3" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}
