"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { SettingsValidationError } from "@/types/settings";
import type { PatchResult } from "@/types/settings";
import { buildImportPreview, type ImportDoc, type ImportPreview } from "./importPreview";
import { useSettingsContext } from "./SettingsContext";
import { appliesSummary, APPLIES_SENTENCE } from "./vocabulary";

/** Reads the picked file and normalises whatever JSON it holds into the
 *  shape `buildImportPreview` expects. A file that isn't valid JSON, or
 *  whose top level isn't an object, throws — the caller turns that into the
 *  dialog's "could not read this file" message rather than a stack trace.
 *  A `values` field that is missing, or isn't itself an object, is passed
 *  through as-is: `buildImportPreview` treats that the same as an
 *  unsupported `format` rather than the caller silently defaulting it to
 *  `{}` and reporting "0 changes" with no explanation. */
async function parseImportFile(file: File): Promise<ImportDoc> {
  const text = await file.text();
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("not an object");
  }
  const record = parsed as Record<string, unknown>;
  return { format: String(record.format ?? ""), values: record.values };
}

/** Everything inside `container` a Tab key could land on — the same
 *  selector list every hand-rolled focus trap in the wild converges on.
 *  `disabled` and negative-tabindex elements are excluded by the browser's
 *  own focus order, so nothing extra is needed for the primary button while
 *  it's disabled. */
function focusableIn(container: HTMLElement): HTMLElement[] {
  const selector =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(container.querySelectorAll<HTMLElement>(selector));
}

/** "Import configuration" opens this: pick a `.json` export, see what it
 *  would change against the settings in effect right now, and send only
 *  the keys that actually differ. Modelled on `ChangesBar`'s review dialog
 *  for the a11y contract (`role="dialog"`, `aria-modal`, a labelled panel,
 *  Escape to close) — this one additionally moves focus onto its own file
 *  input on mount, since unlike the review dialog it opens with nothing on
 *  screen to read yet. */
export default function ImportDialog({ onClose }: { onClose: () => void }) {
  const ctx = useSettingsContext();
  const panelRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [fileName, setFileName] = useState<string | null>(null);
  const [doc, setDoc] = useState<ImportDoc | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string> | null>(null);
  const [result, setResult] = useState<PatchResult | null>(null);

  // Moves focus in on mount and — Important 1 — back out to whatever had it
  // before the dialog opened (the "Import configuration" button, always)
  // once it closes, so a keyboard user resumes tabbing where they left off
  // instead of restarting from `<body>`.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    fileInputRef.current?.focus();
    return () => opener?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      // Important 2: this is the console's first true overlay modal — the
      // settings rows behind the scrim are visually covered but still in
      // the tab order unless something stops Tab at the panel's own edges.
      if (e.key !== "Tab" || !panelRef.current) return;
      const focusable = focusableIn(panelRef.current);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      const outside = !panelRef.current.contains(active);
      if (e.shiftKey ? active === first || outside : active === last || outside) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const handleFile = async (file: File) => {
    setFileName(file.name);
    setReadError(null);
    setDoc(null);
    setPreview(null);
    setSubmitError(null);
    setServerErrors(null);
    setResult(null);
    try {
      const parsedDoc = await parseImportFile(file);
      const currentValues: Record<string, unknown> = {};
      if (typeof parsedDoc.values === "object" && parsedDoc.values !== null) {
        for (const key of Object.keys(parsedDoc.values as Record<string, unknown>)) {
          currentValues[key] = ctx.effectiveValue(key);
        }
      }
      setDoc(parsedDoc);
      setPreview(buildImportPreview(parsedDoc, ctx.entriesByKey, currentValues));
    } catch {
      setReadError("This file could not be read as a settings export.");
    }
  };

  const totalKeys =
    doc && typeof doc.values === "object" && doc.values !== null
      ? Object.keys(doc.values as Record<string, unknown>).length
      : 0;
  const changedCount = preview?.lines.length ?? 0;
  const errorCount = preview ? Object.keys(preview.errors).length : 0;
  const unchangedCount = preview ? totalKeys - preview.lines.length - errorCount : 0;
  const canImport = doc !== null && preview !== null && changedCount > 0 && errorCount === 0;

  const onImport = async () => {
    if (!doc || !preview) return;
    const docValues = doc.values as Record<string, unknown>;
    const values: Record<string, unknown> = {};
    for (const line of preview.lines) values[line.key] = docValues[line.key];
    setSubmitting(true);
    setSubmitError(null);
    setServerErrors(null);
    try {
      const res = await api.importSettings({ format: doc.format, values });
      setResult(res);
      await ctx.reload();
    } catch (e) {
      if (e instanceof SettingsValidationError) setServerErrors(e.errors);
      else setSubmitError(getErrorMessage(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 px-4 pt-20">
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Import configuration"
        className="w-full max-w-lg max-h-[75vh] overflow-auto border border-border rounded bg-bg-surface shadow-lg px-4 py-3"
      >
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-text-primary">Import configuration</h3>
          <button
            type="button"
            aria-label="Close"
            className="text-text-secondary hover:text-text-primary"
            onClick={onClose}
          >
            &times;
          </button>
        </div>

        <p className="text-xs text-text-secondary mt-2">
          Choose a <code>maljan-settings.json</code> file exported from this or another instance.
          Only the keys that actually differ from the settings in effect now are sent.
        </p>

        <div className="mt-3">
          <label htmlFor="import-file" className="sr-only">
            Settings file
          </label>
          <input
            id="import-file"
            ref={fileInputRef}
            type="file"
            accept=".json"
            className="text-xs text-text-secondary"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleFile(file);
            }}
          />
        </div>

        {readError && (
          <div className="text-xs text-status-red mt-3" role="alert">
            {readError}
          </div>
        )}

        {result ? (
          <>
            <div className="text-xs text-status-green mt-3" role="status">
              {appliesSummary(result.applies, result.applied.length)}
            </div>
            <div className="flex gap-3 mt-4 pt-3 border-t border-border">
              <button
                type="button"
                className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors"
                onClick={onClose}
              >
                Close
              </button>
            </div>
          </>
        ) : (
          preview && (
            <>
              {preview.errors.format ? (
                <div className="text-xs text-status-red mt-3" role="alert">
                  This file&rsquo;s format is not supported.
                </div>
              ) : (
                <>
                  {fileName && (
                    <p className="text-[11px] text-text-muted mt-3">
                      {fileName}: {changedCount} change{changedCount === 1 ? "" : "s"}
                      {unchangedCount > 0
                        ? `, ${unchangedCount} unchanged`
                        : ""}
                      {errorCount > 0
                        ? `, ${errorCount} error${errorCount === 1 ? "" : "s"}`
                        : ""}
                    </p>
                  )}

                  {preview.lines.length > 0 && (
                    <ul className="mt-2 space-y-2">
                      {preview.lines.map((line) => (
                        <li key={line.key} className="text-sm text-text-primary">
                          <div>
                            <strong>{line.title}</strong> {line.summary}
                          </div>
                          {line.detail && line.detail.length > 0 && (
                            <ul className="ml-4 mt-1 space-y-0.5 text-xs text-text-secondary">
                              {line.detail.map((d, i) => (
                                <li key={i}>{d}</li>
                              ))}
                            </ul>
                          )}
                          <div className="text-xs text-text-muted">
                            <em>{APPLIES_SENTENCE[line.applies]}</em>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}

                  {errorCount > 0 && (
                    <ul className="mt-3 space-y-1" role="alert">
                      {Object.entries(preview.errors).map(([key, message]) => (
                        <li key={key} className="text-xs text-status-red">
                          {key}: {message}
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}

              {serverErrors && (
                <ul className="mt-3 space-y-1" role="alert">
                  {Object.entries(serverErrors).map(([key, message]) => (
                    <li key={key} className="text-xs text-status-red">
                      {key}: {message}
                    </li>
                  ))}
                </ul>
              )}
              {submitError && (
                <div className="text-xs text-status-red mt-3" role="alert">
                  {submitError}
                </div>
              )}

              <div className="flex items-center gap-4 mt-4 pt-3 border-t border-border">
                <button
                  type="button"
                  disabled={!canImport || submitting}
                  className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
                  onClick={onImport}
                >
                  {submitting
                    ? "Importing…"
                    : `Import ${changedCount} setting${changedCount === 1 ? "" : "s"}`}
                </button>
                <button
                  type="button"
                  className="text-xs text-text-secondary hover:text-text-primary"
                  onClick={onClose}
                >
                  Cancel
                </button>
              </div>
            </>
          )
        )}
      </div>
    </div>
  );
}
