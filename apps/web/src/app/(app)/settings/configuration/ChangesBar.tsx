"use client";

import { useEffect, useState } from "react";
import { buildReviewItems, ReviewList } from "./ReviewList";
import { useSettingsContext } from "./SettingsContext";
import { appliesSummary } from "./vocabulary";

const STATUS_DURATION_MS = 6000;

/** Sticky bottom bar for staged settings, plus the review panel it opens.
 *  Discarding more than three changes at once confirms first — a single
 *  misclick shouldn't drop a session's worth of edits. */
export default function ChangesBar() {
  const ctx = useSettingsContext();
  const { pending, hiddenKeys, saving, lastResult } = ctx;
  const [reviewing, setReviewing] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [statusVisible, setStatusVisible] = useState(false);

  const keys = Object.keys(pending);
  const count = keys.length;
  const hiddenCount = keys.filter((k) => hiddenKeys.includes(k)).length;

  useEffect(() => {
    if (!lastResult) return;
    setStatusVisible(true);
    const t = setTimeout(() => setStatusVisible(false), STATUS_DURATION_MS);
    return () => clearTimeout(t);
  }, [lastResult]);

  // Apply clears `pending`, so the bar itself disappears the moment it
  // succeeds — but the status line it leaves behind still needs a place to
  // render for its 6s window. Only bail out once there is neither a bar nor
  // a status to show.
  if (count === 0 && !(statusVisible && lastResult)) return null;

  const lines = buildReviewItems(ctx);
  // Rows of the list below, not raw error entries: one composite leaf can
  // carry several field-level errors and still be a single row to fix.
  const errorCount = lines.filter((line) => line.error).length;

  const discardAll = () => {
    keys.forEach((k) => ctx.unstage(k));
    setDiscarding(false);
    setReviewing(false);
  };

  const onDiscardAllClick = () => {
    if (count > 3) setDiscarding(true);
    else discardAll();
  };

  const onApply = async () => {
    const result = await ctx.apply();
    if (result) setReviewing(false);
  };

  if (count === 0) {
    return (
      <div className="sticky bottom-0 mt-6 px-4 py-2">
        <div className="text-xs text-status-green" role="status">
          {appliesSummary(lastResult!.applies, lastResult!.applied.length)}
        </div>
      </div>
    );
  }

  return (
    <>
      {reviewing && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Review changes"
          className="fixed inset-x-0 bottom-16 z-40 mx-auto max-w-3xl px-4"
        >
          <div className="border border-border rounded bg-bg-surface shadow-lg px-4 py-3 max-h-[60vh] overflow-auto">
            {errorCount > 0 && (
              <p className="text-xs text-status-red mb-2" role="alert">
                {errorCount} field{errorCount === 1 ? " needs" : "s need"} attention
              </p>
            )}
            <ReviewList lines={lines} />
            <div className="flex items-center gap-4 mt-4 pt-3 border-t border-border">
              <button
                type="button"
                disabled={saving}
                className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
                onClick={onApply}
              >
                {saving ? "Saving…" : "Confirm and apply"}
              </button>
              <button
                type="button"
                className="text-xs text-text-secondary hover:text-text-primary"
                onClick={() => setReviewing(false)}
              >
                Back
              </button>
            </div>
          </div>
        </div>
      )}

      <div
        role="region"
        aria-label="Unsaved changes"
        className="sticky bottom-0 mt-6 border-t border-border bg-bg-surface/95 backdrop-blur px-4 py-3 rounded-t z-30"
      >
        {discarding && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Discard changes"
            className="mb-3 border border-border rounded bg-bg-deep px-3 py-2"
          >
            <p className="text-xs text-text-secondary">Discard {count} changes?</p>
            <div className="flex gap-3 mt-2">
              <button type="button" className="text-xs text-status-red" onClick={discardAll}>
                Discard
              </button>
              <button
                type="button"
                className="text-xs text-text-secondary"
                onClick={() => setDiscarding(false)}
              >
                Keep
              </button>
            </div>
          </div>
        )}

        {statusVisible && lastResult && (
          <div className="text-xs text-status-green mb-2" role="status">
            {appliesSummary(lastResult.applies, lastResult.applied.length)}
          </div>
        )}

        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-sm text-text-primary">
            <span data-testid="changes-count">
              {count} change{count === 1 ? "" : "s"}
            </span>
            {hiddenCount > 0 && (
              <span className="text-text-muted">
                {" "}
                · {hiddenCount} hidden by the current provider selection
              </span>
            )}
          </span>
          <button
            type="button"
            className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors"
            onClick={() => setReviewing(true)}
          >
            Review
          </button>
          <button
            type="button"
            className="text-xs text-text-secondary hover:text-text-primary"
            onClick={onDiscardAllClick}
          >
            Discard all
          </button>
        </div>
      </div>
    </>
  );
}
