"use client";

import Button from "@/components/ui/Button";

/**
 * What a tab shows when drawing it failed.
 *
 * The boundary wraps the tab under the analysis frame, so the header, the
 * tabs and the chat stay where they are and only the tab that failed says
 * so, with the way to try again and the error's own words. One panel can
 * never take the whole analysis page down with it.
 */
export default function AnalysisTabError({ error, retry }: { error: unknown; retry: () => void }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="max-w-[72ch] space-y-3 rounded-md border border-status-red/30 bg-status-red/10 p-4">
      <h2 className="text-base font-semibold text-text-primary">This tab could not be drawn</h2>
      <p className="text-sm text-text-secondary">
        Something in the stored analysis broke this view. The other tabs and the chat still work.
      </p>
      {message && <p className="break-words font-mono text-xs text-text-muted">{message}</p>}
      <Button size="sm" onClick={() => retry()}>
        Try again
      </Button>
    </div>
  );
}
