"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { ENRICH_BUTTON_LABEL, enrichMessage } from "@/lib/enrichment";
import { buttonClass } from "@/components/ui/Button";

/**
 * The one button that asks the threat-intel services about this report.
 *
 * One copy of one action against one endpoint. It sits on the Network tab,
 * whose endpoints' reputation is most of what it changes; the analysis header
 * holds only the page's own actions (Export and Ask).
 */
export default function EnrichButton({ reportId }: { reportId: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const run = async () => {
    if (!reportId || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      // The endpoint distinguishes queued / already_queued /
      // skipped_no_network_iocs — say which one happened rather than always
      // promising a refresh.
      const res = await api.enrichReport(reportId);
      setMessage(enrichMessage(res.status));
    } catch (err) {
      setMessage(`Could not queue enrichment: ${getErrorMessage(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={run}
        disabled={!reportId || busy}
        type="button"
        className={buttonClass("secondary", "sm")}
      >
        {busy ? "Queueing…" : ENRICH_BUTTON_LABEL}
      </button>
      {message && (
        <p className="w-full text-xs text-text-secondary bg-bg-active border border-border rounded px-2 py-1.5">
          {message}
        </p>
      )}
    </div>
  );
}
