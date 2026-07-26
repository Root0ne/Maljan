"use client";

/* The agent conversation, on the PROCESS tab.
 *
 * Draws from both sources at once, because neither covers a job's whole life:
 * a *running* job has pipeline events and no persisted report, an old job has
 * the report and no events (the stream expires after 24 h), and in between it
 * has both. Reading only the report — the first cut of this view — meant the
 * panel announced "This run recorded no agent findings" for the entire
 * duration of every analysis, while the findings were already streaming in.
 *
 * Live events arrive through the layout's existing WebSocket, plus a one-shot
 * back-fill for the case where this tab is opened mid-run and the socket only
 * carries what happened after it connected. */

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import TranscriptPanel from "@/components/TranscriptPanel";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import {
  mergeTranscripts,
  messagesFromEvents,
  messagesFromReport,
} from "@/lib/transcript";
import type { WSEvent } from "@/types";
import { useReport } from "../layout";

export default function TranscriptView() {
  const params = useParams();
  const jobId = params.id as string;
  const { report, job, loading, events } = useReport();

  const [backfill, setBackfill] = useState<WSEvent[]>([]);
  const [backfillError, setBackfillError] = useState<string | null>(null);

  const running = job?.status === "running" || job?.status === "pending";

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.getJobEvents(jobId);
        if (!cancelled) setBackfill(res.events as unknown as WSEvent[]);
      } catch (err) {
        // The stream legitimately expires after 24 h. Only say so while the
        // run is live, where a missing back-fill actually costs the reader
        // something; on a finished job the persisted transcript is complete.
        if (!cancelled) setBackfillError(getErrorMessage(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  const messages = useMemo(
    () =>
      mergeTranscripts(
        messagesFromReport(
          report?.agent_findings,
          report?.negotiation_log,
          report?.verdict
        ),
        messagesFromEvents([...backfill, ...events])
      ),
    [report, backfill, events]
  );

  if (loading) {
    return <p className="text-sm text-text-muted px-1">Loading transcript…</p>;
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted leading-relaxed">
        What each agent reported, the mediator&apos;s rulings between rounds, and
        the final verdict — in the order they happened. Claims carry the concrete
        artefact each one is grounded in; expand a message to read them.
      </p>
      {running && backfillError && (
        <p
          role="alert"
          className="text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded px-2 py-1.5"
        >
          Could not replay earlier messages ({backfillError}). Only messages
          received from now on are shown.
        </p>
      )}
      <TranscriptPanel
        messages={messages}
        live={running}
        emptyHint={
          running
            ? "Waiting for the first agent to report…"
            : "This run recorded no agent findings or negotiation history."
        }
      />
    </div>
  );
}
