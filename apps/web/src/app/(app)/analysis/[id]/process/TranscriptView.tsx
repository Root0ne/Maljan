"use client";

/* Post-run transcript: the same conversation the LIVE tab showed, rebuilt from
 * what was persisted once the WebSocket is long gone.
 *
 * The messages come from lib/transcript, which is also what the live page
 * feeds its panel, so the two views cannot disagree about the run. Reruns of
 * jobs that predate the live feed still render — their findings and
 * negotiation log are enough to reconstruct the exchange. */

import { useMemo } from "react";
import TranscriptPanel from "@/components/TranscriptPanel";
import { messagesFromReport } from "@/lib/transcript";
import { useReport } from "../layout";

export default function TranscriptView() {
  const { report, loading } = useReport();

  const messages = useMemo(
    () =>
      messagesFromReport(
        report?.agent_findings,
        report?.negotiation_log,
        report?.verdict
      ),
    [report]
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
      <TranscriptPanel
        messages={messages}
        emptyHint="This run recorded no agent findings or negotiation history."
      />
    </div>
  );
}
