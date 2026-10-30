"use client";

/* The Conversation tab.
 *
 * One route for a run that is happening and a run that happened: the store
 * behind it holds the socket while the pipeline talks and the recorded feed
 * afterwards, so leaving this page for the dashboard and coming back changes
 * nothing about what is on screen.
 *
 * The per-agent results table sits under the conversation once the run has
 * one. It answers a different question from the exchange above it — what each
 * agent concluded, rather than what it said on the way there — and its tool
 * counts come from the same feed the conversation is drawn from.
 */

import { useParams } from "next/navigation";

import AgentsPanel from "@/components/analysis/AgentsPanel";
import PipelineStrip from "@/components/analysis/PipelineStrip";
import ConversationPanel from "@/components/conversation/ConversationPanel";
import { useRun } from "@/lib/useRun";
import { useReport } from "@/components/analysis/AnalysisContext";

export default function ConversationPage() {
  const params = useParams();
  const jobId = params.id as string;
  const { report, job, loading } = useReport();
  /* Nothing is subscribed until the API has said the job exists: a direct
   * load of a job id that does not would otherwise dial a socket the server
   * closes on the handshake. */
  const run = useRun(job ? jobId : null);

  const live = job?.status === "running" || job?.status === "pending";

  if (loading) {
    return <p className="px-1 text-sm text-text-muted">Loading the conversation…</p>;
  }

  return (
    <div className="space-y-4">
      {/* While the run talks, the reader watching it keeps the stages in
          view; once it has finished they are in run quality. */}
      {live && <PipelineStrip stages={run.stages} roster={run.roster} />}
      <ConversationPanel
        jobId={jobId}
        events={run.events}
        lastSeq={run.lastSeq}
        roster={run.roster}
        connection={run.connection}
        feedError={run.feedError}
        live={Boolean(live)}
        jobStatus={job?.status ?? null}
      />
      {report && <AgentsPanel roster={run.roster} />}
    </div>
  );
}
