"use client";

/* How much work each agent did, answered once.
 *
 * The run's own feed is the source: a `tool_call_finished` per answered call,
 * which the store already holds for this job. A run recorded before the feed
 * carried tool calls has none of those events and its ledger is the only
 * record, so the ledger answers for that case and only for it — one number,
 * one place, with the fallback here rather than in each reader.
 *
 * "The feed carries no tool calls" is only an answer once the run has stopped
 * talking. A live run starts with an empty feed, and reading that as "this run
 * predates tool-call events" sent a ledger request at the top of every run, for
 * a ledger that was still being written.
 */

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { toolCallsFromFeed } from "@/lib/conversation";
import type { RunEvent } from "@/lib/runStore";
import { toolCallsByAgent } from "@/components/analysis/stageTimeline";

/** How much of the ledger a fallback count reads. Beyond this the count is a
 *  floor, because a number that silently stops counting is worse than one
 *  that says where it stopped. */
const LEDGER_SAMPLE = 200;

export interface ToolCounts {
  counts: Record<string, number>;
  /** True when the count is a floor rather than the whole ledger. */
  partial: boolean;
}

/** A job that has stopped: only then is a silent feed a finished feed. */
const TERMINAL = new Set(["completed", "failed", "cancelled"]);

export function useToolCounts(
  jobId: string,
  events: readonly RunEvent[],
  jobStatus: string | null | undefined,
): ToolCounts {
  const fromFeed = toolCallsFromFeed(events);
  const feedHasCalls = Object.keys(fromFeed).length > 0;
  const finished = TERMINAL.has(String(jobStatus ?? ""));
  const [fromLedger, setFromLedger] = useState<Record<string, number>>({});
  const [ledgerTotal, setLedgerTotal] = useState(0);

  useEffect(() => {
    if (!jobId || feedHasCalls || !finished) return;
    let cancelled = false;
    api
      .getJobEvidence(jobId, { pageSize: LEDGER_SAMPLE })
      .then((response) => {
        if (cancelled) return;
        setFromLedger(toolCallsByAgent(response.entries));
        setLedgerTotal(response.total);
      })
      .catch(() => {
        // A ledger the browser could not read leaves the count at zero rather
        // than the view broken.
        if (!cancelled) setFromLedger({});
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, feedHasCalls, finished]);

  return {
    counts: feedHasCalls ? fromFeed : fromLedger,
    partial: !feedHasCalls && ledgerTotal > LEDGER_SAMPLE,
  };
}
