"use client";

/* How a run that failed ends.
 *
 * The conversation simply stopped, mid-stage, on a run the worker had already
 * marked failed — the reader was left to notice the absence. It closes on this
 * instead: what the run published about the failure, and the id the log entries
 * holding the rest of it are filed under, drawn the same way the run header
 * draws them.
 */

import { CircleAlert } from "lucide-react";

import FailureNote from "@/components/ui/FailureNote";
import type { ConversationItem } from "@/lib/conversation";
import { runFailure } from "@/lib/runFailure";

export default function FailureRow({ item }: { item: ConversationItem }) {
  return (
    <div className="flex justify-center">
      <div className="flex max-w-[46rem] items-start gap-2 rounded border border-status-red/30 bg-status-red/10 px-2.5 py-1.5">
        <CircleAlert size={12} aria-hidden="true" className="mt-0.5 text-status-red" />
        {/* The event states its id on its own key, so the sentence is left
            exactly as the worker wrote it. */}
        <FailureNote failure={runFailure(item.text, item.errorId ?? null)} />
      </div>
    </div>
  );
}
