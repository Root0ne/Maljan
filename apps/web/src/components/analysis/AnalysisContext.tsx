"use client";

import { createContext, useContext } from "react";
import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import type { EvidenceSubject } from "./EvidenceDetail";

/**
 * What every tab of one analysis reads: the job, its report, whether they
 * are still being read, and the evidence drawer.
 *
 * The run's events are deliberately absent here. They live in the run store,
 * keyed by job id, where they survive a route change and a second reader — a
 * tab that needs them subscribes with `useRun` rather than being handed a
 * copy that dies with the frame.
 */
export interface AnalysisCtx {
  jobId: string;
  report: ReportDetailDTO | null;
  job: JobDTO | null;
  loading: boolean;
  /** Why the report could not be read; a tab says so instead of drawing empty. */
  reportError: string | null;
  /** Open the evidence drawer on `subject`; `opener` is the control clicked,
   *  which gets focus back when the drawer closes. Null outside an analysis
   *  page, where a citation falls back to a plain link. */
  showEvidence: ((subject: EvidenceSubject, opener?: HTMLElement | null) => void) | null;
  /** Open the chat drawer; null where there is none, or the job cannot be asked yet. */
  openChat?: (() => void) | null;
}

export const AnalysisContext = createContext<AnalysisCtx>({
  jobId: "",
  report: null,
  job: null,
  loading: true,
  reportError: null,
  showEvidence: null,
});

export function useReport(): AnalysisCtx {
  return useContext(AnalysisContext);
}
