/**
 * What the report model wrote, read the way the exported report reads it.
 *
 * The console and the Markdown draw one report object. The model's words are
 * printed as written; what this module decides is only which blocks exist and
 * how each is labelled, so a reader always knows the words are the report
 * model's and not a tool's.
 */

import type {
  C2Channel,
  CommandRow,
  ConfigItem,
  FlowStep,
  KeyFinding,
  MalwareReport,
} from "@/types/malware-report";

/** The voice every block in this module speaks with. */
export const REPORT_MODEL_VOICE = "Written by the report model";

/** How the reason for an absent summary begins, as the report builder writes it. */
export const NO_SUMMARY_PREFIX = "the report model wrote no summary";

export function keyFindings(mr: MalwareReport | null | undefined): KeyFinding[] {
  return (mr?.key_findings ?? []).filter((f) => typeof f?.text === "string" && f.text.trim());
}

/** Why no summary was written, when the report says so, or `""`. */
export function noSummaryReason(mr: MalwareReport | null | undefined): string {
  const reason = (mr?.degradation_reasons ?? []).find((r) => r.startsWith(NO_SUMMARY_PREFIX));
  if (!reason) return "";
  const colon = reason.indexOf(":");
  return colon === -1 ? "the report model wrote none" : reason.slice(colon + 1).trim();
}

export function executionFlow(mr: MalwareReport | null | undefined): FlowStep[] {
  return [...(mr?.technical_analysis?.execution_flow ?? [])].sort((a, b) => a.order - b.order);
}

/** The mark a step carries, in the words the exported report prints. */
export function flowMark(step: FlowStep): string {
  return step.voice === "observed" ? "observed in sandbox" : "assessed";
}

export function configuration(mr: MalwareReport | null | undefined): ConfigItem[] {
  return mr?.technical_analysis?.configuration ?? [];
}

export function commands(mr: MalwareReport | null | undefined): CommandRow[] {
  return mr?.technical_analysis?.commands ?? [];
}

export function c2Channels(mr: MalwareReport | null | undefined): C2Channel[] {
  return mr?.c2_channels ?? [];
}

/** Every entry a channel cites, the single ref of a stored channel included. */
export function channelEvidence(channel: C2Channel): string[] {
  const ids = [...(channel.evidence_refs ?? [])];
  if (channel.evidence_ref && !ids.includes(channel.evidence_ref)) ids.push(channel.evidence_ref);
  return ids;
}

/** Whether the technical-analysis panel has anything of this run to draw. */
export function hasTechnicalAnalysis(mr: MalwareReport | null | undefined): boolean {
  return (
    executionFlow(mr).length > 0 ||
    configuration(mr).length > 0 ||
    commands(mr).length > 0 ||
    c2Channels(mr).length > 0
  );
}
