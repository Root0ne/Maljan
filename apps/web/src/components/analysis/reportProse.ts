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
  HostIdentifier,
  KeyFinding,
  MalwareReport,
} from "@/types/malware-report";

/** The voice every block in this module speaks with. */
export const REPORT_MODEL_VOICE = "Written by the report model";

/** The platform's own voice: what a tool returned, or what the run recorded. */
export const MEASURED_VOICE = "Measured";

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

export function hostIdentifiers(mr: MalwareReport | null | undefined): HostIdentifier[] {
  return mr?.technical_analysis?.host_identifiers ?? [];
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

/** The run's unresolved findings of one code, as the validator recorded them. */
function unresolvedOf(mr: MalwareReport | null | undefined, code: string): string[] {
  return (mr?.run_summary?.validation?.unresolved ?? [])
    .filter((row) => row?.code === code)
    .map((row) => String(row.message ?? ""));
}

/** The orders of the steps a kept `report.flow_voice` finding names. */
export function flowFindings(mr: MalwareReport | null | undefined): Set<string> {
  const out = new Set<string>();
  for (const message of unresolvedOf(mr, "report.flow_voice")) {
    const match = /step (\S+) is marked/.exec(message);
    if (match) out.add(match[1]);
  }
  return out;
}

/** The 1-based items a kept `report.configuration_uncited` finding names. */
export function configFindings(mr: MalwareReport | null | undefined): Set<number> {
  const out = new Set<number>();
  for (const message of unresolvedOf(mr, "report.configuration_uncited")) {
    const match = /configuration item (\d+)/.exec(message);
    if (match) out.add(Number(match[1]));
  }
  return out;
}

/** The 1-based identifiers a kept `report.identifier_uncited` finding names. */
export function identifierFindings(mr: MalwareReport | null | undefined): Set<number> {
  const out = new Set<number>();
  for (const message of unresolvedOf(mr, "report.identifier_uncited")) {
    const match = /identifier (\d+)/.exec(message);
    if (match) out.add(Number(match[1]));
  }
  return out;
}

/** Whether a sandbox recorded anything in this run, as the exported report decides it. */
export function sandboxObserved(mr: MalwareReport | null | undefined): boolean {
  if (mr?.dynamic) return true;
  const net = mr?.network;
  if (!net) return false;
  return [...(net.domains ?? []), ...(net.ips ?? []), ...(net.urls ?? [])].some(
    (row) => row?.source === "sandbox",
  );
}

/** The platform's note beside a step, or `""`: the same words the exported report prints. */
export function flowNote(mr: MalwareReport | null | undefined, step: FlowStep): string {
  if (flowFindings(mr).has(String(step.order))) return "unresolved: report.flow_voice";
  if (step.voice === "observed" && !sandboxObserved(mr)) {
    return "unresolved: report.flow_voice; no sandbox observation in this run";
  }
  return "";
}

const SCHEMES: Record<string, string> = { http: "hxxp", https: "hxxps", ftp: "fxp" };

/**
 * One endpoint a model wrote, written so nobody can click it: the forms the
 * exported report uses (`hxxp://`, `[.]`, `[:]`). A model's endpoint is never
 * printed live on a reading surface.
 */
export function defangEndpoint(value: string): string {
  const text = String(value ?? "").trim();
  const dots = (s: string) => s.replace(/\[\.\]/g, ".").replace(/\./g, "[.]");
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(text);
  if (scheme) {
    const written = SCHEMES[scheme[1].toLowerCase()] ?? scheme[1];
    const rest = text.slice(scheme[0].length);
    const cut = rest.search(/[/?#]/);
    const authority = cut === -1 ? rest : rest.slice(0, cut);
    const tail = cut === -1 ? "" : rest.slice(cut);
    return `${written}://${dots(authority)}${tail}`;
  }
  if (text.includes(":") && !text.includes("[:]") && /^[0-9a-fA-F:]+$/.test(text)) {
    return text.replace(":", "[:]");
  }
  const slash = text.indexOf("/");
  return slash === -1 ? dots(text) : dots(text.slice(0, slash)) + text.slice(slash);
}

/** Whether the technical-analysis panel has anything of this run to draw. */
export function hasTechnicalAnalysis(mr: MalwareReport | null | undefined): boolean {
  return (
    executionFlow(mr).length > 0 ||
    configuration(mr).length > 0 ||
    hostIdentifiers(mr).length > 0 ||
    commands(mr).length > 0 ||
    c2Channels(mr).length > 0
  );
}
