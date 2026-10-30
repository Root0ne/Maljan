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
  ClaimNotDiscussed,
  CommandRow,
  ConfigItem,
  FlaggedStatement,
  FlowStep,
  HostIdentifier,
  KeyFinding,
  MalwareReport,
  QuestionAnswer,
  QuestionOutcome,
  TechnicalSubsection,
} from "@/types/malware-report";

/** The voice every block in this module speaks with. */
export const REPORT_MODEL_VOICE = "AI-written";

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
  return colon === -1 ? "none was written" : reason.slice(colon + 1).trim();
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
    c2Channels(mr).length > 0 ||
    technicalSubsections(mr).length > 0
  );
}

/** One further block of the technical analysis, in the shape the panel draws. */
export interface TechnicalBlock {
  key: string;
  title: string;
  /** Prose, as the model wrote it. */
  body: string;
  /** Verbatim items: commands, flags, list entries. */
  items: string[];
  /** Labelled facts, in declaration order, each with a value. */
  facts: Array<[string, string]>;
  evidence: string[];
}

const PROSE_SUBSECTIONS: Array<[keyof NonNullable<MalwareReport["technical_analysis"]>, string]> = [
  ["command_and_control", "Command and control"],
  ["payloads", "Payloads"],
  ["packing_obfuscation", "Packing and obfuscation"],
  ["string_resolution", "String resolution"],
  ["discovery", "Discovery"],
  ["persistence_detail", "Persistence detail"],
  ["message_packet_structure", "Message and packet structure"],
  ["evasion_antiforensics", "Evasion and anti-forensics"],
];

function said(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.map(said).filter(Boolean) : [];
}

/**
 * The technical-analysis subsections beyond the flow, configuration, host
 * identifiers and commands: the free-prose ones, the command-line flags, the
 * service and process kill list, the shadow-copy commands, the encryption
 * scheme and the ransom note.
 *
 * The report carried all thirteen and the console typed none of them, so a
 * run whose model wrote an encryption scheme or a ransom note showed neither.
 * A subsection is a block only when it says something: an empty body, an
 * empty list, a scheme whose every field is unset is absent, as the exported
 * report leaves it absent.
 */
export function technicalSubsections(mr: MalwareReport | null | undefined): TechnicalBlock[] {
  const ta = mr?.technical_analysis;
  if (!ta) return [];
  const blocks: TechnicalBlock[] = [];
  const push = (block: TechnicalBlock) => {
    if (block.body || block.items.length > 0 || block.facts.length > 0) blocks.push(block);
  };
  for (const [key, fallback] of PROSE_SUBSECTIONS) {
    const sub = ta[key] as TechnicalSubsection | null | undefined;
    if (!sub || typeof sub !== "object") continue;
    push({
      key: String(key),
      title: said(sub.title) || fallback,
      body: said(sub.body),
      items: [],
      facts: [],
      evidence: list(sub.evidence_refs),
    });
  }
  const flags = (ta.cli_flags ?? []).filter((f) => said(f?.flag));
  push({
    key: "cli_flags",
    title: "Command-line flags",
    body: "",
    items: flags.map((f) => (said(f.description) ? `${f.flag} — ${f.description}` : f.flag)),
    facts: [],
    evidence: flags.map((f) => said(f.evidence_ref)).filter(Boolean),
  });
  const kill = ta.service_process_kill;
  if (kill) {
    const facts: Array<[string, string]> = [];
    if (said(kill.mechanism)) facts.push(["Mechanism", said(kill.mechanism)]);
    if (list(kill.kill_list).length > 0) facts.push(["Stops", list(kill.kill_list).join(", ")]);
    if (list(kill.white_list).length > 0) facts.push(["Spares", list(kill.white_list).join(", ")]);
    push({ key: "service_process_kill", title: "Services and processes stopped", body: "", items: [], facts, evidence: [] });
  }
  push({
    key: "shadow_copy_destruction",
    title: "Shadow-copy destruction",
    body: "",
    items: list(ta.shadow_copy_destruction),
    facts: [],
    evidence: [],
  });
  const enc = ta.encryption_scheme;
  if (enc) {
    const facts: Array<[string, string]> = [];
    const field = (label: string, value: unknown) => {
      if (said(value)) facts.push([label, said(value)]);
    };
    field("Cipher", enc.cipher);
    field("Mode", enc.mode);
    field("Library", enc.library);
    field("Key source", enc.key_source);
    field("Key management", enc.key_management);
    field("IV", enc.iv);
    field("File marker", enc.file_marker);
    field("Extension", enc.extension);
    field("Partial encryption", enc.partial_threshold);
    // A per-file key the model did not establish is left out, not said as "no".
    if (enc.per_file_key === true) facts.push(["Per-file key", "yes"]);
    if (enc.per_file_key === false) facts.push(["Per-file key", "no"]);
    push({
      key: "encryption_scheme",
      title: "Encryption scheme",
      body: "",
      items: [],
      facts,
      evidence: said(enc.evidence_ref) ? [said(enc.evidence_ref)] : [],
    });
  }
  const note = ta.ransom_note;
  if (note) {
    const facts: Array<[string, string]> = [];
    if (said(note.filename)) facts.push(["File name", said(note.filename)]);
    if (said(note.company_id_hash)) facts.push(["Company id hash", said(note.company_id_hash)]);
    push({
      key: "ransom_note",
      title: "Ransom note",
      body: said(note.verbatim_content),
      items: list(note.sections),
      facts,
      evidence: [],
    });
  }
  return blocks;
}

/** The sentences a check flagged and the retry left standing. */
export function flaggedStatements(mr: MalwareReport | null | undefined): FlaggedStatement[] {
  return (mr?.flagged_statements ?? []).filter((f) => said(f?.sentence));
}

/** What a flagged sentence's mark says, as the exported report says it. */
export function flaggedMark(statement: FlaggedStatement): string {
  const found = said(statement.label) || statement.code;
  return statement.asked === false
    ? `${found} — the model was not asked about it`
    : `${found} — asked about and left standing`;
}

/** Each outcome as the exported report prints it. */
export const OUTCOME_WORDS: Record<QuestionOutcome, string> = {
  established: "established",
  partial: "partial",
  limited_negative: "limited negative",
  not_determinable: "not determinable from this run",
  out_of_scope: "out of scope",
};

/** The questions the job was asked, with the report's answers. */
export function questionAnswers(mr: MalwareReport | null | undefined): QuestionAnswer[] {
  return (mr?.question_answers ?? []).filter((a) => said(a?.question));
}

/** An answer's outcome as the exported report prints it, with a refused word said. */
export function outcomeLine(answer: QuestionAnswer): string {
  const words = OUTCOME_WORDS[answer.outcome] ?? answer.outcome;
  if (!answer.answered) return words;
  const asked = OUTCOME_WORDS[answer.answered] ?? answer.answered;
  return `${words} (the AI answer said ${asked}; an automatic check did not accept it)`;
}

/** The analyst claims in force the body neither cites nor discusses. */
export function claimsNotDiscussed(mr: MalwareReport | null | undefined): ClaimNotDiscussed[] {
  return (mr?.claims_not_discussed ?? []).filter((c) => said(c?.claim));
}

/** The note on a technique id the ATT&CK catalog does not have, as the report prints it
 *  (`isr_models.UNVERIFIED_TECHNIQUE_MARKER`). */
export const UNVERIFIED_TECHNIQUE_MARKER = "technique id not in the ATT&CK catalog";

/** The note on a technique an absence claim kept when asked, as the report prints it
 *  (`isr_models.ABSENCE_TECHNIQUE_MARKER`). */
export const ABSENCE_TECHNIQUE_MARKER =
  "the claim naming it reads as absence; the analyst kept the technique when asked";

/**
 * A claim's technique ids as the exported report's section 13.1 prints them,
 * each with its note, or `""` for a claim that names none. A claim mapped to
 * several techniques is one claim: its ids together.
 */
export function claimTechniques(claim: ClaimNotDiscussed): string {
  const ids = (claim.technique_ids ?? []).filter(said);
  if (ids.length === 0) return "";
  const unverified = new Set(claim.unverified_technique_ids ?? []);
  const kept = new Set(claim.absence_kept_technique_ids ?? []);
  const written = ids.map((id) => {
    const notes = [
      ...(unverified.has(id) ? [UNVERIFIED_TECHNIQUE_MARKER] : []),
      ...(kept.has(id) ? [ABSENCE_TECHNIQUE_MARKER] : []),
    ];
    return notes.length > 0 ? `${id} (${notes.join("; ")})` : id;
  });
  return `technique${ids.length > 1 ? "s" : ""} ${written.join(", ")}`;
}
