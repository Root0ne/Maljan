/**
 * What the new analysis page reads off a stored report, in one place.
 *
 * Every function here is pure: the page draws what these return, and the
 * tests pin what they return. Nothing is invented: a number the report does
 * not hold is `null` and drawn as "Not measured", a severity the report does
 * not state is unrated. The words are the reader's, not the pipeline's: no
 * stage, agent or record-store names reach the page from here.
 */

import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import { decisionOf } from "@/components/analysis/indicators";
import { runSignatureScale, signatureScore } from "@/lib/severity";
import { jobStopNote } from "@/lib/runFailure";
import { verdictBucket, verdictLabel } from "@/lib/verdict";
import { assessedSeverity, verdictHeadline, verdictReadingNote } from "@/lib/verdictHeader";
import {
  fileTypeLabel,
  type ConfigItem,
  type DefensiveRecommendation,
  type MalwareReport,
  type SampleIdentity,
  type SeverityRating,
} from "@/types/malware-report";
import { safeHref } from "./safeMarkdown";

/* ── Tabs ──────────────────────────────────────────────────────────── */

export type AnalysisTabKey = "overview" | "behaviour" | "network" | "static" | "indicators" | "evidence";

export interface AnalysisTab {
  key: AnalysisTabKey;
  label: string;
  /** The path segment under the analysis; empty for Overview. */
  segment: string;
}

/**
 * The six tabs of an analysis, in their one fixed order. Every one is drawn
 * on every finished analysis: a tab with nothing in it says so inside, so a
 * reader learns the layout once and an absence reads as an answer.
 */
export const ANALYSIS_TABS: readonly AnalysisTab[] = [
  { key: "overview", label: "Overview", segment: "" },
  { key: "behaviour", label: "Behaviour", segment: "behaviour" },
  { key: "network", label: "Network", segment: "network" },
  { key: "static", label: "Static & code", segment: "static" },
  { key: "indicators", label: "Indicators & detection", segment: "indicators" },
  { key: "evidence", label: "Evidence", segment: "evidence" },
];

/** The tabs offered while the job still runs: the live discussion lives under Evidence. */
export const RUNNING_TABS: ReadonlySet<AnalysisTabKey> = new Set<AnalysisTabKey>(["overview", "evidence"]);

export function analysisBase(jobId: string): string {
  return `/analysis/${encodeURIComponent(jobId)}`;
}

export function analysisHref(jobId: string, key: AnalysisTabKey, anchor?: string): string {
  const tab = ANALYSIS_TABS.find((t) => t.key === key) ?? ANALYSIS_TABS[0];
  const path = tab.segment ? `${analysisBase(jobId)}/${tab.segment}` : analysisBase(jobId);
  return anchor ? `${path}#${anchor}` : path;
}

/**
 * Where a record link written before the bundle led the Evidence tab
 * (`/evidence?evidence=ev_0007`) is passed on to: the same query and
 * fragment under Records, so nothing the link carried is dropped.
 */
export function recordsForwardHref(jobId: string, query: string, hash: string): string {
  const search = query.replace(/^\?/, "");
  return `${analysisHref(jobId, "evidence")}/records${search ? `?${search}` : ""}${hash}`;
}

/** Where one tool call's record opens, with its arguments and its output. */
export function evidenceRecordHref(jobId: string, entryId: string): string {
  return `${analysisHref(jobId, "evidence")}/records?evidence=${encodeURIComponent(entryId)}`;
}

/**
 * The block a URL's fragment names (`#persistence`), or null when it names
 * none. A fragment that does not decode (`#%E0%A4%A`) names none: it is
 * skipped rather than thrown on.
 */
export function anchorFromHash(hash: string | null | undefined): string | null {
  const raw = (hash ?? "").replace(/^#/, "");
  if (!raw) return null;
  try {
    return decodeURIComponent(raw) || null;
  } catch {
    return null;
  }
}

/** How many items each tab holds; null where the report does not say. */
export function tabCounts(mr: MalwareReport | null | undefined): Record<AnalysisTabKey, number | null> {
  if (!mr) {
    return { overview: null, behaviour: null, network: null, static: null, indicators: null, evidence: null };
  }
  const net = mr.network;
  return {
    overview: null,
    behaviour: (mr.dynamic?.sandbox_signatures?.length ?? 0) + techniqueIds(mr).length,
    network: net ? net.domains.length + net.ips.length + net.urls.length : null,
    static: mr.static ? mr.static.interesting_strings.length + mr.static.imports.length : null,
    indicators: (mr.consolidated_iocs?.length ?? 0) + (mr.detection_signatures?.length ?? 0),
    evidence: mr.run_summary?.evidence?.entries ?? null,
  };
}

/* ── Header ────────────────────────────────────────────────────────── */

export interface VerdictConfidence {
  /** 0–100, or null when no confidence was assessed. */
  percent: number | null;
  /** The verdict in the reader's word. */
  verdict: string;
  /** What the meter says to a screen reader: "Malicious, confidence 91 percent". */
  label: string;
  /** The rung on the five-step meter, 1 to 5; 0 when none was assessed. */
  step: number;
  /** The fixed word the rung reads as ("High confidence"), or "Confidence not assessed". */
  word: string;
}

/** What the meter's word and number are about: its description. */
export const CONFIDENCE_WHY = "How sure the analysis is of this verdict";

/*
 * The five rungs a confidence number reads as, highest first: the floors and
 * words the exported report prints beside the same number
 * (`CONFIDENCE_WORDS` in `src/maljan/reporting/renderers/markdown.py`), so the
 * page and the report never word one number two ways.
 */
const CONFIDENCE_RUNGS: readonly (readonly [number, string])[] = [
  [0.9, "High confidence"],
  [0.7, "Moderate-to-high confidence"],
  [0.5, "Moderate confidence"],
  [0.3, "Low confidence"],
  [0, "Very low confidence"],
];

/** The rung (5 at the top, 1 at the bottom, 0 for none) and word a confidence reads as. */
export function confidenceRung(confidence: number | null | undefined): { step: number; word: string } {
  if (confidence == null || Number.isNaN(confidence)) return { step: 0, word: "Confidence not assessed" };
  const rounded = Math.round(Math.min(1, Math.max(0, confidence)) * 100) / 100;
  const at = CONFIDENCE_RUNGS.findIndex(([floor]) => rounded >= floor);
  const index = at === -1 ? CONFIDENCE_RUNGS.length - 1 : at;
  return { step: CONFIDENCE_RUNGS.length - index, word: CONFIDENCE_RUNGS[index][1] };
}

/*
 * The meter shows the confidence the analysis put on its verdict, as stored,
 * read on the report's own five rungs, and nothing derived from it. The
 * report has no score field, so the page draws no score until the backend
 * emits one.
 */
export function verdictConfidence(
  verdict: string | null | undefined,
  confidence: number | null | undefined,
): VerdictConfidence {
  const word = verdictBucket(verdict) === "unknown" ? "No verdict" : verdictLabel(verdict);
  const rung = confidenceRung(confidence);
  if (confidence == null || Number.isNaN(confidence)) {
    return { percent: null, verdict: word, label: `${word}, confidence not assessed`, ...rung };
  }
  const percent = Math.round(Math.min(1, Math.max(0, confidence)) * 100);
  return { percent, verdict: word, label: `${word}, confidence ${percent} percent`, ...rung };
}

/** The labels that classify the sample, most telling first, without repeats. */
export function classificationChips(mr: MalwareReport | null | undefined, category?: string | null): string[] {
  const out: string[] = [];
  const add = (v: string | null | undefined) => {
    const t = (v ?? "").trim();
    if (t && !out.some((o) => o.toLowerCase() === t.toLowerCase())) out.push(t);
  };
  add(mr?.malware_category ?? category);
  for (const t of mr?.ttp_mappings ?? []) add(t.tactic_name);
  for (const c of mr?.capability_matrix ?? []) add(c.tactic_name);
  for (const p of mr?.severity?.affected_platforms ?? []) add(platformWord(p));
  return out;
}

/**
 * The one plain sentence under the family: what kind of thing the sample is
 * and what it runs on, from the report's category and affected platforms
 * ("Loader / backdoor targeting Windows."). Empty when the report states
 * neither.
 */
export function verdictSentence(mr: MalwareReport | null | undefined, category?: string | null): string {
  const kind = (mr?.malware_category ?? category ?? "").trim();
  const platforms = [...new Set((mr?.severity?.affected_platforms ?? []).map(platformWord).filter(Boolean))];
  if (!kind && platforms.length === 0) return "";
  const head = kind ? kind.charAt(0).toUpperCase() + kind.slice(1) : "Runs on";
  const tail = platforms.length === 0 ? "" : kind ? ` targeting ${platforms.join(", ")}` : ` ${platforms.join(", ")}`;
  return `${head}${tail}`.replace(/[.\s]*$/, ".");
}

/**
 * What the file is, in a few words: its architecture and, for a library,
 * "DLL", else its format's name ("x86-64 DLL", "PE", "ELF"). Empty when the
 * report holds no identity.
 */
export function fileKind(identity: SampleIdentity | null | undefined): string {
  if (!identity) return "";
  const format = identity.is_dll ? "DLL" : fileTypeLabel(identity.file_type);
  return [identity.architecture?.trim(), format].filter(Boolean).join(" ");
}

/** The classification tags the sentence above does not already say. */
export function headerTags(mr: MalwareReport | null | undefined, category?: string | null): string[] {
  const said = verdictSentence(mr, category).toLowerCase();
  // Said as a whole phrase, never as part of a word: "loader" is not said by
  // "Downloader".
  const says = (tag: string) => {
    const escaped = tag.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}($|[^\\p{L}\\p{N}])`, "u").test(said);
  };
  return classificationChips(mr, category).filter((c) => !says(c));
}

function platformWord(p: string): string {
  const map: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS", android: "Android" };
  return map[p.toLowerCase()] ?? p;
}

/** At most `max` chips, and how many more there are. */
export function capChips<T>(chips: readonly T[], max = 5): { shown: T[]; more: number } {
  return { shown: chips.slice(0, max), more: Math.max(0, chips.length - max) };
}

export interface HashRow {
  label: string;
  value: string;
}

/** Every hash the report holds except SHA-256, which the header shows itself. */
export function otherHashes(mr: MalwareReport | null | undefined): HashRow[] {
  const h = mr?.identity?.hashes;
  if (!h) return [];
  const rows: [string, string | null | undefined][] = [
    ["MD5", h.md5],
    ["SHA-1", h.sha1],
    ["SHA-512", h.sha512],
    ["Import hash", h.imphash],
    ["ssdeep", h.ssdeep],
    ["TLSH", h.tlsh],
  ];
  return rows.filter((r): r is [string, string] => Boolean(r[1])).map(([label, value]) => ({ label, value }));
}

/**
 * The lines under the header, only when the analysis is not whole or its
 * verdict cannot be read on its own.
 *
 * A complete run whose verdict agrees with its severity draws none. Each line
 * is one generic sentence a reader understands: what is missing, or why the
 * verdict needs a second look, and what it means for the findings. The
 * platform's own reason, which names stages and components, is kept as the
 * line's `detail` (drawn as a tooltip) and never as the sentence; the full
 * verdict notes are in run quality under Evidence.
 */
export interface Remark {
  text: string;
  /** The stored reason, verbatim; null when there is none. */
  detail: string | null;
}

export const REMARK_TEXT = {
  incomplete: "The analysis did not finish; some sections may be missing.",
  stageFailed: "A stage of the analysis failed; its findings are missing from this report.",
  degraded: "Parts of the analysis returned less than usual; treat the verdict as preliminary.",
  conflict: "The verdict and the severity rating disagree; read the findings before quoting either.",
  inferred: "The analysis did not state this verdict outright; it was inferred, and no confidence is given for it.",
  stopped: "The analysis was stopped before it finished.",
  notAssessed: "No verdict was reached; the verdict shown is the report's placeholder, not a finding.",
} as const;

export function remarks(report: ReportDetailDTO | null | undefined, job?: JobDTO | null): Remark[] {
  const out: Remark[] = [];
  const stop = jobStopNote(job?.status, job?.error_message);
  if (stop && stop !== report?.incomplete_reason) out.push({ text: REMARK_TEXT.stopped, detail: stop });
  if (!report) return out;
  if (report.incomplete_reason) {
    out.push({ text: REMARK_TEXT.incomplete, detail: report.incomplete_reason });
  }
  const notAssessed = report.malware_report?.verdict_not_assessed?.trim();
  if (notAssessed) out.push({ text: REMARK_TEXT.notAssessed, detail: notAssessed });
  const rs =report.malware_report?.run_summary ?? report.run_summary;
  const failed = rs?.failed_analysts ?? [];
  if (failed.length > 0) {
    out.push({ text: REMARK_TEXT.stageFailed, detail: failed.join(", ") });
  }
  const reasons = (rs?.degradation_reasons ?? []).map((r) => r.trim()).filter(Boolean);
  if (reasons.length > 0 || rs?.degraded_mode || report.malware_report?.degraded_mode) {
    out.push({ text: REMARK_TEXT.degraded, detail: reasons.length > 0 ? reasons.join("\n") : null });
  }
  const headline = verdictHeadline(
    report.verdict,
    report.overall_confidence,
    assessedSeverity(report.malware_report),
  );
  if (headline.conflict) out.push({ text: REMARK_TEXT.conflict, detail: null });
  if (verdictReadingNote(report.verdict_reading)) out.push({ text: REMARK_TEXT.inferred, detail: null });
  return out;
}

/* ── Overview ──────────────────────────────────────────────────────── */

function techniqueIds(mr: MalwareReport): string[] {
  const ids = new Set<string>();
  for (const t of mr.ttp_mappings ?? []) if (t.technique_id) ids.add(t.technique_id);
  for (const c of mr.capability_matrix ?? []) if (c.technique_id) ids.add(c.technique_id);
  return [...ids];
}

export interface Kpi {
  key: string;
  label: string;
  value: number | null;
  tab: AnalysisTabKey;
}

const WRITE_OP = /create|write|drop|copy|move|rename/i;
const OP_KEY = /^(op|operation|action|type|kind)$/i;
const PATH_KEY = /^(path|file|filename|file_name|file_path|target|dest|destination)$/i;

/**
 * How many distinct files the sample wrote while it ran, or null when the
 * run recorded no file activity at all. A file the sample wrote twice is one
 * file; an operation with no path is not counted, since it names no file.
 */
export function filesWritten(mr: MalwareReport | null | undefined): number | null {
  const ops = mr?.dynamic?.file_operations;
  if (!Array.isArray(ops)) return null;
  const paths = new Set<string>();
  for (const op of ops) {
    const entries = Object.entries(op ?? {});
    const writes = entries.some(([k, v]) => OP_KEY.test(k) && typeof v === "string" && WRITE_OP.test(v));
    if (!writes) continue;
    const path = entries.find(([k, v]) => PATH_KEY.test(k) && typeof v === "string" && v.trim());
    if (path) paths.add(String(path[1]).trim().toLowerCase());
  }
  return paths.size;
}

const NETWORK_KIND = /domain|fqdn|host|ip|url|uri/i;

/**
 * How many distinct network indicators the report publishes: the IOC table's
 * network rows whose publish answer is a yes, the same rows the IOC list,
 * STIX and MISP exports carry. A decoded C2 address the report published is
 * counted here; a public resolver it held back is not. Null when the report
 * has no IOC table.
 */
export function publishedNetworkIndicators(mr: MalwareReport | null | undefined): number | null {
  const rows = mr?.consolidated_iocs;
  if (!Array.isArray(rows)) return null;
  const values = new Set<string>();
  for (const row of rows) {
    if (!row || typeof row.value !== "string") continue;
    const network = row.is_network ?? NETWORK_KIND.test(row.kind || row.type || "");
    if (network && decisionOf(row.published).publication === "published") values.add(row.value.trim().toLowerCase());
  }
  return values.size;
}

export interface ReferenceRow {
  source: string;
  url: string;
  /** The address the page links, or null when it makes no link of it: only
   *  an http or https address the Markdown links would also allow. */
  href: string | null;
  note: string;
}

/** The report's external references, each with the link the page may make. */
export function referenceRows(mr: MalwareReport | null | undefined): ReferenceRow[] {
  const rows = Array.isArray(mr?.references) ? mr.references : [];
  return rows
    .filter((r) => r && (typeof r.source === "string" || typeof r.url === "string"))
    .map((r) => {
      const url = typeof r.url === "string" ? r.url.trim() : "";
      const safe = url ? safeHref(url) : null;
      return {
        source: (typeof r.source === "string" && r.source.trim()) || url,
        url,
        href: safe && /^https?:/i.test(safe) ? safe : null,
        note: typeof r.note === "string" ? r.note.trim() : "",
      };
    })
    .filter((r) => r.source);
}

/** The number row above the findings. `null` is a count the report does not hold. */
export function kpis(mr: MalwareReport | null | undefined): Kpi[] {
  if (!mr) return [];
  const hasTechniques = Array.isArray(mr.ttp_mappings) || Array.isArray(mr.capability_matrix);
  return [
    { key: "signatures", label: "Behaviour signatures", value: mr.dynamic ? mr.dynamic.sandbox_signatures.length : null, tab: "behaviour" },
    { key: "techniques", label: "ATT&CK techniques", value: hasTechniques ? techniqueIds(mr).length : null, tab: "behaviour" },
    { key: "iocs", label: "Indicators", value: mr.consolidated_iocs ? mr.consolidated_iocs.length : null, tab: "indicators" },
    { key: "network", label: "Published network indicators", value: publishedNetworkIndicators(mr), tab: "network" },
    { key: "files", label: "Files written", value: filesWritten(mr), tab: "behaviour" },
    {
      key: "rules",
      label: "Detection rules",
      value: Array.isArray(mr.detection_signatures) ? mr.detection_signatures.length : null,
      tab: "indicators",
    },
  ];
}

/**
 * How a finding is known, in the report's own terms.
 *
 * A sandbox signature is what the sandbox saw the sample do. A technique
 * carries the report's own basis: `support` ("capability" when every source
 * is an artefact of the file, "unobserved" when no behaviour source stands
 * behind it) and `source_kinds`, its sources counted by what each is
 * (`run`, `code`, `rule`, `artefact`, `report`, `unplaced`). Which analyst
 * named it says nothing about how it is known, so it is never read: an
 * analyst of the dynamic layer may well name a technique only the code shows.
 * A technique whose report states neither is "Not stated", never a guess.
 */
export type Voice = "observed" | "code" | "rule" | "capability" | "unobserved" | "unstated";

export const VOICE_TEXT: Record<Voice, string> = {
  observed: "Observed when the sample ran",
  code: "Read from the code, not observed running",
  rule: "Matched by a detection rule, not observed running",
  capability: "A capability in the file, not observed",
  unobserved: "Not observed",
  unstated: "Not stated",
};

/** The basis of one technique, from its published row and its matrix cell. */
export function techniqueVoice(
  row: { support?: string; source_kinds?: Record<string, number> } | null | undefined,
  cell?: { support?: string; source_kinds?: Record<string, number> } | null,
): Voice {
  const support = (row?.support || cell?.support || "").trim().toLowerCase();
  if (support === "capability") return "capability";
  if (support === "unobserved") return "unobserved";
  const kinds = row?.source_kinds && Object.keys(row.source_kinds).length > 0 ? row.source_kinds : cell?.source_kinds;
  if (!kinds) return "unstated";
  if ((kinds.run ?? 0) > 0) return "observed";
  if ((kinds.code ?? 0) > 0) return "code";
  if ((kinds.rule ?? 0) > 0) return "rule";
  return "unstated";
}

/**
 * The one marker every claim on the page carries for how it is known, in two
 * shapes: seen when the sample ran, or not seen (read from the code, matched
 * by a rule, present in the file). `label` is the marker's short word;
 * `VOICE_TEXT` says the same in full as its description.
 */
export type Basis = "seen" | "partly" | "not-seen" | "unstated";

export const VOICE_BASIS: Record<Voice, { basis: Basis; label: string }> = {
  observed: { basis: "seen", label: "Seen in sandbox" },
  code: { basis: "not-seen", label: "Code only" },
  rule: { basis: "not-seen", label: "Rule match only" },
  capability: { basis: "not-seen", label: "In the file only" },
  unobserved: { basis: "not-seen", label: "Not seen" },
  unstated: { basis: "unstated", label: "Basis not stated" },
};

const TECHNIQUE_ID = /\bT\d{4}(?:\.\d{3})?\b/g;

/** The ATT&CK technique ids a sentence names, in order, once each. */
export function techniqueIdsIn(text: string | null | undefined): string[] {
  return [...new Set((text ?? "").match(TECHNIQUE_ID) ?? [])];
}

/** Each technique the report maps, with how it is known. */
export function techniqueVoices(mr: MalwareReport | null | undefined): Map<string, Voice> {
  const out = new Map<string, Voice>();
  for (const row of findingRows(mr)) {
    if (row.id.startsWith("ttp-") && row.techniques[0]) out.set(row.techniques[0], row.voice);
  }
  return out;
}

export interface ClaimBasis {
  basis: Basis;
  label: string;
  /** The full sentence: the marker's description. */
  detail: string;
}

/**
 * How a key finding is known, read from the techniques it names and nothing
 * else: seen when every one it names was seen running, not seen when none
 * was, partly seen when some were. A finding that names no mapped technique
 * gets no marker rather than a guess.
 */
export function claimBasis(techniques: readonly string[], voices: ReadonlyMap<string, Voice>): ClaimBasis | null {
  const named = [...new Set(techniques)];
  const known = named
    .map((t) => voices.get(t))
    .filter((v): v is Voice => v !== undefined && v !== "unstated");
  if (known.length === 0) return null;
  const seen = known.filter((v) => v === "observed").length;
  // Seen only when every technique it names was seen: one the report does
  // not map, or maps with no stated basis, is not evidence of having run.
  if (seen === named.length) return { basis: "seen", label: VOICE_BASIS.observed.label, detail: VOICE_TEXT.observed };
  if (seen > 0) {
    return {
      basis: "partly",
      label: "Partly seen",
      detail: `${seen} of the ${named.length} techniques it names were observed when the sample ran`,
    };
  }
  const kinds = [...new Set(known)];
  return kinds.length === 1
    ? { ...VOICE_BASIS[kinds[0]], detail: VOICE_TEXT[kinds[0]] }
    : { basis: "not-seen", label: "Not seen in sandbox", detail: "None of the techniques it names was observed when the sample ran" };
}

export interface FindingRow {
  id: string;
  severity: SeverityRating | null;
  category: string;
  title: string;
  voice: Voice;
  /** The concrete evidence lines the drawer lists. */
  details: string[];
  techniques: string[];
  evidenceIds: string[];
}

/**
 * The findings table: behaviour signatures and ATT&CK techniques, highest
 * severity first, unrated after every rated row.
 *
 * A signature's severity is its own number read on the run's scale; a
 * technique states none, so it is unrated rather than coloured by a guess.
 */
export function findingRows(mr: MalwareReport | null | undefined): FindingRow[] {
  if (!mr) return [];
  const scale = runSignatureScale(mr.run_summary);
  const rows: FindingRow[] = [];
  (mr.dynamic?.sandbox_signatures ?? []).forEach((s, i) => {
    rows.push({
      id: `sig-${i}`,
      severity: signatureScore(s.severity, scale).rung,
      category: "Behaviour",
      title: s.description || s.name,
      voice: "observed",
      details: s.marks ?? [],
      techniques: s.technique_ids ?? [],
      evidenceIds: [],
    });
  });
  const seen = new Set<string>();
  const cells = new Map((mr.capability_matrix ?? []).map((c) => [c.technique_id, c]));
  for (const t of mr.ttp_mappings ?? []) {
    if (seen.has(t.technique_id)) continue;
    seen.add(t.technique_id);
    const cell = cells.get(t.technique_id);
    rows.push({
      id: `ttp-${t.technique_id}`,
      severity: null,
      category: t.tactic_name || cell?.tactic_name || "Technique",
      title: t.technique_name,
      voice: techniqueVoice(t, cell),
      details: [...(t.evidence_quotes ?? []), ...(cell?.evidence ?? [])],
      techniques: [t.technique_id],
      evidenceIds: [...(t.evidence_roots ?? []), ...(cell?.evidence_roots ?? [])],
    });
  }
  for (const c of mr.capability_matrix ?? []) {
    if (seen.has(c.technique_id)) continue;
    seen.add(c.technique_id);
    rows.push({
      id: `ttp-${c.technique_id}`,
      severity: null,
      category: c.tactic_name || "Technique",
      title: c.technique_name,
      voice: techniqueVoice(c),
      details: c.evidence ?? [],
      techniques: [c.technique_id],
      evidenceIds: c.evidence_roots ?? [],
    });
  }
  const rank = (r: FindingRow) => (r.severity ? 5 - ["Critical", "High", "Medium", "Low", "Informational"].indexOf(r.severity) : 0);
  return rows
    .map((r) => ({ ...r, details: [...new Set(r.details)], evidenceIds: [...new Set(r.evidenceIds)] }))
    .sort((a, b) => rank(b) - rank(a));
}

const HOW_OBTAINED: Record<ConfigItem["how_obtained"], string> = {
  decrypted: "Decrypted",
  observed: "Observed",
  "static-string": "Read from strings",
  inferred: "Inferred",
};

export function howObtained(item: ConfigItem): string {
  return HOW_OBTAINED[item.how_obtained] ?? item.how_obtained;
}

/** The configuration as one block of text, for "Copy all". */
export function configText(items: readonly ConfigItem[]): string {
  return items.map((i) => `${i.key}: ${i.value}`).join("\n");
}

/** P0 first; equal priorities keep their order. */
export function sortedRecommendations(recs: readonly DefensiveRecommendation[] | null | undefined): DefensiveRecommendation[] {
  const order = { P0: 0, P1: 1, P2: 2 } as Record<string, number>;
  return [...(recs ?? [])].sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3));
}

/** The file's name, from the report, else the job, else a placeholder (drawn
 *  only once the analysis has loaded; the header shows a skeleton before). */
export function fileName(report: ReportDetailDTO | null, job: JobDTO | null): string {
  return report?.malware_report?.identity?.file_name || job?.sample_filename || "Unnamed sample";
}

/** The file names start with: "maljan-" and the first eight hex of the hash. */
export function exportBaseName(sha256: string | null | undefined, jobId: string): string {
  // Twelve characters, as the console's downloads have always been named.
  const head = (sha256 || jobId).replace(/[^0-9a-zA-Z]/g, "").slice(0, 12);
  return `maljan-${head}`;
}

/* ── Citations in prose ────────────────────────────────────────────── */

/** A run of prose, or one bracketed group of evidence ids cited in it. */
export type ProsePart = { kind: "text"; text: string } | { kind: "cite"; ids: string[] };

// "[ev_0001]", "[ev_0001, ev_0003]", "[ev_0001; ev_0003, …]": a bracket that
// holds evidence ids and nothing else but separators and an ellipsis.
const CITE_GROUP = /\s?\[\s*(ev_[A-Za-z0-9_-]+(?:\s*[,;]\s*ev_[A-Za-z0-9_-]+)*)(?:\s*[,;]?\s*(?:…|\.\.\.))?\s*\]/g;

/**
 * Prose with its bracketed evidence-id groups lifted out.
 *
 * The report's prose may still cite its records inline. The page never
 * prints an id in prose: each group becomes one superscript link that opens
 * the evidence drawer on those ids, and the space before the bracket goes
 * with it, so the sentence reads as if the bracket had never been there.
 */
export function splitCitations(text: string | null | undefined): ProsePart[] {
  const source = text ?? "";
  const parts: ProsePart[] = [];
  let at = 0;
  for (const m of source.matchAll(CITE_GROUP)) {
    const start = m.index ?? 0;
    if (start > at) parts.push({ kind: "text", text: source.slice(at, start) });
    parts.push({ kind: "cite", ids: [...new Set(m[1].split(/\s*[,;]\s*/).filter(Boolean))] });
    at = start + m[0].length;
  }
  if (at < source.length) parts.push({ kind: "text", text: source.slice(at) });
  return parts;
}

const BARE_ID = /\bev_[A-Za-z0-9_-]+/g;

/**
 * Every evidence id a text already cites, in a bracketed group or bare: a
 * list of the evidence behind it then names only the rest, so one record is
 * never marked twice beside one answer.
 */
export function citedIds(text: string | null | undefined): Set<string> {
  return new Set((text ?? "").match(BARE_ID) ?? []);
}

/** The prose alone, its citation groups dropped: for a title or a label. */
export function proseText(text: string | null | undefined): string {
  return splitCitations(text)
    .map((p) => (p.kind === "text" ? p.text : ""))
    .join("");
}
