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
import { verdictBucket, verdictLabel } from "@/lib/verdict";
import type {
  ConfigItem,
  DefensiveRecommendation,
  MalwareReport,
  SeverityRating,
} from "@/types/malware-report";

/* ── Tabs ──────────────────────────────────────────────────────────── */

export type PreviewTabKey = "overview" | "behaviour" | "network" | "static" | "indicators" | "evidence";

export interface PreviewTab {
  key: PreviewTabKey;
  label: string;
  /** The path segment under the analysis; empty for Overview. */
  segment: string;
  /** What the finished tab will hold, listed on its placeholder. */
  planned: string[];
}

export const PREVIEW_TABS: readonly PreviewTab[] = [
  { key: "overview", label: "Overview", segment: "", planned: [] },
  {
    key: "behaviour",
    label: "Behaviour",
    segment: "behaviour",
    planned: [
      "Process tree with the malicious path highlighted and benign branches collapsed",
      "Behaviours of each process, grouped by severity and then by ATT&CK technique",
      "ATT&CK as a compact tactic and technique list, with the full matrix on demand",
      "Persistence and defence evasion as filters of this view",
    ],
  },
  {
    key: "network",
    label: "Network",
    segment: "network",
    planned: [
      "A summary of hosts, requests and protocols first",
      "Hosts on the left, their requests on the right",
      "DNS, HTTP and TLS tables, ten rows at a time, with reputation beside each host",
      "The packet capture download in the tab header",
    ],
  },
  {
    key: "static",
    label: "Static & code",
    segment: "static",
    planned: [
      "File identity and metadata",
      "Executable details: sections and imports as sub-tabs",
      "Strings with filters, decoded strings and where the configuration was read from",
      "Functions examined, each with a short code excerpt",
    ],
  },
  {
    key: "indicators",
    label: "Indicators & detection",
    segment: "indicators",
    planned: [
      "Indicator browser: type filters with counts, search, a table and a detail panel",
      "For each indicator, why it is or is not published and the findings it supports",
      "Generated detection rules in one list, each with copy and download",
      "A graph view of the indicators on demand",
    ],
  },
  {
    key: "evidence",
    label: "Evidence",
    segment: "evidence",
    planned: [
      "Every tool call and record behind the report, with filters and links",
      "The analysts' discussion and their individual findings",
      "Run quality and timing, collapsed",
    ],
  },
];

export function previewBase(jobId: string): string {
  return `/preview/analysis/${encodeURIComponent(jobId)}`;
}

export function previewHref(jobId: string, tab: PreviewTab): string {
  return tab.segment ? `${previewBase(jobId)}/${tab.segment}` : previewBase(jobId);
}

/** The tab a route's optional segment names; null for a segment that is no tab. */
export function tabForSegment(segment: string | undefined): PreviewTab | null {
  return PREVIEW_TABS.find((t) => t.segment === (segment ?? "")) ?? null;
}

/** How many items each tab will hold; null where the report does not say. */
export function tabCounts(mr: MalwareReport | null | undefined): Record<PreviewTabKey, number | null> {
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
  /** What the ring says to a screen reader: "Malicious, confidence 91 percent". */
  label: string;
}

/** The line beside the ring, saying what its number is. */
export const CONFIDENCE_WHY = "How sure the analysis is of this verdict";

/*
 * The ring shows the confidence the analysis put on its verdict, as stored,
 * and nothing derived from it. The report has no score field, so the page
 * draws no score until the backend emits one.
 */
export function verdictConfidence(
  verdict: string | null | undefined,
  confidence: number | null | undefined,
): VerdictConfidence {
  const word = verdictBucket(verdict) === "unknown" ? "No verdict" : verdictLabel(verdict);
  if (confidence == null || Number.isNaN(confidence)) {
    return { percent: null, verdict: word, label: `${word}, confidence not assessed` };
  }
  const percent = Math.round(Math.min(1, Math.max(0, confidence)) * 100);
  return { percent, verdict: word, label: `${word}, confidence ${percent} percent` };
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
 * The lines under the header, only when the analysis is not whole.
 *
 * A complete run draws none. Each line is one generic sentence a reader
 * understands: what is missing and what it means for the findings. The
 * platform's own reason, which names stages and components, is kept as the
 * line's `detail` (drawn as a tooltip) and never as the sentence.
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
} as const;

export function remarks(report: ReportDetailDTO | null | undefined): Remark[] {
  if (!report) return [];
  const out: Remark[] = [];
  if (report.incomplete_reason) {
    out.push({ text: REMARK_TEXT.incomplete, detail: report.incomplete_reason });
  }
  const rs = report.malware_report?.run_summary ?? report.run_summary;
  const failed = rs?.failed_analysts ?? [];
  if (failed.length > 0) {
    out.push({ text: REMARK_TEXT.stageFailed, detail: failed.join(", ") });
  }
  const reasons = (rs?.degradation_reasons ?? []).map((r) => r.trim()).filter(Boolean);
  if (reasons.length > 0 || rs?.degraded_mode || report.malware_report?.degraded_mode) {
    out.push({ text: REMARK_TEXT.degraded, detail: reasons.length > 0 ? reasons.join("\n") : null });
  }
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
  tab: PreviewTabKey;
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
  const head = (sha256 || jobId).replace(/[^0-9a-zA-Z]/g, "").slice(0, 8);
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

/** The prose alone, its citation groups dropped: for a title or a label. */
export function proseText(text: string | null | undefined): string {
  return splitCitations(text)
    .map((p) => (p.kind === "text" ? p.text : ""))
    .join("");
}
