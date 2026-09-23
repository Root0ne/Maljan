/**
 * The rules that fired on this sample, read once.
 *
 * A current run records them as report sections built from the rule tools'
 * ledger rows: `yara_matches` and `sigma_matches`, the second carrying each
 * rule's own `level`. A run stored before those tools existed recorded them as
 * the deterministic layers' agent claims, in prose the layers wrote, with no
 * level at all. A run's sections are read when it has them and the old claims
 * only when it has none, so one run never draws the same match twice. The
 * DETECTION tab's panel draws these rows; the tab bar has to know, before
 * drawing anything, whether there will be any rows at all.
 *
 * Both answers come from here, so they cannot disagree. They used to: the tab
 * asked "does either layer carry a claim" and the panel then took the *first*
 * finding of each name and kept only the claims that are objects — so a layer
 * whose claims arrived as plain strings offered a tab over a heading and
 * nothing else.
 */

import type { AgentFinding } from "@/types";
import type { EvidenceSection } from "@/types/malware-report";
import { sortBySeverity } from "@/lib/severity";

/** One claim of a deterministic layer, in the shape the parsers read. */
export interface ClaimRecord {
  claim: string;
  confidence: number;
  evidence_ref: string;
  technique_id: string;
  /** The rule author's `level` when the claim object carries one as a field. */
  level?: string;
}

export interface YaraMatch {
  rule_name: string;
  pattern_count: number;
  technique_id: string;
  evidence: string;
  /** The rule's tags, as the tool listed them. Empty for an old claim row. */
  tags: string;
  /** The layer's confidence on an old claim row; null on a section row,
   *  which carries none. */
  confidence: number | null;
}

export interface SigmaMatch {
  rule_name: string;
  technique_id: string;
  source: string;
  evidence: string;
  /** The layer's confidence on an old claim row — the rule's maturity status
   *  as a number, not a severity — or null on a section row, which has none. */
  confidence: number | null;
  /**
   * The rule author's own `level`, lower-cased as the rule states it, or null
   * when there is none to show. Nothing here derives one from the confidence.
   */
  level: string | null;
  /**
   * Whether the source records levels at all. A section row does, so a null
   * level there is a rule that declared none; an old claim row does not, so
   * its null level is one that was never recorded.
   */
  recorded: boolean;
}

/** What the layers are recorded under. */
export const YARA_LAYER = "yara_layer";
export const SIGMA_LAYER = "sigma_layer";

/** What the rule tools' matches are recorded under in the report. */
export const YARA_SECTION = "yara_matches";
export const SIGMA_SECTION = "sigma_matches";

/**
 * The claims of one layer, as records.
 *
 * The first finding of that name and no other — a second is the same layer
 * recorded twice, and reading both would draw every match twice — and only
 * the claims that are objects, because a bare string carries no rule name,
 * no technique and no evidence to cite.
 */
export function findingsByName(
  findings: readonly AgentFinding[] | null | undefined,
  name: string,
): ClaimRecord[] {
  const row = findings?.find((f) => f.agent_name === name);
  if (!row || !Array.isArray(row.claims)) return [];
  return row.claims
    .filter((c): c is Record<string, unknown> => !!c && typeof c === "object")
    .map((c) => ({
      claim: String(c.claim ?? ""),
      confidence: Number(c.confidence ?? 0),
      evidence_ref: String(c.evidence_ref ?? ""),
      technique_id: String(c.technique_id ?? ""),
      ...(typeof c.level === "string" && c.level.trim() ? { level: c.level } : {}),
    }));
}

/* ── Claim parsers ─────────────────────────────────────
 * The deterministic layers (src/maljan/analysis/yara_layer.py +
 * sigma_layer.py) emit free-text claims like:
 *
 *   "Deterministic YARA signature match: Virtualization and sandbox
 *    evasion (rule: sandbox_evasion, 1 pattern(s) found)"
 *
 *   "Sigma rule detection: Suspicious DNS Z Flag Bit Set (technique
 *    T1095, source=generic)"
 *
 * The shape is stable enough to extract rule_name + pattern_count /
 * source via regex without a schema change. It carries no level.
 */
export function parseYara(c: ClaimRecord): YaraMatch {
  const ruleMatch = /rule:\s*([^,)\s]+)/i.exec(c.claim);
  const patternMatch = /(\d+)\s+pattern/i.exec(c.claim);
  return {
    rule_name: ruleMatch?.[1] ?? c.claim.split(":").slice(1).join(":").trim() ?? "unknown",
    pattern_count: patternMatch ? Number(patternMatch[1]) : 0,
    technique_id: c.technique_id || "",
    evidence: c.evidence_ref || "",
    tags: "",
    confidence: c.confidence ?? 0,
  };
}

export function parseSigma(c: ClaimRecord): SigmaMatch {
  const nameMatch = /Sigma rule detection:\s*(.+?)\s*\(technique\s+([^,)]+)(?:,\s*source=([^)]+))?\)/i.exec(
    c.claim,
  );
  const ruleName = nameMatch?.[1] ?? c.claim;
  const technique = nameMatch?.[2] ?? c.technique_id ?? "";
  const source = nameMatch?.[3] ?? "";
  // A claim object that carries the level as a field; the stored claims do not.
  const level = (c.level ?? "").trim().toLowerCase();
  return {
    rule_name: ruleName.trim(),
    technique_id: technique.trim(),
    source: source.trim(),
    evidence: c.evidence_ref || "",
    confidence: c.confidence ?? 0,
    level: level || null,
    recorded: false,
  };
}

/** One section with content, by its key. */
function sectionByKey(
  sections: readonly EvidenceSection[] | null | undefined,
  key: string,
): EvidenceSection | null {
  const found = (sections ?? []).find((s) => s?.key === key && Array.isArray(s.rows));
  return found && found.rows.length > 0 ? found : null;
}

/** A row's cell by its column name, or empty; the `-` a table prints for
 *  empty is read as empty. */
function cellOf(section: EvidenceSection, row: string[], column: string): string {
  const index = (section.columns ?? []).findIndex(
    (name) => String(name).trim().toLowerCase() === column.toLowerCase(),
  );
  const value = index >= 0 ? String(row[index] ?? "").trim() : "";
  return value === "-" ? "" : value;
}

/** The `sigma_matches` section's rows: Rule, Level, Technique, Matched fields. */
export function sigmaFromSection(section: EvidenceSection): SigmaMatch[] {
  return section.rows.map((row) => {
    const level = cellOf(section, row, "Level").toLowerCase();
    return {
      rule_name: cellOf(section, row, "Rule") || "unnamed rule",
      technique_id: cellOf(section, row, "Technique"),
      source: "",
      evidence: cellOf(section, row, "Matched fields"),
      confidence: null,
      level: level || null,
      recorded: true,
    };
  });
}

/** The `yara_matches` section's rows: Rule, Tags, Where. */
export function yaraFromSection(section: EvidenceSection): YaraMatch[] {
  return section.rows.map((row) => ({
    rule_name: cellOf(section, row, "Rule") || "unnamed rule",
    pattern_count: 0,
    technique_id: "",
    evidence: cellOf(section, row, "Where"),
    tags: cellOf(section, row, "Tags"),
    confidence: null,
  }));
}

/**
 * The Sigma rows in the order DETECTION draws them.
 *
 * Rows whose rule level was recorded come first, highest rung of the ladder
 * first; rows on one rung keep the order the layer recorded them in. A row
 * with no recorded level takes no part in that sort — it has no place on the
 * ladder to be sorted by — and follows in its recorded order.
 */
export function orderByLevel(rows: readonly SigmaMatch[]): SigmaMatch[] {
  const recorded = rows.filter((row) => row.level !== null);
  const unrecorded = rows.filter((row) => row.level === null);
  return [...sortBySeverity(recorded, (row) => row.level ?? ""), ...unrecorded];
}

export interface RuleMatches {
  yara: YaraMatch[];
  sigma: SigmaMatch[];
  /** The section each kind was read from, for its citations — the ledger
   *  entries it was built from — or null when it came from old claims. */
  yaraSection: EvidenceSection | null;
  sigmaSection: EvidenceSection | null;
}

/**
 * Every rule match this run recorded, in the shape the panel draws.
 *
 * Each kind is read from the run's section when it has one, and from the old
 * layer's claims only when it has none.
 */
export function ruleMatches(
  findings: readonly AgentFinding[] | null | undefined,
  sections?: readonly EvidenceSection[] | null,
): RuleMatches {
  const yaraSection = sectionByKey(sections, YARA_SECTION);
  const sigmaSection = sectionByKey(sections, SIGMA_SECTION);
  return {
    yara: yaraSection
      ? yaraFromSection(yaraSection)
      : findingsByName(findings, YARA_LAYER).map(parseYara),
    sigma: sigmaSection
      ? sigmaFromSection(sigmaSection)
      : findingsByName(findings, SIGMA_LAYER).map(parseSigma),
    yaraSection,
    sigmaSection,
  };
}

/** Whether the panel has a row to draw, which is what decides the tab. */
export function hasRuleMatches(
  findings: readonly AgentFinding[] | null | undefined,
  sections?: readonly EvidenceSection[] | null,
): boolean {
  const matches = ruleMatches(findings, sections);
  return matches.yara.length > 0 || matches.sigma.length > 0;
}
