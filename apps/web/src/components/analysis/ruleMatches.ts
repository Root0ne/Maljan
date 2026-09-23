/**
 * The rules that fired on this sample, read once.
 *
 * The deterministic YARA and Sigma layers record what they matched as an
 * agent's claims, in prose the layers themselves write. The DETECTION tab's
 * panel parses that prose into rows; the tab bar has to know, before drawing
 * anything, whether there will be any rows at all.
 *
 * Both answers come from here, so they cannot disagree. They used to: the tab
 * asked "does either layer carry a claim" and the panel then took the *first*
 * finding of each name and kept only the claims that are objects — so a layer
 * whose claims arrived as plain strings offered a tab over a heading and
 * nothing else.
 */

import type { AgentFinding } from "@/types";
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
  confidence: number;
}

export interface SigmaMatch {
  rule_name: string;
  technique_id: string;
  source: string;
  evidence: string;
  confidence: number;
  /**
   * The rule author's own `level`, lower-cased as the rule states it, or null
   * when the stored row does not record one — every run recorded before the
   * layer carried it. The confidence is the rule's maturity status turned into
   * a number, not a severity, and nothing here derives one from it.
   */
  level: string | null;
}

/** What the layers are recorded under. */
export const YARA_LAYER = "yara_layer";
export const SIGMA_LAYER = "sigma_layer";

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
 *    T1095, source=generic, level=high)"
 *
 * The shape is stable enough to extract rule_name + pattern_count /
 * source via regex without a schema change. `level=` is the rule author's
 * level and is absent from every claim stored before the layer wrote it.
 */
export function parseYara(c: ClaimRecord): YaraMatch {
  const ruleMatch = /rule:\s*([^,)\s]+)/i.exec(c.claim);
  const patternMatch = /(\d+)\s+pattern/i.exec(c.claim);
  return {
    rule_name: ruleMatch?.[1] ?? c.claim.split(":").slice(1).join(":").trim() ?? "unknown",
    pattern_count: patternMatch ? Number(patternMatch[1]) : 0,
    technique_id: c.technique_id || "",
    evidence: c.evidence_ref || "",
    confidence: c.confidence ?? 0,
  };
}

export function parseSigma(c: ClaimRecord): SigmaMatch {
  const nameMatch =
    /Sigma rule detection:\s*(.+?)\s*\(technique\s+([^,)]+)(?:,\s*source=([^,)]+))?(?:,\s*level=([^,)]+))?\)/i.exec(
      c.claim,
    );
  const ruleName = nameMatch?.[1] ?? c.claim;
  const technique = nameMatch?.[2] ?? c.technique_id ?? "";
  const source = nameMatch?.[3] ?? "";
  // The level the layer wrote into the claim, or a field of the claim object;
  // a row recorded before the layer carried it has neither.
  const level = (c.level ?? nameMatch?.[4] ?? "").trim().toLowerCase();
  return {
    rule_name: ruleName.trim(),
    technique_id: technique.trim(),
    source: source.trim(),
    evidence: c.evidence_ref || "",
    confidence: c.confidence ?? 0,
    level: level || null,
  };
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
}

/** Every rule match this run recorded, in the shape the panel draws. */
export function ruleMatches(
  findings: readonly AgentFinding[] | null | undefined,
): RuleMatches {
  return {
    yara: findingsByName(findings, YARA_LAYER).map(parseYara),
    sigma: findingsByName(findings, SIGMA_LAYER).map(parseSigma),
  };
}

/** Whether the panel has a row to draw, which is what decides the tab. */
export function hasRuleMatches(
  findings: readonly AgentFinding[] | null | undefined,
): boolean {
  const matches = ruleMatches(findings);
  return matches.yara.length > 0 || matches.sigma.length > 0;
}
