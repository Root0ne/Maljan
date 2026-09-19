import type { CorroborationRow } from "@/types/malware-report";
/**
 * The ATT&CK matrix, derived from whatever technique list the report carries.
 *
 * Two rules here are not presentation, they are the report's own arithmetic,
 * and the console has to run them the same way the backend does or the same
 * run reads differently in two places.
 *
 * **The judge is a source but not a corroboration.** It is listed, because a
 * technique the judge named and no analyst claimed should say where it came
 * from. It is left out of the count, because the judge read the analysts:
 * agreeing with what it was shown is not a second observation.
 *
 * The comparison is exact, and that is the whole of the rule:
 * `capability_matrix.py` writes `lyr != _JUDGE_SOURCE`, and a layer name is a
 * validated agent key — lowercase, trimmed, matched against
 * `AGENT_KEY_PATTERN` — so there is no `"Judge"` or `" judge"` for a looser
 * comparison to catch. Normalising here and not there would make the persisted
 * `is_corroborated` and the badge on this page disagree about the same run,
 * which is the one thing this module exists to prevent.
 *
 * **An id the catalog does not have keeps its row and gains a marker.** The
 * pipeline stopped deleting a producer's answer; a row nobody can resolve is
 * printed and marked, never dropped.
 */

/* Canonical MITRE Enterprise tactic catalogue in kill-chain (matrix) column
   order, with display names. TA0005 (Defense Evasion / Stealth in ATT&CK v19)
   and TA0112 (Defense Impairment, added in v19) are both listed so the columns
   stay matrix-accurate as the bundle updates.

   The capabilities view renders the Enterprise matrix; the Mobile and ICS
   matrices are catalogued server-side and are not drawn here yet. */
export const ENTERPRISE_TACTICS: { id: string; name: string }[] = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0112", name: "Defense Impairment" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

const ENTERPRISE_NAME_BY_ID: Record<string, string> = Object.fromEntries(
  ENTERPRISE_TACTICS.map((t) => [t.id, t.name])
);
const ENTERPRISE_ORDER_BY_ID: Record<string, number> = Object.fromEntries(
  ENTERPRISE_TACTICS.map((t, i) => [t.id, i])
);

/** What the judge is called in `contributing_layers`. */
export const JUDGE_SOURCE = "judge";

/** A source that is the judge. Exact, because the backend's is. */
function isJudge(source: string): boolean {
  return source === JUDGE_SOURCE;
}

// Sort key: canonical Enterprise order first, then any unrecognized tactic id
// after Enterprise by numeric TA-id so columns stay deterministic.
export function tacticOrder(id: string): number {
  if (id in ENTERPRISE_ORDER_BY_ID) return ENTERPRISE_ORDER_BY_ID[id];
  const n = parseInt(id.replace(/\D/g, ""), 10);
  return 1000 + (Number.isFinite(n) ? n : 9999);
}

export interface Technique {
  id: string;
  name: string;
  matches: number;
  /** Every layer that named the technique, the judge included. */
  sources: string[];
  /** The layers that count towards corroboration — sources, minus the judge. */
  corroborating: string[];
  /** `false` when the ATT&CK catalog has no entry for the id and the producer
   *  kept it after being told. */
  valid: boolean;
  /** Why this run did not publish the technique, in words, and empty when it
   *  did. A producer named it and the report keeps the claim; the card says
   *  the claim was not published rather than drawing it as a capability. */
  notPublished: string;
}

export interface Tactic {
  id: string;
  name: string;
  technique_count: number;
  techniques: Technique[];
}

/** A technique stands on more than one independent observation. */
export function isCorroborated(technique: Technique): boolean {
  return technique.corroborating.length >= 2;
}

/**
 * What a tactic column's header counts, in the same shape the run summary uses.
 *
 * A column that reads "3 techniques" over three the run declined to publish
 * says the same thing "TTPs: 3 named" said before it became "3 claimed, 0
 * published". The published ones are the count; the rest are named beside it.
 */
export function tacticHeaderCount(techniques: Technique[]): string {
  const published = techniques.filter((t) => !t.notPublished).length;
  const head = `${published} technique${published === 1 ? "" : "s"}`;
  const claimed = techniques.length - published;
  return claimed > 0 ? `${head} · ${claimed} claimed, not published` : head;
}

/**
 * Group a flat technique list into tactic buckets keyed by tactic id.
 *
 * The list arrives from one of two places: the cached report's
 * `ttp_mappings`/`capability_matrix`, which carry `contributing_layers` and
 * `technique_id_valid`, or the `/mitre` fallback, which carries `sources` and
 * `match_count`. Both shapes are read so the badges render on either path.
 */
export function parseTechniques(raw: unknown[]): Tactic[] {
  const tacticMap = new Map<string, Tactic>();

  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const t = item as Record<string, unknown>;

    const techId = String(t.technique_id ?? t.id ?? "");
    const techName = String(t.technique_name ?? t.name ?? techId);
    // ``||`` not ``??`` so an empty-string tactic (the TTPMapping default)
    // falls through to "TA0000" instead of collapsing every un-tacticked
    // technique into one mislabeled "Unknown Tactic".
    const tacticId = String(t.tactic_id || t.tactic || "TA0000");
    let tacticName = String(t.tactic_name ?? "");
    const sources = Array.isArray(t.sources)
      ? (t.sources as unknown[]).map(String)
      : Array.isArray(t.contributing_layers)
      ? (t.contributing_layers as unknown[]).map(String)
      : [];
    const matches =
      Number(
        t.matches ??
          t.match_count ??
          (Array.isArray(t.contributing_layers) ? t.contributing_layers.length : 1)
      ) || 1;
    // Absent on rows persisted before the flag existed, and those rows meant
    // "valid" — only an explicit ``false`` marks a row.
    const valid = t.technique_id_valid !== false;
    // Only a capability cell carries this; a published mapping and a /mitre
    // row never do, which reads as published, which they are.
    const notPublished = String(t.not_published ?? "");

    // Canonical Enterprise display name wins for any KNOWN tactic id. This
    // covers two cases: (a) the mapping only carried the TA-id (TTPMapping has
    // no tactic_name, so columns would read "TA0005" instead of "Defense
    // Evasion"), and (b) a persisted/bundle tactic_name that is non-canonical
    // (e.g. "Stealth" for TA0005) would otherwise mislabel the column.
    // Unknown/new tactic ids keep whatever name the mapping supplied.
    const canonicalName = ENTERPRISE_NAME_BY_ID[tacticId];
    if (canonicalName) {
      tacticName = canonicalName;
    } else if (!tacticName || tacticName === tacticId || tacticName === "Unknown Tactic") {
      tacticName = tacticId || "Unknown Tactic";
    }

    if (!tacticMap.has(tacticId)) {
      tacticMap.set(tacticId, {
        id: tacticId,
        name: tacticName,
        technique_count: 0,
        techniques: [],
      });
    }

    const tactic = tacticMap.get(tacticId)!;
    const existing = tactic.techniques.find((x) => x.id === techId);
    if (existing) {
      // Deduplicate techniques within a tactic, summing match counts and
      // taking the union of the layers. A row marked invalid anywhere stays
      // marked: the id either resolves or it does not.
      existing.matches += matches;
      existing.sources = [...new Set([...existing.sources, ...sources])];
      existing.corroborating = existing.sources.filter((source) => !isJudge(source));
      existing.valid = existing.valid && valid;
      existing.notPublished = existing.notPublished || notPublished;
    } else {
      tactic.techniques.push({
        id: techId,
        name: techName,
        matches,
        sources,
        corroborating: sources.filter((source) => !isJudge(source)),
        valid,
        notPublished,
      });
      tactic.technique_count++;
    }
  }

  return Array.from(tacticMap.values());
}

/**
 * Whether these rows produce a matrix at all.
 *
 * The tab rule asks this before offering ATT&CK, and the tab draws what the
 * same parser keeps, so the two cannot disagree about whether there is a
 * mapping: a row that is not an object, or a list of rows that parses to no
 * technique, is not a mapping however long the array is.
 */
export function hasMappedTechniques(raw: unknown[] | null | undefined): boolean {
  if (!Array.isArray(raw) || raw.length === 0) return false;
  return parseTechniques(raw).some((tactic) => tactic.techniques.length > 0);
}

/** The columns, in canonical Enterprise matrix order. */
export function orderedTactics(tactics: Tactic[]): Tactic[] {
  return [...tactics].sort((a, b) => tacticOrder(a.id) - tacticOrder(b.id));
}

/**
 * The sources the run summary recorded for one technique.
 *
 * `run_summary.corroboration` is the pipeline's own record of which producers
 * named which technique, kept apart from the matrix so the two can be compared
 * rather than conflated. Shown on the card that names the technique.
 */
export function corroborationSources(
  corroboration: Record<string, CorroborationRow | string[]> | null | undefined,
  techniqueId: string
): string[] {
  const lists = corroborationLists(corroboration, techniqueId);
  return [...lists.asserted_by, ...lists.claimed_by];
}

/**
 * The two lists behind one technique: who asserted it (a deterministic
 * source carrying its own ATT&CK id) and who claimed it (an agent). A summary
 * stored as a flat list is read as claimed by all of them.
 */
export function corroborationLists(
  corroboration: Record<string, CorroborationRow | string[]> | null | undefined,
  techniqueId: string
): CorroborationRow {
  const row = corroboration?.[techniqueId];
  if (!row) return { asserted_by: [], claimed_by: [] };
  if (Array.isArray(row)) return { asserted_by: [], claimed_by: row };
  return { asserted_by: row.asserted_by ?? [], claimed_by: row.claimed_by ?? [] };
}

/** The ATT&CK release that retired the id, when the run's corroboration row says so. */
export function retiredIn(
  corroboration: Record<string, CorroborationRow | string[]> | null | undefined,
  techniqueId: string
): string | null {
  const row = corroboration?.[techniqueId];
  if (!row || Array.isArray(row)) return null;
  return row.retired_in ?? null;
}

/** The API catalogue's association for the id, shown apart from the sources. */
export function associatedBy(
  corroboration: Record<string, CorroborationRow | string[]> | null | undefined,
  techniqueId: string
): string[] {
  const row = corroboration?.[techniqueId];
  if (!row || Array.isArray(row)) return [];
  return row.associated_by ?? [];
}
