/**
 * What the Behaviour tab lists, and which of it each of its views keeps.
 *
 * The sandbox's signatures are listed by severity, then by the ATT&CK
 * technique each names, so the worst behaviour leads and two signatures for
 * one technique sit together. A signature's severity is the sandbox's own
 * number read on the scale the run recorded for it (`signatureScore`), and is
 * drawn on the console's one n/5 ladder; the sandbox's number stays beside it.
 *
 * Persistence and defence evasion are views of the tab, not blocks of their
 * own: each keeps the behaviours and the techniques under its ATT&CK tactic.
 * Which tactic a technique belongs to is read from the run's own mapping (the
 * capability matrix, else the published mappings), and a sub-technique is
 * read under its parent when only the parent is mapped. Nothing here knows a
 * sandbox, a family or a technique by name.
 */

import type { MalwareReport, SandboxSignature, SeverityRating } from "@/types/malware-report";
import { SEVERITY_LADDER, signatureScore, type SignatureScale } from "@/lib/severity";
import { parseTechniques } from "./capabilityHeatmap";

export type BehaviourView = "all" | "persistence" | "defence-evasion";

/** The ATT&CK tactic each filtered view keeps. */
export const VIEW_TACTIC: Record<Exclude<BehaviourView, "all">, string> = {
  persistence: "TA0003",
  "defence-evasion": "TA0005",
};

/** The view an address's hash asks for, or null when it names none. */
export function viewOfHash(hash: string | null | undefined): BehaviourView | null {
  const h = String(hash ?? "").replace(/^#/, "");
  if (h === "persistence") return "persistence";
  if (h === "defence-evasion" || h === "defense-evasion") return "defence-evasion";
  return null;
}

/** Each mapped technique id with the tactics the run places it under. */
export function techniqueTactics(mr: MalwareReport | null | undefined, extra?: unknown[] | null): Map<string, Set<string>> {
  const raw: unknown[] =
    (mr?.capability_matrix?.length ? mr.capability_matrix : null) ??
    (mr?.ttp_mappings?.length ? mr.ttp_mappings : null) ??
    extra ??
    [];
  const out = new Map<string, Set<string>>();
  for (const tactic of parseTechniques(raw)) {
    for (const tech of tactic.techniques) {
      const id = tech.id.toUpperCase();
      const set = out.get(id) ?? new Set<string>();
      set.add(tactic.id);
      out.set(id, set);
    }
  }
  return out;
}

/** Whether `techniqueId` is under `tactic`, reading a sub-technique under its parent. */
export function techniqueUnder(
  techniqueId: string,
  tactic: string,
  tactics: ReadonlyMap<string, ReadonlySet<string>>,
): boolean {
  const id = String(techniqueId ?? "").trim().toUpperCase();
  if (!id) return false;
  if (tactics.get(id)?.has(tactic)) return true;
  const parent = id.split(".")[0];
  return parent !== id && Boolean(tactics.get(parent)?.has(tactic));
}

/** Whether one view keeps a thing that names `techniqueIds`. */
export function viewKeeps(
  view: BehaviourView,
  techniqueIds: readonly string[],
  tactics: ReadonlyMap<string, ReadonlySet<string>>,
): boolean {
  if (view === "all") return true;
  const tactic = VIEW_TACTIC[view];
  return techniqueIds.some((id) => techniqueUnder(id, tactic, tactics));
}

export interface SignatureRow {
  signature: SandboxSignature;
  /** The rung the sandbox's number means, or null when its scale is unknown. */
  rung: SeverityRating | null;
  /** The sandbox's own reading ("High, 8/10", "unrated, 3", "unknown"). */
  sandboxText: string;
  /** The scale's name, when the run recorded one. */
  scale: string | null;
}

export interface TechniqueGroup {
  /** The technique id, or "" for signatures that name none. */
  technique: string;
  rows: SignatureRow[];
}

export interface SeverityGroup {
  /** A rung of the ladder, or null for signatures whose number has no rung. */
  rung: SeverityRating | null;
  techniques: TechniqueGroup[];
  count: number;
}

/**
 * The signatures, grouped by severity (Critical first, unrated last) and then
 * by the first technique each names (signatures that name none last). A
 * signature naming several techniques is listed once, under its first; the
 * rest are printed on its row.
 */
export function signatureGroups(
  signatures: readonly SandboxSignature[],
  scale: SignatureScale | null | undefined,
): SeverityGroup[] {
  const order: (SeverityRating | null)[] = [...SEVERITY_LADDER, null];
  const byRung = new Map<SeverityRating | null, Map<string, SignatureRow[]>>();
  for (const signature of signatures) {
    const score = signatureScore(signature.severity, scale);
    const row: SignatureRow = { signature, rung: score.rung, sandboxText: score.text, scale: score.scale };
    const technique = (signature.technique_ids ?? [])[0] ?? "";
    const groups = byRung.get(score.rung) ?? new Map<string, SignatureRow[]>();
    groups.set(technique, [...(groups.get(technique) ?? []), row]);
    byRung.set(score.rung, groups);
  }
  return order
    .filter((rung) => byRung.has(rung))
    .map((rung) => {
      const groups = byRung.get(rung)!;
      const techniques = [...groups.entries()]
        .sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)))
        .map(([technique, rows]) => ({ technique, rows }));
      return { rung, techniques, count: techniques.reduce((n, t) => n + t.rows.length, 0) };
    });
}
