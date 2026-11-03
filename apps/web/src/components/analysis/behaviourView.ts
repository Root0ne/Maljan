/**
 * What the Behaviour tab lists, and which of it each of its views keeps.
 *
 * The sandbox's signatures are listed by severity, then by the ATT&CK
 * technique each names, so the worst behaviour leads and two signatures for
 * one technique sit together. A signature's severity is the sandbox's own
 * number read on the scale the run recorded for it (`signatureScore`), and is
 * drawn on the console's one n/5 ladder; the sandbox's number stays beside it.
 * Where the sandbox named the processes it saw the hits in, the reader can
 * list them per process instead, each process's hits grouped that way.
 *
 * Persistence and defence evasion are views of the tab, not blocks of their
 * own: each keeps the behaviours and the techniques under its ATT&CK tactic.
 * Which tactic a technique belongs to is read from the run's own mapping (the
 * capability matrix, else the published mappings), and a sub-technique is
 * read under its parent when only the parent is mapped. Nothing here knows a
 * sandbox, a family or a technique by name.
 */

import type { MalwareReport, ProcessNode, SandboxSignature, SeverityRating } from "@/types/malware-report";
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


/**
 * A signature seen in more processes than this is listed once, under the
 * count of processes it spans, rather than under each: a hit the sandbox saw
 * in fifty processes says something of the run, not of one process.
 */
export const SPAN_PROCESSES = 3;

export type ProcessGroup =
  | {
      kind: "process";
      /** The pid the sandbox saw the hits in. */
      pid: string;
      /** The process's name where the run's process tree lists the pid. */
      name: string | null;
      severities: SeverityGroup[];
      count: number;
    }
  | {
      kind: "spans";
      /** How many processes each signature of the group was seen in. */
      processes: number;
      severities: SeverityGroup[];
      count: number;
    }
  | {
      kind: "none";
      severities: SeverityGroup[];
      count: number;
    };

/** How many processes the sandbox saw one signature's hit in. */
export function signatureSpan(signature: SandboxSignature): number {
  return Math.max(new Set(signature.pids ?? []).size, signature.pids_total ?? 0);
}

/** "Seen in pid 4", "Seen in pids 4, 9", with the count where the list is cut; "" for none. */
export function seenInText(signature: SandboxSignature): string {
  const pids = [...new Set(signature.pids ?? [])];
  if (pids.length === 0) return "";
  const total = signature.pids_total ?? 0;
  const more = total > pids.length ? ` (${pids.length} of ${total} listed)` : "";
  return `Seen in pid${pids.length === 1 && !more ? "" : "s"} ${pids.join(", ")}${more}`;
}

/** Each pid of the tree, in the order the tree lists its processes, with the process's name. */
function treeNames(nodes: readonly ProcessNode[], out: Map<string, string> = new Map()): Map<string, string> {
  for (const node of nodes) {
    const pid = String(node.pid ?? "");
    if (pid && !out.has(pid)) out.set(pid, node.name ?? "");
    treeNames(Array.isArray(node.children) ? node.children : [], out);
  }
  return out;
}

/** Two pids the tree does not list, in numeric order read on their digits (no float rounding). */
function byDigits(a: string, b: string): number {
  return a.length - b.length || (a < b ? -1 : a > b ? 1 : 0);
}

/**
 * The signatures per process the sandbox saw them in, each process's hits
 * grouped as `signatureGroups` groups them; null where no signature names a
 * process, and the tab then has only its severity view.
 *
 * A signature seen in up to {@link SPAN_PROCESSES} processes is listed under
 * each; one seen in more is listed once, under the count it spans. Processes
 * come in the order the run's process tree lists them, the ones it does not
 * list after them by pid, then the wide signatures (widest first), then those
 * that name no process.
 */
export function processGroups(
  signatures: readonly SandboxSignature[],
  scale: SignatureScale | null | undefined,
  tree: readonly ProcessNode[] | null | undefined,
): ProcessGroup[] | null {
  if (!signatures.some((s) => (s.pids ?? []).length > 0)) return null;
  const byPid = new Map<string, SandboxSignature[]>();
  const bySpan = new Map<number, SandboxSignature[]>();
  const none: SandboxSignature[] = [];
  const push = <K>(map: Map<K, SandboxSignature[]>, key: K, s: SandboxSignature) => {
    const rows = map.get(key) ?? [];
    rows.push(s);
    map.set(key, rows);
  };
  for (const signature of signatures) {
    const pids = [...new Set(signature.pids ?? [])];
    const span = signatureSpan(signature);
    if (pids.length === 0) none.push(signature);
    else if (span > SPAN_PROCESSES) push(bySpan, span, signature);
    else for (const pid of pids) push(byPid, pid, signature);
  }
  const names = treeNames(tree ?? []);
  const listed = new Map([...names.keys()].map((pid, i) => [pid, i]));
  // Listed processes in the tree's order, then the unlisted ones by pid.
  const pids = [...byPid.keys()].sort((a, b) => {
    const ia = listed.get(a);
    const ib = listed.get(b);
    if (ia !== undefined && ib !== undefined) return ia - ib;
    if (ia !== undefined) return -1;
    if (ib !== undefined) return 1;
    return byDigits(a, b);
  });
  const groups: ProcessGroup[] = pids.map((pid) => {
    const rows = byPid.get(pid)!;
    return { kind: "process", pid, name: names.get(pid) || null, severities: signatureGroups(rows, scale), count: rows.length };
  });
  for (const span of [...bySpan.keys()].sort((a, b) => b - a)) {
    const rows = bySpan.get(span)!;
    groups.push({ kind: "spans", processes: span, severities: signatureGroups(rows, scale), count: rows.length });
  }
  if (none.length > 0) groups.push({ kind: "none", severities: signatureGroups(none, scale), count: none.length });
  return groups;
}
