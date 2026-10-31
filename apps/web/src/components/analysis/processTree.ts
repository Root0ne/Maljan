/**
 * The sandbox's process tree as the Behaviour tab draws it: the path to what
 * the sample did is open and marked, everything else is folded, and the tree
 * is drawn a bounded number of rows at a time.
 *
 * A tree of three hundred benign system processes with the sample's two
 * children somewhere in it read as a wall; a reader had to find the sample
 * before reading what it did. Which processes matter is read from the report
 * rather than from process names: a process is flagged when the sandbox marks
 * it as the sample's (`marked`), when it injects into another, or when another
 * part of the report ties a behaviour to its pid (a DNS query, a registry
 * write). A flagged process, every ancestor of it and every process it started
 * are the path; the path is open, and the processes beside it fold into one
 * "N other processes" row a reader can open. A tree with nothing flagged has no path to show, and opens
 * its first two levels as it always did.
 */

import type { MalwareReport, ProcessNode } from "@/types/malware-report";

/** How many rows the tree draws before offering more. */
export const PROCESS_ROWS_FIRST = 25;

export type ProcessRow =
  | {
      kind: "process";
      key: string;
      node: ProcessNode;
      depth: number;
      /** This process is one the report ties to the sample's behaviour. */
      flagged: boolean;
      /** This process, one above it or one below it is flagged. */
      onPath: boolean;
      hasChildren: boolean;
      open: boolean;
      /** The words saying why it is flagged ("marked by the sandbox", …). */
      reasons: string[];
    }
  | {
      kind: "fold";
      /** The key of the parent whose off-path children this row folds ("" for the roots). */
      key: string;
      depth: number;
      /** How many processes the fold hides, descendants included. */
      count: number;
    };

/** The reader's choices: which processes were opened or closed, which folds opened. */
export interface TreeState {
  open: Readonly<Record<string, boolean>>;
  unfolded: ReadonlySet<string>;
}

function pidOf(value: unknown): number | null {
  const n = typeof value === "number" ? value : Number(String(value ?? "").trim());
  return Number.isInteger(n) && n > 0 ? n : null;
}

/**
 * The pids other parts of the report tie a behaviour to, each with why: a
 * domain the process queried and a registry write its call made.
 */
export function behaviourPids(mr: MalwareReport | null | undefined): Map<number, string[]> {
  const out = new Map<number, string[]>();
  const add = (pid: number | null, why: string) => {
    if (pid === null) return;
    const list = out.get(pid) ?? [];
    if (!list.includes(why)) list.push(why);
    out.set(pid, list);
  };
  for (const d of mr?.network?.domains ?? []) {
    for (const pid of d.queried_pids ?? []) add(pidOf(pid), "made a DNS query");
  }
  for (const r of mr?.dynamic?.registry_mods ?? []) {
    for (const pid of r.pids ?? []) add(pidOf(pid), "wrote to the registry");
  }
  return out;
}

/** Why one process is flagged, or nothing when it is not. */
export function flagReasons(node: ProcessNode, tied: ReadonlyMap<number, string[]>): string[] {
  const reasons: string[] = [];
  if (node.marked) reasons.push("marked as the sample's by the sandbox");
  if ((node.injected_into ?? []).length > 0) {
    reasons.push(`injects into ${node.injected_into.join(", ")}`);
  }
  reasons.push(...(tied.get(node.pid) ?? []));
  return reasons;
}

function children(node: ProcessNode): ProcessNode[] {
  return Array.isArray(node.children) ? node.children : [];
}

/** How many processes a list of subtrees holds. */
export function subtreeSize(nodes: readonly ProcessNode[]): number {
  let n = 0;
  for (const node of nodes) n += 1 + subtreeSize(children(node));
  return n;
}

/** Whether any process of the tree is flagged. */
export function anyFlagged(nodes: readonly ProcessNode[], tied: ReadonlyMap<number, string[]>): boolean {
  return nodes.some((n) => flagReasons(n, tied).length > 0 || anyFlagged(children(n), tied));
}

/**
 * The rows the tree draws, in order, for the reader's current choices.
 *
 * A process opens by default when it is on the path (or, in a tree with no
 * path, when it is in the first two levels); the reader's own toggle wins.
 * Beside a path, the off-path processes of one parent fold into one row until
 * the reader opens it.
 */
export function processRows(
  roots: readonly ProcessNode[],
  tied: ReadonlyMap<number, string[]>,
  state: TreeState,
): ProcessRow[] {
  const hasPath = anyFlagged(roots, tied);
  const rows: ProcessRow[] = [];

  const belowMemo = new Map<ProcessNode, boolean>();
  const flaggedBelow = (node: ProcessNode): boolean => {
    const known = belowMemo.get(node);
    if (known !== undefined) return known;
    const value = flagReasons(node, tied).length > 0 || children(node).some(flaggedBelow);
    belowMemo.set(node, value);
    return value;
  };

  const walk = (nodes: readonly ProcessNode[], depth: number, parentKey: string, underFlag: boolean) => {
    const onPath = (node: ProcessNode) => underFlag || flaggedBelow(node);
    const off = hasPath ? nodes.filter((n) => !onPath(n)) : [];
    const folded = off.length > 0 && !state.unfolded.has(parentKey);
    nodes.forEach((node, i) => {
      if (folded && !onPath(node)) return;
      const key = parentKey === "" ? String(i) : `${parentKey}.${i}`;
      const kids = children(node);
      const path = hasPath && onPath(node);
      const byDefault = hasPath ? path : depth < 2;
      const open = kids.length > 0 && (state.open[key] ?? byDefault);
      const reasons = flagReasons(node, tied);
      rows.push({
        kind: "process",
        key,
        node,
        depth,
        flagged: reasons.length > 0,
        onPath: path,
        hasChildren: kids.length > 0,
        open,
        reasons,
      });
      if (open) walk(kids, depth + 1, key, underFlag || reasons.length > 0);
    });
    if (folded) rows.push({ kind: "fold", key: parentKey, depth, count: subtreeSize(off) });
  };

  walk(roots, 0, "", false);
  return rows;
}
