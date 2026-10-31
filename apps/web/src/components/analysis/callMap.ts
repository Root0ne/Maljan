import type { CallMapFunction, CallMapResponse } from "@/types/evidence";

/**
 * The call map's two views, as rows: a tree from the roots, opened one
 * function at a time, and a flat list a reader searches.
 *
 * A tree path is the chain of addresses from a root, so one function that
 * several callers reach opens under each of them on its own. A callee
 * already on the path is a call back up the tree: it is drawn once, as a
 * marker naming the function it returns to, and never opened again, so a
 * cycle cannot grow the tree. Only opened rows are built, and an opened
 * function draws its first `CALLEES_FIRST` callees until asked for all, so
 * a map of thousands of functions costs what is on screen.
 */

/** How many roots and how many callees of one function are drawn first. */
export const ROOTS_FIRST = 25;
export const CALLEES_FIRST = 50;
/** How many rows the flat list draws per step. */
export const LIST_STEP = 25;

export type TreeRow =
  | {
      kind: "function";
      key: string;
      level: number;
      setsize: number;
      posinset: number;
      fn: CallMapFunction;
      /** How many functions it calls: what opening it would show. */
      callees: number;
      open: boolean;
    }
  | { kind: "back"; key: string; level: number; setsize: number; posinset: number; address: string; fn: CallMapFunction | undefined }
  | { kind: "more"; key: string; level: number; setsize: number; posinset: number; parent: string; hidden: number };

export interface TreeState {
  /** The tree paths that are open. */
  open: ReadonlySet<string>;
  /** The tree paths whose callees are drawn in full. */
  whole: ReadonlySet<string>;
}

export const PATH_SEP = ">";

export function byAddress(map: CallMapResponse | null | undefined): Map<string, CallMapFunction> {
  const out = new Map<string, CallMapFunction>();
  for (const fn of map?.functions ?? []) if (fn.address) out.set(fn.address, fn);
  return out;
}

/**
 * The tree's visible rows in reading order, with the level, set size and
 * position the tree pattern announces. `roots` is the slice of roots drawn.
 */
export function treeRows(
  roots: readonly string[],
  index: Map<string, CallMapFunction>,
  state: TreeState,
): TreeRow[] {
  const rows: TreeRow[] = [];
  const walk = (addresses: readonly string[], level: number, path: readonly string[], parent: string) => {
    const whole = parent === "" || state.whole.has(parent);
    const drawn = whole ? addresses : addresses.slice(0, CALLEES_FIRST);
    const hidden = addresses.length - drawn.length;
    const setsize = drawn.length + (hidden > 0 ? 1 : 0);
    drawn.forEach((address, i) => {
      const key = parent ? `${parent}${PATH_SEP}${address}` : address;
      const fn = index.get(address);
      if (path.includes(address)) {
        rows.push({ kind: "back", key, level, setsize, posinset: i + 1, address, fn });
        return;
      }
      if (!fn) return;
      const open = state.open.has(key) && fn.calls.length > 0;
      rows.push({ kind: "function", key, level, setsize, posinset: i + 1, fn, callees: fn.calls.length, open });
      if (open) walk(fn.calls, level + 1, [...path, address], key);
    });
    if (hidden > 0) {
      rows.push({ kind: "more", key: `${parent}${PATH_SEP}+`, level, setsize, posinset: setsize, parent, hidden });
    }
  };
  walk(roots, 1, [], "");
  return rows;
}

/** The function a tree path ends on. */
export function pathParent(key: string): string {
  const at = key.lastIndexOf(PATH_SEP);
  return at < 0 ? "" : key.slice(0, at);
}

/** How a function is named in one line: its given names, else its address. */
export function functionLabel(fn: CallMapFunction): string {
  return fn.names.length > 0 ? fn.names.join(", ") : (fn.address ?? "");
}

export type ReadFilter = "all" | "read" | "named";

/**
 * The flat list narrowed by whether a function was read and by a search over
 * its address, offset and names (case folded; a leading `0x` optional).
 */
export function filterFunctions(
  functions: readonly CallMapFunction[],
  filter: ReadFilter,
  query: string,
): CallMapFunction[] {
  const q = query.trim().toLowerCase().replace(/^0x/, "");
  return functions.filter((fn) => {
    if (filter === "read" && !fn.read) return false;
    if (filter === "named" && fn.read) return false;
    if (!q) return true;
    const hay = [fn.address ?? "", fn.offset ?? "", ...fn.names].map((s) => s.toLowerCase().replace(/^0x/, ""));
    return hay.some((s) => s.includes(q));
  });
}

/** How many functions were read and how many only named. */
export function readCounts(functions: readonly CallMapFunction[]): { read: number; named: number } {
  const read = functions.filter((fn) => fn.read).length;
  return { read, named: functions.length - read };
}
