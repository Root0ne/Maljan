/**
 * The dashboard's "Tools used" list, as rows a flat bar can be drawn from.
 *
 * Its own module because it is the part with rules in it: how many rows are
 * worth drawing, how long each bar is and what a row says in words. The page
 * draws what this returns and decides nothing.
 */

import type { ToolUsageDTO } from "@/lib/api";
import { countLabel } from "@/lib/report-utils";

/** How many tools the list draws before it says how many more there are. */
export const TOOLS_SHOWN = 10;

/** The shortest bar drawn, in percent, so a tool called once is still seen. */
const MIN_WIDTH = 2;

export interface ToolBar {
  tool: string;
  calls: number;
  runs: number;
  /** The bar's length as a share of the busiest tool's, in percent. */
  width: number;
  /** The row in words, for a reader who cannot see the bar. */
  spoken: string;
}

export interface ToolBars {
  rows: ToolBar[];
  /** Tools past `TOOLS_SHOWN`, said as a count rather than dropped. */
  more: number;
  /** "12 completed runs", the runs the bars stand on: those that carry the
   *  per-tool record. */
  window: string;
  /** Runs read that carry no per-tool record, said rather than counted as
   *  runs that called nothing. Zero when every run read has one. */
  unrecorded: number;
}

/** The rows to draw, or null when there is nothing to draw at all. */
export function toolBars(usage: ToolUsageDTO | null | undefined): ToolBars | null {
  const tools = (usage?.tools ?? []).filter((row) => row.tool && row.calls > 0);
  if (tools.length === 0) return null;
  const busiest = Math.max(...tools.map((row) => row.calls));
  const runs = usage?.runs ?? 0;
  const rows = tools.slice(0, TOOLS_SHOWN).map((row) => ({
    tool: row.tool,
    calls: row.calls,
    runs: row.runs,
    width: Math.max(MIN_WIDTH, Math.round((row.calls / busiest) * 100)),
    spoken: `${row.tool}: ${countLabel(row.calls, "call")} in ${row.runs} of ${countLabel(runs, "run")}`,
  }));
  return {
    rows,
    more: tools.length - rows.length,
    window: countLabel(runs, "completed run"),
    unrecorded: Math.max(0, (usage?.read ?? runs) - runs),
  };
}
