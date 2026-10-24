/**
 * Whether the dashboard has to say that a tool the team would call is missing.
 *
 * A run whose analysis server had lost capa was accepted, paid for, and said
 * DEGRADED RUN afterwards. `/system/status` now names every tool the stored
 * team would call that the host running its server cannot run, each with the
 * server's own reason and the remedy, so the console says it before anyone
 * submits. A job is still accepted without the tool: this is a warning, and
 * each line is what the operator runs to clear it.
 */

import type { UnavailableToolDTO } from "@/lib/api";

export interface UnavailableToolsNotice {
  /** The few words a reader scanning the page stops on. */
  label: string;
  /** What a run would do without them. */
  detail: string;
  /** One line per tool: where, why, and what to run. */
  lines: string[];
}

/** One tool as a line: `capa on analysis: <reason>. <remedy>`, with what it
 *  still answers when it answers something. */
function toolLine(tool: UnavailableToolDTO): string {
  const still = tool.still_answers ? ` It still answers ${tool.still_answers}.` : "";
  const remedy = tool.remediation ? ` To fix: ${tool.remediation}.` : "";
  return `${tool.tool} on ${tool.server}: ${tool.reason}.${still}${remedy}`;
}

/** The notice for the unavailable tools `/system/status` listed; none when
 *  it listed none or did not carry the field. */
export function unavailableToolsNotice(
  tools: readonly UnavailableToolDTO[] | null | undefined,
): UnavailableToolsNotice | null {
  if (!tools || tools.length === 0) return null;
  const many = tools.length > 1;
  return {
    label: many ? `${tools.length} tools unavailable` : "Tool unavailable",
    detail:
      `A run of the default team would call ${many ? "these tools" : "this tool"}, and the ` +
      "host that runs its server cannot. The run is still accepted, and reports itself as " +
      "degraded where it went on without them.",
    lines: tools.map(toolLine),
  };
}
