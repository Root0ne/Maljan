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

/** The manifest's code for a setting the operator left unset. */
const NOT_CONFIGURED = "not_configured";

function notConfigured(tool: UnavailableToolDTO): boolean {
  return tool.manifest_code === NOT_CONFIGURED;
}

/** One tool as a line: `capa on analysis: <reason>. <remedy>`, with what it
 *  still answers when it answers something. A setting left unset is said to
 *  be not configured, the operator's to set, not a fault to fix. */
function toolLine(tool: UnavailableToolDTO): string {
  const still = tool.still_answers ? ` It still answers ${tool.still_answers}.` : "";
  if (notConfigured(tool)) {
    const set = tool.remediation ? ` To use it: ${tool.remediation}.` : "";
    return `${tool.tool} on ${tool.server} is not configured: ${tool.reason}.${still}${set}`;
  }
  const remedy = tool.remediation ? ` To fix: ${tool.remediation}.` : "";
  return `${tool.tool} on ${tool.server}: ${tool.reason}.${still}${remedy}`;
}

/** What a run does without the tools: a missing tool degrades it, a setting
 *  left unset is listed as not configured and degrades nothing. */
function runDetail(tools: readonly UnavailableToolDTO[]): string {
  const unset = tools.filter(notConfigured).length;
  const missing = tools.length - unset;
  const parts: string[] = [];
  if (missing > 0) {
    parts.push(
      `the host that runs its server cannot run ${missing > 1 ? `${missing} of them` : "one"}, ` +
        "and a run reports itself as degraded where it went on without them",
    );
  }
  if (unset > 0) {
    parts.push(
      `${unset > 1 ? `${unset} are` : "one is"} not configured, which a run lists as ` +
        "not configured and does not count as degrading it",
    );
  }
  return (
    `A run of the default team would call ${tools.length > 1 ? "these tools" : "this tool"}: ` +
    `${parts.join("; ")}. The run is still accepted.`
  );
}

/** The notice for the unavailable tools `/system/status` listed; none when
 *  it listed none or did not carry the field. */
export function unavailableToolsNotice(
  tools: readonly UnavailableToolDTO[] | null | undefined,
): UnavailableToolsNotice | null {
  if (!tools || tools.length === 0) return null;
  const many = tools.length > 1;
  const allUnset = tools.every(notConfigured);
  return {
    label: allUnset
      ? many
        ? `${tools.length} tools not configured`
        : "Tool not configured"
      : many
        ? `${tools.length} tools unavailable`
        : "Tool unavailable",
    detail: runDetail(tools),
    lines: tools.map(toolLine),
  };
}
