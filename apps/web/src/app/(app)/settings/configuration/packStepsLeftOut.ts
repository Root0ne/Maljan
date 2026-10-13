/** The catalog key of the triage pack's stored steps, named once so the row
 *  and the mark beside it agree. */
export const PACK_STEPS_KEY = "core.triage.steps";

/** One stored step the API leaves out, and why. */
export interface LeftOutStep {
  /** The step's id, else `#<position>` in the stored list. */
  step: string;
  reason: string;
}

/**
 * The stored pack steps the API leaves out, in the order it serves them
 * (`SchemaResponse.pack_steps_left_out`).
 *
 * Whatever left a step out (a step this release cannot run, a reset of the
 * server it calls, a shipped declaration that changed its tool's kind), it
 * does not run, and the shipped step it changed, if any, runs instead. A
 * reason that is not text is not invented: the step is still listed.
 */
export function leftOutSteps(served: Record<string, unknown> | undefined | null): LeftOutStep[] {
  if (!served || typeof served !== "object" || Array.isArray(served)) return [];
  return Object.entries(served).map(([step, reason]) => ({
    step,
    reason: typeof reason === "string" ? reason : "",
  }));
}

/** What the mark beside the steps says above the list of steps left out. */
export const LEFT_OUT_HEADLINE =
  "These stored steps cannot run, so they are left out; the shipped step each one changed, " +
  "if any, runs instead. Edit or remove them to clear this mark.";
