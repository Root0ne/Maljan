/**
 * The guide's own scratch, handed to every step component.
 *
 * A guide makes choices no catalog key holds — which server it is building,
 * which agent it just cloned, whether that agent resolved — and the steps
 * after the one that made the choice need to read it. `state` is that object;
 * `setState` merges a patch into it and re-renders the guide, so a step's
 * `canContinue` sees the value the step body just stored.
 */
export interface GuideStepProps {
  state: Record<string, unknown>;
  setState: (patch: Record<string, unknown>) => void;
}

/** A string the guide stored under `field`, or null when it stored nothing
 *  usable there yet. */
export function stateString(
  state: Record<string, unknown>,
  field: string
): string | null {
  const value = state[field];
  return typeof value === "string" && value !== "" ? value : null;
}
