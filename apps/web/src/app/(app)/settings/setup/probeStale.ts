/**
 * Whether a finished probe result still describes what pressing the button
 * again would do.
 *
 * The console asks a boolean question — "is anything this probe reads
 * staged?" — which is enough there because a result and its inputs sit side
 * by side. In a guide the credentials step comes *before* the test step and
 * `core.llm.provider` itself carries `probe: "llm"`, so that boolean is
 * already true when the probe runs and can never flip: a green result would
 * survive going Back and typing a different API key. Comparing the staged
 * values themselves is the only rule that catches that.
 *
 * The fingerprint is an in-memory string only: it is compared, never
 * rendered, logged or sent — a staged secret appears in it verbatim.
 */
export function probeFingerprint(values: Record<string, unknown>): string {
  // Key order must not matter: `probeValues` walks the catalog, but a staged
  // map's own insertion order is whatever the operator typed first.
  const sorted = Object.keys(values)
    .sort()
    .map((key) => [key, values[key]] as const);
  return JSON.stringify(sorted);
}

/** True when the inputs moved since the recorded run. */
export function isProbeStale(recorded: string, current: string): boolean {
  return recorded !== current;
}
