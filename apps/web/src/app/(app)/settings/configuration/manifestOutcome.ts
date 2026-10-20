import { probeDetail } from "@/lib/probeDetail";
import type { ProbeResult } from "@/types/settings";

/**
 * What a "List tools" probe established: the tools, or why it could not say.
 * A probe that failed, or answered with no manifest at all, is a failure to
 * list, never "this server reported no tools"; only an answered, empty
 * manifest is that.
 */
export function manifestOutcome(result: ProbeResult): { tools: string[] } | { error: string } {
  if (!result.ok) return { error: probeDetail(result.detail) };
  if (result.tools === null || result.tools === undefined) {
    return { error: "the server answered without a tool manifest" };
  }
  return { tools: result.tools };
}
