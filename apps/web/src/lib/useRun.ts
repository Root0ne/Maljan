"use client";

/* The React side of the run store.
 *
 * `useSyncExternalStore` is the whole adapter: the store already publishes an
 * immutable snapshot on every change, so a component re-renders when its run
 * changes and never when another run does. Subscribing is also what keeps the
 * socket open, so a page that reads a run is by definition a page that holds
 * its feed.
 */

import { useCallback, useSyncExternalStore } from "react";

import { getRun, subscribeRun, type RunState } from "@/lib/runStore";

export function useRun(jobId: string | null): RunState {
  const subscribe = useCallback(
    (listener: () => void) => {
      if (!jobId) return () => {};
      return subscribeRun(jobId, listener);
    },
    [jobId],
  );
  const snapshot = useCallback(() => getRun(jobId), [jobId]);
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}
