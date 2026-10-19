import { describe, expect, it, vi } from "vitest";
import {
  LEASE_MS,
  LEASE_POLL_MS,
  REFRESH_LOCK_NAME,
  REFRESH_RACE_WAIT_MS,
  RefreshLockBusy,
  TRANSPORT_RETRY_ACQUIRE_MS,
  refreshWithPromptRetry,
  waitForNewToken,
  withRefreshLock,
  type LeaseStorage,
  type LockEnv,
} from "@/lib/refreshLock";

class MemoryStorage implements LeaseStorage {
  values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
}

/** A clock that only moves when a waiter sleeps, so the test is deterministic. */
function env(storage: LeaseStorage, owner: string, clock: { t: number }): LockEnv {
  return {
    storage,
    owner,
    now: () => clock.t,
    sleep: async (ms) => {
      clock.t += ms;
      await new Promise((resolve) => setTimeout(resolve, 0));
    },
  };
}

describe("withRefreshLock without Web Locks", () => {
  it("runs two tabs' refreshes one after the other, never together", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    const events: string[] = [];
    let inside = 0;
    const refresh = (tab: string) => async () => {
      inside += 1;
      expect(inside).toBe(1);
      events.push(`${tab} start`);
      await new Promise((resolve) => setTimeout(resolve, 5));
      events.push(`${tab} end`);
      inside -= 1;
      return tab;
    };

    const results = await Promise.all([
      withRefreshLock(refresh("a"), env(storage, "a", clock)),
      withRefreshLock(refresh("b"), env(storage, "b", clock)),
    ]);

    expect(results.sort()).toEqual(["a", "b"]);
    expect(events).toHaveLength(4);
    expect(events[0].split(" ")[0]).toBe(events[1].split(" ")[0]);
    expect(events[1].endsWith("end")).toBe(true);
    // The lease is released once both are done.
    expect(storage.values.size).toBe(0);
  });

  it("takes over a lease its dead holder left behind once it expires", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    storage.setItem(
      `${REFRESH_LOCK_NAME}-lease`,
      JSON.stringify({ owner: "crashed", until: clock.t + LEASE_MS }),
    );

    const result = await withRefreshLock(async () => "ran", env(storage, "me", clock));

    expect(result).toBe("ran");
    expect(clock.t).toBeGreaterThanOrEqual(1_000 + LEASE_MS);
  });

  it("releases the lease when the refresh fails", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    await expect(
      withRefreshLock(async () => {
        throw new Error("401");
      }, env(storage, "me", clock)),
    ).rejects.toThrow("401");
    expect(storage.values.size).toBe(0);
  });
});

describe("withRefreshLock with Web Locks", () => {
  it("hands the work to the browser's lock under the shared name", async () => {
    const names: string[] = [];
    const locks = {
      request: async <T,>(name: string, _options: { signal?: AbortSignal }, fn: () => Promise<T>) => {
        names.push(name);
        return fn();
      },
    };
    expect(await withRefreshLock(async () => 7, { locks })).toBe(7);
    expect(names).toEqual([REFRESH_LOCK_NAME]);
  });

  it("aborts granted work where a lease would end (navigator.locks stubbed)", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("navigator", {
      locks: {
        request: async <T,>(_name: string, _options: unknown, fn: () => Promise<T>) => fn(),
      },
    });
    try {
      let seen: AbortSignal | undefined;
      const outcome = withRefreshLock(
        (signal) =>
          new Promise<string>((_resolve, reject) => {
            seen = signal;
            signal?.addEventListener("abort", () => reject(new Error("aborted")));
          }),
      );
      const settled = expect(outcome).rejects.toThrow("aborted");
      await vi.advanceTimersByTimeAsync(LEASE_MS - LEASE_POLL_MS - 1);
      expect(seen?.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await settled;
      expect(seen?.aborted).toBe(true);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });
});

describe("the lease never outlives its work", () => {
  it("aborts the work when the lease ends", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    let fire: (() => void) | null = null;
    let firesAfter = 0;
    let cleared = false;
    const lockEnv: LockEnv = {
      ...env(storage, "me", clock),
      setTimer: (fn, ms) => {
        fire = fn;
        firesAfter = ms;
        return "timer";
      },
      clearTimer: () => {
        cleared = true;
      },
    };

    const outcome = withRefreshLock(
      (signal) =>
        // A request that never answers on its own: only the abort ends it.
        new Promise<string>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(new Error("aborted")));
          setTimeout(() => (fire as (() => void) | null)?.(), 0); // the lease runs out
        }),
      lockEnv,
    );

    await expect(outcome).rejects.toThrow("aborted");
    expect(firesAfter).toBeLessThanOrEqual(LEASE_MS);
    expect(cleared).toBe(true);
    expect(storage.values.size).toBe(0);
  });
});

describe("waitForNewToken", () => {
  it("adopts a token another tab stores while it waits", async () => {
    const storage = new MemoryStorage();
    storage.setItem("access_token", "stale");
    let polls = 0;
    const fresh = await waitForNewToken("stale", {
      storage,
      sleep: async () => {
        polls += 1;
        if (polls === 3) storage.setItem("access_token", "winner");
      },
    });
    expect(fresh).toBe("winner");
  });

  it("gives up after the race window when nothing changes", async () => {
    const storage = new MemoryStorage();
    storage.setItem("access_token", "stale");
    let slept = 0;
    const fresh = await waitForNewToken("stale", {
      storage,
      sleep: async (ms) => {
        slept += ms;
      },
    });
    expect(fresh).toBeNull();
    expect(slept).toBeGreaterThanOrEqual(REFRESH_RACE_WAIT_MS);
  });
});

describe("the prompt retry after a failed transport", () => {
  const transport = (e: unknown) => e instanceof TypeError;

  it("gives up waiting for a busy lease within the retry budget", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    storage.setItem(
      `${REFRESH_LOCK_NAME}-lease`,
      JSON.stringify({ owner: "other-tab", until: clock.t + LEASE_MS }),
    );
    let ran = false;
    await expect(
      withRefreshLock(
        async () => {
          ran = true;
        },
        env(storage, "me", clock),
        TRANSPORT_RETRY_ACQUIRE_MS,
      ),
    ).rejects.toBeInstanceOf(RefreshLockBusy);
    expect(ran).toBe(false);
    expect(clock.t - 1_000).toBeLessThanOrEqual(TRANSPORT_RETRY_ACQUIRE_MS + 50);
  });

  it("retries a transport failure once, at once, under a fresh lease", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    const outcomes: unknown[] = [new TypeError("network"), null];
    let calls = 0;
    const result = await refreshWithPromptRetry(
      async () => {
        calls += 1;
        return outcomes.shift();
      },
      transport,
      env(storage, "me", clock),
    );
    expect(result).toBeNull();
    expect(calls).toBe(2);
    // Out within the retry budget of the first attempt's end, not on the
    // normal schedule's multi-second floor.
    expect(clock.t - 1_000).toBeLessThan(TRANSPORT_RETRY_ACQUIRE_MS);
  });

  it("does not retry an answer from the API", async () => {
    const storage = new MemoryStorage();
    const refused = new Error("Unauthorized");
    let calls = 0;
    const result = await refreshWithPromptRetry(
      async () => {
        calls += 1;
        return refused;
      },
      transport,
      env(storage, "me", { t: 1_000 }),
    );
    expect(result).toBe(refused);
    expect(calls).toBe(1);
  });

  it("hands back the first failure when the retry cannot get the lock in time", async () => {
    const storage = new MemoryStorage();
    const clock = { t: 1_000 };
    const first = new TypeError("network");
    let calls = 0;
    const takeLease = () =>
      storage.setItem(
        `${REFRESH_LOCK_NAME}-lease`,
        JSON.stringify({ owner: "other-tab", until: clock.t + LEASE_MS }),
      );
    const result = await refreshWithPromptRetry(
      async () => {
        calls += 1;
        // Another tab takes the lease as this attempt ends.
        setTimeout(takeLease, 0);
        return first;
      },
      transport,
      env(storage, "me", clock),
    );
    expect(result).toBe(first);
    expect(calls).toBe(1);
  });
});
