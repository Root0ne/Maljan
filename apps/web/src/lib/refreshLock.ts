/**
 * One holder at a time for anything that rotates the session's tokens.
 *
 * The backend rotates the refresh cookie on every use. A second use of a
 * rotated token by another client, or by any client after the server's grace
 * window, is treated as theft: every session of the account is revoked. Two
 * tabs refreshing at once, or a refresh racing a password change, must
 * therefore never both reach the server with the same cookie. With Web Locks
 * the browser serialises them (`navigator.locks`); without them (a plain-HTTP
 * LAN deployment is not a secure context, so `navigator.locks` is absent
 * there) a lease in localStorage does the same across the tabs of one origin.
 */

export const REFRESH_LOCK_NAME = "maljan-token-refresh";
const LEASE_KEY = `${REFRESH_LOCK_NAME}-lease`;

/**
 * How long a lease holds. The work under it is aborted when the lease ends,
 * so a lease never outlives its request and a dead tab holds the others up
 * for at most this long.
 *
 * Coupled to the server. A refresh aborted (or lost) at the lease's end may
 * still have rotated the cookie on the server; the console then retries once
 * at once, acquiring a fresh lease within `TRANSPORT_RETRY_ACQUIRE_MS`, so
 * the old cookie, if the browser never received the successor, reaches the
 * server again at most `LEASE_MS + TRANSPORT_RETRY_ACQUIRE_MS + LEASE_POLL_MS`
 * plus the network's own latency after the rotation: inside the grace
 * window, from the same client, refused without anything being revoked. The
 * work is aborted at the lease's end on both paths, Web Locks included. The
 * API mirrors these values as `CONSOLE_REFRESH_LEASE_SECONDS`,
 * `CONSOLE_REFRESH_RETRY_SECONDS` and `CONSOLE_REFRESH_POLL_SECONDS`, adds
 * `CONSOLE_REFRESH_LATENCY_MARGIN_SECONDS` for the network, and refuses any
 * `refresh_reuse_grace_seconds` between 0 (off) and that sum rounded up
 * (`settings_catalog_api`); a test pins the two sides together.
 */
export const LEASE_MS = 7_000;
/** How long the one prompt retry after a failed transport may wait for its
 *  lease; past it, the retry gives way to the normal schedule. */
export const TRANSPORT_RETRY_ACQUIRE_MS = 1_000;

/** The lock could not be had within the caller's acquire budget. */
export class RefreshLockBusy extends Error {
  constructor() {
    super("refresh lock busy");
    this.name = "RefreshLockBusy";
  }
}
/** How often a waiting tab looks at the lease again. */
export const LEASE_POLL_MS = 50;
/**
 * How long a refused refresh waits for another tab's new token before it is
 * read as a rejected session. A winner stores its token as soon as its own
 * response arrives, which is a round trip, not seconds.
 */
export const REFRESH_RACE_WAIT_MS = 2_000;

export interface LeaseStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface LockEnv {
  locks?: {
    request<T>(name: string, options: { signal?: AbortSignal }, fn: () => Promise<T>): Promise<T>;
  };
  storage?: LeaseStorage;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  owner?: string;
}

/** The work run under the lock; abort `signal` ends it when the lease ends. */
export type LockedWork<T> = (signal?: AbortSignal) => Promise<T>;

interface Lease {
  owner: string;
  until: number;
}

function readLease(storage: LeaseStorage): Lease | null {
  try {
    const raw = storage.getItem(LEASE_KEY);
    if (!raw) return null;
    const lease = JSON.parse(raw) as Partial<Lease>;
    return typeof lease.owner === "string" && typeof lease.until === "number"
      ? { owner: lease.owner, until: lease.until }
      : null;
  } catch {
    return null;
  }
}

function browserStorage(): LeaseStorage | undefined {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
}

function defaultEnv(): LockEnv {
  const nav = globalThis.navigator as (Navigator & { locks?: LockEnv["locks"] }) | undefined;
  return { locks: nav?.locks, storage: browserStorage() };
}

const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Run `work` while holding the session-rotation lock.
 *
 * Web Locks when the browser has them (the browser releases the lock if the
 * tab dies). Otherwise a localStorage lease: write a lease naming this
 * caller, wait one poll, and proceed only if the lease still names it (of two
 * tabs that wrote at the same moment exactly one reads its own name back);
 * the work is handed an AbortSignal that fires when the lease ends. With
 * neither (no storage at all) `work` simply runs: there is no other tab.
 *
 * `acquireWithinMs` bounds the wait for the lock: past it, `RefreshLockBusy`
 * is thrown and `work` never runs.
 */
export async function withRefreshLock<T>(
  work: LockedWork<T>,
  env: LockEnv = defaultEnv(),
  acquireWithinMs?: number,
): Promise<T> {
  const setTimer = env.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
  const clearTimer = env.clearTimer ?? ((h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>));
  // The work is cut off where a lease would end on either path, so a lost
  // answer surfaces in time for the prompt retry to land inside the server's
  // grace window, not after a transport timeout.
  const bounded = async (): Promise<T> => {
    const controller = new AbortController();
    const timer = setTimer(() => controller.abort(), LEASE_MS - LEASE_POLL_MS);
    try {
      return await work(controller.signal);
    } finally {
      clearTimer(timer);
    }
  };

  if (env.locks) {
    if (acquireWithinMs === undefined) return env.locks.request(REFRESH_LOCK_NAME, {}, bounded);
    let granted = false;
    try {
      return await env.locks.request(
        REFRESH_LOCK_NAME,
        { signal: AbortSignal.timeout(acquireWithinMs) },
        () => {
          granted = true;
          return bounded();
        },
      );
    } catch (err) {
      // The signal only ends the wait for the lock, never granted work.
      if (!granted) throw new RefreshLockBusy();
      throw err;
    }
  }
  const storage = env.storage;
  if (!storage) return work();
  const now = env.now ?? Date.now;
  const sleep = env.sleep ?? realSleep;
  const owner = env.owner ?? `${now()}-${Math.random().toString(36).slice(2)}`;
  const startedAt = now();

  for (;;) {
    if (acquireWithinMs !== undefined && now() - startedAt > acquireWithinMs) {
      throw new RefreshLockBusy();
    }
    const held = readLease(storage);
    if (!held || held.until <= now()) {
      try {
        storage.setItem(LEASE_KEY, JSON.stringify({ owner, until: now() + LEASE_MS }));
      } catch {
        return work(); // storage refuses writes: nothing to coordinate through
      }
      await sleep(LEASE_POLL_MS);
      if (readLease(storage)?.owner === owner) break;
      continue;
    }
    await sleep(LEASE_POLL_MS);
  }

  // The lease was written for LEASE_MS from before the confirming poll; the
  // work is cut off where the lease ends, never after it.
  try {
    return await bounded();
  } finally {
    if (readLease(storage)?.owner === owner) {
      try {
        storage.removeItem(LEASE_KEY);
      } catch {
        // The lease expires on its own.
      }
    }
  }
}

/**
 * Wait up to `REFRESH_RACE_WAIT_MS` for the stored access token to differ from
 * `stale`, looking again every poll (another tab's write is visible to
 * `getItem` at once); resolve with the new token, or `null` if none came.
 */
export async function waitForNewToken(
  stale: string,
  env: { storage?: LeaseStorage; sleep?: (ms: number) => Promise<void> } = {
    storage: browserStorage(),
  },
): Promise<string | null> {
  const storage = env.storage;
  if (!storage) return null;
  const sleep = env.sleep ?? realSleep;
  const read = () => {
    try {
      const current = storage.getItem("access_token");
      return current && current !== stale ? current : null;
    } catch {
      return null;
    }
  };
  for (let waited = 0; waited <= REFRESH_RACE_WAIT_MS; waited += LEASE_POLL_MS) {
    const fresh = read();
    if (fresh) return fresh;
    await sleep(LEASE_POLL_MS);
  }
  return read();
}

/**
 * Run one refresh `attempt` under the lock and, if it failed in transport
 * (aborted at the lease's end, the network dropped: `isTransportFailure`),
 * run it once more at once under a fresh lease acquired within
 * `TRANSPORT_RETRY_ACQUIRE_MS`.
 *
 * The failed attempt may have rotated the cookie on the server with the
 * successor never reaching the browser. The normal schedule retries no
 * sooner than its floor, which can land past the server's grace window and
 * turn the old cookie into a replay that revokes every session; the prompt
 * retry lands inside it (see `LEASE_MS`). `attempt` answers its own error,
 * or a falsy value when it succeeded; the final error, if any, is returned.
 */
export async function refreshWithPromptRetry(
  attempt: LockedWork<unknown>,
  isTransportFailure: (error: unknown) => boolean,
  env?: LockEnv,
): Promise<unknown> {
  const first = await withRefreshLock(attempt, env);
  if (!first || !isTransportFailure(first)) return first;
  try {
    return await withRefreshLock(attempt, env, TRANSPORT_RETRY_ACQUIRE_MS);
  } catch (err) {
    if (err instanceof RefreshLockBusy) return first; // the normal schedule takes over
    throw err;
  }
}
