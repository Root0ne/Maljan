/**
 * Renew the access token after the API refused it, once per tab at a time.
 *
 * The refresh cookie was only ever spent by the timer `auth.tsx` arms from the
 * token's expiry. A tab reopened after the token expired, or woken after the
 * laptop slept through the timer, sent the expired token, got a 401, and the
 * client cleared the token and went to /login — with a refresh cookie that
 * would have answered. A 401 on a request that carried a token now asks for a
 * new one first (`ApiClient`), and the live feed does the same when the
 * server closes it over the credential (`runStore`).
 *
 * Single-flight: every caller that arrives while a renewal is running shares
 * it, so ten requests refused together cost one refresh. Across tabs the
 * renewal runs under the same lock as the timer's refresh
 * (`refreshWithPromptRetry`), and inside it the stored token is read again: a
 * tab that queued behind another tab's rotation adopts the token that tab
 * stored instead of spending a cookie that has already been rotated. A refusal
 * waits briefly for another tab's token (`waitForNewToken`) before it is read
 * as a rejected session, which is what `auth.tsx` does for the same race.
 */

import { ApiError } from "./errors";
import type { RefreshedToken } from "./refreshRequest";
import {
  refreshWithPromptRetry,
  waitForNewToken,
  type LeaseStorage,
  type LockEnv,
} from "./refreshLock";

/** What a renewal established. */
export type Renewal =
  /** A token other than the refused one is now stored. */
  | { kind: "renewed"; token: string }
  /** The server refused the refresh cookie: the session is over. */
  | { kind: "rejected" }
  /** The refresh never got an answer, so nothing is known about the session. */
  | { kind: "unreachable"; error: unknown };

export interface RenewalDeps {
  refresh: (signal?: AbortSignal) => Promise<RefreshedToken>;
  storage?: LeaseStorage;
  lockEnv?: LockEnv;
  sleep?: (ms: number) => Promise<void>;
}

function browserStorage(): LeaseStorage | undefined {
  try {
    return globalThis.localStorage ?? undefined;
  } catch {
    return undefined;
  }
}

function read(storage: LeaseStorage | undefined): string | null {
  try {
    return storage?.getItem("access_token") ?? null;
  } catch {
    return null;
  }
}

let inFlight: Promise<Renewal> | null = null;

/* Bumped on every sign-out. A renewal that started before a sign-out and
 * answers after it must not write its token back: that would sign the tab in
 * again behind the reader's back. */
let signOutGeneration = 0;

/** The current sign-out generation, for a refresh outside this module to check. */
export function currentSignOutGeneration(): number {
  return signOutGeneration;
}

/** Record a sign-out: renewals already running finish without storing anything. */
export function noteSignOut(): void {
  signOutGeneration += 1;
  inFlight = null;
}

async function renew(refused: string | null, deps: RenewalDeps): Promise<Renewal> {
  const storage = deps.storage ?? browserStorage();
  const generation = signOutGeneration;
  const signedOutSince = () => generation !== signOutGeneration;
  // Another request, the timer or another tab has already replaced it.
  const before = read(storage);
  if (before && before !== refused) return { kind: "renewed", token: before };

  let token: string | null = null;
  const failed = await refreshWithPromptRetry(
    async (signal) => {
      const current = read(storage);
      if (current && current !== refused) {
        token = current;
        return null;
      }
      try {
        const answer = await deps.refresh(signal);
        if (signedOutSince()) return null;
        try {
          storage?.setItem("access_token", answer.access_token);
        } catch {
          // A storage that refuses writes still lets this tab carry on.
        }
        token = answer.access_token;
        return null;
      } catch (error) {
        return error;
      }
    },
    (error) => !(error instanceof ApiError),
    deps.lockEnv,
  );
  if (signedOutSince()) return { kind: "rejected" };
  if (token) return { kind: "renewed", token };
  if (failed instanceof ApiError && failed.status === 401) {
    const fresh = refused
      ? await waitForNewToken(refused, { storage, sleep: deps.sleep })
      : null;
    return fresh ? { kind: "renewed", token: fresh } : { kind: "rejected" };
  }
  // A 500, a timeout, a dropped connection: no answer about the session.
  return { kind: "unreachable", error: failed };
}

/**
 * Renew after `refused` was turned down; callers arriving while one renewal
 * runs share its answer.
 */
export function renewSession(refused: string | null, deps: RenewalDeps): Promise<Renewal> {
  if (!inFlight) {
    inFlight = renew(refused, deps).finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}
