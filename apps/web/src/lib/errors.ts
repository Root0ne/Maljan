/**
 * Wave 10 W10-LINT-DEBT-01 (2026-05-30): typed narrowing helper for the
 * ``catch (err) { ... err.message ... }`` pattern that the ESLint v9
 * migration (W10-LINT-07) exposed across the app router pages.
 *
 * Previously the pages used ``catch (err: any)`` which silently
 * permitted every property access. Switching to the implicit
 * ``unknown`` catch type forces an instanceof / typeof gate before
 * reading ``.message``. This helper centralises the gate so every
 * call site reads the same way.
 */

/**
 * An HTTP response the API answered with, carrying its status.
 *
 * The client used to throw a bare `Error` for every failure, so a clean 404
 * and an unreachable backend arrived at the caller as the same thing: the
 * analysis page read "the job could not be fetched" as an outage and told the
 * operator to check that the backend was running, on a request the backend had
 * answered. `message` is unchanged — the server's `detail`, or "Unauthorized"
 * for a rejected credential, which `auth.tsx::isSessionRejection` matches on.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** A response the API answered with, for `status` — not a transport failure. */
export function isApiStatus(e: unknown, status: number): boolean {
  return e instanceof ApiError && e.status === status;
}

/**
 * The request never reached an answer: DNS, TLS, a refused connection, an
 * aborted fetch. `fetch` rejects with a `TypeError` for all of them, which is
 * the only way to tell "the server said no" from "there was no server".
 */
export function isNetworkFailure(e: unknown): boolean {
  return e instanceof TypeError;
}

export function getErrorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (typeof e === "object" && e !== null) {
    const maybe = (e as { message?: unknown }).message;
    if (typeof maybe === "string") return maybe;
  }
  return "Unknown error";
}
