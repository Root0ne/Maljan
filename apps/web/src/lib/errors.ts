/**
 * Typed narrowing helper for the
 * ``catch (err) { ... err.message ... }`` pattern that the ESLint v9
 * migration exposed across the app router pages.
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
    /** How long the server asked the client to wait (`Retry-After`), when it did. */
    readonly retryAfterMs: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * A `Retry-After` header in milliseconds: delay-seconds or an HTTP date.
 * `null` when absent or unreadable.
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | null {
  const text = (value ?? "").trim();
  if (!text) return null;
  if (/^\d+$/.test(text)) return Number(text) * 1000;
  const at = Date.parse(text);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
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
