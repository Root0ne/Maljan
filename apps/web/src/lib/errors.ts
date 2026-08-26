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

export function getErrorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (typeof e === "object" && e !== null) {
    const maybe = (e as { message?: unknown }).message;
    if (typeof maybe === "string") return maybe;
  }
  return "Unknown error";
}
