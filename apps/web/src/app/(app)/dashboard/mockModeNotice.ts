/**
 * Whether the dashboard warns about mock mode, and in which words.
 *
 * The red MOCK MODE ALLOWED banner was drawn from the system status, and the
 * status call is best-effort: when it failed the banner simply was not drawn,
 * which reads exactly like "mock mode is off". An unread status is not a
 * clean one, so it gets a banner of its own that says the gate could not be
 * checked.
 */

export type MockModeNotice = { kind: "allowed" } | { kind: "unknown"; reason: string } | null;

export function mockModeNotice(
  status: { mock_mode_allowed?: boolean | null } | null,
  statusError: string | null,
): MockModeNotice {
  if (status?.mock_mode_allowed) return { kind: "allowed" };
  if (status) return null;
  if (statusError !== null) return { kind: "unknown", reason: statusError };
  return null;
}
