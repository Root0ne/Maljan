export type KeyState = "active" | "expired" | "revoked";

/**
 * What a key can do now. A key past `expires_at` is refused by the API even
 * though `is_active` is still true, so it is not shown as Active. A revoked
 * key stays revoked whatever its expiry. An unreadable expiry is not treated
 * as expired.
 */
export function apiKeyState(
  key: { is_active: boolean; expires_at: string | null },
  now: number = Date.now(),
): KeyState {
  if (!key.is_active) return "revoked";
  if (key.expires_at) {
    const at = Date.parse(key.expires_at);
    if (!Number.isNaN(at) && at <= now) return "expired";
  }
  return "active";
}

/** The last-use line: a key never used says so rather than showing nothing. */
export function lastUsedText(lastUsedAt: string | null, format: (iso: string) => string): string {
  return lastUsedAt ? `Last used ${format(lastUsedAt)}` : "Never used";
}
