import { ApiError } from "@/lib/errors";

export interface RefreshedToken {
  access_token: string;
  token_type: string;
}

/**
 * `POST /auth/refresh`, without touching the stored access token.
 *
 * A 401 throws `ApiError("Unauthorized", 401)`, the error every session check
 * in the console recognises, and leaves localStorage as it was: when another
 * tab won the rotation, the token in storage is the winner's, and clearing it
 * would sign every tab out.
 */
export async function refreshAccessToken(
  baseUrl: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<RefreshedToken> {
  const res = await fetchImpl(`${baseUrl}/api/v1/auth/refresh`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    signal,
  });
  if (res.status === 401) throw new ApiError("Unauthorized", res.status);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(body.detail || `Request failed: ${res.status}`, res.status);
  }
  return res.json();
}
