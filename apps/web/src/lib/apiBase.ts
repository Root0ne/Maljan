const LOOPBACK = "http://127.0.0.1:8000";

/**
 * The API origin. When `NEXT_PUBLIC_API_URL` is unset the console falls back
 * to the loopback address, which is right for a developer machine and wrong
 * anywhere else; `fellBack` lets the caller say so instead of failing silently.
 */
export function resolveApiBase(configured: string | undefined): { base: string; fellBack: boolean } {
  if (configured) return { base: configured, fellBack: false };
  return { base: LOOPBACK, fellBack: true };
}

const resolved = resolveApiBase(process.env.NEXT_PUBLIC_API_URL);

if (resolved.fellBack && process.env.NODE_ENV === "production" && typeof window !== "undefined") {
  console.warn(
    `NEXT_PUBLIC_API_URL is not set; API requests go to ${resolved.base}. ` +
      "Set it at build time if the API is not on this machine.",
  );
}

export const API_BASE: string = resolved.base;
