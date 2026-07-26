import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* Enable standalone output for Docker deployment */
  output: "standalone",

  /* There is deliberately no `/api/:path*` rewrite proxy here.
   *
   * One existed and was unreachable: every request goes through `ApiClient`,
   * which builds an absolute URL from `NEXT_PUBLIC_API_URL` (lib/api.ts), so
   * nothing in `src/` has ever fetched a relative `/api/…` path for the proxy
   * to catch. The 2026-07-26 audit flagged it for removal on those grounds.
   *
   * Re-adding it would now be actively harmful: the E2E suite points
   * NEXT_PUBLIC_API_URL at the Next server's own origin so the mocked API is
   * same-origin (see playwright.config.ts), and a rewrite whose destination is
   * derived from that same variable would proxy the server to itself. Without
   * it an unmocked call is a clean 404 instead of a loop.
   */
};

export default nextConfig;
