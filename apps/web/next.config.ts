import type { NextConfig } from "next";

/* The routes that moved, and where they moved to.
 *
 * Twelve analysis tabs became five, and `/reports` became a filter on the one
 * list of runs. Each retired route used to be a client component that mounted,
 * read its params and called `router.replace` — nine files whose only job was
 * to draw "Redirecting…" for one frame. The server answers now, before the
 * bundle is fetched, so a bookmark or a link in an already-issued report lands
 * on the tab that answers what it asked without loading a page that has
 * nothing to draw.
 *
 * Permanent, because these are not coming back: a 308 is cached by the client
 * and tells a crawler the same thing.
 */
const MOVED: Array<[string, string]> = [
  // The run is one conversation now, live and replayed by the same view.
  ["/analysis/:id/live", "/analysis/:id/conversation"],
  ["/analysis/:id/process", "/analysis/:id/conversation"],
  ["/analysis/:id/agents", "/analysis/:id/conversation"],
  ["/analysis/:id/pipeline", "/analysis/:id/conversation"],
  ["/analysis/:id/timeline", "/analysis/:id/conversation"],
  // ATT&CK absorbed the separate technique browser.
  ["/analysis/:id/ttps", "/analysis/:id/capabilities"],
  // Rule matches, generated rules and the STIX bundle share one tab.
  ["/analysis/:id/rules", "/analysis/:id/detection"],
  ["/analysis/:id/signatures", "/analysis/:id/detection"],
  ["/analysis/:id/stix", "/analysis/:id/detection"],
  // A report is a completed job, so the reports table was the jobs table with
  // one status filter already applied.
  ["/reports", "/jobs?status=completed"],
];

const nextConfig: NextConfig = {
  /* Enable standalone output for Docker deployment */
  output: "standalone",

  redirects() {
    return Promise.resolve(
      MOVED.map(([source, destination]) => ({ source, destination, permanent: true })),
    );
  },

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
