import type { NextConfig } from "next";

import { SECURITY_HEADERS } from "./src/lib/securityHeaders";

/* The routes that moved, and where they moved to.
 *
 * The analysis page is six tabs (Overview, Behaviour, Network, Static & code,
 * Indicators & detection, Evidence), and every route the page had before
 * lands on the tab that now holds its content, at the block it became where
 * the tab holds several. `/reports` became a filter on the one list of runs.
 * The server answers before the bundle is fetched, so a bookmark or a link in
 * an already-issued report lands on the tab that answers what it asked
 * without loading a page that has nothing to draw.
 *
 * Permanent, because these are not coming back: a 308 is cached by the client
 * and tells a crawler the same thing.
 */
const MOVED: Array<[string, string]> = [
  // The run's discussion, live and replayed by the same view, is a view of
  // the evidence, and so is each agent's and server's own output.
  ["/analysis/:id/conversation", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/live", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/process", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/agents", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/pipeline", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/timeline", "/analysis/:id/evidence/conversation"],
  ["/analysis/:id/agent/:key", "/analysis/:id/evidence/agent/:key"],
  ["/analysis/:id/server/:key", "/analysis/:id/evidence/server/:key"],
  // What the sample does: the sandbox, ATT&CK and persistence.
  ["/analysis/:id/dynamic", "/analysis/:id/behaviour#dynamic"],
  ["/analysis/:id/capabilities", "/analysis/:id/behaviour#attack"],
  ["/analysis/:id/ttps", "/analysis/:id/behaviour#attack"],
  ["/analysis/:id/persistence", "/analysis/:id/behaviour#persistence"],
  // What the file is sits beside what reading it showed.
  ["/analysis/:id/identity", "/analysis/:id/static#identity"],
  // Rule matches, generated rules, indicators, the STIX bundle and
  // attribution share one tab.
  ["/analysis/:id/detection", "/analysis/:id/indicators#detection"],
  ["/analysis/:id/rules", "/analysis/:id/indicators#detection"],
  ["/analysis/:id/signatures", "/analysis/:id/indicators#detection"],
  ["/analysis/:id/stix", "/analysis/:id/indicators#detection"],
  ["/analysis/:id/attribution", "/analysis/:id/indicators#attribution"],
  // The recommendations are the end of the Overview.
  ["/analysis/:id/defense", "/analysis/:id#recommendations"],
  // The preview of this page, before it became the page.
  ["/preview/analysis/:id", "/analysis/:id"],
  ["/preview/analysis/:id/:path*", "/analysis/:id/:path*"],
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

  /* Every page refuses to be framed and is served with the other headers in
   * `SECURITY_HEADERS` (src/lib/securityHeaders.ts says why each is there). */
  headers() {
    return Promise.resolve([{ source: "/:path*", headers: [...SECURITY_HEADERS] }]);
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
