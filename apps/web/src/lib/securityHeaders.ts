/**
 * The response headers every console page is served with.
 *
 * The console sent none, so any site could frame it and dress a click on
 * "Revoke", "Apply" or "Start" as a click on something of its own. Framing is
 * refused twice — `X-Frame-Options` for the browsers that read only that, and
 * the CSP `frame-ancestors` directive for the ones that prefer it — and the
 * CSP carries nothing else, so no script, style or connection the pages make
 * today is affected by it.
 *
 * `nosniff` stops a browser from reading a served file as a type it guesses,
 * and `no-referrer` keeps a run's id, which is in every analysis URL, out of
 * the `Referer` a followed link would send to the site it leads to.
 *
 * Kept out of `next.config.ts` so a test can read the list.
 */
export const SECURITY_HEADERS: ReadonlyArray<{ key: string; value: string }> = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
];
