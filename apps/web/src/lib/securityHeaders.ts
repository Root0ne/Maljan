/**
 * The response headers every console page is served with.
 *
 * The console sent none, so any site could frame it and dress a click on
 * "Revoke", "Apply" or "Start" as a click on something of its own. Framing is
 * refused twice — `X-Frame-Options` for the browsers that read only that, and
 * the CSP `frame-ancestors` directive for the ones that prefer it.
 *
 * The CSP also pins what a page may load and where it may connect: this site
 * plus the API and live-feed addresses the console is configured with. Next's
 * own inline hydration scripts need `'unsafe-inline'` (a nonce would make every
 * page dynamic), and dev mode adds `'unsafe-eval'` and the HMR socket. It still
 * stops a foreign script source, a foreign connection, a plugin object, a
 * changed base URL and a form posted away.
 *
 * `nosniff` stops a browser from reading a served file as a type it guesses,
 * and `no-referrer` keeps a run's id, which is in every analysis URL, out of
 * the `Referer` a followed link would send to the site it leads to.
 *
 * Kept out of `next.config.ts` so a test can read the list.
 */

interface CspEnv {
  apiUrl?: string;
  wsUrl?: string;
  dev?: boolean;
}

function siteOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** The CSP for a console configured with these API / live-feed addresses. */
export function contentSecurityPolicy(env: CspEnv): string {
  const api = siteOf(env.apiUrl) ?? "http://127.0.0.1:8000";
  const feed = siteOf(env.wsUrl) ?? api;
  const twin = (u: string) => u.replace(/^http/, "ws");
  const connect = new Set(["'self'", api, feed, twin(api), twin(feed)]);
  if (env.dev) connect.add("ws:");
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${env.dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${[...connect].join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export function securityHeaders(env: CspEnv): ReadonlyArray<{ key: string; value: string }> {
  return [
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Content-Security-Policy", value: contentSecurityPolicy(env) },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "no-referrer" },
  ];
}

export const SECURITY_HEADERS: ReadonlyArray<{ key: string; value: string }> = securityHeaders({
  apiUrl: process.env.NEXT_PUBLIC_API_URL,
  wsUrl: process.env.NEXT_PUBLIC_WS_URL,
  dev: process.env.NODE_ENV !== "production",
});
