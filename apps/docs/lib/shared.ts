export const appName = 'Malspark';
export const repoUrl = 'https://github.com/Root0ne/Maljan';
/* The branch "Edit this page" opens; the docs are written on dev. */
export const editBranch = 'dev';
/* The site's own address. Canonical links, the sitemap, Open Graph and the
 * structured data name it, whichever host serves a given build. */
export const siteUrl = 'https://malspark.com';
/* The path the site is served under: empty at the domain's root, '/Maljan'
 * for the GitHub Pages build. next.config.mjs reads the same variable. */
export const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
export const siteDescription =
  'Malspark is an open-source malware analysis framework in which teams of LLM agents ' +
  'call plug-in tools, models and sandboxes, and every claim in the report cites the ' +
  'tool call it came from. Reports map to MITRE ATT&CK and export as STIX 2.1.';
/* The generated Open Graph card, 1200 by 630 (public/og.png). */
export const ogImage = { url: `${siteUrl}/og.png`, width: 1200, height: 630, alt: appName };

/* An address on the site, absolute, for canonical links and the sitemap. */
export function absolute(path: string): string {
  return `${siteUrl}${path}`;
}
