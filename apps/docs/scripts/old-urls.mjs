/* Run after `next build`: keeps every address the MkDocs site served.
 *
 * REDIRECTS maps each page address the MkDocs site had to the page that holds
 * its text now. Where the two differ, a small HTML page at the old address
 * sends the reader on (a meta refresh, with the new page as canonical);
 * where they are the same, the page itself must exist. Either way a missing
 * target fails the build, so a page cannot lose its old address unnoticed.
 *
 * Every other docs page the site served at the root before the docs moved
 * under /docs/ is found in the build and redirected the same way.
 *
 * The MkDocs site also served docs/examples/ as files; the importable team
 * document still lives there for the tests that read it, and is copied in.
 */
import { cpSync, existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'out');
/* The path the build is served under (next.config.mjs reads the same). */
const base = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
const siteUrl = 'https://malspark.com';

const same = (path) => [path, path];
/* The docs moved under /docs/ when the home page took the root. */
const moved = (path) => [path, `/docs${path}`];

export const REDIRECTS = Object.fromEntries([
  same('/'),
  moved('/getting-started/'),
  moved('/console/'),
  moved('/usage/running-an-analysis/'),
  moved('/usage/teams/'),
  moved('/usage/reports-and-exports/'),
  moved('/providers/'),
  moved('/providers/openai-compatible/'),
  moved('/providers/anthropic/'),
  moved('/providers/gemini/'),
  moved('/providers/ollama/'),
  moved('/providers/llama-cpp/'),
  moved('/tools/'),
  moved('/tools/ghidra/'),
  moved('/tools/radare2/'),
  moved('/tools/capa-yara/'),
  moved('/tools/sandboxes/'),
  moved('/tools/virustotal/'),
  moved('/tools/sidecars/'),
  moved('/tools/generic-mcp/'),
  moved('/api/'),
  moved('/integrations/mcp-servers/'),
  moved('/integrations/ci/'),
  moved('/configuration/'),
  moved('/architecture/'),
  moved('/security/'),
  moved('/deployment/'),
  moved('/operations/'),
  moved('/development/'),
  moved('/benchmark/'),
  moved('/benchmark/scores/latrodectus-all-tools-local6/'),
  moved('/benchmark/scores/latrodectus-all-tools-run5/'),
  moved('/benchmark/scores/latrodectus-all-tools-run4/'),
  moved('/benchmark/scores/latrodectus-iteration6-default/'),
  moved('/benchmark/scores/latrodectus-iteration5-default/'),
  moved('/benchmark/scores/latrodectus-iteration4-default/'),
  moved('/benchmark/scores/latrodectus-iteration2-default/'),
  moved('/benchmark/scores/latrodectus-iteration2-r2/'),
  moved('/benchmark/scores/latrodectus-iteration1-default/'),
  moved('/benchmark/scores/latrodectus-iteration1-small/'),
  ['/paper/', '/docs/benchmark/'],
]);

const page = (path) => join(out, path, 'index.html');

/* Every docs page under out/docs/, by the address it had at the root. */
function docsPages(dir = join(out, 'docs'), prefix = '/') {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const path = `${prefix}${entry.name}/`;
    if (existsSync(join(dir, entry.name, 'index.html'))) found.push(path);
    found.push(...docsPages(join(dir, entry.name), path));
  }
  return found;
}

for (const path of docsPages()) {
  if (!(path in REDIRECTS)) REDIRECTS[path] = `/docs${path}`;
}

/* The script carries the anchor along; the meta refresh is the fallback
 * without scripts. */
function redirectPage(to) {
  const url = base + to;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved</title>
<link rel="canonical" href="${siteUrl}${to}">
<meta name="robots" content="noindex">
<script>location.replace(${JSON.stringify(url)} + location.hash)</script>
<meta http-equiv="refresh" content="0; url=${url}">
</head>
<body><p>This page is now at <a href="${url}">${url}</a>.</p></body>
</html>
`;
}

const missing = [];
let written = 0;
for (const [from, to] of Object.entries(REDIRECTS)) {
  if (!existsSync(page(to))) {
    missing.push(`${from} -> ${to}`);
    continue;
  }
  if (from === to) continue;
  if (existsSync(page(from))) {
    missing.push(`${from} is a page of its own; it cannot also redirect to ${to}`);
    continue;
  }
  mkdirSync(join(out, from), { recursive: true });
  writeFileSync(page(from), redirectPage(to));
  written += 1;
}

cpSync(join(here, '..', '..', '..', 'docs', 'examples'), join(out, 'examples'), { recursive: true });

if (missing.length) {
  console.error(`old addresses without a page:\n  ${missing.join('\n  ')}`);
  process.exit(1);
}
console.log(`${Object.keys(REDIRECTS).length} old addresses kept, ${written} redirect pages written`);
