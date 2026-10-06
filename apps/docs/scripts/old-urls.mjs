/* Run after `next build`: keeps every address the MkDocs site served.
 *
 * REDIRECTS maps each page address the MkDocs site had to the page that holds
 * its text now. Where the two differ, a small HTML page at the old address
 * sends the reader on (a meta refresh, with the new page as canonical);
 * where they are the same, the page itself must exist. Either way a missing
 * target fails the build, so a page cannot lose its old address unnoticed.
 *
 * The MkDocs site also served docs/examples/ as files; the importable team
 * document still lives there for the tests that read it, and is copied in.
 */
import { cpSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'out');
const base = '/Maljan';

const same = (path) => [path, path];

export const REDIRECTS = Object.fromEntries([
  same('/'),
  same('/getting-started/'),
  same('/console/'),
  same('/usage/running-an-analysis/'),
  same('/usage/teams/'),
  same('/usage/reports-and-exports/'),
  same('/providers/'),
  same('/providers/openai-compatible/'),
  same('/providers/anthropic/'),
  same('/providers/gemini/'),
  same('/providers/ollama/'),
  same('/providers/llama-cpp/'),
  same('/tools/'),
  same('/tools/ghidra/'),
  same('/tools/radare2/'),
  same('/tools/capa-yara/'),
  same('/tools/sandboxes/'),
  same('/tools/virustotal/'),
  same('/tools/sidecars/'),
  same('/tools/generic-mcp/'),
  same('/api/'),
  same('/integrations/mcp-servers/'),
  same('/integrations/ci/'),
  same('/configuration/'),
  same('/architecture/'),
  same('/security/'),
  same('/deployment/'),
  same('/operations/'),
  same('/development/'),
  same('/benchmark/'),
  same('/benchmark/scores/latrodectus-all-tools-local6/'),
  same('/benchmark/scores/latrodectus-all-tools-run5/'),
  same('/benchmark/scores/latrodectus-all-tools-run4/'),
  same('/benchmark/scores/latrodectus-iteration6-default/'),
  same('/benchmark/scores/latrodectus-iteration5-default/'),
  same('/benchmark/scores/latrodectus-iteration4-default/'),
  same('/benchmark/scores/latrodectus-iteration2-default/'),
  same('/benchmark/scores/latrodectus-iteration2-r2/'),
  same('/benchmark/scores/latrodectus-iteration1-default/'),
  same('/benchmark/scores/latrodectus-iteration1-small/'),
  same('/paper/'),
]);

const page = (path) => join(out, path, 'index.html');

function redirectPage(to) {
  const url = base + to;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved</title>
<link rel="canonical" href="${url}">
<meta name="robots" content="noindex">
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
