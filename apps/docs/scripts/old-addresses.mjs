/* The docs addresses the old site served, relative to its root
 * (https://root0ne.github.io/Maljan/), from the MkDocs era on.
 *
 * Each now lives at the same path under /docs/ on malspark.com, except those
 * in MOVED, which name their new address. scripts/pages-redirect.mjs applies
 * MOVED before the generic rule, and scripts/check.mjs fails when an old
 * address no longer leads to a page.
 */
export const OLD_PATHS = [
  '/',
  '/getting-started/',
  '/console/',
  '/usage/running-an-analysis/',
  '/usage/teams/',
  '/usage/reports-and-exports/',
  '/providers/',
  '/providers/openai-compatible/',
  '/providers/anthropic/',
  '/providers/gemini/',
  '/providers/ollama/',
  '/providers/llama-cpp/',
  '/tools/',
  '/tools/ghidra/',
  '/tools/radare2/',
  '/tools/capa-yara/',
  '/tools/sandboxes/',
  '/tools/virustotal/',
  '/tools/sidecars/',
  '/tools/generic-mcp/',
  '/api/',
  '/integrations/mcp-servers/',
  '/integrations/ci/',
  '/configuration/',
  '/architecture/',
  '/security/',
  '/deployment/',
  '/operations/',
  '/development/',
  '/benchmark/',
  '/benchmark/scores/latrodectus-all-tools-local6/',
  '/benchmark/scores/latrodectus-all-tools-run5/',
  '/benchmark/scores/latrodectus-all-tools-run4/',
  '/benchmark/scores/latrodectus-iteration6-default/',
  '/benchmark/scores/latrodectus-iteration5-default/',
  '/benchmark/scores/latrodectus-iteration4-default/',
  '/benchmark/scores/latrodectus-iteration2-default/',
  '/benchmark/scores/latrodectus-iteration2-r2/',
  '/benchmark/scores/latrodectus-iteration1-default/',
  '/benchmark/scores/latrodectus-iteration1-small/',
  '/paper/',
];

/* Old path -> its address on malspark.com, where it is not /docs + the path. */
export const MOVED = {
  '/paper/': '/docs/benchmark/',
  // The per-run score pages were folded into the one benchmark page, which
  // holds the latest run only.
  '/benchmark/scores/latrodectus-all-tools-local6/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-all-tools-run5/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-all-tools-run4/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration6-default/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration5-default/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration4-default/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration2-default/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration2-r2/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration1-default/': '/docs/benchmark/',
  '/benchmark/scores/latrodectus-iteration1-small/': '/docs/benchmark/',
};

/** The malspark.com path an old address leads to. */
export function newPath(old) {
  return MOVED[old] ?? `/docs${old}`;
}
