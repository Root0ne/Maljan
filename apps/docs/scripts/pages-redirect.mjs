/* Writes the GitHub Pages site that sends readers from the old docs address,
 * https://root0ne.github.io/Maljan/<path>, to https://malspark.com/docs/<path>
 * (and /examples/<path> to https://malspark.com/examples/<path>), anchor kept.
 *
 * index.html covers the root; every other address is a miss on GitHub Pages,
 * which serves 404.html, whose script works out the new address. Without
 * script, both fall back to the docs home.
 *
 * Usage: node scripts/pages-redirect.mjs <output directory>
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
if (!out) {
  console.error('usage: node scripts/pages-redirect.mjs <output directory>');
  process.exit(2);
}

const site = 'https://malspark.com';
const home = `${site}/docs/`;

function page(head) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Malspark docs have moved</title>
<meta name="robots" content="noindex">
<link rel="canonical" href="${home}">
${head}
</head>
<body>
<p>The Malspark docs have moved to <a href="${home}">${home}</a>.</p>
</body>
</html>
`;
}

const index = page(`<meta http-equiv="refresh" content="0; url=${home}">`);

/* The path after /Maljan; an address already under /docs/ or /examples/
 * keeps its prefix, anything else is a docs page. */
const notFound = page(`<script>
(function () {
  var rest = location.pathname.replace(/^\\/Maljan(?=\\/|$)/, '') || '/';
  var known = /^\\/(docs|examples)(\\/|$)/.test(rest);
  location.replace('${site}' + (known ? '' : '/docs') + rest + location.hash);
})();
</script>
<noscript><meta http-equiv="refresh" content="0; url=${home}"></noscript>`);

mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'index.html'), index);
writeFileSync(join(out, '404.html'), notFound);
console.log(`wrote index.html and 404.html to ${out}`);
