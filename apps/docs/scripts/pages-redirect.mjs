/* Writes the GitHub Pages site that sends readers from the old docs address,
 * https://root0ne.github.io/Maljan/<path>, to https://malspark.com/docs/<path>
 * (and /examples/... and /assets/... to the same path on malspark.com), query
 * and anchor kept. An address in MOVED (scripts/old-addresses.mjs) goes to the
 * page that holds its text now.
 *
 * index.html covers the root; every other address is a miss on GitHub Pages,
 * which serves 404.html. Both run the same script; without script, both fall
 * back to the docs home.
 *
 * Usage: node scripts/pages-redirect.mjs <output directory>
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { MOVED } from './old-addresses.mjs';

const out = process.argv[2];
if (!out) {
  console.error('usage: node scripts/pages-redirect.mjs <output directory>');
  process.exit(2);
}

const site = 'https://malspark.com';
const home = `${site}/docs/`;

/* The path after /Maljan; an address already under /docs/, /examples/ or
 * /assets/ keeps its prefix, anything else is a docs page. */
const script = `<script>
(function () {
  var moved = ${JSON.stringify(MOVED)};
  var rest = location.pathname.replace(/^\\/Maljan(?=\\/|$)/, '') || '/';
  var key = rest.replace(/\\/?$/, '/');
  var path = moved[key] || (/^\\/(docs|examples|assets)(\\/|$)/.test(rest) ? rest : '/docs' + rest);
  location.replace('${site}' + path + location.search + location.hash);
})();
</script>`;

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Malspark docs have moved</title>
<meta name="robots" content="noindex">
<link rel="canonical" href="${home}">
${script}
<noscript><meta http-equiv="refresh" content="0; url=${home}"></noscript>
</head>
<body>
<p>The Malspark docs have moved to <a href="${home}">${home}</a>.</p>
</body>
</html>
`;

mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'index.html'), page);
writeFileSync(join(out, '404.html'), page);
console.log(`wrote index.html and 404.html to ${out}`);
