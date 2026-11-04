/* The content check for the docs pages; the site that renders them is built
 * and published separately and reads content/docs, public/assets and
 * docs/examples from this repository.
 *
 * Fails when a page does not compile as MDX, has no title, a meta.json does
 * not parse or lists a page that is not there, or a link to /docs/...,
 * /assets/... or /examples/... (or a #anchor on one) leads nowhere.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '@mdx-js/mdx';
import { toString } from 'mdast-util-to-string';
import remarkFrontmatter from 'remark-frontmatter';
import remarkGfm from 'remark-gfm';
import { visit } from 'unist-util-visit';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const content = join(root, 'content', 'docs');
const assets = join(root, 'public', 'assets');
const examples = join(root, '..', '..', 'docs', 'examples');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

/* Heading ids as the site generates them: the text folded to ASCII, all but
 * word characters, spaces and hyphens dropped, lower case, runs of spaces and
 * hyphens made one hyphen, and a repeat suffixed _1, _2, ... */
function slugify(text) {
  return text
    .normalize('NFKD')
    .replace(/[^\x00-\x7f]/g, '')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .toLowerCase()
    .replace(/[-\s]+/g, '-');
}

function uniqueId(ids, text) {
  let id = slugify(text);
  while (!id || ids.has(id)) {
    const m = /^(.*)_([0-9]+)$/.exec(id);
    id = m ? `${m[1]}_${Number(m[2]) + 1}` : `${id}_1`;
  }
  ids.add(id);
  return id;
}

/* content/docs/a/b.mdx is /docs/a/b/, and content/docs/a/index.mdx is /docs/a/. */
function route(file) {
  const rel = relative(content, file).replace(/\.mdx$/, '').replace(/(^|\/)index$/, '');
  return rel ? `/docs/${rel}/` : '/docs/';
}

const errors = [];
const pages = new Map(); // route -> { file, ids, links }
const files = walk(content);

for (const file of files.filter((f) => f.endsWith('.mdx'))) {
  const page = { file: relative(root, file), ids: new Set(), links: [], title: null };
  const collect = () => (tree) => {
    visit(tree, (node) => {
      if (node.type === 'yaml') {
        const m = /^title:\s*(.+)$/m.exec(node.value);
        page.title = m ? m[1].trim().replace(/^(['"])(.*)\1$/, '$2') : null;
        if (page.title) uniqueId(page.ids, page.title);
      } else if (node.type === 'heading') {
        uniqueId(page.ids, toString(node));
      } else if (['link', 'image', 'definition'].includes(node.type)) {
        page.links.push(node.url);
      } else if (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') {
        for (const attr of node.attributes) {
          if (['href', 'src'].includes(attr.name) && typeof attr.value === 'string') {
            page.links.push(attr.value);
          }
        }
      }
    });
  };
  try {
    await compile(readFileSync(file, 'utf8'), {
      remarkPlugins: [remarkFrontmatter, remarkGfm, collect],
    });
  } catch (err) {
    errors.push(`${page.file}: does not compile: ${err.message}`);
    page.ids = null; // its links and headings are unknown; links to it still resolve
  }
  if (page.ids && !page.title) errors.push(`${page.file}: the frontmatter has no title`);
  pages.set(route(file), page);
}

for (const file of files.filter((f) => f.endsWith('meta.json'))) {
  const where = relative(root, file);
  let meta;
  try {
    meta = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    errors.push(`${where}: does not parse: ${err.message}`);
    continue;
  }
  /* An entry names a page or a folder; separators, links and the rest marker are not files. */
  for (const entry of meta.pages ?? []) {
    if (/^---.*---$|^\[.*\]\(.*\)$|^\.\.\.|^z\.\.\.a$/.test(entry)) continue;
    const path = join(dirname(file), entry.replace(/^!/, ''));
    if (!existsSync(`${path}.mdx`) && !existsSync(path)) {
      errors.push(`${where}: lists ${entry}, which is not a page or folder`);
    }
  }
}

let checked = 0;
for (const [here, page] of pages) {
  for (const link of page.links) {
    const [path, anchor] = link.split('#');
    let target;
    if (/^\/(docs|assets|examples)(\/|$)|^#/.test(link)) checked += 1;
    if (path === '') target = here;
    else if (path === '/docs' || path.startsWith('/docs/')) {
      target = path.endsWith('/') ? path : `${path}/`;
      if (!pages.has(target)) {
        errors.push(`${page.file}: ${link} is not a page`);
        continue;
      }
    } else if (path.startsWith('/assets/')) {
      if (!existsSync(join(assets, path.slice('/assets/'.length)))) {
        errors.push(`${page.file}: ${link} is not a file in public/assets`);
      }
      continue;
    } else if (path.startsWith('/examples/')) {
      if (!existsSync(join(examples, path.slice('/examples/'.length)))) {
        errors.push(`${page.file}: ${link} is not a file in docs/examples`);
      }
      continue;
    } else continue;
    if (anchor && pages.get(target).ids && !pages.get(target).ids.has(anchor)) {
      errors.push(`${page.file}: ${link} names no heading on ${target}`);
    }
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  console.error(`\n${errors.length} problem(s) in the docs content.`);
  process.exit(1);
}
console.log(`${pages.size} pages compile, every meta.json parses, ${checked} links and images resolve.`);
