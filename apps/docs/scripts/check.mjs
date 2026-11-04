/* The content check for the docs pages; the site that renders them is built
 * and published separately and reads content/docs, public/assets and
 * docs/examples from this repository.
 *
 * Fails when a page does not compile as MDX, its frontmatter is not what the
 * site reads, it uses a component the site does not provide, a meta.json does
 * not parse or lists a page that is not there, a link leads nowhere (a page,
 * #anchor, asset or example), a link is relative or points at the old
 * GitHub Pages address, or an old address no longer leads to a page.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '@mdx-js/mdx';
import { toString } from 'mdast-util-to-string';
import remarkFrontmatter from 'remark-frontmatter';
import remarkGfm from 'remark-gfm';
import { visit } from 'unist-util-visit';
import { parse as parseYaml } from 'yaml';
import { OLD_PATHS, newPath } from './old-addresses.mjs';

/* The components a page may use without importing them. This must match the
 * site's MDX component map: the UI library's defaults plus what the site
 * adds (Accordion, Accordions, Hero, Step, Steps, Tab, Tabs). */
const SITE_COMPONENTS = new Set([
  'Accordion',
  'Accordions',
  'Callout',
  'CalloutContainer',
  'CalloutDescription',
  'CalloutTitle',
  'Card',
  'Cards',
  'CodeBlockTab',
  'CodeBlockTabs',
  'CodeBlockTabsList',
  'CodeBlockTabsTrigger',
  'Hero',
  'Step',
  'Steps',
  'Tab',
  'Tabs',
]);

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
const pages = new Map(); // route -> { file, ids, titleId, links, title }
const files = walk(content);

/* The frontmatter fields the site reads, and the type each must have. */
/* The capitalised JSX names inside an expression, such as icon={<Rocket />}. */
function jsxNames(node, found = new Set()) {
  if (!node || typeof node !== 'object') return found;
  if (node.type === 'JSXOpeningElement' && node.name.type === 'JSXIdentifier') {
    if (/^[A-Z]/.test(node.name.name)) found.add(node.name.name);
  }
  for (const value of Object.values(node)) {
    if (value && typeof value === 'object') jsxNames(value, found);
  }
  return found;
}

function checkFrontmatter(page, value) {
  let data;
  try {
    data = parseYaml(value);
  } catch (err) {
    return [`the frontmatter does not parse: ${err.message.split('\n')[0]}`];
  }
  const problems = [];
  if (typeof data?.title !== 'string' || !data.title.trim()) {
    problems.push('the frontmatter has no title');
  } else page.title = data.title;
  for (const key of ['description', 'sidebarTitle']) {
    if (data?.[key] !== undefined && typeof data[key] !== 'string') {
      problems.push(`the frontmatter's ${key} is not a string`);
    }
  }
  if (data?.full !== undefined && typeof data.full !== 'boolean') {
    problems.push("the frontmatter's full is not true or false");
  }
  return problems;
}

for (const file of files.filter((f) => f.endsWith('.mdx'))) {
  const here = route(file);
  /* titleId: the page title's own id, apart from the headings' ids. */
  const page = { file: relative(root, file), ids: new Set(), titleId: null, links: [], title: null };
  const problems = [];
  let frontmatter = false;
  const imported = new Set();
  const used = new Set();
  const collect = () => (tree) => {
    visit(tree, (node) => {
      if (node.type === 'yaml') {
        frontmatter = true;
        problems.push(...checkFrontmatter(page, node.value));
      } else if (node.type === 'heading') {
        uniqueId(page.ids, toString(node));
      } else if (['link', 'image', 'definition'].includes(node.type)) {
        page.links.push(node.url);
      } else if (node.type === 'mdxjsEsm') {
        for (const statement of node.data?.estree?.body ?? []) {
          for (const specifier of statement.specifiers ?? []) imported.add(specifier.local.name);
          for (const declaration of statement.declaration?.declarations ?? []) {
            if (declaration.id.name) imported.add(declaration.id.name);
          }
        }
      } else if (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') {
        if (node.name && /^[A-Z]/.test(node.name)) used.add(node.name.split('.')[0]);
        for (const attr of node.attributes) {
          if (['href', 'src'].includes(attr.name) && typeof attr.value === 'string') {
            page.links.push(attr.value);
          }
          for (const name of jsxNames(attr.value?.data?.estree)) used.add(name);
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
    pages.set(here, page);
    continue;
  }
  if (!frontmatter) problems.push('has no frontmatter');
  for (const name of used) {
    if (!imported.has(name) && !SITE_COMPONENTS.has(name)) {
      problems.push(`uses <${name}>, which it does not import and the site does not provide`);
    }
  }
  /* The docs home shows no title heading of its own. */
  if (page.title && here !== '/docs/') page.titleId = slugify(page.title);
  errors.push(...problems.map((problem) => `${page.file}: ${problem}`));
  pages.set(here, page);
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
  if (meta.pages !== undefined && !Array.isArray(meta.pages)) {
    errors.push(`${where}: pages is not a list`);
    continue;
  }
  for (const entry of meta.pages ?? []) {
    if (typeof entry !== 'string') {
      errors.push(`${where}: lists ${JSON.stringify(entry)}, which is not a page name`);
      continue;
    }
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
    checked += 1;
    const [address, anchor] = link.split('#');
    const path = address.split('?')[0];
    if (/^[a-z][a-z0-9+.-]*:/i.test(link)) {
      if (/^https?:\/\/root0ne\.github\.io\/Maljan(\/|$)/i.test(link)) {
        errors.push(`${page.file}: ${link} is the old address; link to /docs/... instead`);
      }
      continue;
    }
    let target;
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
    } else if (path.startsWith('/')) {
      errors.push(`${page.file}: ${link} is outside /docs/, /assets/ and /examples/`);
      continue;
    } else {
      errors.push(`${page.file}: ${link} is relative; write it as /docs/..., /assets/... or /examples/...`);
      continue;
    }
    const { ids, titleId } = pages.get(target);
    if (anchor && ids && !ids.has(anchor) && anchor !== titleId) {
      errors.push(`${page.file}: ${link} names no heading on ${target}`);
    }
  }
}

/* Every address the old site served still leads to a page. */
for (const old of OLD_PATHS) {
  if (!pages.has(newPath(old))) {
    errors.push(`old address ${old} leads to ${newPath(old)}, which is not a page`);
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  console.error(`\n${errors.length} problem(s) in the docs content.`);
  process.exit(1);
}
console.log(
  `${pages.size} pages compile, every meta.json parses, ${checked} links and images check out, ` +
    `${OLD_PATHS.length} old addresses lead to a page.`,
);
