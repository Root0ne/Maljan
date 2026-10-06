/* Heading ids as the MkDocs site generated them (Python-Markdown's toc
 * extension), so every anchor a reader bookmarked or another page links to
 * still lands on its heading: the text folded to ASCII, everything but word
 * characters, spaces and hyphens dropped, lower case, runs of spaces and
 * hyphens collapsed into one hyphen, and a repeat suffixed _1, _2, ... */
const seen = new WeakMap<object, Set<string>>();

/** The id of one heading text, before de-duplication; the page title's id. */
export function slugify(text: string): string {
  return text
    .normalize('NFKD')
    .replace(/[^\x00-\x7f]/g, '')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .toLowerCase()
    .replace(/[-\s]+/g, '-');
}

export function mkdocsSlug(root: object, _heading: unknown, text: string): string {
  let ids = seen.get(root);
  if (!ids) {
    ids = new Set();
    seen.set(root, ids);
  }
  let id = slugify(text);
  while (!id || ids.has(id)) {
    const m = /^(.*)_([0-9]+)$/.exec(id);
    id = m ? `${m[1]}_${Number(m[2]) + 1}` : `${id}_1`;
  }
  ids.add(id);
  return id;
}
