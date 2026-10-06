import { source } from '@/lib/source';
import { createFromSource } from 'fumadocs-core/search/server';

export const revalidate = false;

/* Results are ranked by relevance and never sorted by a field, so the
 * index ships without the sort tables (about a quarter of its size). */
export const { staticGET: GET } = createFromSource(source, {
  // https://docs.orama.com/docs/orama-js/supported-languages
  language: 'english',
  sort: { enabled: false },
});
