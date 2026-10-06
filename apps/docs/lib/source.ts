import { docs } from 'collections/server';
import { loader, type LoaderPlugin } from 'fumadocs-core/source';

/* A page's sidebarTitle, when it has one, names it in the navigation; the
 * full title stays the page heading and the browser title. */
const sidebarTitles: LoaderPlugin = {
  name: 'sidebar-title',
  transformPageTree: {
    file(node, filePath) {
      if (!filePath) return node;
      const file = this.storage.read(filePath);
      if (file?.format !== 'page') return node;
      const short = (file.data as { sidebarTitle?: string }).sidebarTitle;
      return short ? { ...node, name: short } : node;
    },
  },
};

export const source = loader({
  baseUrl: '/',
  source: docs.toFumadocsSource(),
  plugins: [sidebarTitles],
});

export type DocsPage = NonNullable<ReturnType<typeof source.getPage>>;

/* The section a page belongs to: the separator above it in the sidebar,
 * shown as a small label over the title. A page whose sidebar name is the
 * section's own name (Paper) has no label. */
export function sectionOf(url: string): string | undefined {
  let section: string | undefined;
  for (const node of source.getPageTree().children) {
    if (node.type === 'separator') section = typeof node.name === 'string' ? node.name : undefined;
    else if (node.type === 'page' && node.url === url) {
      return section !== node.name ? section : undefined;
    }
  }
  return undefined;
}
